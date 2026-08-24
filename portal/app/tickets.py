"""Ticket logic for the VOC portal.

Auto-assignment rule (Feature 8 - smart routing):
    a user receives a new ticket only if they have SOLVED more than 50% of
    all tickets ever assigned to them (resolution_rate > 0.5). Among eligible
    users the ticket goes to the one with the highest resolution rate; ties
    are broken by fewest currently-open tickets. Critical tickets additionally
    require rate >= ROUTING_MIN_RATE_CRITICAL (default 70%) and an open load
    below ROUTING_MAX_OPEN_CRITICAL so one analyst is not flooded with the
    hardest work. Every assignment stores a transparent reason string.

Time formula (estimated hours to resolve):
    est_hours = base_hours[severity] / max(rate, 0.1)
    blended with the user's historical average once history exists.
"""
import os
from datetime import datetime, timezone

from .db import get_db

BASE_HOURS = {'critical': 6.0, 'high': 12.0, 'medium': 24.0, 'low': 48.0}
SOLVE_THRESHOLD = 0.5
MIN_RATE_FOR_CRITICAL = float(os.getenv('ROUTING_MIN_RATE_CRITICAL', '0.7'))
MAX_OPEN_FOR_CRITICAL = int(os.getenv('ROUTING_MAX_OPEN_CRITICAL', '5'))

# Roles eligible for automatic assignment (legacy names kept for DBs created
# before the role migration ran).
ASSIGNABLE_ROLES = ('soc1', 'soc2', 'soc3', 'noc', 'voc', 'user', 'soc')

RESOLVED_STATUSES = ('solved', 'closed')


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def resolution_rate(user_id):
    with get_db() as conn:
        row = conn.execute(
            'SELECT COUNT(*) AS total, SUM(CASE WHEN status="solved" THEN 1 ELSE 0 END) AS solved '
            'FROM tickets WHERE assigned_to=? AND assigned_at IS NOT NULL', (user_id,)).fetchone()
    total = row['total'] or 0
    solved = row['solved'] or 0
    return (solved / total) if total else 0.0, solved, total


def open_load(user_id):
    with get_db() as conn:
        row = conn.execute(
            'SELECT COUNT(*) AS c FROM tickets WHERE assigned_to=? '
            'AND status NOT IN ("solved","closed")', (user_id,)).fetchone()
    return row['c']


def user_avg_resolution_hours(user_id):
    with get_db() as conn:
        rows = conn.execute(
            'SELECT (julianday(solved_at) - julianday(assigned_at)) * 24.0 AS h '
            'FROM tickets WHERE assigned_to=? AND status="solved" AND assigned_at IS NOT NULL '
            'AND solved_at IS NOT NULL', (user_id,)).fetchall()
    hours = [r['h'] for r in rows if r['h'] is not None and r['h'] >= 0]
    return (sum(hours) / len(hours)) if hours else None


def estimate_hours(severity, user_id):
    base = BASE_HOURS.get(severity, 12.0)
    rate, _, _ = resolution_rate(user_id)
    est = base / max(rate, 0.1)
    avg = user_avg_resolution_hours(user_id)
    if avg is not None:
        return round((est + avg) / 2, 1)
    return round(est, 1)


def best_assignee(severity='medium'):
    """Pick the eligible user for a new ticket (rate > 50%), best first.

    Returns (user_id | None, human-readable reasoning).
    """
    with get_db() as conn:
        placeholders = ','.join('?' * len(ASSIGNABLE_ROLES))
        users = conn.execute(
            f'SELECT id, username, full_name, role FROM users '
            f'WHERE active=1 AND role IN ({placeholders})',
            ASSIGNABLE_ROLES).fetchall()

    critical = severity == 'critical'
    candidates = []
    skipped = []
    for u in users:
        rate, _, _ = resolution_rate(u['id'])
        if rate <= SOLVE_THRESHOLD:
            continue
        load = open_load(u['id'])
        if critical and (rate < MIN_RATE_FOR_CRITICAL or load >= MAX_OPEN_FOR_CRITICAL):
            skipped.append(f"{u['username']}(rate {rate:.0%}, open {load})")
            continue
        avg = user_avg_resolution_hours(u['id'])
        candidates.append({
            'id': u['id'], 'username': u['username'],
            'rate': round(rate, 2), 'open': load,
            'avg_hours': round(avg, 1) if avg is not None else None,
        })

    if not candidates:
        why = 'no analyst exceeds the 50% resolution threshold'
        if critical:
            why = (f'no analyst eligible for Critical (need rate>='
                   f'{MIN_RATE_FOR_CRITICAL:.0%} and <{MAX_OPEN_FOR_CRITICAL} open); '
                   f'skipped: {", ".join(skipped) if skipped else "none"}')
        return None, why

    candidates.sort(key=lambda c: (-c['rate'], c['open']))
    pick = candidates[0]
    reason = (f"Resolution rate: {pick['rate']:.0%}; "
              f"Open tickets: {pick['open']}; "
              f"Avg remediation time: "
              f"{pick['avg_hours'] if pick['avg_hours'] is not None else 'n/a'}h; "
              f"Eligible for Critical: "
              f"{'YES' if pick['rate'] >= MIN_RATE_FOR_CRITICAL else 'NO'}")
    return pick['id'], reason


def assign_ticket(ticket_id, severity=None):
    """Auto-assign an unassigned ticket to the best eligible user."""
    with get_db() as conn:
        t = conn.execute('SELECT * FROM tickets WHERE id=?', (ticket_id,)).fetchone()
    if not t or t['assigned_to'] is not None:
        return None
    sev = severity or t['severity']
    user_id, reason = best_assignee(sev)
    if user_id is None:
        return None
    est = estimate_hours(sev, user_id)
    with get_db() as conn:
        conn.execute(
            'UPDATE tickets SET assigned_to=?, assigned_at=?, est_hours=?, '
            'assignment_reason=?, '
            'status=CASE WHEN status="open" THEN "assigned" ELSE status END '
            'WHERE id=?', (user_id, _now(), est, reason, ticket_id))
    notify_assignment(ticket_id, sev, reason)
    return user_id


def rebalance_unassigned():
    """After any solve, try to assign all unassigned tickets."""
    with get_db() as conn:
        rows = conn.execute('SELECT id FROM tickets WHERE assigned_to IS NULL '
                            'AND status NOT IN ("solved","closed")').fetchall()
    return [assign_ticket(r['id']) for r in rows]


def unassign_user(user_id, conn=None):
    """Release all of a user's tickets back to the open queue."""
    own = conn is None
    if own:
        conn = get_db()
    conn.execute('UPDATE tickets SET assigned_to=NULL, assigned_at=NULL, '
                 'est_hours=NULL, status="open" WHERE assigned_to=?', (user_id,))
    if own:
        conn.close()


_host_cache = {}


def hostname_for(ip):
    """Resolve an IP to the inventory hostname (cached per process)."""
    if not ip or ip in _host_cache:
        return _host_cache.get(ip)
    name = None
    try:
        import requests as rq
        from .esdata import ES_PASSWORD, ES_URL, ES_USER
        r = rq.post(f'{ES_URL}/assets/_search', auth=(ES_USER, ES_PASSWORD),
                    json={'size': 1, 'query': {'term': {'ip_address': ip}},
                          '_source': ['hostname']}, timeout=8)
        if r.status_code == 200:
            hits = r.json().get('hits', {}).get('hits', [])
            name = (hits[0]['_source'].get('hostname') or None) if hits else None
    except Exception:
        pass
    _host_cache[ip] = name
    return name


def ticket_payload(t):
    d = dict(t)
    d['hostname'] = hostname_for(d.get('host'))
    d['sla_status_label'] = (d.get('sla_status') or '').upper() or None
    d['remaining_hours'] = None
    if d.get('sla_deadline') and d.get('status') not in RESOLVED_STATUSES:
        from .sla import remaining_hours
        rem = remaining_hours(d['sla_deadline'])
        d['remaining_hours'] = round(rem, 1) if rem is not None else None
    d['assignee'] = None
    if t['assigned_to']:
        with get_db() as conn:
            u = conn.execute('SELECT id, username, full_name, role FROM users WHERE id=?',
                             (t['assigned_to'],)).fetchone()
        if u:
            d['assignee'] = dict(u)
    rate, solved, total = resolution_rate(t['assigned_to']) if t['assigned_to'] else (0, 0, 0)
    d['assignee_rate'] = round(rate, 2)
    d['technique'] = None
    if t.get('technique_id'):
        with get_db() as conn:
            tec = conn.execute('SELECT * FROM techniques WHERE id=?',
                               (t['technique_id'],)).fetchone()
        if tec:
            d['technique'] = dict(tec)
    return d


# ---------------------------------------------------------------------------
# Security audit trail (Feature 9) - append-only, immutable for normal users.
# ---------------------------------------------------------------------------
def audit(user_id, action, detail, ip='', resource='', resource_id='',
          old_value=None, new_value=None, result='success'):
    """Record one audit event. Never raises into business logic."""
    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO audit (user_id, action, detail, at, ip, resource, '
                'resource_id, old_value, new_value, result) VALUES (?,?,?,?,?,?,?,?,?,?)',
                (user_id, action, detail, _now(), ip or '', resource or '',
                 str(resource_id or ''), old_value, new_value, result))
    except Exception:
        import logging
        logging.getLogger(__name__).exception('audit insert failed')


# ---------------------------------------------------------------------------
# Notification bridge (Feature 11): portal events -> ES request docs ->
# worker drain task -> provider abstraction. The portal itself never talks
# to Telegram/SMTP.
# ---------------------------------------------------------------------------
NOTIFY_INDEX = 'notification-requests'


def enqueue_notification(event, payload):
    """Write a notification request doc; best-effort, never blocks."""
    import requests
    from .esdata import ES_PASSWORD, ES_URL, ES_USER
    doc = {
        'source': 'voc_notify',
        '@timestamp': _now(),
        'requested_at': _now(),
        'state': 'pending',
        'event': event,
        'payload': payload,
    }
    try:
        r = requests.post(f'{ES_URL}/{NOTIFY_INDEX}/_doc?refresh=false',
                          auth=(ES_USER, ES_PASSWORD), json=doc, timeout=10)
        return r.status_code in (200, 201)
    except Exception:
        return False


def notify_assignment(ticket_id, severity, reason):
    """Queue a ticket-assigned notification with assignee context."""
    with get_db() as conn:
        t = conn.execute(
            'SELECT t.id, t.title, t.severity, t.sla_deadline, t.assigned_to, '
            'u.username AS assignee FROM tickets t LEFT JOIN users u '
            'ON u.id = t.assigned_to WHERE t.id=?', (ticket_id,)).fetchone()
    if not t or not t['assigned_to']:
        return
    enqueue_notification('ticket_assigned', {
        'ticket_id': t['id'], 'title': t['title'], 'severity': t['severity'],
        'assignee': t['assignee'] or '?', 'reason': reason,
        'sla_deadline': t['sla_deadline'] or 'n/a',
    })


# ---------------------------------------------------------------------------
# Verification bridge (Feature 6): portal marks remediated -> verification
# request doc; worker sweep re-scans and writes a result doc; the portal
# picks results up lazily via sync_verification_results().
# ---------------------------------------------------------------------------
VERIFY_REQ_INDEX = 'verification-requests'


def request_verification(ticket):
    """Enqueue a verification scan request for a remediated ticket."""
    import requests
    from .esdata import ES_PASSWORD, ES_URL, ES_USER
    t = dict(ticket) if not isinstance(ticket, dict) else ticket
    doc = {
        'source': 'voc_verification',
        '@timestamp': _now(),
        'requested_at': _now(),
        'state': 'pending',
        'attempts': 0,
        'ticket_id': t['id'],
        'cve': t['cve'],
        'host': t['host'],
        'port': (t.get('finding_key') or '').split('|')[-1] if t.get('finding_key') else '',
        'scanner': os.getenv('VERIFICATION_SCANNER', 'nmap'),
    }
    try:
        r = requests.post(f'{ES_URL}/{VERIFY_REQ_INDEX}/_doc',
                          auth=(ES_USER, ES_PASSWORD), json=doc, timeout=10)
        return r.status_code in (200, 201)
    except Exception:
        return False


def sync_verification_results():
    """Apply finished verification results to portal tickets (lazy sync).

    Called from dashboard/ticket-list endpoints; cheap when there is nothing
    to apply (single small ES query).
    """
    import requests
    from .esdata import ES_PASSWORD, ES_URL, ES_USER
    applied = {'verified': 0, 'reopened': 0}
    try:
        r = requests.post(f'{ES_URL}/verification-results/_search?size=25&sort=_doc',
                          auth=(ES_USER, ES_PASSWORD),
                          json={'query': {'bool': {'must_not': [
                              {'term': {'applied': True}}]}}},
                          timeout=10)
        r.raise_for_status()
        hits = r.json().get('hits', {}).get('hits', [])
    except Exception:
        return applied

    for h in hits:
        res = h.get('_source', {})
        tid = res.get('ticket_id')
        outcome = res.get('outcome')
        if not tid:
            continue
        with get_db() as conn:
            t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
            if not t:
                continue
            now = _now()
            if outcome == 'verified':
                conn.execute(
                    'UPDATE tickets SET status="solved", solved_at=?, resolved_by="scanner", '
                    'verification_state="verified", verification_scan_id=?, verification_at=?, '
                    'sla_status=CASE WHEN sla_status="breached" THEN "breached" '
                    'WHEN julianday(?) <= julianday(sla_deadline) THEN "completed" '
                    'ELSE "breached" END WHERE id=?',
                    (res.get('finished_at') or now, res.get('verification_scan_id'),
                     res.get('finished_at') or now, res.get('finished_at') or now, tid))
                enqueue_notification('vuln_resolved', {
                    'ticket_id': tid, 'cve': t['cve'], 'host': t['host'],
                    'detail': res.get('detail', ''),
                })
                applied['verified'] += 1
            elif outcome == 'reopen':
                conn.execute(
                    'UPDATE tickets SET status="reopened", solved_at=NULL, remediated_at=NULL, '
                    'resolved_by="", reopened_count=reopened_count+1, '
                    'verification_state="failed", verification_scan_id=?, verification_at=? '
                    'WHERE id=?',
                    (res.get('verification_scan_id'), res.get('finished_at') or now, tid))
                enqueue_notification('vuln_reopened', {
                    'ticket_id': tid, 'cve': t['cve'], 'host': t['host'],
                    'detail': res.get('detail', ''),
                })
                applied['reopened'] += 1
        # mark result as consumed
        try:
            requests.post(f'{ES_URL}/verification-results/_update/{h["_id"]}',
                          auth=(ES_USER, ES_PASSWORD), json={'doc': {'applied': True}},
                          timeout=10)
        except Exception:
            pass
    return applied
