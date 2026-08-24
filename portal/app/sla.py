"""SLA management (Feature 7).

Deadlines are computed at ticket creation from the severity, using env-
configurable hour budgets (no hard-coding in business logic):

    SLA_CRITICAL_HOURS (default 24)
    SLA_HIGH_HOURS     (default 72)
    SLA_MEDIUM_HOURS   (default 168  = 7 days)
    SLA_LOW_HOURS      (default 720  = 30 days)

States:
    ON_TRACK   - comfortably before the deadline
    DUE_SOON   - within SLA_DUE_SOON_HOURS of the deadline (default 24h)
    OVERDUE    - past the deadline and not resolved
    PAUSED     - reserved for future workflow needs (never set automatically)
    COMPLETED  - resolved within the deadline
    BREACHED   - resolved after the deadline (kept for honest metrics)

The hourly beat-equivalent sweep runs lazily inside portal requests
(sync_sla_states) so no extra container/queue is required.
"""
import os
from datetime import datetime, timedelta, timezone

from .db import get_db

DEFAULT_SLA_HOURS = {
    'critical': float(os.getenv('SLA_CRITICAL_HOURS', '24')),
    'high': float(os.getenv('SLA_HIGH_HOURS', '72')),
    'medium': float(os.getenv('SLA_MEDIUM_HOURS', '168')),
    'low': float(os.getenv('SLA_LOW_HOURS', '720')),
}
DUE_SOON_HOURS = float(os.getenv('SLA_DUE_SOON_HOURS', '24'))

# Ticket statuses that mean "work finished" for SLA purposes.
RESOLVED_STATUSES = ('solved', 'closed')


def sla_hours(severity):
    return DEFAULT_SLA_HOURS.get((severity or '').lower(), DEFAULT_SLA_HOURS['medium'])


def compute_deadline(severity, created_at=None):
    """ISO deadline for a ticket created at created_at (default: now)."""
    base = datetime.fromisoformat(created_at) if created_at else datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return (base + timedelta(hours=sla_hours(severity))).isoformat(timespec='seconds')


def _parse(ts):
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def remaining_hours(deadline_ts, now=None):
    dl = _parse(deadline_ts)
    if not dl:
        return None
    now = now or datetime.now(timezone.utc)
    return (dl - now).total_seconds() / 3600.0


def status_for(deadline_ts, resolved=False, resolved_in_hours=None):
    rem = remaining_hours(deadline_ts)
    if resolved:
        if resolved_in_hours is None:
            return 'COMPLETED'
        return 'COMPLETED' if resolved_in_hours >= 0 else 'BREACHED'
    if rem is None:
        return 'ON_TRACK'
    if rem < 0:
        return 'OVERDUE'
    if rem <= DUE_SOON_HOURS:
        return 'DUE_SOON'
    return 'ON_TRACK'


def sync_sla_states():
    """Recompute sla_status for every open ticket; returns counts."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, severity, sla_deadline FROM tickets "
            "WHERE sla_deadline IS NOT NULL AND status NOT IN ('solved','closed')").fetchall()
        counts = {'ON_TRACK': 0, 'DUE_SOON': 0, 'OVERDUE': 0}
        for r in rows:
            st = status_for(r['sla_deadline'], resolved=False)
            counts[st] = counts.get(st, 0) + 1
            conn.execute('UPDATE tickets SET sla_status=? WHERE id=?', (st.lower(), r['id']))
    return counts


def metrics():
    """Dashboard SLA metrics block."""
    with get_db() as conn:
        total_resolved = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE solved_at IS NOT NULL").fetchone()['c']
        breached = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE sla_status='breached'").fetchone()['c']
        completed = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE sla_status IN ('completed') OR "
            "(solved_at IS NOT NULL AND sla_status NOT IN ('breached'))").fetchone()['c']
        overdue = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE sla_status='overdue' "
            "AND status != 'solved' AND status != 'closed'").fetchone()['c']
        due24 = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE sla_status='due_soon' "
            "AND status != 'solved' AND status != 'closed'").fetchone()['c']
        due72 = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE sla_status='on_track' "
            "AND sla_deadline IS NOT NULL "
            "AND julianday(sla_deadline) <= julianday('now') + 3.0 "
            "AND status != 'solved' AND status != 'closed'").fetchone()['c']
        open_cnt = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE status NOT IN ('solved','closed')").fetchone()['c']
        avg_mttr = conn.execute(
            "SELECT AVG(julianday(solved_at) - julianday(created_at)) * 24.0 AS h "
            "FROM tickets WHERE solved_at IS NOT NULL").fetchone()['h']

    compliance = round(100.0 * completed / max(completed + breached, 1), 1)
    return {
        'open_tickets': open_cnt,
        'overdue': overdue,
        'due_within_24h': due24,
        'due_within_72h': due72,
        'resolved_total': total_resolved,
        'breached_total': breached,
        'sla_compliance_pct': compliance,
        'avg_remediation_hours': round(avg_mttr, 1) if avg_mttr is not None else None,
    }
