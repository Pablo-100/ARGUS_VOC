"""VOC Portal - the single entry point for the whole SOC platform.

Users have roles (admin / voc / soc3 / soc2 / soc1 / noc). Tickets come from
the admin or are auto-imported from the vulnerability pipeline. New tickets
are auto-assigned by the smart-routing rule (>50% resolution rate). A ticket
can only become 'solved' after a scanner-verified re-scan confirms the
vulnerability is gone - a user click marks it 'remediated' and schedules the
verification scan (Feature 6). Every ticket carries an SLA deadline computed
from its severity (Feature 7).
"""
import json
import os
import time
from pathlib import Path

import requests
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import esdata, provision, roles, sla, tickets
from .auth import decode_token, hash_password, make_token, verify_password
from .db import get_db
from .deps import current_user, require_cap
from .roles import has_cap, valid_role
from .routes_assets import router as assets_router
from .routes_glpi import router as glpi_router
from .routes_infra import router as infra_router
from .routes_misp import router as misp_router
from .routes_endpoints import router as endpoints_router
from .routes_endpoints import router as endpoints_router
from .routes_intel import router as intel_router
from .routes_tools import router as tools_router
from .routes_vulns import router as vulns_router
from .seed import import_auto_tickets, seed, seed_users, technique_for_cve

app = FastAPI(title='VOC Portal', version='2.0.0')
STATIC = Path(__file__).parent / 'static'

app.mount('/static', StaticFiles(directory=str(STATIC)), name='static')
app.include_router(misp_router)
app.include_router(glpi_router)
app.include_router(infra_router)
app.include_router(vulns_router)
app.include_router(tools_router)
app.include_router(endpoints_router)
app.include_router(intel_router)
app.include_router(assets_router)


# ---------------------------------------------------------------------------
# Security headers on every response (Feature 16/20).
# ---------------------------------------------------------------------------
@app.middleware('http')
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'")
    return response


# ---------------------------------------------------------------------------
# Brute-force protection for /api/login (in-memory sliding window; adequate
# for the single-replica lab deployment, documented for production IdP swap).
# ---------------------------------------------------------------------------
LOGIN_MAX_ATTEMPTS = int(os.getenv('LOGIN_MAX_ATTEMPTS', '5'))
LOGIN_LOCKOUT_SECONDS = int(os.getenv('LOGIN_LOCKOUT_SECONDS', '900'))
_login_failures = {}  # key -> list of failure timestamps


def _client_ip(request: Request) -> str:
    fwd = request.headers.get('x-forwarded-for')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.client.host if request.client else ''


def _login_locked(ip, username):
    key = f'{ip}|{username}'
    now = time.time()
    fails = [t for t in _login_failures.get(key, []) if now - t < LOGIN_LOCKOUT_SECONDS]
    _login_failures[key] = fails
    return len(fails) >= LOGIN_MAX_ATTEMPTS


def _record_login_failure(ip, username):
    key = f'{ip}|{username}'
    _login_failures.setdefault(key, []).append(time.time())


def _safe_user(u, with_provision=True):
    """Never leak the plaintext platform password used for SSO URLs."""
    d = dict(u)
    d.pop('platform_pass', None)
    if with_provision:
        try:
            d['provision'] = json.loads(d.get('provision') or '{}')
        except Exception:
            d['provision'] = {}
    return d


@app.get('/')
def index():
    return FileResponse(STATIC / 'index.html')


@app.post('/api/login')
def login(body: dict, request: Request = None):
    username = ((body.get('username') or '').strip())[:64]
    password = body.get('password') or ''
    ip = _client_ip(request) if request else ''

    if _login_locked(ip, username):
        tickets.audit(None, 'login.locked_out', f'user={username}', ip=ip,
                      resource='session', result='locked')
        raise HTTPException(429, 'Too many failed attempts - try again later')

    with get_db() as conn:
        u = conn.execute('SELECT * FROM users WHERE username=? AND active=1',
                         (username,)).fetchone()
    if not u or not verify_password(password, u['password_hash']):
        _record_login_failure(ip, username)
        tickets.audit(None, 'login.failed', f'user={username}', ip=ip,
                      resource='session', result='failure')
        raise HTTPException(401, 'Invalid credentials')

    _login_failures.pop(f'{ip}|{username}', None)
    token = make_token(u['id'], u['username'], u['role'])
    tickets.audit(u['id'], 'login.success', f'user={u["username"]}', ip=ip,
                  resource='session')
    return {'token': token, 'user': _safe_user(u)}


ROLE_PRIVILEGES = {}


@app.get('/api/me')
def me(user=Depends(current_user)):
    out = _safe_user(user)
    out['role_label'] = roles.role_label(user['role'])
    out['caps'] = roles.effective_caps(user)
    out['grants'] = roles.grants_for(user)
    out['privileges'] = roles.privileges(user)
    out['access'] = provision.access_list(user['username'], user.get('platform_pass'))
    return out


@app.put('/api/me')
def update_me(body: dict, user=Depends(current_user)):
    with get_db() as conn:
        full_name = (body.get('full_name') or user['full_name']).strip()
        conn.execute('UPDATE users SET full_name=? WHERE id=?', (full_name, user['id']))
    tickets.audit(user['id'], 'me.update', 'profile updated')
    return {'ok': True, 'full_name': full_name}


@app.post('/api/me/password')
def change_password(body: dict, user=Depends(current_user)):
    current = body.get('current_password') or ''
    new = body.get('new_password') or ''
    if len(new) < 6:
        raise HTTPException(400, 'new password (>=6 chars) required')
    with get_db() as conn:
        u = conn.execute('SELECT * FROM users WHERE id=?', (user['id'],)).fetchone()
        if not verify_password(current, u['password_hash']):
            raise HTTPException(400, 'current password is incorrect')
        conn.execute('UPDATE users SET password_hash=?, platform_pass=? WHERE id=?',
                     (hash_password(new), new, user['id']))
    res = provision.provision_user(u['username'], new, u['full_name'],
                                   u['role'], bool(u['active']))
    with get_db() as conn:
        conn.execute('UPDATE users SET provision=? WHERE id=?',
                     (json.dumps(res), user['id']))
    tickets.audit(user['id'], 'me.password', 'password changed + rotated to all platforms')
    return {'ok': True, 'provision': res}


@app.get('/api/dashboard')
def dashboard(user=Depends(current_user)):
    tickets.sync_verification_results()   # lazy-apply scanner verification outcomes
    sla.sync_sla_states()
    widgets = esdata.dashboard_widgets()
    widgets['sla'] = sla.metrics()
    with get_db() as conn:
        recent = conn.execute(
            'SELECT * FROM tickets ORDER BY id DESC LIMIT 8').fetchall()
        open_cnt = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE status NOT IN ('solved','closed')").fetchone()['c']
        solved_cnt = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE status='solved'").fetchone()['c']
        queue = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE assigned_to IS NULL "
            "AND status NOT IN ('solved','closed')").fetchone()['c']
        remediated = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE status='remediated'").fetchone()['c']
        reopened_cnt = conn.execute(
            "SELECT COUNT(*) c FROM tickets WHERE status='reopened'").fetchone()['c']
    widgets['tickets'] = {
        'open': open_cnt, 'solved': solved_cnt, 'queue': queue,
        'remediated': remediated, 'reopened': reopened_cnt,
        'recent': [tickets.ticket_payload(dict(t)) for t in recent],
    }
    with get_db() as conn:
        widgets['attack'] = [dict(a) for a in conn.execute(
            'SELECT t.id, t.name, t.tactic, COUNT(tk.id) AS c '
            'FROM techniques t LEFT JOIN tickets tk '
            'ON tk.technique_id=t.id AND tk.status!="solved" '
            'GROUP BY t.id HAVING c > 0 ORDER BY c DESC LIMIT 8').fetchall()]
    return widgets


@app.get('/api/roles')
def list_roles(user=Depends(current_user)):
    require_cap(user, 'roles.manage')
    return roles.list_roles_db()


@app.post('/api/roles')
def create_role(body: dict, user=Depends(current_user), request: Request = None):
    require_cap(user, 'roles.manage')
    name = (body.get('name') or '').strip().lower()
    label = (body.get('label') or '').strip() or name.title()
    caps = [c for c in (body.get('caps') or []) if c in roles.ALL_CAPS]
    import re as _re
    if not _re.fullmatch(r'[a-z0-9][a-z0-9_-]{1,31}', name):
        raise HTTPException(400, 'role name must be 2-32 chars: a-z 0-9 _ -')
    if roles.valid_role(name):
        raise HTTPException(409, f'role {name!r} already exists')
    from .db import get_db
    with get_db() as conn:
        conn.execute('INSERT INTO roles (name, label, builtin, caps) VALUES (?,?,0,?)',
                     (name, label, json.dumps(caps)))
    tickets.audit(user['id'], 'role.create', f'{name} ({len(caps)} caps)',
                  ip=_client_ip(request) if request else '', resource='role',
                  resource_id=name, new_value=json.dumps(caps))
    return {'ok': True, 'name': name}


@app.put('/api/roles/{rid}')
def update_role(rid: int, body: dict, user=Depends(current_user), request: Request = None):
    require_cap(user, 'roles.manage')
    from .db import get_db
    with get_db() as conn:
        row = conn.execute('SELECT * FROM roles WHERE id=?', (rid,)).fetchone()
        if not row:
            raise HTTPException(404, 'role not found')
        if row['builtin']:
            # anti-lockout: built-in roles are immutable through the API
            raise HTTPException(400, 'built-in roles cannot be modified - '
                                     'clone it as a custom role instead')
        old_caps = row['caps']
        label = (body.get('label') or row['label']).strip()
        caps = [c for c in (body.get('caps') if 'caps' in body else json.loads(row['caps'] or '[]'))
                if c in roles.ALL_CAPS]
        conn.execute('UPDATE roles SET label=?, caps=? WHERE id=?',
                     (label, json.dumps(caps), rid))
    tickets.audit(user['id'], 'role.update', f'{row["name"]} ({len(caps)} caps)',
                  ip=_client_ip(request) if request else '', resource='role',
                  resource_id=row['name'], old_value=old_caps, new_value=json.dumps(caps))
    return {'ok': True}


@app.delete('/api/roles/{rid}')
def delete_role(rid: int, user=Depends(current_user), request: Request = None):
    require_cap(user, 'roles.manage')
    from .db import get_db
    with get_db() as conn:
        row = conn.execute('SELECT * FROM roles WHERE id=?', (rid,)).fetchone()
        if not row:
            raise HTTPException(404, 'role not found')
        if row['builtin']:
            raise HTTPException(400, 'built-in roles cannot be deleted')
        users_on_role = conn.execute('SELECT COUNT(*) c FROM users WHERE role=?',
                                     (row['name'],)).fetchone()['c']
        if users_on_role:
            raise HTTPException(409, f'role still assigned to {users_on_role} user(s) - '
                                     f'reassign them first')
        conn.execute('DELETE FROM roles WHERE id=?', (rid,))
    tickets.audit(user['id'], 'role.delete', f'{row["name"]}',
                  ip=_client_ip(request) if request else '', resource='role',
                  resource_id=row['name'], old_value=row['caps'])
    return {'ok': True}


@app.get('/api/roles/catalog')
def caps_catalog(user=Depends(current_user)):
    """Full capability catalog grouped for the matrix editor."""
    require_cap(user, 'roles.manage')
    return {'groups': roles.CAP_GROUPS,
            'meta': roles.CAP_META,
            'all_caps': roles.ALL_CAPS}


@app.get('/api/tickets')
def list_tickets(scope: str = 'all', user=Depends(current_user)):
    tickets.sync_verification_results()   # lazy-apply scanner verification outcomes
    with get_db() as conn:
        if scope == 'mine':
            rows = conn.execute(
                'SELECT * FROM tickets WHERE assigned_to=? ORDER BY '
                'CASE severity WHEN "critical" THEN 0 WHEN "high" THEN 1 '
                'WHEN "medium" THEN 2 ELSE 3 END, id DESC', (user['id'],)).fetchall()
        else:
            require_cap(user, 'tickets.view_all')
            rows = conn.execute('SELECT * FROM tickets ORDER BY id DESC LIMIT 500').fetchall()
    return [tickets.ticket_payload(dict(t)) for t in rows]


@app.post('/api/tickets')
def create_ticket(body: dict, user=Depends(current_user), request: Request = None):
    require_cap(user, 'tickets.create')
    title = (body.get('title') or '').strip()
    if not title:
        raise HTTPException(400, 'title required')
    severity = (body.get('severity') or 'medium').lower()
    if severity not in ('critical', 'high', 'medium', 'low'):
        severity = 'medium'
    assignee = body.get('assignee_id')
    technique = body.get('technique_id')
    if not technique:
        technique = technique_for_cve(body.get('cve'))
    deadline = sla.compute_deadline(severity)
    with get_db() as conn:
        if technique and not conn.execute('SELECT 1 FROM techniques WHERE id=?',
                                          (technique,)).fetchone():
            raise HTTPException(400, 'unknown technique')
        cur = conn.execute(
            'INSERT INTO tickets (title, description, severity, source, cve, host, port, '
            'cvss, risk_score, assigned_to, assigned_at, est_hours, technique_id, '
            'sla_deadline, finding_key) '
            'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (title, body.get('description') or '', severity, 'admin',
             body.get('cve'), body.get('host'), body.get('port'), body.get('cvss'),
             body.get('risk_score'),
             assignee, None, None, technique,
             deadline,
             (f"{body.get('host')}|{body.get('cve')}|{body.get('port')}"
              if body.get('cve') else None)))
        ticket_id = cur.lastrowid
    tickets.audit(user['id'], 'ticket.create', f'#{ticket_id} {title}',
                  ip=_client_ip(request) if request else '',
                  resource='ticket', resource_id=ticket_id,
                  new_value=f'severity={severity} sla_deadline={deadline}')
    if assignee is None:
        tickets.assign_ticket(ticket_id)  # auto-assign via the smart-routing rule
    else:
        with get_db() as conn:
            conn.execute('UPDATE tickets SET assigned_at=?, est_hours=?, assignment_reason=? '
                         'WHERE id=?',
                         (tickets._now(), tickets.estimate_hours(severity, assignee),
                          f'manually assigned by {user["username"]}', ticket_id))
            conn.execute('UPDATE tickets SET status="assigned" WHERE id=?', (ticket_id,))
        tickets.notify_assignment(ticket_id, severity,
                                  f'manually assigned by {user["username"]}')
    return {'id': ticket_id}


@app.post('/api/tickets/{tid}/assign')
def assign_ticket(tid: int, body: dict, user=Depends(current_user), request: Request = None):
    require_cap(user, 'tickets.assign')
    with get_db() as conn:
        t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
        if not t:
            raise HTTPException(404, 'ticket not found')
        if not conn.execute('SELECT 1 FROM users WHERE id=? AND active=1',
                            (body['user_id'],)).fetchone():
            raise HTTPException(400, 'unknown or inactive user')
        reason = f'manually assigned by {user["username"]}'
        conn.execute(
            'UPDATE tickets SET assigned_to=?, assigned_at=?, est_hours=?, assignment_reason=?, '
            'status="assigned" WHERE id=?',
            (body['user_id'], tickets._now(),
             tickets.estimate_hours(t['severity'], body['user_id']), reason, tid))
    tickets.audit(user['id'], 'ticket.assign', f'#{tid} -> user {body["user_id"]}',
                  ip=_client_ip(request), resource='ticket', resource_id=tid,
                  old_value=str(t['assigned_to']), new_value=str(body['user_id']))
    tickets.notify_assignment(tid, t['severity'], reason)
    return {'ok': True}


@app.post('/api/tickets/{tid}/start')
def start_ticket(tid: int, user=Depends(current_user), request: Request = None):
    with get_db() as conn:
        t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
        if not t:
            raise HTTPException(404, 'ticket not found')
        if t['assigned_to'] != user['id']:
            raise HTTPException(403, 'Not your ticket')
        conn.execute('UPDATE tickets SET status="in_progress" WHERE id=?', (tid,))
    tickets.audit(user['id'], 'ticket.start', f'#{tid}',
                  ip=_client_ip(request), resource='ticket', resource_id=tid,
                  old_value=t['status'], new_value='in_progress')
    return {'ok': True}


@app.post('/api/tickets/{tid}/solve')
def solve_ticket(tid: int, user=Depends(current_user), request: Request = None):
    """Remediation claim (Feature 6): a click here does NOT resolve the
    ticket. It marks it remediated and schedules a verification re-scan.
    Only a scanner-verified absence of the CVE resolves the ticket."""
    with get_db() as conn:
        t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
        if not t:
            raise HTTPException(404, 'ticket not found')
        if t['assigned_to'] != user['id']:
            raise HTTPException(403, 'Not your ticket')
        if t['status'] in ('remediated', 'rescan_pending'):
            raise HTTPException(400, 'verification already pending for this ticket')
        conn.execute(
            'UPDATE tickets SET status="remediated", remediated_at=?, '
            'verification_state="requested" WHERE id=?',
            (tickets._now(), tid))
    queued = tickets.request_verification(t)
    tickets.audit(user['id'], 'ticket.remediate', f'#{tid} - verification '
                  f'{"queued" if queued else "queue-unavailable"}',
                  ip=_client_ip(request), resource='ticket', resource_id=tid,
                  old_value=t['status'], new_value='remediated')
    assigned = tickets.rebalance_unassigned()
    return {'ok': True,
            'state': 'verification_pending',
            'message': ('Remediation recorded. The vulnerability is NOT yet resolved - '
                        'a verification scan has been scheduled and the ticket will be '
                        'closed automatically once the scanner confirms the CVE is gone.'),
            'auto_assigned': assigned}


@app.post('/api/tickets/{tid}/close')
def close_ticket(tid: int, body: dict, user=Depends(current_user), request: Request = None):
    """Explicit override closure (admin/soc3 only). Audited and clearly
    marked as admin_override - never presented as scanner-verified."""
    require_cap(user, 'tickets.verify_force')
    with get_db() as conn:
        t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
        if not t:
            raise HTTPException(404, 'ticket not found')
        reason = (body.get('reason') or '').strip()
        if not reason:
            raise HTTPException(400, 'reason required for override closure')
        conn.execute(
            'UPDATE tickets SET status="solved", solved_at=?, resolved_by="admin_override", '
            'verification_state="override" WHERE id=?', (tickets._now(), tid))
    tickets.audit(user['id'], 'ticket.close_override', f'#{tid}: {reason}',
                  ip=_client_ip(request), resource='ticket', resource_id=tid,
                  old_value=t['status'], new_value='solved(admin_override)')
    assigned = tickets.rebalance_unassigned()
    return {'ok': True, 'auto_assigned': assigned}


@app.post('/api/tickets/{tid}/reopen')
def reopen_ticket(tid: int, user=Depends(current_user), request: Request = None):
    require_cap(user, 'tickets.reopen')
    with get_db() as conn:
        t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
        if not t:
            raise HTTPException(404, 'ticket not found')
        conn.execute('UPDATE tickets SET status="reopened", solved_at=NULL, '
                     'remediated_at=NULL WHERE id=?', (tid,))
    tickets.audit(user['id'], 'ticket.reopen', f'#{tid}',
                  ip=_client_ip(request), resource='ticket', resource_id=tid,
                  old_value=t['status'], new_value='reopened')
    return {'ok': True}


@app.put('/api/tickets/{tid}')
def update_ticket(tid: int, body: dict, user=Depends(current_user)):
    require_cap(user, 'tickets.edit')
    with get_db() as conn:
        t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
        if not t:
            raise HTTPException(404, 'ticket not found')
        title = (body.get('title') or '').strip() or t['title']
        severity = (body.get('severity') or t['severity']).lower()
        if severity not in ('critical', 'high', 'medium', 'low'):
            severity = t['severity']
        technique = body.get('technique_id', t['technique_id'])
        if technique and not conn.execute('SELECT 1 FROM techniques WHERE id=?',
                                          (technique,)).fetchone():
            raise HTTPException(400, 'unknown technique')
        conn.execute(
            'UPDATE tickets SET title=?, severity=?, description=?, cve=?, host=?, '
            'cvss=?, risk_score=?, technique_id=? WHERE id=?',
            (title, severity, body.get('description', t['description']),
             body.get('cve', t['cve']), body.get('host', t['host']),
             body.get('cvss', t['cvss']), body.get('risk_score', t['risk_score']),
             technique, tid))
        if 'assignee_id' in body:
            assignee = body.get('assignee_id')
            if assignee is not None and not conn.execute(
                    'SELECT 1 FROM users WHERE id=?', (assignee,)).fetchone():
                raise HTTPException(400, 'unknown assignee')
            if assignee is None:
                conn.execute('UPDATE tickets SET assigned_to=NULL, assigned_at=NULL, '
                             'est_hours=NULL, status="open" WHERE id=?', (tid,))
            else:
                conn.execute('UPDATE tickets SET assigned_to=?, assigned_at=?, est_hours=?, '
                             'status=CASE WHEN status="open" THEN "assigned" ELSE status END '
                             'WHERE id=?', (assignee, tickets._now(),
                                            tickets.estimate_hours(severity, assignee), tid))
    tickets.audit(user['id'], 'ticket.update', f'#{tid}')
    return {'ok': True}


@app.delete('/api/tickets/{tid}')
def delete_ticket(tid: int, user=Depends(current_user)):
    require_cap(user, 'tickets.delete')
    with get_db() as conn:
        t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
        if not t:
            raise HTTPException(404, 'ticket not found')
        conn.execute('DELETE FROM tickets WHERE id=?', (tid,))
    tickets.audit(user['id'], 'ticket.delete', f'#{tid} {t["title"]}')
    return {'ok': True}


@app.post('/api/sync')
def sync_auto(user=Depends(current_user)):
    require_cap(user, 'tickets.import')
    n = import_auto_tickets()
    assigned = tickets.rebalance_unassigned()
    tickets.audit(user['id'], 'tickets.sync', f'imported {n}, auto-assigned {sum(1 for a in assigned if a)}')
    return {'imported': n, 'auto_assigned': sum(1 for a in assigned if a)}


@app.get('/api/users')
def list_users(user=Depends(current_user)):
    require_cap(user, 'users.manage')
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM users ORDER BY id').fetchall()
    out = []
    for u in rows:
        d = _safe_user(u)
        rate, solved, total = tickets.resolution_rate(u['id'])
        d['resolution_rate'] = round(rate, 2)
        d['solved'] = solved
        d['total_assigned'] = total
        d['open'] = tickets.open_load(u['id'])
        d['grants'] = roles.grants_for(d)
        d['role_label'] = roles.role_label(d['role'])
        out.append(d)
    return out


@app.post('/api/users')
def create_user(body: dict, user=Depends(current_user)):
    require_cap(user, 'users.manage')
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    role = body.get('role') or 'soc1'
    if not username or len(password) < 6:
        raise HTTPException(400, 'username and password (>=6 chars) required')
    if not valid_role(role):
        raise HTTPException(400, 'bad role')
    grants = json.dumps([g for g in (body.get('grants') or []) if g in roles.ALL_CAPS])
    full_name = body.get('full_name') or username
    with get_db() as conn:
        if conn.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
            raise HTTPException(409, 'username exists')
        conn.execute(
            'INSERT INTO users (username, password_hash, platform_pass, full_name, role, grants) VALUES (?,?,?,?,?,?)',
            (username, hash_password(password), password, full_name, role, grants))
        uid = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()['id']
    res = provision.provision_user(username, password, full_name, role, True)
    with get_db() as conn:
        conn.execute('UPDATE users SET provision=? WHERE id=?', (json.dumps(res), uid))
    tickets.audit(user['id'], 'user.create', f'{username} -> {role} ({len([r for r in res.values() if r.get("ok")])}/4 platforms)')
    return {'ok': True, 'provision': res}


@app.post('/api/users/{uid}/toggle')
def toggle_user(uid: int, user=Depends(current_user)):
    require_cap(user, 'users.manage')
    if uid == user['id']:
        raise HTTPException(400, 'cannot disable yourself')
    with get_db() as conn:
        conn.execute('UPDATE users SET active = 1 - active WHERE id=?', (uid,))
        u = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    res = provision.provision_user(u['username'], u['platform_pass'], u['full_name'],
                                   u['role'], bool(u['active']))
    with get_db() as conn:
        conn.execute('UPDATE users SET provision=? WHERE id=?', (json.dumps(res), uid))
    tickets.audit(user['id'], 'user.toggle',
                  f'user {uid} {"disabled" if not u["active"] else "enabled"} on all platforms')
    return {'ok': True, 'provision': res}


@app.put('/api/users/{uid}')
def update_user(uid: int, body: dict, user=Depends(current_user)):
    require_cap(user, 'users.manage')
    if uid == user['id'] and body.get('role') not in (None, user['role']):
        raise HTTPException(400, 'cannot change your own role')
    with get_db() as conn:
        u = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        if not u:
            raise HTTPException(404, 'user not found')
        role = body.get('role') or u['role']
        if not valid_role(role):
            raise HTTPException(400, 'bad role')
        grants = u['grants'] if 'grants' not in body else json.dumps(
            [g for g in (body.get('grants') or []) if g in roles.ALL_CAPS])
        conn.execute('UPDATE users SET full_name=?, role=?, grants=? WHERE id=?',
                     (body.get('full_name', u['full_name']), role, grants, uid))
    if role != u['role']:
        res = provision.provision_user(u['username'], u['platform_pass'],
                                       body.get('full_name', u['full_name']),
                                       role, bool(u['active']))
        with get_db() as conn:
            conn.execute('UPDATE users SET provision=? WHERE id=?', (json.dumps(res), uid))
    tickets.audit(user['id'], 'user.update', f'user {uid} -> {role}')
    return {'ok': True}


@app.post('/api/users/{uid}/password')
def reset_password(uid: int, body: dict, user=Depends(current_user)):
    require_cap(user, 'users.manage')
    password = body.get('password') or ''
    if len(password) < 6:
        raise HTTPException(400, 'password (>=6 chars) required')
    with get_db() as conn:
        if not conn.execute('SELECT 1 FROM users WHERE id=?', (uid,)).fetchone():
            raise HTTPException(404, 'user not found')
        u = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        conn.execute('UPDATE users SET password_hash=?, platform_pass=? WHERE id=?',
                     (hash_password(password), password, uid))
    res = provision.provision_user(u['username'], password, u['full_name'],
                                   u['role'], bool(u['active']))
    with get_db() as conn:
        conn.execute('UPDATE users SET provision=? WHERE id=?', (json.dumps(res), uid))
    tickets.audit(user['id'], 'user.password', f'user {uid} password reset + rotated to all platforms')
    return {'ok': True, 'provision': res}


@app.delete('/api/users/{uid}')
def delete_user(uid: int, user=Depends(current_user)):
    require_cap(user, 'users.manage')
    if uid == user['id']:
        raise HTTPException(400, 'cannot delete yourself')
    with get_db() as conn:
        u = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        if not u:
            raise HTTPException(404, 'user not found')
        if u['role'] == 'admin':
            admins = conn.execute('SELECT COUNT(*) c FROM users '
                                  'WHERE role="admin" AND active=1').fetchone()['c']
            if admins <= 1:
                raise HTTPException(400, 'cannot delete the last admin')
        tickets.unassign_user(uid, conn)
        conn.execute('DELETE FROM users WHERE id=?', (uid,))
    dep = provision.deprovision_user(u['username'])
    tickets.audit(user['id'], 'user.delete', f'user {uid} {u["username"]} '
                  f'(platforms removed: {len([r for r in dep.values() if r.get("ok")])}/4)')
    return {'ok': True, 'deprovision': dep}


@app.post('/api/logout')
def logout(user=Depends(current_user), request: Request = None):
    tickets.audit(user['id'], 'logout', f'user={user["username"]}',
                  ip=_client_ip(request), resource='session')
    return {'ok': True}


@app.get('/api/audit')
def audit_trail(action: str = '', limit: int = 200, user=Depends(current_user)):
    """Immutable security audit trail (Feature 9). Admin-only."""
    require_cap(user, 'audit.view')
    limit = max(1, min(limit, 1000))
    with get_db() as conn:
        if action:
            rows = conn.execute(
                'SELECT a.*, u.username FROM audit a LEFT JOIN users u ON u.id=a.user_id '
                'WHERE a.action LIKE ? ORDER BY a.id DESC LIMIT ?',
                (f'%{action}%', limit)).fetchall()
        else:
            rows = conn.execute(
                'SELECT a.*, u.username FROM audit a LEFT JOIN users u ON u.id=a.user_id '
                'ORDER BY a.id DESC LIMIT ?', (limit,)).fetchall()
    return [dict(r) for r in rows]


@app.get('/api/services')
def services(user=Depends(current_user)):
    require_cap(user, 'services.view')
    host = os.getenv('VOC_PUBLIC_HOST', 'localhost')
    return {
        'kibana': f'http://{host}:5601',
        'glpi': f'http://{host}:8080',
        'misp': f'https://{host}:8443',
        'es': f'http://{host}:9200',
        'rabbitmq': f'http://{host}:15672',
        'portal': f'http://{host}:4200',
    }


@app.get('/api/services/access')
def services_access(user=Depends(current_user)):
    """Service entry points. Basic-auth platforms return a single-sign-on URL
    with the caller's own credentials embedded, so opening the link in the
    browser goes straight in with no second login."""
    require_cap(user, 'services.view')
    return provision.access_list(user['username'], user.get('platform_pass'))


@app.get('/api/health')
def health(user=Depends(current_user)):
    """Liveness of the platform services, seen from inside the docker network."""
    es = esdata.ES_URL
    checks = {}
    try:
        r = requests.get(f"{es}/_cluster/health",
                         auth=(esdata.ES_USER, esdata.ES_PASSWORD), timeout=5)
        checks['elasticsearch'] = r.json().get('status', 'unknown')
    except Exception:
        checks['elasticsearch'] = 'down'

    targets = [
        ('kibana', 'http://kibana:5601/api/status', False),
        ('glpi', 'http://glpi:80', False),
        ('misp', 'https://misp:443', True),
        ('rabbitmq', 'http://rabbitmq:15672', False),
        ('logstash', 'http://logstash:9600', False),
        ('risk-engine', 'http://risk-engine:8000/health', False),
    ]
    for name, url, ssl in targets:
        try:
            r = requests.get(url, timeout=5, verify=(not ssl))
            checks[name] = 'up' if r.status_code < 500 else f'http:{r.status_code}'
        except Exception:
            checks[name] = 'down'
    return checks


@app.get('/api/attack')
def attack_grid(user=Depends(current_user)):
    """MITRE ATT&CK technique activity across open tickets."""
    require_cap(user, 'attack.view')
    with get_db() as conn:
        rows = conn.execute(
            'SELECT t.*, COUNT(tk.id) AS open_tickets '
            'FROM techniques t LEFT JOIN tickets tk '
            'ON tk.technique_id = t.id AND tk.status != "solved" '
            'GROUP BY t.id ORDER BY t.tactic, t.id').fetchall()
        tickets_by_tech = conn.execute(
            'SELECT technique_id, id, title, severity, status, cve, host, risk_score '
            'FROM tickets WHERE technique_id IS NOT NULL AND status != "solved" '
            'ORDER BY risk_score DESC').fetchall()
    grouped = {}
    for r in rows:
        d = dict(r)
        d['open_tickets'] = int(d['open_tickets'])
        grouped.setdefault(d['tactic'], []).append(d)
    by_tech = {}
    for t in tickets_by_tech:
        by_tech.setdefault(t['technique_id'], []).append(dict(t))
    return {'tactics': grouped, 'tickets': by_tech}


@app.exception_handler(Exception)
def unhandled(exc, request):
    return JSONResponse({'error': str(exc)}, status_code=500)


@app.on_event('startup')
def on_startup():
    seed()