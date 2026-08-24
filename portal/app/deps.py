"""Shared FastAPI dependencies (auth + RBAC).

Split out from main.py so the feature routers (routes_misp/routes_glpi/
routes_infra/routes_vulns) can import them without a circular import back
into main.py.
"""
from fastapi import Header, HTTPException

from .auth import decode_token
from .db import get_db
from .roles import has_cap


def current_user(authorization: str = Header(default='')):
    if not authorization.startswith('Bearer '):
        raise HTTPException(401, 'Missing token')
    payload = decode_token(authorization[7:])
    if not payload:
        raise HTTPException(401, 'Invalid or expired token')
    with get_db() as conn:
        u = conn.execute('SELECT * FROM users WHERE id=?', (int(payload['sub']),)).fetchone()
    if not u or not u['active']:
        raise HTTPException(401, 'User disabled')
    return dict(u)


def require_cap(user, cap):
    if not has_cap(user, cap):
        raise HTTPException(403, 'Insufficient privilege')
