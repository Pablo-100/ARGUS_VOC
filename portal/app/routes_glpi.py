"""Live GLPI ticket detail + actions, surfaced inline in the portal's own
ticket modal - status changes, follow-ups and technician assignment without
opening the standalone GLPI UI. Only ever finds a match for auto-pipeline
tickets (risk_score >= 7, which is what creates a GLPI ticket in the first
place) since that's the only kind of ticket workers/glpi_client.py creates.
"""
from fastapi import APIRouter, Depends, HTTPException

from . import glpi_client
from .deps import current_user, require_cap
from .tickets import audit

router = APIRouter(prefix='/api/glpi', tags=['glpi'])


def _upstream(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:
        raise HTTPException(502, f'GLPI unreachable: {e}')


@router.get('/lookup')
def lookup(cve: str = '', host: str = '', user=Depends(current_user)):
    require_cap(user, 'glpi.view')
    t = _upstream(glpi_client.find_ticket_by_cve_host, cve, host)
    if not t:
        return {'found': False}
    return {'found': True, 'id': t.get('id'), 'name': t.get('name')}


@router.get('/tickets/{ticket_id}')
def ticket(ticket_id: int, user=Depends(current_user)):
    require_cap(user, 'glpi.view')
    t = _upstream(glpi_client.get_ticket, ticket_id)
    if not t:
        raise HTTPException(404, 'ticket not found')
    followups = _upstream(glpi_client.get_followups, ticket_id)
    return {
        'id': t.get('id'), 'name': t.get('name'), 'content': t.get('content'),
        'status': t.get('status'), 'status_label': glpi_client.STATUS_LABELS.get(t.get('status'), '?'),
        'urgency': t.get('urgency'), 'priority': t.get('priority'),
        'date_creation': t.get('date_creation'), 'date_mod': t.get('date_mod'),
        'followups': [{'id': f.get('id'), 'content': f.get('content'),
                      'date': f.get('date_creation') or f.get('date')} for f in followups],
    }


@router.put('/tickets/{ticket_id}/status')
def set_status(ticket_id: int, body: dict, user=Depends(current_user)):
    require_cap(user, 'glpi.manage')
    try:
        status = int(body.get('status'))
    except (TypeError, ValueError):
        raise HTTPException(400, f'status must be one of {list(glpi_client.STATUS_LABELS)}')
    try:
        glpi_client.set_status(ticket_id, status)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f'GLPI unreachable: {e}')
    audit(user['id'], 'glpi.set_status', f'ticket #{ticket_id} -> {glpi_client.STATUS_LABELS.get(status)}')
    return {'ok': True}


@router.post('/tickets/{ticket_id}/followup')
def add_followup(ticket_id: int, body: dict, user=Depends(current_user)):
    require_cap(user, 'glpi.manage')
    content = (body.get('content') or '').strip()
    if not content:
        raise HTTPException(400, 'content required')
    _upstream(glpi_client.add_followup, ticket_id, content)
    audit(user['id'], 'glpi.add_followup', f'ticket #{ticket_id}')
    return {'ok': True}


@router.post('/tickets/{ticket_id}/assign')
def assign(ticket_id: int, body: dict, user=Depends(current_user)):
    require_cap(user, 'glpi.manage')
    username = (body.get('username') or '').strip()
    if not username:
        raise HTTPException(400, 'username required')
    uid = _upstream(glpi_client.find_user_id, username)
    if not uid:
        raise HTTPException(404, f'no GLPI user named {username!r}')
    _upstream(glpi_client.assign_technician, ticket_id, uid)
    audit(user['id'], 'glpi.assign', f'ticket #{ticket_id} -> {username}')
    return {'ok': True}
