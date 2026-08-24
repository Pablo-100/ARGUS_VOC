"""Native MISP threat-intel page - search/browse events, create + publish +
delete, replacing the standalone MISP UI for day-to-day analyst use. Every
mutating action is audited via tickets.audit(), matching the pattern every
other mutating endpoint in main.py already follows.
"""
from fastapi import APIRouter, Depends, HTTPException

from . import misp_client
from .deps import current_user, require_cap
from .tickets import audit

router = APIRouter(prefix='/api/misp', tags=['misp'])


def _upstream(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:
        raise HTTPException(502, f'MISP unreachable: {e}')


@router.get('/events')
def events(q: str = '', user=Depends(current_user)):
    require_cap(user, 'misp.view')
    return _upstream(misp_client.search_events, q)


@router.get('/events/{event_id}')
def event(event_id: str, user=Depends(current_user)):
    require_cap(user, 'misp.view')
    ev = _upstream(misp_client.get_event, event_id)
    if not ev:
        raise HTTPException(404, 'event not found')
    return ev


@router.post('/events')
def create(body: dict, user=Depends(current_user)):
    require_cap(user, 'misp.manage')
    info = (body.get('info') or '').strip()
    if not info:
        raise HTTPException(400, 'info required')
    tags = body.get('tags') or None
    ev = _upstream(misp_client.create_event, info, tags)
    if not ev:
        raise HTTPException(502, 'MISP did not return the created event')
    audit(user['id'], 'misp.create_event', f'#{ev.get("id")} {info}')
    return ev


@router.post('/events/{event_id}/publish')
def publish(event_id: str, user=Depends(current_user)):
    require_cap(user, 'misp.manage')
    _upstream(misp_client.publish_event, event_id)
    audit(user['id'], 'misp.publish_event', f'#{event_id}')
    return {'ok': True}


@router.delete('/events/{event_id}')
def delete(event_id: str, user=Depends(current_user)):
    require_cap(user, 'misp.manage')
    _upstream(misp_client.delete_event, event_id)
    audit(user['id'], 'misp.delete_event', f'#{event_id}')
    return {'ok': True}


@router.post('/events/{event_id}/attributes')
def add_attribute(event_id: str, body: dict, user=Depends(current_user)):
    require_cap(user, 'misp.manage')
    value = (body.get('value') or '').strip()
    if not value:
        raise HTTPException(400, 'value required')
    attr = {'type': body.get('type') or 'text', 'category': body.get('category') or 'Other',
            'value': value, 'comment': body.get('comment') or '', 'to_ids': False}
    res = _upstream(misp_client.add_attribute, event_id, attr)
    audit(user['id'], 'misp.add_attribute', f'#{event_id} {attr["type"]}={value[:60]}')
    return res
