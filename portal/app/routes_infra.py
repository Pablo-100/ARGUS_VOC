"""Native RabbitMQ + Elasticsearch infrastructure page - queue health/purge
and ES cluster/index health/delete, replacing the RabbitMQ management UI and
Kibana's index management for the actions analysts actually need day-to-day.
infra.manage (purge/delete) defaults to admin-only in roles.py - highest
blast radius of anything this feature adds, since it reaches the platform's
data plane rather than one ticket.
"""
from fastapi import APIRouter, Depends, HTTPException

from . import es_admin, rabbitmq_client
from .deps import current_user, require_cap
from .tickets import audit

router = APIRouter(prefix='/api/infra', tags=['infra'])


def _upstream(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:
        raise HTTPException(502, f'upstream unreachable: {e}')


@router.get('/queues')
def queues(user=Depends(current_user)):
    require_cap(user, 'infra.view')
    return _upstream(rabbitmq_client.list_queues)


@router.post('/queues/{name}/purge')
def purge_queue(name: str, user=Depends(current_user)):
    require_cap(user, 'infra.manage')
    _upstream(rabbitmq_client.purge_queue, name)
    audit(user['id'], 'infra.purge_queue', f'queue={name}')
    return {'ok': True}


@router.get('/es/health')
def es_health(user=Depends(current_user)):
    require_cap(user, 'infra.view')
    return _upstream(es_admin.cluster_health)


@router.get('/es/indices')
def es_indices(user=Depends(current_user)):
    require_cap(user, 'infra.view')
    return _upstream(es_admin.list_indices)


@router.delete('/es/indices/{name}')
def es_delete_index(name: str, user=Depends(current_user)):
    require_cap(user, 'infra.manage')
    try:
        es_admin.delete_index(name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f'upstream unreachable: {e}')
    audit(user['id'], 'infra.delete_index', f'index={name}')
    return {'ok': True}
