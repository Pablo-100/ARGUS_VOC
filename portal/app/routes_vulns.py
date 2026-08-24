"""Vulnerability explorer / attack graph / predictions - native replacement
for browsing this data in Kibana. Read-only: gated on the same
dashboard.view/attack.view capabilities every role already has, since it's
the same SOC-visibility tier as the dashboard widgets these extend.
"""
from fastapi import APIRouter, Depends, HTTPException

from . import vulns_data
from .deps import current_user, require_cap

router = APIRouter(prefix='/api/vulns', tags=['vulns'])


def _upstream(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:
        raise HTTPException(502, f'Elasticsearch unreachable: {e}')


@router.get('')
def list_vulns(q: str = '', severity: str = '', host: str = '', status: str = 'active',
               confidence: str = '', page: int = 1, page_size: int = 25,
               user=Depends(current_user)):
    require_cap(user, 'dashboard.view')
    return _upstream(vulns_data.search_vulns, q=q, severity=severity, host=host,
                     status=status, confidence=confidence, page=page,
                     page_size=page_size)


@router.get('/attack-graph')
def attack_graph(user=Depends(current_user)):
    require_cap(user, 'attack.view')
    return _upstream(vulns_data.attack_graph)


@router.get('/detail')
def vuln_detail(finding_id: str = '', user=Depends(current_user)):
    """Full vulnerability detail view (Feature 13): what is vulnerable, why
    it is dangerous/prioritized, evidence, remediation and verification."""
    require_cap(user, 'dashboard.view')
    if not finding_id:
        raise HTTPException(400, 'finding_id required')
    d = _upstream(vulns_data.get_finding, finding_id=finding_id)
    if not d:
        raise HTTPException(404, 'finding not found')
    return d


@router.get('/detail/history')
def vuln_history(finding_id: str = '', user=Depends(current_user)):
    require_cap(user, 'dashboard.view')
    if not finding_id:
        raise HTTPException(400, 'finding_id required')
    return _upstream(vulns_data.get_finding_history, finding_id=finding_id)


@router.get('/predictions')
def predictions(user=Depends(current_user)):
    require_cap(user, 'dashboard.view')
    return _upstream(vulns_data.predictions)


@router.get('/predictions/validation')
def validation(user=Depends(current_user)):
    require_cap(user, 'dashboard.view')
    return _upstream(vulns_data.validation_history)
