"""Asset inventory API (Feature 1).

Assets live in Elasticsearch (index assets-v1, alias assets) and are
created/updated automatically by the scan pipeline. The portal exposes them
read-only for viewers and allows metadata edits (criticality, environment,
owner, business_service, network_zone, internet_exposed, status) for
assets.edit holders - every edit is audited with old/new values.
"""
from fastapi import APIRouter, Depends, HTTPException, Request

from . import esdata
from .deps import current_user, require_cap
from .tickets import audit

router = APIRouter(prefix='/api/assets', tags=['assets'])


def _client_ip(request):
    fwd = request.headers.get('x-forwarded-for') if request else None
    if fwd:
        return fwd.split(',')[0].strip()
    return request.client.host if (request and request.client) else ''

CRITICALITY_LABELS = {1: 'Low', 2: 'Moderate', 3: 'Important', 4: 'High',
                      5: 'Mission Critical'}
EDITABLE_FIELDS = ('criticality', 'environment', 'department', 'owner',
                   'business_service', 'network_zone', 'internet_exposed',
                   'status', 'notes', 'hostname')


@router.get('')
def list_assets(q: str = '', criticality: int = 0, status: str = '',
                page: int = 1, page_size: int = 25, user=Depends(current_user)):
    require_cap(user, 'assets.view')
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    must = []
    if q:
        must.append({'multi_match': {'query': q, 'fields': [
            'hostname', 'ip_address', 'os', 'business_service', 'owner']}})
    if criticality:
        must.append({'term': {'criticality': criticality}})
    if status:
        must.append({'term': {'status': status}})
    body = {
        'from': (page - 1) * page_size, 'size': page_size,
        'query': {'bool': {'must': must}} if must else {'match_all': {}},
        'sort': [{'_script': {'type': 'number', 'script': {
            'source': "doc.containsKey('criticality') ? doc['criticality'].value : 3"},
            'order': 'desc'}}],
    }
    try:
        data = esdata._search('assets', body)
    except Exception as e:
        raise HTTPException(502, f'Elasticsearch unreachable: {e}')
    hits = data['hits']
    total = hits['total']['value'] if isinstance(hits['total'], dict) else hits['total']
    rows = []
    for h in hits['hits']:
        src = h['_source']
        crit = src.get('criticality') or 3
        src['criticality_label'] = CRITICALITY_LABELS.get(crit, '?')
        rows.append(src)
    return {'total': total, 'page': page, 'page_size': page_size, 'rows': rows}


@router.get('/{asset_id}')
def get_asset(asset_id: str, user=Depends(current_user)):
    require_cap(user, 'assets.view')
    try:
        r = _es().get(f"{esdata.ES_URL}/assets/_doc/{asset_id}",
                      auth=(esdata.ES_USER, esdata.ES_PASSWORD), timeout=10)
    except Exception as e:
        raise HTTPException(502, f'Elasticsearch unreachable: {e}')
    if r.status_code == 404:
        raise HTTPException(404, 'asset not found')
    r.raise_for_status()
    src = r.json().get('_source', {})
    crit = src.get('criticality') or 3
    src['criticality_label'] = CRITICALITY_LABELS.get(crit, '?')
    # include recent findings for this asset (context for the detail view)
    ip = src.get('ip_address')
    if ip:
        try:
            vulns = esdata._search('vulnerabilities-*', {
                'size': 20,
                'query': {'bool': {'filter': [
                    {'term': {'host_ip': ip}},
                    {'term': {'status': 'active'}}]}},
                'sort': [{'risk_score': 'desc'}],
            })
            src['active_findings'] = [
                {k: h['_source'].get(k) for k in
                 ('cve', 'severity', 'risk_score', 'port', 'service', 'product',
                  'version', 'finding_id')}
                for h in vulns['hits']['hits']]
        except Exception:
            src['active_findings'] = []
    return src


@router.patch('/{asset_id}')
def patch_asset(asset_id: str, body: dict, user=Depends(current_user),
                request: Request = None):
    require_cap(user, 'assets.edit')
    fields = {k: v for k, v in body.items() if k in EDITABLE_FIELDS}
    if not fields:
        raise HTTPException(400, f'no editable fields provided '
                                 f'(editable: {list(EDITABLE_FIELDS)})')

    def _patch():
        import requests as rq
        r = rq.get(f'{esdata.ES_URL}/assets/_doc/{asset_id}',
                   auth=(esdata.ES_USER, esdata.ES_PASSWORD), timeout=10)
        if r.status_code == 404:
            raise KeyError(f'asset {asset_id} not found')
        r.raise_for_status()
        old = r.json()['_source']
        clean = dict(old)
        if 'criticality' in fields:
            c = int(fields['criticality'])
            if c not in CRITICALITY_LABELS:
                raise ValueError('criticality must be 1-5')
            clean['criticality'] = c
        if 'environment' in fields and fields['environment']:
            env = str(fields['environment']).lower()
            if env not in ('development', 'testing', 'staging', 'production'):
                raise ValueError('invalid environment')
            clean['environment'] = env
        if 'status' in fields and fields['status']:
            st = str(fields['status']).lower()
            if st not in ('active', 'inactive', 'decommissioned', 'unknown'):
                raise ValueError('invalid status')
            clean['status'] = st
        for k in ('department', 'owner', 'business_service', 'network_zone', 'notes',
                  'hostname'):
            if k in fields:
                clean[k] = str(fields[k]).strip()[:120] or None
        if 'internet_exposed' in fields:
            clean['internet_exposed'] = bool(fields['internet_exposed'])
        r = rq.put(f'{esdata.ES_URL}/assets/_doc/{asset_id}',
                   auth=(esdata.ES_USER, esdata.ES_PASSWORD), json=clean, timeout=10)
        r.raise_for_status()
        return old, clean

    try:
        old, new = _patch()
    except KeyError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f'Elasticsearch unreachable: {e}')

    changed = {k: (old.get(k), new.get(k)) for k in fields if old.get(k) != new.get(k)}
    audit(user['id'], 'asset.update', f'{asset_id}: {", ".join(changed) or "no-op"}',
          ip=_client_ip(request) if request else '', resource='asset',
          resource_id=asset_id,
          old_value=str({k: v[0] for k, v in changed.items()}),
          new_value=str({k: v[1] for k, v in changed.items()}))
    return {'ok': True, 'changed': list(changed)}
