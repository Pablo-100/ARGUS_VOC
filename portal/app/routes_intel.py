"""Host Intel — résultats du Deep Scan Ansible (agent-intel-host).

Le super-pouvoir authentifié : contrairement à Nmap qui devine depuis
l'extérieur, le Deep Scan entre sur chaque machine via SSH/Ansible et
collecte paquets exacts, comptes, ports en écoute et services.
"""
import os

from fastapi import APIRouter, Depends, HTTPException

from . import esdata
from .deps import current_user, require_cap

router = APIRouter(prefix='/api/intel', tags=['intel'])
INDEX = 'agent-intel-host'


def _search(body):
    import requests
    r = requests.post(f"{esdata.ES_URL}/{INDEX}/_search",
                      auth=(esdata.ES_USER, esdata.ES_PASSWORD), json=body, timeout=20)
    r.raise_for_status()
    return r.json()


@router.get('/hosts')
def intel_hosts(user=Depends(current_user)):
    """Dernier scan par machine."""
    require_cap(user, 'infra.view')
    try:
        d = _search({
            'size': 0,
            'aggs': {'by_host': {
                'terms': {'field': 'host', 'size': 50},
                'aggs': {'latest': {'top_hits': {'size': 1,
                        'sort': [{'@timestamp': 'desc'}],
                        '_source': ['@timestamp', 'host', 'ip', 'os', 'kernel',
                                    'uptime_days', 'packages_count',
                                    'services_enabled_count', 'users',
                                    'scan_profile']}}}},
            }})
    except Exception as e:
        raise HTTPException(502, f'Elasticsearch unreachable: {e}')
    rows = []
    for b in d.get('aggregations', {}).get('by_host', {}).get('buckets', []):
        hits = b['latest']['hits']['hits']
        if not hits:
            continue
        s = hits[0]['_source']
        rows.append({'host': s.get('host'), 'ip': s.get('ip'), 'os': s.get('os'),
                     'kernel': s.get('kernel'),
                     'uptime_days': s.get('uptime_days'),
                     'packages_count': s.get('packages_count'),
                     'services_count': s.get('services_enabled_count'),
                     'users_count': len(s.get('users') or []),
                     'scan_profile': s.get('scan_profile'),
                     'scanned_at': s.get('@timestamp')})
    rows.sort(key=lambda x: x.get('scanned_at') or '', reverse=True)
    return {'hosts': rows}


@router.get('/host/{hostname}')
def intel_detail(hostname: str, user=Depends(current_user)):
    """Dernier rapport complet d'une machine."""
    require_cap(user, 'infra.view')
    try:
        d = _search({'size': 1,
                     'query': {'term': {'host': hostname}},
                     'sort': [{'@timestamp': 'desc'}]})
        hits = d['hits']['hits']
    except Exception as e:
        raise HTTPException(502, f'Elasticsearch unreachable: {e}')
    if not hits:
        raise HTTPException(404, 'no scan for this host')
    src = hits[0]['_source']

    # parser les ports depuis la sortie brute de ss -tulpn
    ports = []
    for line in (src.get('listening_ports_raw') or [])[1:]:
        parts = line.split()
        if len(parts) >= 5 and ':' in parts[4]:
            local = parts[4]
            ip, _, port = local.rpartition(':')
            proc = parts[6].strip('"{}') if len(parts) > 6 else ''
            name = proc.split('=')[-1].strip('"') if '=' in proc else proc
            ports.append({'port': port, 'local': local, 'process': name})
    return {
        'host': src.get('host'), 'ip': src.get('ip'), 'os': src.get('os'),
        'kernel': src.get('kernel'), 'uptime_days': src.get('uptime_days'),
        'scanned_at': src.get('@timestamp'),
        'scan_profile': src.get('scan_profile'),
        'packages_count': src.get('packages_count'),
        'packages': src.get('packages') or [],
        'users': src.get('users') or [],
        'ports': ports,
        'services_enabled': src.get('services_enabled') or [],
        'recent_logins': src.get('recent_logins') or [],
        'top_processes': src.get('top_processes') or [],
    }
