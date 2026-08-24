"""Unified Tools Hub registry (Feature: "see everything like using the tools").

Every platform surface - native portal consoles AND external tools - exposed
as one registry with live health, category and the right deep-link per user.
Optional tools (Zabbix / Shuffle / Zeek) appear with deployment status so the
hub is honest about what is running where.
"""
import os

from fastapi import APIRouter, Depends, HTTPException

from . import es_admin, provision, rabbitmq_client
from .deps import current_user, require_cap

router = APIRouter(prefix='/api/tools', tags=['tools'])


def _probe(url, verify=False):
    import requests
    try:
        r = requests.get(url, timeout=3, verify=verify)
        return 'up' if r.status_code < 500 else f'degraded ({r.status_code})'
    except Exception:
        return 'down'


@router.get('')
def tools_hub(user=Depends(current_user)):
    require_cap(user, 'services.view')
    access = {a['key']: a for a in provision.access_list(user['username'],
                                                         user.get('platform_pass'))}
    embed_url = os.getenv('KIBANA_EMBED_URL', '')
    public = os.getenv('VOC_PUBLIC_HOST', 'localhost')
    shuffle_status = _probe('http://shuffle-frontend/')
    zbx_url = os.getenv('ZABBIX_PUBLIC_URL') or f'http://{public}:8081'
    shuffle_url = os.getenv('SHUFFLE_URL') or f'http://{public}:3001'

    def tool(key, name, category, cap, probe=None, note='', extra=None,
             verify=False):
        a = access.get(key, {})
        entry = {
            'key': key, 'name': name, 'category': category,
            'cap': cap, 'url': a.get('url'), 'sso': a.get('sso', False),
            'same_credentials': a.get('same_credentials', False),
            'status': _probe(probe, verify=verify) if probe else ('up' if a else 'not_deployed'),
            'note': note,
        }
        if extra:
            entry.update(extra)
        return entry

    zabbix_status = _probe('http://zabbix-web:8080')
    if zabbix_status == 'down':
        zabbix_status = 'not_deployed'

    tools = [
        tool('kibana', 'Kibana', 'SIEM & Dashboards', 'services.view',
             probe='http://kibana:5601/api/status'),
        tool('es', 'Elasticsearch', 'SIEM & Dashboards', 'infra.view',
             probe=f"{os.getenv('ES_URL', 'http://elasticsearch:9200')}/"),
        {'key': 'voc_dashboards', 'name': 'VOC Dashboards (native)',
         'category': 'SIEM & Dashboards', 'cap': 'dashboard.view',
         'url': '/?tab=dashboards', 'sso': False, 'status': 'up',
         'note': 'Native SOC views - no Kibana login needed'},
        tool('glpi', 'GLPI', 'ITSM', None,  # visible to all; pages gate themselves
             probe='http://glpi:80/'),
        tool('misp', 'MISP', 'Threat Intelligence', None,
             probe='https://misp:443'),  # self-signed cert -> unverified probe
        tool('rabbitmq', 'RabbitMQ Management', 'Messaging & Queues', 'infra.view',
             probe='http://rabbitmq:15672/api/overview'),
        {'key': 'zabbix', 'name': 'Zabbix', 'category': 'Monitoring', 'cap':
         'services.view', 'url': zbx_url,
         'sso': False, 'status': zabbix_status,
         'note': ('start with: docker compose --profile zabbix up -d'
                  if zabbix_status == 'not_deployed' else
                  f'web UI: {zbx_url} (Admin / see .env)')},
        {'key': 'shuffle', 'name': 'Shuffle (SOAR)', 'category': 'Automation / SOAR',
         'cap': 'services.view', 'url': shuffle_url,
         'sso': False,
         'status': ('up' if shuffle_status == 'up' else
                    'starting' if shuffle_status != 'down' else shuffle_status),
         'note': 'login: admin / adminadmin · workflows persistés dans Elasticsearch'},
        {'key': 'zeek', 'name': 'Zeek', 'category': 'Network Analytics',
         'cap': 'services.view', 'url': '', 'sso': False, 'status': 'covered',
         'note': 'network telemetry currently covered by Packetbeat; '
                 'full Zeek = sensor host (docs/EXTRA_TOOLS.md)'},
    ]

    # hide entries the user has no business seeing (cap-gated ones)
    from .roles import has_cap
    out = []
    for t in tools:
        cap = t.pop('cap', None)
        if cap and not has_cap(user, cap):
            continue
        out.append(t)
    return {
        'tools': out,
        'kibana_embed_url': embed_url or None,
        'public_host': os.getenv('VOC_PUBLIC_HOST', 'localhost'),
    }


@router.get('/health')
def tools_health(user=Depends(current_user)):
    require_cap(user, 'services.view')
    # re-expose existing infra probes for the hub status strip
    checks = {}
    es = os.getenv('ES_URL', 'http://elasticsearch:9200')
    try:
        import requests
        r = requests.get(f'{es}/_cluster/health',
                         auth=(os.getenv('ES_USER', 'elastic'),
                               os.getenv('ELASTIC_PASSWORD', '')), timeout=5)
        checks['elasticsearch'] = r.json().get('status', 'unknown')
    except Exception:
        checks['elasticsearch'] = 'down'
    for name, url in [('kibana', 'http://kibana:5601/api/status'),
                      ('glpi', 'http://glpi:80/'),
                      ('zabbix', 'http://zabbix-web:8080')]:
        checks[name] = _probe(url) if name != 'zabbix' else (
            'down' if _probe(url) == 'down' else 'up')
    try:
        rabbitmq_client.list_queues()
        checks['rabbitmq'] = 'up'
    except Exception:
        checks['rabbitmq'] = 'down'
    return checks
