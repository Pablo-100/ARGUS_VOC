"""Endpoint activity view (Feature: "see everything the agents see - down to
a single modified file or folder").

Reads the Auditbeat telemetry already flowing into Elasticsearch:
  * file_integrity  -> every created/modified/attributes-changed/deleted file
                       under /etc, /opt/voc-platform and system binaries,
                       including sha256 hashes
  * auditd/system   -> processes, logins, privilege changes
"""
import os

from fastapi import APIRouter, Depends, HTTPException

from . import esdata
from .deps import current_user, require_cap

router = APIRouter(prefix='/api/endpoints', tags=['endpoints'])

AUDITBEAT_INDEX = '.ds-auditbeat-*'


def _search(body):
    import requests
    r = requests.post(f"{esdata.ES_URL}/{AUDITBEAT_INDEX}/_search",
                      auth=(esdata.ES_USER, esdata.ES_PASSWORD), json=body, timeout=15)
    r.raise_for_status()
    return r.json()


@router.get('/files')
def file_events(q: str = '', host: str = '', action: str = '',
                page: int = 1, page_size: int = 50, user=Depends(current_user)):
    """Every file create/modify/attribute-change/delete seen by the agents."""
    require_cap(user, 'infra.view')
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    must = [{'term': {'event.module': 'file_integrity'}}]
    if q:
        must.append({'wildcard': {'file.path': {'value': f'*{q}*', 'case_insensitive': True}}})
    if host:
        must.append({'term': {'host.name': host}})
    if action:
        must.append({'term': {'event.action': action}})
    body = {
        'from': (page - 1) * page_size, 'size': page_size,
        'query': {'bool': {'must': must}},
        'sort': [{'@timestamp': 'desc'}],
        '_source': ['@timestamp', 'host.name', 'file.path', 'file.type',
                    'event.action', 'file.hash.sha256', 'user.name', 'user.id',
                    'process.name'],
    }
    try:
        data = _search(body)
    except Exception as e:
        raise HTTPException(502, f'Elasticsearch unreachable: {e}')
    hits = data['hits']
    total = hits['total']['value'] if isinstance(hits['total'], dict) else hits['total']
    rows = []
    for h in hits['hits']:
        s = h['_source']
        actions = s.get('event', {}).get('action')
        rows.append({
            '@timestamp': s.get('@timestamp'),
            'host': s.get('host', {}).get('name'),
            'path': s.get('file', {}).get('path'),
            'file_type': s.get('file', {}).get('type'),
            'action': actions if isinstance(actions, list) else [actions],
            'sha256': s.get('file', {}).get('hash', {}).get('sha256'),
            'user': s.get('user', {}).get('name'),
            'process': s.get('process', {}).get('name'),
        })
    return {'total': total, 'page': page, 'page_size': page_size, 'rows': rows}


@router.get('/processes')
def process_events(q: str = '', host: str = '', page: int = 1, page_size: int = 50,
                   user=Depends(current_user)):
    """Process executions observed on monitored hosts."""
    require_cap(user, 'infra.view')
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    must = [{'term': {'event.dataset': 'process'}}]
    if q:
        must.append({'match': {'process.args': q}})
    if host:
        must.append({'term': {'host.name': host}})
    body = {
        'from': (page - 1) * page_size, 'size': page_size,
        'query': {'bool': {'must': must}},
        'sort': [{'@timestamp': 'desc'}],
        '_source': ['@timestamp', 'host.name', 'process.pid', 'process.name',
                    'process.args', 'user.name', 'user.id'],
    }
    try:
        data = _search(body)
    except Exception as e:
        raise HTTPException(502, f'Elasticsearch unreachable: {e}')
    hits = data['hits']
    total = hits['total']['value'] if isinstance(hits['total'], dict) else hits['total']
    rows = []
    for h in hits['hits']:
        s = h['_source']
        args = s.get('process', {}).get('args') or []
        rows.append({
            '@timestamp': s.get('@timestamp'),
            'host': s.get('host', {}).get('name'),
            'pid': s.get('process', {}).get('pid'),
            'name': s.get('process', {}).get('name'),
            'cmdline': ' '.join(args)[:300] if args else '',
            'user': s.get('user', {}).get('name'),
        })
    return {'total': total, 'page': page, 'page_size': page_size, 'rows': rows}


@router.get('/summary')
def endpoint_summary(user=Depends(current_user)):
    """Counts for the Endpoints overview strip."""
    require_cap(user, 'infra.view')
    out = {'file_changes_24h': 0, 'processes_24h': 0, 'hosts': [], 'actions': []}
    gte24 = 'now-24h'
    try:
        d = _search({'size': 0, 'track_total_hits': True, 'query': {
            'bool': {'must': [{'term': {'event.module': 'file_integrity'}}],
                     'filter': [{'range': {'@timestamp': {'gte': gte24}}}]}},
            'aggs': {
                'by_action': {'terms': {'field': 'event.action', 'size': 10}},
                'by_host': {'terms': {'field': 'host.name', 'size': 20}},
            }})
        out['file_changes_24h'] = d['hits']['total']['value']
        out['actions'] = [(b['key'], b['doc_count'])
                          for b in d['aggregations']['by_action']['buckets']]
        out['hosts'] = [b['key'] for b in d['aggregations']['by_host']['buckets']]
    except Exception:
        pass
    try:
        d2 = _search({'size': 0, 'track_total_hits': True, 'query': {
            'bool': {'must': [{'term': {'event.dataset': 'process'}}],
                     'filter': [{'range': {'@timestamp': {'gte': gte24}}}]}}})
        out['processes_24h'] = d2['hits']['total']['value']
    except Exception:
        pass
    return out


@router.post('/test-fim')
def test_fim(user=Depends(current_user), request=None):
    """Write a canary file under a watched path to prove end-to-end FIM.
    Requires infra.manage. Returns the path to look for in the Files view."""
    require_cap(user, 'infra.manage')
    from .tickets import audit
    import time
    base = os.getenv('FIM_CANARY_DIR', '/canary')
    path = f'{base}/voc-fim-canary-{int(time.time())}.txt'
    try:
        os.makedirs(base, exist_ok=True)
        with open(path, 'w') as f:
            f.write(f'VOC FIM canary written at request of {user["username"]}\n')
    except OSError as e:
        raise HTTPException(500, f'cannot write canary ({e}) - check the '
                                 f'./logs volume bind')
    audit(user['id'], 'endpoint.fim_canary', path, resource='endpoint')
    return {'ok': True, 'path': path,
            'hint': 'watched path -> appears in Files within ~15s'}


# ---------------------------------------------------------------------------
# Fleet agents + live network neighbourhood
# ---------------------------------------------------------------------------
FLEET_INDEX = '.fleet-agents-7'
SERVER_IPS = tuple(os.getenv('DISCOVERY_SUBNET', '').split(','))


def _parse_iso(ts):
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
    except ValueError:
        return None


@router.get('/fleet')
def fleet_agents(user=Depends(current_user)):
    """Every Elastic Agent enrolled in Fleet: identity, IPs, OS, online state."""
    require_cap(user, 'infra.view')
    import requests
    try:
        r = requests.post(f'{esdata.ES_URL}/{FLEET_INDEX}/_search',
                          auth=(esdata.ES_USER, esdata.ES_PASSWORD),
                          json={'size': 100,
                                'sort': [{'last_checkin': 'desc'}],
                                '_source': ['agent', 'active', 'last_checkin',
                                            'enrolled_at', 'local_metadata.host',
                                            'local_metadata.os', 'policy_id']},
                          timeout=15)
        r.raise_for_status()
        hits = r.json()['hits']['hits']
    except Exception as e:
        raise HTTPException(502, f'Elasticsearch unreachable: {e}')

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    out, online = [], 0
    for h in hits:
        s = h['_source']
        lm = s.get('local_metadata') or {}
        host = lm.get('host') or {}
        ost = lm.get('os') or {}
        lc = _parse_iso(s.get('last_checkin'))
        mins = ((now - lc).total_seconds() / 60) if lc else None
        is_online = bool(s.get('active')) and mins is not None and mins < 10
        online += 1 if is_online else 0
        ips = [ip.split('/')[0] for ip in (host.get('ip') or [])
               if not ip.startswith(('127.', '::', 'fe80'))]
        out.append({
            'name': host.get('hostname') or host.get('name') or '?',
            'ips': ips,
            'os': ost.get('full'),
            'version': (s.get('agent') or {}).get('version'),
            'policy_id': s.get('policy_id'),
            'last_checkin': s.get('last_checkin'),
            'checkin_minutes_ago': round(mins) if mins is not None else None,
            'online': is_online,
            'enrolled_at': s.get('enrolled_at'),
        })
    out.sort(key=lambda a: (not a['online'], a['checkin_minutes_ago'] or 99999))
    return {'total': len(out), 'online': online, 'agents': out}


@router.get('/network')
def network_live(minutes: int = 30, user=Depends(current_user)):
    """Machines currently talking to this server (Packetbeat flows, last N min),
    enriched with asset inventory identity when known."""
    require_cap(user, 'infra.view')
    minutes = max(5, min(minutes, 240))
    import requests
    body = {
        'size': 0,
        'query': {'bool': {'filter': [
            {'range': {'@timestamp': {'gte': f'now-{minutes}m'}}},
        ]}},
        'aggs': {
            'clients': {'terms': {'field': 'client.ip', 'size': 200}},
            'servers_remote': {'terms': {'field': 'destination.ip', 'size': 200}},
        },
    }
    try:
        r = requests.post(f'{esdata.ES_URL}/.ds-packetbeat-*/_search',
                          auth=(esdata.ES_USER, esdata.ES_PASSWORD),
                          json=body, timeout=20)
        r.raise_for_status()
        aggs = r.json()['aggregations']
    except Exception as e:
        raise HTTPException(502, f'packetbeat data unavailable: {e}')

    import ipaddress
    counts = {}

    def keep(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if a.is_loopback or a.is_multicast:
            return False
        # skip docker bridge ranges (our own containers)
        return not (a in ipaddress.ip_network('172.16.0.0/12'))

    for b in aggs['clients']['buckets']:
        if keep(b['key']):
            counts[b['key']] = counts.get(b['key'], 0) + b['doc_count']
    for b in aggs['servers_remote']['buckets']:
        if keep(b['key']):
            counts[b['key']] = counts.get(b['key'], 0) + b['doc_count']

    # enrich with asset inventory (hostname / criticality / known?)
    known = {}
    if counts:
        try:
            rr = requests.post(f'{esdata.ES_URL}/assets/_search',
                               auth=(esdata.ES_USER, esdata.ES_PASSWORD),
                               json={'size': 500, 'query': {'terms': {
                                   'ip_address': list(counts.keys())}},
                                   '_source': ['ip_address', 'hostname',
                                               'criticality', 'status']},
                               timeout=10)
            for h in rr.json().get('hits', {}).get('hits', []):
                src = h['_source']
                known[str(src.get('ip_address'))] = src
        except Exception:
            pass

    rows = []
    for ip, flows in sorted(counts.items(), key=lambda kv: -kv[1]):
        asset = known.get(ip) or {}
        rows.append({'ip': ip, 'flows': flows,
                     'hostname': asset.get('hostname'),
                     'known_asset': bool(asset),
                     'criticality': asset.get('criticality'),
                     'status': asset.get('status') or 'seen_in_traffic'})
    return {'window_minutes': minutes, 'machines': rows}


# ---------------------------------------------------------------------------
# Unified activity search: files + logins across ALL monitored hosts
#   * voc-host      -> Auditbeat (file_integrity + auditd logins)
#   * fleet agents  -> logs-system.auth (logins) + fim/auditd (files)
# ---------------------------------------------------------------------------
def _is_noise(text):
    t = (text or '').lower()
    return any(pat.lower() in t for pat in NOISE_PATTERNS)


def _login_outcome_from_message(msg):
    m = (msg or '').lower()
    if 'failed password' in m or 'invalid user' in m or 'authentication failure' in m \
       or 'connection closed by authenticating user' in m and 'preauth' in m:
        return 'failed'
    if 'accepted password' in m or 'accepted publickey' in m or 'session opened' in m:
        return 'success'
    return None


NOISE_PATTERNS = [
    '.cache', 'tracker3', 'AnsiballZ', 'ansible-tmp', 'ansible_',
    '/run/user', '/proc/', '/sys/', 'snap/', '.db-wal', '.db-shm',
    'opencode.db', '.local/share/opencode', 'dconf', 'gvfs',
]



@router.get('/activity')
def unified_activity(type: str = '', host: str = '', result: str = '',
                     q: str = '', minutes: int = 1440, noise: int = 1,
                     page: int = 1, page_size: int = 50,
                     user=Depends(current_user)):
    """One searchable feed: file changes + login attempts (success & failed)
    from every monitored machine."""
    require_cap(user, 'infra.view')
    import requests as rq
    minutes = max(5, min(minutes, 10080))
    page = max(1, page)
    page_size = max(10, min(page_size, 200))
    rows = []

    want_files = type in ('', 'file')
    want_logins = type in ('', 'login')

    # ---- 1) Auditbeat (voc-host): FIM + auditd logins ----
    ab_must = [{'range': {'@timestamp': {'gte': f'now-{minutes}m'}}}]
    if want_files:
        pass
    should = []
    if want_files:
        should.append({'bool': {'must': [{'term': {'event.module': 'file_integrity'}}],
                                'must_not': [{'term': {'event.action': 'initial_scan'}}]}})
    if want_logins:
        should.append({'bool': {'must': [
            {'term': {'event.module': 'auditd'}},
            {'terms': {'event.action': ['USER_LOGIN', 'USER_AUTH', 'USER_START',
                                        'ACCT_LOCK', 'LOGIN']}}]}})
    if q:
        ab_must.append({'multi_match': {'query': q,
                                        'fields': ['file.path', 'message', 'user.name']}})
    if host:
        ab_must.append({'match_phrase': {'host.name': host}})
    if should:
        try:
            body = {'size': page_size * page if page_size * page < 400 else 400,
                    'query': {'bool': {'must': ab_must,
                                       'minimum_should_match': 1, 'should': should}},
                    'sort': [{'@timestamp': 'desc'}],
                    '_source': ['@timestamp', 'host.name', 'event.action',
                                'event.outcome', 'file.path', 'file.hash.sha256',
                                'user.name', 'source.ip', 'message']}
            d = rq.post(f'{esdata.ES_URL}/.ds-auditbeat-*/_search',
                        auth=(esdata.ES_USER, esdata.ES_PASSWORD),
                        json=body, timeout=20).json()
            for h in d.get('hits', {}).get('hits', []):
                src = h['_source']
                actions = src.get('event', {}).get('action') or []
                action = actions[0] if isinstance(actions, list) else actions
                is_login = str(action).startswith(('USER_', 'LOGIN', 'ACCT'))
                path = src.get('file', {}).get('path')
                msg = (src.get('message') or '')[:220]
                rows.append({
                    '@timestamp': src.get('@timestamp'),
                    'host': src.get('host', {}).get('name'),
                    'kind': 'login' if is_login else 'file',
                    'action': action,
                    'detail': path or msg,
                    'sha256': (src.get('file', {}) or {}).get('hash', {}).get('sha256'),
                    'user': src.get('user', {}).get('name'),
                    'ip': src.get('source', {}).get('ip') or src.get('destination', {}).get('ip'),
                    'outcome': src.get('event', {}).get('outcome') or (
                        'success' if 'success' in str(src.get('event', {}).get('outcome', '')) else None),
                })
        except Exception:
            pass

    # ---- 1b) voc-server auth.log via filebeat ----
    if want_logins:
        must = [{'term': {'log_type': 'system'}}, {'term': {'source': 'auth'}},
                {'range': {'@timestamp': {'gte': f'now-{minutes}m'}}}]
        if q:
            must.append({'match_phrase': {'message': q}})
        try:
            body = {'size': 300,
                    'query': {'bool': {'must': must}},
                    'sort': [{'@timestamp': 'desc'}],
                    '_source': ['@timestamp', 'message']}
            d = rq.post(f'{esdata.ES_URL}/filebeat-*/_search',
                        auth=(esdata.ES_USER, esdata.ES_PASSWORD),
                        json=body, timeout=20).json()
            import re
            for h in d.get('hits', {}).get('hits', []):
                src = h['_source']
                msg = (src.get('message') or '')
                outc = _login_outcome_from_message(msg)
                if result == 'success' and outc != 'success':
                    continue
                if result == 'failed' and outc != 'failed':
                    continue
                user_name = None
                mm = re.search(r'(?:user|for)\s+(?:invalid user\s+)?(\S+)', msg)
                if mm:
                    user_name = mm.group(1)
                rows.append({
                    '@timestamp': src.get('@timestamp'),
                    'host': 'voc-server',
                    'kind': 'login',
                    'action': 'auth',
                    'detail': msg[:220],
                    'sha256': None,
                    'user': user_name,
                    'ip': (re.search(r'from ([\d.]+)', msg) or [None, None])[1],
                    'outcome': outc,
                })
        except Exception:
            pass

    # ---- 1c) Fleet agents: FIM via bridge auditd->syslog (files) ----
    if want_files:
        must = [{'term': {'event.dataset': 'system.syslog'}},
                {'range': {'@timestamp': {'gte': f'now-{minutes}m'}}},
                {'match_phrase': {'message': 'nametype='}}]
        if q:
            must.append({'match_phrase': {'message': q}})
        if host:
            must.append({'match_phrase': {'host.name': host}})
        try:
            import re as _re
            body = {'size': 300,
                    'query': {'bool': {'must': must,
                                       'must_not': [{'match_phrase': {'message': 'nametype=PARENT'}},
                                                    {'match_phrase': {'message': 'nametype=NORMAL'}}]}},
                    'sort': [{'@timestamp': 'desc'}],
                    '_source': ['@timestamp', 'host.name', 'message']}
            d = rq.post(f'{esdata.ES_URL}/logs-system.syslog-*/_search',
                        auth=(esdata.ES_USER, esdata.ES_PASSWORD),
                        json=body, timeout=20).json()
            for h in d.get('hits', {}).get('hits', []):
                src = h['_source']
                msg = src.get('message') or ''
                nm = _re.search(r'nametype=(\w+)', msg)
                nm_type = nm.group(1) if nm else 'CHANGE'
                path_m = None
                for pm in _re.finditer(r'name="([^"]+)"', msg):
                    cand = pm.group(1)
                    if not cand.endswith(('.lock',)) and 'audit(' not in cand:
                        path_m = cand
                action_map = {'CREATE': 'created', 'DELETE': 'deleted',
                              'NORMAL': 'modified'}
                rows.append({
                    '@timestamp': src.get('@timestamp'),
                    'host': src.get('host', {}).get('name'),
                    'kind': 'file',
                    'action': action_map.get(nm_type, nm_type.lower()),
                    'detail': f"{path_m or msg[:120]} ({nm_type})",
                    'sha256': None,
                    'user': None,
                    'ip': None,
                    'outcome': None,
                })
        except Exception:
            pass

    # ---- 2) Fleet agents: system.auth (logins via auth.log) ----
    if want_logins:
        must = [{'term': {'event.dataset': 'system.auth'}},
                {'range': {'@timestamp': {'gte': f'now-{minutes}m'}}}]
        if q:
            must.append({'match_phrase': {'message': q}})
        if host:
            must.append({'match_phrase': {'host.name': host}})
        try:
            body = {'size': page_size * page if page_size * page < 400 else 400,
                    'query': {'bool': {'must': must}},
                    'sort': [{'@timestamp': 'desc'}],
                    '_source': ['@timestamp', 'host.name', 'message', 'user.name',
                                'source.ip', 'event.outcome']}
            d = rq.post(f'{esdata.ES_URL}/logs-system.auth-*/_search',
                        auth=(esdata.ES_USER, esdata.ES_PASSWORD),
                        json=body, timeout=20).json()
            for h in d.get('hits', {}).get('hits', []):
                src = h['_source']
                msg = (src.get('message') or '')
                outc = _login_outcome_from_message(msg)
                if result == 'success' and outc != 'success':
                    continue
                if result == 'failed' and outc != 'failed':
                    continue
                user_name = src.get('user', {}).get('name')
                if not user_name:
                    import re
                    mm = re.search(r'(?:user|for)\s+(\S+)', msg)
                    user_name = mm.group(1) if mm else None
                rows.append({
                    '@timestamp': src.get('@timestamp'),
                    'host': src.get('host', {}).get('name'),
                    'kind': 'login',
                    'action': 'auth',
                    'detail': msg[:220],
                    'sha256': None,
                    'user': user_name,
                    'ip': src.get('source', {}).get('ip'),
                    'outcome': outc,
                })
        except Exception:
            pass

    # ---- filters applied post-merge (outcomes computed above) ----
    if result in ('success', 'failed'):
        rows = [r0 for r0 in rows if r0['outcome'] == result]
    if noise:
        rows = [r0 for r0 in rows
                if not (_is_noise(r0.get('detail')) or _is_noise(r0.get('user') or ''))]

    # déduplication (audit émet SYSCALL+PATH et syslog peut doubler)
    seen = set()
    dedup = []
    for r0 in rows:
        k = (r0['@timestamp'], r0['kind'], r0.get('detail'), r0.get('action'))
        if k not in seen:
            seen.add(k)
            dedup.append(r0)
    rows = dedup
    rows.sort(key=lambda r0: r0['@timestamp'] or '', reverse=True)
    total = len(rows)
    start = (page - 1) * page_size
    return {'total': total, 'page': page, 'page_size': page_size,
            'rows': rows[start:start + page_size]}
