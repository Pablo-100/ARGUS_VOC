"""Real asset inventory for the VOC platform.

Assets are stored in the Elasticsearch index ``assets-v1`` (alias ``assets``),
one document per unique asset, updated in place by scan pipelines.

Stable identity (Feature 5 of the hardening mandate):
    1. MAC + IP + hostname   (preferred when all are known)
    2. IP + hostname
    3. hostname              (when no IP observed - rare)
    4. IP                    (fallback when nothing else is available)

``asset_id`` is a sha1 of the identity string so re-scans update the same
document instead of creating duplicates.

Metadata fields (criticality / environment / owner / ...) can be patched by
the portal; the worker upsert preserves any metadata it does not know about
by merging with the existing document (fetch-then-merge on version conflict).
"""
import hashlib
import logging
import os
import threading
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

ES_URL = os.getenv('ES_URL', 'http://elasticsearch:9200')
ES_USER = os.getenv('ES_USER', 'elastic')
ES_PASSWORD = os.getenv('ELASTIC_PASSWORD', '')

ASSET_INDEX = 'assets-v1'
ASSET_ALIAS = 'assets'

CRITICALITY_LABELS = {1: 'Low', 2: 'Moderate', 3: 'Important', 4: 'High', 5: 'Mission Critical'}
ENVIRONMENTS = ('development', 'testing', 'staging', 'production')
ASSET_STATUSES = ('active', 'inactive', 'decommissioned', 'unknown')

# Fields the portal may patch; everything else is worker-owned.
METADATA_FIELDS = frozenset({
    'criticality', 'environment', 'department', 'owner', 'business_service',
    'network_zone', 'internet_exposed', 'status', 'notes', 'hostname',
})

_local = threading.local()


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _session():
    s = getattr(_local, 'asset_session', None)
    if s is None:
        retry = Retry(total=2, backoff_factor=0.5,
                      status_forcelist=[429, 502, 503, 504],
                      allowed_methods=['GET', 'PUT', 'POST'])
        adapter = HTTPAdapter(max_retries=retry)
        s = requests.Session()
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        _local.asset_session = s
    return s


def ensure_index():
    """Create the assets index + alias if missing (idempotent)."""
    try:
        r = _session().head(f'{ES_URL}/{ASSET_INDEX}', auth=(ES_USER, ES_PASSWORD), timeout=10)
        if r.status_code == 200:
            return True
        body = {
            'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
            'mappings': {
                'dynamic': True,
                'properties': {
                    'ip_address': {'type': 'ip'},
                    'hostname': {'type': 'keyword'},
                    'mac_address': {'type': 'keyword'},
                    'os': {'type': 'text'},
                    'os_version': {'type': 'keyword'},
                    'criticality': {'type': 'integer'},
                    'internet_exposed': {'type': 'boolean'},
                    'open_ports': {'type': 'integer'},
                    'services': {'type': 'flattened'},
                    'software': {'type': 'keyword'},
                    'cpes': {'type': 'keyword'},
                    'first_seen': {'type': 'date'},
                    'last_seen': {'type': 'date'},
                    'status': {'type': 'keyword'},
                },
            },
        }
        r = _session().put(f'{ES_URL}/{ASSET_INDEX}', auth=(ES_USER, ES_PASSWORD),
                           json=body, timeout=15)
        r.raise_for_status()
        r = _session().post(f'{ES_URL}/_aliases', auth=(ES_USER, ES_PASSWORD),
                            json={'actions': [{'add': {'index': ASSET_INDEX, 'alias': ASSET_ALIAS}}]},
                            timeout=15)
        r.raise_for_status()
        logger.info('asset inventory index %s created (alias %s)', ASSET_INDEX, ASSET_ALIAS)
        return True
    except Exception as e:
        logger.warning('ensure_index failed: %s', e)
        return False


def asset_identity(ip=None, mac=None, hostname=None):
    """Return (asset_id, identity_kind) using stable identity logic."""
    ip = (ip or '').strip()
    mac = (mac or '').strip().lower()
    hostname = (hostname or '').strip().lower()
    if mac and ip and hostname:
        kind, raw = 'mac+ip+hostname', f'{mac}|{ip}|{hostname}'
    elif ip and hostname:
        kind, raw = 'ip+hostname', f'{ip}|{hostname}'
    elif hostname:
        kind, raw = 'hostname', hostname
    elif ip:
        kind, raw = 'ip', ip
    else:
        return None, None
    return hashlib.sha1(raw.encode()).hexdigest()[:16], kind


def get_asset(asset_id):
    try:
        r = _session().get(f'{ES_URL}/{ASSET_ALIAS}/_doc/{asset_id}',
                           auth=(ES_USER, ES_PASSWORD), timeout=10)
        if r.status_code == 200:
            return r.json().get('_source') or {}
        if r.status_code == 404:
            return None
        r.raise_for_status()
    except Exception as e:
        logger.warning('get_asset(%s) failed: %s', asset_id, e)
    return None


def upsert_asset(ip=None, mac=None, hostname=None, os_name=None, services=None,
                 cpes=None, software=None, source='nmap'):
    """Create or update an asset document from a host observation.

    Returns the asset_id or None on failure. Worker-owned fields are merged
    over the existing doc so portal-managed metadata survives.

    Identity-drift detection (user requirement: "same IP, different machine"):
    when a previously-seen MAC at this IP is replaced by a different MAC the
    asset is flagged device_changed and the observation history records what
    was there before.
    """
    ensure_index()
    asset_id, kind = asset_identity(ip=ip, mac=mac, hostname=hostname)
    if not asset_id:
        return None

    services = services or {}
    now = utcnow_iso()
    existing = get_asset(asset_id) or {}

    ports = [k for k in sorted(services, key=lambda x: str(x))]
    sw = sorted({s for s in (software or []) if s} |
                {f"{svc.get('product')}{' ' + svc['version'] if svc.get('version') else ''}".strip()
                 for svc in services.values() if svc.get('product')})

    # ---- identity-drift detection -----------------------------------------
    history = list(existing.get('observations_history') or [])
    prev_mac = existing.get('mac_address')
    new_mac = mac or None
    device_changed = False
    change_reason = existing.get('device_change_reason')
    fingerprint_src = f"{new_mac or ''}|{os_name or ''}|{'-'.join(str(p) for p in ports)}"
    fingerprint = hashlib.sha1(fingerprint_src.encode()).hexdigest()[:12]
    if prev_mac and new_mac and prev_mac.lower() != new_mac.lower():
        device_changed = True
        change_reason = f"MAC changed {prev_mac} -> {new_mac}"
        history.insert(0, {
            'date': now,
            'event': 'device_changed',
            'detail': change_reason,
            'previous': {'mac': prev_mac, 'os': existing.get('os'),
                         'hostname': existing.get('hostname'),
                         'open_ports': existing.get('open_ports')},
        })
        logger.warning('[ASSET] identity change at %s: %s', ip, change_reason)
    elif existing.get('fingerprint') and fingerprint != existing.get('fingerprint'):
        # surface evolution (ports/os) - recorded, but not flagged as a swap
        history.insert(0, {
            'date': now,
            'event': 'surface_changed',
            'detail': f"os='{os_name}' ports={len(ports)} hostname={hostname}",
        })
    history = history[:10]

    doc = dict(existing)  # preserve metadata (criticality, owner, ...)
    doc.update({
        'asset_id': asset_id,
        'identity_kind': kind,
        'ip_address': ip or existing.get('ip_address'),
        'mac_address': new_mac or existing.get('mac_address'),
        'hostname': hostname or existing.get('hostname'),
        'os': os_name or existing.get('os'),
        'services': {str(p): services[p] for p in ports},
        'open_ports': len(ports),
        'cpes': sorted({c for c in (cpes or []) if c} | set(existing.get('cpes') or [])),
        'software': sorted(set(sw) | set(existing.get('software') or [])),
        'first_seen': existing.get('first_seen', now),
        'last_seen': now,
        'status': existing.get('status', 'active') if existing.get('status') in ('decommissioned',)
                  else 'active',
        'source': source,
        'fingerprint': fingerprint,
        'device_changed': bool(device_changed or existing.get('device_changed')),
        'device_change_reason': change_reason,
        'observations_history': history,
    })
    if 'criticality' not in doc or doc['criticality'] not in CRITICALITY_LABELS:
        try:
            doc['criticality'] = int(doc.get('criticality') or 3)
        except (TypeError, ValueError):
            doc['criticality'] = 3
    if 'status' not in doc or not doc.get('status'):
        doc['status'] = 'active'
    try:
        r = _session().put(f'{ES_URL}/{ASSET_ALIAS}/_doc/{asset_id}',
                           auth=(ES_USER, ES_PASSWORD), json=doc, timeout=15)
        r.raise_for_status()
        return asset_id
    except Exception as e:
        logger.warning('upsert_asset(%s) failed: %s', asset_id, e)
        return None


def patch_metadata(asset_id, fields):
    """Patch portal-managed metadata fields on an asset. Returns old/new."""
    existing = get_asset(asset_id)
    if existing is None:
        raise KeyError(f'asset {asset_id} not found')
    clean = {k: v for k, v in fields.items() if k in METADATA_FIELDS}
    if not clean:
        return existing, existing
    updated = dict(existing)
    updated.update(clean)
    if 'criticality' in clean and int(clean['criticality']) not in CRITICALITY_LABELS:
        raise ValueError(f'criticality must be one of {sorted(CRITICALITY_LABELS)}')
    if clean.get('environment') and str(clean['environment']).lower() not in ENVIRONMENTS:
        raise ValueError(f'environment must be one of {ENVIRONMENTS}')
    if clean.get('status') and str(clean['status']).lower() not in ASSET_STATUSES:
        raise ValueError(f'status must be one of {ASSET_STATUSES}')
    if 'environment' in updated and updated['environment']:
        updated['environment'] = str(updated['environment']).lower()
    if 'status' in updated and updated['status']:
        updated['status'] = str(updated['status']).lower()
    try:
        r = _session().put(f'{ES_URL}/{ASSET_ALIAS}/_doc/{asset_id}',
                           auth=(ES_USER, ES_PASSWORD), json=updated, timeout=15)
        r.raise_for_status()
    except Exception as e:
        raise RuntimeError(f'Elasticsearch unreachable: {e}')
    return existing, updated


def mark_missing_hosts_inactive(seen_asset_ids, subnet_scope=True):
    """After a full-subnet scan, assets previously active that were NOT seen
    become inactive (not decommissioned - a single missed ping is not proof)."""
    body = {
        'script': {'source': "ctx._source.status = 'inactive'", 'lang': 'painless'},
        'query': {
            'bool': {
                'filter': [
                    {'term': {'status': 'active'}},
                    {'bool': {'must_not': [{'terms': {'_id': list(seen_asset_ids)}}]}},
                ],
            },
        },
    }
    try:
        r = _session().post(f'{ES_URL}/{ASSET_ALIAS}/_update_by_query?conflicts=proceed',
                            auth=(ES_USER, ES_PASSWORD), json=body, timeout=60)
        r.raise_for_status()
        n = r.json().get('updated', 0)
        if n:
            logger.info('asset inventory: %s asset(s) marked inactive (not seen in last full scan)', n)
        return n
    except Exception as e:
        logger.warning('mark_missing_hosts_inactive failed: %s', e)
        return 0


def get_asset_context(ip):
    """Lightweight context lookup used by the risk pipeline.

    Returns dict(criticality, environment, internet_exposed, business_service,
    network_zone) with safe defaults when the asset is unknown.
    """
    defaults = {'criticality': 3, 'environment': '', 'internet_exposed': False,
                'business_service': '', 'network_zone': ''}
    try:
        r = _session().post(f'{ES_URL}/{ASSET_ALIAS}/_search',
                            auth=(ES_USER, ES_PASSWORD),
                            json={'size': 1, 'query': {'term': {'ip_address': ip}}},
                            timeout=10)
        r.raise_for_status()
        hits = r.json().get('hits', {}).get('hits', [])
        if not hits:
            return defaults
        src = hits[0].get('_source', {})
        try:
            defaults['criticality'] = int(src.get('criticality') or 3)
        except (TypeError, ValueError):
            pass
        defaults['environment'] = src.get('environment') or ''
        defaults['internet_exposed'] = bool(src.get('internet_exposed'))
        defaults['business_service'] = src.get('business_service') or ''
        defaults['network_zone'] = src.get('network_zone') or ''
        return defaults
    except Exception:
        return defaults
