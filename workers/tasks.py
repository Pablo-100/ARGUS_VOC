import os
import logging
import json
import time
import ipaddress
import requests
import redis
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from celery import Celery, chain, group, chord
from celery.exceptions import MaxRetriesExceededError
from celery.schedules import crontab
from celery.signals import worker_ready
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from scanners import get_adapter, KNOWN_SCANNERS

def _utcnow():
    """Timezone-aware UTC timestamp (ISO-8601) - replaces deprecated utcnow()."""
    return datetime.now(timezone.utc)

# ---------------------------------------------------------------------------
# Runtime guards / performance tuning
# ---------------------------------------------------------------------------
SCAN_LOCK_KEY = 'voc:scan:lock'
# Must exceed the longest possible full-subnet scan: with concurrency=2 workers,
# a -p- (all 65535 ports) + -O scan per host, N live hosts run in ceil(N/2)
# sequential batches - a handful of hosts can easily exceed 1h. Configurable
# because the discovery subnet size varies per deployment.
SCAN_LOCK_TTL = int(os.getenv('SCAN_LOCK_TTL', '10800'))  # 3h default
MISP_CACHE_TTL = 86400        # cache MISP restSearch results per CVE (24h)
MISP_CONCURRENCY = int(os.getenv('MISP_CONCURRENCY', '8'))  # parallel MISP lookups inside one enrich task
DLQ_LOGSTASH_KEY = 'voc:dlq:logstash'  # documents that failed to reach Logstash after all retries
DLQ_TTL = 7 * 24 * 3600        # keep queued docs at most a week
RESOLVED_TOMBSTONE_TTL = int(os.getenv('RESOLVED_TOMBSTONE_TTL', str(30 * 86400)))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Celery('voc')
app.conf.update(
    broker_url=os.getenv('BROKER_URL', 'amqp://guest@localhost//'),
    result_backend=os.getenv('RESULT_BACKEND', 'redis://localhost:6379/0'),
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_routes={
        'tasks.scan_host': {'queue': 'scan'},
        'tasks.nmap_network_scan': {'queue': 'scan'},
        'tasks.process_network_results': {'queue': 'scan'},
        'tasks.scan_host_with': {'queue': 'scan'},
        'tasks.enrich': {'queue': 'enrich'},
        'tasks.enhance': {'queue': 'enrich'},
        'tasks.score': {'queue': 'score'},
        'tasks.index_to_elk': {'queue': 'index'},
        'tasks.create_ticket': {'queue': 'ticket'},
        'tasks.misp_to_glpi': {'queue': 'ticket'},
        'tasks.sync_glpi_to_elk': {'queue': 'index'},
        'tasks.build_attack_graph': {'queue': 'index'},
        'tasks.weekly_prediction': {'queue': 'index'},
        'tasks.validate_predictions': {'queue': 'index'},
        'tasks.drain_logstash_dlq': {'queue': 'index'},
        'tasks.process_verification_requests': {'queue': 'ticket'},
        'tasks.drain_notification_queue': {'queue': 'ticket'},
    },
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    # Beat schedule lives in app.conf so the beat process (which imports
    # tasks.py) actually picks it up.
    beat_schedule={
        'nmapsubnet-scan': {
            'task': 'tasks.nmap_network_scan',
            'schedule': crontab(hour='*/6', minute=0),
            'args': (os.getenv('DISCOVERY_SUBNET', '192.168.184.0/24'),),
        },
        'hourly-glpi-sync': {
            'task': 'tasks.sync_glpi_to_elk',
            'schedule': crontab(minute=0),
        },
        'voc-attack-graph': {
            'task': 'tasks.build_attack_graph',
            'schedule': crontab(hour=7, minute=0),
        },
        'voc-weekly-prediction': {
            'task': 'tasks.weekly_prediction',
            'schedule': crontab(hour=6, minute=0, day_of_week='sun'),
        },
        'voc-weekly-validation': {
            'task': 'tasks.validate_predictions',
            'schedule': crontab(hour=6, minute=30, day_of_week='sun'),
        },
        'voc-dlq-drain': {
            'task': 'tasks.drain_logstash_dlq',
            'schedule': crontab(minute='*/15'),
        },
        'voc-verification-sweeper': {
            'task': 'tasks.process_verification_requests',
            'schedule': crontab(minute='*/5'),
        },
        'voc-notification-drain': {
            'task': 'tasks.drain_notification_queue',
            'schedule': crontab(minute='*/2'),
        },
    },
)

try:
    import nmap
except ImportError:
    nmap = None
    logger.warning("python-nmap not installed")


SCAN_STATE_KEY = 'voc:scan:state'

PORT_LIST = '21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,1723,2049,3000,3306,3389,5432,5601,5672,6379,8080,8081,8443,9200,9300,9600,11211,27017,27018,50000'


def create_session_with_retries(verify_ssl=True):
    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504],
                           allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE"])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    return session


def get_redis():
    return redis.Redis(
        host=os.getenv('REDIS_HOST', 'redis'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        db=int(os.getenv('REDIS_DB', 0)),
        password=os.getenv('REDIS_PASSWORD') or None,
        decode_responses=True,
    )


def load_scan_state():
    try:
        r = get_redis()
        raw = r.get(SCAN_STATE_KEY)
        return json.loads(raw) if raw else {}
    except Exception as e:
        logger.warning(f"Could not load scan state from Redis: {e}")
        return {}


def save_scan_state(state):
    try:
        r = get_redis()
        r.set(SCAN_STATE_KEY, json.dumps(state), ex=24 * 3600)
    except Exception as e:
        logger.warning(f"Could not save scan state to Redis: {e}")


def _dlq_push(doc):
    """Queue a document that permanently failed to reach Logstash (all retries
    exhausted) so it can be replayed once Logstash/ES recovers, instead of
    being silently dropped."""
    try:
        r = get_redis()
        r.rpush(DLQ_LOGSTASH_KEY, json.dumps(doc))
        r.expire(DLQ_LOGSTASH_KEY, DLQ_TTL)
    except Exception as e:
        logger.error(f"Could not queue failed document to DLQ (data will be lost): {e}")


def identify_vulnerabilities(service, product, version, cpe, port):
    """Backward-compatible CVE lookup (used by verification re-scans and
    external callers). The live scan path goes through NmapAdapter."""
    from nvd_client import lookup_cves
    product_key = product if product else service
    vulns = []
    if not product_key:
        return vulns
    for cve in lookup_cves(product_key, version):
        vulns.append({
            "cve": cve.get("cve"), "cvss": cve.get("cvss"),
            "desc": cve.get("desc"), "severity": cve.get("severity"),
            "cwes": cve.get("cwes", []),
        })
    return vulns


# ============================================================
# NMAP / SCANNER TASKS
# ============================================================

def _scan_host_raw(host, scanner='nmap'):
    """Run a full scan of one host via the named scanner adapter.

    Returns the normalized result dict produced by the adapter:
      {host, os, scan_date, vulns[], scan_id, scan_type, observation?, error?}
    """
    try:
        adapter = get_adapter(scanner)
    except KeyError as e:
        raise ValueError(str(e))
    if not adapter.available():
        raise RuntimeError(f"scanner '{scanner}' is not available in this deployment "
                           f"(check its configuration)")
    result = adapter.scan_host(host)
    # Ensure every finding carries the pipeline-required keys.
    for v in result.setdefault('vulns', []):
        v.setdefault('risk_factors', {})
        if not v.get('finding_id'):
            v['finding_id'] = f"{host}|{v.get('cve')}|{v.get('port')}"
    return result


@app.task(bind=True, max_retries=2, default_retry_delay=60)
def scan_host(self, host, dispatch=True, scanner='nmap'):
    """Scan a single host with the given scanner adapter.

    When called directly (dispatch=True) it runs the full VOC pipeline.
    When called from nmap_network_scan (dispatch=False) it only returns the raw
    result; the chord callback process_network_results handles diff + pipeline.
    """
    logger.info(f"Scanning host {host} (scanner={scanner})")
    try:
        result = _scan_host_raw(host, scanner=scanner)
        if dispatch:
            pipeline = chain(enrich.s(), enhance.s(), score.s(), index_to_elk.s(), create_ticket.s())
            pipeline.apply_async(args=[result])
        return result
    except Exception as exc:
        logger.error(f"{scanner} scan failed for {host}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@app.task(bind=True, max_retries=2, default_retry_delay=60)
def scan_host_with(self, host, scanner='nmap', dispatch=False):
    """Explicit scanner-parameterized scan task (used by verification sweeps)."""
    return scan_host.apply_async(args=[host], kwargs={'dispatch': dispatch, 'scanner': scanner})


@app.task(bind=True, max_retries=3, default_retry_delay=120)
def nmap_network_scan(self, subnet):
    """
    Periodic full-subnet nmap scan (scheduled by beat).

    Discovers live hosts across one or more subnets (comma-separated or a list),
    scans each live host with nmap -sV, then diffs the current findings against
    the previous scan state (stored in Redis):
      - new: not present before -> GLPI ticket + MISP event + pipeline
      - still_present: present before and now -> pipeline only (already reported)
      - resolved: present before, gone now -> status update in ELK
    """
    if isinstance(subnet, (list, tuple)):
        subnets = list(subnet)
    else:
        subnets = [s.strip() for s in str(subnet).split(',') if s.strip()]

    # Validate CIDR notation - reject malformed ranges before scanning.
    valid_subnets = []
    for s in subnets:
        try:
            ipaddress.ip_network(s, strict=False)
            valid_subnets.append(s)
        except ValueError as e:
            logger.error(f"Invalid subnet '{s}' ignored (malformed CIDR): {e}")
    subnets = valid_subnets
    if not subnets:
        raise ValueError(f"DISCOVERY_SUBNET contains no valid CIDR ranges: {subnet!r}")

    logger.info(f"Starting nmap network scan: {subnets}")
    try:
        r = get_redis()
        if not r.set(SCAN_LOCK_KEY, datetime.now(timezone.utc).isoformat(), nx=True, ex=SCAN_LOCK_TTL):
            logger.warning("Another network scan is already in progress; skipping this run")
            return {"status": "already_running", "subnet": subnets, "skipped": True}

        if nmap is None:
            # Honesty guarantee: never fabricate hosts when the scanner is
            # unavailable - fail loudly instead (mandate: no fake data).
            raise RuntimeError("python-nmap is not installed in this worker - "
                               "network discovery aborted rather than fabricating results")
        nm = nmap.PortScanner()
        for sub in subnets:
            nm.scan(hosts=sub, arguments='-sn -PE -PS22,80,443,3389')
        hosts = list(nm.all_hosts())
        logger.info(f"Discovered {len(hosts)} hosts: {hosts}")

        if not hosts:
            r.delete(SCAN_LOCK_KEY)
            return {"status": "no_hosts_found", "subnet": subnets}

        scan_id = f"nmap_{int(time.time())}"
        header = [scan_host.s(h, False) for h in hosts]
        callback = process_network_results.s(subnet=subnets, scan_id=scan_id)
        chord(header)(callback)
        return {"status": "started", "scan_id": scan_id, "hosts": hosts, "count": len(hosts),
                "timestamp": datetime.now(timezone.utc).isoformat()}
    except Exception as exc:
        logger.error(f"nmap network scan failed: {exc}")
        # Release the lock so the retry (or the next scheduled run) can
        # actually acquire it instead of seeing "already_running" until the
        # TTL expires on its own.
        try:
            get_redis().delete(SCAN_LOCK_KEY)
        except Exception as del_exc:
            logger.warning(f"Could not release scan lock after failure: {del_exc}")
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=2, default_retry_delay=60)
def process_network_results(self, results, subnet=None, scan_id=None):
    """Compare scan results against previous state and dispatch new/still/resolved.

    Also maintains the asset inventory (Feature 1) and the resolved-tombstone
    store used to detect REOPENED vulnerabilities (a CVE that comes back after
    having been resolved re-enters the pipeline flagged as a reopening).
    """
    now = _utcnow().isoformat(timespec='seconds')
    scan_id = scan_id or f"nmap_{int(time.time())}"
    prev = load_scan_state()
    # Bookkeeping key holding previously-resolved findings (for reopen
    # detection); must not leak into the vuln diff itself.
    tombstones = prev.pop('__tombstones__', {}) if isinstance(prev, dict) else {}
    current = {}
    host_vulns = {}
    host_os = {}
    host_hostnames = {}
    host_observations = {}

    for r in results:
        host = r.get("host")
        if not host:
            continue
        if r.get("os"):
            host_os[host] = r["os"]
        if r.get("observation"):
            host_observations[host] = r["observation"]
            if r["observation"].get("hostname"):
                host_hostnames[host] = r["observation"]["hostname"]
        host_vulns[host] = r.get("vulns", [])
        for v in r.get("vulns", []):
            key = f"{host}|{v.get('cve')}|{v.get('port')}"
            current[key] = {
                "host": host,
                "cve": v.get("cve"),
                "port": v.get("port"),
                "cvss": v.get("cvss"),
                "severity": v.get("severity"),
                "desc": v.get("desc"),
                "service": v.get("service"),
                "product": v.get("product"),
                "version": v.get("version"),
                "first_seen": prev.get(key, {}).get("first_seen") or now
                              if key in prev else now,
                "last_seen": now,
            }

    new_keys = set(current) - set(prev)
    still_keys = set(current) & set(prev)
    resolved_keys = set(prev) - set(current)

    # Tombstones: keys that disappeared before and are now back = REOPENED.
    reopened_keys = {k for k in (new_keys & set(tombstones))}

    logger.info(f"Scan diff: {len(new_keys)} new ({len(reopened_keys)} reopened), "
                f"{len(still_keys)} still present, {len(resolved_keys)} resolved")

    # ---- Feature 1: asset inventory upsert for every observed host ----
    try:
        import assets as assets_mod
        seen_asset_ids = set()
        for host, obs in host_observations.items():
            aid = assets_mod.upsert_asset(
                ip=obs.get('ip') or host,
                mac=obs.get('mac'),
                hostname=obs.get('hostname'),
                os_name=obs.get('os_name') or host_os.get(host),
                services=obs.get('services') or {},
                cpes=obs.get('cpes') or [],
                software=obs.get('software') or [],
            )
            if aid:
                seen_asset_ids.add(aid)
        # hosts scanned without an observation payload still get a minimal entry
        for host in host_vulns:
            if host not in host_observations:
                aid = assets_mod.upsert_asset(ip=host, os_name=host_os.get(host))
                if aid:
                    seen_asset_ids.add(aid)
        if subnet:  # full-subnet scans see every live host -> safe to demote
            assets_mod.mark_missing_hosts_inactive(seen_asset_ids)
    except Exception as e:
        logger.warning(f"Asset inventory update failed: {e}")

    # Dispatch pipeline for each host:
    #  - new vulns -> enrich -> score -> index -> ticket (ticket + MISP event)
    #  - still present -> enrich -> score -> index (no duplicate ticket/event)
    for host, vulns in host_vulns.items():
        new_vulns = [v for v in vulns if f"{host}|{v.get('cve')}|{v.get('port')}" in new_keys]
        still_vulns = [v for v in vulns if f"{host}|{v.get('cve')}|{v.get('port')}" in still_keys]

        if new_vulns:
            reopened = any(f"{host}|{v.get('cve')}|{v.get('port')}" in reopened_keys
                           for v in new_vulns)
            logger.info(f"[{host}] dispatching {len(new_vulns)} NEW vulns"
                        f"{' (REOPENED)' if reopened else ''}")
            data = {"host": host, "os": host_os.get(host),
                    "hostname": host_hostnames.get(host),
                    "vulns": new_vulns,
                    "scan_id": scan_id, "scan_type": "nmap",
                    "reopened": reopened}
            for v in new_vulns:
                key = f"{host}|{v.get('cve')}|{v.get('port')}"
                v["first_seen"] = tombstones[key]['first_seen'] if key in reopened_keys \
                    else now
                v["reopened"] = key in reopened_keys
                if key in reopened_keys:
                    v["previous_resolution"] = tombstones[key]
                try:
                    from misp_client import create_event_from_vuln
                    event_id = create_event_from_vuln(v, host)
                    v["misp_event_id"] = event_id
                    logger.info(f"[MISP] event #{event_id} for {v.get('cve')} on {host}")
                except Exception as e:
                    logger.error(f"[MISP] event creation failed for {v.get('cve')} on {host}: {e}")
            chain(enrich.s(), enhance.s(), score.s(), index_to_elk.s(), create_ticket.s()).apply_async(args=[data])

        if still_vulns:
            logger.info(f"[{host}] re-indexing {len(still_vulns)} still-present vulns")
            data = {"host": host, "os": host_os.get(host),
                    "hostname": host_hostnames.get(host), "vulns": still_vulns,
                    "scan_id": scan_id, "scan_type": "nmap"}
            for v in data["vulns"]:
                key = f"{host}|{v.get('cve')}|{v.get('port')}"
                v["first_seen"] = (prev.get(key) or {}).get("first_seen", now) \
                    if isinstance(prev.get(key), dict) else now
            chain(enrich.s(), enhance.s(), score.s(), index_to_elk.s()).apply_async(args=[data])

    # Mark resolved vulns in ELK + record tombstones so a later re-appearance
    # is treated as a reopening instead of a brand-new finding.
    newly_resolved = {}
    for key in sorted(resolved_keys):
        info = prev.get(key)
        if not isinstance(info, dict):  # skip the __tombstones__ bookkeeping key
            continue
        info['resolved_at'] = now
        newly_resolved[key] = {'first_seen': info.get('first_seen'), 'resolved_at': now}
        try:
            from logstash_client import index_resolved
            index_resolved(info, now)
        except Exception as e:
            logger.warning(f"Could not index resolved vuln {key}: {e}")

    merged_tombstones = {k: v for k, v in tombstones.items() if k not in current}
    merged_tombstones.update(newly_resolved)
    save_scan_state({**current, '__tombstones__': merged_tombstones})

    # Release the mutual-exclusion lock so the next scheduled scan can start.
    try:
        r = get_redis()
        r.delete(SCAN_LOCK_KEY)
    except Exception as e:
        logger.warning(f"Could not release scan lock: {e}")

    summary = {
        "scan_type": "nmap",
        "scan_id": scan_id,
        "subnet": subnet,
        "new": len(new_keys),
        "still_present": len(still_keys),
        "resolved": len(resolved_keys),
        "hosts": len(host_vulns),
    }
    logger.info(f"Scan summary: {summary}")
    return summary


def _misp_rest_search(session, misp_url, headers, cve, redis_client):
    """MISP restSearch for a single CVE, cached in Redis for MISP_CACHE_TTL."""
    key = f"voc:misp:{cve}"
    if redis_client is not None:
        try:
            cached = redis_client.get(key)
            if cached:
                return cve, json.loads(cached)
        except Exception:
            pass
    try:
        resp = session.post(f"{misp_url}/events/restSearch/json", headers=headers,
                            json={"value": cve, "returnFormat": "json"}, timeout=12)
        resp.raise_for_status()
        iocs = resp.json().get("response", [])
        if redis_client is not None:
            try:
                redis_client.setex(key, MISP_CACHE_TTL, json.dumps(iocs))
            except Exception:
                pass
        return cve, iocs
    except Exception as e:
        logger.warning(f"MISP enrichment failed for {cve}: {e}")
        return cve, []


@app.task(bind=True, max_retries=3, default_retry_delay=30)
def enrich(self, data):
    # Guard against out-of-band / injected payloads (no valid scan_id or an
    # unknown scanner type).
    if not data.get("scan_id") or data.get("scan_type") not in KNOWN_SCANNERS:
        logger.error(f"Rejecting enrich payload without valid scan_id/scan_type "
                     f"(possible out-of-band injection): host={data.get('host')} "
                     f"scan_type={data.get('scan_type')!r}")
        return {"rejected": True, "reason": "missing_scan_id", "host": data.get("host")}

    misp_url = os.getenv('MISP_URL', 'https://192.168.184.135:8443')
    misp_key = os.getenv('MISP_KEY', '')
    verify_ssl = os.getenv('MISP_VERIFY_SSL', 'true').lower() == 'true'
    if not misp_key:
        logger.error("[MISP] MISP_KEY is not configured - threat enrichment disabled. "
                     "Set MISP_KEY in .env; this finding will be indexed WITHOUT threat context.")
        for v in data.get("vulns", []):
            v["misp_iocs"] = []
            v["misp_enrichment_error"] = "MISP_KEY not configured"
        return data

    headers = {"Authorization": misp_key, "Accept": "application/json", "Content-Type": "application/json"}
    session = create_session_with_retries(verify_ssl)
    vulns = data.get("vulns", [])
    try:
        redis_client = get_redis()
    except Exception:
        redis_client = None

    cves = list(dict.fromkeys(v.get("cve") for v in vulns if v.get("cve")))
    if cves:
        found = {}
        workers = min(MISP_CONCURRENCY, len(cves))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_misp_rest_search, session, misp_url, headers, cve, redis_client)
                       for cve in cves]
            for fut in as_completed(futures):
                try:
                    cve, iocs = fut.result()
                    found[cve] = iocs
                except Exception as e:
                    logger.warning(f"MISP enrichment task failed: {e}")
        for v in vulns:
            v["misp_iocs"] = found.get(v.get("cve"), [])
    else:
        for v in vulns:
            v["misp_iocs"] = []
    logger.info(f"MISP enrichment complete for {len(vulns)} findings")
    return data


@app.task(bind=True, max_retries=3, default_retry_delay=30)
def enhance(self, data):
    """Enrich each finding with vulnerability classification, MITRE ATT&CK
    mapping, remediation + CIS Benchmark recommendations, threat intelligence
    (EPSS, CISA KEV, OSV/Exploit-DB, VirusTotal) and a validation checklist."""
    from ticket_enrichment import enrich_vulnerability, finalize_description
    host = data.get("host")
    for v in data.get("vulns", []):
        try:
            enrich_vulnerability(v, host)
            finalize_description(v, host)
        except Exception as e:
            logger.error(f"Ticket enrichment failed for {v.get('cve')}: {e}")
            v.setdefault("vuln_type", "Security Vulnerability")
            v.setdefault("cwes", [])
            v.setdefault("attack_techniques", [])
            v.setdefault("attack_tactics", [])
            v.setdefault("checklist", [])
    return data


@app.task(bind=True, max_retries=3, default_retry_delay=30)
def score(self, data):
    """Score every finding via the risk engine, feeding it real asset context
    (criticality / environment / internet exposure) from the asset inventory
    so risk is genuinely contextual instead of CVSS-only."""
    engine = os.getenv('RISK_ENGINE_URL', 'http://risk-engine:8000')
    api_key = os.getenv('RISK_ENGINE_API_KEY', '')
    session = create_session_with_retries()
    try:
        import assets as assets_mod
        asset_ctx = assets_mod.get_asset_context(data.get("host"))
    except Exception:
        asset_ctx = {'criticality': 3, 'environment': '',
                     'internet_exposed': False, 'business_service': '',
                     'network_zone': ''}
    for v in data.get("vulns", []):
        payload = {
            "cvss_base": float(v.get("cvss") or 0.0),
            "is_critical_asset": v.get("is_critical_asset",
                                       int(asset_ctx['criticality']) >= 5),
            "asset_criticality": int(asset_ctx['criticality']),
            "environment_production": str(asset_ctx.get('environment', '')).lower() == 'production',
            "internet_exposed": bool(asset_ctx.get('internet_exposed')),
            "business_service": asset_ctx.get('business_service') or '',
            "misp_threat_active": len(v.get("misp_iocs", [])) > 0,
            "exploit_available": v.get("exploit_available", False),
            "network_exposure": float(v.get("network_exposure",
                                            os.getenv('DEFAULT_NETWORK_EXPOSURE', 0.3))),
            "epss_score": float(v.get("epss_score", 0.0) or 0.0),
            "in_kev": bool(v.get("in_kev", False)),
        }
        headers = {}
        if api_key:
            headers["X-API-Key"] = api_key
        try:
            r = session.post(f"{engine}/score", json=payload, headers=headers, timeout=15)
            r.raise_for_status()
            result = r.json()
            v["risk_score"] = result.get("risk_score", 5.0)
            v["severity"] = result.get("severity", "Medium")
            v["risk_factors"] = result.get("factors", {})
            v["risk_breakdown"] = result.get("breakdown", {})
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                logger.error(f"[RISK-ENGINE] authentication failed - check RISK_ENGINE_API_KEY: {e}")
                raise self.retry(exc=e)
            logger.warning(f"Risk engine failed: {e}")
            v["risk_score"] = float(v.get("cvss") or 0.0)
            v["severity"] = v.get("severity", "Low")
            v["risk_factors"] = {"fallback": True}
        except Exception as e:
            logger.warning(f"Risk engine failed: {e}")
            v["risk_score"] = float(v.get("cvss") or 0.0)
            v["severity"] = v.get("severity", "Low")
            v["risk_factors"] = {"fallback": True}
        # Persist the asset context used for scoring (explainability + UI).
        v["asset_context"] = {
            "criticality": asset_ctx['criticality'],
            "environment": asset_ctx.get('environment'),
            "internet_exposed": bool(asset_ctx.get('internet_exposed')),
            "business_service": asset_ctx.get('business_service'),
        }
        try:
            from ticket_enrichment import finalize_description
            finalize_description(v, data.get("host"))
        except Exception as e:
            logger.warning(f"Description finalization failed for {v.get('cve')}: {e}")
    return data


@app.task(bind=True, max_retries=3, default_retry_delay=15)
def index_to_elk(self, data):
    logstash = os.getenv('LOGSTASH_URL', 'http://logstash:5044')
    session = create_session_with_retries()
    scan_id = data.get("scan_id") or 'unknown'
    for v in data.get("vulns", []):
        # finding_id gives every observation a stable correlation handle that
        # follows it through enrichment -> scoring -> ticket -> verification.
        finding_id = v.get("finding_id") or f"{data['host']}|{v.get('cve')}|{v.get('port')}"
        lifecycle = 'reopened' if (v.get("reopened") or data.get("reopened")) else 'detected'
        doc = {
            "@timestamp": _utcnow().isoformat(timespec='seconds'),
            "host_ip": data["host"],
            "hostname": (data.get("hostname")
                         or (data.get("observation") or {}).get("hostname")),
            "os": data.get("os"),
            "finding_id": finding_id,
            "scan_id": scan_id,
            "scanner": v.get("scanner", data.get("scan_type", "nmap")),
            "lifecycle_state": lifecycle,
            # 'confirmed' = NSE active check proved it; 'potential' = version match
            "confidence": v.get("confidence", "potential"),
            "cve": v.get("cve"), "cvss": v.get("cvss"), "risk_score": v.get("risk_score"),
            "severity": v.get("severity"), "description": v.get("desc"),
            "port": v.get("port"), "service": v.get("service"), "product": v.get("product"),
            "version": v.get("version"), "cpe": v.get("cpe"),
            "source": f"voc-{v.get('scanner', data.get('scan_type', 'nmap'))}",
            "misp_enriched": len(v.get("misp_iocs", [])) > 0,
            "misp_event_id": v.get("misp_event_id"),
            "risk_factors": v.get("risk_factors", {}),
            "risk_breakdown": v.get("risk_breakdown", {}),
            "asset_context": v.get("asset_context", {}),
            "status": "active",
            "first_seen": v.get("first_seen"),
            "last_seen": _utcnow().isoformat(timespec='seconds'),
            "vulnerability_type": v.get("vuln_type"),
            "owasp_category": v.get("owasp_category"),
            "cwe_ids": v.get("cwes", []),
            "attack_tactics": v.get("attack_tactics", []),
            "attack_techniques": [t.get("id") for t in v.get("attack_techniques", [])],
            "epss_score": v.get("epss_score"),
            "epss_percentile": v.get("epss_percentile"),
            "in_kev": v.get("in_kev", False),
            "kev": v.get("kev"),
            "exploit_available": v.get("exploit_available", False),
            "exploitdb": v.get("exploitdb", []),
            "virustotal": v.get("virustotal"),
            "osv": v.get("osv"),
            "remediation": v.get("remediation", []),
            "cis_benchmark": v.get("cis_benchmark"),
            "cis_sections": v.get("cis_sections", []),
            "cis_hardening": v.get("cis_hardening", []),
            "checklist": v.get("checklist", []),
            "technical_description": v.get("technical_description"),
        }
        if v.get("plugin_id"):
            doc["plugin_id"] = v["plugin_id"]
        if v.get("solution"):
            doc["solution"] = v["solution"]
        if not doc.get("evidence") and v.get("evidence"):
            doc["evidence"] = str(v["evidence"])[:4000]
        if v.get("confidence"):
            doc["confidence"] = v["confidence"]
        try:
            r = session.post(logstash, json=doc, timeout=10)
            r.raise_for_status()
        except Exception as e:
            logger.error(f"ELK indexing failed: {e}")
            try:
                raise self.retry(exc=e)
            except MaxRetriesExceededError:
                logger.error(f"ELK indexing permanently failed for {v.get('cve')} on "
                             f"{data.get('host')} after {self.max_retries} retries; queued to DLQ")
                _dlq_push(doc)
    return data


@app.task(bind=True, max_retries=2, default_retry_delay=60)
def create_ticket(self, data):
    if not data.get("vulns"):
        return "no_vulnerabilities"
    from glpi_client import create_ticket as glpi_create_ticket
    from glpi_client import find_existing_ticket as glpi_find_existing
    created = 0
    skipped = 0
    notified = 0
    for v in data.get("vulns", []):
        if v.get("risk_score", 0) >= 7.0:
            try:
                existing = glpi_find_existing(data["host"], v)
                if v.get("reopened") and existing:
                    # The CVE came back after resolution: push the GLPI ticket
                    # back into processing instead of creating a duplicate.
                    from glpi_client import reopen_ticket as glpi_reopen
                    glpi_reopen(existing.get('id'))
                    logger.info(f"[GLPI] reopened ticket #{existing.get('id')} - "
                                f"{v.get('cve')} re-detected on {data['host']}")
                    continue
                if existing:
                    logger.info(f"[GLPI] skipping duplicate ticket for {v.get('cve')} on {data['host']}")
                    skipped += 1
                    continue
                result = glpi_create_ticket(data["host"], v)
                logger.info(f"[GLPI] {result}")
                if result.startswith("ticket_created"):
                    created += 1
            except Exception as e:
                logger.error(f"Failed to create ticket: {e}")
    # Critical-vulnerability notifications (Feature 11) - fire-and-forget,
    # never blocks or fails the pipeline.
    for v in data.get("vulns", []):
        try:
            from notifications import notify_critical_vulnerability
            if notify_critical_vulnerability(v, data.get("host"), scan_id=data.get("scan_id")):
                notified += 1
        except Exception as e:
            logger.warning(f"Critical notification failed for {v.get('cve')}: {e}")
    return f"created_{created}_tickets__skipped_{skipped}_duplicates__notified_{notified}"


# ============================================================
# SOC ANALYTICS TASKS (attack graph + exploitation prediction)
# ============================================================

def _post_analytics(docs):
    """Index analytics docs through Logstash (source field selects the index)."""
    from soc_analytics import _post_docs
    try:
        sent = _post_docs(docs)
        logger.info(f"Indexed {sent} SOC-analytics documents")
        return {"indexed": sent}
    except Exception as e:
        logger.error(f"SOC-analytics indexing failed: {e}")
        return {"indexed": 0, "error": str(e)}


@app.task(bind=True, max_retries=2, default_retry_delay=300)
def build_attack_graph(self):
    """Rebuild the attack-path / blast-radius graph snapshot (daily)."""
    from soc_analytics import build_attack_graph as _build
    from soc_analytics import _delete_by_query
    try:
        _delete_by_query('attack-graph-*', {'query': {'term': {'snapshot_id': 'latest'}}})
        docs = _build()
        return _post_analytics(docs)
    except Exception as exc:
        logger.error(f"build_attack_graph failed: {exc}")
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=2, default_retry_delay=300)
def weekly_prediction(self):
    """Weekly: predict the top-N CVEs most likely to be exploited."""
    from soc_analytics import build_prediction
    try:
        docs = build_prediction()
        return _post_analytics(docs)
    except Exception as exc:
        logger.error(f"weekly_prediction failed: {exc}")
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=2, default_retry_delay=300)
def validate_predictions(self):
    """Weekly: validate past predictions against the current CISA KEV catalog."""
    from soc_analytics import run_validation
    try:
        docs = run_validation()
        return _post_analytics(docs)
    except Exception as exc:
        logger.error(f"validate_predictions failed: {exc}")
        raise self.retry(exc=exc)


# ============================================================
# MISP → GLPI TASK
# ============================================================

@app.task(bind=True, max_retries=3, default_retry_delay=60)
def misp_to_glpi(self, event_data=None):
    from misp_client import search_event
    from glpi_client import create_ticket as glpi_create_ticket

    if event_data:
        events = [event_data]
    else:
        logger.info("Searching MISP for recent events...")
        result = search_event("")
        events = result.get("response", []) if result else []

    created = 0
    for event in events:
        evt = event.get("Event", event)
        info = evt.get("info", "")
        tags = [t.get("name", "") for t in evt.get("Tag", [])]

        severity_tag = next((t for t in tags if t.startswith("severity:")), "")
        severity = severity_tag.split(":")[1] if severity_tag else "Medium"

        host_tag = next((t for t in tags if t.startswith("host:")), "")
        host = host_tag.split(":")[1] if host_tag else "unknown"

        vuln = {
            "cve": info,
            "severity": severity,
            "risk_score": 8.0 if severity == "critical" else 7.0 if severity == "high" else 5.0,
            "desc": info,
            "port": "N/A",
            "misp_iocs": [{"Event": evt}]
        }

        try:
            result = glpi_create_ticket(host, vuln)
            if result.startswith("ticket_created"):
                created += 1
                logger.info(f"Created GLPI ticket from MISP event: {info}")
        except Exception as e:
            logger.error(f"Failed to create GLPI ticket from MISP: {e}")

    return {"created_tickets": created}


# ============================================================
# GLPI → ELK SYNC TASK
# ============================================================

@app.task(bind=True, max_retries=3, default_retry_delay=60)
def sync_glpi_to_elk(self):
    from glpi_sync import get_all_glpi_data
    logstash_url = os.getenv('LOGSTASH_URL', 'http://logstash:5044')
    session = create_session_with_retries()

    glpi_data = get_all_glpi_data()
    tickets = glpi_data.get("tickets", [])

    if not tickets:
        logger.warning("No GLPI tickets to sync")
        return {"synced": 0}

    synced = 0
    for ticket in tickets:
        doc = {
            "@timestamp": ticket.get("date_mod") or ticket.get("date_creation", datetime.now(timezone.utc).isoformat()),
            "ticket_id": ticket.get("id"),
            "title": ticket.get("name", ""),
            "content": ticket.get("content", ""),
            "status": ticket.get("status"),
            "urgency": ticket.get("urgency"),
            "impact": ticket.get("impact"),
            "priority": ticket.get("priority"),
            "type": ticket.get("type"),
            "date_creation": ticket.get("date_creation"),
            "date_mod": ticket.get("date_mod"),
            "closedate": ticket.get("closedate"),
            "source": "glpi",
            "category_id": ticket.get("itilcategories_id")
        }
        try:
            r = session.post(logstash_url, json=doc, timeout=10)
            r.raise_for_status()
            synced += 1
        except Exception as e:
            logger.error(f"GLPI ticket sync failed for ticket {ticket.get('id')}: {e}; queued to DLQ")
            _dlq_push(doc)

    logger.info(f"Synced {synced}/{len(tickets)} GLPI tickets to ELK")
    return {"synced": synced, "total": len(tickets)}


# ============================================================
# DEAD-LETTER DRAIN (replays docs that lost the race with a Logstash outage)
# ============================================================

@app.task(bind=True, max_retries=0)
def drain_logstash_dlq(self):
    """Replay documents queued by index_to_elk/sync_glpi_to_elk after they
    exhausted their own retries during a Logstash/ES outage. Runs every 15min
    (beat schedule); stops for this run as soon as a POST fails again so a
    still-down Logstash doesn't turn into a hot retry loop."""
    logstash = os.getenv('LOGSTASH_URL', 'http://logstash:5044')
    session = create_session_with_retries()
    try:
        r = get_redis()
    except Exception as e:
        logger.warning(f"DLQ drain: could not reach Redis: {e}")
        return {"drained": 0}

    drained = 0
    for _ in range(200):  # cap per run so a huge backlog can't block the queue
        raw = r.lpop(DLQ_LOGSTASH_KEY)
        if raw is None:
            break
        try:
            doc = json.loads(raw)
            resp = session.post(logstash, json=doc, timeout=10)
            resp.raise_for_status()
            drained += 1
        except Exception as e:
            r.rpush(DLQ_LOGSTASH_KEY, raw)
            logger.warning(f"DLQ drain: Logstash still unreachable, stopping this run: {e}")
            break
    if drained:
        logger.info(f"DLQ drain: replayed {drained} previously-failed document(s) to Logstash")
    return {"drained": drained}


# ============================================================
# REMEDIATION VERIFICATION (Feature 6)
# ============================================================
# The portal marks a ticket "remediated" and writes a verification request
# document into Elasticsearch (source=voc_verification). This sweep runs every
# 5 minutes, re-scans the target with the configured scanner, and decides:
#   CVE still present -> REOPEN (ES vuln + GLPI ticket + portal via result doc)
#   CVE gone          -> VERIFIED (portal flips the ticket to solved)
#
# A vulnerability can therefore NEVER become resolved just because a user
# clicked a button - only a scanner-verified absence closes it (or an explicit,
# audited admin override in the portal).

VERIFICATION_INDEX = 'verification-requests'
VERIFICATION_RESULT_INDEX = 'verification-results'


def _es_session():
    return create_session_with_retries()


def _es_request(session, method, path, json_body=None):
    url = os.getenv('ES_URL', 'http://elasticsearch:9200')
    user = os.getenv('ES_USER', 'elastic')
    password = os.getenv('ELASTIC_PASSWORD', '')
    r = session.request(method, f'{url}{path}', auth=(user, password),
                        json=json_body, timeout=30)
    r.raise_for_status()
    return r.json() if r.content else {}


@app.task(bind=True, max_retries=2, default_retry_delay=120)
def process_verification_requests(self):
    """Consume pending verification requests: rescan -> reopen or verify."""
    session = _es_session()
    try:
        data = _es_request(session, 'POST', f'/{VERIFICATION_INDEX}/_search', {
            'size': 10,
            'query': {'term': {'state': 'pending'}},
            'sort': [{'requested_at': 'asc'}],
        })
    except Exception as e:
        logger.warning(f'verification sweep: cannot reach Elasticsearch: {e}')
        return {'checked': 0}

    hits = data.get('hits', {}).get('hits', [])
    if not hits:
        return {'checked': 0}
    processed = 0
    for hit in hits:
        req = hit['_source']
        rid = hit['_id']
        ticket_id = req.get('ticket_id')
        host = req.get('host')
        cve = (req.get('cve') or '').upper()
        port = req.get('port') or ''
        scanner = req.get('scanner') or os.getenv('VERIFICATION_SCANNER', 'nmap')
        if not host or not cve:
            _finish_verification_request(session, rid, {'outcome': 'error',
                                                        'detail': 'malformed request'})
            continue
        try:
            result = _scan_host_raw(host, scanner=scanner)
        except Exception as e:
            # Scanner unavailable is a real operational condition - leave the
            # request pending but record the failure so operators can see it.
            logger.warning(f'verification of {cve} on {host}: scan failed: {e}')
            _note_verification_failure(session, rid, str(e))
            continue

        still_present = False
        evidence = ''
        for v in result.get('vulns', []):
            if (v.get('cve') or '').upper() == cve and \
               (not port or str(v.get('port')) == str(port)):
                still_present = True
                evidence = v.get('desc') or ''
                break

        scan_id = result.get('scan_id') or 'unknown'
        outcome = 'reopen' if still_present else 'verified'
        detail = (f'CVE {cve} STILL PRESENT on {host} ({scanner} scan {scan_id})'
                  if still_present else
                  f'CVE {cve} no longer detected on {host} ({scanner} scan {scan_id})')
        _finish_verification_request(session, rid, {
            'outcome': outcome,
            'ticket_id': ticket_id,
            'host': host,
            'cve': cve,
            'port': port,
            'verification_scan_id': scan_id,
            'scanner': scanner,
            'detail': detail,
            'evidence': evidence,
            'finished_at': _utcnow().isoformat(timespec='seconds'),
        })

        if still_present:
            _reopen_after_verification(session, host, cve, port, scan_id, detail)
        processed += 1
        logger.info(f'[VERIFY] {detail}')
    return {'checked': len(hits), 'processed': processed}


def _update_doc_fields(session, index, doc_id, fields):
    """Partial update of one ES document (creates nothing on missing doc)."""
    try:
        _es_request(session, 'POST', f'/{index}/_update/{doc_id}',
                    {'doc': fields})
        return True
    except Exception as e:
        logger.warning(f'ES update failed for {index}/{doc_id}: {e}')
        return False


def _note_verification_failure(session, doc_id, error):
    """Record a scan failure on the request (kept pending, attempt counted)."""
    try:
        _es_request(session, 'POST', f'/{VERIFICATION_INDEX}/_update/{doc_id}', {
            'script': {
                'source': ("ctx._source.attempts = (ctx._source.attempts ?: 0) + 1; "
                           "ctx._source.last_error = params.err"),
                'params': {'err': str(error)[:500]},
            },
        })
    except Exception as e:
        logger.warning(f'Could not record verification failure on {doc_id}: {e}')


def _finish_verification_request(session, doc_id, fields):
    fields['state'] = 'done'
    _update_doc_fields(session, VERIFICATION_INDEX, doc_id, fields)
    # Mirror the outcome into the results index so the portal can pick it up.
    try:
        _es_request(session, 'POST', f'/{VERIFICATION_RESULT_INDEX}/_doc', fields)
    except Exception as e:
        logger.warning(f'Could not store verification result: {e}')


def _reopen_after_verification(session, host, cve, port, scan_id, detail):
    """CVE still present after remediation claim -> flip everything back."""
    # 1) ES vulnerability docs back to active/reopened.
    try:
        _es_request(session, 'POST', '/vulnerabilities-*/_update_by_query?conflicts=proceed', {
            'query': {'bool': {'filter': [
                {'term': {'status': 'resolved'}},
                {'term': {'cve': cve}},
                {'term': {'host_ip': host}},
            ]}},
            'script': {
                'source': ("ctx._source.status = 'active'; "
                           "ctx._source.lifecycle_state = 'reopened'; "
                           "ctx._source.reopened_at = params.now; "
                           "ctx._source.reopen_reason = params.reason"),
                'params': {'now': _utcnow().isoformat(timespec='seconds'),
                           'reason': detail},
            },
        })
    except Exception as e:
        logger.warning(f'reopen ES update failed for {cve}@{host}: {e}')

    # 2) Re-arm the Redis diff state so future scans treat it as still-present.
    try:
        r = get_redis()
        key = f'{host}|{cve}|{port}'
        raw = r.get(SCAN_STATE_KEY)
        state = json.loads(raw) if raw else {}
        tombstones = state.pop('__tombstones__', {})
        tombstones.pop(key, None)
        state[key] = {
            'host': host, 'cve': cve, 'port': port,
            'first_seen': _utcnow().isoformat(timespec='seconds'),
        }
        save_scan_state({**state, '__tombstones__': tombstones})
    except Exception as e:
        logger.warning(f'reopen Redis state update failed: {e}')


# ============================================================
# NOTIFICATION QUEUE DRAIN (Feature 11 - portal -> worker bridge)
# ============================================================
# The portal cannot talk to Telegram/SMTP directly (no outbound provider
# config there); it enqueues notification request docs into ES
# (source=voc_notify) and this sweep delivers them through the provider
# abstraction in notifications.py every 2 minutes.

NOTIFY_REQUEST_INDEX = 'notification-requests'


@app.task(bind=True, max_retries=0)
def drain_notification_queue(self):
    session = _es_session()
    try:
        data = _es_request(session, 'POST', f'/{NOTIFY_REQUEST_INDEX}/_search', {
            'size': 25,
            'query': {'term': {'state': 'pending'}},
            'sort': [{'requested_at': 'asc'}],
        })
    except Exception as e:
        logger.debug(f'notification drain: ES unreachable: {e}')
        return {'sent': 0}

    from notifications import deliver_request
    hits = data.get('hits', {}).get('hits', [])
    sent = 0
    for hit in hits:
        req = hit['_source']
        try:
            ok = deliver_request(req)
            state = 'sent' if ok else 'failed'
            if ok:
                sent += 1
        except Exception as e:
            logger.warning(f'notification {hit["_id"]} delivery error: {e}')
            state = 'failed'
        _update_doc_fields(session, NOTIFY_REQUEST_INDEX, hit['_id'], {
            'state': state,
            'processed_at': _utcnow().isoformat(timespec='seconds'),
        })
    return {'queued': len(hits), 'sent': sent}
