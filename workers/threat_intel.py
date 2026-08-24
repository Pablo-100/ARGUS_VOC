import gzip
import io
import json
import logging
import os
import re
import threading
import time
import csv as _csv

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
EPSS_API_URL = os.getenv('EPSS_API_URL', 'https://api.first.org/data/v1/epss')
KEV_CATALOG_URL = os.getenv('KEV_CATALOG_URL',
                            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
OSV_API_URL = os.getenv('OSV_API_URL', 'https://api.osv.dev')
EXPLOITDB_CSV_URL = os.getenv('EXPLOITDB_CSV_URL',
                              'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
VIRUSTOTAL_API_URL = os.getenv('VIRUSTOTAL_API_URL', 'https://www.virustotal.com/api/v3')

CACHE_TTL_DEFAULT = int(os.getenv('TI_CACHE_TTL', '86400'))  # 24h
EXPLOITDB_REFRESH_HOURS = int(os.getenv('EXPLOITDB_REFRESH_HOURS', '24'))
TI_TIMEOUT = int(os.getenv('TI_TIMEOUT', '30'))

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def create_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=["HEAD", "GET", "POST"])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def _fetch(url, params=None, json_body=None, headers=None, timeout=TI_TIMEOUT):
    session = create_session()
    if json_body is not None:
        r = session.post(url, params=params, json=json_body, headers=headers, timeout=timeout)
    else:
        r = session.get(url, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Cache helpers (Redis-first, in-memory fallback)
# ---------------------------------------------------------------------------
_mem_cache = {}
_mem_lock = threading.Lock()


class _Cache:
    def __init__(self):
        self._r = None

    def _redis(self):
        if self._r is None:
            try:
                import redis
                self._r = redis.Redis(
                    host=os.getenv('REDIS_HOST', 'redis'),
                    port=int(os.getenv('REDIS_PORT', 6379)),
                    db=int(os.getenv('REDIS_DB', 0)),
                    password=os.getenv('REDIS_PASSWORD') or None,
                    decode_responses=True,
                )
                self._r.ping()
            except Exception:
                self._r = None
        return self._r

    def get(self, key):
        r = self._redis()
        if r is not None:
            try:
                raw = r.get(f'voc:ti:{key}')
                if raw:
                    return json.loads(raw)
            except Exception:
                pass
        with _mem_lock:
            item = _mem_cache.get(key)
            if item and time.time() < item['exp']:
                return item['value']
        return None

    def set(self, key, value, ttl=CACHE_TTL_DEFAULT):
        r = self._redis()
        if r is not None:
            try:
                r.setex(f'voc:ti:{key}', ttl, json.dumps(value, default=str))
            except Exception:
                pass
        with _mem_lock:
            _mem_cache[key] = {'value': value, 'exp': time.time() + ttl}


_cache = _Cache()


# ---------------------------------------------------------------------------
# EPSS (FIRST) - Exploit Prediction Scoring System
# ---------------------------------------------------------------------------
def get_epss(cve):
    cve = cve.upper()
    cached = _cache.get(f'epss:{cve}')
    if cached is not None:
        return cached or None
    result = None
    try:
        data = _fetch(EPSS_API_URL, params={'cve': cve})
        scores = data.get('data', []) or data.get('score', [])
        if scores:
            s = scores[0]
            result = {
                'epss_score': float(s.get('epss', 0.0)),
                'epss_percentile': float(s.get('percentile', 0.0)),
                'epss_date': s.get('date', ''),
            }
            logger.info(f"EPSS {cve}: {result['epss_score']:.4f} (p{result['epss_percentile']:.4f})")
    except Exception as e:
        logger.warning(f"EPSS lookup failed for {cve}: {e}")
    _cache.set(f'epss:{cve}', result or {})
    return result


# ---------------------------------------------------------------------------
# CISA KEV - Known Exploited Vulnerabilities
# ---------------------------------------------------------------------------
def get_kev_catalog():
    cached = _cache.get('kev:catalog')
    if cached is not None:
        return cached
    catalog = {}
    try:
        data = _fetch(KEV_CATALOG_URL, timeout=60)
        for vuln in data.get('vulnerabilities', []):
            cve = str(vuln.get('cveID', '')).upper()
            if cve:
                catalog[cve] = {
                    'kev_vendor': vuln.get('vendorProject', ''),
                    'kev_product': vuln.get('product', ''),
                    'kev_name': vuln.get('vulnerabilityName', ''),
                    'kev_date_added': vuln.get('dateAdded', ''),
                    'kev_description': vuln.get('shortDescription', ''),
                    'kev_required_action': vuln.get('requiredAction', ''),
                    'kev_due_date': vuln.get('dueDate', ''),
                    'kev_ransomware': bool(vuln.get('knownRansomwareCampaignUse', '')),
                }
        logger.info(f"KEV catalog loaded: {len(catalog)} entries")
    except Exception as e:
        logger.warning(f"KEV catalog download failed: {e}")
    _cache.set('kev:catalog', catalog, ttl=CACHE_TTL_DEFAULT)
    return catalog


def get_kev_entry(cve):
    return get_kev_catalog().get(cve.upper())


# ---------------------------------------------------------------------------
# OSV - Open Source Vulnerability DB (references incl. exploits)
# ---------------------------------------------------------------------------
def get_osv(cve):
    cve = cve.upper()
    cached = _cache.get(f'osv:{cve}')
    if cached is not None:
        return cached or None
    result = None
    try:
        data = _fetch(f'{OSV_API_URL}/v1/vulns/{cve}')
        refs = [r.get('url', '') for r in data.get('references', []) if r.get('url')]
        result = {
            'osv_id': data.get('id', cve),
            'osv_summary': data.get('details', ''),
            'osv_published': data.get('published', ''),
            'osv_modified': data.get('modified', ''),
            'osv_aliases': data.get('aliases', []),
            'osv_references': refs,
            'osv_severity': _extract_osv_severity(data),
        }
        result['osv_has_exploit'] = _osv_references_indicate_exploit(refs)
        logger.info(f"OSV {cve}: {len(refs)} refs, exploit_hint={result['osv_has_exploit']}")
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            logger.info(f"OSV no entry for {cve}")
        else:
            logger.warning(f"OSV lookup failed for {cve}: {e}")
    except Exception as e:
        logger.warning(f"OSV lookup failed for {cve}: {e}")
    _cache.set(f'osv:{cve}', result or {})
    return result


def _extract_osv_severity(data):
    sev = data.get('severity') or []
    if sev:
        return [{'type': s.get('type', ''), 'score': s.get('score', '')} for s in sev]
    # fall back to database_specific CVSS
    db = data.get('database_specific') or {}
    cvss = db.get('severity')
    if cvss:
        return [{'type': 'CVSS', 'score': str(cvss)}]
    return []


_EXPLOIT_KEYWORDS = re.compile(
    r'(exploit-db|exploitdb|exploits/|/exploits|poc|proof[-_ ]?of[-_ ]?concept|metasploit|rapid7|kernel\.org|'
    r'cve-mitre|nuclei-template|nuclei\b|searchsploit|buffal0|'
    r'github\.com.*(exploit|poc)|raw\.githubusercontent.*(poc|cve)|CVE.*exploit)', re.IGNORECASE)


def _osv_references_indicate_exploit(refs):
    for url in refs:
        if _EXPLOIT_KEYWORDS.search(url):
            return True
    return False


# ---------------------------------------------------------------------------
# Exploit-DB (CSV snapshot) - optional, memory-cached
# ---------------------------------------------------------------------------
_edb_index = {}
_edb_index_ts = 0.0
_edb_lock = threading.Lock()
_EDB_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def _load_exploitdb_index(force=False):
    global _edb_index, _edb_index_ts
    now = time.time()
    with _edb_lock:
        if _edb_index and not force and (now - _edb_index_ts) < EXPLOITDB_REFRESH_HOURS * 3600:
            return _edb_index
        try:
            session = create_session()
            r = session.get(EXPLOITDB_CSV_URL, timeout=120)
            r.raise_for_status()
            decoded = r.content.decode('utf-8', errors='replace')
            index = {}
            for row in _csv.DictReader(io.StringIO(decoded)):
                codes = row.get('codes', '') or ''
                cves = set(_EDB_CVE_RE.findall(codes))
                if not cves:
                    continue
                entry = {
                    'id': row.get('id', ''),
                    'file': row.get('file', ''),
                    'description': (row.get('description', '') or '')[:300],
                    'type': row.get('type', ''),
                    'platform': row.get('platform', ''),
                    'verified': row.get('verified', ''),
                    'source_url': row.get('source_url', ''),
                    'exploitdb_url': f"https://www.exploit-db.com/exploits/{row.get('id', '')}",
                }
                for cve in cves:
                    index.setdefault(cve.upper(), []).append(entry)
            _edb_index = index
            _edb_index_ts = now
            logger.info(f"Exploit-DB index loaded: {len(index)} CVEs, {sum(len(v) for v in index.values())} exploits")
        except Exception as e:
            logger.warning(f"Exploit-DB index download failed: {e}")
        return _edb_index


def search_exploitdb(cve):
    if not EXPLOITDB_CSV_URL:
        return []
    index = _load_exploitdb_index()
    return index.get(cve.upper(), [])


# ---------------------------------------------------------------------------
# VirusTotal - optional (requires API key)
# ---------------------------------------------------------------------------
def get_virustotal(cve):
    if not VIRUSTOTAL_API_KEY:
        return None
    cve = cve.upper()
    cached = _cache.get(f'vt:{cve}')
    if cached is not None:
        return cached or None
    result = None
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        data = _fetch(f'{VIRUSTOTAL_API_URL}/search', params={'query': cve}, headers=headers)
        items = data.get('data', [])
        detections = []
        for item in items:
            attrs = item.get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            detections.append({
                'type': item.get('type', ''),
                'name': attrs.get('meaningful_name') or attrs.get('name') or item.get('id', ''),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': attrs.get('reputation', 0),
            })
        total = len(items)
        mal = sum(1 for d in detections if d['malicious'] > 0)
        result = {
            'vt_total': total,
            'vt_malicious_count': mal,
            'vt_verdict': 'malicious' if mal > 0 else ('suspicious' if any(d['suspicious'] > 0 for d in detections) else 'benign'),
            'vt_detections': detections[:10],
            'vt_source': 'virustotal',
        }
        logger.info(f"VirusTotal {cve}: {mal}/{total} malicious matches")
    except Exception as e:
        logger.warning(f"VirusTotal lookup failed for {cve}: {e}")
    _cache.set(f'vt:{cve}', result or {})
    return result


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------
def enrich_threat_intel(cve):
    """Consolidate EPSS + KEV + OSV + ExploitDB + VirusTotal for a CVE."""
    cve = cve.upper()
    result = {'cve': cve}

    epss = get_epss(cve)
    if epss:
        result.update(epss)

    kev = get_kev_entry(cve)
    if kev:
        result['in_kev'] = True
        result['kev'] = kev
    else:
        result['in_kev'] = False

    osv = get_osv(cve)
    if osv:
        result['osv'] = osv

    edb = search_exploitdb(cve)
    if edb:
        result['exploitdb'] = edb

    vt = get_virustotal(cve)
    if vt:
        result['virustotal'] = vt

    # Determine exploit availability from all sources.
    result['exploit_available'] = bool(
        result.get('in_kev') or
        (osv or {}).get('osv_has_exploit') or
        bool(edb)
    )
    return result
