import json
import logging
import os
import re
import time
import threading
import requests

logger = logging.getLogger(__name__)

NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
VERIFY_SSL = True

NVD_CACHE_TTL = int(os.getenv('NVD_CACHE_TTL', '86400'))  # 24h Redis/in-memory TTL

try:
    import redis as _redis
except ImportError:
    _redis = None

_cache = {}
_cache_lock = threading.Lock()
_last_request_ts = 0.0
_rate_lock = threading.Lock()


def _redis_client():
    if _redis is None:
        return None
    try:
        return _redis.Redis(
            host=os.getenv('REDIS_HOST', 'redis'),
            port=int(os.getenv('REDIS_PORT', 6379)),
            db=int(os.getenv('REDIS_DB', 0)),
            password=os.getenv('REDIS_PASSWORD') or None,
            decode_responses=True,
        )
    except Exception:
        return None


def _nvd_cache_get(key):
    """Return a cached NVD result (Redis-first, in-memory fallback) or None."""
    with _cache_lock:
        item = _cache.get(key)
        if item and time.time() < item['exp']:
            return item['value']
    try:
        r = _redis_client()
        if r is not None:
            raw = r.get(f'voc:nvd:{key[0]}|{key[1]}')
            if raw:
                val = json.loads(raw)
                with _cache_lock:
                    _cache[key] = {'value': val, 'exp': time.time() + NVD_CACHE_TTL}
                return val
    except Exception:
        pass
    return None


def _nvd_cache_set(key, value):
    with _cache_lock:
        _cache[key] = {'value': value, 'exp': time.time() + NVD_CACHE_TTL}
    try:
        r = _redis_client()
        if r is not None:
            r.setex(f'voc:nvd:{key[0]}|{key[1]}', NVD_CACHE_TTL, json.dumps(value))
    except Exception:
        pass

_VERSION_RE = re.compile(r'\d+(\.\d+)*')

# Detected product/service name -> (vendor, product) for NVD CPE matching.
PRODUCT_CPE = {
    'apache': ('apache', 'http_server'),
    'apache httpd': ('apache', 'http_server'),
    'apache http server': ('apache', 'http_server'),
    'httpd': ('apache', 'http_server'),
    'nginx': ('f5', 'nginx'),
    'nginx web server': ('f5', 'nginx'),
    'openssh': ('openbsd', 'openssh'),
    'ssh': ('openbsd', 'openssh'),
    'openssh portable': ('openbsd', 'openssh'),
    'vsftpd': ('vsftpd', 'vsftpd'),
    'mysql': ('oracle', 'mysql'),
    'mariadb': ('mariadb', 'mariadb'),
    'redis': ('redis', 'redis'),
    'redis key-value store': ('redis', 'redis'),
    'elasticsearch': ('elastic', 'elasticsearch'),
    'rabbitmq': ('pivotal_software', 'rabbitmq'),
    'postgresql': ('postgresql', 'postgresql'),
    'postgres': ('postgresql', 'postgresql'),
    'mongodb': ('mongodb', 'mongodb'),
    'memcached': ('memcached', 'memcached'),
    'php': ('php', 'php'),
    'apache tomcat': ('apache', 'tomcat'),
    'tomcat': ('apache', 'tomcat'),
    'openssl': ('openssl', 'openssl'),
    'exim': ('exim', 'exim'),
    'proftpd': ('proftpd', 'proftpd'),
    'gitlab': ('gitlab', 'gitlab'),
    'grafana': ('grafana', 'grafana'),
    'jenkins': ('jenkins', 'jenkins'),
    'wordpress': ('wordpress', 'wordpress'),
    'drupal': ('drupal', 'drupal'),
    'docker': ('docker', 'docker'),
    'kubernetes': ('kubernetes', 'kubernetes'),
    'nfs': ('netapp', 'nfs'),
    'samba': ('samba', 'samba'),
    'smtp': ('gnu', 'mailutils'),
    'pop3': ('gnu', 'mailutils'),
    'imap': ('gnu', 'mailutils'),
    'snmp': ('net-snmp', 'net-snmp'),
    'telnet': ('netkit', 'netkit-telnet'),
    'ftp': ('ftpd', 'ftpd'),
    'proftp': ('proftpd', 'proftpd'),
    'http-proxy': ('apache', 'http_server'),
    'ssl': ('openssl', 'openssl'),
}


def _rate_limited_request(params):
    global _last_request_ts
    with _rate_lock:
        elapsed = time.time() - _last_request_ts
        if elapsed < 6.0:
            time.sleep(6.0 - elapsed)
        try:
            r = requests.get(NVD_BASE, params=params, timeout=25, verify=VERIFY_SSL)
            _last_request_ts = time.time()
            return r
        except Exception:
            _last_request_ts = time.time()
            raise


def _parse_version(version):
    if not version:
        return None
    version = version.strip().strip('"')
    m = _VERSION_RE.search(version)
    if not m:
        return None
    return [int(x) for x in m.group(0).split('.')]


def _compare_versions(v1, v2):
    if v1 is None or v2 is None:
        return 0
    for i in range(max(len(v1), len(v2))):
        a = v1[i] if i < len(v1) else 0
        b = v2[i] if i < len(v2) else 0
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


def _version_in_range(version, match):
    if version is None:
        return False
    start_inc = match.get('versionStartIncluding')
    start_exc = match.get('versionStartExcluding')
    end_inc = match.get('versionEndIncluding')
    end_exc = match.get('versionEndExcluding')
    if not (start_inc or start_exc or end_inc or end_exc):
        cpe_ver = _extract_cpe_version(match.get('criteria', ''))
        if cpe_ver is not None:
            return _compare_versions(version, cpe_ver) == 0
        return True
    if start_inc and _compare_versions(version, _parse_version(start_inc)) < 0:
        return False
    if start_exc and _compare_versions(version, _parse_version(start_exc)) <= 0:
        return False
    if end_inc and _compare_versions(version, _parse_version(end_inc)) > 0:
        return False
    if end_exc and _compare_versions(version, _parse_version(end_exc)) >= 0:
        return False
    return True


def _extract_cpe_version(criteria):
    # CPE 2.3: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:...
    parts = criteria.split(':')
    if len(parts) >= 6:
        ver_field = parts[5]
        if ver_field and ver_field != '*' and ver_field != '-':
            return _parse_version(ver_field)
    return None


def _cpe_products(criteria):
    # cpe:2.3:<part>:<vendor>:<product>:<version>:... -> vendor=idx3, product=idx4
    parts = criteria.split(':')
    if len(parts) >= 5:
        return [parts[3], parts[4]] if parts[4] != '*' else [parts[3]]
    return []


def _product_token_matches(product_token, crit_products):
    if not product_token or not crit_products:
        return False
    pt = product_token.lower().replace(' ', '')
    words = [w for w in re.split(r'[^a-z0-9]+', product_token.lower()) if w]
    for cp in crit_products:
        if not cp:
            continue
        cp = cp.lower().replace('_', '')
        if cp in pt or pt in cp:
            return True
        for w in words:
            if len(w) >= 4 and w in cp:
                return True
    return False


def _cve_affects_product_version(cve, product_token, version):
    """True only if an affected cpeMatch node references the product AND version in range."""
    configs = cve.get('configurations', [])
    if not configs:
        return False
    for config in configs:
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if not match.get('vulnerable', True):
                    continue
                criteria = match.get('criteria', '')
                if not criteria.lower().startswith('cpe:2.3:a:'):
                    continue
                crit_products = _cpe_products(criteria)
                if not _product_token_matches(product_token, crit_products):
                    continue
                if _version_in_range(version, match):
                    return True
    return False


def _normalize_version(version):
    if not version:
        return ''
    m = _VERSION_RE.search(version)
    return m.group(0) if m else version.strip()


def _extract_cwes(cve):
    """Extract CWE IDs (e.g. CWE-79) from an NVD 2.0 CVE record."""
    cwes = []
    for weakness in cve.get('weaknesses', []):
        if weakness.get('type') != 'CWE':
            continue
        for desc in weakness.get('description', []):
            value = desc.get('value', '')
            if value.startswith('CWE-'):
                cwes.append(value)
    # de-dup, keep order
    seen = set()
    out = []
    for cwe in cwes:
        if cwe not in seen:
            seen.add(cwe)
            out.append(cwe)
    return out


def _find_cpe(product):
    key = product.strip().lower()
    if key in PRODUCT_CPE:
        return PRODUCT_CPE[key]
    for k, v in PRODUCT_CPE.items():
        if k in key or key in k:
            return v
    return None


def lookup_cves(product, version):
    """Return real CVEs from NVD for a product+version. Empty list = none found."""
    if not product:
        return []
    cache_key = (product.lower().strip(), (version or '').strip())
    cached = _nvd_cache_get(cache_key)
    if cached is not None:
        return cached

    norm_version = _normalize_version(version)
    version_parsed = _parse_version(version)
    raw_found = []

    cpe = _find_cpe(product)
    if cpe and norm_version:
        try:
            vendor, prod = cpe
            raw_found = _search_cpe(vendor, prod, norm_version)
        except Exception as e:
            logger.warning(f'NVD cpe search failed for {product} {version}: {e}')

    if not raw_found:
        try:
            raw_found = _search_nvd(f'{product} {norm_version}'.strip())
        except Exception as e:
            logger.warning(f'NVD keyword search failed for {product}: {e}')

    result = []
    for item in raw_found:
        cve = item.get('cve', {})
        cid = cve.get('id', '')
        if not cid or not cid.startswith('CVE-'):
            continue
        if not _cve_affects_product_version(cve, product, version_parsed):
            continue
        metrics = (cve.get('metrics') or {})
        base = None
        for mk in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            if metrics.get(mk):
                base = metrics[mk][0].get('cvssData', {}).get('baseScore')
                if base is not None:
                    break
        if base is None:
            continue
        desc = ''
        for d in cve.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')
                break
        cwes = _extract_cwes(cve)
        severity = ('Critical' if base >= 9.0 else
                    'High' if base >= 7.0 else
                    'Medium' if base >= 4.0 else 'Low')
        result.append({'cve': cid, 'cvss': base, 'severity': severity, 'desc': desc, 'cwes': cwes})

    seen = set()
    unique = []
    for r in result:
        if r['cve'] not in seen:
            seen.add(r['cve'])
            unique.append(r)
    unique.sort(key=lambda x: x['cvss'], reverse=True)

    _nvd_cache_set(cache_key, unique)
    logger.info(f'NVD lookup {product} {version}: {len(unique)} real CVEs')
    return unique


def lookup_cve_record(cve_id):
    """Fetch one CVE record from NVD by id (used to enrich CONFIRMED findings
    discovered by NSE active checks that have no product/version context).

    Returns {cvss, severity, desc, cwes} or {} when not found/unavailable.
    Cached in Redis + memory like the other lookups.
    """
    if not cve_id or not str(cve_id).upper().startswith('CVE-'):
        return {}
    cve_id = str(cve_id).upper()
    key = ('record', cve_id)
    cached = _nvd_cache_get(key)
    if cached is not None:
        return cached

    try:
        r = _rate_limited_request({'cveId': cve_id})
        if r.status_code != 200:
            raise requests.HTTPError(f'{r.status_code}: {r.text[:100]}')
        vulns = r.json().get('vulnerabilities', [])
        record = {}
        for item in vulns:
            cve = item.get('cve', {})
            if cve.get('id', '').upper() != cve_id:
                continue
            metrics = cve.get('metrics') or {}
            base = None
            for mk in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                if metrics.get(mk):
                    base = metrics[mk][0].get('cvssData', {}).get('baseScore')
                    if base is not None:
                        break
            desc = ''
            for d in cve.get('descriptions', []):
                if d.get('lang') == 'en':
                    desc = d.get('value', '')
                    break
            severity = ('Critical' if (base or 0) >= 9.0 else
                        'High' if (base or 0) >= 7.0 else
                        'Medium' if (base or 0) >= 4.0 else 'Low')
            record = {'cvss': base, 'severity': severity,
                      'desc': desc, 'cwes': _extract_cwes(cve)}
            break
        _nvd_cache_set(key, record)
        return record
    except Exception as e:
        logger.warning(f'NVD record lookup failed for {cve_id}: {e}')
        return {}


def _search_cpe(vendor, product, version):
    cpe = f'cpe:2.3:a:{vendor}:{product}:{version}'
    params = {'cpeName': cpe, 'resultsPerPage': 500, 'startIndex': 0}
    r = _rate_limited_request(params)
    if r.status_code != 200:
        raise requests.HTTPError(f'{r.status_code}: {r.text[:100]}')
    data = r.json()
    total = data.get('totalResults', 0)
    results = data.get('vulnerabilities', [])
    start = len(results)
    while start < total and len(results) < 500:
        params['startIndex'] = start
        r = _rate_limited_request(params)
        if r.status_code != 200:
            break
        batch = r.json().get('vulnerabilities', [])
        results.extend(batch)
        start += len(batch)
        if not batch:
            break
    return results


def _search_nvd(query):
    params = {'keywordSearch': query, 'resultsPerPage': 500, 'startIndex': 0}
    r = _rate_limited_request(params)
    if r.status_code != 200:
        raise requests.HTTPError(f'{r.status_code}: {r.text[:100]}')
    data = r.json()
    total = data.get('totalResults', 0)
    results = data.get('vulnerabilities', [])
    start = len(results)
    while start < total and len(results) < 500:
        params['startIndex'] = start
        r = _rate_limited_request(params)
        if r.status_code != 200:
            break
        batch = r.json().get('vulnerabilities', [])
        results.extend(batch)
        start += len(batch)
        if not batch:
            break
    return results
