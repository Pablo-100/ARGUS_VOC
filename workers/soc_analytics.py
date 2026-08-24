#!/usr/bin/env python3
"""SOC analytics: attack-path / blast-radius graph, weekly exploitation
prediction and self-validation against the CISA KEV catalog.

Consumed by three celery tasks (tasks.py):
  * tasks.build_attack_graph  -> docs in `attack-graph-*`
  * tasks.weekly_prediction   -> doc  in `predictions-*`
  * tasks.validate_predictions-> docs in `prediction-validation-*`
"""
import os
import logging
import ipaddress
from datetime import datetime, timedelta, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

ES_URL = os.getenv('ES_URL', 'http://elasticsearch:9200')
ES_USER = os.getenv('ES_USER', 'elastic')
ES_PASSWORD = os.getenv('ELASTIC_PASSWORD', '')
LOGSTASH_URL = os.getenv('LOGSTASH_URL', 'http://logstash:5044')

MODEL_VERSION = 'voc-intel-v1'
HORIZON_DAYS = int(os.getenv('PREDICTION_HORIZON_DAYS', '7'))
PREDICTION_TOP_N = int(os.getenv('PREDICTION_TOP_N', '10'))
CRITICAL_RISK_THRESHOLD = float(os.getenv('CRITICAL_RISK_THRESHOLD', '8.0'))
CRITICAL_ASSETS = {a.strip() for a in os.getenv('CRITICAL_ASSETS', '').split(',') if a.strip()}


def create_session():
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=["GET", "POST"])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    return s


def _search_es(index, body):
    """Run a query against ES and return the list of _source docs."""
    s = create_session()
    resp = s.post(f"{ES_URL}/{index}/_search",
                  auth=(ES_USER, ES_PASSWORD), json=body, timeout=30)
    resp.raise_for_status()
    return [h.get('_source', {}) for h in resp.json().get('hits', {}).get('hits', [])]


def _delete_by_query(index, body):
    s = create_session()
    resp = s.post(f"{ES_URL}/{index}/_delete_by_query?refresh=true",
                  auth=(ES_USER, ES_PASSWORD), json=body, timeout=60)
    resp.raise_for_status()
    return resp.json().get('deleted', 0)


def _post_docs(docs):
    """Send docs to Logstash for indexing (one HTTP request per doc)."""
    if not docs:
        return 0
    s = create_session()
    for d in docs:
        resp = s.post(LOGSTASH_URL, json=d, timeout=15)
        resp.raise_for_status()
    return len(docs)


def json_dumps(obj):
    import json
    return json.dumps(obj, default=str)


# ---------------------------------------------------------------------------
# Feature 1 - Attack path / blast radius graph
# ---------------------------------------------------------------------------

def _same_subnet(a, b, subnets):
    a_ip, b_ip = ipaddress.ip_address(a), ipaddress.ip_address(b)
    for s in subnets:
        net = ipaddress.ip_network(s, strict=False)
        if a_ip in net and b_ip in net:
            return True
    return False


def build_attack_graph():
    """Build the attack-path graph from active findings in Elasticsearch.

    Nodes are vulnerable hosts (from `vulnerabilities-*`), edges are
    same-subnet reachability (lab assumption: hosts on the same discovery
    subnet can reach each other). Blast radius = sum of the risk of the
    critical assets reachable from each host.
    """
    subnets = [s.strip() for s in os.getenv('DISCOVERY_SUBNET', '').split(',') if s.strip()]
    docs = _search_es('vulnerabilities-*', {
        'size': 10000,
        'query': {'bool': {'filter': [{'term': {'status': 'active'}}]}},
        'sort': [{'@timestamp': 'desc'}],
    })

    hosts = {}
    for d in docs:
        ip = d.get('host_ip')
        if not ip:
            continue
        h = hosts.setdefault(ip, {
            'os': d.get('os'), 'services': {}, 'cves': set(),
            'risk_max': 0.0, 'cvss_max': 0.0, 'severity': 'Low',
            'in_kev_any': False, 'exploit_any': False, 'epss_max': 0.0,
        })
        port = d.get('port')
        if port:
            h['services'][str(port)] = {
                'service': d.get('service'), 'product': d.get('product'),
                'version': d.get('version'),
            }
        cve = d.get('cve')
        if cve:
            h['cves'].add(cve)
        h['risk_max'] = max(h['risk_max'], float(d.get('risk_score') or 0.0))
        h['cvss_max'] = max(h['cvss_max'], float(d.get('cvss') or 0.0))
        h['epss_max'] = max(h['epss_max'], float(d.get('epss_score') or 0.0))
        h['in_kev_any'] = h['in_kev_any'] or bool(d.get('in_kev'))
        h['exploit_any'] = h['exploit_any'] or bool(d.get('exploit_available'))
        sev = d.get('severity') or 'Low'
        if h['severity'] != 'Critical' and sev == 'Critical':
            h['severity'] = 'Critical'
        elif h['severity'] != 'Critical' and h['severity'] != 'High' and sev == 'High':
            h['severity'] = 'High'
        elif h['severity'] not in ('Critical', 'High') and sev == 'Medium':
            h['severity'] = 'Medium'

    if not hosts:
        logger.warning('attack-graph: no active findings in Elasticsearch')
        return []

    # critical assets: explicit list OR high risk
    critical = {ip for ip, h in hosts.items()
                if ip in CRITICAL_ASSETS or h['risk_max'] >= CRITICAL_RISK_THRESHOLD}

    nodes, edges = [], []
    for ip, h in hosts.items():
        nodes.append({
            'source': 'voc_graph',
            'snapshot_id': 'latest', 'doc_type': 'node', 'ip': ip, 'os': h['os'],
            'risk_score': round(h['risk_max'], 2), 'cvss': round(h['cvss_max'], 2),
            'severity': h['severity'], 'critical': ip in critical,
            'entry': ip not in critical and len(h['cves']) > 0,
            'service_count': len(h['services']),
            'exploit_count': len(h['cves']),
            'in_kev': h['in_kev_any'], 'exploit_available': h['exploit_any'],
            'epss': round(h['epss_max'], 4),
            'services': [{'port': p, **svc} for p, svc in sorted(h['services'].items())],
        })

    # same-subnet reachability edges
    ips = sorted(hosts)
    for i in range(len(ips)):
        for j in range(i + 1, len(ips)):
            if _same_subnet(ips[i], ips[j], subnets):
                edges.append({
                    'source': 'voc_graph',
                    'snapshot_id': 'latest', 'doc_type': 'edge',
                    'src': ips[i], 'tgt': ips[j], 'kind': 'same-subnet', 'weight': 1,
                })

    # blast radius: critical assets reachable via BFS over subnet edges
    adj = {}
    for e in edges:
        adj.setdefault(e['src'], set()).add(e['tgt'])
        adj.setdefault(e['tgt'], set()).add(e['src'])

    def reachable_critical(start):
        seen, stack = set(), [start]
        total = 0.0
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            if cur in critical and cur != start:
                total += hosts[cur]['risk_max']
            for nxt in adj.get(cur, ()):
                if nxt not in seen:
                    stack.append(nxt)
        return total

    blast = {}
    for ip in hosts:
        blast[ip] = reachable_critical(ip)
        for n in nodes:
            if n['ip'] == ip:
                n['blast_radius'] = round(blast[ip], 2)

    summary = {
        'source': 'voc_graph',
        'snapshot_id': 'latest', 'doc_type': 'summary',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'host_count': len(hosts), 'edge_count': len(edges),
        'critical_assets': sorted(critical), 'subnets': subnets,
        'model_version': MODEL_VERSION,
        'top_blast': sorted([{'ip': ip, 'blast': round(b, 2)} for ip, b in blast.items()],
                            key=lambda x: x['blast'], reverse=True)[:10],
    }

    logger.info(f'attack-graph: {len(nodes)} nodes, {len(edges)} edges, '
                f'{len(critical)} critical assets')
    return [summary] + nodes + edges


# ---------------------------------------------------------------------------
# Feature 2 - Weekly exploitation prediction + self-validation vs KEV
# ---------------------------------------------------------------------------

def _prediction_features():
    """Aggregate active findings per CVE."""
    docs = _search_es('vulnerabilities-*', {
        'size': 10000,
        'query': {'bool': {'filter': [{'term': {'status': 'active'}}]}},
        'sort': [{'@timestamp': 'desc'}],
    })
    per_cve = {}
    for d in docs:
        cve = (d.get('cve') or '').upper()
        if not cve:
            continue
        item = per_cve.setdefault(cve, {
            'epss_score': 0.0, 'epss_percentile': 0.0, 'in_kev': False,
            'exploit_available': False, 'risk_score': 0.0, 'hosts': set(),
        })
        item['epss_score'] = max(item['epss_score'], float(d.get('epss_score') or 0.0))
        item['epss_percentile'] = max(item['epss_percentile'], float(d.get('epss_percentile') or 0.0))
        item['in_kev'] = item['in_kev'] or bool(d.get('in_kev'))
        item['exploit_available'] = item['exploit_available'] or bool(d.get('exploit_available'))
        item['risk_score'] = max(item['risk_score'], float(d.get('risk_score') or 0.0))
        if d.get('host_ip'):
            item['hosts'].add(d['host_ip'])
    for item in per_cve.values():
        item['host_count'] = len(item['hosts'])
    return per_cve


def build_prediction():
    """Predict the top-N CVEs most likely to be exploited in the next week."""
    from threat_intel import get_kev_catalog
    kev = get_kev_catalog()
    per_cve = _prediction_features()
    if not per_cve:
        logger.warning('prediction: no active CVEs to rank')
        return []

    ranked = []
    for cve, f in per_cve.items():
        score = (
            0.40 * min(f['epss_score'], 1.0)
            + 0.15 * min(f['epss_percentile'], 1.0)
            + 0.20 * (1.0 if f['exploit_available'] else 0.0)
            + 0.10 * (1.0 if f['in_kev'] else 0.0)
            + 0.15 * min(f['risk_score'] / 10.0, 1.0)
        )
        ranked.append({'cve': cve, 'pred_score': round(score, 4), **f})

    ranked.sort(key=lambda x: x['pred_score'], reverse=True)
    top = ranked[:PREDICTION_TOP_N]
    prediction = {
        'source': 'voc_prediction',
        'prediction_date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        'horizon_days': HORIZON_DAYS,
        'model_version': MODEL_VERSION,
        'top_n': len(top),
        'top10': [{
            'cve': t['cve'], 'pred_score': t['pred_score'],
            'epss_score': round(t['epss_score'], 4),
            'epss_percentile': round(t['epss_percentile'], 4),
            'in_kev': t['in_kev'], 'exploit_available': t['exploit_available'],
            'risk_score': round(t['risk_score'], 2), 'host_count': t['host_count'],
        } for t in top],
        'predicted_cves': [t['cve'] for t in top],
        'universe_size': len(ranked),
        'kev_total': len(kev),
    }
    logger.info(f'prediction: {len(top)} CVEs ranked from {len(ranked)} candidates')
    return [prediction]


def _kev_added_on_or_after(cve, date_str, kev):
    """True if the CVE was added to KEV on/after the given ISO date."""
    entry = kev.get(cve)
    if not entry or not entry.get('kev_date_added'):
        return False
    try:
        return datetime.fromisoformat(entry['kev_date_added']).date() >= datetime.fromisoformat(date_str).date()
    except ValueError:
        return False


def run_validation():
    """Validate past predictions: did the predicted CVEs actually get
    exploited (per CISA KEV)? Computes precision@N."""
    from threat_intel import get_kev_catalog
    kev = get_kev_catalog()
    predictions = _search_es('predictions-*', {
        'size': 1000, 'query': {'match_all': {}},
        'sort': [{'prediction_date': 'asc'}],
    })
    if not predictions:
        logger.warning('validation: no stored predictions')
        return []

    validated = {d.get('prediction_date') for d in
                 _search_es('prediction-validation-*', {'size': 1000, 'query': {'match_all': {}}})}

    now = datetime.now(timezone.utc).date()
    out = []
    for p in predictions:
        pdate = p.get('prediction_date')
        horizon = int(p.get('horizon_days', HORIZON_DAYS))
        if not pdate or pdate in validated:
            continue
        try:
            pdate_dt = datetime.fromisoformat(pdate).date()
        except ValueError:
            continue
        if (now - pdate_dt).days < horizon:
            continue  # not enough time elapsed yet

        predicted = p.get('predicted_cves', [])
        hits = [c for c in predicted if c in kev]
        new_hits = [c for c in hits if _kev_added_on_or_after(c, pdate, kev)]
        doc = {
            'source': 'voc_validation',
            'prediction_date': pdate,
            'validated_at': datetime.now(timezone.utc).isoformat(),
            'model_version': p.get('model_version', MODEL_VERSION),
            'horizon_days': horizon,
            'top_n': len(predicted),
            'precision_at_10': round(len(hits) / max(len(predicted), 1), 4),
            'precision_new_at_10': round(len(new_hits) / max(len(predicted), 1), 4),
            'hits': hits,
            'new_to_kev_hits': new_hits,
            'predicted_cves': predicted,
        }
        out.append(doc)
        logger.info(f'validation {pdate}: precision@10={doc["precision_at_10"]} '
                    f'({len(hits)}/{len(predicted)}) new_to_kev={len(new_hits)}')
    return out