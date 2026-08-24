"""ES-backed data for the native Vulnerabilities / Attack-Graph / Predictions
page - the portal's replacement for browsing these in Kibana day-to-day.
"""
import requests

from .esdata import ES_URL, ES_USER, ES_PASSWORD

DETAIL_FIELDS = [
    'finding_id', 'scan_id', 'scanner', 'lifecycle_state', 'cve', 'cvss',
    'risk_score', 'severity', 'description', 'technical_description', 'port',
    'service', 'product', 'version', 'cpe', 'host_ip', 'os', 'status',
    'first_seen', 'last_seen', 'epss_score', 'epss_percentile', 'in_kev',
    'kev', 'exploit_available', 'exploitdb', 'virustotal', 'osv',
    'misp_enriched', 'misp_event_id', 'remediation', 'cis_benchmark',
    'cis_sections', 'cis_hardening', 'checklist', 'risk_factors',
    'risk_breakdown', 'asset_context', 'plugin_id', 'solution', 'evidence',
    'confidence',
    'reopened_at', 'reopen_reason', '@timestamp',
]


def _search(index, body):
    r = requests.post(f"{ES_URL}/{index}/_search", auth=(ES_USER, ES_PASSWORD), json=body, timeout=15)
    r.raise_for_status()
    return r.json()


def search_vulns(q='', severity='', host='', status='active', page=1, page_size=25,
                 confidence=''):
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    must = []
    filters = []
    if confidence:
        filters.append({'term': {'confidence': confidence}})
    if severity:
        # stored severities are capitalized ("High"); match case-insensitively
        must.append({'term': {'severity': {'value': severity, 'case_insensitive': True}}})
    if host:
        must.append({'term': {'host_ip': host}})
    if status and status != 'all':
        filters.append({'term': {'status': status}})
    if q:
        must.append({'multi_match': {'query': q,
                                     'fields': ['cve', 'host_ip', 'description', 'product',
                                                'finding_id']}})
    body = {
        'from': (page - 1) * page_size, 'size': page_size,
        'query': {'bool': {'must': must, 'filter': filters}},
        'sort': [{'risk_score': 'desc'}],
    }
    data = _search('vulnerabilities-*', body)
    hits = data['hits']
    total = hits['total']['value'] if isinstance(hits['total'], dict) else hits['total']
    rows = []
    for h in hits['hits']:
        src = h['_source']
        src.setdefault('finding_id', f"{src.get('host_ip')}|{src.get('cve')}|{src.get('port')}")
        rows.append(src)
    return {'total': total, 'page': page, 'page_size': page_size, 'rows': rows}


def get_finding(finding_id):
    """Latest document for one finding (vulnerability detail view)."""
    body = {
        'size': 1,
        'query': {'bool': {'should': [
            {'term': {'finding_id': finding_id}},
            {'term': {'finding_id.keyword': finding_id}},
        ]}},
        'sort': [{'@timestamp': 'desc'}],
    }
    data = _search('vulnerabilities-*', body)
    hits = data['hits']['hits']
    if not hits:
        return None
    return {k: hits[0]['_source'].get(k) for k in DETAIL_FIELDS
            if hits[0]['_source'].get(k) is not None}


def get_finding_history(finding_id):
    """All documents for a finding (timeline: detections/resolutions over time)."""
    body = {
        'size': 100,
        'query': {'bool': {'should': [
            {'term': {'finding_id': finding_id}},
            {'term': {'finding_id.keyword': finding_id}},
        ]}},
        'sort': [{'@timestamp': 'desc'}],
    }
    data = _search('vulnerabilities-*', body)
    out = []
    for h in data['hits']['hits']:
        s = h['_source']
        if s.get('finding_id') != finding_id:
            continue  # history = only this finding, not same-host neighbors
        out.append({'@timestamp': s.get('@timestamp'), 'status': s.get('status'),
                    'lifecycle_state': s.get('lifecycle_state'),
                    'risk_score': s.get('risk_score'),
                    'scan_id': s.get('scan_id'), 'scanner': s.get('scanner'),
                    'lifecycle_event': s.get('lifecycle_event')})
    return out


def attack_graph(limit=200):
    body = {'size': limit, 'query': {'term': {'doc_type': 'node'}}, 'sort': [{'blast_radius': 'desc'}]}
    nodes = [h['_source'] for h in _search('attack-graph-*', body)['hits']['hits']]
    return [{'host': n.get('ip'), 'blast': round(n.get('blast_radius') or 0, 1),
             'critical': bool(n.get('critical')), 'risk': round(n.get('risk_score') or 0, 1)}
            for n in nodes]


def predictions(limit=6):
    body = {'size': limit, 'query': {'match_all': {}}, 'sort': [{'prediction_date': 'desc'}]}
    out = []
    for h in _search('predictions-*', body)['hits']['hits']:
        p = h['_source']
        out.append({'date': p.get('prediction_date'),
                    'top10': [{'cve': t.get('cve'), 'score': round(t.get('pred_score') or 0, 3),
                               'epss': round(t.get('epss_score') or 0, 3), 'in_kev': t.get('in_kev')}
                              for t in (p.get('top10') or [])]})
    return out


def validation_history(limit=12):
    body = {'size': limit, 'query': {'match_all': {}}, 'sort': [{'@timestamp': 'desc'}]}
    out = []
    for h in _search('prediction-validation-*', body)['hits']['hits']:
        v = h['_source']
        out.append({'date': v.get('@timestamp'), 'precision_at_10': v.get('precision_at_10'),
                    'precision_new_at_10': v.get('precision_new_at_10')})
    return list(reversed(out))
