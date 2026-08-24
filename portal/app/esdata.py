"""Fetch live SOC widgets from Elasticsearch for the unified portal dashboard."""
import os

import requests

ES_URL = os.getenv('ES_URL', 'http://elasticsearch:9200')
ES_USER = os.getenv('ES_USER', 'elastic')
ES_PASSWORD = os.getenv('ELASTIC_PASSWORD', '')


def _search(index, body):
    resp = requests.post(
        f"{ES_URL}/{index}/_search", auth=(ES_USER, ES_PASSWORD),
        json=body, timeout=15)
    resp.raise_for_status()
    return resp.json()


def _docs(index, body):
    return [h['_source'] for h in _search(index, body)['hits']['hits']]


def vuln_trend(days=14):
    """Count of critical/high findings per day (last N days) for the trend chart.

    Only the LATEST document per finding counts: the pipeline re-indexes every
    still-present finding on each scan, so raw doc counts would inflate the
    trend with duplicates. We deduplicate on finding_id keeping max @timestamp.
    """
    try:
        resp = _search('vulnerabilities-*', {
            'size': 0,
            'aggs': {
                'by_finding': {
                    'terms': {'field': 'finding_id.keyword', 'size': 65536},
                    'aggs': {
                        'latest': {'top_hits': {'size': 1,
                                                'sort': [{'@timestamp': 'desc'}],
                                                '_source': ['@timestamp', 'risk_score',
                                                            'status', 'severity',
                                                            'confidence']}},
                    },
                },
            },
        })
        buckets = resp.get('aggregations', {}).get('by_finding', {}).get('buckets', [])
        per_day = {}
        for b in buckets:
            hits = b.get('latest', {}).get('hits', {}).get('hits', [])
            if not hits:
                continue
            src = hits[0]['_source']
            day = str(src.get('@timestamp', ''))[:10]
            if not day:
                continue
            agg = per_day.setdefault(day, {'total': 0, 'critical': 0, 'high': 0,
                                           'medium': 0, 'confirmed': 0})
            if src.get('status') == 'resolved':
                continue
            agg['total'] += 1
            if src.get('confidence') == 'confirmed':
                agg['confirmed'] += 1
            risk = float(src.get('risk_score') or 0)
            if risk >= 9.0:
                agg['critical'] += 1
            elif risk >= 7.0:
                agg['high'] += 1
            elif risk >= 4.0:
                agg['medium'] += 1
        out = [{'date': d, **per_day[d]} for d in sorted(per_day)]
        return out[-days:]
    except Exception:
        return []


def severity_dist():
    """Severity distribution over ACTIVE findings (latest state per finding)."""
    try:
        resp = _search('vulnerabilities-*', {
            'size': 0,
            'query': {'term': {'status': 'active'}},
            'aggs': {'sev': {'terms': {'field': 'severity.keyword', 'size': 8}}},
        })
        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        buckets = [(b['key'], b['doc_count'])
                   for b in resp['aggregations']['sev']['buckets']]
        buckets.sort(key=lambda kv: order.get(str(kv[0]).lower(), 9))
        return buckets
    except Exception:
        return []


def dashboard_widgets():
    widgets = {'vulns': {}, 'critical_assets': [], 'prediction': None,
               'top_cves': [], 'kev': {}, 'exposure': {}}

    # Active-state aggregation helper: only latest docs matter; status=active
    # filters out resolved history so KPIs reflect reality.
    active_filter = [{'term': {'status': 'active'}}]

    try:
        aggs = _search('vulnerabilities-*', {
            'size': 0,
            'query': {'bool': {'filter': active_filter}},
            'aggs': {
                # every KPI counts DISTINCT findings - the pipeline re-indexes
                # still-present vulnerabilities on each scan, so raw doc
                # counts would inflate the numbers.
                'critical': {'filter': {'range': {'risk_score': {'gte': 9.0}}},
                             'aggs': {'n': {'cardinality': {'field': 'finding_id.keyword'}}}},
                'high': {'filter': {'range': {'risk_score': {'gte': 7.0, 'lt': 9.0}}},
                         'aggs': {'n': {'cardinality': {'field': 'finding_id.keyword'}}}},
                'total': {'cardinality': {'field': 'finding_id.keyword'}},
                'unique_cves': {'cardinality': {'field': 'cve'}},
                'confirmed': {'filter': {'term': {'confidence': 'confirmed'}}},
                'potential': {'filter': {'term': {'confidence': 'potential'}}},
                'kev': {'filter': {'term': {'in_kev': True}}},
                'exploitable': {'filter': {'term': {'exploit_available': True}}},
                'internet_exposed': {
                    'filter': {'term': {'asset_context.internet_exposed': True}}},
                'top_cves': {'terms': {'field': 'cve', 'size': 6,
                                       'order': {'risk': 'desc'}},
                             'aggs': {'risk': {'max': {'field': 'risk_score'}}}},
                'top_hosts': {'terms': {'field': 'host_ip', 'size': 6,
                                        'order': {'risk': 'desc'}},
                              'aggs': {'risk': {'max': {'field': 'risk_score'}}}},
            },
        })
        a = aggs['aggregations']
        widgets['vulns'] = {
            'total': a['total']['value'] or 0,
            'unique_cves': a['unique_cves']['value'] or 0,
            'critical': a['critical']['n']['value'],
            'high': a['high']['n']['value'],
        }
        widgets['kev'] = {'count': a['kev']['doc_count']}
        widgets['confidence'] = {'confirmed': a['confirmed']['doc_count'],
                                 'potential': a['potential']['doc_count']}
        widgets['exposure'] = {
            'internet_exposed_vulns': a['internet_exposed']['doc_count'],
            'with_public_exploit': a['exploitable']['doc_count'],
        }
        widgets['top_cves'] = [{'cve': b['key'], 'risk': round(b['risk']['value'] or 0, 1)}
                               for b in a['top_cves']['buckets']]
        widgets['top_hosts'] = [{'host': b['key'], 'risk': round(b['risk']['value'] or 0, 1)}
                                for b in a['top_hosts']['buckets']]
    except Exception:
        pass

    try:
        resp = _search('assets', {'size': 0, 'track_total_hits': True,
                                  'query': {'match_all': {}}})
        t = resp['hits']['total']
        widgets['assets_total'] = t['value'] if isinstance(t, dict) else t
    except Exception:
        pass

    try:
        nodes = _docs('attack-graph-*', {
            'size': 100,
            'query': {'bool': {'must': [{'term': {'doc_type': 'node'}}]}},
            'sort': [{'blast_radius': 'desc'}],
        })
        widgets['critical_assets'] = [
            {'host': n.get('ip'), 'blast': round(n.get('blast_radius') or 0, 1),
             'critical': n.get('critical'), 'risk': round(n.get('risk_score') or 0, 1)}
            for n in nodes[:8]]
    except Exception:
        pass

    try:
        preds = _docs('predictions-*', {
            'size': 1, 'query': {'match_all': {}},
            'sort': [{'prediction_date': 'desc'}],
        })
        if preds:
            p = preds[0]
            widgets['prediction'] = {
                'date': p.get('prediction_date'),
                'top10': [{'cve': t['cve'], 'score': round(t.get('pred_score') or 0, 3),
                           'epss': round(t.get('epss_score') or 0, 3),
                           'in_kev': t.get('in_kev')} for t in (p.get('top10') or [])],
            }
    except Exception:
        pass

    widgets['trend'] = vuln_trend()
    widgets['severity_dist'] = severity_dist()
    return widgets
