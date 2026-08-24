"""Elasticsearch cluster/index management for the portal's native Infrastructure
page. esdata.py already reads vulnerabilities-*/attack-graph-*/predictions-*
for the dashboard widgets (same auth pattern reused here) - this module adds
the cluster-health and index-management surface nothing else in the repo has.
"""
import os

import requests

ES_URL = os.getenv('ES_URL', 'http://elasticsearch:9200')
ES_USER = os.getenv('ES_USER', 'elastic')
ES_PASSWORD = os.getenv('ELASTIC_PASSWORD', '')

# Never let this page delete a system index (.kibana, .security, .monitoring,
# ...) - those aren't pipeline data and destroying one can break the whole
# ELK stack rather than just losing scan history.
PROTECTED_PREFIXES = ('.',)


def _auth():
    return (ES_USER, ES_PASSWORD)


def cluster_health():
    r = requests.get(f"{ES_URL}/_cluster/health", auth=_auth(), timeout=10)
    r.raise_for_status()
    return r.json()


def list_indices():
    r = requests.get(f"{ES_URL}/_cat/indices?format=json&bytes=b", auth=_auth(), timeout=15)
    r.raise_for_status()
    out = [{
        'index': i.get('index'),
        'health': i.get('health'),
        'status': i.get('status'),
        'docs_count': int(i.get('docs.count') or 0),
        'store_size': int(i.get('store.size') or 0),
    } for i in r.json()]
    out.sort(key=lambda x: x['index'])
    return out


def delete_index(name):
    if not name or name.startswith(PROTECTED_PREFIXES):
        raise ValueError('refusing to delete a system index')
    r = requests.delete(f"{ES_URL}/{name}", auth=_auth(), timeout=15)
    r.raise_for_status()
    return True
