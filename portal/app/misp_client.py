"""MISP REST client for the portal's native Threat Intel page.

Mirrors the shape of workers/misp_client.py (same auth header, same retry-free
requests.request call) but adds publish/edit/delete - none of which exist
anywhere in the repo today, since the worker pipeline only ever creates
events. PROVISION_MISP_URL is the container-reachable address (provision.py
already resolved this split - MISP_URL alone is the host-facing one used for
SSO links and isn't reachable from inside this container).
"""
import os
from datetime import datetime, timezone

import requests

MISP_URL = os.getenv('PROVISION_MISP_URL') or os.getenv('MISP_URL', '')
MISP_KEY = os.getenv('MISP_KEY', '')
MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'true').lower() == 'true'


def _headers():
    return {'Authorization': MISP_KEY, 'Accept': 'application/json', 'Content-Type': 'application/json'}


def _request(method, endpoint, json_body=None):
    if not MISP_URL or not MISP_KEY:
        raise RuntimeError('MISP not configured (MISP_URL/MISP_KEY)')
    r = requests.request(method, f"{MISP_URL}{endpoint}", headers=_headers(),
                         json=json_body, verify=MISP_VERIFY_SSL, timeout=20)
    r.raise_for_status()
    return r.json() if r.content else {}


def search_events(value=''):
    body = {'returnFormat': 'json', 'limit': 50}
    if value:
        body['value'] = value
    data = _request('POST', '/events/restSearch/json', body)
    return data.get('response', [])


def get_event(event_id):
    data = _request('GET', f'/events/view/{event_id}')
    return data.get('Event')


def create_event(info, tags=None):
    event = {'Event': {
        'info': info,
        'distribution': '0',
        'threat_level_id': '2',
        'analysis': '0',
        'date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        'Tag': [{'name': t} for t in (tags or ['source:voc-portal', 'tlp:white'])],
    }}
    data = _request('POST', '/events/add', event)
    return data.get('Event')


def publish_event(event_id):
    return _request('POST', f'/events/publish/{event_id}')


def delete_event(event_id):
    return _request('POST', f'/events/delete/{event_id}')


def add_attribute(event_id, attribute_data):
    return _request('POST', f'/events/addAttribute/{event_id}', attribute_data)
