"""GLPI REST client for the portal's live ticket panel.

workers/glpi_client.py and workers/glpi_sync.py each reimplement the
initSession dance independently; this is a third, portal-side copy rather
than a shared import because workers/ and portal/ are separate Docker images
with no shared package between them. Adds ticket status-change, follow-ups
and technician assignment - only ticket *creation* existed anywhere before
this (workers/glpi_client.py:create_ticket). PROVISION_GLPI_URL is the
container-reachable address, same split provision.py already relies on.
"""
import json
import os
import threading
import time

import requests

GLPI_URL = os.getenv('PROVISION_GLPI_URL') or os.getenv('GLPI_URL', '')
APP_TOKEN = os.getenv('GLPI_APP_TOKEN', '')
USER_TOKEN = os.getenv('GLPI_USER_TOKEN', '')
VERIFY_SSL = os.getenv('GLPI_VERIFY_SSL', 'true').lower() == 'true'

STATUS_LABELS = {1: 'New', 2: 'Processing (assigned)', 3: 'Processing (planned)',
                 4: 'Pending', 5: 'Solved', 6: 'Closed'}

_lock = threading.Lock()
_token = None
_expiry = 0


def _session_token():
    global _token, _expiry
    now = time.time()
    if _token and now < _expiry - 60:
        return _token
    with _lock:
        if _token and now < _expiry - 60:
            return _token
        if not GLPI_URL or not APP_TOKEN or not USER_TOKEN:
            raise RuntimeError('GLPI not configured')
        r = requests.get(f"{GLPI_URL}/apirest.php/initSession",
                         headers={'App-Token': APP_TOKEN, 'Authorization': f'user_token {USER_TOKEN}'},
                         verify=VERIFY_SSL, timeout=10)
        r.raise_for_status()
        _token = r.json().get('session_token')
        _expiry = now + 3600
        return _token


def _request(method, endpoint, json_body=None, params=None, _retry=True):
    headers = {'Content-Type': 'application/json', 'App-Token': APP_TOKEN,
               'Session-Token': _session_token()}
    r = requests.request(method, f"{GLPI_URL}/apirest.php{endpoint}", headers=headers,
                         json=json_body, params=params, verify=VERIFY_SSL, timeout=15)
    if r.status_code == 401 and _retry:
        global _token
        _token = None
        return _request(method, endpoint, json_body, params, _retry=False)
    r.raise_for_status()
    return r.json() if r.content else {}


def find_ticket_by_cve_host(cve, host):
    """Same '[VOC] {severity} - {cve} ... on {host}' name lookup as
    workers/glpi_client.find_existing_ticket - only auto-pipeline tickets
    (risk_score >= 7) ever get created in GLPI, so admin-only portal tickets
    legitimately won't match anything here."""
    if not cve or not host:
        return None
    data = _request('GET', '/Ticket', params={
        'expand_contents': 'false',
        'searchText': cve,
        'criteria': json.dumps([
            {'field': 12, 'searchtype': 'contains', 'value': f'on {host}'},
            {'link': 'AND', 'field': 12, 'searchtype': 'contains', 'value': cve},
        ]),
        'forcedisplay': '1,3,12',
    })
    tickets = data if isinstance(data, list) else ([data] if data else [])
    for t in tickets:
        name = t.get('name', '')
        if cve in name and f'on {host}' in name:
            return t
    return None


def get_ticket(ticket_id):
    return _request('GET', f'/Ticket/{ticket_id}')


def get_followups(ticket_id):
    data = _request('GET', f'/Ticket/{ticket_id}/TicketFollowup')
    return data if isinstance(data, list) else []


def set_status(ticket_id, status):
    if status not in STATUS_LABELS:
        raise ValueError(f'invalid GLPI status {status!r} - must be one of {list(STATUS_LABELS)}')
    return _request('PUT', f'/Ticket/{ticket_id}', {'input': {'status': status}})


def add_followup(ticket_id, content):
    return _request('POST', f'/Ticket/{ticket_id}/TicketFollowup',
                    {'input': {'items_id': int(ticket_id), 'itemtype': 'Ticket', 'content': content}})


def find_user_id(username):
    data = _request('GET', '/User', params={'range': '0-500'})
    for u in (data or []):
        if u.get('name') == username:
            return int(u['id'])
    return None


def assign_technician(ticket_id, glpi_user_id):
    return _request('POST', '/Ticket_User',
                    {'input': {'tickets_id': int(ticket_id), 'users_id': int(glpi_user_id), 'type': 2}})
