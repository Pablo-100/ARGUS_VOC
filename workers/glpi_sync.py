import os
import logging
import requests
import json
from datetime import datetime, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

GLPI_URL = os.getenv('GLPI_URL', 'http://192.168.184.135:8080')
APP_TOKEN = os.getenv('GLPI_APP_TOKEN', '')
USER_TOKEN = os.getenv('GLPI_USER_TOKEN', '')
VERIFY_SSL = os.getenv('GLPI_VERIFY_SSL', 'true').lower() == 'true'

_session_token = None


def create_session():
    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = VERIFY_SSL
    return session


def _get_session():
    global _session_token
    if _session_token:
        return _session_token

    if not APP_TOKEN or not USER_TOKEN:
        return None

    session = create_session()
    try:
        r = session.get(
            f"{GLPI_URL}/apirest.php/initSession",
            headers={"App-Token": APP_TOKEN, "Authorization": f"user_token {USER_TOKEN}"},
            timeout=10
        )
        r.raise_for_status()
        _session_token = r.json().get("session_token")
        return _session_token
    except Exception as e:
        logger.error(f"GLPI session failed: {e}")
        return None


def _glpi_request(method, endpoint, data=None, _retry=True):
    token = _get_session()
    if not token:
        return None

    headers = {
        "Content-Type": "application/json",
        "App-Token": APP_TOKEN,
        "Session-Token": token
    }

    session = create_session()
    url = f"{GLPI_URL}/apirest.php{endpoint}"

    try:
        if method == 'GET':
            r = session.get(url, headers=headers, timeout=15)
        elif method == 'POST':
            r = session.post(url, headers=headers, json=data, timeout=15)
        elif method == 'PUT':
            r = session.put(url, headers=headers, json=data, timeout=15)
        else:
            return None

        if r.status_code in [200, 201, 204, 206]:
            # GLPI returns 206 Partial Content when the requested range spans
            # more than the server's default page size. The body is still a
            # valid ticket list, so treat it as success.
            return r.json() if r.content else {}
        elif r.status_code == 401:
            global _session_token
            _session_token = None
            if _retry:
                return _glpi_request(method, endpoint, data, _retry=False)
            return None
        else:
            logger.error(f"GLPI API error {r.status_code}: {r.text[:200]}")
            return None
    except Exception as e:
        logger.error(f"GLPI request failed: {e}")
        return None


def get_tickets(criteria=None, buf=100):
    """Fetch GLPI tickets, paging through every 100 ("range=0-99" style)."""
    tickets = []
    start = 0
    while True:
        endpoint = f'/Ticket?expand_contents=false&range={start}-{start + buf - 1}'
        if criteria:
            endpoint += f"&criteria={json.dumps(criteria)}"
        batch = _glpi_request('GET', endpoint)
        if not batch:
            break
        tickets.extend(batch)
        if len(batch) < buf:
            break
        start += buf
    return tickets


def get_ticket(ticket_id):
    return _glpi_request('GET', f'/Ticket/{ticket_id}')


def get_ticket_followups(ticket_id):
    return _glpi_request('GET', f'/Ticket/{ticket_id}/TicketFollowup')


def sync_tickets_to_dict():
    tickets = get_tickets()
    result = []
    for ticket in tickets:
        result.append({
            "id": ticket.get("id"),
            "name": ticket.get("name", ""),
            "content": ticket.get("content", ""),
            "status": ticket.get("status"),
            "urgency": ticket.get("urgency"),
            "impact": ticket.get("impact"),
            "priority": ticket.get("priority"),
            "type": ticket.get("type"),
            "date_creation": ticket.get("date_creation"),
            "date_mod": ticket.get("date_mod"),
            "closedate": ticket.get("closedate"),
            "sources_id": ticket.get("sources_id"),
            "users_id_recipient": ticket.get("users_id_recipient"),
            "requesttypes_id": ticket.get("requesttypes_id"),
            "itilcategories_id": ticket.get("itilcategories_id"),
            "actiontime": ticket.get("actiontime"),
        })
    return result


def get_all_glpi_data():
    tickets = sync_tickets_to_dict()
    return {
        "tickets": tickets,
        "total": len(tickets),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
