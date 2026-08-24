import os
import logging
import requests
import json
from datetime import datetime, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

MISP_URL = os.getenv('MISP_URL', 'https://192.168.184.135:8443')
MISP_KEY = os.getenv('MISP_KEY', '')
MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'true').lower() == 'true'


def create_session():
    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.verify = MISP_VERIFY_SSL
    return session


def _misp_request(method, endpoint, data=None):
    if not MISP_KEY:
        logger.warning("MISP_KEY not configured")
        return None

    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    session = create_session()
    url = f"{MISP_URL}{endpoint}"

    try:
        if method == 'GET':
            r = session.get(url, headers=headers, timeout=30)
        elif method == 'POST':
            r = session.post(url, headers=headers, json=data, timeout=30)
        elif method == 'PUT':
            r = session.put(url, headers=headers, json=data, timeout=30)
        else:
            return None

        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error(f"MISP API error ({endpoint}): {e}")
        return None


def search_event(value, return_format='json'):
    return _misp_request('POST', '/events/restSearch/json', {
        "value": value,
        "returnFormat": return_format
    })


def create_event(event_data):
    default_event = {
        "Event": {
            "info": "VOC Vulnerability Finding",
            "distribution": "0",
            "threat_level_id": "1",
            "analysis": "0",
            "date": datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
            "Tag": [
                {"name": "source:voc"},
                {"name": "tlp:white"}
            ]
        }
    }

    if isinstance(event_data, dict):
        if "Event" in event_data:
            event = event_data
        else:
            event = {"Event": {**default_event["Event"], **event_data}}
    else:
        event = default_event

    return _misp_request('POST', '/events/add', event)


def add_attribute(event_id, attribute_data):
    return _misp_request('POST', f'/events/addAttribute/{event_id}', attribute_data)


def create_event_from_vuln(vuln, host):
    cve = vuln.get('cve', 'unknown')
    severity = vuln.get('severity', 'Medium')
    cvss = vuln.get('cvss', 0)
    port = vuln.get('port', 'unknown')
    service = vuln.get('service', 'unknown')
    description = vuln.get('desc', vuln.get('description', ''))

    event_data = {
        "Event": {
            "info": f"[VOC] {severity} vulnerability: {cve} on {host}",
            "distribution": "0",
            "threat_level_id": "1" if cvss >= 7 else "2",
            "analysis": "0",
            "date": datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
            "Tag": [
                {"name": "source:voc"},
                {"name": f"severity:{severity.lower()}"},
                {"name": f"cvss:{cvss}"},
                {"name": f"host:{host}"},
                {"name": "tlp:white"}
            ],
            "Attribute": [
                {
                    "type": "vulnerability",
                    "category": "Payload delivery",
                    "value": cve,
                    "comment": f"Detected on {host}:{port} ({service})",
                    "to_ids": False
                },
                {
                    "type": "ip-src",
                    "category": "Network activity",
                    "value": host,
                    "comment": "Target host",
                    "to_ids": False
                },
                {
                    "type": "text",
                    "category": "Other",
                    "value": f"Port: {port}, Service: {service}, CVSS: {cvss}",
                    "comment": "VOC scan details",
                    "to_ids": False
                }
            ]
        }
    }

    if description:
        event_data["Event"]["Attribute"].append({
            "type": "comment",
            "category": "Other",
            "value": description[:1000],
            "comment": "Vulnerability description",
            "to_ids": False
        })

    result = create_event(event_data)
    if result and 'Event' in result:
        event_id = result['Event'].get('id')
        logger.info(f"Created MISP event #{event_id} for {cve} on {host}")
        return event_id

    logger.warning(f"Failed to create MISP event for {cve} on {host}")
    return None


def get_threats_for_host(host):
    result = search_event(host)
    if result and 'response' in result:
        return result['response']
    return []
