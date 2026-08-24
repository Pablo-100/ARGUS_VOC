"""RabbitMQ management-API client for the portal's native Infrastructure page.

provision.py already talks to this same API for user/permission management
(see _rmq() there) - this module covers queue-level operations, which nothing
in the codebase touched before now.
"""
import os
from urllib.parse import quote

import requests

RABBITMQ_MGMT_URL = os.getenv('RABBITMQ_MGMT_URL', 'http://rabbitmq:15672')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'voc')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', '')


def _auth():
    return (RABBITMQ_USER, RABBITMQ_PASS)


def list_queues():
    r = requests.get(f"{RABBITMQ_MGMT_URL}/api/queues", auth=_auth(), timeout=10)
    r.raise_for_status()
    out = []
    for q in r.json():
        rate = ((q.get('message_stats') or {}).get('publish_details') or {}).get('rate', 0)
        out.append({
            'name': q.get('name'),
            'vhost': q.get('vhost', '/'),
            'state': q.get('state'),
            'messages_ready': q.get('messages_ready', 0),
            'messages_unacknowledged': q.get('messages_unacknowledged', 0),
            'consumers': q.get('consumers', 0),
            'message_rate': round(rate or 0, 2),
        })
    out.sort(key=lambda x: -x['messages_ready'])
    return out


def purge_queue(name, vhost='/'):
    r = requests.delete(
        f"{RABBITMQ_MGMT_URL}/api/queues/{quote(vhost, safe='')}/{quote(name, safe='')}/contents",
        auth=_auth(), timeout=10)
    r.raise_for_status()
    return True
