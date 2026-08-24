import os
import logging
from datetime import datetime, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import requests

logger = logging.getLogger(__name__)

LOGSTASH_URL = os.getenv('LOGSTASH_URL', 'http://logstash:5044')


def create_session_with_retries(verify_ssl=True):
    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504],
                           allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE"])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    return session


def index_resolved(info, timestamp=None):
    """Index a vulnerability that disappeared from the last scan as resolved."""
    session = create_session_with_retries()
    doc = {
        "@timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "host_ip": info.get("host"),
        "cve": info.get("cve"),
        "port": info.get("port"),
        "cvss": info.get("cvss"),
        "severity": info.get("severity"),
        "description": info.get("desc"),
        "service": info.get("service"),
        "product": info.get("product"),
        "version": info.get("version"),
        "source": "voc-nmap",
        "status": "resolved",
        "last_seen": timestamp or datetime.now(timezone.utc).isoformat(),
    }
    try:
        r = session.post(LOGSTASH_URL, json=doc, timeout=10)
        r.raise_for_status()
        logger.info(f"Indexed resolved vuln {info.get('cve')} on {info.get('host')}")
        return True
    except Exception as e:
        logger.error(f"ELK resolved indexing failed: {e}")
        return False
