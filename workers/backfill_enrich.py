#!/usr/bin/env python3
"""
Backfill enrichment for historical VOC data.

Re-runs the ticket-enrichment pipeline over data that was collected before the
enrichment feature existed:

  * ELK mode (default): reads active documents from the `vulnerabilities-*`
    indices, re-enriches each unique (host, cve) finding, and writes enriched
    documents back through Logstash (creating new `vulnerabilities-*` docs
    flagged with `re_enriched: true`).

  * GLPI mode (--glpi): for every OPEN GLPI ticket matching the VOC naming
    convention `[VOC] <Severity> - <CVE> (<Type>) on <host>`, updates the
    ticket content with the enriched report and adds a checklist follow-up.

Usage (inside the worker container, which holds all dependencies):
    docker exec voc-celery-worker python /app/backfill_enrich.py [--glpi] [--limit N]
"""
import argparse
import os
import re
import sys
import logging
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'workers'))

from ticket_enrichment import enrich_vulnerability, finalize_description  # noqa: E402
from threat_intel import enrich_threat_intel  # noqa: E402

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ES_URL = os.getenv('ES_URL', 'http://elasticsearch:9200')
ES_USER = os.getenv('ES_USER', 'elastic')
ES_PASSWORD = os.getenv('ELASTIC_PASSWORD', '')
ES_VERIFY_SSL = os.getenv('ES_VERIFY_SSL', 'true').lower() == 'true'
LOGSTASH_URL = os.getenv('LOGSTASH_URL', 'http://logstash:5044')
RISK_ENGINE_URL = os.getenv('RISK_ENGINE_URL', 'http://risk-engine:8000')
RISK_ENGINE_API_KEY = os.getenv('RISK_ENGINE_API_KEY', '')

GLPI_URL = os.getenv('GLPI_URL', 'http://glpi:8080')
GLPI_APP_TOKEN = os.getenv('GLPI_APP_TOKEN', '')
GLPI_USER_TOKEN = os.getenv('GLPI_USER_TOKEN', '')

_TITLE_RE = re.compile(r'^\[VOC\] (.+?) - (CVE-\d{4}-\d{4,7}) \(.*\) on (.+)$')


def _es_session():
    s = requests.Session()
    s.auth = (ES_USER, ES_PASSWORD)
    s.verify = ES_VERIFY_SSL
    return s


def _fetch_active_vulns(limit=200):
    s = _es_session()
    query = {
        "size": limit,
        "query": {"bool": {"filter": [{"term": {"status": "active"}}]}},
        "sort": [{"@timestamp": "desc"}],
    }
    r = s.post(f"{ES_URL}/vulnerabilities-*/_search", json=query, timeout=30)
    r.raise_for_status()
    hits = r.json().get('hits', {}).get('hits', [])
    seen = {}
    for hit in hits:
        doc = hit.get('_source', {})
        cve = doc.get('cve')
        host = doc.get('host_ip')
        if not cve:
            continue
        key = (host, cve)
        if key not in seen:
            seen[key] = {
                'host': host, 'cve': cve, 'port': doc.get('port'),
                'service': doc.get('service'), 'product': doc.get('product'),
                'version': doc.get('version'), 'desc': doc.get('description'),
                'cwes': doc.get('cwe_ids') or [], 'cvss': doc.get('cvss'),
            }
    return list(seen.values())


def _score(vuln):
    payload = {
        "cvss_base": float(vuln.get('cvss') or 0.0),
        "is_critical_asset": False,
        "misp_threat_active": False,
        "exploit_available": vuln.get('exploit_available', False),
        "network_exposure": float(os.getenv('DEFAULT_NETWORK_EXPOSURE', '0.3')),
        "epss_score": float(vuln.get('epss_score', 0.0) or 0.0),
        "in_kev": bool(vuln.get('in_kev', False)),
    }
    headers = {"X-API-Key": RISK_ENGINE_API_KEY} if RISK_ENGINE_API_KEY else {}
    try:
        r = requests.post(f"{RISK_ENGINE_URL}/score", json=payload, headers=headers, timeout=15)
        r.raise_for_status()
        res = r.json()
        vuln['risk_score'] = res.get('risk_score', 5.0)
        vuln['severity'] = res.get('severity', 'Medium')
        vuln['risk_factors'] = res.get('factors', {})
    except Exception as e:
        logger.warning(f"Risk engine failed for {vuln.get('cve')}: {e}")
        vuln['risk_score'] = float(vuln.get('cvss') or 0.0)
        vuln['severity'] = 'Unknown'
    return vuln


def _index_doc(vuln, host):
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "host_ip": host,
        "cve": vuln.get('cve'), "cvss": vuln.get('cvss'), "risk_score": vuln.get('risk_score'),
        "severity": vuln.get('severity'), "description": vuln.get('desc'),
        "port": vuln.get('port'), "source": "voc-nmap-backfill",
        "misp_enriched": False,
        "risk_factors": vuln.get('risk_factors', {}),
        "status": "active",
        "vulnerability_type": vuln.get('vuln_type'),
        "owasp_category": vuln.get('owasp_category'),
        "cwe_ids": vuln.get('cwes', []),
        "attack_tactics": vuln.get('attack_tactics', []),
        "attack_techniques": [t.get('id') for t in vuln.get('attack_techniques', [])],
        "epss_score": vuln.get('epss_score'), "epss_percentile": vuln.get('epss_percentile'),
        "in_kev": vuln.get('in_kev', False), "kev": vuln.get('kev'),
        "exploit_available": vuln.get('exploit_available', False),
        "exploitdb": vuln.get('exploitdb', []), "virustotal": vuln.get('virustotal'),
        "osv": vuln.get('osv'), "remediation": vuln.get('remediation', []),
        "cis_benchmark": vuln.get('cis_benchmark'), "cis_sections": vuln.get('cis_sections', []),
        "cis_hardening": vuln.get('cis_hardening', []), "checklist": vuln.get('checklist', []),
        "technical_description": vuln.get('technical_description'),
        "re_enriched": True,
    }
    r = requests.post(LOGSTASH_URL, json=doc, timeout=10)
    r.raise_for_status()


def _glpi_session_token():
    if not (GLPI_APP_TOKEN and GLPI_USER_TOKEN):
        return None
    r = requests.get(f"{GLPI_URL}/apirest.php/initSession",
                     headers={"App-Token": GLPI_APP_TOKEN,
                              "Authorization": f"user_token {GLPI_USER_TOKEN}"},
                     timeout=10)
    r.raise_for_status()
    return r.json().get('session_token')


def _backfill_glpi(vulns_by_key):
    token = _glpi_session_token()
    if not token:
        logger.error("GLPI credentials not configured; skipping GLPI backfill")
        return 0
    headers = {"App-Token": GLPI_APP_TOKEN, "Session-Token": token, "Content-Type": "application/json"}
    r = requests.get(f"{GLPI_URL}/apirest.php/Ticket?range=0-500", headers=headers, timeout=15)
    r.raise_for_status()
    updated = 0
    for ticket in r.json():
        status = ticket.get('status')
        if status in (5, 6):  # solved/closed
            continue
        name = ticket.get('name', '')
        m = _TITLE_RE.match(name)
        if not m:
            continue
        cve = m.group(2)
        host = m.group(3).strip()
        vuln = vulns_by_key.get((host, cve))
        if not vuln:
            continue
        try:
            from glpi_client import _build_ticket_content, _checklist_to_html
            content = _build_ticket_content(host, vuln)
            up = requests.put(f"{GLPI_URL}/apirest.php/Ticket/{ticket['id']}",
                              headers=headers,
                              json={"input": {"content": content}}, timeout=15)
            up.raise_for_status()
            if vuln.get('checklist'):
                from glpi_client import add_ticket_followup
                add_ticket_followup(ticket['id'], _checklist_to_html(vuln['checklist']), headers)
            updated += 1
            logger.info(f"Updated GLPI ticket #{ticket['id']} ({cve})")
        except Exception as e:
            logger.warning(f"Failed to update GLPI ticket #{ticket['id']}: {e}")
    return updated


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--glpi', action='store_true', help='Also re-enrich open GLPI tickets')
    ap.add_argument('--limit', type=int, default=200, help='Max documents to read from ES')
    args = ap.parse_args()

    findings = _fetch_active_vulns(limit=args.limit)
    logger.info(f"Loaded {len(findings)} unique active findings from Elasticsearch")

    processed = 0
    vulns_by_key = {}
    for f in findings:
        try:
            vuln = dict(f)
            enrich_vulnerability(vuln, f['host'])
            _score(vuln)
            finalize_description(vuln, f['host'])
            _index_doc(vuln, f['host'])
            vulns_by_key[(f['host'], f['cve'])] = vuln
            processed += 1
            logger.info(f"Re-enriched {f['cve']} on {f['host']} -> risk {vuln.get('risk_score')} "
                        f"({vuln.get('vuln_type')})")
        except Exception as e:
            logger.error(f"Backfill failed for {f}: {e}")

    logger.info(f"Backfilled {processed}/{len(findings)} findings to Elasticsearch")

    if args.glpi:
        n = _backfill_glpi(vulns_by_key)
        logger.info(f"Updated {n} open GLPI tickets")


if __name__ == '__main__':
    main()
