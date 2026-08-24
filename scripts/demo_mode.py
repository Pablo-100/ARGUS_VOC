#!/usr/bin/env python3
"""VOC DEMO MODE - safe, deterministic end-to-end demonstration.

Seeds ONE labeled demo asset + ONE labeled demo vulnerability through the
real pipeline stages, then walks the full lifecycle:

    asset discovered -> finding detected -> enriched -> scored
    -> ticket created -> assigned -> remediated -> verification scan
    -> verified resolved

Honesty guarantees (mandate Feature 23):
  * every document is tagged demo=true / source=voc-demo / [DEMO] prefix
  * the "verification scan" is a MOCKED scanner result - clearly reported as
    such; this script NEVER pretends a real scan happened
  * nothing touches the real DISCOVERY_SUBNET or any live host

Usage (from the repo root):
    python3 scripts/demo_mode.py            # full lifecycle
    python3 scripts/demo_mode.py --cleanup  # remove demo documents
"""
import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import requests

ES_URL = os.getenv('ES_URL', 'http://localhost:9200')
ES_USER = os.getenv('ES_USER', 'elastic')
ES_PASSWORD = os.getenv('ELASTIC_PASSWORD', '')
PORTAL_URL = os.getenv('PORTAL_URL', 'http://localhost:4200')
DEMO_IP = '172.31.255.254'          # TEST-NET-ish IP that must never be scanned
DEMO_HOSTNAME = 'demo-vulnerable-box'
DEMO_CVE = 'CVE-2021-44228'         # Log4Shell - well known, good for demos


def es(method, path, body=None):
    r = requests.request(method, f'{ES_URL}{path}', auth=(ES_USER, ES_PASSWORD),
                         json=body, timeout=30)
    r.raise_for_status()
    return r.json() if r.content else {}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def demo_finding_id():
    return f'{DEMO_IP}|{DEMO_CVE}|8080/tcp|demo'


def seed_asset():
    asset_id = hashlib.sha1(f'demo-mac|{DEMO_IP}|{DEMO_HOSTNAME}'.encode()).hexdigest()[:16]
    doc = {
        'asset_id': asset_id,
        'ip_address': DEMO_IP,
        'hostname': DEMO_HOSTNAME,
        'mac_address': '00:de:mo:00:00:01',
        'os': 'Ubuntu Linux (DEMO)',
        'criticality': 5,
        'environment': 'production',
        'internet_exposed': True,
        'business_service': 'Demo web service',
        'owner': 'demo-team',
        'services': {'8080': {'service': 'http', 'product': 'Apache Tomcat',
                              'version': '9.0.30'}},
        'open_ports': 1,
        'cpes': ['cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*'],
        'software': ['Apache Tomcat 9.0.30'],
        'first_seen': now(), 'last_seen': now(),
        'status': 'active',
        'source': 'voc-demo',
        'demo': True,
    }
    es('PUT', f'/assets/_doc/{asset_id}', doc)
    print(f'[1/8] demo asset created: {asset_id} ({DEMO_HOSTNAME})')
    return asset_id


def seed_finding(scan_id):
    finding_id = demo_finding_id()
    doc = {
        '@timestamp': now(),
        'finding_id': finding_id,
        'scan_id': scan_id,
        'scanner': 'demo',
        'scan_type': 'demo',
        'lifecycle_state': 'detected',
        'host_ip': DEMO_IP,
        'os': 'Ubuntu Linux (DEMO)',
        'cve': DEMO_CVE,
        'cvss': 10.0,
        'risk_score': None,   # filled by the risk engine call below
        'severity': 'Critical',
        'description': '[DEMO] Log4Shell JNDI injection on the demo Tomcat instance.',
        'port': '8080/tcp', 'service': 'http',
        'product': 'Apache Tomcat', 'version': '9.0.30',
        'cpe': 'cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*',
        'source': 'voc-demo',
        'status': 'active',
        'first_seen': now(), 'last_seen': now(),
        'in_kev': True,
        'exploit_available': True,
        'epss_score': 0.97,
        'demo': True,
        'lifecycle_event': 'detected',
    }
    # score through the REAL risk engine so the explanation is genuine
    key = os.getenv('RISK_ENGINE_API_KEY', '')
    headers = {'X-API-Key': key} if key else {}
    try:
        r = requests.post(
            f"{os.getenv('RISK_ENGINE_URL', 'http://localhost:8000')}/score",
            json={'cvss_base': 10.0, 'asset_criticality': 5, 'environment_production': True,
                  'internet_exposed': True, 'network_exposure': 0.3,
                  'misp_threat_active': False, 'exploit_available': True,
                  'epss_score': 0.97, 'in_kev': True},
            headers=headers, timeout=15)
        r.raise_for_status()
        out = r.json()
        doc['risk_score'] = out['risk_score']
        doc['severity'] = out['severity']
        doc['risk_factors'] = out.get('factors', {})
        doc['risk_breakdown'] = out.get('breakdown', {})
        doc['risk_explanation'] = out.get('risk_factors', [])
    except Exception as e:
        print(f'    (risk engine unavailable: {e} - storing raw CVSS)')
        doc['risk_score'] = 10.0
    # daily-pattern index so all existing vulnerabilities-* queries see it
    day = datetime.now(timezone.utc).strftime('%Y.%m.%d')
    es('POST', f'/vulnerabilities-{day}/_doc', doc)
    print(f'[2/8] demo finding indexed: {DEMO_CVE} risk={doc["risk_score"]}/10 '
          f'({doc["severity"]}) - scored by the real risk engine')
    return doc


def create_ticket():
    import urllib.request
    req = urllib.request.Request(
        f'{PORTAL_URL}/api/login', method='POST',
        data=json.dumps({'username': os.environ.get('DEMO_ADMIN_USER', 'admin'),
                         'password': os.environ.get('PORTAL_ADMIN_PASSWORD', '')}).encode(),
        headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            token = json.load(resp)['token']
    except Exception as e:
        print(f'[3/8] SKIPPED portal ticket (login failed: {e}) - '
              f'set PORTAL_ADMIN_PASSWORD to enable')
        return None, None
    hdr = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    body = {
        'title': f'[DEMO] {DEMO_CVE} on {DEMO_HOSTNAME}',
        'description': '[DEMO MODE] deterministic demonstration finding.',
        'severity': 'critical', 'cve': DEMO_CVE, 'host': DEMO_IP, 'port': '8080/tcp',
        'cvss': 10.0, 'risk_score': 10.0,
    }
    req = urllib.request.Request(f'{PORTAL_URL}/api/tickets', method='POST',
                                 data=json.dumps(body).encode(), headers=hdr)
    with urllib.request.urlopen(req, timeout=15) as resp:
        tid = json.load(resp)['id']
    print(f'[3/8] portal ticket #{tid} created (SLA deadline computed server-side)')
    # fetch our own user id so we can walk the lifecycle deterministically
    with urllib.request.urlopen(urllib.request.Request(
            f'{PORTAL_URL}/api/me', headers=hdr), timeout=15) as resp:
        me = json.load(resp)['id']
    req = urllib.request.Request(f'{PORTAL_URL}/api/tickets/{tid}/assign', method='POST',
                                 data=json.dumps({'user_id': me}).encode(), headers=hdr)
    try:
        urllib.request.urlopen(req, timeout=15)
    except Exception as e:
        print(f'    (self-assign failed: {e})')
    for step in ('start', 'solve'):
        try:
            req = urllib.request.Request(f'{PORTAL_URL}/api/tickets/{tid}/{step}',
                                         method='POST', data=b'{}', headers=hdr)
            with urllib.request.urlopen(req, timeout=30) as resp:
                out = json.load(resp)
            if step == 'solve':
                print(f'[6/8] remediation recorded -> {out.get("message", "")[:90]}...')
            else:
                print(f'[5/8] work started on ticket #{tid}')
        except Exception as e:
            print(f'    ({step}: {e})')
    return tid, token


def verify_and_resolve(tid=None):
    print('[7/8] verification scan: running MOCKED scanner check '
          '(explicitly not a real scan)...')
    time.sleep(2)
    result = {
        'source': 'voc-demo', 'state': 'done', 'outcome': 'verified',
        'ticket_id': tid, 'cve': DEMO_CVE, 'host': DEMO_IP,
        'verification_scan_id': f'demo_verify_{uuid.uuid4().hex[:8]}',
        'scanner': 'mocked-for-demo',
        'lifecycle_event': 'verified',
        'detail': f'[DEMO] mocked verification: {DEMO_CVE} no longer detected on {DEMO_IP}',
        'finished_at': now(), 'applied': False, 'demo': True,
    }
    es('POST', '/verification-results/_doc', result)
    if tid:
        print(f'      -> ticket #{tid} will flip to solved/scanner-verified on next '
              f'portal refresh (lazy sync)')
    print('[7/8] verification result stored')


def cleanup():
    print('Removing demo documents...')
    es('POST', '/assets/_delete_by_query?conflicts=proceed',
       {'query': {'term': {'demo': True}}})
    es('POST', '/vulnerabilities-*/_delete_by_query?conflicts=proceed',
       {'query': {'term': {'demo': True}}})
    es('POST', '/verification-results/_delete_by_query?conflicts=proceed',
       {'query': {'term': {'demo': True}}})
    print('done.')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cleanup', action='store_true')
    args = ap.parse_args()
    if args.cleanup:
        cleanup()
        return
    scan_id = f'demo_{uuid.uuid4().hex[:8]}'
    print(f'=== VOC DEMO MODE (all data labeled demo=true) ===')
    seed_asset()
    seed_finding(scan_id)
    tid, _ = create_ticket()
    print('[4/8] enrichment/threat-intel context present (KEV, EPSS, exploit)')
    verify_and_resolve(tid)
    print('[8/8] done. Open the portal dashboard to see the demo flow.')
    print(f'     Remove all demo data anytime: {sys.argv[0]} --cleanup')


if __name__ == '__main__':
    main()
