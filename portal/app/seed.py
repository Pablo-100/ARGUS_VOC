"""Seed users, MITRE ATT&CK data and import auto-tickets from Elasticsearch."""
import os

import requests

from .auth import hash_password
from .db import get_db, init_db

DEMO_USERS = [
    {'username': 'analyst1', 'full_name': 'Sylvia Analyst', 'role': 'soc3'},
    {'username': 'user1', 'full_name': 'Alice Technicienne', 'role': 'soc1'},
    {'username': 'user2', 'full_name': 'Bob Ingénieur', 'role': 'noc'},
]

# Curated MITRE ATT&CK enterprise techniques relevant to vulnerability ops.
# IDs / names / tactics follow the public ATT&CK framework (attack.mitre.org).
TECHNIQUES = [
    ('T1190', 'Exploit Public-Facing Application', 'initial-access'),
    ('T1195', 'Supply Chain Compromise', 'initial-access'),
    ('T1189', 'Drive-by Compromise', 'initial-access'),
    ('T1133', 'External Remote Services', 'initial-access'),
    ('T1078', 'Valid Accounts', 'initial-access'),
    ('T1110', 'Brute Force', 'credential-access'),
    ('T1552', 'Unsecured Credentials', 'credential-access'),
    ('T1557', 'Adversary-in-the-Middle', 'credential-access'),
    ('T1059', 'Command and Scripting Interpreter', 'execution'),
    ('T1055', 'Process Injection', 'defense-evasion'),
    ('T1562', 'Impair Defenses', 'defense-evasion'),
    ('T1027', 'Obfuscated Files or Information', 'defense-evasion'),
    ('T1046', 'Network Service Discovery', 'discovery'),
    ('T1210', 'Exploitation of Remote Services', 'lateral-movement'),
    ('T1021', 'Remote Services', 'lateral-movement'),
    ('T1213', 'Data from Information Repositories', 'collection'),
    ('T1005', 'Data from Local System', 'collection'),
    ('T1071', 'Application Layer Protocol', 'command-and-control'),
    ('T1568', 'Dynamic Resolution', 'command-and-control'),
    ('T1543', 'Create or Modify System Process', 'persistence'),
    ('T1498', 'Network Denial of Service', 'impact'),
    ('T1485', 'Data Destruction', 'impact'),
]

# Known high-profile CVE -> technique mappings (curated).
CVE_TECHNIQUES = {
    'CVE-2024-6387': 'T1190',   # OpenSSH regreSSHion
    'CVE-2021-44228': 'T1190',  # Log4Shell
    'CVE-2021-34527': 'T1190',  # PrintNightmare
    'CVE-2023-34362': 'T1190',  # MOVEit Transfer
    'CVE-2022-22965': 'T1190',  # Spring4Shell
    'CVE-2022-26134': 'T1190',  # Confluence OGNL
    'CVE-2024-3400': 'T1190',   # PAN-OS GlobalProtect
    'CVE-2023-44487': 'T1498',  # HTTP/2 rapid reset
    'CVE-2023-23397': 'T1557',  # Outlook NTLM leak
    'CVE-2021-1675': 'T1190',   # PrintNightmare variant
    'CVE-2020-1472': 'T1210',   # Zerologon
    'CVE-2021-26855': 'T1190',  # ProxyLogon
    'CVE-2021-26084': 'T1190',  # Confluence RCE
    'CVE-2017-0144': 'T1210',   # EternalBlue
    'CVE-2019-0708': 'T1190',   # BlueKeep
}

TACTICS = [
    ('initial-access', 'Initial Access'),
    ('execution', 'Execution'),
    ('persistence', 'Persistence'),
    ('defense-evasion', 'Defense Evasion'),
    ('credential-access', 'Credential Access'),
    ('discovery', 'Discovery'),
    ('lateral-movement', 'Lateral Movement'),
    ('collection', 'Collection'),
    ('command-and-control', 'Command & Control'),
    ('impact', 'Impact'),
]


def technique_for_cve(cve):
    """Look up a technique id for a CVE (curated mapping)."""
    if not cve:
        return None
    with get_db() as conn:
        row = conn.execute('SELECT technique_id FROM cve_techniques WHERE cve=?',
                           (cve.upper(),)).fetchone()
    return row['technique_id'] if row else None


def seed_attack():
    init_db()
    with get_db() as conn:
        conn.executemany(
            'INSERT OR REPLACE INTO techniques (id, name, tactic, url) VALUES (?,?,?,?)',
            [(t, n, tac, f'https://attack.mitre.org/techniques/{t}/')
             for t, n, tac in TECHNIQUES])
        conn.executemany(
            'INSERT OR REPLACE INTO cve_techniques (cve, technique_id) VALUES (?,?)',
            CVE_TECHNIQUES.items())
        conn.execute(
            'UPDATE tickets SET technique_id = '
            'COALESCE((SELECT technique_id FROM cve_techniques WHERE cve = tickets.cve), '
            '  CASE '
            '    WHEN description LIKE \'%(smb)%\' OR description LIKE \'%Port 445%\' '
            '      OR description LIKE \'%Port 139%\' THEN \'T1210\' '
            '    WHEN description LIKE \'%(rdp)%\' OR description LIKE \'%Port 3389%\' THEN \'T1210\' '
            '    WHEN description LIKE \'%(ftp)%\' OR description LIKE \'%Port 21%\' '
            '      OR description LIKE \'%(telnet)%\' OR description LIKE \'%Port 23%\' THEN \'T1190\' '
            '    WHEN description LIKE \'%(mssql)%\' OR description LIKE \'%Port 1433%\' '
            '      OR description LIKE \'%(mysql)%\' OR description LIKE \'%Port 3306%\' THEN \'T1210\' '
            '    ELSE \'T1190\' '
            '  END) '
            'WHERE technique_id IS NULL AND cve IS NOT NULL')


def seed_users():
    init_db()
    from .roles import ensure_builtin_roles, migrate_roles
    admin_user = os.getenv('PORTAL_ADMIN_USERNAME', 'admin')
    admin_pass = os.getenv('PORTAL_ADMIN_PASSWORD', '')
    demo_pass = os.getenv('PORTAL_DEMO_PASSWORD', '')
    if not admin_pass:
        # No silent default credentials: seeding an admin with a known
        # password must be an explicit opt-in (lab convenience only).
        if os.getenv('PORTAL_ALLOW_DEFAULT_ADMIN', '').lower() != 'true':
            print('[seed] PORTAL_ADMIN_PASSWORD not set - admin user NOT created. '
                  'Set it in .env (or PORTAL_ALLOW_DEFAULT_ADMIN=true for a lab).')
        else:
            admin_pass = 'admin'  # explicit lab-only fallback
    with get_db() as conn:
        migrate_roles(conn)
        ensure_builtin_roles(conn)
        if not conn.execute('SELECT 1 FROM users WHERE username=?', (admin_user,)).fetchone():
            conn.execute('INSERT INTO users (username, password_hash, full_name, role) VALUES (?,?,?,?)',
                         (admin_user, hash_password(admin_pass), 'VOC Administrator', 'admin'))
        if demo_pass:
            for u in DEMO_USERS:
                if not conn.execute('SELECT 1 FROM users WHERE username=?', (u['username'],)).fetchone():
                    conn.execute(
                        'INSERT INTO users (username, password_hash, platform_pass, full_name, role) VALUES (?,?,?,?,?)',
                        (u['username'], hash_password(demo_pass), demo_pass, u['full_name'], u['role']))
                else:
                    conn.execute('UPDATE users SET role=?, full_name=? WHERE username=?',
                                 (u['role'], u['full_name'], u['username']))
        # backfill plaintext SSO password for accounts created before provisioning existed
        for u in conn.execute('SELECT id, username, platform_pass FROM users').fetchall():
            if u['platform_pass']:
                continue
            known = admin_pass if u['username'] == admin_user else (demo_pass if demo_pass else '')
            if known:
                conn.execute('UPDATE users SET platform_pass=? WHERE id=?', (known, u['id']))


def import_auto_tickets(max_tickets=25):
    """Create portal tickets from high-risk (>=7) findings in Elasticsearch."""
    from .esdata import ES_PASSWORD, ES_URL, ES_USER

    try:
        resp = requests.post(
            f"{ES_URL}/vulnerabilities-*/_search",
            auth=(ES_USER, ES_PASSWORD),
            json={'size': max_tickets,
                  'query': {'bool': {'filter': [
                      {'range': {'risk_score': {'gte': 7.0}}},
                      {'term': {'status': 'active'}}]}},
                  'sort': [{'risk_score': 'desc'}],
                  '_source': ['cve', 'host_ip', 'severity', 'cvss', 'risk_score', 'first_seen',
                              'port', 'service', 'product', 'version', 'vuln_type',
                              'finding_id', '@timestamp']},
            timeout=30)
        resp.raise_for_status()
        hits = resp.json()['hits']['hits']
    except Exception:
        return 0

    created = 0
    with get_db() as conn:
        for h in hits:
            src = h.get('_source', {})
            cve = src.get('cve')
            host = src.get('host_ip')
            if isinstance(host, dict):
                host = host.get('ip')
            dedup = f"{host}|{cve}"
            if conn.execute('SELECT 1 FROM tickets WHERE dedup_key=?', (dedup,)).fetchone():
                continue
            severity = (src.get('severity') or 'medium').lower()
            if severity not in ('critical', 'high', 'medium', 'low'):
                severity = 'high' if (src.get('risk_score') or 0) >= 9 else 'medium'

            def _f(v):
                if isinstance(v, dict):
                    return _f(v.get('score') or v.get('value'))
                if isinstance(v, (int, float)):
                    return float(v)
                try:
                    return float(v)
                except (TypeError, ValueError):
                    return None

            port = str(src.get('port') or '')
            desc = (f"Port {port} ({src.get('service')}) - "
                    f"{src.get('product')} {src.get('version')} | first_seen "
                    f"{src.get('first_seen')}")
            technique = technique_for_cve(cve)
            if not technique:
                service = (src.get('service') or '').lower()
                if 'smb' in service or port in ('445', '139', '445/tcp'):
                    technique = 'T1210'
                elif 'rdp' in service or port.startswith('3389'):
                    technique = 'T1210'
                elif 'mssql' in service or 'mysql' in service or port.startswith(('1433', '3306')):
                    technique = 'T1210'
                else:
                    technique = 'T1190'
            from .sla import compute_deadline
            conn.execute(
                'INSERT INTO tickets (title, description, severity, source, cve, host, port, '
                'cvss, risk_score, dedup_key, technique_id, sla_deadline, finding_key) '
                'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (f"[{severity.upper()}] {cve} on {host}", desc[:500], severity, 'auto',
                 cve, host, port or None, _f(src.get('cvss')), _f(src.get('risk_score')),
                 dedup, technique, compute_deadline(severity),
                 src.get('finding_id') or f"{host}|{cve}|{port}"))
            created += 1
    return created


def seed():
    seed_users()
    seed_attack()
    import_auto_tickets()
    from .provision import provision_background
    provision_background()