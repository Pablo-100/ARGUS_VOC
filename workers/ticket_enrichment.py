import json
import logging
import os
from datetime import datetime

from threat_intel import enrich_threat_intel

logger = logging.getLogger(__name__)

KB_DIR = os.path.join(os.path.dirname(__file__), 'knowledge')

_kb_cache = {}


def _load_kb(name):
    if name not in _kb_cache:
        path = os.path.join(KB_DIR, name)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                _kb_cache[name] = json.load(f)
        except Exception as e:
            logger.error(f"Could not load knowledge base {name}: {e}")
            _kb_cache[name] = {}
    return _kb_cache[name]


# ---------------------------------------------------------------------------
# Classification: CWE -> vulnerability type
# ---------------------------------------------------------------------------
def classify_vulnerability(cwes, service=''):
    """Return (vuln_type, owasp, matched_cwes)."""
    types = _load_kb('cwe_types.json').get('types', {})
    default_type = _load_kb('cwe_types.json').get('default', 'Security Vulnerability')

    matches = []
    cwe_set = {c.upper() for c in (cwes or []) if c}

    for tname, tdata in types.items():
        for cwe in tdata.get('cwes', []):
            if cwe.upper() in cwe_set:
                matches.append((tname, tdata))
                break

    if matches:
        vuln_type, tdata = matches[0]
        return vuln_type, tdata.get('owasp', ''), list(cwe_set)

    # No CWE from NVD: fall back to service heuristic.
    heuristic = _heuristic_from_service(service)
    if heuristic:
        return heuristic, types.get(heuristic, {}).get('owasp', ''), list(cwe_set)
    return default_type, '', list(cwe_set)


def _heuristic_from_service(service):
    service = (service or '').lower()
    if 'web' in service or 'http' in service or 'nginx' in service or 'apache' in service:
        return 'Security Misconfiguration'
    if 'sql' in service or 'mysql' in service or 'postgres' in service or 'mariadb' in service:
        return 'Security Misconfiguration'
    if 'dns' in service or 'snmp' in service:
        return 'Security Misconfiguration'
    return None


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping: CWE -> techniques/tactics
# ---------------------------------------------------------------------------
def get_attack_mapping(cwes):
    attack_map = _load_kb('attack_map.json')
    techniques = attack_map.get('techniques', {})
    defaults = attack_map.get('default', [])

    matched = []
    seen = set()
    for cwe in (cwes or []):
        for t in techniques.get(cwe.upper(), []):
            key = t['id']
            if key not in seen:
                seen.add(key)
                matched.append(t)
    if not matched:
        for t in defaults:
            if t['id'] not in seen:
                seen.add(t['id'])
                matched.append(t)

    tactics = []
    for t in matched:
        for tac in t.get('tactics', []):
            if tac not in tactics:
                tactics.append(tac)
    return matched, tactics


# ---------------------------------------------------------------------------
# Remediation + CIS Benchmark recommendations
# ---------------------------------------------------------------------------
def get_remediation(cwes):
    rem_map = _load_kb('remediation.json')
    default = rem_map.get('default', {})
    remediation = []
    validation = []
    for cwe in (cwes or []):
        entry = rem_map.get(cwe.upper())
        if isinstance(entry, dict):
            remediation.extend(entry.get('remediation', []))
            validation.extend(entry.get('validation', []))
    if not remediation:
        remediation = default.get('remediation', [])
    if not validation:
        validation = default.get('validation', [])
    return _dedup(remediation), _dedup(validation)


def get_cis_recommendations(service, product=''):
    cis = _load_kb('cis_benchmarks.json')
    benchmarks = cis.get('benchmarks', {})
    aliases = cis.get('aliases', {})

    key = (service or '').strip().lower()
    if not key:
        key = (product or '').strip().lower()
    if key in aliases:
        key = aliases[key]
    entry = benchmarks.get(key)
    if not entry:
        entry = benchmarks.get('default')
    if not entry:
        return [], [], []
    return entry.get('benchmark', ''), entry.get('sections', []), entry.get('hardening', [])


# ---------------------------------------------------------------------------
# Security checklist
# ---------------------------------------------------------------------------
def build_checklist(vuln, host):
    _, validation = get_remediation(vuln.get('cwes', []))
    _, _, cis_hardening = get_cis_recommendations(vuln.get('service', ''), vuln.get('product', ''))
    rem, _ = get_remediation(vuln.get('cwes', []))

    checklist = []
    idx = 1
    for item in _dedup(validation):
        checklist.append({'id': f'VAL-{idx:02d}', 'category': 'Validation', 'action': item, 'done': False})
        idx += 1
    for item in _dedup(rem):
        checklist.append({'id': f'REM-{idx:02d}', 'category': 'Remediation', 'action': item, 'done': False})
        idx += 1
    checklist.append({
        'id': f'VER-{idx:02d}', 'category': 'Verification',
        'action': f"Re-scan {host} to confirm {vuln.get('cve', 'the finding')} is resolved and the ticket can be closed.",
        'done': False,
    })
    idx += 1
    for item in _dedup(cis_hardening)[:5]:
        checklist.append({'id': f'CIS-{idx:02d}', 'category': 'CIS Benchmark', 'action': item, 'done': False})
        idx += 1
    return checklist


# ---------------------------------------------------------------------------
# Technical description (deterministic Markdown)
# ---------------------------------------------------------------------------
def build_technical_description(vuln, host, attack_techniques, tactics):
    cve = vuln.get('cve', 'N/A')
    vuln_type = vuln.get('vuln_type', 'Security Vulnerability')
    cwes = vuln.get('cwes', [])
    lines = []

    lines.append(f"## Vulnerability Overview")
    lines.append(f"- **CVE**: {cve}")
    lines.append(f"- **Host**: {host}")
    lines.append(f"- **Port / Service**: {vuln.get('port', 'N/A')} ({vuln.get('service', 'N/A')})")
    lines.append(f"- **Product / Version**: {vuln.get('product', 'N/A')} {vuln.get('version', '')}")
    if vuln.get('cpe'):
        lines.append(f"- **CPE**: {vuln.get('cpe')}")
    lines.append(f"- **Vulnerability Type**: {vuln_type}")
    if vuln.get('owasp_category'):
        lines.append(f"- **OWASP Top 10**: {vuln.get('owasp_category')}")
    if cwes:
        lines.append(f"- **CWE**: {', '.join(cwes)}")

    desc = (vuln.get('desc') or '').strip()
    if desc:
        lines.append("")
        lines.append(f"## Description")
        lines.append(desc[:2000])

    lines.append("")
    lines.append("## MITRE ATT&CK")
    if tactics:
        lines.append(f"- **Tactics**: {', '.join(tactics)}")
    for t in attack_techniques:
        lines.append(f"- **{t['id']}** {t['name']} - {', '.join(t.get('tactics', []))}")
        lines.append(f"  https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/")

    lines.append("")
    lines.append("## Threat Intelligence")
    lines.append(f"- **CVSS Base Score**: {vuln.get('cvss', 'N/A')}")
    lines.append(f"- **VOC Risk Score**: {vuln.get('risk_score', 'N/A')} ({vuln.get('severity', 'N/A')})")
    if vuln.get('epss_score') is not None:
        lines.append(f"- **EPSS**: {float(vuln['epss_score']):.4f} (percentile {float(vuln.get('epss_percentile', 0)):.4f})")
    lines.append(f"- **CISA KEV**: {'YES - actively exploited' if vuln.get('in_kev') else 'No'}")
    lines.append(f"- **Public Exploit Available**: {'YES' if vuln.get('exploit_available') else 'No'}")
    if vuln.get('exploitdb'):
        lines.append(f"- **Exploit-DB entries**: {len(vuln['exploitdb'])}")
    vt = vuln.get('virustotal')
    if vt:
        lines.append(f"- **VirusTotal verdict**: {vt.get('vt_verdict', 'N/A')} "
                     f"({vt.get('vt_malicious_count', 0)} malicious / {vt.get('vt_total', 0)} matches)")
    if vuln.get('kev'):
        k = vuln['kev']
        lines.append(f"- **KEV details**: {k.get('kev_name', '')} (added {k.get('kev_date_added', '')})")
        lines.append(f"- **KEV required action**: {k.get('kev_required_action', '')} (due {k.get('kev_due_date', '')})")
        if k.get('kev_ransomware'):
            lines.append(f"- **Known ransomware campaign use**: YES")

    remediation, _ = get_remediation(cwes)
    lines.append("")
    lines.append("## Recommended Remediation")
    for i, r in enumerate(remediation, 1):
        lines.append(f"{i}. {r}")

    benchmark, sections, hardening = get_cis_recommendations(vuln.get('service', ''), vuln.get('product', ''))
    if benchmark:
        lines.append("")
        lines.append(f"## CIS Benchmark Hardening ({benchmark})")
        if sections:
            lines.append(f"- **Sections**: {', '.join(sections)}")
        for i, h in enumerate(hardening, 1):
            lines.append(f"- {h}")

    lines.append("")
    lines.append("## References")
    lines.append(f"- NVD: https://nvd.nist.gov/vuln/detail/{cve}")
    for cwe in cwes:
        lines.append(f"- CWE: https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html")
    osv = vuln.get('osv') or {}
    for ref in osv.get('osv_references', [])[:10]:
        lines.append(f"- OSV: {ref}")
    for e in vuln.get('exploitdb', [])[:5]:
        lines.append(f"- Exploit-DB #{e.get('id')}: {e.get('exploitdb_url', '')}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point: enrich a single vulnerability dict
# ---------------------------------------------------------------------------
def enrich_vulnerability(vuln, host):
    cve = vuln.get('cve')
    cwes = list(vuln.get('cwes') or [])

    # Threat intelligence (EPSS, KEV, OSV, ExploitDB, VirusTotal).
    ti = {}
    if cve:
        ti = enrich_threat_intel(cve)
        for k, v in ti.items():
            if k != 'cve':
                vuln[k] = v
        cwes = _merge_cwes(cwes, (ti.get('osv') or {}).get('osv_aliases', []))

    # Classification.
    vuln_type, owasp, cwes = classify_vulnerability(cwes, vuln.get('service', ''))
    vuln['vuln_type'] = vuln_type
    vuln['owasp_category'] = owasp
    vuln['cwes'] = cwes

    # ATT&CK mapping.
    attack_techniques, tactics = get_attack_mapping(cwes)
    vuln['attack_techniques'] = attack_techniques
    vuln['attack_tactics'] = tactics

    # Remediation + CIS.
    remediation, validation = get_remediation(cwes)
    vuln['remediation'] = remediation
    vuln['validation_steps'] = validation
    benchmark, sections, hardening = get_cis_recommendations(vuln.get('service', ''), vuln.get('product', ''))
    vuln['cis_benchmark'] = benchmark
    vuln['cis_sections'] = sections
    vuln['cis_hardening'] = hardening

    # Checklist + description (description after risk_score so it can embed it).
    vuln['checklist'] = build_checklist(vuln, host)
    return vuln


def finalize_description(vuln, host):
    """Build the Markdown description after scoring (needs risk_score/severity)."""
    attack_techniques = vuln.get('attack_techniques', [])
    tactics = vuln.get('attack_tactics', [])
    vuln['technical_description'] = build_technical_description(vuln, host, attack_techniques, tactics)
    return vuln


def _merge_cwes(cwes, aliases):
    result = list(cwes)
    for alias in aliases or []:
        alias = str(alias).strip().upper()
        if alias.startswith('CWE-') and alias not in result:
            result.append(alias)
    return result


def _dedup(items):
    out = []
    for i in items:
        if i and i not in out:
            out.append(i)
    return out
