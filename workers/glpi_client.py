import os
import json
import requests
import logging
import threading
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GLPI_URL = os.getenv('GLPI_URL', 'http://192.168.184.135')
APP_TOKEN = os.getenv('GLPI_APP_TOKEN', '')
USER_TOKEN = os.getenv('GLPI_USER_TOKEN', '')
VERIFY_SSL = os.getenv('GLPI_VERIFY_SSL', 'true').lower() == 'true'

_session_lock = threading.Lock()
_session_token = None
_session_expiry = 0
_session = None


def create_session_with_retries(verify_ssl: bool = True) -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    return session


def get_session_token() -> str:
    global _session_token, _session_expiry, _session

    current_time = time.time()
    if _session_token and current_time < _session_expiry - 60:
        return _session_token

    with _session_lock:
        if _session_token and current_time < _session_expiry - 60:
            return _session_token

        if not APP_TOKEN or not USER_TOKEN:
            logger.error("GLPI credentials not configured")
            return None

        try:
            session = create_session_with_retries(VERIFY_SSL)
            r = session.get(
                f"{GLPI_URL}/apirest.php/initSession",
                headers={
                    "App-Token": APP_TOKEN,
                    "Authorization": f"user_token {USER_TOKEN}"
                },
                timeout=10
            )
            r.raise_for_status()
            data = r.json()
            _session_token = data.get("session_token")
            _session_expiry = current_time + 3600
            _session = session
            logger.info("GLPI session created successfully")
            return _session_token
        except requests.exceptions.RequestException as e:
            logger.error(f"GLPI initSession failed: {e}")
            return None
        except Exception as e:
            logger.error(f"GLPI initSession error: {e}")
            return None


def kill_session(token: str = None) -> bool:
    global _session_token, _session_expiry, _session
    token = token or _session_token
    if not token:
        return True

    try:
        session = _session or create_session_with_retries(VERIFY_SSL)
        r = session.get(
            f"{GLPI_URL}/apirest.php/killSession",
            headers={
                "App-Token": APP_TOKEN,
                "Session-Token": token
            },
            timeout=5
        )
        if r.status_code in [200, 204]:
            logger.info("GLPI session killed successfully")
        _session_token = None
        _session_expiry = 0
        _session = None
        return True
    except Exception as e:
        logger.warning(f"GLPI killSession failed: {e}")
        _session_token = None
        _session_expiry = 0
        _session = None
        return False


def set_ticket_status(ticket_id, status):
    """Set a GLPI ticket's lifecycle status (1=new 2=assigned 3=planned
    4=pending 5=solved 6=closed). Returns True/False."""
    token = get_session_token()
    if not token or not ticket_id:
        return False
    headers = {
        "Content-Type": "application/json",
        "App-Token": APP_TOKEN,
        "Session-Token": token,
    }
    session = _session or create_session_with_retries(VERIFY_SSL)
    try:
        r = session.put(
            f"{GLPI_URL}/apirest.php/Ticket/{int(ticket_id)}",
            headers=headers,
            json={"input": {"status": int(status)}},
            timeout=15,
        )
        ok = r.status_code in [200, 201]
        if not ok:
            logger.warning(f"GLPI status change for #{ticket_id} -> {status} "
                           f"failed: {r.status_code} {r.text[:160]}")
        return ok
    except Exception as e:
        logger.warning(f"GLPI status change failed for #{ticket_id}: {e}")
        return False


def reopen_ticket(ticket_id):
    """Reopen a GLPI ticket (back to 'Processing (assigned)')."""
    ok = set_ticket_status(ticket_id, 2)
    if not ok:
        # fall back to plain 'new' if the assignment transition is refused
        return set_ticket_status(ticket_id, 1)
    try:
        add_ticket_followup(ticket_id,
                            "<p>[VOC] Ticket reopened automatically: the "
                            "vulnerability was re-detected by a follow-up scan.</p>",
                            {"Content-Type": "application/json", "App-Token": APP_TOKEN,
                             "Session-Token": get_session_token()})
    except Exception as e:
        logger.warning(f"Reopen follow-up failed for #{ticket_id}: {e}")
    return True


def close_ticket(ticket_id):
    """Mark a GLPI ticket closed after verified remediation."""
    return set_ticket_status(ticket_id, 6)


def find_existing_ticket(host: str, vuln: dict, statuses=('1', '2', '3', '4', '5')) -> dict:
    """Return an existing open/new ticket matching (host, CVE) or None.

    GLPI ticket names follow the '[VOC] {severity} - {cve} ... on {host}' format,
    so we search by CVE + host in the ticket name. Only active statuses
    (new/progressed/planned/pending/solved) are considered duplicates.
    """
    token = get_session_token()
    if not token:
        return None

    headers = {
        "Content-Type": "application/json",
        "App-Token": APP_TOKEN,
        "Session-Token": token
    }
    session = _session or create_session_with_retries(VERIFY_SSL)
    vuln_id = vuln.get('cve', 'N/A')
    status_query = ",".join(statuses)

    try:
        r = session.get(
            f"{GLPI_URL}/apirest.php/Ticket",
            headers=headers,
            params={
                "expand_contents": "false",
                "searchText": f"[VOC] {vuln.get('severity', '*')} - {vuln_id}",
                "criteria": json.dumps([
                    {"field": 12, "searchtype": "contains", "value": f"on {host}"},
                    {"link": "AND", "field": 12, "searchtype": "contains", "value": vuln_id},
                    {"link": "AND", "field": 12, "searchtype": "contains", "value": "[VOC]"},
                ]),
                "forcedisplay": "1,3,12",
            },
            timeout=15,
        )
        if r.status_code in [200, 201]:
            tickets = r.json()
        elif r.status_code in [206] and r.content:
            tickets = r.json()
        else:
            return None
    except requests.exceptions.RequestException as e:
        logger.warning(f"GLPI dedup lookup failed for {vuln_id} on {host}: {e}")
        return None
    except Exception as e:
        logger.warning(f"GLPI dedup lookup error: {e}")
        return None

    if not isinstance(tickets, list):
        tickets = [tickets]
    for t in tickets:
        name = t.get('name', '')
        if vuln_id in name and f"on {host}" in name:
            return t
    return None


def create_ticket(host: str, vuln: dict, _retry=True) -> str:
    token = get_session_token()
    if not token:
        return "glpi_auth_failed"

    headers = {
        "Content-Type": "application/json",
        "App-Token": APP_TOKEN,
        "Session-Token": token
    }

    session = _session or create_session_with_retries(VERIFY_SSL)

    try:
        risk_score = vuln.get('risk_score', 0)
        urgency = 5 if risk_score >= 9 else 4
        impact = 4
        priority = 5 if risk_score >= 7 else 4

        category_id = os.getenv('GLPI_CATEGORY_ID', '1')
        ticket_type = os.getenv('GLPI_TICKET_TYPE', '2')

        vuln_type = vuln.get('vuln_type') or 'Security Vulnerability'
        name = f"[VOC] {vuln.get('severity', 'Unknown')} - {vuln.get('cve', 'N/A')} ({vuln_type}) on {host}"
        content = _build_ticket_content(host, vuln)

        payload = {
            "input": {
                "name": name,
                "content": content,
                "urgency": urgency,
                "impact": impact,
                "priority": priority,
                "itilcategories_id": int(category_id),
                "type": int(ticket_type)
            }
        }

        r = session.post(
            f"{GLPI_URL}/apirest.php/Ticket",
            headers=headers,
            json=payload,
            timeout=15
        )

        if r.status_code in [200, 201]:
            ticket_id = r.json().get('id', 'unknown')
            logger.info(f"Created GLPI ticket #{ticket_id} for {vuln.get('cve')} on {host}")
            if os.getenv('CHECKLIST_IN_GLPI', 'true').lower() == 'true' and vuln.get('checklist'):
                add_ticket_followup(ticket_id, _checklist_to_html(vuln.get('checklist', [])), headers)
            return f"ticket_created: {ticket_id}"
        elif r.status_code == 401:
            logger.warning("GLPI session expired, recreating...")
            kill_session(token)
            if _retry:
                return create_ticket(host, vuln, _retry=False)
            return "glpi_auth_failed"
        else:
            logger.error(f"GLPI API error {r.status_code}: {r.text}")
            return f"glpi_api_error_{r.status_code}"

    except requests.exceptions.RequestException as e:
        logger.error(f"GLPI ticket creation request failed: {e}")
        return f"glpi_request_failed: {str(e)}"
    except Exception as e:
        logger.error(f"GLPI ticket creation error: {e}")
        return f"glpi_error: {str(e)}"


def _build_ticket_content(host: str, vuln: dict) -> str:
    """Build the enriched HTML ticket body from the VOC pipeline data."""
    summary = [
        f"<tr><td><b>CVE</b></td><td>{_esc(vuln.get('cve', 'N/A'))}</td></tr>",
        f"<tr><td><b>Host</b></td><td>{_esc(host)}</td></tr>",
        f"<tr><td><b>Port / Service</b></td><td>{_esc(vuln.get('port', 'N/A'))} ({_esc(vuln.get('service', 'N/A'))})</td></tr>",
        f"<tr><td><b>Product / Version</b></td><td>{_esc(vuln.get('product', 'N/A'))} {_esc(vuln.get('version', ''))}</td></tr>",
        f"<tr><td><b>Vulnerability Type</b></td><td>{_esc(vuln.get('vuln_type', 'Security Vulnerability'))}</td></tr>",
    ]
    if vuln.get('owasp_category'):
        summary.append(f"<tr><td><b>OWASP Top 10</b></td><td>{_esc(vuln.get('owasp_category'))}</td></tr>")
    if vuln.get('cwes'):
        summary.append(f"<tr><td><b>CWE</b></td><td>{_esc(', '.join(vuln.get('cwes')))}</td></tr>")
    summary.append(f"<tr><td><b>CVSS Base Score</b></td><td>{_esc(vuln.get('cvss', 'N/A'))}</td></tr>")
    summary.append(f"<tr><td><b>VOC Risk Score</b></td><td>{_esc(vuln.get('risk_score', 'N/A'))} ({_esc(vuln.get('severity', 'N/A'))})</td></tr>")
    if vuln.get('epss_score') is not None:
        summary.append(f"<tr><td><b>EPSS</b></td><td>{float(vuln.get('epss_score')):.4f} (percentile {float(vuln.get('epss_percentile', 0)):.4f})</td></tr>")
    summary.append(f"<tr><td><b>CISA KEV</b></td><td>{'YES - actively exploited' if vuln.get('in_kev') else 'No'}</td></tr>")
    summary.append(f"<tr><td><b>Public Exploit Available</b></td><td>{'YES' if vuln.get('exploit_available') else 'No'}</td></tr>")
    if vuln.get('exploitdb'):
        summary.append(f"<tr><td><b>Exploit-DB entries</b></td><td>{len(vuln.get('exploitdb'))}</td></tr>")
    vt = vuln.get('virustotal')
    if vt:
        summary.append(f"<tr><td><b>VirusTotal verdict</b></td><td>{_esc(vt.get('vt_verdict', 'N/A'))} ({vt.get('vt_malicious_count', 0)} malicious / {vt.get('vt_total', 0)} matches)</td></tr>")

    html = [f"<h3>VOC Enriched Vulnerability Report</h3><table>{''.join(summary)}</table>"]

    desc = (vuln.get('desc') or '').strip()
    if desc:
        html.append(f"<h3>Description</h3><p>{_esc(desc[:2000])}</p>")

    tactics = vuln.get('attack_tactics', [])
    techniques = vuln.get('attack_techniques', [])
    if tactics or techniques:
        html.append("<h3>MITRE ATT&CK</h3>")
        if tactics:
            html.append(f"<p><b>Tactics</b>: {_esc(', '.join(tactics))}</p>")
        html.append("<ul>")
        for t in techniques:
            html.append(f"<li><b>{_esc(t.get('id', ''))}</b> {_esc(t.get('name', ''))} "
                        f"({_esc(', '.join(t.get('tactics', [])))})</li>")
        html.append("</ul>")

    kev = vuln.get('kev')
    if kev:
        html.append(f"<h3>CISA KEV Details</h3><p><b>{_esc(kev.get('kev_name', ''))}</b> "
                    f"(added {_esc(kev.get('kev_date_added', ''))})<br>"
                    f"Required action: {_esc(kev.get('kev_required_action', ''))} "
                    f"(due {_esc(kev.get('kev_due_date', ''))})</p>")

    remediation = vuln.get('remediation', [])
    if remediation:
        html.append("<h3>Recommended Remediation</h3><ol>")
        for r in remediation:
            html.append(f"<li>{_esc(r)}</li>")
        html.append("</ol>")

    if vuln.get('cis_benchmark'):
        html.append(f"<h3>CIS Benchmark Hardening ({_esc(vuln.get('cis_benchmark'))})</h3>")
        if vuln.get('cis_sections'):
            html.append(f"<p><b>Sections</b>: {_esc(', '.join(vuln.get('cis_sections')))}</p>")
        html.append("<ul>")
        for h in vuln.get('cis_hardening', [])[:10]:
            html.append(f"<li>{_esc(h)}</li>")
        html.append("</ul>")

    refs = [f"- NVD: https://nvd.nist.gov/vuln/detail/{_esc(vuln.get('cve', ''))}"]
    for cwe in vuln.get('cwes', []):
        cwe_id = str(cwe).split('-')[-1]
        refs.append(f"- CWE: https://cwe.mitre.org/data/definitions/{cwe_id}.html")
    osv = vuln.get('osv') or {}
    for ref in osv.get('osv_references', [])[:8]:
        refs.append(f"- {_esc(ref)}")
    for e in vuln.get('exploitdb', [])[:5]:
        refs.append(f"- Exploit-DB #{e.get('id')}: {_esc(e.get('exploitdb_url', ''))}")
    html.append("<h3>References</h3><ul>" + "".join(f"<li>{r}</li>" for r in refs) + "</ul>")

    return "".join(html)


def _checklist_to_html(checklist):
    html = ["<h3>Security Checklist (Validation & Remediation Tracking)</h3><ul>"]
    for item in checklist:
        html.append(f"<li>[ ] <b>{_esc(item.get('id', ''))} / {_esc(item.get('category', ''))}</b> - "
                    f"{_esc(item.get('action', ''))}</li>")
    html.append("</ul>")
    return "".join(html)


def add_ticket_followup(ticket_id, content, headers):
    try:
        session = _session or create_session_with_retries(VERIFY_SSL)
        payload = {"input": {"items_id": int(ticket_id), "itemtype": "Ticket", "content": content}}
        r = session.post(
            f"{GLPI_URL}/apirest.php/Ticket/{ticket_id}/TicketFollowup",
            headers=headers,
            json=payload,
            timeout=15
        )
        if r.status_code in [200, 201]:
            logger.info(f"Added checklist follow-up to GLPI ticket #{ticket_id}")
            return True
        logger.warning(f"Follow-up not added to ticket #{ticket_id}: {r.status_code} {r.text[:200]}")
        return False
    except Exception as e:
        logger.warning(f"Follow-up add failed for ticket #{ticket_id}: {e}")
        return False


def _esc(value):
    """Escape a value for safe HTML output."""
    if value is None:
        return ''
    return (str(value).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;'))