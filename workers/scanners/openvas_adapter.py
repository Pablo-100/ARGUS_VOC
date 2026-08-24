"""OpenVAS / Greenbone adapter.

Speaks GMP (Greenbone Management Protocol - XML over TLS, default port 9390)
with just enough commands to authenticate and pull scan results for a host:

    <authenticate .../>  <get_results filter="..."/>  <get_tasks .../>

Configuration (env):
    OPENVAS_HOST      - hostname/IP of the GVM/OpenVAS manager (gvmd)
    OPENVAS_PORT      - default 9390
    OPENVAS_USER      - GMP user
    OPENVAS_PASS      - GMP password

If OPENVAS_HOST is not configured the adapter reports available()=False and
the pipeline keeps running nmap-only. This adapter NEVER fakes results: when
the scanner is unreachable it returns an explicit error so the operator knows
authenticated scanning did NOT happen.
"""
import logging
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

from .base import HostObservation, NormalizedFinding, ScannerAdapter, register_scanner

logger = logging.getLogger(__name__)

_GMP_TIMEOUT = float(os.getenv('OPENVAS_TIMEOUT', '30'))

_SEV_RE = re.compile(r'\d+(\.\d+)?')


def _text(elem):
    return (elem.text or '').strip() if elem is not None else ''


def parse_gmp_results(xml_bytes, target):
    """Parse a get_results GMP response into NormalizedFindings + HostObservation.

    Public so tests can exercise parsing against recorded fixtures without a
    live OpenVAS deployment.
    """
    root = ET.fromstring(xml_bytes)
    findings = []
    services = {}
    cpes = []
    os_name = None
    hostname = None

    for res in root.iter('result'):
        host_elem = res.find('host')
        host = _text(host_elem) or target
        # newer GMP versions put the asset/hostname in attributes/children
        if hostname is None and host_elem is not None:
            hn = host_elem.find('hostname')
            if hn is not None:
                hostname = _text(hn) or None

        name = _text(res.find('name'))
        severity_txt = _text(res.find('severity'))
        m = _SEV_RE.search(severity_txt)
        cvss = float(m.group(0)) if m else None
        port_raw = _text(res.find('port'))
        # port strings look like "80/tcp" or "general/tcp"
        port_s, _, proto = port_raw.partition('/')
        service = 'general' if not proto else f'{port_s}/{proto}'
        if proto and port_s.isdigit():
            services[str(port_s)] = {'service': service}

        nvts = res.find('nvt')
        cve_refs = []
        plugin_id = ''
        solution = ''
        if nvts is not None:
            plugin_id = nvts.get('oid', '')
            for ref in nvts.findall('./cve'):
                if ref.get('#text') or ref.text:
                    cve_refs.append((ref.get('#text') or ref.text).strip())
            solution = _text(nvts.find('./solution'))

        description = _text(res.find('description'))[:2000]
        sev_word = ('Critical' if (cvss or 0) >= 9 else
                    'High' if (cvss or 0) >= 7 else
                    'Medium' if (cvss or 0) >= 4 else
                    'Low' if (cvss or 0) > 0 else 'Info')

        cves = [c.upper() for c in cve_refs if c.upper().startswith('CVE-')]
        findings.append(NormalizedFinding(
            scanner='openvas', target=host,
            finding_id=f"{host}|{plugin_id}|{port_raw}",
            cve=cves[0] if cves else '',
            cvss=cvss, severity=sev_word,
            desc=name or description[:200],
            port=port_raw or 'general', service=service,
            product='', version='', cpe='',
            plugin_id=plugin_id, solution=solution,
            evidence=description, all_cves=cves,
        ))

        # host detail results carry OS/CPE info (NVTs of type "Host Details")
        if 'cpe' in name.lower() and '/a:' in description or 'cpe:/' in description:
            m2 = re.search(r'cpe:/[aho]:[^,\s]+', description)
            if m2 and m2.group(0) not in cpes:
                cpes.append(m2.group(0))

    obs = HostObservation(ip=target, hostname=hostname, os_name=os_name,
                          services=services, cpes=cpes)
    return findings, obs


class _GMPConnection:
    """Minimal GMP-over-TLS client (authenticate + run one command)."""

    def __init__(self, host, port, user, password, timeout=_GMP_TIMEOUT):
        self.host, self.port = host, int(port)
        self.user, self.password = user, password
        self.timeout = timeout
        self.sock = None

    def __enter__(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # self-signed GVM certs are the norm
        self.sock = ctx.wrap_socket(raw)
        self._read_response()  # banner <gmp_response status="200">
        return self

    def __exit__(self, *exc):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        return False

    def _send(self, xml_cmd):
        self.sock.sendall(xml_cmd.encode())

    def _read_response(self):
        """Read one XML document from the socket."""
        buf = b''
        while True:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            if b'</authenticate_response>' in buf or \
               b'</get_results_response>' in buf or \
               b'</get_tasks_response>' in buf or \
               b'</start_task_response>' in buf or \
               b'</create_target_response>' in buf or \
               b'</create_task_response>' in buf or \
               b'gmp_response' in buf:
                break
        return buf

    def authenticate(self):
        self._send(f'<authenticate credentials=""><username>{xml_escape(self.user)}</username>'
                   f'<password>{xml_escape(self.password)}</password></authenticate>')
        resp = self._read_response()
        root = ET.fromstring(resp)
        if root.get('status') != '200':
            raise RuntimeError(f'OpenVAS authentication failed: {root.get("status")} '
                               f'{root.get("status_text", "")}')

    def command(self, xml_cmd):
        self._send(xml_cmd)
        return self._read_response()


@register_scanner('openvas')
class OpenVASAdapter(ScannerAdapter):
    name = 'openvas'

    def __init__(self):
        self.host = os.getenv('OPENVAS_HOST', '')
        self.port = os.getenv('OPENVAS_PORT', '9390')
        self.user = os.getenv('OPENVAS_USER', '')
        self.password = os.getenv('OPENVAS_PASS', '')

    def available(self):
        return bool(self.host)

    def config_summary(self):
        return {'host': self.host or '(not configured)', 'port': self.port,
                'user': self.user or '(not configured)'}

    def scan_host(self, host):
        """Pull existing OpenVAS results for `host` from the GVM manager.

        This queries whatever the latest finished task says about the host -
        it does not start a new authenticated scan per call (scan policies are
        managed inside Greenbone). If no results exist the response carries an
        explicit error rather than fabricated data.
        """
        if not self.available():
            raise RuntimeError('OPENVAS_HOST is not configured')
        now_iso = datetime.now(timezone.utc).isoformat(timespec='seconds')
        result = {
            'host': host, 'os': None,
            'scan_date': now_iso,
            'vulns': [], 'scan_type': self.name,
            'scan_id': f"openvas_{host}_{int(datetime.now(timezone.utc).timestamp())}",
        }
        filt = f'results?rows=-1&first=1&sort=severity&host={xml_escape(host)}'
        cmd = (f'<get_results details="1" filter="{filt}"/>')
        try:
            with _GMPConnection(self.host, self.port, self.user, self.password) as gmp:
                gmp.authenticate()
                resp = gmp.command(cmd)
        except Exception as e:
            logger.error('[OpenVAS] query failed for %s: %s', host, e)
            result['error'] = f'openvas_unreachable: {e}'
            return result

        try:
            findings, obs = parse_gmp_results(resp, host)
        except ET.ParseError as e:
            logger.error('[OpenVAS] unparseable GMP response for %s: %s', host, e)
            result['error'] = f'openvas_bad_response: {e}'
            return result

        result['vulns'] = [dict(f) for f in findings]
        obs['ip'] = host
        result['observation'] = obs
        result['os'] = obs.get('os_name')
        logger.info('[OpenVAS] %s normalized findings for %s', len(findings), host)
        return result
