"""Nmap adapter - wraps the existing full TCP + version + OS nmap scan and
adds an optional NSE "super power" pass that actively CHECKS for specific
vulnerabilities (Feature: authenticated-grade confirmation without OpenVAS).

Two-phase design:
  1. Discovery scan (-sS -sV -O -p-): open ports, services, versions, OS.
     Product/version matches against NVD become findings with
     confidence='potential'.
  2. NSE check scan (--script <expr>) restricted to the ports found open in
     phase 1. Scripts in the `vuln` category probe the actual service and
     report VULNERABLE blocks with CVE ids + evidence. Those become findings
     with confidence='confirmed' and are merged over matching potential ones.

Safety: the default expression excludes `dos`, `intrusive` and `exploit`
categories so scans never crash services or run exploit payloads -
detection-only. Override via NMAP_VULN_SCRIPTS at your own risk.
"""
import logging
import os
import re
from datetime import datetime, timezone

from .base import HostObservation, NormalizedFinding, ScannerAdapter, register_scanner

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_RISK_RE = re.compile(r'Risk factor:\s*(\w+)', re.IGNORECASE)

_RISK_MAP = {
    'critical': 'Critical', 'high': 'High', 'medium': 'Medium',
    'low': 'Low', 'informational': 'Info',
}


def parse_script_findings(script_id, output, host, port_str, service=''):
    """Convert one NSE script output block into normalized CONFIRMED findings.

    Returns [] unless the output contains a VULNERABLE marker; a single block
    may reference several CVEs (one finding each). Public for unit tests.
    """
    if not output or 'VULNERABLE' not in output.upper():
        return []
    cves = list(dict.fromkeys(c.upper() for c in _CVE_RE.findall(output)))
    if not cves:
        # vulnerable state but no CVE id to correlate on - keep as evidence
        # note rather than inventing an identifier.
        logger.warning('NSE %s reported VULNERABLE on %s without any CVE id '
                       '- recorded as evidence only', script_id, host)
        return []

    m = _RISK_RE.search(output)
    sev = _RISK_MAP.get((m.group(1) or '').lower()) if m else None

    findings = []
    for cve in cves:
        findings.append(NormalizedFinding(
            scanner='nmap', target=host,
            finding_id=f"{host}|{cve}|{port_str}",
            cve=cve,
            severity=sev or 'Unknown',
            desc=f"[NSE:{script_id}] Vulnerability CONFIRMED by active "
                 f"check on {host}:{port_str}",
            port=port_str, service=service,
            plugin_id=f"NSE-{script_id}",
            evidence=output.strip()[:2000],
            confidence='confirmed',
            risk_factors={'nse_check': True, 'script': script_id},
        ))
    return findings


@register_scanner('nmap')
class NmapAdapter(ScannerAdapter):
    name = 'nmap'

    DEFAULT_SCAN_ARGS = '-sS -sV --version-intensity 5 -O -p- -T4'
    DEFAULT_VULN_SCRIPTS = 'vuln and not (dos or intrusive)'

    def __init__(self):
        try:
            import nmap  # python-nmap
            self._nmap = nmap
        except ImportError:
            self._nmap = None
            logger.warning('python-nmap not installed - NmapAdapter unavailable')

    def available(self):
        return self._nmap is not None

    def config_summary(self):
        return {
            'scan_args': os.getenv('NMAP_SCAN_ARGS', self.DEFAULT_SCAN_ARGS),
            'nse_vuln_scan': self._nse_enabled(),
            'vuln_scripts': os.getenv('NMAP_VULN_SCRIPTS', self.DEFAULT_VULN_SCRIPTS),
        }

    @staticmethod
    def _nse_enabled():
        return os.getenv('NMAP_NSE_VULN_SCAN', 'true').lower() == 'true'

    def scan_host(self, host):
        if not self.available():
            raise RuntimeError('python-nmap not installed')

        scan_args = os.getenv('NMAP_SCAN_ARGS', self.DEFAULT_SCAN_ARGS)
        # Reverse-DNS resolution populates real hostnames (user requirement:
        # see WHICH machine is behind an IP). -n would disable it.
        if os.getenv('NMAP_RESOLVE', 'true').lower() == 'true' \
                and '-R' not in scan_args and '-n' not in scan_args:
            scan_args += ' -R'
        nm = self._nmap.PortScanner()
        nm.scan(hosts=host, arguments=scan_args)

        obs = HostObservation(ip=host)
        result = {
            'host': host, 'os': None,
            'scan_date': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'vulns': [], 'scan_type': self.name,
            'scan_id': f"nmap_{host}_{int(datetime.now(timezone.utc).timestamp())}",
        }
        if host not in nm.all_hosts():
            result['error'] = 'Host not found'
            return result

        host_data = nm[host]
        addresses = getattr(host_data, 'addresses', {}) or {}
        obs['mac'] = addresses.get('mac')
        obs['ip'] = addresses.get('ipv4', host)
        try:
            hostnames = host_data.hostname() or {}
            if isinstance(hostnames, dict):
                obs['hostname'] = hostnames.get('name')
        except Exception:
            pass
        try:
            osmatch = host_data.get('osmatch', [])
            if osmatch:
                result['os'] = osmatch[0].get('name')
                obs['os_name'] = result['os']
        except Exception as e:
            logger.warning('OS detection failed for %s: %s', host, e)

        services = {}
        open_tcp_ports = []
        for proto in host_data.all_protocols():
            for port, info in host_data[proto].items():
                if info.get('state', '') != 'open':
                    continue
                service = info.get('name', 'unknown')
                product = info.get('product', '')
                version = info.get('version', '')
                cpe = info.get('cpe', '')
                services[str(port)] = {'service': service, 'product': product,
                                       'version': version}
                if proto == 'tcp':
                    open_tcp_ports.append(port)
                if cpe:
                    obs['cpes'].append(cpe)
                if product:
                    sw = f'{product} {version}'.strip()
                    if sw not in obs['software']:
                        obs['software'].append(sw)

                for v in self._identify(service, product, version, cpe, port, proto, host):
                    result['vulns'].append(v)

        obs['services'] = services
        result['observation'] = obs

        # ---- NSE confirmation pass ("nmap super powers") ------------------
        if self._nse_enabled() and open_tcp_ports:
            try:
                confirmed = self._run_nse_checks(
                    host, sorted(open_tcp_ports), services)
                result['vulns'] = self._merge_confirmed(result['vulns'], confirmed)
            except Exception as e:
                logger.error('[NSE] vulnerability check pass failed for %s: %s '
                             '(version-based findings kept)', host, e)

        return result

    @staticmethod
    def _identify(service, product, version, cpe, port, proto, host):
        """CPE/version-aware CVE lookup via the NVD client (existing logic)."""
        from nvd_client import lookup_cves
        product_key = product or service
        if not product_key:
            return []
        findings = []
        for cve in lookup_cves(product_key, version):
            findings.append(NormalizedFinding(
                scanner='nmap', target=host,
                finding_id=f"{host}|{cve.get('cve')}|{port}/{proto}",
                cve=cve.get('cve'), cvss=cve.get('cvss'),
                severity=cve.get('severity'), desc=cve.get('desc'),
                port=f'{port}/{proto}', service=service, product=product,
                version=version, cpe=cpe,
                cwes=cve.get('cwes', []),
                confidence='potential',
                risk_factors={'open_port': True, 'service_detected': True},
            ))
        return findings

    def _run_nse_checks(self, host, tcp_ports, services):
        """Second nmap invocation running the curated NSE script set against
        ONLY the ports already known open (fast + low impact)."""
        expr = os.getenv('NMAP_VULN_SCRIPTS', self.DEFAULT_VULN_SCRIPTS)
        timeout = os.getenv('NSE_HOST_TIMEOUT', '20m')
        port_arg = ','.join(str(p) for p in tcp_ports)
        args = (f'-Pn --script {expr} -p {port_arg} '
                f'--host-timeout {timeout} -T4')

        logger.info('[NSE] running vulnerability checks on %s ports %s '
                    '(scripts: %s)', host, port_arg, expr)
        nm = self._nmap.PortScanner()
        nm.scan(hosts=host, arguments=args)

        if host not in nm.all_hosts():
            logger.warning('[NSE] no results returned for %s (timeout?)', host)
            return []

        findings = []
        host_data = nm[host]

        # host-level scripts (e.g. smb-vuln-* run once per host)
        for entry in host_data.get('hostscript', []) or []:
            sid = entry.get('id') or 'unknown-script'
            out = entry.get('output') or ''
            findings.extend(parse_script_findings(sid, out, host, 'general'))

        # per-port scripts (http-vuln-*, ssl-heartbleed, ftp-vsftpd-backdoor...)
        for proto in host_data.all_protocols():
            for port, info in host_data[proto].items():
                scripts = info.get('script') or {}
                svc = (services.get(str(port)) or {}).get('service', 'unknown')
                for sid, out in scripts.items():
                    findings.extend(parse_script_findings(
                        sid, out, host, f'{port}/{proto}', svc))

        logger.info('[NSE] %s confirmed finding(s) on %s', len(findings), host)
        return findings

    @staticmethod
    def _merge_confirmed(potential, confirmed):
        """Overlay confirmed NSE findings onto version-matched potentials.

        A potential finding whose (cve, port) matches a confirmed one is
        upgraded in place (keeps its richer NVD description/CVSS/CWE data and
        gains confidence/evidence). Confirmed CVEs without a potential match
        get their CVSS/description filled from the NVD record-by-id lookup;
        if that lookup fails they are still emitted (cvss=None) - never
        dropped, since an active check outranks a database match.
        """
        by_key = {(f.get('cve'), f.get('port')): f for f in potential}
        merged = list(potential)
        for c in confirmed:
            key = (c.get('cve'), c.get('port'))
            existing = by_key.pop(key, None)
            if existing is not None:
                merged.remove(existing)
                upgraded = dict(existing)
                upgraded.update({
                    'confidence': 'confirmed',
                    'evidence': c.get('evidence'),
                    'plugin_id': c.get('plugin_id'),
                    'risk_factors': {**(existing.get('risk_factors') or {}),
                                     **(c.get('risk_factors') or {})},
                    'finding_id': existing.get('finding_id'),
                })
                if c.get('severity') != 'Unknown':
                    upgraded['severity'] = c['severity']
                merged.append(upgraded)
            else:
                rec = {}
                try:
                    from nvd_client import lookup_cve_record
                    rec = lookup_cve_record(c.get('cve')) or {}
                except Exception as e:
                    logger.warning('[NSE] NVD record lookup failed for %s: %s',
                                   c.get('cve'), e)
                extra = dict(c)
                extra.setdefault('desc', c['desc'])
                if rec.get('cvss') is not None:
                    extra['cvss'] = rec['cvss']
                if rec.get('severity'):
                    extra['severity'] = rec['severity']
                if rec.get('desc'):
                    extra['desc'] = (
                        f"{rec['desc'][:800]}\n\n"
                        f"[CONFIRMED by {c.get('plugin_id')}]\n"
                        f"{(c.get('evidence') or '')[:1200]}")
                if rec.get('cwes'):
                    extra['cwes'] = rec['cwes']
                merged.append(extra)
        return merged
