"""Base classes for the scanner abstraction layer."""
import abc
import logging

logger = logging.getLogger(__name__)

# Registry of adapter classes keyed by a short scanner name ('nmap',
# 'openvas', ...). Adapters self-register on import via @register_scanner.
_REGISTRY = {}

# Scanner names the enrichment pipeline accepts. Anything outside this set is
# treated as an untrusted out-of-band payload and rejected by tasks.enrich().
KNOWN_SCANNERS = {'nmap'}


def register_scanner(name):
    def _wrap(cls):
        _REGISTRY[name] = cls
        KNOWN_SCANNERS.add(name)
        return cls
    return _wrap


class NormalizedFinding(dict):
    """One vulnerability observation, normalized across scanners.

    Required keys: cve (may be ''), severity, port, service, evidence,
    scanner. Optional keys carry whatever the scanner knows; downstream
    enrichment fills in the rest (EPSS/KEV/CWE/remediation/risk).
    """

    def __init__(self, *, scanner, target, finding_id='', cve='', cvss=None,
                 severity='Unknown', desc='', port='', service='', product='',
                 version='', cpe='', plugin_id='', solution='', evidence='',
                 **extra):
        super().__init__(
            scanner=scanner, target=target, finding_id=finding_id, cve=cve,
            cvss=cvss, severity=severity, desc=desc, port=port,
            service=service, product=product, version=version, cpe=cpe,
            plugin_id=plugin_id, solution=solution, evidence=evidence, **extra)


class HostObservation(dict):
    """What one host looked like during a scan (feeds the asset inventory)."""

    def __init__(self, *, ip=None, mac=None, hostname=None, os_name=None,
                 services=None, cpes=None, software=None):
        super().__init__(ip=ip, mac=mac, hostname=hostname, os_name=os_name,
                         services=services or {}, cpes=cpes or [],
                         software=software or [])


class ScannerAdapter(abc.ABC):
    """Common interface every scanner must implement."""

    name = 'abstract'

    @classmethod
    def get(cls, name):
        adapter_cls = _REGISTRY.get(name)
        if not adapter_cls:
            raise KeyError(f'no scanner adapter named {name!r} '
                           f'(available: {sorted(k for k in _REGISTRY)})')
        return adapter_cls()

    @abc.abstractmethod
    def available(self):
        """True when this adapter is configured and can run in this deployment."""

    @abc.abstractmethod
    def scan_host(self, host):
        """Run a scan against one host.

        Returns dict(host=<ip>, os=<str|None>, services=<dict>,
        mac=<str|None>, hostname=<str|None>, cpes=[...], findings=[
        NormalizedFinding...], scan_type=<self.name>, scan_date=<iso>,
        error=<str|None>).
        """

    def describe(self):
        cfg = self.config_summary() if hasattr(self, 'config_summary') else {}
        return {'scanner': self.name, 'available': self.available(), **cfg}
