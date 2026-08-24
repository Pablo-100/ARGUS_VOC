import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanners import ScannerAdapter, get_adapter, KNOWN_SCANNERS  # noqa: E402
from scanners.openvas_adapter import parse_gmp_results, OpenVASAdapter  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'openvas_get_results.xml')


class TestRegistry(unittest.TestCase):
    def test_nmap_registered(self):
        adapter = get_adapter('nmap')
        self.assertIsInstance(adapter, ScannerAdapter)
        self.assertEqual(adapter.name, 'nmap')

    def test_openvas_registered(self):
        adapter = get_adapter('openvas')
        self.assertEqual(adapter.name, 'openvas')

    def test_unknown_adapter_raises(self):
        with self.assertRaises(KeyError):
            get_adapter('nessus-does-not-exist')

    def test_known_scanners_guard(self):
        self.assertIn('nmap', KNOWN_SCANNERS)
        self.assertIn('openvas', KNOWN_SCANNERS)


class TestOpenVASParsing(unittest.TestCase):
    def setUp(self):
        with open(FIXTURE, 'rb') as f:
            self.xml = f.read()

    def test_parses_findings(self):
        findings, obs = parse_gmp_results(self.xml, '192.168.184.20')
        self.assertEqual(len(findings), 3)
        hosts = {f['target'] for f in findings}
        self.assertIn('192.168.184.20', hosts)
        self.assertIn('192.168.184.21', hosts)

    def test_cve_extraction(self):
        findings, _ = parse_gmp_results(self.xml, '192.168.184.20')
        cve_findings = [f for f in findings if f['cve']]
        self.assertTrue(any(f['cve'] == 'CVE-2021-41773' for f in cve_findings))

    def test_severity_mapping(self):
        findings, _ = parse_gmp_results(self.xml, '192.168.184.20')
        by_sev = {f['cve'] or f['plugin_id']: f['severity'] for f in findings}
        self.assertIn('High', by_sev.values())

    def test_solution_and_plugin_carried(self):
        findings, _ = parse_gmp_results(self.xml, '192.168.184.20')
        cve_f = next(f for f in findings if f['cve'] == 'CVE-2021-41773')
        self.assertTrue(cve_f['solution'])
        self.assertTrue(cve_f['plugin_id'])

    def test_services_collected(self):
        _, obs = parse_gmp_results(self.xml, '192.168.184.20')
        self.assertIn('80', obs['services'])

    def test_adapter_disabled_without_config(self):
        adapter = OpenVASAdapter()
        if not os.getenv('OPENVAS_HOST'):
            self.assertFalse(adapter.available())
            with self.assertRaises(RuntimeError):
                adapter.scan_host('127.0.0.1')


if __name__ == '__main__':
    unittest.main()
