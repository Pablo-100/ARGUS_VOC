import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanners.nmap_adapter import NmapAdapter, parse_script_findings  # noqa: E402

MS17_OUTPUT = """
VULNERABLE:
Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
  State: VULNERABLE
  IDs:  CVE:CVE-2017-0143
  Risk factor: HIGH
  A critical remote code execution vulnerability exists.
"""

HEARTBLEED_OUTPUT = """
VULNERABLE:
The TLS service allows client to initiate renegotiation (CVE-2009-3555)
Example: CVE-2014-0160 (heartbleed) also detected.
"""

SAFE_OUTPUT = "  State: likely VULNERABLE checks ran clean, nothing found"
NO_CVE_OUTPUT = "VULNERABLE:\nSome issue without any identifier."


class TestNSEParser(unittest.TestCase):
    def test_vulnerable_block_parsed(self):
        out = parse_script_findings('smb-vuln-ms17-010', MS17_OUTPUT,
                                    '10.0.0.9', 'general')
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f['cve'], 'CVE-2017-0143')
        self.assertEqual(f['confidence'], 'confirmed')
        self.assertEqual(f['severity'], 'High')
        self.assertEqual(f['plugin_id'], 'NSE-smb-vuln-ms17-010')
        self.assertIn('VULNERABLE', f['evidence'])

    def test_multiple_cves_in_one_block(self):
        out = parse_script_findings('ssl-heartbleed', HEARTBLEED_OUTPUT,
                                    '10.0.0.9', '443/tcp', 'https')
        cves = {f['cve'] for f in out}
        self.assertEqual(cves, {'CVE-2009-3555', 'CVE-2014-0160'})
        for f in out:
            self.assertEqual(f['port'], '443/tcp')
            self.assertEqual(f['confidence'], 'confirmed')

    def test_clean_output_yields_nothing(self):
        # 'likely VULNERABLE' contains the marker... guard against false parse:
        out = parse_script_findings('x', SAFE_OUTPUT, '10.0.0.9', '22/tcp')
        # the marker IS present -> parsed; but no CVE ids -> empty result set
        self.assertEqual(out, [])

    def test_no_cve_ids_rejected(self):
        self.assertEqual(parse_script_findings(
            'x', NO_CVE_OUTPUT, '10.0.0.9', '22/tcp'), [])

    def test_empty_output(self):
        self.assertEqual(parse_script_findings('x', '', 'h', 'p'), [])


class TestMergeConfirmed(unittest.TestCase):
    def _pot(self, cve, port='445/tcp'):
        return {'cve': cve, 'port': port, 'confidence': 'potential',
                'cvss': 8.1, 'severity': 'High',
                'desc': 'NVD description here', 'cwes': ['CWE-20'],
                'finding_id': f'h|{cve}|{port}'}

    def test_upgrade_in_place_keeps_nvd_data(self):
        pot = [self._pot('CVE-2017-0143')]
        conf = [{'cve': 'CVE-2017-0143', 'port': '445/tcp',
                 'confidence': 'confirmed', 'severity': 'High',
                 'evidence': 'VULNERABLE block', 'plugin_id': 'NSE-smb-vuln-ms17-010',
                 'risk_factors': {'nse_check': True}}]
        merged = NmapAdapter._merge_confirmed(pot, conf)
        self.assertEqual(len(merged), 1)
        m = merged[0]
        self.assertEqual(m['confidence'], 'confirmed')
        self.assertEqual(m['cvss'], 8.1)          # kept from version match
        self.assertEqual(m['desc'], 'NVD description here')
        self.assertEqual(m['evidence'], 'VULNERABLE block')

    def test_confirmed_without_potential_appended(self):
        from unittest import mock
        with mock.patch('nvd_client.lookup_cve_record',
                        return_value={'cvss': 9.8, 'severity': 'Critical',
                                      'desc': 'NVD text', 'cwes': ['CWE-502']}):
            merged = NmapAdapter._merge_confirmed([], [
                {'cve': 'CVE-2021-9999', 'port': '80/tcp', 'confidence': 'confirmed',
                 'severity': 'Unknown', 'desc': '[NSE:x] confirmed', 'plugin_id':
                 'NSE-x', 'evidence': 'ev', 'risk_factors': {}}])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]['confidence'], 'confirmed')
        self.assertEqual(merged[0]['cvss'], 9.8)   # filled from NVD record
        self.assertIn('NVD text', merged[0]['desc'])

    def test_potential_without_confirmation_stays_potential(self):
        pot = [self._pot('CVE-2000-0001')]
        merged = NmapAdapter._merge_confirmed(pot, [])
        self.assertEqual(merged[0]['confidence'], 'potential')


class TestSafetyDefaults(unittest.TestCase):
    def test_default_expression_excludes_dangerous_categories(self):
        expr = os.getenv('NMAP_VULN_SCRIPTS', NmapAdapter.DEFAULT_VULN_SCRIPTS)
        low = expr.lower()
        self.assertIn('not', low)
        for bad in ('dos', 'intrusive'):
            self.assertIn(bad, low)

    def test_nse_enabled_by_default(self):
        self.assertTrue(NmapAdapter._nse_enabled())


if __name__ == '__main__':
    unittest.main()
