import sys
import os
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import ticket_enrichment as te  # noqa: E402


class TestClassification(unittest.TestCase):
    def test_classify_sqli(self):
        t, owasp, cwes = te.classify_vulnerability(['CWE-89'])
        self.assertEqual(t, 'SQL Injection')
        self.assertIn('A03', owasp)

    def test_classify_xss(self):
        t, owasp, cwes = te.classify_vulnerability(['CWE-79'])
        self.assertEqual(t, 'XSS')

    def test_classify_dos(self):
        t, _, _ = te.classify_vulnerability(['CWE-400'])
        self.assertEqual(t, 'DoS')

    def test_classify_default_no_cwe(self):
        t, _, _ = te.classify_vulnerability([])
        self.assertEqual(t, 'Security Vulnerability')

    def test_classify_matches_first(self):
        t, _, _ = te.classify_vulnerability(['CWE-78', 'CWE-79'])
        self.assertEqual(t, 'RCE')


class TestAttackMapping(unittest.TestCase):
    def test_mapping_sqli(self):
        techniques, tactics = te.get_attack_mapping(['CWE-89'])
        ids = [t['id'] for t in techniques]
        self.assertIn('T1190', ids)
        self.assertIn('Initial Access', tactics)

    def test_mapping_default(self):
        techniques, tactics = te.get_attack_mapping(['CWE-99999'])
        self.assertTrue(techniques)
        self.assertTrue(all(t['id'] for t in techniques))


class TestRemediationAndCis(unittest.TestCase):
    def test_remediation_sqli(self):
        rem, val = te.get_remediation(['CWE-89'])
        self.assertTrue(rem)
        self.assertTrue(any('parameterized' in r.lower() for r in rem))

    def test_remediation_default(self):
        rem, val = te.get_remediation(['CWE-99999'])
        self.assertTrue(rem)

    def test_cis_nginx(self):
        b, sec, h = te.get_cis_recommendations('nginx', '')
        self.assertIn('NGINX', b)
        self.assertTrue(h)

    def test_cis_default(self):
        b, sec, h = te.get_cis_recommendations('unknown-service', '')
        self.assertTrue(h)


class TestChecklist(unittest.TestCase):
    def test_build_checklist(self):
        vuln = {'cve': 'CVE-2020-0001', 'host': '10.0.0.1', 'cwes': ['CWE-89'],
                'service': 'nginx', 'product': '', 'risk_score': 9.0}
        items = te.build_checklist(vuln, '10.0.0.1')
        self.assertTrue(items)
        cats = {i['category'] for i in items}
        self.assertIn('Validation', cats)
        self.assertIn('Remediation', cats)
        self.assertIn('Verification', cats)
        for it in items:
            self.assertIn('done', it)


class TestDescription(unittest.TestCase):
    def test_build_description(self):
        vuln = {'cve': 'CVE-2020-0002', 'cvss': 7.5, 'risk_score': 8.5, 'severity': 'High',
                'desc': 'Test desc', 'port': '80/tcp', 'service': 'http', 'product': 'nginx',
                'version': '1.0', 'cwes': ['CWE-79'], 'vuln_type': 'XSS',
                'owasp_category': 'A03', 'epss_score': 0.9, 'epss_percentile': 0.95,
                'in_kev': True, 'exploit_available': True, 'exploitdb': [{'id': '1', 'exploitdb_url': 'http://x'}],
                'osv': {'osv_references': ['https://github.com/x/poc']},
                'kev': {'kev_name': 'X', 'kev_date_added': '2020-01-01', 'kev_required_action': 'A',
                        'kev_due_date': '2020-02-01', 'kev_ransomware': False}}
        techniques, tactics = te.get_attack_mapping(['CWE-79'])
        desc = te.build_technical_description(vuln, '10.0.0.1', techniques, tactics)
        self.assertIn('CVE-2020-0002', desc)
        self.assertIn('MITRE ATT&CK', desc)
        self.assertIn('EPSS', desc)
        self.assertIn('CISA KEV', desc)
        self.assertIn('Recommended Remediation', desc)


class TestEnrichVulnerability(unittest.TestCase):
    @mock.patch('ticket_enrichment.enrich_threat_intel')
    def test_enrich_vuln(self, mock_ti):
        mock_ti.return_value = {
            'cve': 'CVE-2020-0003', 'epss_score': 0.75, 'epss_percentile': 0.8,
            'in_kev': False, 'exploit_available': False, 'osv': {}, 'exploitdb': [],
        }
        vuln = {'cve': 'CVE-2020-0003', 'cvss': 6.5, 'severity': 'Medium',
                'desc': 'x', 'port': '443/tcp', 'service': 'https', 'product': 'nginx',
                'version': '1.18', 'cwes': ['CWE-400'], 'risk_score': 7.0}
        out = te.enrich_vulnerability(vuln, '10.0.0.1')
        self.assertEqual(out['vuln_type'], 'DoS')
        self.assertIn('attack_techniques', out)
        self.assertIn('checklist', out)
        self.assertIn('remediation', out)
        self.assertEqual(out['epss_score'], 0.75)
        te.finalize_description(out, '10.0.0.1')
        self.assertIn('technical_description', out)
        self.assertIn('Recommended Remediation', out['technical_description'])


if __name__ == '__main__':
    unittest.main()
