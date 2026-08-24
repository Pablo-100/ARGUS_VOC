import sys
import os
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import threat_intel as ti  # noqa: E402


class TestOSVHelpers(unittest.TestCase):
    def test_exploit_detection_poc_url(self):
        self.assertTrue(ti._osv_references_indicate_exploit(
            ['https://github.com/org/repo/tree/main/poc']))

    def test_exploit_detection_exploitdb(self):
        self.assertTrue(ti._osv_references_indicate_exploit(
            ['https://www.exploit-db.com/exploits/12345']))

    def test_exploit_detection_metasploit(self):
        self.assertTrue(ti._osv_references_indicate_exploit(
            ['https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/x.rb']))

    def test_exploit_detection_benign(self):
        self.assertFalse(ti._osv_references_indicate_exploit(
            ['https://access.redhat.com/security/cve/CVE-2020-0001', 'https://nvd.nist.gov/vuln/detail/CVE-2020-0001']))

    def test_osv_severity(self):
        data = {'severity': [{'type': 'CVSS_V3', 'score': '9.8'}]}
        self.assertEqual(ti._extract_osv_severity(data)[0]['score'], '9.8')


class TestAggregator(unittest.TestCase):
    @mock.patch.object(ti, 'get_epss', return_value={'epss_score': 0.9, 'epss_percentile': 0.9})
    @mock.patch.object(ti, 'get_kev_entry', return_value={'kev_name': 'X'})
    @mock.patch.object(ti, 'get_osv', return_value={'osv_has_exploit': True, 'osv_references': []})
    @mock.patch.object(ti, 'search_exploitdb', return_value=[])
    @mock.patch.object(ti, 'get_virustotal', return_value=None)
    def test_enrich_aggregates(self, *mocks):
        res = ti.enrich_threat_intel('CVE-2020-0004')
        self.assertTrue(res['in_kev'])
        self.assertTrue(res['exploit_available'])
        self.assertEqual(res['epss_score'], 0.9)
        self.assertIn('kev', res)

    @mock.patch.object(ti, 'get_epss', return_value=None)
    @mock.patch.object(ti, 'get_kev_entry', return_value=None)
    @mock.patch.object(ti, 'get_osv', return_value=None)
    @mock.patch.object(ti, 'search_exploitdb', return_value=[])
    @mock.patch.object(ti, 'get_virustotal', return_value=None)
    def test_enrich_no_sources(self, *mocks):
        res = ti.enrich_threat_intel('CVE-2020-0005')
        self.assertFalse(res['in_kev'])
        self.assertFalse(res['exploit_available'])
        self.assertNotIn('epss_score', res)


if __name__ == '__main__':
    unittest.main()
