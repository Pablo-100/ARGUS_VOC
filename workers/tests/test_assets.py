import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from assets import asset_identity, CRITICALITY_LABELS  # noqa: E402


class TestAssetIdentity(unittest.TestCase):
    def test_full_identity_preferred(self):
        aid1, kind = asset_identity(ip='10.0.0.5', mac='aa:bb:cc:dd:ee:ff', hostname='web01')
        self.assertEqual(kind, 'mac+ip+hostname')
        # stable across call order
        aid2, _ = asset_identity(hostname='web01', mac='AA:BB:CC:DD:EE:FF', ip='10.0.0.5')
        self.assertEqual(aid1, aid2)

    def test_fallback_ip_hostname(self):
        _, kind = asset_identity(ip='10.0.0.5', hostname='web01')
        self.assertEqual(kind, 'ip+hostname')

    def test_fallback_hostname_only(self):
        _, kind = asset_identity(hostname='printer-lab')
        self.assertEqual(kind, 'hostname')

    def test_fallback_ip_only(self):
        _, kind = asset_identity(ip='10.0.0.9')
        self.assertEqual(kind, 'ip')

    def test_no_identity(self):
        self.assertEqual(asset_identity(), (None, None))

    def test_mac_case_insensitive(self):
        a1, _ = asset_identity(mac='AA-BB', ip='1.2.3.4')
        a2, _ = asset_identity(mac='aa-bb', ip='1.2.3.4')
        self.assertEqual(a1, a2)

    def test_criticality_domain(self):
        self.assertEqual(sorted(CRITICALITY_LABELS), [1, 2, 3, 4, 5])


if __name__ == '__main__':
    unittest.main()
