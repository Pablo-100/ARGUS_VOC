import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import importlib.util  # noqa: E402

_RISK_PATH = os.environ.get(
    'RISK_ENGINE_MAIN',
    os.path.join(os.path.dirname(__file__), '..', '..', 'risk-engine', 'main.py'))
try:
    spec = importlib.util.spec_from_file_location('risk_engine', _RISK_PATH)
    risk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(risk)
except (FileNotFoundError, ModuleNotFoundError, ImportError):
    # The risk-engine source is intentionally not shipped inside the worker
    # image. When executing inside voc-celery-worker, skip these tests rather
    # than fail the environment-specific suite. On the repo host (or when
    # RISK_ENGINE_MAIN points at a valid file) they run normally.
    risk = None

_TEST = os.environ.get('RISK_ENGINE_MAIN')


class TestRiskEngineBoosts(unittest.TestCase):
    """v2 backward compatibility - these scores MUST NOT change."""

    @classmethod
    def setUpClass(cls):
        if risk is None:
            raise unittest.SkipTest(
                f"risk-engine source not available at {_RISK_PATH}; skipping "
                "(run from the repo host or set RISK_ENGINE_MAIN)")

    def test_kev_boost(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=7.0, in_kev=True))
        self.assertEqual(out.risk_score, 9.0)
        self.assertIn('kev_boost', out.factors)

    def test_epss_boost_above_threshold(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=7.0, epss_score=0.6))
        self.assertEqual(out.risk_score, 8.0)
        self.assertIn('epss_boost', out.factors)

    def test_epss_boost_below_threshold(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=7.0, epss_score=0.3))
        self.assertEqual(out.risk_score, 7.0)
        self.assertNotIn('epss_boost', out.factors)

    def test_combined_caps_at_10(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=9.0, in_kev=True, epss_score=0.9,
                                                     exploit_available=True))
        self.assertEqual(out.risk_score, 10.0)
        self.assertEqual(out.severity, 'Critical')

    def test_backward_compatible_defaults(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=5.0))
        self.assertEqual(out.risk_score, 5.0)
        self.assertEqual(out.severity, 'Medium')


class TestContextualScoring(unittest.TestCase):
    """v3 asset-context features."""

    @classmethod
    def setUpClass(cls):
        if risk is None:
            raise unittest.SkipTest('risk-engine source not available')

    def test_breakdown_present_and_explained(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=7.5, in_kev=True))
        b = out.breakdown
        for key in ('base_score', 'threat_score', 'exploit_score',
                    'exposure_score', 'asset_score', 'final_risk_score'):
            self.assertIn(key, b)
        self.assertEqual(b['base_score'], 7.5)
        self.assertEqual(b['threat_score'], 2.0)
        self.assertTrue(out.risk_factors)

    def test_criticality_4_adds_quarter_cvss(self):
        plain = risk.compute_risk_score(risk.RiskInput(cvss_base=8.0))
        crit4 = risk.compute_risk_score(risk.RiskInput(cvss_base=8.0, asset_criticality=4))
        self.assertEqual(crit4.risk_score, min(plain.risk_score + 2.0, 10.0))

    def test_criticality_3_neutral(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=6.0, asset_criticality=3))
        self.assertEqual(out.risk_score, 6.0)

    def test_is_critical_asset_maps_to_half_cvss(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=6.0, is_critical_asset=True))
        self.assertEqual(out.risk_score, 9.0)

    def test_internet_exposed_floor(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=4.0, internet_exposed=True))
        # exposure floor of 1.5 replaces network_exposure*2 (0 by default)
        self.assertEqual(out.risk_score, 5.5)

    def test_production_boost(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=5.0, environment_production=True))
        self.assertEqual(out.risk_score, 5.5)

    def test_attack_path_relevance(self):
        out = risk.compute_risk_score(risk.RiskInput(cvss_base=5.0, attack_path_relevance=0.5))
        self.assertEqual(out.risk_score, 5.5)

    def test_full_contextual_example_caps_at_10(self):
        out = risk.compute_risk_score(risk.RiskInput(
            cvss_base=7.5, epss_score=0.7, in_kev=False, exploit_available=False,
            asset_criticality=5, internet_exposed=True, environment_production=True))
        self.assertEqual(out.risk_score, 10.0)
        self.assertEqual(out.severity, 'Critical')


if __name__ == '__main__':
    unittest.main()
