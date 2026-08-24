import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from notifications import (EVENT_TEMPLATES, LogProvider, deliver_request,  # noqa: E402
                           notify_critical_vulnerability)


class TestCriticalGating(unittest.TestCase):
    def test_critical_severity_notifies(self):
        v = {'cve': 'CVE-2024-1', 'severity': 'Critical', 'risk_score': 9.6,
             'cvss': 9.8, 'epss_score': 0.9, 'in_kev': True,
             'asset_context': {'criticality': 5, 'internet_exposed': True}}
        with mock_providers():
            sent = notify_critical_vulnerability(v, '10.0.0.5', scan_id='scan_1')
        self.assertTrue(sent)

    def test_low_risk_ignored(self):
        v = {'cve': 'CVE-2024-2', 'severity': 'Low', 'risk_score': 3.1}
        self.assertFalse(notify_critical_vulnerability(v, '10.0.0.5'))

    def test_high_but_below_threshold_no_notify(self):
        v = {'cve': 'CVE-2024-3', 'severity': 'High', 'risk_score': 8.0}
        self.assertFalse(notify_critical_vulnerability(v, '10.0.0.5'))


class TestTemplates(unittest.TestCase):
    def test_all_events_render(self):
        base = {'ticket_id': 7, 'title': 'T', 'severity': 'critical',
                'assignee': 'analyst1', 'reason': 'r', 'sla_deadline': '2026-01-01',
                'host': 'h', 'cve': 'CVE-1', 'detail': 'd', 'overdue_hours': 2.0}
        for event in EVENT_TEMPLATES:
            body = EVENT_TEMPLATES[event]['fmt'].format(**dict(base))
            self.assertIn('#7', body)

    def test_deliver_request_unknown_event(self):
        self.assertFalse(deliver_request({'event': 'nope', 'payload': {}}))

    def test_deliver_request_sla_overdue(self):
        ok = deliver_request({'event': 'sla_overdue', 'payload': {
            'ticket_id': 3, 'title': 'X', 'severity': 'high', 'host': 'h',
            'cve': 'CVE-2', 'sla_deadline': '2026-01-01', 'assignee': 'a',
            'overdue_hours': 5.5}})
        self.assertTrue(ok)


class _RecordingProvider(LogProvider):
    sent = []

    def send(self, subject, body):
        type(self).sent.append((subject, body))
        return True


def mock_providers():
    import notifications
    holder = {}

    class Ctx:
        def __enter__(self):
            holder['old'] = notifications._PROVIDERS
            notifications._PROVIDERS = [_RecordingProvider()]
            return None

        def __exit__(self, *exc):
            notifications._PROVIDERS = holder['old']
    return Ctx()


if __name__ == '__main__':
    unittest.main()
