import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.environ['PORTAL_DB'] = '/tmp/voc_test_sla.db'
if os.path.exists('/tmp/voc_test_sla.db'):
    os.remove('/tmp/voc_test_sla.db')

from app import sla  # noqa: E402
from app.db import init_db, get_db  # noqa: E402


class TestSLAComputation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def _insert(self, severity, created_at=None, solved=False):
        with get_db() as conn:
            cur = conn.execute(
                'INSERT INTO tickets (title, severity, status, created_at, sla_deadline) '
                'VALUES (?,?,?,?,?)',
                (f'T-{severity}', severity,
                 'solved' if solved else 'open',
                 created_at or datetime.now(timezone.utc).isoformat(timespec='seconds'),
                 sla.compute_deadline(severity, created_at)))
            return cur.lastrowid

    def test_default_budgets(self):
        self.assertEqual(sla.sla_hours('critical'), 24)
        self.assertEqual(sla.sla_hours('high'), 72)
        self.assertEqual(sla.sla_hours('medium'), 168)
        self.assertEqual(sla.sla_hours('low'), 720)

    def test_deadline_math(self):
        created = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        dl = sla.compute_deadline('critical', created.isoformat())
        self.assertEqual(dl, '2026-01-02T00:00:00+00:00')

    def test_status_on_track(self):
        future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        self.assertEqual(sla.status_for(future), 'ON_TRACK')

    def test_status_due_soon(self):
        soon = (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat()
        self.assertEqual(sla.status_for(soon), 'DUE_SOON')

    def test_status_overdue(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
        self.assertEqual(sla.status_for(past), 'OVERDUE')

    def test_sync_marks_overdue(self):
        past = (datetime.now(timezone.utc) - timedelta(days=3))
        tid = self._insert('high', past.isoformat())
        sla.sync_sla_states()
        with get_db() as conn:
            row = conn.execute('SELECT sla_status FROM tickets WHERE id=?', (tid,)).fetchone()
        self.assertEqual(row['sla_status'], 'overdue')

    def test_metrics_counts(self):
        m = sla.metrics()
        for key in ('sla_compliance_pct', 'overdue', 'due_within_24h',
                    'avg_remediation_hours', 'open_tickets'):
            self.assertIn(key, m)


if __name__ == '__main__':
    unittest.main()
