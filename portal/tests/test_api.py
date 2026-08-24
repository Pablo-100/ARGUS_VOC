"""API + authorization tests (Feature 22).

Run inside the portal container:
    docker compose exec portal python -m unittest discover -s /app/tests
"""
import os
import sys
import unittest

sys.path.insert(0, '/app')

os.environ['PORTAL_DB'] = '/tmp/voc_test_api.db'
if os.path.exists('/tmp/voc_test_api.db'):
    os.remove('/tmp/voc_test_api.db')

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.db import init_db, get_db  # noqa: E402

client = TestClient(app)


def _mkuser(username, role, active=1):
    from app.auth import hash_password
    with get_db() as conn:
        conn.execute(
            'INSERT INTO users (username, password_hash, platform_pass, role, active) '
            'VALUES (?,?,?,?,?)', (username, hash_password('passw0rd'), '', role, active))


def _login(username):
    r = client.post('/api/login', json={'username': username, 'password': 'passw0rd'})
    assert r.status_code == 200, r.text
    return {'Authorization': f'Bearer {r.json()["token"]}'}


class _Base(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        with get_db() as conn:
            if not conn.execute("SELECT 1 FROM users WHERE username='rootadmin'").fetchone():
                _mkuser('rootadmin', 'admin')
            for name, role in (('soc1u', 'soc1'), ('soc2u', 'soc2'), ('nocu', 'noc')):
                if not conn.execute('SELECT 1 FROM users WHERE username=?', (name,)).fetchone():
                    _mkuser(name, role)
        cls.admin = _login('rootadmin')
        cls.soc1 = _login('soc1u')
        cls.soc2 = _login('soc2u')


    def _ticket(self, **kw):
        body = {'title': kw.get('title', 'T'), 'severity': kw.get('severity', 'high')}
        return client.post('/api/tickets', headers=self.admin, json=body).json()['id']

class TestAuth(_Base):
    def test_login_rejects_bad_password(self):
        r = client.post('/api/login', json={'username': 'rootadmin', 'password': 'wrong'})
        self.assertEqual(r.status_code, 401)

    def test_me_requires_token(self):
        self.assertEqual(client.get('/api/me').status_code, 401)

    def test_garbage_token_rejected(self):
        r = client.get('/api/me', headers={'Authorization': 'Bearer nope'})
        self.assertEqual(r.status_code, 401)

    def test_lockout_after_max_failures(self):
        import app.main as m
        m._login_failures.clear()
        m.LOGIN_MAX_ATTEMPTS = 3
        for _ in range(3):
            client.post('/api/login', json={'username': 'nocu', 'password': 'bad'})
        r = client.post('/api/login', json={'username': 'nocu', 'password': 'passw0rd'})
        self.assertEqual(r.status_code, 429)
        m.LOGIN_MAX_ATTEMPTS = 5


class TestRBACAndIDOR(_Base):
    """Server-side authorization must hold regardless of UI hiding."""

    def test_soc1_cannot_view_all_tickets(self):
        r = client.get('/api/tickets?scope=all', headers=self.soc1)
        self.assertEqual(r.status_code, 403)

    def test_soc1_cannot_create_users(self):
        r = client.post('/api/users', headers=self.soc1,
                        json={'username': 'h4x', 'password': 'passw0rd'})
        self.assertEqual(r.status_code, 403)

    def test_soc1_cannot_manage_infra(self):
        self.assertEqual(client.post('/api/infra/queues/x/purge', headers=self.soc1).status_code, 403)

    def test_audit_is_admin_only(self):
        self.assertEqual(client.get('/api/audit', headers=self.soc2).status_code, 403)
        ok = client.get('/api/audit', headers=self.admin)
        self.assertEqual(ok.status_code, 200)

    def test_user_cannot_edit_other_users(self):
        r = client.put('/api/users/999999', headers=self.soc2, json={'full_name': 'x'})
        self.assertEqual(r.status_code, 403)

    def test_assets_view_for_soc1_but_edit_denied(self):
        # list may fail on ES connectivity (502) but must never be 403 for viewers
        r = client.get('/api/assets', headers=self.soc1)
        self.assertIn(r.status_code, (200, 502))
        r2 = client.patch('/api/assets/nonexistent', headers=self.soc1,
                          json={'criticality': 5})
        self.assertEqual(r2.status_code, 403)


class TestTicketLifecycle(_Base):
    def test_create_sets_sla_deadline(self):
        tid = self._ticket(severity='critical')
        with get_db() as conn:
            t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
        self.assertIsNotNone(t['sla_deadline'])

    def test_solve_marks_remediated_not_solved(self):
        tid = self._ticket()
        # a non-assignee analyst must not be able to remediate (IDOR guard)
        r_forbidden = client.post(f'/api/tickets/{tid}/solve', headers=self.soc2)
        self.assertEqual(r_forbidden.status_code, 403)
        # assignee claims remediation -> verification pending, NOT solved
        client.post(f'/api/tickets/{tid}/assign', headers=self.admin,
                    json={'user_id': 1})
        r = client.post(f'/api/tickets/{tid}/solve', headers=self.admin)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json().get('state'), 'verification_pending')
        with get_db() as conn:
            t = conn.execute('SELECT * FROM tickets WHERE id=?', (tid,)).fetchone()
        self.assertEqual(t['status'], 'remediated')
        self.assertIsNone(t['solved_at'])
        self.assertEqual(t['verification_state'], 'requested')
        # double-solve is refused
        r2 = client.post(f'/api/tickets/{tid}/solve', headers=self.admin)
        self.assertEqual(r2.status_code, 400)

    def test_close_override_needs_cap_and_reason(self):
        tid = self._ticket()
        r = client.post(f'/api/tickets/{tid}/close', headers=self.soc2, json={'reason': 'x'})
        self.assertEqual(r.status_code, 403)   # soc2 lacks tickets.verify_force
        r2 = client.post(f'/api/tickets/{tid}/close', headers=self.admin, json={})
        self.assertEqual(r2.status_code, 400)  # admin needs a reason

    def test_invalid_severity_defaults_to_medium(self):
        tid = self._ticket(severity='apocalyptic')
        with get_db() as conn:
            t = conn.execute('SELECT severity FROM tickets WHERE id=?', (tid,)).fetchone()
        self.assertEqual(t['severity'], 'medium')

    def test_pagination_caps(self):
        r = client.get('/api/vulns?page=0&page_size=1000', headers=self.admin)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertLessEqual(data.get('page_size', 25), 100)


class TestAuditTrail(_Base):
    def test_failed_login_audited(self):
        client.post('/api/login', json={'username': 'ghost', 'password': 'x'})
        rows = client.get('/api/audit?action=login.failed&limit=10',
                          headers=self.admin).json()
        self.assertTrue(any(r['action'] == 'login.failed' for r in rows))

    def test_ticket_creation_audited(self):
        tid = self._ticket(title='audited-ticket')
        rows = client.get('/api/audit?action=ticket.create&limit=10',
                          headers=self.admin).json()
        self.assertTrue(any(str(tid) in str(r.get('resource_id', '')) for r in rows))


if __name__ == '__main__':
    unittest.main()
