"""SQLite persistence for the VOC portal (users, tickets)."""
import os
import sqlite3

DB_PATH = os.getenv('PORTAL_DB', '/data/portal.db')

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'user',
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tickets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT NOT NULL,
    description   TEXT DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'medium',
    source        TEXT NOT NULL DEFAULT 'admin',
    status        TEXT NOT NULL DEFAULT 'open',
    cve           TEXT,
    host          TEXT,
    port          TEXT,
    cvss          REAL,
    risk_score    REAL,
    est_hours     REAL,
    dedup_key     TEXT UNIQUE,
    created_at    TEXT DEFAULT (datetime('now')),
    assigned_to   INTEGER REFERENCES users(id),
    assigned_at   TEXT,
    solved_at     TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    action     TEXT,
    detail     TEXT,
    at         TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS techniques (
    id       TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    tactic   TEXT NOT NULL,
    url      TEXT
);

CREATE TABLE IF NOT EXISTS cve_techniques (
    cve          TEXT PRIMARY KEY,
    technique_id TEXT NOT NULL REFERENCES techniques(id)
);

CREATE TABLE IF NOT EXISTS roles (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT UNIQUE NOT NULL,
    label    TEXT NOT NULL,
    builtin  INTEGER NOT NULL DEFAULT 0,
    caps     TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_tickets_status   ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_assigned ON tickets(assigned_to);
"""


def _migrate(conn):
    # --- tickets: vulnerability lifecycle / SLA / verification columns ---
    cols = {r['name'] for r in conn.execute('PRAGMA table_info(tickets)')}
    adds = {
        'port': "ALTER TABLE tickets ADD COLUMN port TEXT",
        'technique_id': "ALTER TABLE tickets ADD COLUMN technique_id TEXT REFERENCES techniques(id)",
        'sla_deadline': "ALTER TABLE tickets ADD COLUMN sla_deadline TEXT",
        'sla_status': "ALTER TABLE tickets ADD COLUMN sla_status TEXT DEFAULT 'on_track'",
        'assignment_reason': "ALTER TABLE tickets ADD COLUMN assignment_reason TEXT",
        'resolved_by': "ALTER TABLE tickets ADD COLUMN resolved_by TEXT DEFAULT ''",
        'remediated_at': "ALTER TABLE tickets ADD COLUMN remediated_at TEXT",
        'verification_state': "ALTER TABLE tickets ADD COLUMN verification_state TEXT DEFAULT ''",
        'verification_scan_id': "ALTER TABLE tickets ADD COLUMN verification_scan_id TEXT",
        'verification_at': "ALTER TABLE tickets ADD COLUMN verification_at TEXT",
        'reopened_count': "ALTER TABLE tickets ADD COLUMN reopened_count INTEGER DEFAULT 0",
        'glpi_ticket_id': "ALTER TABLE tickets ADD COLUMN glpi_ticket_id INTEGER",
        'finding_key': "ALTER TABLE tickets ADD COLUMN finding_key TEXT",
    }
    for col, ddl in adds.items():
        if col not in cols and ddl:
            conn.execute(ddl)
    conn.execute('CREATE INDEX IF NOT EXISTS idx_tickets_sla ON tickets(sla_status)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_tickets_technique ON tickets(technique_id)')

    # --- audit: full security trail columns (immutable append-only log) ---
    acols = {r['name'] for r in conn.execute('PRAGMA table_info(audit)')}
    for col, ddl in {
        'ip': "ALTER TABLE audit ADD COLUMN ip TEXT DEFAULT ''",
        'resource': "ALTER TABLE audit ADD COLUMN resource TEXT DEFAULT ''",
        'resource_id': "ALTER TABLE audit ADD COLUMN resource_id TEXT DEFAULT ''",
        'old_value': "ALTER TABLE audit ADD COLUMN old_value TEXT",
        'new_value': "ALTER TABLE audit ADD COLUMN new_value TEXT",
        'result': "ALTER TABLE audit ADD COLUMN result TEXT DEFAULT 'success'",
    }.items():
        if col not in acols:
            conn.execute(ddl)
    conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at)')

    ucols = {r['name'] for r in conn.execute('PRAGMA table_info(users)')}
    if 'grants' not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN grants TEXT DEFAULT '[]'")
    if 'platform_pass' not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN platform_pass TEXT DEFAULT ''")
    if 'provision' not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN provision TEXT DEFAULT '{}'")


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)