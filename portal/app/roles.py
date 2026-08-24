"""Role-based access control for the VOC portal.

Roles model a real SOC staffing pyramid and are now DYNAMIC: admins can
create custom roles at runtime (Feature: "admin creates roles and grants
them CRUD privileges"). Built-in roles are seeded into the `roles` table on
startup and stay immutable through the API so the platform can never be
locked out; custom roles are fully editable.

Authorization itself remains capability-based: every endpoint checks a cap
string via require_cap(). A user's effective caps = base caps of their role
(from DB, falling back to the static map) + per-user grants.
"""
import json

from .db import get_db

ALL_CAPS = [
    'dashboard.view',
    'tickets.view_all',
    'tickets.create',
    'tickets.edit',
    'tickets.delete',
    'tickets.assign',
    'tickets.reopen',
    'tickets.import',
    'tickets.verify_force',
    'assets.view',
    'assets.create',
    'assets.edit',
    'assets.delete',
    'users.manage',
    'roles.manage',
    'audit.view',
    'services.view',
    'attack.view',
    'misp.view',
    'misp.manage',
    'glpi.view',
    'glpi.manage',
    'infra.view',
    'infra.manage',
]

ROLE_CAPS = {
    'admin': list(ALL_CAPS),
    'voc': ['dashboard.view', 'tickets.view_all', 'tickets.create', 'tickets.edit',
            'tickets.assign', 'tickets.reopen', 'tickets.import', 'tickets.verify_force',
            'assets.view', 'assets.create', 'assets.edit', 'services.view',
            'attack.view', 'misp.view', 'misp.manage', 'glpi.view', 'glpi.manage',
            'infra.view'],
    'soc3': ['dashboard.view', 'tickets.view_all', 'tickets.edit', 'tickets.assign',
             'tickets.reopen', 'tickets.verify_force', 'assets.view', 'services.view',
             'attack.view', 'misp.view', 'glpi.view', 'glpi.manage', 'infra.view'],
    'soc2': ['dashboard.view', 'tickets.view_all', 'tickets.assign', 'tickets.reopen',
             'assets.view', 'attack.view'],
    'soc1': ['dashboard.view', 'assets.view', 'attack.view'],
    'noc': ['dashboard.view', 'tickets.view_all', 'tickets.reopen', 'services.view',
            'assets.view', 'attack.view', 'infra.view'],
}

ROLE_LABELS = {
    'admin': 'Admin',
    'voc': 'VOC Ops',
    'soc3': 'SOC L3 · Senior',
    'soc2': 'SOC L2',
    'soc1': 'SOC L1 · Junior',
    'noc': 'NOC',
}

ROLE_ORDER = ['admin', 'voc', 'soc3', 'soc2', 'soc1', 'noc']

# legacy roles -> new roles (migrated on startup)
LEGACY_ROLES = {'soc': 'soc2', 'user': 'soc1'}

IMPLICIT_CAPS = ['tickets.view_mine', 'account.manage']

CAP_GROUPS = [
    ('Visibility & Dashboards', ['dashboard.view', 'attack.view', 'audit.view']),
    ('Tickets', ['tickets.view_all', 'tickets.create', 'tickets.edit',
                 'tickets.delete', 'tickets.assign', 'tickets.reopen',
                 'tickets.import', 'tickets.verify_force']),
    ('Assets', ['assets.view', 'assets.create', 'assets.edit', 'assets.delete']),
    ('Users & Roles', ['users.manage', 'roles.manage']),
    ('Threat Intel (MISP)', ['misp.view', 'misp.manage']),
    ('ITSM (GLPI)', ['glpi.view', 'glpi.manage']),
    ('Infrastructure', ['infra.view', 'infra.manage', 'services.view']),
]

CAP_META = {
    'dashboard.view': ('View dashboard', 'KPIs, charts, live trends'),
    'tickets.view_all': ('View all tickets', 'Full queue, any assignee'),
    'tickets.create': ('Create tickets', 'Manually open a ticket'),
    'tickets.edit': ('Edit tickets', 'Update details of any ticket'),
    'tickets.delete': ('Delete tickets', 'Permanently remove tickets'),
    'tickets.assign': ('Assign tickets', 'Route work to analysts'),
    'tickets.reopen': ('Reopen tickets', 'Revive solved tickets'),
    'tickets.import': ('Sync scanner feed', 'Import auto-tickets from the pipeline'),
    'tickets.verify_force': ('Override closure', 'Close without scanner verification (audited)'),
    'assets.view': ('View asset inventory', 'Assets, criticality, exposure'),
    'assets.create': ('Create assets', 'Register assets manually'),
    'assets.edit': ('Edit asset metadata', 'Criticality, owner, environment'),
    'assets.delete': ('Delete assets', 'Remove assets from inventory'),
    'users.manage': ('Manage users & access', 'Accounts, passwords, provisioning'),
    'roles.manage': ('Manage roles', 'Create roles, edit permission matrix'),
    'audit.view': ('View audit trail', 'Security-relevant event history'),
    'services.view': ('Access platform services', 'Tools hub & service links'),
    'attack.view': ('MITRE ATT&CK mapping', 'Technique heatmap & drill-down'),
    'misp.view': ('View threat intel', 'Browse MISP events & IOCs'),
    'misp.manage': ('Manage threat intel', 'Create, publish, delete MISP events'),
    'glpi.view': ('View GLPI tickets', 'Live ticket status & history'),
    'glpi.manage': ('Manage GLPI tickets', 'Status changes, follow-ups, assignment'),
    'infra.view': ('View infrastructure health', 'RabbitMQ queues & ES cluster/indices'),
    'infra.manage': ('Manage infrastructure', 'Purge queues, delete indices'),
}


def migrate_roles(conn):
    for old, new in LEGACY_ROLES.items():
        conn.execute('UPDATE users SET role=? WHERE role=?', (new, old))


def ensure_builtin_roles(conn):
    """Seed/refresh the built-in roles into the DB (idempotent). Custom roles
    created by admins are never touched."""
    for name in ROLE_ORDER:
        conn.execute(
            'INSERT INTO roles (name, label, builtin, caps) VALUES (?,? ,1,?) '
            'ON CONFLICT(name) DO UPDATE SET label=excluded.label, '
            'caps=excluded.caps, builtin=1',
            (name, ROLE_LABELS[name], json.dumps(ROLE_CAPS[name])))


def list_roles_db():
    """All roles from DB: [{name,label,builtin,caps:[...],users:N}]"""
    with get_db() as conn:
        ensure_builtin_roles(conn)
        rows = conn.execute(
            'SELECT r.id, r.name, r.label, r.builtin, r.caps, '
            '(SELECT COUNT(*) FROM users u WHERE u.role = r.name) AS users '
            'FROM roles r ORDER BY r.builtin DESC, r.id').fetchall()
    return [{'id': r['id'], 'name': r['name'], 'label': r['label'],
             'builtin': bool(r['builtin']),
             'caps': json.loads(r['caps'] or '[]'), 'users': r['users']}
            for r in rows]


def get_role_row(role_name):
    with get_db() as conn:
        return conn.execute('SELECT * FROM roles WHERE name=?',
                            (role_name,)).fetchone()


def valid_role(role):
    if role in ROLE_CAPS:
        return True
    return get_role_row(role) is not None


def role_label(role):
    row = get_role_row(role) if role else None
    if row:
        return row['label']
    return ROLE_LABELS.get(role, role or '?')


def base_caps(role):
    """Caps of a role: DB first (custom roles), static fallback."""
    row = get_role_row(role)
    if row:
        try:
            caps = json.loads(row['caps'] or '[]')
            if isinstance(caps, list):
                return [c for c in caps if c in ALL_CAPS]
        except ValueError:
            pass
    return list(ROLE_CAPS.get(role, []))


def grants_for(user):
    try:
        grants = json.loads(user.get('grants') or '[]')
        return [g for g in grants if g in ALL_CAPS] if isinstance(grants, list) else []
    except (ValueError, TypeError):
        return []


def effective_caps(user):
    caps = set(base_caps(user.get('role')))
    caps.update(grants_for(user))
    return sorted(caps)


def has_cap(user, cap):
    return cap in effective_caps(user)


def privileges(user):
    """Human-readable privilege list for the My Account page."""
    caps = effective_caps(user)
    meta = CAP_META
    out = []
    for cap in sorted(caps):
        if cap in meta:
            out.append({'cap': cap, 'permission': meta[cap][0], 'scope': meta[cap][1]})
    out.append({'cap': 'tickets.view_mine', 'permission': meta.get(
        'tickets.view_mine', ('Work own tickets', ''))[0],
        'scope': 'Start / solve assigned work'})
    out.append({'cap': 'account.manage', 'permission': 'Manage own account',
                'scope': 'Profile & password self-service'})
    return out
