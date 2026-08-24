"""Cross-platform identity provisioning for the VOC platform.

When an admin creates or edits a user in the portal, the same identity is
pushed to every platform that has its own user store (Elasticsearch/Kibana,
RabbitMQ, GLPI, MISP). All accounts share one password, so analysts log in
once on the portal and can jump into every tool with the same credentials.
Basic-auth services (ES, Kibana, RabbitMQ) even open pre-authenticated via
credentials embedded in a single-sign-on URL.

The plaintext password is retained in `users.platform_pass` ONLY to rebuild
those SSO URLs - this is a lab compromise that must be replaced by a proper
IdP/SAML in production.
"""
import json
import os
import threading

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PUBLIC_HOST = os.getenv('VOC_PUBLIC_HOST', 'localhost')

# portal role -> platform role maps
ES_ROLES = {
    'admin': ['superuser'],
    'voc': ['kibana_admin', 'viewer'],
    'soc3': ['viewer'], 'soc2': ['viewer'], 'soc1': ['viewer'],
    'noc': ['viewer'],
}
RMQ_TAGS = {
    'admin': ['administrator'],
    'voc': ['management'],
    'soc3': ['monitoring'], 'soc2': ['monitoring'], 'soc1': ['monitoring'],
    'noc': ['monitoring'],
}
GLPI_PROFILE = {
    'admin': 4, 'voc': 3, 'soc3': 6, 'soc2': 6, 'soc1': 6, 'noc': 8,
}
MISP_ROLE = {
    'admin': 1, 'voc': 4, 'soc3': 3, 'soc2': 3, 'soc1': 3, 'noc': 6,
}

MISP_DOMAIN = os.getenv('MISP_USER_DOMAIN', 'voc.local')
MISP_ORG = int(os.getenv('MISP_ORG_ID', '1'))

# SSO-capable platforms: embed user:pass in the URL so the browser
# pre-authenticates (HTTP Basic) with zero further logins.
SSO_PLATFORMS = {'kibana', 'es', 'rabbitmq'}


def _env(key, default=''):
    return os.getenv(key, default) or default


def glpi_profile(role):
    return GLPI_PROFILE.get(role, 8)


def misp_role(role):
    return MISP_ROLE.get(role, 6)


def _timeout():
    return float(_env('PROVISION_TIMEOUT', '6'))


def _es():
    return {
        'url': _env('ES_URL') or _env('ELASTIC_URL', 'http://elasticsearch:9200'),
        'user': _env('ES_USER') or _env('ELASTIC_USERNAME', 'elastic'),
        'pass': _env('ELASTIC_PASSWORD', ''),
    }


def _rmq():
    return {
        'url': _env('RABBITMQ_MGMT_URL', 'http://rabbitmq:15672'),
        'user': _env('RABBITMQ_USER', 'voc'),
        'pass': _env('RABBITMQ_PASS', ''),
    }


def _glpi():
    return {
        'url': _env('PROVISION_GLPI_URL') or _env('GLPI_URL', ''),
        'app': _env('GLPI_APP_TOKEN', ''),
        'user_token': _env('GLPI_USER_TOKEN', ''),
    }


def _glpi_db():
    return {
        'host': _env('GLPI_DB_HOST', 'mariadb'),
        'port': int(_env('GLPI_DB_PORT', '3306')),
        'user': _env('GLPI_DB_USER', 'glpi'),
        'pass': _env('GLPI_DB_PASSWORD', ''),
        'name': _env('GLPI_DB_NAME', 'glpi'),
    }


def _misp():
    return {
        'url': _env('PROVISION_MISP_URL') or _env('MISP_URL', ''),
        'key': _env('MISP_KEY', ''),
        'verify': _env('MISP_VERIFY_SSL', 'false').lower() == 'true',
    }


def _result(ok, detail=''):
    return {'ok': ok, 'detail': detail}


# ---------------------------------------------------------------- ES / Kibana
def _es_provision(username, password, full_name, role, active):
    c = _es()
    if not c['pass']:
        return _result(None, 'elasticsearch not configured')
    url = f"{c['url']}/_security/user/{requests.utils.quote(username)}"
    body = {
        'password': password, 'enabled': bool(active),
        'roles': ES_ROLES.get(role, ['viewer']),
        'full_name': full_name or username,
        'metadata': {'provisioned_by': 'voc-portal'},
    }
    try:
        r = requests.put(url, auth=(c['user'], c['pass']), json=body,
                         timeout=_timeout())
        return _result(r.status_code in (200, 201),
                       'ok' if r.status_code in (200, 201) else r.text[:160])
    except Exception as e:
        return _result(False, str(e)[:160])


def _es_deprovision(username):
    c = _es()
    if not c['pass']:
        return _result(None, 'not configured')
    url = f"{c['url']}/_security/user/{requests.utils.quote(username)}"
    try:
        roles = []
        r = requests.get(url, auth=(c['user'], c['pass']), timeout=_timeout())
        if r.status_code == 200:
            roles = r.json().get('roles', [])
        r = requests.put(url, auth=(c['user'], c['pass']),
                         json={'enabled': False, 'roles': roles}, timeout=_timeout())
        return _result(r.status_code in (200, 404),
                       'disabled' if r.status_code == 200 else r.text[:160])
    except Exception as e:
        return _result(False, str(e)[:160])


# ------------------------------------------------------------- RabbitMQ mgmt
def _rmq_provision(username, password, full_name, role, active):
    c = _rmq()
    if not c['pass']:
        return _result(None, 'rabbitmq not configured')
    name = requests.utils.quote(username, safe='')
    try:
        if not active:
            r = requests.delete(f"{c['url']}/api/users/{name}",
                                auth=(c['user'], c['pass']), timeout=_timeout())
            return _result(r.status_code in (200, 204, 404), 'disabled')
        r = requests.put(f"{c['url']}/api/users/{name}",
                         auth=(c['user'], c['pass']),
                         json={'password': password,
                               'tags': ','.join(RMQ_TAGS.get(role, ['monitoring']))},
                         timeout=_timeout())
        if r.status_code not in (200, 201, 204):
            return _result(False, r.text[:160])
        # grant access to the default vhost (/)
        r2 = requests.put(f"{c['url']}/api/permissions/%2f/{name}",
                          auth=(c['user'], c['pass']),
                          json={'configure': '', 'write': '', 'read': '.*'},
                          timeout=_timeout())
        return _result(r2.status_code in (200, 201, 204),
                       'ok' if r2.status_code in (200, 201, 204) else r2.text[:160])
    except Exception as e:
        return _result(False, str(e)[:160])


def _rmq_deprovision(username):
    c = _rmq()
    if not c['pass']:
        return _result(None, 'not configured')
    try:
        r = requests.delete(f"{c['url']}/api/users/{requests.utils.quote(username, safe='')}",
                            auth=(c['user'], c['pass']), timeout=_timeout())
        return _result(r.status_code in (200, 204, 404), 'deleted')
    except Exception as e:
        return _result(False, str(e)[:160])


# ----------------------------------------------------------------------- GLPI
def _glpi_session():
    c = _glpi()
    if not c['url'] or not c['app'] or not c['user_token']:
        return None, _result(None, 'glpi not configured')
    try:
        r = requests.post(f"{c['url']}/apirest.php/initSession",
                          headers={'Content-Type': 'application/json',
                                   'App-Token': c['app'],
                                   'Authorization': f"user_token {c['user_token']}"},
                          timeout=_timeout())
        if r.status_code != 200:
            return None, _result(False, r.text[:160])
        return r.json().get('session_token'), None
    except Exception as e:
        return None, _result(False, str(e)[:160])


def _glpi_kill(session):
    c = _glpi()
    if not session:
        return
    try:
        requests.post(f"{c['url']}/apirest.php/killSession",
                      headers={'App-Token': c['app'], 'Session-Token': session},
                      timeout=_timeout())
    except Exception:
        pass


def _glpi_find_user(session, username):
    c = _glpi()
    h = {'Content-Type': 'application/json', 'App-Token': c['app'],
         'Session-Token': session}
    try:
        r = requests.get(f"{c['url']}/apirest.php/User",
                         headers=h, params={'range': '0-500'},
                         timeout=_timeout())
        if r.status_code != 200:
            return None, _result(False, r.text[:160])
        for u in r.json():
            if u.get('name') == username:
                return int(u['id']), None
        return None, None
    except Exception as e:
        return None, _result(False, str(e)[:160])


def _glpi_set_profile(uid, profile_id):
    """Attach the target GLPI profile to a user (root entity, recursive).
    GLPI's REST API can't assign arbitrary profiles (its right-hierarchy check
    rejects the customized profiles), so this links it directly in the GLPI DB -
    the same table the web UI writes to."""
    c = _glpi_db()
    if not c['pass']:
        return _result(None, 'glpi db not configured')
    try:
        import pymysql
        conn = pymysql.connect(host=c['host'], port=c['port'],
                               user=c['user'], password=c['pass'],
                               database=c['name'], connect_timeout=_timeout())
        try:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM glpi_profiles_users WHERE users_id=%s', (uid,))
                cur.execute(
                    'INSERT INTO glpi_profiles_users'
                    ' (users_id, profiles_id, entities_id, is_recursive, is_default_profile)'
                    ' VALUES (%s, %s, 0, 1, 1)',
                    (uid, profile_id))
            conn.commit()
        finally:
            conn.close()
        return _result(True, f'profile {profile_id}')
    except Exception as e:
        return _result(False, str(e)[:160])


def _glpi_provision(username, password, full_name, role, active):
    session, err = _glpi_session()
    if err:
        return err
    c = _glpi()
    h = {'Content-Type': 'application/json', 'App-Token': c['app'],
         'Session-Token': session}
    try:
        uid, ferr = _glpi_find_user(session, username)
        if ferr:
            _glpi_kill(session)
            return ferr
        name_bits = (full_name or username).strip().split(None, 1)
        first = name_bits[0][:40] if name_bits else username
        real = (name_bits[1] if len(name_bits) > 1 else '')[:40]
        payload = {'firstname': first, 'realname': real,
                   'active': 1 if active else 0, 'is_deleted': 0 if active else 1}
        already_has = False
        if password and uid is not None:
            try:
                import bcrypt
                import pymysql
                c2 = _glpi_db()
                conn = pymysql.connect(host=c2['host'], port=c2['port'],
                                       user=c2['user'], password=c2['pass'],
                                       database=c2['name'], connect_timeout=_timeout())
                try:
                    with conn.cursor() as cur:
                        cur.execute('SELECT password FROM glpi_users WHERE id=%s', (uid,))
                        row = cur.fetchone()
                    stored = row[0] if row else None
                    if stored and stored.startswith('$2') and bcrypt.checkpw(password.encode(), stored.encode()):
                        already_has = True
                finally:
                    conn.close()
            except Exception:
                pass
        if password and not already_has:
            # GLPI only hashes the password when password2 (confirmation) is present
            payload['password'] = password
            payload['password2'] = password
        if uid is None:
            payload['name'] = username
            r = requests.post(f"{c['url']}/apirest.php/User", headers=h,
                              json={'input': payload}, timeout=_timeout())
            if r.status_code not in (200, 201):
                _glpi_kill(session)
                return _result(False, r.text[:160])
            uid = r.json().get('id')
            if not uid:
                _glpi_kill(session)
                return _result(False, 'glpi create returned no id')
        else:
            if 'password' in payload:
                # GLPI enforces a password-reuse policy; wipe the history so the
                # new password can be applied during syncs
                try:
                    import pymysql
                    c2 = _glpi_db()
                    conn = pymysql.connect(host=c2['host'], port=c2['port'],
                                           user=c2['user'], password=c2['pass'],
                                           database=c2['name'], connect_timeout=_timeout())
                    try:
                        with conn.cursor() as cur:
                            cur.execute("UPDATE glpi_users SET password_history='' WHERE id=%s", (uid,))
                        conn.commit()
                    finally:
                        conn.close()
                except Exception:
                    pass
            r = requests.put(f"{c['url']}/apirest.php/User/{uid}", headers=h,
                             json={'input': payload}, timeout=_timeout())
            if r.status_code not in (200, 201):
                _glpi_kill(session)
                return _result(False, r.text[:160])
        if active:
            prof = _glpi_set_profile(uid, glpi_profile(role))
            if not prof['ok']:
                _glpi_kill(session)
                return _result(False, f"user ok, profile: {prof['detail']}")
        _glpi_kill(session)
        return _result(True, f'glpi id {uid}')
    except Exception as e:
        _glpi_kill(session)
        return _result(False, str(e)[:160])


def _glpi_deprovision(username):
    session, err = _glpi_session()
    if err:
        return err
    try:
        uid, ferr = _glpi_find_user(session, username)
        if ferr:
            _glpi_kill(session)
            return ferr
        if uid is None:
            _glpi_kill(session)
            return _result(True, 'absent')
        c = _glpi()
        h = {'Content-Type': 'application/json', 'App-Token': c['app'],
             'Session-Token': session}
        r = requests.put(f"{c['url']}/apirest.php/User/{uid}", headers=h,
                         json={'input': {'active': 0, 'is_deleted': 1}},
                         timeout=_timeout())
        _glpi_kill(session)
        return _result(r.status_code in (200, 201), 'disabled')
    except Exception as e:
        _glpi_kill(session)
        return _result(False, str(e)[:160])


# ----------------------------------------------------------------------- MISP
def _misp_provision(username, password, full_name, role, active):
    c = _misp()
    if not c['url'] or not c['key']:
        return _result(None, 'misp not configured')
    email = f"{username}@{MISP_DOMAIN}"
    h = {'Authorization': c['key'], 'Accept': 'application/json',
         'Content-Type': 'application/json'}
    v = c['verify']
    try:
        if not active:
            r = requests.post(f"{c['url']}/admin/users/delete/{username}",
                              headers=h, verify=v, timeout=_timeout())
            return _result(r.status_code in (200, 404), 'disabled')
        body = {'email': email, 'org_id': MISP_ORG,
                'role_id': misp_role(role), 'external_auth_required': 0,
                'change_pw': 0}
        if password:
            body['password'] = password
        r = requests.post(f"{c['url']}/admin/users/add", headers=h,
                          json=body, verify=v, timeout=_timeout())
        low = r.text.lower()
        if r.status_code in (200, 201) and 'already exists' not in low and 'taken' not in low:
            uid = (r.json().get('User') or {}).get('id')
            return _result(True, f'misp id {uid}' if uid else 'ok')
        # user already exists -> edit it
        found = None
        try:
            lst = requests.get(f"{c['url']}/admin/users/index", headers=h,
                               verify=v, timeout=_timeout())
            if lst.status_code == 200:
                data = lst.json()
                data = data.get('response', data) if isinstance(data, dict) else data
                for u in data:
                    row = u.get('User', u)
                    if row.get('email') == email:
                        found = row.get('id')
                        break
        except Exception:
            pass
        if not found:
            return _result(False, r.text[:160] if r.status_code else 'user not found')
        edit = requests.post(f"{c['url']}/admin/users/edit/{found}",
                             headers=h, json={'role_id': misp_role(role),
                                              'password': password or '',
                                              'change_pw': 0},
                             verify=v, timeout=_timeout())
        return _result(edit.status_code in (200, 201),
                       'updated' if edit.status_code in (200, 201) else edit.text[:160])
    except Exception as e:
        return _result(False, str(e)[:160])


def _misp_deprovision(username):
    c = _misp()
    if not c['url'] or not c['key']:
        return _result(None, 'not configured')
    h = {'Authorization': c['key'], 'Accept': 'application/json'}
    v = c['verify']
    try:
        email = f"{username}@{MISP_DOMAIN}"
        found = None
        lst = requests.get(f"{c['url']}/admin/users/index", headers=h,
                           verify=v, timeout=_timeout())
        if lst.status_code == 200:
            data = lst.json()
            data = data.get('response', data) if isinstance(data, dict) else data
            for u in data:
                row = u.get('User', u)
                if row.get('email') == email:
                    found = row.get('id')
                    break
        if not found:
            return _result(True, 'absent')
        r = requests.post(f"{c['url']}/admin/users/delete/{found}",
                          headers=h, verify=v, timeout=_timeout())
        return _result(r.status_code in (200, 404), 'deleted')
    except Exception as e:
        return _result(False, str(e)[:160])


# ---------------------------------------------------------------- top level
def provision_user(username, password, full_name='', role='soc1', active=True):
    """Create/refresh the identity on every platform. Returns per-platform results."""
    return {
        'es': _es_provision(username, password, full_name, role, active),
        'rabbitmq': _rmq_provision(username, password, full_name, role, active),
        'glpi': _glpi_provision(username, password, full_name, role, active),
        'misp': _misp_provision(username, password, full_name, role, active),
    }


def deprovision_user(username):
    """Disable/delete the identity everywhere (best effort)."""
    return {
        'es': _es_deprovision(username),
        'rabbitmq': _rmq_deprovision(username),
        'glpi': _glpi_deprovision(username),
        'misp': _misp_deprovision(username),
    }


def sso_url(platform, username, password):
    """Return a single-sign-on URL embedding the user's credentials for
    basic-auth platforms.

    SECURITY: URLs with embedded credentials leak via browser history,
    proxy logs and Referrer headers, so this is opt-in via
    VOC_SSO_EMBED_CREDENTIALS=true (trusted lab demos). Default: plain
    service URL; users log in with their usual credentials.
    """
    if not password:
        return None
    if platform not in SSO_PLATFORMS:
        return None
    if os.getenv('VOC_SSO_EMBED_CREDENTIALS', 'false').lower() != 'true':
        return None
    try:
        from urllib.parse import quote
        port = {'kibana': 5601, 'es': 9200, 'rabbitmq': 15672}.get(platform)
        scheme = 'https' if port == 15672 and _env('RABBITMQ_MGMT_URL', '').startswith('https') else 'http'
        return f"{scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{PUBLIC_HOST}:{port}"
    except Exception:
        return None


def access_list(username, password):
    """Service access entries shown on My Account. Same-credentials platforms
    note that the portal identity works there too."""
    base = f"http://{PUBLIC_HOST}"
    sso_on = os.getenv('VOC_SSO_EMBED_CREDENTIALS', 'false').lower() == 'true'
    out = [
        {'key': 'kibana', 'name': 'Kibana', 'tag': 'Dashboards · alerts',
         'url': sso_url('kibana', username, password) or f"{base}:5601", 'sso': sso_on},
        {'key': 'es', 'name': 'Elasticsearch', 'tag': 'Search & index engine',
         'url': sso_url('es', username, password) or f"{base}:9200", 'sso': sso_on},
        {'key': 'rabbitmq', 'name': 'RabbitMQ', 'tag': 'Queues & message broker',
         'url': sso_url('rabbitmq', username, password) or f"{base}:15672", 'sso': sso_on},
        {'key': 'glpi', 'name': 'GLPI', 'tag': 'ITSM · assets · tickets',
         'url': f"{base}:8080", 'sso': False, 'same_credentials': True},
        {'key': 'misp', 'name': 'MISP', 'tag': 'Threat intelligence',
         'url': f"{_env('MISP_URL', '') or 'https://' + PUBLIC_HOST + ':8443'}", 'sso': False, 'same_credentials': True},
    ]
    return out


def provision_background():
    """Idempotent one-shot backfill for users that exist before this feature."""
    from .db import get_db
    from .roles import migrate_roles

    def run():
        try:
            with get_db() as conn:
                migrate_roles(conn)
                users = conn.execute(
                    'SELECT * FROM users').fetchall()
                for u in users:
                    if not u['platform_pass']:
                        continue
                    res = provision_user(u['username'], u['platform_pass'],
                                         u['full_name'], u['role'], bool(u['active']))
                    conn.execute('UPDATE users SET provision=? WHERE id=?',
                                 (json.dumps(res), u['id']))
        except Exception as e:
            import sys
            print(f'[provision] backfill error: {e}', file=sys.stderr)

    threading.Thread(target=run, daemon=True).start()