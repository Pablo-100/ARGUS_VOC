"""Password hashing + JWT auth for the VOC portal."""
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt

SECRET = os.getenv('PORTAL_SECRET', '')
ALGO = 'HS256'
TOKEN_TTL_HOURS = 12

if not SECRET:
    raise RuntimeError('PORTAL_SECRET must be set')


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 120_000)
    return f'pbkdf2${salt}${dk.hex()}'


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, hexdk = stored.split('$')
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 120_000)
        return hmac.compare_digest(dk.hex(), hexdk)
    except Exception:
        return False


def make_token(user_id: int, username: str, role: str) -> str:
    payload = {
        'sub': str(user_id),
        'username': username,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS),
    }
    return jwt.encode(payload, SECRET, algorithm=ALGO)


def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET, algorithms=[ALGO])
    except Exception:
        return None