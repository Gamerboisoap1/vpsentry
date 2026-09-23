import hashlib
import hmac
import secrets
import time
import threading
from collections import OrderedDict
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from backend.config import settings

basic = HTTPBasic(auto_error=False)
failures = OrderedDict()
verified = OrderedDict()
guard = threading.Lock()

def hash_password(password):
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 600000).hex()

def authorized(request: Request, credentials: HTTPBasicCredentials | None = Depends(basic)):
    if not settings.password_hash:
        if settings.host in ('127.0.0.1', '::1', 'localhost'):
            return
        raise HTTPException(503, 'Administrator authentication is not configured')
    valid = False
    if credentials:
        now = time.monotonic()
        address = request.client.host if request.client else 'unknown'
        fingerprint = hashlib.sha256((credentials.username + '\0' + credentials.password + '\0' + settings.password_hash).encode()).digest()
        with guard:
            if verified.get(fingerprint, 0) > now:
                return
            count, reset = failures.get(address, (0, now + 60))
            if reset <= now:
                count, reset = 0, now + 60
            if count >= 10:
                raise HTTPException(429, 'Too many failed logins. Try again in one minute.', headers={'Retry-After': '60'})
        try:
            salt, expected = settings.password_hash.split(':', 1)
            actual = hashlib.pbkdf2_hmac('sha256', credentials.password.encode(), salt.encode(), 600000).hex()
            valid = hmac.compare_digest(credentials.username, settings.admin_user) and hmac.compare_digest(actual, expected)
        except (ValueError, UnicodeError):
            pass
        with guard:
            if valid:
                verified[fingerprint] = now + 60
                verified.move_to_end(fingerprint)
                if len(verified) > 128:
                    verified.popitem(last=False)
                failures.pop(address, None)
            else:
                failures[address] = (count + 1, reset)
                failures.move_to_end(address)
                if len(failures) > 1024:
                    failures.popitem(last=False)
    if not valid:
        raise HTTPException(401, 'Authentication required', headers={'WWW-Authenticate': 'Basic realm="VPSentry", charset="UTF-8"'})
