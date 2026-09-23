#!/usr/bin/env python3
"""Generate a password hash without placing a password in shell history."""
import getpass
from backend.services.auth import hash_password
if __name__ == '__main__':
    password = getpass.getpass('New VPSentry administrator password: ')
    if len(password) < 12:
        raise SystemExit('Use at least 12 characters.')
    if password != getpass.getpass('Repeat password: '):
        raise SystemExit('Passwords do not match.')
    print('VPSENTRY_PASSWORD_HASH=' + hash_password(password))
