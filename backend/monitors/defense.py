"""Read-only host hardening, file integrity and suspicious-process checks."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import time

import psutil

MAX_HASH_BYTES = 100 * 1024 * 1024
RISKY_DIRECTORIES = ('/tmp/', '/var/tmp/', '/dev/shm/')


def command(args, timeout=12):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def checklist(store):
    items = []
    firewall = store.get('firewall_status', {})
    firewall_state = firewall.get('state', 'unknown')
    items.append({
        'id': 'firewall', 'label': 'Firewall active',
        'status': 'pass' if firewall_state == 'active' else 'warn' if firewall_state == 'inactive' else 'unknown',
        'detail': firewall.get('message', 'Firewall has not been inspected yet'),
        'recommendation': 'Enable UFW, nftables or iptables input filtering.'
    })

    if not shutil.which('systemctl'):
        fail2ban_status, fail2ban_detail = 'unknown', 'systemd is unavailable'
    else:
        result = command(['systemctl', 'is-active', 'fail2ban'], 5)
        active = bool(result and result.returncode == 0 and result.stdout.strip() == 'active')
        fail2ban_status = 'pass' if active else 'warn'
        fail2ban_detail = 'Fail2ban is running' if active else 'Fail2ban is not running'
    items.append({'id': 'fail2ban', 'label': 'Fail2ban running', 'status': fail2ban_status,
                  'detail': fail2ban_detail, 'recommendation': 'Install and enable Fail2ban for automated login protection.'})

    ssh = effective_ssh()
    root = ssh.get('permitrootlogin')
    if root is None:
        root_status, root_detail = 'unknown', 'Could not read the effective SSH configuration'
    elif root == 'no':
        root_status, root_detail = 'pass', 'Direct root SSH login is disabled'
    else:
        root_status, root_detail = 'warn', f'Effective PermitRootLogin is {root}'
    items.append({'id': 'ssh_root', 'label': 'SSH root login disabled', 'status': root_status,
                  'detail': root_detail, 'recommendation': 'Set PermitRootLogin no after confirming sudo access.'})

    password = ssh.get('passwordauthentication')
    if password is None:
        password_status, password_detail = 'unknown', 'Could not read the effective SSH configuration'
    elif password == 'no':
        password_status, password_detail = 'pass', 'SSH password authentication is disabled'
    else:
        password_status, password_detail = 'warn', 'SSH password authentication is enabled'
    items.append({'id': 'ssh_password', 'label': 'SSH password login disabled', 'status': password_status,
                  'detail': password_detail, 'recommendation': 'Use SSH keys, then set PasswordAuthentication no.'})

    updates = available_updates()
    if updates is None:
        update_status, update_detail = 'unknown', 'Package update information is unavailable'
    elif updates['security']:
        update_status, update_detail = 'warn', f"{updates['security']} security update(s) available"
    elif updates['total']:
        update_status, update_detail = 'pass', f"No security updates; {updates['total']} other update(s) available"
    else:
        update_status, update_detail = 'pass', 'No package updates are currently listed'
    items.append({'id': 'updates', 'label': 'Security updates installed', 'status': update_status,
                  'detail': update_detail, 'recommendation': 'Run apt update and install available security updates.'})
    return items


def effective_ssh():
    executable = shutil.which('sshd')
    if not executable:
        return {}
    result = command([executable, '-T'], 8)
    if not result or result.returncode != 0:
        return {}
    wanted = {'permitrootlogin', 'passwordauthentication'}
    values = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(' ')
        if key in wanted:
            values[key] = value.strip().lower()
    return values


def available_updates():
    executable = shutil.which('apt')
    if not executable:
        return None
    result = command([executable, 'list', '--upgradable'], 20)
    if not result or result.returncode != 0:
        return None
    lines = [line for line in result.stdout.splitlines() if '/' in line and not line.startswith('Listing')]
    return {'total': len(lines), 'security': sum('-security' in line.lower() for line in lines)}


def watched_paths(settings):
    paths = []
    for raw in settings.watch_files.split(','):
        value = raw.strip()
        if value and os.path.isabs(value) and value not in paths:
            paths.append(value)
    # VAULT is a built-in watch folder. Every regular file placed inside it
    # is monitored automatically, including nested folders.
    vault = Path(settings.vault_dir)
    try:
        vault.mkdir(parents=True, exist_ok=True)
        for target in sorted(vault.rglob('*')):
            if target.is_file() and not target.is_symlink():
                value = str(target)
                if value not in paths:
                    paths.append(value)
    except OSError:
        pass
    return paths[:50]


def file_fingerprint(path):
    target = Path(path)
    try:
        stat = target.stat()
        if not target.is_file():
            return {'status': 'unavailable', 'message': 'Path is not a regular file'}
        if stat.st_size > MAX_HASH_BYTES:
            return {'status': 'unavailable', 'message': 'File is larger than the 100 MB safety limit', 'size': stat.st_size}
        digest = hashlib.sha256()
        with target.open('rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(block)
        return {'status': 'ok', 'sha256': digest.hexdigest(), 'size': stat.st_size,
                'mtime': stat.st_mtime, 'mode': oct(stat.st_mode & 0o777)}
    except FileNotFoundError:
        return {'status': 'missing', 'message': 'File does not exist'}
    except (OSError, PermissionError) as exc:
        return {'status': 'unavailable', 'message': str(exc)[:160]}


def inspect_files(store, settings, now=None):
    now = time.time() if now is None else now
    baseline = store.get('file_integrity_baseline', {})
    current, rows = {}, []
    for path in watched_paths(settings):
        fingerprint = file_fingerprint(path)
        previous = baseline.get(path)
        current[path] = fingerprint
        changed = previous is not None and previous != fingerprint
        if changed:
            kind = 'FILE_DELETED' if fingerprint['status'] == 'missing' else 'FILE_CHANGED'
            store.event(kind, 'System', 'HIGH', f'Watched file changed: {path}',
                        details={'path': path, 'previous': previous, 'current': fingerprint})
        rows.append({'path': path, **fingerprint, 'changed': changed, 'last_checked': now,
                     'baseline': 'updated' if changed else 'created' if previous is None else 'matched'})
    # Detect files added to or removed from the built-in VAULT folder.
    previous_paths = {path for path in baseline if path.startswith(str(settings.vault_dir) + os.sep)}
    current_paths = {path for path in current if path.startswith(str(settings.vault_dir) + os.sep)}
    for path in sorted(current_paths - previous_paths):
        if baseline:
            store.event('FILE_ADDED', 'System', 'HIGH', f'New VAULT file detected: {path}', details={'path': path})
    for path in sorted(previous_paths - current_paths):
        store.event('FILE_DELETED', 'System', 'HIGH', f'VAULT file deleted: {path}', details={'path': path})
    store.set('file_integrity_baseline', current)
    store.set('file_integrity', {'updated': now, 'items': rows})
    return rows


def inspect_processes(store, settings, now=None):
    now = time.time() if now is None else now
    findings = []
    seen = store.get('suspicious_process_seen', {})
    active_keys = set()
    for process in psutil.process_iter(['pid', 'name', 'username', 'exe', 'memory_percent']):
        try:
            info = process.info
            cpu = process.cpu_percent(None)
            memory = float(info.get('memory_percent') or 0)
            executable = info.get('exe') or ''
            if os.name == 'posix' and os.path.lexists(f'/proc/{process.pid}/exe'):
                try:
                    executable = os.readlink(f'/proc/{process.pid}/exe')
                except OSError:
                    pass
            reasons = []
            if cpu >= settings.process_cpu_threshold:
                reasons.append(f'CPU usage {cpu:.1f}%')
            if memory >= settings.process_memory_threshold:
                reasons.append(f'memory usage {memory:.1f}%')
            if not reasons:
                continue
            key = f"{process.pid}:{'|'.join(sorted(reasons))}"
            active_keys.add(key)
            row = {'pid': process.pid, 'name': info.get('name') or 'unknown',
                   'username': info.get('username'), 'executable': executable,
                   'cpu': round(cpu, 1), 'memory': round(memory, 1), 'reasons': reasons}
            findings.append(row)
            if key not in seen or now - seen[key] > 3600:
                store.event('SUSPICIOUS_PROCESS', 'System', 'HIGH',
                            f"Suspicious process: {row['name']} (PID {process.pid})", details=row)
                seen[key] = now
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    seen = {key: timestamp for key, timestamp in seen.items() if key in active_keys or now - timestamp < 3600}
    store.set('suspicious_process_seen', seen)
    store.set('suspicious_processes', {'updated': now, 'items': findings})
    return findings


class DefenseMonitor:
    def __init__(self, store, settings, stop):
        self.store, self.settings, self.stop = store, settings, stop

    def run(self):
        last_checklist = 0
        while not self.stop.is_set():
            now = time.time()
            try:
                inspect_files(self.store, self.settings, now)
                inspect_processes(self.store, self.settings, now)
                if now - last_checklist >= 300:
                    self.store.set('defense_checklist', {'updated': now, 'items': checklist(self.store)})
                    last_checklist = now
                self.store.set('defense_status', {'state': 'active', 'message': 'Defense checks are running', 'updated': now})
            except Exception as exc:
                self.store.set('defense_status', {'state': 'unavailable', 'message': str(exc)[:160], 'updated': now})
            self.stop.wait(self.settings.defense_seconds)
