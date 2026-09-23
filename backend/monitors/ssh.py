import json
import os
import subprocess
import select
import time

class SSHMonitor:
    def __init__(self, store, settings, detector, stop):
        self.store, self.settings, self.detector, self.stop = store, settings, detector, stop
        self.process = None

    def status(self, state, message):
        self.store.set('ssh_status', {'state': state, 'message': message, 'updated': time.time()})

    def run(self):
        while not self.stop.is_set():
            try:
                if self.settings.ssh_source == 'file':
                    self.follow_file()
                elif self.settings.ssh_source == 'journal':
                    self.follow_journal()
                else:
                    raise ValueError('SSH source must be journal or file')
            except Exception as exc:
                self.status('unavailable', str(exc)[:180])
            self.stop.wait(10)

    def follow_file(self):
        path = self.settings.auth_log
        with path.open() as file:
            stat = os.fstat(file.fileno())
            saved = self.store.get('ssh_file_cursor', {})
            if saved.get('inode') == stat.st_ino and saved.get('offset', 0) <= stat.st_size:
                file.seek(saved['offset'])
            else:
                file.seek(0, 2)  # First start follows new activity, not historical attacks.
            self.status('active', 'Following SSH authentication file')
            heartbeat = 0
            while not self.stop.is_set():
                if time.time() - heartbeat > 5:
                    self.status('active', 'Following SSH authentication file')
                    heartbeat = time.time()
                line = file.readline()
                if line:
                    self.detector.ssh(line)
                    self.store.set('ssh_file_cursor', {'inode': stat.st_ino, 'offset': file.tell()})
                else:
                    current = path.stat()
                    if current.st_ino != stat.st_ino or current.st_size < file.tell():
                        # Rotated files start at the beginning on the next pass.
                        self.store.set('ssh_file_cursor', {'inode': current.st_ino, 'offset': 0})
                        return
                    self.stop.wait(0.5)

    def follow_journal(self):
        cursor = self.store.get('ssh_journal_cursor')
        args = ['journalctl', '--follow', '--output=json', '--no-pager', '_COMM=sshd', '+', '_COMM=sshd-session']
        args[1:1] = ['--after-cursor=' + cursor] if cursor else ['--since=now']
        # Check access independently; an empty journal is not proof of a healthy reader.
        check = subprocess.run(['journalctl', '-n', '1', '--no-pager', '-q'], capture_output=True, text=True, timeout=5)
        if check.returncode or 'not seeing messages' in check.stderr or 'permission' in check.stderr.lower():
            raise PermissionError('SSH journal is not readable; check systemd-journal group membership')
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.status('active', 'Following systemd SSH journal')
        try:
            buffer = b''
            heartbeat = 0
            while not self.stop.is_set() and self.process.poll() is None:
                if time.time() - heartbeat > 5:
                    self.status('active', 'Following systemd SSH journal')
                    heartbeat = time.time()
                if not select.select([self.process.stdout], [], [], 1)[0]:
                    continue
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    break
                buffer += chunk
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    entry = json.loads(line)
                    self.detector.ssh(entry.get('MESSAGE', ''), int(entry.get('__REALTIME_TIMESTAMP', time.time() * 1e6)) / 1e6)
                    if '__CURSOR' in entry:
                        self.store.set('ssh_journal_cursor', entry['__CURSOR'])
                if len(buffer) > 1048576:
                    buffer = b''
            if not self.stop.is_set():
                raise RuntimeError('Journal reader exited; check cursor and journal access')
        finally:
            self.close()

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
