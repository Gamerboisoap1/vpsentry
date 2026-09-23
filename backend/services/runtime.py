import logging
import threading
import time
import psutil
from backend.monitors import system
from backend.monitors.detection import Detector
from backend.monitors.ssh import SSHMonitor
from backend.services.geoip import GeoIP

log = logging.getLogger(__name__)

class Runtime:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        self.stop = threading.Event()
        self.ssh = SSHMonitor(store, settings, Detector(store, settings), self.stop)
        self.geoip = GeoIP(store, settings, self.stop)
        self.threads = []

    def start(self):
        self.store.event('SERVICE_STARTED', 'System', 'INFO', 'VPSentry service started')
        for target in (self.sample, self.ssh.run, self.geoip.run):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self.threads.append(thread)

    def close(self):
        self.stop.set()
        self.ssh.close()
        for thread in self.threads:
            thread.join(timeout=5)

    def sample(self):
        last_prune = 0
        while not self.stop.is_set():
            try:
                current = system.stats()
                self.store.set('stats', current)
                self.store.sample(current)
                try:
                    ports = system.ports()
                    keys = [f"{p['protocol']}:{p['address']}:{p['port']}" for p in ports]
                    seen = self.store.get('known_ports')
                    if seen is not None:
                        for port, key in zip(ports, keys):
                            if key not in seen:
                                self.store.event('NEW_LISTENING_PORT', 'System', 'MEDIUM', f"New {port['protocol']} listener on port {port['port']}", details=port)
                    self.store.set('known_ports', sorted(set((seen or []) + keys)))
                    self.store.set('ports', ports)
                    self.store.set('ports_status', {'state': 'active', 'message': 'Listening sockets observed; process names depend on permissions', 'updated': time.time()})
                except (psutil.AccessDenied, PermissionError, OSError) as exc:
                    self.store.set('ports_status', {'state': 'unavailable', 'message': 'Listening sockets unavailable: ' + str(exc)[:100], 'updated': time.time()})
                if time.time() - last_prune > 3600:
                    self.store.prune(self.settings.retention_days)
                    last_prune = time.time()
            except Exception:
                log.exception('System sampling failed')
            self.stop.wait(self.settings.sample_seconds)
