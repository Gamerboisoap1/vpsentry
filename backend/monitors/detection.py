"""Bounded, sliding-window detectors. Never perform remediation or outbound scans."""
import ipaddress
import re
import time
from collections import OrderedDict, deque

SSH = re.compile(r'(?P<result>Failed password|Failed publickey|Accepted password|Accepted publickey|Accepted keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+) port \d+')

class Detector:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        self.failures, self.probes = OrderedDict(), OrderedDict()
        self.incidents = {}

    def bucket(self, buckets, ip, now, window):
        # Bound both idle source count and per-source storage under hostile traffic.
        if ip not in buckets:
            if len(buckets) >= 4096:
                buckets.popitem(last=False)
            buckets[ip] = deque(maxlen=4096)
        buckets.move_to_end(ip)
        bucket = buckets[ip]
        while bucket and bucket[0][0] < now - window:
            bucket.popleft()
        return bucket

    def incident(self, kind, category, ip, details, now, window, description):
        key = (kind, ip)
        previous = self.incidents.get(key)
        if previous and now - previous[1] <= window:
            event_id, _, first = previous
            details['first_seen'] = first
            self.store.update_incident(event_id, details)
        else:
            first = details['first_seen']
            event_id = self.store.event(kind, category, 'HIGH', description, ip, details, timestamp=now)
        self.incidents[key] = (event_id, now, first)
        if len(self.incidents) > 8192:
            self.incidents = {k: v for k, v in self.incidents.items() if now - v[1] <= window}

    def ssh(self, line, now=None):
        match = SSH.search(line)
        if not match:
            return False
        now = now or time.time()
        ip, user, result = match['ip'], match['user'][:128], match['result']
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return False
        failed = result.startswith('Failed')
        self.store.event('SSH_FAILED_LOGIN' if failed else 'SSH_SUCCESSFUL_LOGIN', 'SSH', 'LOW' if failed else 'INFO',
                         f'{"Failed" if failed else "Successful"} SSH login for {user}', ip, {'username': user}, timestamp=now)
        if failed:
            bucket = self.bucket(self.failures, ip, now, self.settings.ssh_window)
            bucket.append((now, user))
            if len(bucket) >= self.settings.ssh_threshold:
                self.incident('SSH_BRUTE_FORCE', 'SSH', ip, {'attempts': len(bucket), 'username': user, 'first_seen': bucket[0][0], 'last_seen': now}, now,
                              self.settings.ssh_window, 'Repeated SSH authentication failures')
        return True

    def probe(self, ip, port, now=None):
        now = now or time.time()
        ip = str(ipaddress.ip_address(ip))
        bucket = self.bucket(self.probes, ip, now, self.settings.scan_window)
        bucket.append((now, port))
        ports = sorted({x[1] for x in bucket})
        if len(ports) >= self.settings.scan_threshold:
            self.incident('PORT_SCAN', 'Network', ip, {'ports': ports, 'port_count': len(ports), 'first_seen': bucket[0][0], 'last_seen': now}, now,
                          self.settings.scan_window, 'Multiple destination ports probed')
