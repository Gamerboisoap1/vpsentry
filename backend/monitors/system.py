import os
import platform
import pwd
import socket
import time
import psutil


def stats():
    memory, disk = psutil.virtual_memory(), psutil.disk_usage('/')
    return {'timestamp': time.time(), 'hostname': socket.gethostname(), 'platform': platform.system(),
            'release': platform.release(), 'cpu': psutil.cpu_percent(), 'cores': psutil.cpu_count(),
            'ram': {'percent': memory.percent, 'used': memory.total - memory.available, 'total': memory.total},
            'disk': {'percent': disk.percent, 'used': disk.used, 'total': disk.total},
            'uptime': max(0, time.time() - psutil.boot_time()), 'load': list(os.getloadavg())}


def ports():
    result = {}
    for item in psutil.net_connections(kind='inet'):
        if item.status != psutil.CONN_LISTEN and not (item.type == socket.SOCK_DGRAM and item.laddr and not item.raddr):
            continue
        if not item.laddr:
            continue
        protocol = 'TCP' if item.type == socket.SOCK_STREAM else 'UDP'
        process = None
        if item.pid:
            try:
                process = psutil.Process(item.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        try:
            service = socket.getservbyport(item.laddr.port, protocol.lower())
        except OSError:
            service = 'Unknown'
        key = (protocol, item.laddr.ip, item.laddr.port)
        result[key] = {'port': item.laddr.port, 'protocol': protocol, 'address': item.laddr.ip,
                       'process': process, 'service': service,
                       'exposure': 'Local' if item.laddr.ip in ('127.0.0.1', '::1') else 'Network'}
    return sorted(result.values(), key=lambda p: (p['port'], p['protocol'], p['address']))


def users():
    return [{'username': u.pw_name, 'uid': u.pw_uid, 'home': u.pw_dir, 'shell': u.pw_shell,
             'interactive': bool(u.pw_shell) and u.pw_shell.rsplit('/', 1)[-1] not in ('nologin', 'false', 'sync')}
            for u in pwd.getpwall() if u.pw_uid == 0 or 1000 <= u.pw_uid < 65534]
