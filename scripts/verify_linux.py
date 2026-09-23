"""Run after installation on a Linux host. Does not attack or modify host policy."""
import json
import platform
import subprocess
import time
import urllib.request
from backend.config import Settings
from backend.models.store import Store


def main():
    if platform.system() != 'Linux':
        raise SystemExit('Linux is required for this installed-service verification.')
    settings=Settings(_env_file='/etc/vpsentry/vpsentry.env')
    host='127.0.0.1' if settings.host in ('0.0.0.0','localhost') else '[::1]' if settings.host=='::1' else settings.host
    def get(path):
        with urllib.request.urlopen(f'http://{host}:{settings.port}{path}',timeout=10) as response:
            return response.read()
    for unit in ('vpsentry','vpsentry-network','vpsentry-firewall.timer'):
        subprocess.run(['systemctl','is-active','--quiet',unit],check=True)
        subprocess.run(['systemctl','is-enabled','--quiet',unit],check=True)
    db=Store(settings.data_dir)
    marker='verification-'+str(time.time_ns())
    db.set('verification_marker',marker)
    for route in ('/','/ssh','/network','/ports','/users','/activity','/attack-map'):
        assert b'id="root"' in get(route), route
    for path in ('health','stats','events','events/recent','ssh','scans','ports','users','security-score','attack-map'):
        json.loads(get('/api/'+path))
    health=json.loads(get('/api/health'))
    assert health['sampling_ok'], health
    assert health['monitors']['network']['state']=='active', health
    assert json.loads(get('/api/stats'))['ram']['total']>0
    subprocess.run(['systemctl','restart','vpsentry'],check=True)
    for _ in range(30):
        try:
            if json.loads(get('/api/health'))['status']=='online': break
        except (OSError, ValueError): pass
        time.sleep(1)
    else: raise AssertionError('Service did not recover after restart')
    assert Store(settings.data_dir).get('verification_marker')==marker
    print('PASS: installed services, enabled units, port binding, API, frontend routes, live statistics, network heartbeat and database persistence after restart.')
    print('SSH status:', health['monitors']['ssh']['state'], '-', health['monitors']['ssh']['message'])
    print('A real reboot and inbound traffic from another host must still be checked separately.')

if __name__=='__main__': main()
