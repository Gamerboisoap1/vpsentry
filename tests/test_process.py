"""Real-process restart test, independent of Linux-only packet privileges."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
from backend.models.store import Store


def test_real_process_restart_and_legacy_isolation(tmp_path):
    with socket.socket() as port_probe:
        port_probe.bind(('127.0.0.1',0))
        port=port_probe.getsockname()[1]
    env={**os.environ,'VPSENTRY_HOST':'127.0.0.1','VPSENTRY_PORT':str(port),
         'VPSENTRY_DATA_DIR':str(tmp_path)}
    root=Path(__file__).resolve().parents[1]
    def request(path, data=None):
        body=json.dumps(data).encode() if data else None
        req=urllib.request.Request(f'http://127.0.0.1:{port}{path}',data=body,headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as result:
            return result.status,result.read()
    def start():
        process=subprocess.Popen([sys.executable,'-m','backend'],env=env,cwd=root,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if process.poll() is not None: raise AssertionError('Server process failed to start')
                try:
                    if request('/api/stats')[0]==200: return process
                except OSError: pass
                time.sleep(.1)
            raise AssertionError('Server did not become ready')
        except BaseException:
            process.terminate();process.wait(timeout=10)
            raise
    process=start()
    try:
        assert request('/ssh')[0]==200
        Store(tmp_path).event('SSH_BRUTE_FORCE','SSH','HIGH','Legacy simulated row',demo=True)
        Store(tmp_path).set('restart_marker','survived')
    finally:
        process.terminate();process.wait(timeout=10)
    process=start()
    try:
        assert Store(tmp_path).get('restart_marker')=='survived'
        assert Store(tmp_path).events(demo=True)['total']==1
        assert json.loads(request('/api/ssh')[1])['attacks_24h']==0
        assert json.loads(request('/api/security-score')[1])['score']==100
        try:
            request('/api/demo/events',{'type':'PORT_SCAN'})
            raise AssertionError('Production mode accepted a demo event')
        except urllib.error.HTTPError as error:
            assert error.code==405
    finally:
        process.terminate();process.wait(timeout=10)
