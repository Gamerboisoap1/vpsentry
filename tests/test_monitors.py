import threading
import time
from types import SimpleNamespace
import socket
import psutil
import pytest
from backend.monitors.ssh import SSHMonitor
from backend.monitors.detection import Detector
from backend.monitors import system, firewall
from backend.services.runtime import Runtime
from backend.monitors.network import parse_packet
from tests.test_network import packet


def wait_for(predicate):
    deadline=time.monotonic()+4
    while time.monotonic()<deadline:
        if predicate(): return
        time.sleep(.03)
    raise AssertionError('Timed out waiting for monitor')


def test_file_follow_rotation_and_restart(store, config, tmp_path):
    path=tmp_path/'auth.log'
    path.write_text('Historical log entry\n')
    config.auth_log=path
    config.ssh_source='file'
    stop=threading.Event()
    monitor=SSHMonitor(store,config,Detector(store,config),stop)
    thread=threading.Thread(target=monitor.follow_file)
    thread.start()
    wait_for(lambda: store.get('ssh_status',{}).get('state')=='active')
    with path.open('a') as file:
        file.write('sshd: Failed password for root from 192.0.2.1 port 123 ssh2\n')
    wait_for(lambda: store.events(kind='SSH_FAILED_LOGIN')['total']==1)
    stop.set();thread.join(2)
    assert not thread.is_alive()
    assert store.get('ssh_file_cursor')['offset']==path.stat().st_size
    with path.open('a') as file:
        file.write('sshd: Accepted publickey for root from 192.0.2.1 port 123 ssh2\n')
    stop.clear();thread=threading.Thread(target=monitor.follow_file);thread.start()
    wait_for(lambda: store.events(kind='SSH_SUCCESSFUL_LOGIN')['total']==1)
    assert store.events(kind='SSH_FAILED_LOGIN')['total']==1
    path.rename(tmp_path/'auth.log.1')
    path.write_text('sshd: Failed password for test from 192.0.2.2 port 124 ssh2\n')
    thread.join(2)
    assert not thread.is_alive()
    thread=threading.Thread(target=monitor.follow_file);thread.start()
    wait_for(lambda: store.events(kind='SSH_FAILED_LOGIN')['total']==2)
    stop.set();thread.join(2)


def test_missing_log_reports_unavailable(store,config,tmp_path):
    config.auth_log=tmp_path/'missing'
    config.ssh_source='file'
    stop=threading.Event()
    monitor=SSHMonitor(store,config,Detector(store,config),stop)
    thread=threading.Thread(target=monitor.run);thread.start()
    wait_for(lambda:store.get('ssh_status',{}).get('state')=='unavailable')
    stop.set();thread.join(2)
    assert not thread.is_alive()


def test_listening_port_mapping(monkeypatch):
    def connection(port,kind,status,ip='0.0.0.0'):
        return SimpleNamespace(status=status,type=kind,laddr=SimpleNamespace(ip=ip,port=port),raddr=(),pid=None)
    monkeypatch.setattr(psutil,'net_connections',lambda **_: [connection(22,socket.SOCK_STREAM,psutil.CONN_LISTEN),connection(53,socket.SOCK_DGRAM,psutil.CONN_NONE,'127.0.0.1'),connection(9876,socket.SOCK_STREAM,psutil.CONN_ESTABLISHED)])
    result=system.ports()
    assert [p['port'] for p in result]==[22,53]
    assert result[1]['protocol']=='UDP'
    assert result[1]['exposure']=='Local'


def test_new_port_event_and_permission_failure(store,config,monkeypatch):
    runtime=Runtime(store,config)
    metric={'timestamp':time.time(),'cpu':1,'ram':{'percent':1},'disk':{'percent':1}}
    monkeypatch.setattr(system,'stats',lambda:metric)
    port={'protocol':'TCP','address':'0.0.0.0','port':8787,'exposure':'Network'}
    store.set('known_ports',[])
    def ports():
        runtime.stop.set()
        return [port]
    monkeypatch.setattr(system,'ports',ports)
    runtime.sample()
    assert store.events(kind='NEW_LISTENING_PORT')['total']==1
    runtime.stop.clear();runtime.sample()
    assert store.events(kind='NEW_LISTENING_PORT')['total']==1
    def denied():
        runtime.stop.set()
        raise psutil.AccessDenied()
    runtime.stop.clear();monkeypatch.setattr(system,'ports',denied);runtime.sample()
    assert store.get('ports_status')['state']=='unavailable'
    assert store.get('stats')['cpu']==1


def test_packet_must_target_local_ip():
    assert parse_packet(packet(),{'192.0.2.6'})==('192.0.2.5',8787)
    assert parse_packet(packet(),{'192.0.2.99'}) is None

@pytest.mark.parametrize('rules,expected', [('{"nftables":[]}', 'inactive'),('{"nftables":[{"chain":{"name":"input","table":"filter","family":"inet","hook":"input","policy":"drop"}}]}','active')])
def test_firewall_observation(monkeypatch,rules,expected):
    monkeypatch.setattr(firewall.shutil,'which',lambda cmd: '/usr/sbin/nft' if cmd=='nft' else None)
    monkeypatch.setattr(firewall.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=rules))
    assert firewall.inspect()['state']==expected
