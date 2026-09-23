import time
import pytest
from fastapi.testclient import TestClient
from backend.config import settings
from backend.main import app
from backend.models.store import Store
from backend.monitors import system

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'host', '127.0.0.1')
    monkeypatch.setattr(settings, 'data_dir', tmp_path)
    with TestClient(app) as client:
        for _ in range(40):
            if app.state.store.get('stats'):
                break
            time.sleep(.05)
        yield client

@pytest.mark.parametrize('path',['/api/health','/api/stats','/api/events','/api/events/recent','/api/ssh','/api/scans','/api/ports','/api/users','/api/security-score','/api/activity','/api/attack-map','/api/geoip?ip=192.0.2.1'])
def test_endpoints(client,path):
    response=client.get(path)
    assert response.status_code==200
    assert response.headers['cache-control']=='no-store'

@pytest.mark.parametrize('path',['/','/ssh','/network','/ports','/users','/activity','/attack-map'])
def test_production_routes(client,path):
    response=client.get(path)
    assert response.status_code==200
    assert '<div id="root">' in response.text
    assert 'text/html' in response.headers['content-type']

def test_validation_and_removed_simulation(client):
    assert client.get('/api/events?limit=9999').status_code==422
    assert client.get('/api/events?severity=invalid').status_code==422
    assert client.get('/api/events?offset=-1').status_code==422
    assert client.get('/api/missing').status_code==404
    assert client.post('/api/demo/events',json={'type':'PORT_SCAN'}).status_code==405
    app.state.store.event('PORT_SCAN','Network','HIGH','Legacy simulated row',demo=True)
    assert client.get('/api/events?demo=true').json()['total']==client.get('/api/events').json()['total']
    assert all(not event['demo'] for event in client.get('/api/events?demo=true').json()['items'])
    assert client.get('/api/scans').json()['scans_24h']==0
    assert client.get('/api/stats').status_code==200
    assert client.get('/ssh').status_code==200


def test_real_metrics(client):
    data=client.get('/api/stats').json()
    assert data['ram']['total']>0
    assert data['disk']['total']>0
    assert data['uptime']>0
    assert 0<=data['cpu']<=100
    assert data['hostname']==system.stats()['hostname']


def test_stale_monitor(client):
    app.state.store.set('network_status',{'state':'active','message':'old','updated':time.time()-100})
    assert client.get('/api/health').json()['monitors']['network']['state']=='unavailable'


def test_public_bind_without_login(monkeypatch,tmp_path):
    monkeypatch.setattr(settings,'host','0.0.0.0')
    monkeypatch.setattr(settings,'data_dir',tmp_path)
    with TestClient(app) as public_client:
        assert public_client.get('/api/health').status_code == 200


def test_map_excludes_demo_and_geoip_validates_ip(client):
    app.state.store.event('PORT_SCAN','Network','HIGH','Observed scan','192.0.2.10')
    app.state.store.event('PORT_SCAN','Network','HIGH','Legacy simulated scan','192.0.2.11',demo=True)
    data = client.get('/api/attack-map').json()
    assert data['total'] == 1
    assert data['items'][0]['location']['status'] == 'private'
    assert client.get('/api/geoip?ip=https://example.com').status_code == 422
    assert client.get('/api/geoip?ip=8.8.8.8').json()['status'] == 'not_requested'
