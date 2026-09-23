import io
import json
import threading
import time
import urllib.error
import pytest
from backend.services import geoip

@pytest.mark.parametrize('address', ['127.0.0.1','10.1.1.1','192.0.2.1','::1','fc00::1','224.0.0.1','ff02::1','https://example.com','2606:4700::1%eth0'])
def test_nonpublic_ips_never_leave_host(address, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Network access is forbidden for this input')
    monkeypatch.setattr(geoip.urllib.request, 'build_opener', forbidden)
    assert geoip.fetch_location(address)['status'] == 'private'


def test_geoip_cache_and_budget_persist(store, config, monkeypatch):
    calls=[]
    config.geoip_daily_limit=1
    monkeypatch.setattr(geoip, 'fetch_location', lambda ip: calls.append(ip) or {'status':'located','country':'Example country','latitude':10,'longitude':20})
    worker=geoip.GeoIP(store,config,threading.Event())
    assert worker.enrich_one('8.8.8.8')
    assert not worker.enrich_one('8.8.8.8')
    restarted=geoip.GeoIP(store,config,threading.Event())
    assert restarted.location('8.8.8.8')['status']=='located'
    assert not restarted.enrich_one('1.1.1.1')
    assert calls==['8.8.8.8']
    assert restarted.location('1.1.1.1')['status']=='rate_limited'


def test_rate_limit_stops_all_lookups(store, config, monkeypatch):
    def limited(ip):
        raise urllib.error.HTTPError('https://ipwho.is',429,'Rate limit',{'Retry-After':'3600'},None)
    monkeypatch.setattr(geoip,'fetch_location',limited)
    worker=geoip.GeoIP(store,config,threading.Event())
    assert worker.enrich_one('8.8.8.8')
    assert not worker.enrich_one('1.1.1.1')
    assert worker.location('8.8.8.8')['status']=='unavailable'
    assert store.get('geoip_status')['retry_at']>time.time()+3500


def test_disabled_lookup_and_failure_cache(store, config, monkeypatch):
    def failure(ip):
        raise OSError('offline')
    monkeypatch.setattr(geoip,'fetch_location',failure)
    worker=geoip.GeoIP(store,config,threading.Event())
    config.geoip_enabled=False
    assert not worker.enrich_one('8.8.8.8')
    assert worker.location('8.8.8.8')['status']=='disabled'
    config.geoip_enabled=True
    assert worker.enrich_one('8.8.8.8')
    assert not worker.enrich_one('8.8.8.8')
    assert worker.location('8.8.8.8')['status']=='unavailable'


@pytest.mark.parametrize('patch',[{'latitude':999},{'longitude':float('nan')},{'ip':'1.1.1.1'},{'success':False},{'latitude':True}])
def test_provider_response_validation(patch, monkeypatch):
    data={'success':True,'ip':'8.8.8.8','latitude':20,'longitude':30,**patch}
    class Opener:
        def open(self, request, timeout):
            assert request.full_url.startswith('https://ipwho.is/8.8.8.8?')
            assert timeout==4
            return io.BytesIO(json.dumps(data).encode())
    monkeypatch.setattr(geoip.urllib.request,'build_opener',lambda *args: Opener())
    with pytest.raises(ValueError):
        geoip.fetch_location('8.8.8.8')


def test_valid_response_only_retains_required_fields(monkeypatch):
    data={'success':True,'ip':'8.8.8.8','latitude':20,'longitude':30,'country':'Example','country_code':'EX','city':'Example city','connection':{'isp':'Example network'},'unneeded':'discard me'}
    class Opener:
        def open(self, request, timeout): return io.BytesIO(json.dumps(data).encode())
    monkeypatch.setattr(geoip.urllib.request,'build_opener',lambda *args: Opener())
    result=geoip.fetch_location('8.8.8.8')
    assert result['status']=='located'
    assert result['isp']=='Example network'
    assert 'unneeded' not in result


def test_attack_source_aggregation_uses_recent_observations(store):
    old=store.event('PORT_SCAN','Network','HIGH','Ongoing scan','8.8.8.8',timestamp=1000)
    store.update_incident(old, {'last_seen':100000})
    store.event('SSH_BRUTE_FORCE','SSH','HIGH','Attack','8.8.8.8',timestamp=100000)
    store.event('PORT_SCAN','Network','HIGH','Old scan','1.1.1.1',timestamp=1000)
    store.event('PORT_SCAN','Network','HIGH','Simulated','9.9.9.9',timestamp=100000,demo=True)
    result=store.attack_sources(now=100010)
    assert result['total']==1
    assert result['items'][0]['incidents']==2
    assert set(result['items'][0]['types'])=={'PORT_SCAN','SSH_BRUTE_FORCE'}
