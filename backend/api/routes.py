import time
from typing import Literal
from fastapi import APIRouter, HTTPException, Query, Request, Depends
from backend.config import settings
from backend.monitors.system import users
from backend.services.auth import authorized
from backend.services.score import score

router = APIRouter(prefix='/api', dependencies=[Depends(authorized)])

def store(request):
    return request.app.state.store

@router.get('/health')
def health(request: Request):
    db = store(request)
    statuses = {}
    for name in ('ssh', 'network', 'ports'):
        status = db.get(name + '_status', {'state': 'unavailable', 'message': 'Waiting for monitor', 'updated': 0})
        if time.time() - status['updated'] > (max(30, settings.sample_seconds * 3) if name == 'ports' else 30):
            status = {**status, 'state': 'unavailable', 'message': 'Monitor has not reported recently'}
        statuses[name] = status
    stats = db.get('stats', {})
    return {'status': 'online', 'version': '0.1.0', 'port': settings.port, 'monitors': statuses, 'active_alerts': db.active_alerts(),
            'sample_seconds': settings.sample_seconds, 'sampling_ok': time.time() - stats.get('timestamp', 0) < max(30, settings.sample_seconds * 3)}

@router.get('/stats')
def stats(request: Request):
    result = store(request).get('stats')
    if not result:
        raise HTTPException(503, 'First system sample is pending')
    return {**result, 'history': store(request).history()}

@router.get('/events')
@router.get('/activity')
def events(request: Request, category: Literal['SSH', 'Network', 'System'] | None = None,
           severity: Literal['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] | None = None,
           q: str = Query('', max_length=128), limit: int = Query(50, ge=1, le=200),
           offset: int = Query(0, ge=0)):
    return store(request).events(category=category, severity=severity, query=q, limit=limit, offset=offset)

@router.get('/events/recent')
def recent(request: Request):
    return store(request).events(limit=8)

@router.get('/ssh')
def ssh(request: Request):
    db = store(request)
    return {'threshold': settings.ssh_threshold, 'window': settings.ssh_window,
            'failed_24h': db.events(kind='SSH_FAILED_LOGIN', since=time.time() - 86400, limit=1)['total'],
            'successful_24h': db.events(kind='SSH_SUCCESSFUL_LOGIN', since=time.time() - 86400, limit=1)['total'],
            'attacks_24h': db.events(kind='SSH_BRUTE_FORCE', since=time.time() - 86400, limit=1)['total'],
            'incidents': db.events(kind='SSH_BRUTE_FORCE', limit=100)['items']}

@router.get('/scans')
def scans(request: Request):
    return {'threshold': settings.scan_threshold, 'window': settings.scan_window,
            'scans_24h': store(request).events(kind='PORT_SCAN', since=time.time() - 86400, limit=1)['total'],
            'incidents': store(request).events(kind='PORT_SCAN', limit=100)['items']}

@router.get('/ports')
def ports(request: Request):
    return {'items': store(request).get('ports', []), 'status': store(request).get('ports_status')}

@router.get('/users')
def system_users():
    return {'items': users()}

@router.get('/security-score')
def security_score(request: Request):
    return score(store(request), settings)



@router.get('/attack-map')
def attack_map(request: Request):
    from backend.services.geoip import GeoIP, PROVIDER
    geo = GeoIP(store(request), settings, None)
    sources = store(request).attack_sources()
    return {**sources, 'enabled': settings.geoip_enabled, 'provider': PROVIDER,
            'items': [{**source, 'location': geo.location(source['source_ip'])} for source in sources['items']]}


@router.get('/geoip')
def geoip_lookup(request: Request, ip: str = Query(..., max_length=45)):
    import ipaddress
    from backend.services.geoip import GeoIP
    try:
        address = str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(422, 'Enter a valid IPv4 or IPv6 address')
    # Cache-only: this endpoint cannot trigger arbitrary outbound lookups.
    result = GeoIP(store(request), settings, None).location(address)
    if result['status'] == 'pending' and not any(source['source_ip'] == address for source in store(request).attack_sources()['items']):
        return {'status': 'not_requested', 'message': 'Lookups run automatically for detected attack sources from the last 24 hours'}
    return result
