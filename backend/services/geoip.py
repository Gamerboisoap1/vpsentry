"""Cached, optional HTTPS enrichment. Never contacts an observed IP directly."""
import ipaddress
import json
import math
import ssl
import certifi
import time
import urllib.error
import urllib.request

PROVIDER = 'ipwho.is'


def public_ip(value):
    try:
        if '%' in value:
            return None
        ip = ipaddress.ip_address(value)
        return str(ip) if ip.is_global and not ip.is_multicast else None
    except ValueError:
        return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_location(ip):
    """Fixed provider URL and bounded, validated response; no credentials sent."""
    if not public_ip(ip):
        return {'status': 'private', 'message': 'Non-public address; no lookup sent'}
    request = urllib.request.Request(f'https://ipwho.is/{ip}?fields=ip,success,country,country_code,city,latitude,longitude,connection.isp',
                                     headers={'User-Agent': 'VPSentry/0.1 GeoIP', 'Accept': 'application/json'})
    with urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certifi.where()))).open(request, timeout=4) as response:
        raw = response.read(16385)
    if len(raw) > 16384:
        raise ValueError('GeoIP response too large')
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get('success') is not True or ipaddress.ip_address(data.get('ip', '')) != ipaddress.ip_address(ip):
        raise ValueError('GeoIP result did not match the requested address')
    lat, lon = data.get('latitude'), data.get('longitude')
    if any(isinstance(v, bool) or not isinstance(v, (float, int)) or not math.isfinite(v) for v in (lat, lon)) or not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError('Invalid GeoIP coordinates')
    def label(value, length=100):
        return value[:length] if isinstance(value, str) else ''
    connection = data.get('connection')
    return {'status': 'located', 'country': label(data.get('country')), 'country_code': label(data.get('country_code'), 2),
            'city': label(data.get('city')), 'latitude': lat, 'longitude': lon,
            'isp': label(connection.get('isp')) if isinstance(connection, dict) else '', 'provider': PROVIDER}


class GeoIP:
    def __init__(self, store, settings, stop):
        self.store, self.settings, self.stop = store, settings, stop

    def location(self, ip):
        if not self.settings.geoip_enabled:
            return {'status': 'disabled', 'message': 'Online GeoIP is disabled'}
        if not public_ip(ip):
            return {'status': 'private', 'message': 'Non-public address; no lookup sent'}
        cached = self.store.get('geoip:' + ip)
        if cached and cached['expires'] > time.time():
            return cached['location']
        status = self.store.get('geoip_status', {})
        if status.get('retry_at', 0) > time.time():
            return {'status': 'rate_limited', 'message': 'Lookup allowance reached; retry scheduled'}
        return {'status': 'pending', 'message': 'Queued for background lookup'}

    def enrich_one(self, ip):
        if not self.settings.geoip_enabled or not public_ip(ip):
            return False
        now = time.time()
        cached = self.store.get('geoip:' + ip)
        if cached and cached['expires'] > now:
            return False
        if self.store.get('geoip_status', {}).get('retry_at', 0) > now:
            return False
        # Rolling 24-hour budget survives restarts. Leave headroom below provider limits.
        budget = self.store.get('geoip_budget', {'started': now, 'used': 0})
        if now - budget['started'] >= 86400:
            budget = {'started': now, 'used': 0}
        if budget['used'] >= self.settings.geoip_daily_limit:
            self.store.set('geoip_status', {'retry_at': budget['started'] + 86400})
            return False
        budget['used'] += 1
        self.store.set('geoip_budget', budget)
        ttl = 7 * 86400
        try:
            result = fetch_location(ip)
        except urllib.error.HTTPError as error:
            ttl = 900
            if error.code == 429:
                try:
                    ttl = min(86400, max(60, int(error.headers.get('Retry-After', '86400'))))
                except (TypeError, ValueError):
                    ttl = 86400
                self.store.set('geoip_status', {'retry_at': now + ttl})
            result = {'status': 'unavailable', 'message': 'GeoIP provider unavailable; lookup will retry'}
        except (OSError, ValueError, TypeError):
            ttl = 900
            result = {'status': 'unavailable', 'message': 'GeoIP provider unavailable; lookup will retry'}
        self.store.set('geoip:' + ip, {'expires': now + ttl, 'location': result})
        return True

    def run(self):
        while not self.stop.is_set():
            try:
                if self.settings.geoip_enabled:
                    for source in self.store.attack_sources()['items']:
                        if self.stop.is_set():
                            break
                        if self.enrich_one(source['source_ip']):
                            if self.stop.wait(3):
                                break
            except Exception:
                # Optional enrichment must never stop host/security monitoring.
                import logging
                logging.getLogger(__name__).exception('GeoIP enrichment failed')
            self.stop.wait(10)
