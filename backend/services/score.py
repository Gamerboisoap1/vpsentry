import time

def score(store, settings):
    deductions = []
    since = time.time() - 86400
    for kind, points, label in [('SSH_BRUTE_FORCE', 15, 'SSH brute-force activity in the last 24 hours'), ('PORT_SCAN', 10, 'Network scans in the last 24 hours')]:
        if store.events(kind=kind, since=since, limit=1)['total']:
            deductions.append({'reason': label, 'points': points})
    suspicious = {int(p.strip()) for p in settings.suspicious_ports.split(',') if p.strip().isdigit()}
    exposed = sorted({p['port'] for p in store.get('ports', []) if p['port'] in suspicious and p['exposure'] == 'Network'})
    if exposed:
        deductions.append({'reason': 'Potentially sensitive ports exposed: ' + ', '.join(map(str, exposed)), 'points': min(20, 5 * len(exposed))})
    firewall = store.get('firewall_status', {})
    firewall_state = firewall.get('state', 'unknown') if time.time() - firewall.get('updated', 0) < 180 else 'unknown'
    if firewall_state == 'inactive':
        deductions.append({'reason': 'No input firewall rules or drop policy detected', 'points': 20})
    unknown = ['Firewall state is not verified.'] if firewall_state == 'unknown' else []
    for key, label in [('ssh_status', 'SSH'), ('network_status', 'Network'), ('ports_status', 'Listening ports')]:
        status = store.get(key, {})
        max_age = max(30, settings.sample_seconds * 3) if key == 'ports_status' else 30
        if status.get('state') != 'active' or time.time() - status.get('updated', 0) > max_age:
            unknown.append(label + ' monitoring coverage is unavailable.')
    value = max(0, 100 - sum(d['points'] for d in deductions))
    return {'score': value, 'label': 'Excellent' if value >= 90 else 'Good' if value >= 75 else 'Warning' if value >= 50 else 'Critical',
            'deductions': deductions, 'unknown': unknown, 'firewall': firewall_state,
            'description': 'VPSentry Security Score is an internal indicator based on observed activity, not an industry-standard assessment. Unverified coverage does not imply safety.'}
