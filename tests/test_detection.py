from backend.monitors.detection import Detector


def line(ip='198.51.100.5', user='root', result='Failed password'):
    return f'Jan 1 sshd[10]: {result} for invalid user {user} from {ip} port 45678 ssh2'


def test_brute_force_threshold_and_dedup(store, config):
    detector = Detector(store, config)
    for n in range(4):
        detector.ssh(line(), 1000 + n)
    assert store.events(kind='SSH_BRUTE_FORCE')['total'] == 0
    for n in range(4, 30):
        detector.ssh(line(), 1000 + n)
    attack = store.events(kind='SSH_BRUTE_FORCE')
    assert attack['total'] == 1
    assert attack['items'][0]['details']['attempts'] == 30
    assert attack['items'][0]['details']['first_seen'] == 1000
    assert store.events(kind='SSH_FAILED_LOGIN')['total'] == 30
    for n in range(5):
        detector.ssh(line(), 2000 + n)
    assert store.events(kind='SSH_BRUTE_FORCE')['total'] == 2


def test_window_ip_isolation_and_success(store, config):
    detector = Detector(store, config)
    for n in range(5):
        detector.ssh(line(), 1000 + 61*n)
        detector.ssh(line(ip=f'198.51.100.{n+10}'), 1000+n)
    assert store.events(kind='SSH_BRUTE_FORCE')['total'] == 0
    detector.ssh(line('2001:db8::1', 'admin', 'Accepted publickey'), 1400)
    event = store.events(kind='SSH_SUCCESSFUL_LOGIN')['items'][0]
    assert event['source_ip'] == '2001:db8::1'
    assert event['details']['username'] == 'admin'
    assert not detector.ssh('some unrelated log line')
    assert not detector.ssh(line('999.999.999.999'))


def test_scan_unique_ports_window_and_dedup(store, config):
    detector = Detector(store, config)
    for n in range(10):
        detector.probe('192.0.2.7', 22, 1000+n)
    assert store.events(kind='PORT_SCAN')['total'] == 0
    for port in [80, 443, 8080, 9000, 1234]:
        detector.probe('192.0.2.7', port, 1020)
    result = store.events(kind='PORT_SCAN')
    assert result['total'] == 1
    assert result['items'][0]['details']['ports'] == [22,80,443,1234,8080,9000]
    detector.probe('192.0.2.7', 5000, 2000)
    assert store.events(kind='PORT_SCAN')['total'] == 1
