from types import SimpleNamespace

from backend.monitors import defense


def test_file_integrity_creates_baseline_then_alerts(store, config, tmp_path):
    watched = tmp_path / 'important.conf'
    watched.write_text('safe=true\n')
    config.watch_files = str(watched)
    first = defense.inspect_files(store, config, now=100)
    assert first[0]['baseline'] == 'created'
    assert store.events(kind='FILE_CHANGED')['total'] == 0
    watched.write_text('safe=false\n')
    second = defense.inspect_files(store, config, now=200)
    assert second[0]['changed'] is True
    assert store.events(kind='FILE_CHANGED')['items'][0]['details']['path'] == str(watched)
    defense.inspect_files(store, config, now=300)
    assert store.events(kind='FILE_CHANGED')['total'] == 1


def test_watch_files_accepts_absolute_paths_only(config):
    config.watch_files = '/etc/passwd,relative.txt,/etc/passwd,/tmp/example'
    assert defense.watched_paths(config) == ['/etc/passwd', '/tmp/example']


def test_checklist_reports_hardening(monkeypatch, store):
    store.set('firewall_status', {'state': 'active', 'message': 'rules found'})
    monkeypatch.setattr(defense, 'effective_ssh', lambda: {'permitrootlogin': 'no', 'passwordauthentication': 'no'})
    monkeypatch.setattr(defense, 'available_updates', lambda: {'total': 2, 'security': 1})
    monkeypatch.setattr(defense.shutil, 'which', lambda name: '/bin/systemctl' if name == 'systemctl' else None)
    monkeypatch.setattr(defense, 'command', lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='active\n'))
    items = {item['id']: item for item in defense.checklist(store)}
    assert items['firewall']['status'] == 'pass'
    assert items['fail2ban']['status'] == 'pass'
    assert items['ssh_root']['status'] == 'pass'
    assert items['ssh_password']['status'] == 'pass'
    assert items['updates']['status'] == 'warn'


def test_suspicious_process_event_is_deduplicated(monkeypatch, store, config):
    process = SimpleNamespace(pid=44, info={'pid': 44, 'name': 'miner', 'username': 'nobody', 'exe': '/tmp/miner', 'memory_percent': 1.0}, cpu_percent=lambda _: 99.0)
    monkeypatch.setattr(defense.psutil, 'process_iter', lambda attrs: [process])
    monkeypatch.setattr(defense.os.path, 'lexists', lambda path: False)
    defense.inspect_processes(store, config, now=100)
    defense.inspect_processes(store, config, now=200)
    assert store.events(kind='SUSPICIOUS_PROCESS')['total'] == 1
    assert store.get('suspicious_processes')['items'][0]['pid'] == 44
