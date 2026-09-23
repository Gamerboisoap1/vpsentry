from backend.models.store import Store


def test_alerts_expire_and_exclude_unrelated_and_simulated(store):
    store.event('SSH_BRUTE_FORCE', 'SSH', 'HIGH', 'attack', timestamp=1000)
    store.event('PORT_SCAN', 'Network', 'HIGH', 'scan', timestamp=1001, demo=True)
    store.event('SSH_FAILED_LOGIN', 'SSH', 'LOW', 'single failure', timestamp=1001)
    assert store.active_alerts(now=1100)['total'] == 1
    assert store.active_alerts(now=1121)['total'] == 0


def test_ongoing_old_incident_stays_visible_after_restart(store, config):
    event_id = store.event('PORT_SCAN', 'Network', 'HIGH', 'scan', timestamp=1000, details={'last_seen': 1000})
    store.update_incident(event_id, {'first_seen': 1000, 'last_seen': 5000})
    result = Store(config.data_dir).active_alerts(now=5010)
    assert result['total'] == 1
    assert result['items'][0]['id'] == event_id
    assert store.active_alerts(now=5121)['total'] == 0


def test_alerts_count_multiple_sources_and_limit_banner_rows(store):
    for n in range(8):
        store.event('SSH_BRUTE_FORCE', 'SSH', 'HIGH', 'attack', source_ip=f'192.0.2.{n}', timestamp=1000+n)
    result = store.active_alerts(now=1010)
    assert result['total'] == 8
    assert len(result['items']) == 3
    assert result['items'][0]['source_ip'] == '192.0.2.7'
