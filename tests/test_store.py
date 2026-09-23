import time
from concurrent.futures import ThreadPoolExecutor
from backend.models.store import Store
from backend.services.score import score


def test_persistence_filters_and_concurrency(store, config):
    def add(n):
        store.event('SSH_FAILED_LOGIN','SSH','LOW',f'Failed login {n}', '192.0.2.1', {'attempt':n})
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(add,range(20)))
    store.event('PORT_SCAN','Network','HIGH','Simulated scan',demo=True)
    reopened=Store(config.data_dir)
    assert reopened.events()['total']==20
    assert reopened.events(demo=True)['total']==1
    assert len(reopened.events(limit=5,offset=5)['items'])==5
    assert reopened.events(query='192.0.2.1')['total']==20
    assert reopened.events(query="' OR 1=1 --")['total']==0
    assert reopened.events(category='Network')['total']==0
    reopened.set('test', {'persistent':True})
    assert Store(config.data_dir).get('test')['persistent']


def test_score_ignores_demo_and_old_events(store, config):
    store.event('SSH_BRUTE_FORCE','SSH','HIGH','Old attack',timestamp=time.time()-90000)
    store.event('PORT_SCAN','Network','HIGH','Demo',demo=True)
    assert score(store,config)['score']==100
    assert score(store,config)['unknown']
    store.event('SSH_BRUTE_FORCE','SSH','HIGH','Recent attack')
    store.event('PORT_SCAN','Network','HIGH','Recent scan')
    store.set('firewall_status',{'state':'inactive','updated':time.time()})
    store.set('ports',[{'port':6379,'exposure':'Network'}])
    assert score(store,config)['score']==50
    store.prune(1)
    assert store.events()['total']==2
