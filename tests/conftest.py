import pytest
from backend.config import Settings
from backend.models.store import Store

@pytest.fixture
def config(tmp_path):
    return Settings(_env_file=None, host='127.0.0.1', data_dir=tmp_path, ssh_threshold=5, scan_threshold=5)

@pytest.fixture
def store(config):
    return Store(config.data_dir)
