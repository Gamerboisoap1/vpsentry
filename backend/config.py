from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='VPSENTRY_', env_file='.env', extra='ignore')
    host: str = '0.0.0.0'
    port: int = Field(8787, ge=1, le=65535)
    data_dir: Path = ROOT / 'data'
    frontend_dir: Path = ROOT / 'frontend/dist'
    geoip_enabled: bool = True
    geoip_daily_limit: int = Field(500, ge=1, le=1000)
    ssh_source: str = 'journal'
    auth_log: Path = Path('/var/log/auth.log')
    ssh_threshold: int = Field(5, ge=2, le=4096)
    ssh_window: int = Field(60, ge=1, le=3600)
    scan_threshold: int = Field(10, ge=2, le=4096)
    scan_window: int = Field(60, ge=1, le=3600)
    sample_seconds: int = Field(5, ge=2, le=300)
    retention_days: int = Field(30, ge=1, le=3650)
    suspicious_ports: str = '23,3389,6379,27017'

settings = Settings()
