import uvicorn
from backend.config import settings
uvicorn.run('backend.main:app', host=settings.host, port=settings.port, proxy_headers=False)
