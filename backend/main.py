from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from backend.config import settings
from backend.models.store import Store
from backend.services.runtime import Runtime
from backend.services.auth import authorized
from backend.api.routes import router

@asynccontextmanager
async def lifespan(app):
    if settings.host not in ('127.0.0.1', '::1', 'localhost') and not settings.password_hash:
        raise RuntimeError('Set VPSENTRY_PASSWORD_HASH before binding publicly, or use VPSENTRY_HOST=127.0.0.1 for local development')
    app.state.store = Store(settings.data_dir)
    runtime = Runtime(app.state.store, settings)
    runtime.start()
    yield
    runtime.close()

app = FastAPI(title='VPSentry', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)

@app.middleware('http')
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response

if (settings.frontend_dir / 'assets').is_dir():
    app.mount('/assets', StaticFiles(directory=settings.frontend_dir / 'assets'), name='assets')

@app.get('/{path:path}', dependencies=[Depends(authorized)])
def frontend(path: str):
    if path.startswith('api/') or path not in ('', 'ssh', 'network', 'ports', 'users', 'activity', 'attack-map'):
        raise HTTPException(404, 'Not found')
    index = settings.frontend_dir / 'index.html'
    if not index.is_file():
        raise HTTPException(503, 'Build the frontend with npm run build in frontend/')
    return FileResponse(index)
