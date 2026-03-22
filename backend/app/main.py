"""
CYPHER AI — FastAPI Main Application
"""
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from app.core.config import settings
from app.core.database import engine, Base
from app.api import (
    auth_router, incidents_router, alerts_router,
    integrations_router, actions_router, playbooks_router,
    iocs_router, reports_router, webhooks_router,
    ws_router, organizations_router, clients_router,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("cypher_starting", env=settings.APP_ENV)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title="CYPHER AI API",
    description="AI-Powered Security Incident Response Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.APP_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Instrumentator().instrument(app).expose(app, endpoint="/metrics")

PREFIX = settings.API_V1_PREFIX
app.include_router(auth_router,          prefix=f"{PREFIX}/auth",          tags=["Auth"])
app.include_router(organizations_router, prefix=f"{PREFIX}/organizations",  tags=["Organizations"])
app.include_router(clients_router,       prefix=f"{PREFIX}/clients",        tags=["Clients"])
app.include_router(incidents_router,     prefix=f"{PREFIX}/incidents",      tags=["Incidents"])
app.include_router(alerts_router,        prefix=f"{PREFIX}/alerts",         tags=["Alerts"])
app.include_router(integrations_router,  prefix=f"{PREFIX}/integrations",   tags=["Integrations"])
app.include_router(actions_router,       prefix=f"{PREFIX}/actions",        tags=["Actions"])
app.include_router(playbooks_router,     prefix=f"{PREFIX}/playbooks",      tags=["Playbooks"])
app.include_router(iocs_router,          prefix=f"{PREFIX}/iocs",           tags=["IOCs"])
app.include_router(reports_router,       prefix=f"{PREFIX}/reports",        tags=["Reports"])
app.include_router(webhooks_router,      prefix=f"{PREFIX}/webhooks",       tags=["Webhooks"])
app.include_router(ws_router,            prefix="/ws",                       tags=["WebSocket"])


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "service": "CYPHER AI", "version": "1.0.0"}
