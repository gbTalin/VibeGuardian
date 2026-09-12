from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from cg_threat_intel.api import router
from cg_threat_intel.config import get_settings
from cg_threat_intel.db import Base, engine
from cg_threat_intel.integrations import router as integration_router
from cg_threat_intel.demo import router as demo_router
from cg_threat_intel.release_events import router as release_event_router
from cg_threat_intel.webhooks import router as webhook_router

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Temporary local-development bootstrap. Replace with Alembic migrations before production.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="CyberGuard Threat Intelligence Plugin",
    version="0.1.0",
    description="Production vulnerability intelligence and posture service for CyberGuard.",
    lifespan=lifespan,
)
app.include_router(router, prefix=settings.api_prefix)
app.include_router(webhook_router, prefix=settings.api_prefix)
app.include_router(release_event_router, prefix=settings.api_prefix)
app.include_router(integration_router, prefix=settings.api_prefix)
app.include_router(demo_router, prefix=settings.api_prefix)
app.mount("/ui", StaticFiles(directory="src/cg_threat_intel/static", html=True), name="ui")


@app.get("/health", tags=["platform"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}
