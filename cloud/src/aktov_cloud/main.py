"""FastAPI application entrypoint for Aktov Cloud."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aktov_cloud import __version__
from aktov_cloud.config import settings
from aktov_cloud.database import dispose_engine, init_db

logger = logging.getLogger("aktov_cloud")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown lifecycle handler."""
    logging.basicConfig(level=settings.log_level)
    logger.info("Aktov Cloud %s starting (env=%s)", __version__, settings.environment)

    if settings.environment == "dev":
        await init_db()
        logger.info("Dev mode: tables created via init_db()")

    yield

    await dispose_engine()
    logger.info("Aktov Cloud shut down.")


app = FastAPI(
    title="Aktov Cloud",
    version=__version__,
    description="Detection engineering for AI agents — trace ingestion, rule evaluation, and alert delivery.",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Include API routers
# ---------------------------------------------------------------------------
from aktov_cloud.api.traces import router as traces_router  # noqa: E402
from aktov_cloud.api.alerts import router as alerts_router  # noqa: E402
from aktov_cloud.api.agents import router as agents_router  # noqa: E402
from aktov_cloud.api.rules import router as rules_router  # noqa: E402

app.include_router(traces_router)
app.include_router(alerts_router)
app.include_router(agents_router)
app.include_router(rules_router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["meta"])
async def health_check() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "environment": settings.environment,
    }


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------
@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.exception_handler(PermissionError)
async def permission_error_handler(request: Request, exc: PermissionError) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": str(exc)})
