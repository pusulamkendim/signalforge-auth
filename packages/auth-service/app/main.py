from __future__ import annotations

from contextlib import asynccontextmanager
from uuid import uuid4

import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.auth.router import router as auth_router
from app.core.config import get_auth_settings
from app.core.limiter import RateLimitExceeded, limiter, _rate_limit_exceeded_handler
from app.core.middleware import AuthEnvelopeMiddleware


# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    _cfg = get_auth_settings()
    _redis = aioredis.from_url(_cfg.redis_url, decode_responses=True)
    await _redis.ping()
    app.state.redis = _redis
    yield
    await _redis.aclose()


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(title="SignalForge Auth Service", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(AuthEnvelopeMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production via env config
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    rid = str(uuid4())
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": "Invalid request payload"})


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "auth"}
