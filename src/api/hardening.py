"""M3 API hardening: environment gating, request limits, security headers,
correlation IDs and safe errors (readiness plan section 6)."""
import logging
import os
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

log = logging.getLogger("mlshield.api")


def app_env() -> str:
    """'production' unless MLSHIELD_ENV=dev. Fails closed on anything else, and
    refuses to start in production with the dev-auth switch set."""
    env = os.environ.get("MLSHIELD_ENV", "production")
    if env not in ("dev", "production"):
        raise RuntimeError(f"MLSHIELD_ENV must be 'dev' or 'production', got {env!r}")
    if env == "production" and os.environ.get("MLSHIELD_DEV_AUTH"):
        raise RuntimeError("MLSHIELD_DEV_AUTH is set but MLSHIELD_ENV is production: refusing to start")
    return env


def cors_origins(env: str) -> list[str]:
    configured = os.environ.get("MLSHIELD_CORS_ORIGINS")
    if configured:
        return [o.strip() for o in configured.split(",") if o.strip()]
    return ["http://localhost:5173", "http://127.0.0.1:5173"] if env == "dev" else []


def add_hardening(app: FastAPI, env: str) -> None:
    max_body = int(os.environ.get("MLSHIELD_MAX_BODY_BYTES", 1_000_000))
    # 0 disables. Default off in dev so the test suite and local use are not throttled.
    limit = int(os.environ.get("MLSHIELD_RATE_LIMIT", 300 if env == "production" else 0))
    window: dict[str, list] = {}  # ponytail: per-process counter keyed on socket peer (behind the proxy that is the proxy); shared limiter in Redis (M2) if needed

    @app.middleware("http")
    async def guard(request: Request, call_next):
        cid = request.headers.get("x-correlation-id") or uuid.uuid4().hex
        request.state.correlation_id = cid

        def reject(status: int, detail: str) -> JSONResponse:
            r = JSONResponse(status_code=status, content={"detail": detail, "correlation_id": cid})
            r.headers["X-Correlation-ID"] = cid
            return r

        # ponytail: checks the declared length only; chunked bodies are bounded by the proxy
        if int(request.headers.get("content-length") or 0) > max_body:
            return reject(413, "request body too large")
        if limit and not request.url.path.startswith("/health"):
            now = time.monotonic()
            key = request.client.host if request.client else "unknown"
            start, count = window.get(key, (now, 0))
            if now - start >= 60:
                start, count = now, 0
            if count >= limit:
                return reject(429, "rate limit exceeded")
            window[key] = (start, count + 1)

        response = await call_next(request)
        response.headers["X-Correlation-ID"] = cid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.exception_handler(Exception)
    async def safe_error(request: Request, exc: Exception):
        cid = getattr(request.state, "correlation_id", "unknown")
        log.exception("unhandled error, correlation_id=%s", cid)  # details stay in the server log
        return JSONResponse(status_code=500, content={"detail": "internal error", "correlation_id": cid})
