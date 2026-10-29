from time import perf_counter
from uuid import uuid4

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid4())
        request.state.request_id = request_id
        started = perf_counter()
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id, method=request.method)
        try:
            response = await call_next(request)
        except Exception:
            structlog.get_logger("http").exception("request_unhandled_error", path=request.url.path)
            raise
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        structlog.get_logger("http").info(
            "request_complete",
            route=getattr(request.scope.get("route"), "path", "unmatched"),
            status_code=response.status_code,
            duration_ms=round((perf_counter() - started) * 1000, 2),
        )
        structlog.contextvars.clear_contextvars()
        return response
