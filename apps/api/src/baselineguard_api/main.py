from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ExceptionHandler

from baselineguard_api.config import get_settings
from baselineguard_api.embedded import start_embedded_workers
from baselineguard_api.errors import (
    AppError,
    app_error_handler,
    http_error_handler,
    internal_error_handler,
    validation_error_handler,
)
from baselineguard_api.logging_config import configure_logging
from baselineguard_api.middleware import RequestContextMiddleware
from baselineguard_api.routes.health import router as health_router
from baselineguard_api.routes.v1.router import router as v1_router

settings = get_settings()
configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(_: FastAPI):
    stop = start_embedded_workers(settings)
    try:
        yield
    finally:
        stop()


app = FastAPI(
    title="BaselineGuard API",
    version="0.1.0",
    docs_url="/api/docs"
    if settings.docs_enabled and settings.environment != "production"
    else None,
    redoc_url=None,
    openapi_url="/api/openapi.json"
    if settings.docs_enabled and settings.environment != "production"
    else None,
    debug=False,
    lifespan=lifespan,
)
app.add_middleware(RequestContextMiddleware)
if settings.cors_origins and settings.environment != "production":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "If-Match",
            "Idempotency-Key",
            "X-CSRF-Token",
        ],
        max_age=600,
    )
app.add_exception_handler(AppError, cast(ExceptionHandler, app_error_handler))
app.add_exception_handler(StarletteHTTPException, cast(ExceptionHandler, http_error_handler))
app.add_exception_handler(RequestValidationError, cast(ExceptionHandler, validation_error_handler))
app.add_exception_handler(Exception, internal_error_handler)
app.include_router(health_router)
app.include_router(v1_router)
