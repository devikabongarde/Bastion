from collections.abc import Mapping

import structlog
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException


class Problem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = "about:blank"
    title: str
    status: int
    code: str
    detail: str
    request_id: str
    errors: list[dict[str, str]] | None = None


class AppError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        title: str,
        detail: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.headers = dict(headers or {})


def _response(
    request: Request,
    *,
    status: int,
    code: str,
    title: str,
    detail: str,
    errors: list[dict[str, str]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    body = Problem(
        status=status,
        code=code,
        title=title,
        detail=detail,
        request_id=request_id,
        errors=errors,
    )
    return JSONResponse(
        status_code=status,
        content=body.model_dump(mode="json", exclude_none=True),
        media_type="application/problem+json",
        headers=dict(headers or {}),
    )


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    return _response(
        request,
        status=exc.status,
        code=exc.code,
        title=exc.title,
        detail=exc.detail,
        headers=exc.headers,
    )


async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    # Framework-generated details can contain URLs, headers, or implementation data.
    safe = {
        401: ("AUTHENTICATION_REQUIRED", "Authentication required", "Sign in to continue."),
        403: ("FORBIDDEN", "Access denied", "You do not have permission for this action."),
        404: ("NOT_FOUND", "Not found", "The requested resource is not available."),
        405: ("METHOD_NOT_ALLOWED", "Method not allowed", "This operation is not available."),
    }.get(
        exc.status_code, ("HTTP_ERROR", "Request rejected", "The request could not be completed.")
    )
    return _response(
        request,
        status=exc.status_code,
        code=safe[0],
        title=safe[1],
        detail=safe[2],
        headers=exc.headers,
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    safe_errors = [
        {"field": ".".join(str(part) for part in error["loc"]), "code": str(error["type"])}
        for error in exc.errors()
    ]
    return _response(
        request,
        status=422,
        code="INVALID_REQUEST",
        title="Invalid request",
        detail="One or more request fields are invalid.",
        errors=safe_errors,
    )


async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
    structlog.get_logger("api").error(
        "internal_error",
        request_id=getattr(request.state, "request_id", "unknown"),
        error_type=type(exc).__name__,
    )
    return _response(
        request,
        status=500,
        code="INTERNAL_ERROR",
        title="Internal server error",
        detail="The request could not be completed.",
    )
