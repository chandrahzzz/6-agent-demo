"""Consistent error format: {"error": {"code", "message", "details"}}."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("mallya")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict | None = None) -> None:
        self.status, self.code, self.message, self.details = status, code, message, details or {}


def _body(code: str, message: str, details: dict | list | None = None) -> dict:
    return {"error": {"code": code, "message": message, "details": details or {}}}


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api(_: Request, exc: ApiError):
        return JSONResponse(_body(exc.code, exc.message, exc.details), status_code=exc.status)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException):
        return JSONResponse(_body("http_error", str(exc.detail)), status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        # Do not echo input values back (they could contain anything a client sent).
        errs = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
        return JSONResponse(_body("validation_error", "Request validation failed.", {"errors": errs}), status_code=422)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        # Log the exception TYPE only; messages may embed data and are kept out of logs.
        log.error("unhandled error: %s", type(exc).__name__)
        return JSONResponse(_body("internal_error", "Unexpected server error."), status_code=500)
