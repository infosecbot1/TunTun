from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from tuntun_core.api.dependencies import SimulatedGuestAppDependencies
from tuntun_core.api.routes.health import register_health_route
from tuntun_core.api.routes.session import register_session_route

_NO_STORE_HEADER = (b"cache-control", b"no-store")
_FORBIDDEN_BODY = b'{"status":"forbidden"}'
_TOO_LARGE_BODY = b'{"status":"too_large"}'
_MAX_REQUEST_BODY_BYTES = 4096


class LoopbackNoStoreBoundary:
    """Pure ASGI boundary for local-only simulated Guest traffic."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        loopback_host: str,
        max_body_bytes: int = _MAX_REQUEST_BODY_BYTES,
    ) -> None:
        self._app = app
        self._loopback_host = loopback_host
        self._max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        client = scope.get("client")
        peer = client[0] if isinstance(client, tuple) and client else None
        if peer != self._loopback_host:
            await self._send_static_json(send, status=403, body=_FORBIDDEN_BODY)
            return
        if _declared_content_length(scope) > self._max_body_bytes:
            await self._send_static_json(send, status=413, body=_TOO_LARGE_BODY)
            return

        async def no_store_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                updated = dict(message)
                updated["headers"] = _with_no_store(updated.get("headers", []))
                await send(updated)
                return
            await send(message)

        await self._app(scope, receive, no_store_send)

    async def _send_static_json(self, send: Send, *, status: int, body: bytes) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    _NO_STORE_HEADER,
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _declared_content_length(scope: Scope) -> int:
    headers = scope.get("headers", [])
    if not isinstance(headers, list):
        return 0
    for name, value in headers:
        if name.lower() != b"content-length":
            continue
        try:
            declared = int(value)
        except ValueError:
            return _MAX_REQUEST_BODY_BYTES + 1
        return max(declared, 0)
    return 0


def _with_no_store(headers: Any) -> list[tuple[bytes, bytes]]:
    if not isinstance(headers, list):
        return [_NO_STORE_HEADER]
    retained = [
        (name, value)
        for name, value in headers
        if name.lower() != _NO_STORE_HEADER[0]
    ]
    retained.append(_NO_STORE_HEADER)
    return retained


async def _validation_error_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    del request, exc
    return JSONResponse(
        {"status": "invalid"},
        status_code=422,
        headers={"Cache-Control": "no-store"},
    )


def create_app(dependencies: SimulatedGuestAppDependencies) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.router.redirect_slashes = False
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_middleware(
        LoopbackNoStoreBoundary,
        loopback_host=dependencies.loopback_host,
        max_body_bytes=_MAX_REQUEST_BODY_BYTES,
    )
    register_health_route(app, dependencies)
    register_session_route(app, dependencies)
    return app
