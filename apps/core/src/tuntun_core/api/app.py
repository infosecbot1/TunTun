from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import Message, Receive, Scope, Send
from tuntun_core.api.dependencies import SimulatedGuestAppDependencies
from tuntun_core.api.routes.health import register_health_route
from tuntun_core.api.routes.session import register_session_route

_NO_STORE_HEADER = (b"cache-control", b"no-store")
_FORBIDDEN_BODY = b'{"status":"forbidden"}'
_TOO_LARGE_BODY = b'{"status":"too_large"}'
_UNEXPECTED_ERROR_BODY = b'{"status":"error"}'
_MAX_REQUEST_BODY_BYTES = 4096


class SimulatedGuestFastAPI(FastAPI):
    """Pure ASGI boundary for local-only simulated Guest traffic."""

    def __init__(
        self,
        *,
        loopback_host: str,
        max_body_bytes: int = _MAX_REQUEST_BODY_BYTES,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._loopback_host = loopback_host
        self._max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await super().__call__(scope, receive, send)
            return
        client = scope.get("client")
        peer = client[0] if isinstance(client, tuple) and client else None
        if peer != self._loopback_host:
            await self._send_static_json(send, status=403, body=_FORBIDDEN_BODY)
            return
        if not _declared_content_length_within_bound(
            scope.get("headers", []),
            self._max_body_bytes,
        ):
            await self._send_static_json(send, status=413, body=_TOO_LARGE_BODY)
            return
        replay_messages = await _read_bounded_request(receive, self._max_body_bytes)
        if replay_messages is None:
            await self._send_static_json(send, status=413, body=_TOO_LARGE_BODY)
            return
        replay_receive = _replay_receive(replay_messages)
        response_started = False

        async def no_store_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                updated = dict(message)
                updated["headers"] = _with_no_store(updated.get("headers", []))
                await send(updated)
                return
            await send(message)

        try:
            await super().__call__(scope, replay_receive, no_store_send)
        except Exception:
            if not response_started:
                await self._send_static_json(
                    send,
                    status=500,
                    body=_UNEXPECTED_ERROR_BODY,
                )

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


def _declared_content_length_within_bound(headers: Any, max_body_bytes: int) -> bool:
    declared_length: bytes | None = None
    max_length = str(max_body_bytes).encode("ascii")
    if not isinstance(headers, list):
        return False
    for header in headers:
        if not isinstance(header, tuple) or len(header) != 2:
            return False
        name, value = header
        if type(name) is not bytes or type(value) is not bytes:
            return False
        if name.lower() != b"content-length":
            continue
        for part in value.split(b","):
            normalized = _normalize_content_length(part, max_length)
            if normalized is None:
                return False
            if declared_length is None:
                declared_length = normalized
            elif normalized != declared_length:
                return False
    return True


def _normalize_content_length(value: bytes, max_length: bytes) -> bytes | None:
    stripped = value.strip(b" \t")
    if not stripped:
        return None
    if not all(ord("0") <= octet <= ord("9") for octet in stripped):
        return None
    normalized = stripped.lstrip(b"0") or b"0"
    if len(normalized) > len(max_length):
        return None
    if len(normalized) == len(max_length) and normalized > max_length:
        return None
    return normalized


async def _read_bounded_request(
    receive: Receive,
    max_body_bytes: int,
) -> list[Message] | None:
    total = 0
    messages: list[Message] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            messages.append(message)
            return messages
        body = message.get("body", b"")
        if type(body) is not bytes:
            return None
        total += len(body)
        if total > max_body_bytes:
            return None
        messages.append(message)
        if not message.get("more_body", False):
            return messages


def _replay_receive(messages: list[Message]) -> Receive:
    pending = iter(messages)

    async def receive() -> Message:
        try:
            return next(pending)
        except StopIteration:
            return {"type": "http.request", "body": b"", "more_body": False}

    return receive


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
    app = SimulatedGuestFastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        loopback_host=dependencies.loopback_host,
        max_body_bytes=_MAX_REQUEST_BODY_BYTES,
    )
    app.router.redirect_slashes = False
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    register_health_route(app, dependencies)
    register_session_route(app, dependencies)
    return app
