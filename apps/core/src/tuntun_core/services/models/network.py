from __future__ import annotations

import http.client
import ipaddress
import multiprocessing
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from urllib.parse import urlsplit

_NETWORK_CLEANUP_NOTE = "additional network resource cleanup failure"


def _cleanup_preserving_primary(
    resource: object,
    closer: object,
    primary_error: BaseException,
) -> None:
    try:
        closer(resource)  # type: ignore[operator]
    except BaseException:
        primary_error.add_note(_NETWORK_CLEANUP_NOTE)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, pinned_ip: str, timeout: float, deadline: float) -> None:
        self._ssl_context = ssl.create_default_context()
        super().__init__(
            hostname,
            443,
            timeout=timeout,
            context=self._ssl_context,
        )
        self._pinned_ip = pinned_ip
        self._deadline = deadline

    def connect(self) -> None:
        raw: socket.socket | None = None
        wrapped: ssl.SSLSocket | None = None
        try:
            raw = socket.create_connection((self._pinned_ip, 443), self.timeout)
            self.sock = raw
            wrapped = self._ssl_context.wrap_socket(raw, server_hostname=self.host)
            self.sock = wrapped
            if time.monotonic() >= self._deadline:
                self.close()
                raise TimeoutError("model download total deadline")
        except BaseException as error:
            if wrapped is not None:
                _cleanup_preserving_primary(wrapped, type(wrapped).close, error)
            if raw is not None and raw is not wrapped:
                _cleanup_preserving_primary(raw, type(raw).close, error)
            self.sock = None
            raise


def _resolver_child(send: Connection, hostname: str) -> None:
    try:
        values = sorted(
            {
                answer[4][0]
                for answer in socket.getaddrinfo(
                    hostname,
                    443,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                )
            }
        )
        send.send(("ok", values))
    except BaseException as error:
        with suppress(BaseException):
            send.send(("error", type(error).__name__))
    finally:
        send.close()


def _bounded_stop(process: BaseProcess, _download_deadline: float) -> None:
    cleanup_deadline = time.monotonic() + 1.0
    if process.is_alive():
        process.terminate()
    process.join(max(0.0, cleanup_deadline - time.monotonic()))
    if process.is_alive():
        process.kill()
        process.join(max(0.0, cleanup_deadline - time.monotonic()))
    if process.is_alive():
        raise RuntimeError("model resolver did not exit")


def resolve_public_addresses_bounded(hostname: str, deadline: float) -> tuple[str, ...]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("model download total deadline")
    context = multiprocessing.get_context("spawn")
    receive: Connection | None = None
    send: Connection | None = None
    process: BaseProcess | None = None
    primary_error: BaseException | None = None
    try:
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=_resolver_child, args=(send, hostname), daemon=True)
        process.start()
        send.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("model download total deadline")
        if not receive.poll(remaining):
            raise TimeoutError("model DNS deadline")
        try:
            status, payload = receive.recv()
        except EOFError as error:
            raise OSError("model DNS resolution failed") from error
        if (
            status != "ok"
            or not isinstance(payload, list)
            or not payload
            or any(not isinstance(value, str) for value in payload)
        ):
            raise OSError("model DNS resolution failed")
        try:
            addresses = tuple(payload)
            parsed_addresses = tuple(ipaddress.ip_address(value) for value in addresses)
            if any(not address.is_global or address.is_multicast for address in parsed_addresses):
                raise PermissionError("model host did not resolve only to public addresses")
        except ValueError as error:
            raise OSError("model DNS resolution failed") from error
        return addresses
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_error = primary_error
        cleanup_actions: list[tuple[object, object]] = []
        if receive is not None and not receive.closed:
            cleanup_actions.append((receive, type(receive).close))
        if send is not None and not send.closed:
            cleanup_actions.append((send, type(send).close))
        if process is not None and process.pid is not None:
            cleanup_actions.append((process, lambda value: _bounded_stop(value, deadline)))
        if process is not None:
            cleanup_actions.append((process, type(process).close))
        for resource, closer in cleanup_actions:
            try:
                closer(resource)  # type: ignore[operator]
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
                else:
                    cleanup_error.add_note(_NETWORK_CLEANUP_NOTE)
        if primary_error is None and cleanup_error is not None:
            raise cleanup_error


class DeadlineBoundResponse:
    def __init__(
        self,
        response: http.client.HTTPResponse,
        connection: _PinnedHTTPSConnection,
        deadline: float,
        per_read_timeout: float,
    ) -> None:
        self._response = response
        self._connection = connection
        self._deadline = deadline
        self._per_read_timeout = per_read_timeout
        self.status = response.status
        self.headers = response.headers

    def read(self, size: int) -> bytes:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("model download total deadline")
        sock = self._connection.sock
        if sock is None:
            raise OSError("model download connection closed")
        sock.settimeout(min(self._per_read_timeout, remaining))
        try:
            chunk = self._response.read1(size)
        except TimeoutError as error:
            raise TimeoutError("model download deadline") from error
        if time.monotonic() > self._deadline:
            raise TimeoutError("model download total deadline")
        return chunk


class PinnedHttpsTransport:
    @contextmanager
    def stream_exact(
        self,
        url: str,
        allowed_hosts: frozenset[str],
        deadline: float,
        per_read_timeout: float = 30.0,
    ) -> Iterator[DeadlineBoundResponse]:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as error:
            raise PermissionError("model URL is not allowlisted HTTPS") from error
        hostname = parsed.hostname
        if (
            parsed.scheme != "https"
            or hostname not in allowed_hosts
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or parsed.query
            or parsed.fragment
        ):
            raise PermissionError("model URL is not allowlisted HTTPS")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("model download total deadline")
        addresses = resolve_public_addresses_bounded(hostname, deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("model download total deadline")
        connection = _PinnedHTTPSConnection(
            hostname, addresses[0], min(per_read_timeout, remaining), deadline
        )
        timer = threading.Timer(remaining, connection.close)
        timer.daemon = True
        primary_error: BaseException | None = None
        try:
            timer.start()
            connection.request(
                "GET",
                parsed.path or "/",
                headers={
                    "Host": hostname,
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            yield DeadlineBoundResponse(
                connection.getresponse(), connection, deadline, per_read_timeout
            )
        except OSError as error:
            if time.monotonic() >= deadline:
                primary_error = TimeoutError("model download total deadline")
                raise primary_error from error
            primary_error = error
            raise
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_error = primary_error
            try:
                timer.cancel()
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
                else:
                    cleanup_error.add_note(_NETWORK_CLEANUP_NOTE)
            try:
                connection.close()
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
                else:
                    cleanup_error.add_note(_NETWORK_CLEANUP_NOTE)
            if primary_error is None and cleanup_error is not None:
                raise cleanup_error
