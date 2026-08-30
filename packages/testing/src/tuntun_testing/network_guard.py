from __future__ import annotations

import socket
import sys
from collections.abc import Callable
from typing import Any, Never


class NetworkDeniedError(RuntimeError):
    pass


_ORIGINAL_SOCKET = socket.socket
_INSTALLED = False
_BLOCKED_AUDIT_EVENTS = frozenset(
    {
        "socket.bind",
        "socket.connect",
        "socket.getaddrinfo",
        "socket.gethostbyaddr",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.getnameinfo",
        "socket.sendto",
    }
)


def _deny(*_args: object, **_kwargs: object) -> Never:
    raise NetworkDeniedError("network access denied")


class _GuardedSocket(_ORIGINAL_SOCKET):
    def __new__(
        cls,
        family: int = socket.AF_INET,
        type: int = socket.SOCK_STREAM,
        proto: int = 0,
        fileno: int | None = None,
    ) -> _GuardedSocket:
        if family != socket.AF_UNIX:
            raise NetworkDeniedError("network access denied")
        return _ORIGINAL_SOCKET.__new__(  # type: ignore[call-arg]
            cls,
            family,
            type,
            proto,
            fileno,
        )


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if event in _BLOCKED_AUDIT_EVENTS:
        raise NetworkDeniedError("network access denied")
    if event == "socket.__new__" and len(args) >= 2:
        family = args[1]
        if family != socket.AF_UNIX:
            raise NetworkDeniedError("network access denied")


def install_network_guard() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    socket.socket = _GuardedSocket  # type: ignore[misc]
    blocked_functions: tuple[str, ...] = (
        "create_connection",
        "getaddrinfo",
        "getfqdn",
        "gethostbyaddr",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostname",
        "getnameinfo",
    )
    for name in blocked_functions:
        setattr(socket, name, _deny)
    sys.addaudithook(_audit_hook)
    _INSTALLED = True


def guarded(function: Callable[[], int]) -> int:
    install_network_guard()
    return function()
