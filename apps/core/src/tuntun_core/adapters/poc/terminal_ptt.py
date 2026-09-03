from __future__ import annotations

import asyncio
import os
import sys
import termios
import time
import tty
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Protocol

from tuntun_core.services.poc.ports import CorePttEvent


class TerminalModePort(Protocol):
    def enter(self) -> object: ...

    def restore(self, token: object) -> None: ...


class PosixTerminalMode:
    def __init__(self, fd: int | None = None) -> None:
        self._fd = sys.stdin.fileno() if fd is None else fd

    def enter(self) -> object:
        prior = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)
        return prior

    def restore(self, token: object) -> None:
        if isinstance(token, list):
            termios.tcsetattr(self._fd, termios.TCSADRAIN, token)


class ScriptedTerminalBytes:
    def __init__(self, keys: list[bytes] | tuple[bytes, ...] = ()) -> None:
        self._keys = deque(keys)
        self._ready = asyncio.Event()
        if self._keys:
            self._ready.set()

    def push(self, key: bytes) -> None:
        self._keys.append(key)
        self._ready.set()

    async def read(self) -> bytes:
        while not self._keys:
            self._ready.clear()
            await self._ready.wait()
        return self._keys.popleft()


async def read_stdin_byte(fd: int | None = None) -> bytes:
    selected_fd = sys.stdin.fileno() if fd is None else fd
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, os.read, selected_fd, 1)


class TerminalPttInput:
    def __init__(
        self,
        byte_reader: Callable[[], Awaitable[bytes]] = read_stdin_byte,
        *,
        terminal_mode: TerminalModePort | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        debounce_seconds: float = 0.15,
    ) -> None:
        if debounce_seconds < 0:
            raise ValueError("invalid-terminal-ptt")
        self._byte_reader = byte_reader
        self._terminal_mode = PosixTerminalMode() if terminal_mode is None else terminal_mode
        self._monotonic = monotonic
        self._debounce_seconds = debounce_seconds
        self._armed = False
        self._last_space_at: float | None = None
        self._closed = False

    async def receive(self) -> CorePttEvent:
        if self._closed:
            raise RuntimeError("terminal-ptt-closed")
        token = self._terminal_mode.enter()
        try:
            while True:
                raw = await self._byte_reader()
                if type(raw) is not bytes or len(raw) != 1:
                    continue
                if raw == b"\x1b":
                    self._armed = False
                    return CorePttEvent.CANCEL
                if raw != b" ":
                    continue
                now = self._monotonic()
                last_space_at = self._last_space_at
                self._last_space_at = now
                if (
                    last_space_at is not None
                    and self._debounce_seconds
                    and now - last_space_at < self._debounce_seconds
                ):
                    continue
                if not self._armed:
                    self._armed = True
                    return CorePttEvent.START
                self._armed = False
                return CorePttEvent.SUBMIT
        finally:
            self._terminal_mode.restore(token)

    async def close(self) -> None:
        self._closed = True
