"""SDK-free Reachy PTT simulator for the Task 5 supervised fake loop."""

from __future__ import annotations

import asyncio
import binascii
import os
import sys
import time
from collections import deque
from collections.abc import Coroutine
from contextlib import suppress
from typing import Any
from uuid import UUID, uuid4

from tuntun_contracts.poc.framing import (
    MAX_FEED_BYTES,
    TRANSPORT_AUDIO_FORMAT,
    PttInputMode,
    PttSessionOutcome,
)
from tuntun_contracts.speech import AudioFormat

from tuntun_edge.poc.ports import CleanupTaskSpawner
from tuntun_edge.poc.reachy_ptt import ReachyPttSession


class StdioPttTransport:
    def __init__(self, *, stdin_fd: int = 0, stdout_fd: int = 1) -> None:
        self._stdin_fd = stdin_fd
        self._stdout_fd = stdout_fd
        self._closed = False
        self._read_waiter: asyncio.Future[None] | None = None
        self._write_waiter: asyncio.Future[None] | None = None
        _make_nonblocking(stdin_fd)
        _make_nonblocking(stdout_fd)

    async def receive(self, max_bytes: int) -> bytes:
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FEED_BYTES:
            raise ValueError("invalid simulated PTT receive")
        while True:
            if self._closed:
                return b""
            try:
                return os.read(self._stdin_fd, max_bytes)
            except BlockingIOError:
                await self._wait_readable()
            except InterruptedError:
                continue

    async def send(self, frame: bytes) -> None:
        if type(frame) is not bytes or not frame:
            raise ValueError("invalid simulated PTT send")
        offset = 0
        while offset < len(frame):
            if self._closed:
                raise OSError("simulated PTT transport closed")
            try:
                written = os.write(self._stdout_fd, frame[offset:])
            except BlockingIOError:
                await self._wait_writable()
                continue
            except InterruptedError:
                continue
            if written <= 0:
                raise OSError("simulated PTT write failed")
            offset += written

    async def close(self) -> None:
        self._closed = True
        self._wake_waiter(self._read_waiter)
        self._wake_waiter(self._write_waiter)
        return None

    async def _wait_readable(self) -> None:
        await self._wait_for_fd(self._stdin_fd, writer=False)

    async def _wait_writable(self) -> None:
        await self._wait_for_fd(self._stdout_fd, writer=True)

    async def _wait_for_fd(self, fd: int, *, writer: bool) -> None:
        loop = asyncio.get_running_loop()
        waiter = loop.create_future()
        current = self._write_waiter if writer else self._read_waiter
        if current is not None:
            raise RuntimeError("simulated PTT transport concurrent wait")
        if writer:
            self._write_waiter = waiter
        else:
            self._read_waiter = waiter

        def wake() -> None:
            self._wake_waiter(waiter)

        try:
            if writer:
                loop.add_writer(fd, wake)
            else:
                loop.add_reader(fd, wake)
        except (NotImplementedError, OSError, RuntimeError):
            if writer:
                self._write_waiter = None
            else:
                self._read_waiter = None
            raise
        try:
            await waiter
        finally:
            if writer:
                with suppress(OSError, RuntimeError):
                    loop.remove_writer(fd)
                if self._write_waiter is waiter:
                    self._write_waiter = None
            else:
                with suppress(OSError, RuntimeError):
                    loop.remove_reader(fd)
                if self._read_waiter is waiter:
                    self._read_waiter = None

    @staticmethod
    def _wake_waiter(waiter: asyncio.Future[None] | None) -> None:
        if waiter is not None and not waiter.done():
            waiter.set_result(None)


class SimulatedReachyMedia:
    def __init__(self, capture_pcm: bytes) -> None:
        self._capture = deque(_chunks(capture_pcm, 3_200))
        self.playback: list[bytes] = []

    async def open_capture(self, *, output_format: AudioFormat, max_frame_bytes: int) -> None:
        if output_format != TRANSPORT_AUDIO_FORMAT or max_frame_bytes != 6_400:
            raise ValueError("invalid simulated capture")

    async def read_capture(self) -> bytes | None:
        if self._capture:
            await asyncio.sleep(0)
            return self._capture.popleft()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def close_capture(self) -> bool:
        return True

    async def open_playback(self, *, input_format: AudioFormat) -> None:
        if input_format != TRANSPORT_AUDIO_FORMAT:
            raise ValueError("invalid simulated playback")

    async def write_playback(self, pcm: bytes) -> None:
        if type(pcm) is not bytes or not pcm or len(pcm) % 2:
            raise ValueError("invalid simulated playback")
        self.playback.append(pcm)

    async def close_playback(self) -> bool:
        return True

    async def stop_recording(self) -> bool:
        return True

    async def stop_playback(self) -> bool:
        return True

    async def stop_motion(self) -> bool:
        return True

    async def disable_audio_reactive(self) -> bool:
        return True


class ScriptedReachyCaptureInput:
    async def wait_for_start(self) -> None:
        return None

    async def wait_for_submit(self) -> None:
        return None


class NeverStopInput:
    async def wait_for_stop(self) -> None:
        await asyncio.Event().wait()


class RealMonotonicClock:
    def now(self) -> float:
        return time.monotonic()

    async def sleep_until(self, deadline: float) -> None:
        await asyncio.sleep(max(0.0, deadline - self.now()))


class AsyncioTaskSpawner(CleanupTaskSpawner):
    def start(
        self,
        operation: Coroutine[Any, Any, bool],
        *,
        name: str,
    ) -> asyncio.Task[bool]:
        return asyncio.create_task(operation, name=name)


async def run_simulator(
    *,
    turn_id: UUID | None = None,
    input_mode: PttInputMode = PttInputMode.CORE_TERMINAL_TOGGLE,
    capture_pcm: bytes = b"\x01\x00\x02\x00\x03\x00\x04\x00",
    transport: StdioPttTransport | None = None,
) -> PttSessionOutcome:
    if type(input_mode) is not PttInputMode:
        raise ValueError("invalid simulated PTT input mode")
    if type(capture_pcm) is not bytes or not capture_pcm or len(capture_pcm) % 2:
        raise ValueError("invalid simulated PTT capture")
    selected_turn_id = uuid4() if turn_id is None else turn_id
    capture_input = (
        ScriptedReachyCaptureInput() if input_mode is PttInputMode.REACHY_LOCAL else None
    )
    stop_input = NeverStopInput() if input_mode is PttInputMode.REACHY_LOCAL else None
    session = ReachyPttSession(
        turn_id=selected_turn_id,
        input_mode=input_mode,
        media=SimulatedReachyMedia(capture_pcm),
        transport=StdioPttTransport() if transport is None else transport,
        capture_input=capture_input,
        stop_input=stop_input,
        capture_buffer=_Buffer(),
        playback_buffer=_Buffer(),
        clock=RealMonotonicClock(),
        task_spawner=AsyncioTaskSpawner(),
    )
    return await session.run()


def parse_capture_hex(value: str) -> bytes:
    try:
        parsed = binascii.unhexlify(value)
    except (binascii.Error, ValueError):
        raise ValueError("invalid simulated PTT capture") from None
    if not parsed or len(parsed) % 2:
        raise ValueError("invalid simulated PTT capture")
    return parsed


class _Buffer:
    def __init__(self) -> None:
        self._data = bytearray()

    def append(self, data: bytes) -> None:
        self._data.extend(data)

    def take(self, max_bytes: int) -> bytes:
        result = bytes(self._data[:max_bytes])
        del self._data[:max_bytes]
        return result

    def clear(self) -> bool:
        self._data.clear()
        return True

    def is_empty(self) -> bool:
        return not self._data


def _chunks(raw: bytes, size: int) -> tuple[bytes, ...]:
    return tuple(raw[offset : offset + size] for offset in range(0, len(raw), size))


def _make_nonblocking(fd: int) -> None:
    with suppress(OSError, ValueError):
        os.set_blocking(fd, False)


def main(
    *,
    turn_id: str | None = None,
    input_mode: PttInputMode = PttInputMode.CORE_TERMINAL_TOGGLE,
    capture_hex: str = "0100020003000400",
) -> int:
    try:
        parsed_turn_id = None if turn_id is None else UUID(turn_id)
        outcome = asyncio.run(
            run_simulator(
                turn_id=parsed_turn_id,
                input_mode=input_mode,
                capture_pcm=parse_capture_hex(capture_hex),
            )
        )
    except (Exception, ValueError):
        sys.stderr.write("simulate-ptt-rejected\n")
        return 70
    return 0 if outcome is PttSessionOutcome.COMPLETED else 1
