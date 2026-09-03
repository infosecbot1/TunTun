"""Dependency boundaries for the disposable robot-local PTT supervisor."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, Protocol, runtime_checkable

from tuntun_contracts.speech import AudioFormat


class MonotonicClock(Protocol):
    def now(self) -> float: ...

    async def sleep_until(self, deadline: float) -> None: ...


class EdgeTransportPort(Protocol):
    async def receive(self, max_bytes: int) -> bytes: ...

    async def send(self, frame: bytes) -> None: ...

    async def close(self) -> None: ...


class EdgeCaptureInputPort(Protocol):
    async def wait_for_start(self) -> None: ...

    async def wait_for_submit(self) -> None: ...


class EdgeStopInputPort(Protocol):
    async def wait_for_stop(self) -> None: ...


@runtime_checkable
class ReachyLocalMediaPort(Protocol):
    async def open_capture(
        self,
        *,
        output_format: AudioFormat,
        max_frame_bytes: int,
    ) -> None: ...

    async def read_capture(self) -> bytes | None: ...

    async def close_capture(self) -> bool: ...

    async def open_playback(self, *, input_format: AudioFormat) -> None: ...

    async def write_playback(self, pcm: bytes) -> None: ...

    async def close_playback(self) -> bool: ...

    async def stop_recording(self) -> bool: ...

    async def stop_playback(self) -> bool: ...

    async def stop_motion(self) -> bool: ...

    async def disable_audio_reactive(self) -> bool: ...


class MutableAudioBuffer(Protocol):
    def append(self, data: bytes) -> None: ...

    def take(self, max_bytes: int) -> bytes: ...

    def clear(self) -> bool: ...

    def is_empty(self) -> bool: ...


class CleanupTaskSpawner(Protocol):
    def start(
        self,
        operation: Coroutine[Any, Any, bool],
        *,
        name: str,
    ) -> asyncio.Task[bool]: ...
