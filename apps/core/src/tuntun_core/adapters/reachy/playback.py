from __future__ import annotations

import asyncio
import contextlib
import math
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from tuntun_contracts.reachy import ReachyCommand, ReachyReceipt, ReachyState

PLAYBACK_STREAM_MAX_BYTES = 8_388_608
MAX_COMMAND_TIMEOUT_SECONDS = 30.0
MAX_MEDIA_CLOSE_SECONDS = 5.0


class ReachySender(Protocol):
    async def send(self, command: ReachyCommand) -> ReachyReceipt: ...


class MediaRegistry(Protocol):
    async def register_bounded_playback(
        self,
        stream_id: UUID,
        turn_id: UUID,
        audio: AsyncIterator[bytes],
        *,
        max_bytes: int,
    ) -> None: ...

    async def close(self, stream_id: UUID) -> None: ...


class AudioConverter(Protocol):
    def convert(
        self,
        audio: AsyncIterator[bytes],
        source: object,
        target: object,
    ) -> AsyncIterator[bytes]: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class ReachyPlaybackAdapter:
    """Private workflow convenience adapter; the public dependency remains ReachyPort."""

    def __init__(
        self,
        reachy: ReachySender,
        media: MediaRegistry,
        converter: AudioConverter,
        clock: Clock,
        source_format: object,
        reachy_format: object,
        *,
        command_timeout: float = 2.0,
        close_timeout: float = 1.0,
    ) -> None:
        self._reachy = reachy
        self._media = media
        self._converter = converter
        self._clock = clock
        self._source_format = source_format
        self._reachy_format = reachy_format
        self._command_timeout = _bounded_positive_float(
            command_timeout,
            "reachy_command_timeout",
            MAX_COMMAND_TIMEOUT_SECONDS,
        )
        self._close_timeout = _bounded_positive_float(
            close_timeout,
            "reachy_media_close_timeout",
            MAX_MEDIA_CLOSE_SECONDS,
        )
        self._close_degradation_codes: tuple[str, ...] = ()

    @property
    def close_degradation_codes(self) -> tuple[str, ...]:
        return self._close_degradation_codes

    async def play(self, turn_id: UUID, audio: AsyncIterator[bytes]) -> None:
        if type(turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        if not hasattr(audio, "__aiter__"):
            raise TypeError("playback audio must be an async iterator")
        stream_id = uuid4()
        registered = False
        try:
            converted = self._converter.convert(audio, self._source_format, self._reachy_format)
            if not hasattr(converted, "__aiter__"):
                raise TypeError("converted playback audio must be an async iterator")
            await self._media.register_bounded_playback(
                stream_id,
                turn_id,
                converted,
                max_bytes=PLAYBACK_STREAM_MAX_BYTES,
            )
            registered = True
            command = ReachyCommand(
                command_id=uuid4(),
                turn_id=turn_id,
                kind="playback",
                state=None,
                media_stream_id=stream_id,
                gesture_id=None,
                expires_at=self._clock.now() + timedelta(seconds=2),
            )
            receipt = await asyncio.wait_for(
                self._reachy.send(command),
                timeout=self._command_timeout,
            )
            if type(receipt) is not ReachyReceipt or receipt.command_id != command.command_id:
                raise RuntimeError("reachy_receipt_binding_mismatch")
            if not receipt.accepted:
                raise RuntimeError("reachy_playback_rejected")
        except asyncio.CancelledError:
            if registered:
                await self._close_registered_stream(stream_id)
            raise
        except BaseException:
            if registered:
                await self._close_registered_stream(stream_id)
            raise

    async def set_state(self, state: ReachyState, turn_id: UUID | None = None) -> None:
        if not isinstance(state, ReachyState):
            raise TypeError("reachy state must be a ReachyState")
        if turn_id is not None and type(turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        command = ReachyCommand(
            command_id=uuid4(),
            turn_id=turn_id,
            kind="state",
            state=state,
            media_stream_id=None,
            gesture_id=None,
            expires_at=self._clock.now() + timedelta(seconds=2),
        )
        receipt = await asyncio.wait_for(self._reachy.send(command), timeout=self._command_timeout)
        if type(receipt) is not ReachyReceipt or receipt.command_id != command.command_id:
            raise RuntimeError("reachy_receipt_binding_mismatch")
        if not receipt.accepted:
            raise RuntimeError("reachy_state_rejected")

    async def _close_registered_stream(self, stream_id: UUID) -> None:
        close_task = self._spawn_close_task(stream_id)
        if close_task is None:
            return
        cancellations = 0
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._close_timeout
        while not close_task.done():
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                await asyncio.wait_for(asyncio.shield(close_task), timeout=remaining)
            except TimeoutError:
                break
            except asyncio.CancelledError:
                cancellations += 1
                continue

        if close_task.done():
            try:
                close_task.result()
            except BaseException as exc:
                self._record_close_degradation(f"media_close:{type(exc).__name__}")
        else:
            close_task.cancel()
            close_task.add_done_callback(_consume_task_exception)
            self._record_close_degradation("media_close:timeout")
        if cancellations:
            self._record_close_degradation("media_close:cancelled_deferred")

    def _spawn_close_task(self, stream_id: UUID) -> asyncio.Task[None] | None:
        try:
            coroutine = self._media.close(stream_id)
        except BaseException:
            self._record_close_degradation("media_close:factory_unavailable")
            return None
        try:
            return asyncio.create_task(coroutine, name="reachy_playback_media_close")
        except BaseException:
            with contextlib.suppress(BaseException):
                coroutine.close()

        try:
            fallback = self._media.close(stream_id)
        except BaseException:
            self._record_close_degradation("media_close:factory_unavailable")
            return None
        try:
            task = asyncio.Task(
                fallback,
                loop=asyncio.get_running_loop(),
                name="reachy_playback_media_close",
            )
        except BaseException:
            with contextlib.suppress(BaseException):
                fallback.close()
            self._record_close_degradation("media_close:factory_unavailable")
            return None
        self._record_close_degradation("media_close:factory_fallback")
        return task

    def _record_close_degradation(self, code: str) -> None:
        if code not in self._close_degradation_codes:
            self._close_degradation_codes = (*self._close_degradation_codes, code)


def _bounded_positive_float(value: float, label: str, maximum: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or value <= 0 or value > maximum:
        raise ValueError(f"{label}_positive_required")
    return float(value)


def _consume_task_exception(task: asyncio.Task[None]) -> None:
    with contextlib.suppress(BaseException):
        task.result()


__all__ = ("PLAYBACK_STREAM_MAX_BYTES", "ReachyPlaybackAdapter")
