from __future__ import annotations

import asyncio
from collections import deque
from typing import Final

MAX_TURN_BYTES: Final = 8_388_608


def _require_exact_int(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact integer")
    return value


def _require_audio_bytes(value: object, *, label: str) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be bytes")
    if not value:
        raise ValueError(f"{label} must not be empty")
    return value


def _running_loop() -> asyncio.AbstractEventLoop | None:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _wipe(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)
    buffer.clear()


class AudioRing:
    """RAM-only newest-pre-roll and post-wake audio buffer for one event loop."""

    _active_turn: bool
    _owner_loop: asyncio.AbstractEventLoop | None
    _post_wake: bytearray
    _pre_roll_bytes: int
    _pre_wake: deque[bytearray]
    _pre_wake_size: int
    _turn_limit_bytes: int

    __slots__ = (
        "_active_turn",
        "_owner_loop",
        "_post_wake",
        "_pre_roll_bytes",
        "_pre_wake",
        "_pre_wake_size",
        "_turn_limit_bytes",
    )

    def __init__(
        self,
        *,
        bytes_per_second: int,
        pre_roll_seconds: int,
        turn_limit_bytes: int = MAX_TURN_BYTES,
    ) -> None:
        checked_bytes_per_second = _require_exact_int(
            bytes_per_second,
            label="bytes_per_second",
        )
        checked_pre_roll_seconds = _require_exact_int(
            pre_roll_seconds,
            label="pre_roll_seconds",
        )
        checked_turn_limit_bytes = _require_exact_int(
            turn_limit_bytes,
            label="turn_limit_bytes",
        )
        if checked_bytes_per_second <= 0 or checked_bytes_per_second > MAX_TURN_BYTES:
            raise ValueError("audio-ring-byte-rate")
        if checked_pre_roll_seconds not in {3, 4, 5}:
            raise ValueError("audio-ring-pre-roll")
        if not 1 <= checked_turn_limit_bytes <= MAX_TURN_BYTES:
            raise ValueError("audio-ring-turn-limit")

        self._owner_loop = _running_loop()
        self._pre_roll_bytes = checked_bytes_per_second * checked_pre_roll_seconds
        if self._pre_roll_bytes > MAX_TURN_BYTES:
            raise ValueError("audio-ring-pre-roll")
        self._turn_limit_bytes = checked_turn_limit_bytes
        self._pre_wake = deque()
        self._pre_wake_size = 0
        self._post_wake = bytearray()
        self._active_turn = False

    @property
    def pre_roll_bytes(self) -> int:
        return self._pre_roll_bytes

    @property
    def pre_wake_size(self) -> int:
        self._check_owner()
        return self._pre_wake_size

    @property
    def post_wake_size(self) -> int:
        self._check_owner()
        return len(self._post_wake)

    def append_pre_wake(self, chunk: bytes) -> None:
        self._check_owner()
        checked_chunk = _require_audio_bytes(chunk, label="pre_wake")
        limit = self._pre_wake_limit()
        if limit == 0:
            self._clear_pre_wake()
            return
        if len(checked_chunk) >= limit:
            self._clear_pre_wake()
            self._pre_wake.append(bytearray(checked_chunk[-limit:]))
            self._pre_wake_size = limit
            return

        self._pre_wake.append(bytearray(checked_chunk))
        self._pre_wake_size += len(checked_chunk)
        self._trim_pre_wake()

    def begin_turn(self) -> None:
        self._check_owner()
        _wipe(self._post_wake)
        self._active_turn = True
        self._trim_pre_wake()

    def append_post_wake(self, chunk: bytes) -> None:
        self._check_owner()
        checked_chunk = _require_audio_bytes(chunk, label="post_wake")
        if not self._active_turn:
            raise RuntimeError("audio-ring-turn-not-started")
        if len(checked_chunk) > self._turn_limit_bytes - len(self._post_wake):
            raise ValueError("audio-ring-turn-limit")
        self._post_wake.extend(checked_chunk)
        self._trim_pre_wake()

    def snapshot_pre_wake(self) -> bytes:
        self._check_owner()
        return b"".join(self._pre_wake)

    def snapshot_post_wake(self) -> bytes:
        self._check_owner()
        return bytes(self._post_wake)

    def snapshot_turn(self) -> bytes:
        self._check_owner()
        self._trim_pre_wake()
        return self.snapshot_pre_wake() + self.snapshot_post_wake()

    def clear(self) -> None:
        self._check_owner()
        self._clear_pre_wake()
        _wipe(self._post_wake)
        self._active_turn = False

    def _check_owner(self) -> None:
        current = _running_loop()
        if current is None:
            if self._owner_loop is not None:
                raise RuntimeError("audio-ring-event-loop-owner")
            return
        if self._owner_loop is None:
            self._owner_loop = current
            return
        if self._owner_loop is not current:
            raise RuntimeError("audio-ring-event-loop-owner")

    def _trim_pre_wake(self) -> None:
        excess = self._pre_wake_size - self._pre_wake_limit()
        while excess > 0:
            oldest = self._pre_wake[0]
            if len(oldest) <= excess:
                removed = self._pre_wake.popleft()
                excess -= len(removed)
                self._pre_wake_size -= len(removed)
                _wipe(removed)
                continue

            oldest[:excess] = b"\x00" * excess
            del oldest[:excess]
            self._pre_wake_size -= excess
            excess = 0

    def _pre_wake_limit(self) -> int:
        remaining_turn_budget = self._turn_limit_bytes - len(self._post_wake)
        if remaining_turn_budget <= 0:
            return 0
        return min(self._pre_roll_bytes, remaining_turn_budget)

    def _clear_pre_wake(self) -> None:
        while self._pre_wake:
            _wipe(self._pre_wake.popleft())
        self._pre_wake_size = 0


__all__ = ["MAX_TURN_BYTES", "AudioRing"]
