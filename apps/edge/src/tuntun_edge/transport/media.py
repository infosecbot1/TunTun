from __future__ import annotations

import math
from _thread import LockType
from threading import Lock
from typing import Final

from tuntun_contracts.reachy_media import (
    MAX_AUDIO_PAYLOAD,
    MAX_CAMERA_PAYLOAD,
    MAX_HEADER,
    PREFIX,
    CameraWindow,
    parse_prefix,
)

AUDIO_TURN_MAX_SECONDS: Final = 90.0
AUDIO_TURN_MAX_BYTES: Final = 8_388_608
AUDIO_MIN_FRAME_INTERVAL_SECONDS: Final = 0.02
AUDIO_MIN_FRAME_DURATION_MS: Final = 1
AUDIO_MAX_FRAME_DURATION_MS: Final = 200


def _require_exact_int(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    return value


def _require_mono_time(value: object, *, label: str) -> float:
    if type(value) is int:
        result = float(value)
    elif type(value) is float:
        result = value
    else:
        raise TypeError(f"{label} must be a number")
    if not math.isfinite(result):
        raise ValueError("audio monotonic time invalid")
    return result


class MediaQuota:
    _bytes_received: int
    _initialized: bool
    _last_frame_mono: float | None
    _lock: LockType
    _started_mono: float

    __slots__ = (
        "_bytes_received",
        "_initialized",
        "_last_frame_mono",
        "_lock",
        "_started_mono",
    )

    def __init__(
        self,
        started_mono: float,
        last_frame_mono: float | None = None,
        bytes_received: int = 0,
    ) -> None:
        if getattr(self, "_initialized", False):
            raise RuntimeError("audio quota already initialized")

        checked_started_mono = _require_mono_time(
            started_mono,
            label="audio started monotonic time",
        )
        checked_last_frame_mono = None
        if last_frame_mono is not None:
            checked_last_frame_mono = _require_mono_time(
                last_frame_mono,
                label="audio last frame monotonic time",
            )
            if checked_last_frame_mono < checked_started_mono:
                raise ValueError("audio monotonic time rollback")
            if checked_last_frame_mono - checked_started_mono > AUDIO_TURN_MAX_SECONDS:
                raise ValueError("audio turn duration cap exceeded")
        checked_bytes_received = _require_exact_int(
            bytes_received,
            label="audio bytes received",
        )
        if not 0 <= checked_bytes_received <= AUDIO_TURN_MAX_BYTES:
            raise ValueError("audio turn byte cap exceeded")

        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_started_mono", checked_started_mono)
        object.__setattr__(self, "_last_frame_mono", checked_last_frame_mono)
        object.__setattr__(self, "_bytes_received", checked_bytes_received)
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("audio quota state is read-only")
        object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        return (
            f"MediaQuota(started_mono={self._started_mono!r}, "
            f"last_frame_mono={self._last_frame_mono!r}, "
            f"bytes_received={self._bytes_received!r})"
        )

    @property
    def started_mono(self) -> float:
        return self._started_mono

    @property
    def last_frame_mono(self) -> float | None:
        return self._last_frame_mono

    @property
    def bytes_received(self) -> int:
        return self._bytes_received

    def accept_audio(self, payload_size: int, duration_ms: int, now_mono: float) -> None:
        with self._lock:
            checked_payload_size = _require_exact_int(
                payload_size,
                label="audio payload size",
            )
            checked_duration_ms = _require_exact_int(duration_ms, label="audio duration")
            checked_now_mono = _require_mono_time(now_mono, label="audio monotonic time")
            self._validate_current_state()

            if not 0 <= checked_payload_size <= MAX_AUDIO_PAYLOAD:
                raise ValueError("audio frame byte cap exceeded")
            if (
                not AUDIO_MIN_FRAME_DURATION_MS
                <= checked_duration_ms
                <= AUDIO_MAX_FRAME_DURATION_MS
            ):
                raise ValueError("audio frame duration cap exceeded")
            if checked_now_mono < self._started_mono:
                raise ValueError("audio monotonic time rollback")
            if checked_now_mono - self._started_mono > AUDIO_TURN_MAX_SECONDS:
                raise ValueError("audio turn duration cap exceeded")

            if self._last_frame_mono is not None:
                interval = checked_now_mono - self._last_frame_mono
                if interval < 0:
                    raise ValueError("audio monotonic time rollback")
                if interval < AUDIO_MIN_FRAME_INTERVAL_SECONDS and not math.isclose(
                    interval,
                    AUDIO_MIN_FRAME_INTERVAL_SECONDS,
                    rel_tol=0,
                    abs_tol=1e-12,
                ):
                    raise ValueError("audio frame rate exceeded")

            if self._bytes_received + checked_payload_size > AUDIO_TURN_MAX_BYTES:
                raise ValueError("audio turn byte cap exceeded")

            object.__setattr__(self, "_last_frame_mono", checked_now_mono)
            object.__setattr__(
                self,
                "_bytes_received",
                self._bytes_received + checked_payload_size,
            )

    def _validate_current_state(self) -> None:
        if not math.isfinite(self._started_mono):
            raise ValueError("audio monotonic time invalid")
        if self._last_frame_mono is not None:
            if not math.isfinite(self._last_frame_mono):
                raise ValueError("audio monotonic time invalid")
            if self._last_frame_mono < self._started_mono:
                raise ValueError("audio monotonic time rollback")
            if self._last_frame_mono - self._started_mono > AUDIO_TURN_MAX_SECONDS:
                raise ValueError("audio turn duration cap exceeded")
        if type(self._bytes_received) is not int or self._bytes_received < 0:
            raise ValueError("audio turn byte cap exceeded")
        if self._bytes_received > AUDIO_TURN_MAX_BYTES:
            raise ValueError("audio turn byte cap exceeded")


__all__ = [
    "AUDIO_MAX_FRAME_DURATION_MS",
    "AUDIO_MIN_FRAME_DURATION_MS",
    "AUDIO_MIN_FRAME_INTERVAL_SECONDS",
    "AUDIO_TURN_MAX_BYTES",
    "AUDIO_TURN_MAX_SECONDS",
    "CameraWindow",
    "MAX_AUDIO_PAYLOAD",
    "MAX_CAMERA_PAYLOAD",
    "MAX_HEADER",
    "MediaQuota",
    "PREFIX",
    "parse_prefix",
]
