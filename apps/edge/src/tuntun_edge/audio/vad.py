from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

VAD_SAMPLE_RATE_HZ: Final = 16_000
VAD_FRAME_DURATION_MS: Final = 20
VAD_FRAME_SAMPLES: Final = VAD_SAMPLE_RATE_HZ * VAD_FRAME_DURATION_MS // 1_000
VAD_FRAME_BYTES: Final = VAD_FRAME_SAMPLES * 2
SCORE_FLOOR: Final = 0
SCORE_CEILING: Final = 1_000_000
_CONTROL_FLOW_ERRORS: tuple[type[BaseException], ...] = (
    asyncio.CancelledError,
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
)


@runtime_checkable
class GovernedVadInference(Protocol):
    model_id: str
    activated: bool
    runtime_download: bool

    def infer_voice_score(self, frame: bytes) -> int: ...


@dataclass(frozen=True, slots=True)
class VadResult:
    is_voice: bool
    started: bool
    ended: bool


class VadDetectionError(RuntimeError):
    """Content-free VAD runtime rejection."""

    def __init__(self) -> None:
        super().__init__("vad-inference-rejected")


@dataclass(frozen=True, slots=True)
class _GovernedHandleSnapshot:
    method: object
    model_id: object
    activated: object
    runtime_download: object
    download: object
    download_model: object
    cloud_endpoint: object


def _require_exact_int(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise TypeError(label)
    return value


def _require_score(value: object, *, label: str) -> int:
    checked = _require_exact_int(value, label=label)
    if not SCORE_FLOOR <= checked <= SCORE_CEILING:
        raise ValueError(label)
    return checked


def _require_bounded_count(value: object, *, label: str, minimum: int, maximum: int) -> int:
    checked = _require_exact_int(value, label=label)
    if not minimum <= checked <= maximum:
        raise ValueError(label)
    return checked


def _capture_governed_handle_snapshot(
    handle: object,
    *,
    method_name: str,
    error_factory: Callable[[], RuntimeError],
) -> _GovernedHandleSnapshot:
    snapshot: _GovernedHandleSnapshot | None = None
    snapshot_failed = False
    try:
        snapshot = _GovernedHandleSnapshot(
            method=getattr(handle, method_name, None),
            model_id=getattr(handle, "model_id", None),
            activated=getattr(handle, "activated", None),
            runtime_download=getattr(handle, "runtime_download", None),
            download=getattr(handle, "download", None),
            download_model=getattr(handle, "download_model", None),
            cloud_endpoint=getattr(handle, "cloud_endpoint", None),
        )
    except _CONTROL_FLOW_ERRORS:
        raise
    except BaseException:
        snapshot_failed = True
    if snapshot_failed or snapshot is None:
        raise error_factory()
    return snapshot


def _validate_governed_handle(
    handle: object,
    *,
    method_name: str,
    error_factory: Callable[[], RuntimeError],
) -> None:
    snapshot = _capture_governed_handle_snapshot(
        handle,
        method_name=method_name,
        error_factory=error_factory,
    )
    if not callable(snapshot.method):
        raise TypeError("governed-local-inference-handle")
    if (
        snapshot.activated is not True
        or snapshot.runtime_download is not False
        or type(snapshot.model_id) is not str
        or not snapshot.model_id
        or callable(snapshot.download)
        or callable(snapshot.download_model)
        or snapshot.cloud_endpoint is not None
    ):
        raise ValueError("governed-local-inference-handle")


class VoiceActivityDetector:
    """Governed local VAD with fixed 20 ms frames, start debounce, and hangover."""

    _active: bool
    _end_frames: int
    _hangover_frames: int
    _inference: GovernedVadInference
    _silence_run: int
    _speech_run: int
    _start_frames: int
    _threshold: int

    __slots__ = (
        "_active",
        "_end_frames",
        "_hangover_frames",
        "_inference",
        "_silence_run",
        "_speech_run",
        "_start_frames",
        "_threshold",
    )

    def __init__(
        self,
        inference: GovernedVadInference,
        *,
        threshold: int,
        start_frames: int = 2,
        hangover_frames: int = 3,
        end_frames: int = 2,
    ) -> None:
        _validate_governed_handle(
            inference,
            method_name="infer_voice_score",
            error_factory=VadDetectionError,
        )
        self._inference = inference
        self._threshold = _require_score(threshold, label="vad-threshold-contract")
        self._start_frames = _require_bounded_count(
            start_frames,
            label="vad-start-frames-contract",
            minimum=1,
            maximum=10,
        )
        self._hangover_frames = _require_bounded_count(
            hangover_frames,
            label="vad-hangover-frames-contract",
            minimum=0,
            maximum=50,
        )
        self._end_frames = _require_bounded_count(
            end_frames,
            label="vad-end-frames-contract",
            minimum=1,
            maximum=10,
        )
        self._speech_run = 0
        self._silence_run = 0
        self._active = False

    def process(self, frame: bytes) -> VadResult:
        if type(frame) is not bytes:
            raise TypeError("vad-frame-contract")
        if len(frame) != VAD_FRAME_BYTES:
            raise ValueError("vad-frame-contract")

        inference_failed = False
        try:
            raw_score = self._inference.infer_voice_score(frame)
        except _CONTROL_FLOW_ERRORS:
            raise
        except BaseException:
            inference_failed = True
            raw_score = None
        if inference_failed:
            raise VadDetectionError()

        score = _require_score(
            raw_score,
            label="vad-score-contract",
        )
        if score >= self._threshold:
            self._speech_run += 1
            self._silence_run = 0
            if not self._active and self._speech_run >= self._start_frames:
                self._active = True
                return VadResult(is_voice=True, started=True, ended=False)
            return VadResult(is_voice=self._active, started=False, ended=False)

        self._speech_run = 0
        if self._active:
            self._silence_run += 1
            if (
                self._silence_run > self._hangover_frames
                and self._silence_run - self._hangover_frames >= self._end_frames
            ):
                self._active = False
                self._silence_run = 0
                return VadResult(is_voice=False, started=False, ended=True)
            return VadResult(is_voice=True, started=False, ended=False)

        return VadResult(is_voice=False, started=False, ended=False)


__all__ = [
    "SCORE_CEILING",
    "SCORE_FLOOR",
    "VAD_FRAME_BYTES",
    "VAD_FRAME_DURATION_MS",
    "VAD_FRAME_SAMPLES",
    "VAD_SAMPLE_RATE_HZ",
    "GovernedVadInference",
    "VadDetectionError",
    "VadResult",
    "VoiceActivityDetector",
]
