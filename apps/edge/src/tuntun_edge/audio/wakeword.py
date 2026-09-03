from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

HELLO_WAKE_MODEL_ID: Final = "hello-tuntun-v1"
STOP_KEYWORD_MODEL_ID: Final = "stop-tuntun-v1"
WAKE_SAMPLE_RATE_HZ: Final = 16_000
WAKE_FRAME_SAMPLES: Final = 1_280
WAKE_FRAME_BYTES: Final = WAKE_FRAME_SAMPLES * 2
SCORE_FLOOR: Final = 0
SCORE_CEILING: Final = 1_000_000
_REQUIRED_CONSECUTIVE_WAKE_FRAMES: Final = 2
_CONTROL_FLOW_ERRORS: tuple[type[BaseException], ...] = (
    asyncio.CancelledError,
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
)


@runtime_checkable
class GovernedWakeInference(Protocol):
    model_id: str
    activated: bool
    runtime_download: bool

    def infer_score(self, frame: bytes) -> int: ...


class WakeDetectionError(RuntimeError):
    """Content-free wake detector runtime rejection."""

    def __init__(self) -> None:
        super().__init__("wake-inference-rejected")


class StopDetectionError(RuntimeError):
    """Content-free stop-keyword detector runtime rejection."""

    def __init__(self) -> None:
        super().__init__("stop-inference-rejected")


@dataclass(frozen=True, slots=True)
class _GovernedHandleSnapshot:
    method: object
    model_id: object
    activated: object
    runtime_download: object
    download: object
    download_model: object
    cloud_endpoint: object


def _require_score(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise TypeError(label)
    if not SCORE_FLOOR <= value <= SCORE_CEILING:
        raise ValueError(label)
    return value


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
    expected_model_id: str,
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
        or snapshot.model_id != expected_model_id
        or callable(snapshot.download)
        or callable(snapshot.download_model)
        or snapshot.cloud_endpoint is not None
    ):
        raise ValueError("governed-local-inference-handle")


def _require_frame(frame: object, *, label: str) -> bytes:
    if type(frame) is not bytes:
        raise TypeError(label)
    if len(frame) != WAKE_FRAME_BYTES:
        raise ValueError(label)
    return frame


def _infer_content_free_score(
    inference: GovernedWakeInference,
    frame: bytes,
    *,
    score_label: str,
    error_factory: Callable[[], RuntimeError],
) -> int:
    inference_failed = False
    raw_score: object
    try:
        raw_score = inference.infer_score(frame)
    except _CONTROL_FLOW_ERRORS:
        raise
    except BaseException:
        inference_failed = True
        raw_score = None
    if inference_failed:
        raise error_factory()
    return _require_score(raw_score, label=score_label)


class WakeDetector:
    """Two-frame governed wake detector for exact 80 ms s16le mono windows."""

    _consecutive: int
    _inference: GovernedWakeInference
    _threshold: int

    __slots__ = ("_consecutive", "_inference", "_threshold")

    def __init__(self, inference: GovernedWakeInference, *, threshold: int) -> None:
        _validate_governed_handle(
            inference,
            method_name="infer_score",
            expected_model_id=HELLO_WAKE_MODEL_ID,
            error_factory=WakeDetectionError,
        )
        self._inference = inference
        self._threshold = _require_score(threshold, label="wake-threshold-contract")
        self._consecutive = 0

    def process(self, frame: bytes) -> bool:
        checked_frame = _require_frame(frame, label="wake-frame-contract")
        score = _infer_content_free_score(
            self._inference,
            checked_frame,
            score_label="wake-score-contract",
            error_factory=WakeDetectionError,
        )
        if score >= self._threshold:
            self._consecutive += 1
        else:
            self._consecutive = 0
        return self._consecutive >= _REQUIRED_CONSECUTIVE_WAKE_FRAMES


class StopDetector:
    """One-frame governed stop-keyword detector for exact 80 ms s16le mono windows."""

    _inference: GovernedWakeInference
    _threshold: int

    __slots__ = ("_inference", "_threshold")

    def __init__(self, inference: GovernedWakeInference, *, threshold: int) -> None:
        _validate_governed_handle(
            inference,
            method_name="infer_score",
            expected_model_id=STOP_KEYWORD_MODEL_ID,
            error_factory=StopDetectionError,
        )
        self._inference = inference
        self._threshold = _require_score(threshold, label="stop-threshold-contract")

    def process(self, frame: bytes) -> bool:
        checked_frame = _require_frame(frame, label="stop-frame-contract")
        score = _infer_content_free_score(
            self._inference,
            checked_frame,
            score_label="stop-score-contract",
            error_factory=StopDetectionError,
        )
        return score >= self._threshold


__all__ = [
    "HELLO_WAKE_MODEL_ID",
    "SCORE_CEILING",
    "SCORE_FLOOR",
    "STOP_KEYWORD_MODEL_ID",
    "WAKE_FRAME_BYTES",
    "WAKE_FRAME_SAMPLES",
    "WAKE_SAMPLE_RATE_HZ",
    "GovernedWakeInference",
    "StopDetectionError",
    "StopDetector",
    "WakeDetectionError",
    "WakeDetector",
]
