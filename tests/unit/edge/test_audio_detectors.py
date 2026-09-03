from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError, dataclass, field
from typing import Literal, cast

import pytest
from tuntun_edge.audio import wakeword
from tuntun_edge.audio.vad import (
    VAD_FRAME_BYTES,
    VadDetectionError,
    VadResult,
    VoiceActivityDetector,
)
from tuntun_edge.audio.wakeword import WAKE_FRAME_BYTES, WakeDetectionError, WakeDetector

DetectorKind = Literal["wake", "stop", "vad"]
_GOVERNANCE_ATTRIBUTES = (
    "model_id",
    "activated",
    "runtime_download",
    "download",
    "download_model",
    "cloud_endpoint",
)


@dataclass
class _WakeHandle:
    scores: list[object]
    model_id: str = "hello-tuntun-v1"
    activated: bool = True
    runtime_download: bool = False
    frames: list[bytes] = field(default_factory=list)

    def infer_score(self, frame: bytes) -> float:
        self.frames.append(frame)
        return cast(float, self.scores.pop(0))


@dataclass
class _VadHandle:
    scores: list[int]
    model_id: str = "vad-local-v1"
    activated: bool = True
    runtime_download: bool = False
    frames: list[bytes] = field(default_factory=list)

    def infer_voice_score(self, frame: bytes) -> int:
        self.frames.append(frame)
        return self.scores.pop(0)


@dataclass
class _PrivateWakeFailureHandle:
    model_id: str = "hello-tuntun-v1"
    activated: bool = True
    runtime_download: bool = False

    def infer_score(self, frame: bytes) -> float:
        raise RuntimeError("private wake sentinel child voice bytes")


@dataclass
class _PrivateWakeBaseFailureHandle:
    model_id: str = "hello-tuntun-v1"
    activated: bool = True
    runtime_download: bool = False

    def infer_score(self, frame: bytes) -> float:
        raise BaseException("private wake fatal sentinel")


@dataclass
class _WakeControlFlowHandle:
    error: BaseException
    model_id: str = "hello-tuntun-v1"
    activated: bool = True
    runtime_download: bool = False

    def infer_score(self, frame: bytes) -> float:
        raise self.error


@dataclass
class _PrivateVadFailureHandle:
    model_id: str = "vad-local-v1"
    activated: bool = True
    runtime_download: bool = False

    def infer_voice_score(self, frame: bytes) -> int:
        raise RuntimeError("private vad sentinel child voice bytes")


@dataclass
class _PrivateVadBaseFailureHandle:
    model_id: str = "vad-local-v1"
    activated: bool = True
    runtime_download: bool = False

    def infer_voice_score(self, frame: bytes) -> int:
        raise BaseException("private vad fatal sentinel")


@dataclass
class _VadControlFlowHandle:
    error: BaseException
    model_id: str = "vad-local-v1"
    activated: bool = True
    runtime_download: bool = False

    def infer_voice_score(self, frame: bytes) -> int:
        raise self.error


class _HostileGovernanceHandle:
    def __init__(
        self,
        *,
        model_id: str,
        failing_attribute: str | None,
        error: BaseException,
    ) -> None:
        self._model_id = model_id
        self._failing_attribute = failing_attribute
        self._error = error
        self.reads: list[str] = []

    @property
    def model_id(self) -> object:
        return self._read("model_id", self._model_id)

    @property
    def activated(self) -> object:
        return self._read("activated", True)

    @property
    def runtime_download(self) -> object:
        return self._read("runtime_download", False)

    @property
    def download(self) -> object:
        return self._read("download", None)

    @property
    def download_model(self) -> object:
        return self._read("download_model", None)

    @property
    def cloud_endpoint(self) -> object:
        return self._read("cloud_endpoint", None)

    def infer_score(self, frame: bytes) -> float:
        del frame
        return 0.0

    def infer_voice_score(self, frame: bytes) -> int:
        del frame
        return 0

    def _read(self, name: str, value: object) -> object:
        self.reads.append(name)
        if name == self._failing_attribute:
            raise self._error
        return value


def _model_id_for_detector(kind: DetectorKind) -> str:
    if kind == "wake":
        return "hello-tuntun-v1"
    if kind == "stop":
        return "stop-tuntun-v1"
    return "vad-local-v1"


def _error_type_for_detector(kind: DetectorKind) -> type[BaseException]:
    if kind == "wake":
        return WakeDetectionError
    if kind == "stop":
        return wakeword.StopDetectionError
    return VadDetectionError


def _error_message_for_detector(kind: DetectorKind) -> str:
    if kind == "wake":
        return "wake-inference-rejected"
    if kind == "stop":
        return "stop-inference-rejected"
    return "vad-inference-rejected"


def _construct_detector(kind: DetectorKind, handle: object) -> object:
    if kind == "wake":
        return WakeDetector(handle, threshold=0.5)  # type: ignore[arg-type]
    if kind == "stop":
        return wakeword.StopDetector(handle, threshold=0.5)  # type: ignore[arg-type]
    return VoiceActivityDetector(handle, threshold=500_000)  # type: ignore[arg-type]


def test_native_wake_score_converts_to_event_score_micros_explicitly() -> None:
    assert wakeword.SCORE_FLOOR == 0
    assert type(wakeword.SCORE_FLOOR) is int
    assert wakeword.SCORE_CEILING == 1_000_000
    assert type(wakeword.SCORE_CEILING) is int
    assert wakeword.NATIVE_SCORE_FLOOR == 0.0
    assert wakeword.NATIVE_SCORE_CEILING == 1.0

    assert wakeword.native_score_to_micros(0.0) == 0
    assert wakeword.native_score_to_micros(0.0000005) == 1
    assert wakeword.native_score_to_micros(0.5) == 500_000
    assert wakeword.native_score_to_micros(0.5000005) == 500_001
    assert wakeword.native_score_to_micros(0.9) == 900_000
    assert wakeword.native_score_to_micros(1.0) == 1_000_000


@pytest.mark.parametrize(
    ("bad_score", "error_type"),
    (
        (True, TypeError),
        (1, TypeError),
        (float("nan"), ValueError),
        (float("inf"), ValueError),
        (-0.1, ValueError),
        (1.1, ValueError),
    ),
)
def test_native_wake_score_to_micros_rejects_non_native_scores(
    bad_score: object,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type, match="native-score-contract"):
        wakeword.native_score_to_micros(cast(float, bad_score))


def test_wake_detector_scored_decision_exposes_exact_event_score_micros() -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    detector = WakeDetector(_WakeHandle([0.5000005, 0.5000005]), threshold=0.5)

    first = detector.process_with_score(frame)
    second = detector.process_with_score(frame)

    assert first == wakeword.WakeFrameDecision(detected=False, score_micros=500_001)
    assert second == wakeword.WakeFrameDecision(detected=True, score_micros=500_001)
    with pytest.raises(FrozenInstanceError):
        second.score_micros = 0  # type: ignore[misc]


def test_stop_detector_scored_decision_exposes_exact_event_score_micros() -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    detector = wakeword.StopDetector(
        _WakeHandle([0.0000005], model_id="stop-tuntun-v1"),
        threshold=0.5,
    )

    assert detector.process_with_score(frame) == wakeword.WakeFrameDecision(
        detected=False,
        score_micros=1,
    )


def test_wake_detector_process_delegates_to_scored_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    detector = WakeDetector(_WakeHandle([0.1]), threshold=0.5)
    calls: list[bytes] = []

    def fake_process_with_score(
        self: WakeDetector,
        candidate: bytes,
    ) -> wakeword.WakeFrameDecision:
        del self
        calls.append(candidate)
        return wakeword.WakeFrameDecision(detected=True, score_micros=123)

    monkeypatch.setattr(WakeDetector, "process_with_score", fake_process_with_score)

    assert detector.process(frame) is True
    assert calls == [frame]


def test_wake_detector_requires_exact_frame_and_two_consecutive_native_scores() -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    handle = _WakeHandle([0.9, 0.1, 0.9, 0.9, 0.9])
    detector = WakeDetector(handle, threshold=0.8)

    assert detector.process(frame) is False
    assert detector.process(frame) is False
    assert detector.process(frame) is False
    assert detector.process(frame) is True
    assert detector.process(frame) is True
    assert handle.frames == [frame, frame, frame, frame, frame]


def test_wake_detector_rejects_non_bytes_and_wrong_lengths() -> None:
    detector = WakeDetector(_WakeHandle([0.5]), threshold=0.5)

    with pytest.raises(TypeError):
        detector.process(bytearray(WAKE_FRAME_BYTES))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="wake-frame-contract"):
        detector.process(b"\x00" * (WAKE_FRAME_BYTES - 2))


@pytest.mark.parametrize("kind", ("wake", "stop"))
@pytest.mark.parametrize(
    ("bad_score", "error_type"),
    (
        (True, TypeError),
        (1, TypeError),
        (float("nan"), ValueError),
        (float("inf"), ValueError),
        (-0.1, ValueError),
        (1.1, ValueError),
    ),
)
def test_wake_and_stop_detectors_reject_non_native_scores(
    kind: Literal["wake", "stop"],
    bad_score: object,
    error_type: type[Exception],
) -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    detector: WakeDetector | wakeword.StopDetector
    if kind == "wake":
        detector = WakeDetector(_WakeHandle([bad_score]), threshold=0.5)
        label = "wake-score-contract"
    else:
        detector = wakeword.StopDetector(
            _WakeHandle([bad_score], model_id="stop-tuntun-v1"),
            threshold=0.5,
        )
        label = "stop-score-contract"

    with pytest.raises(error_type, match=label):
        detector.process(frame)


@pytest.mark.parametrize("kind", ("wake", "stop"))
@pytest.mark.parametrize(
    ("bad_threshold", "error_type"),
    (
        (True, TypeError),
        (1, TypeError),
        (float("nan"), ValueError),
        (float("inf"), ValueError),
        (-0.1, ValueError),
        (1.1, ValueError),
    ),
)
def test_wake_and_stop_detectors_reject_non_native_thresholds(
    kind: Literal["wake", "stop"],
    bad_threshold: object,
    error_type: type[Exception],
) -> None:
    handle = _WakeHandle([0.5], model_id=_model_id_for_detector(kind))
    detector_type = WakeDetector if kind == "wake" else wakeword.StopDetector
    label = f"{kind}-threshold-contract"

    with pytest.raises(error_type, match=label):
        detector_type(handle, threshold=bad_threshold)  # type: ignore[arg-type]


def test_wake_detector_accepts_only_activated_local_governed_handles() -> None:
    downloader = _WakeHandle([0.9], activated=True, runtime_download=True)

    with pytest.raises(ValueError, match="governed-local-inference-handle"):
        WakeDetector(downloader, threshold=0.5)

    with pytest.raises(TypeError):
        WakeDetector("/tmp/model.onnx", threshold=0.5)  # type: ignore[arg-type]


def test_wake_detector_accepts_only_hello_model_identity() -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    detector = WakeDetector(_WakeHandle([0.9, 0.9]), threshold=0.8)

    assert detector.process(frame) is False
    assert detector.process(frame) is True

    rejected_model_ids = (
        "stop-tuntun-v1",
        "hello-tuntun-v2",
        "arbitrary-local-model",
        "",
    )
    for model_id in rejected_model_ids:
        with pytest.raises(ValueError, match="governed-local-inference-handle"):
            WakeDetector(_WakeHandle([0.9], model_id=model_id), threshold=0.8)


def test_stop_detector_accepts_only_stop_identity_and_fires_on_first_frame() -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    handle = _WakeHandle([0.9, 0.0], model_id="stop-tuntun-v1")
    detector = wakeword.StopDetector(handle, threshold=0.8)

    assert detector.process(frame) is True
    assert detector.process(frame) is False
    assert handle.frames == [frame, frame]

    rejected_model_ids = (
        "hello-tuntun-v1",
        "stop-tuntun-v2",
        "arbitrary-local-model",
        "",
    )
    for model_id in rejected_model_ids:
        with pytest.raises(ValueError, match="governed-local-inference-handle"):
            wakeword.StopDetector(
                _WakeHandle([0.9], model_id=model_id),
                threshold=0.8,
            )


def test_stop_detector_translates_failures_without_private_leakage() -> None:
    detector = wakeword.StopDetector(
        _PrivateWakeFailureHandle(model_id="stop-tuntun-v1"),
        threshold=0.5,
    )

    with pytest.raises(wakeword.StopDetectionError, match="^stop-inference-rejected$") as raised:
        detector.process(b"\x00" * WAKE_FRAME_BYTES)

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "sentinel" not in rendered
    assert "child voice" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    "error",
    (
        asyncio.CancelledError(),
        KeyboardInterrupt(),
        SystemExit(),
        GeneratorExit(),
    ),
)
def test_stop_detector_preserves_control_flow_base_exceptions(error: BaseException) -> None:
    detector = wakeword.StopDetector(
        _WakeControlFlowHandle(error, model_id="stop-tuntun-v1"),
        threshold=0.5,
    )

    with pytest.raises(type(error)):
        detector.process(b"\x00" * WAKE_FRAME_BYTES)


def test_vad_frame_contract_and_hangover_debounce_are_frozen() -> None:
    frame = b"\x00" * VAD_FRAME_BYTES
    detector = VoiceActivityDetector(
        _VadHandle([900_000, 900_000, 0, 0, 0, 900_000]),
        threshold=800_000,
        start_frames=2,
        hangover_frames=2,
        end_frames=1,
    )

    assert detector.process(frame) == VadResult(is_voice=False, started=False, ended=False)
    assert detector.process(frame) == VadResult(is_voice=True, started=True, ended=False)
    assert detector.process(frame) == VadResult(is_voice=True, started=False, ended=False)
    assert detector.process(frame) == VadResult(is_voice=True, started=False, ended=False)
    assert detector.process(frame) == VadResult(is_voice=False, started=False, ended=True)
    assert detector.process(frame) == VadResult(is_voice=False, started=False, ended=False)


def test_vad_rejects_strict_types_wrong_lengths_and_runtime_downloads() -> None:
    detector = VoiceActivityDetector(_VadHandle([0]), threshold=500_000)

    with pytest.raises(TypeError):
        detector.process(memoryview(b"\x00" * VAD_FRAME_BYTES))  # type: ignore[arg-type]

    for payload in (b"", b"\x00", b"\x00" * (VAD_FRAME_BYTES - 2), b"\x00" * (VAD_FRAME_BYTES + 2)):
        with pytest.raises(ValueError, match="vad-frame-contract"):
            detector.process(payload)

    with pytest.raises(TypeError):
        VoiceActivityDetector(_VadHandle([0]), threshold=True)

    with pytest.raises(ValueError, match="governed-local-inference-handle"):
        VoiceActivityDetector(_VadHandle([0], runtime_download=True), threshold=500_000)


def test_wake_detector_translates_inference_failures_without_private_leakage() -> None:
    detector = WakeDetector(_PrivateWakeFailureHandle(), threshold=0.5)

    with pytest.raises(WakeDetectionError, match="^wake-inference-rejected$") as raised:
        detector.process(b"\x00" * WAKE_FRAME_BYTES)

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "sentinel" not in rendered
    assert "child voice" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_wake_detector_translates_non_control_base_exception_without_private_leakage() -> None:
    detector = WakeDetector(_PrivateWakeBaseFailureHandle(), threshold=0.5)

    with pytest.raises(WakeDetectionError, match="^wake-inference-rejected$") as raised:
        detector.process(b"\x00" * WAKE_FRAME_BYTES)

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "fatal" not in rendered
    assert "sentinel" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    "error",
    (
        asyncio.CancelledError(),
        KeyboardInterrupt(),
        SystemExit(),
        GeneratorExit(),
    ),
)
def test_wake_detector_preserves_control_flow_base_exceptions(error: BaseException) -> None:
    detector = WakeDetector(_WakeControlFlowHandle(error), threshold=0.5)

    with pytest.raises(type(error)):
        detector.process(b"\x00" * WAKE_FRAME_BYTES)


def test_vad_translates_inference_failures_without_private_leakage() -> None:
    detector = VoiceActivityDetector(_PrivateVadFailureHandle(), threshold=500_000)

    with pytest.raises(VadDetectionError, match="^vad-inference-rejected$") as raised:
        detector.process(b"\x00" * VAD_FRAME_BYTES)

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "sentinel" not in rendered
    assert "child voice" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_vad_translates_non_control_base_exception_without_private_leakage() -> None:
    detector = VoiceActivityDetector(_PrivateVadBaseFailureHandle(), threshold=500_000)

    with pytest.raises(VadDetectionError, match="^vad-inference-rejected$") as raised:
        detector.process(b"\x00" * VAD_FRAME_BYTES)

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "fatal" not in rendered
    assert "sentinel" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    "error",
    (
        asyncio.CancelledError(),
        KeyboardInterrupt(),
        SystemExit(),
        GeneratorExit(),
    ),
)
def test_vad_preserves_control_flow_base_exceptions(error: BaseException) -> None:
    detector = VoiceActivityDetector(_VadControlFlowHandle(error), threshold=500_000)

    with pytest.raises(type(error)):
        detector.process(b"\x00" * VAD_FRAME_BYTES)


@pytest.mark.parametrize("kind", ("wake", "stop", "vad"))
@pytest.mark.parametrize("attribute", _GOVERNANCE_ATTRIBUTES)
def test_detector_constructor_sanitizes_hostile_governance_attributes(
    kind: DetectorKind,
    attribute: str,
) -> None:
    handle = _HostileGovernanceHandle(
        model_id=_model_id_for_detector(kind),
        failing_attribute=attribute,
        error=RuntimeError(f"private {attribute} descriptor sentinel"),
    )

    with pytest.raises(
        _error_type_for_detector(kind),
        match=f"^{_error_message_for_detector(kind)}$",
    ) as raised:
        _construct_detector(kind, handle)

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "descriptor" not in rendered
    assert "sentinel" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize("kind", ("wake", "stop", "vad"))
def test_detector_constructor_sanitizes_non_control_base_exception_attribute(
    kind: DetectorKind,
) -> None:
    handle = _HostileGovernanceHandle(
        model_id=_model_id_for_detector(kind),
        failing_attribute="model_id",
        error=BaseException("private base descriptor sentinel"),
    )

    with pytest.raises(
        _error_type_for_detector(kind),
        match=f"^{_error_message_for_detector(kind)}$",
    ) as raised:
        _construct_detector(kind, handle)

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "base" not in rendered
    assert "descriptor" not in rendered
    assert "sentinel" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize("kind", ("wake", "stop", "vad"))
@pytest.mark.parametrize(
    "error",
    (
        asyncio.CancelledError(),
        KeyboardInterrupt(),
        SystemExit(),
        GeneratorExit(),
    ),
)
def test_detector_constructor_preserves_control_flow_governance_failures(
    kind: DetectorKind,
    error: BaseException,
) -> None:
    handle = _HostileGovernanceHandle(
        model_id=_model_id_for_detector(kind),
        failing_attribute="activated",
        error=error,
    )

    with pytest.raises(type(error)):
        _construct_detector(kind, handle)


@pytest.mark.parametrize("kind", ("wake", "stop", "vad"))
def test_detector_constructor_reads_governance_attributes_once_as_snapshot(
    kind: DetectorKind,
) -> None:
    handle = _HostileGovernanceHandle(
        model_id=_model_id_for_detector(kind),
        failing_attribute=None,
        error=RuntimeError("unused"),
    )

    _construct_detector(kind, handle)

    assert handle.reads == list(_GOVERNANCE_ATTRIBUTES)
