from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Literal

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
    scores: list[int]
    model_id: str = "hello-tuntun-v1"
    activated: bool = True
    runtime_download: bool = False
    frames: list[bytes] = field(default_factory=list)

    def infer_score(self, frame: bytes) -> int:
        self.frames.append(frame)
        return self.scores.pop(0)


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

    def infer_score(self, frame: bytes) -> int:
        raise RuntimeError("private wake sentinel child voice bytes")


@dataclass
class _PrivateWakeBaseFailureHandle:
    model_id: str = "hello-tuntun-v1"
    activated: bool = True
    runtime_download: bool = False

    def infer_score(self, frame: bytes) -> int:
        raise BaseException("private wake fatal sentinel")


@dataclass
class _WakeControlFlowHandle:
    error: BaseException
    model_id: str = "hello-tuntun-v1"
    activated: bool = True
    runtime_download: bool = False

    def infer_score(self, frame: bytes) -> int:
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

    def infer_score(self, frame: bytes) -> int:
        del frame
        return 0

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
        return WakeDetector(handle, threshold=500_000)  # type: ignore[arg-type]
    if kind == "stop":
        return wakeword.StopDetector(handle, threshold=500_000)  # type: ignore[arg-type]
    return VoiceActivityDetector(handle, threshold=500_000)  # type: ignore[arg-type]


def test_wake_detector_requires_exact_frame_and_two_consecutive_integer_scores() -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    handle = _WakeHandle([900_000, 100_000, 900_000, 900_000, 900_000])
    detector = WakeDetector(handle, threshold=800_000)

    assert detector.process(frame) is False
    assert detector.process(frame) is False
    assert detector.process(frame) is False
    assert detector.process(frame) is True
    assert detector.process(frame) is True
    assert handle.frames == [frame, frame, frame, frame, frame]


def test_wake_detector_rejects_non_bytes_wrong_lengths_and_bad_scores() -> None:
    detector = WakeDetector(_WakeHandle([500_000]), threshold=500_000)

    with pytest.raises(TypeError):
        detector.process(bytearray(WAKE_FRAME_BYTES))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="wake-frame-contract"):
        detector.process(b"\x00" * (WAKE_FRAME_BYTES - 2))

    bad_score = WakeDetector(_WakeHandle([True]), threshold=500_000)
    with pytest.raises(TypeError, match="wake-score-contract"):
        bad_score.process(b"\x00" * WAKE_FRAME_BYTES)


def test_wake_detector_accepts_only_activated_local_governed_handles() -> None:
    downloader = _WakeHandle([900_000], activated=True, runtime_download=True)

    with pytest.raises(ValueError, match="governed-local-inference-handle"):
        WakeDetector(downloader, threshold=500_000)

    with pytest.raises(TypeError):
        WakeDetector("/tmp/model.onnx", threshold=500_000)  # type: ignore[arg-type]


def test_wake_detector_accepts_only_hello_model_identity() -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    detector = WakeDetector(_WakeHandle([900_000, 900_000]), threshold=800_000)

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
            WakeDetector(_WakeHandle([900_000], model_id=model_id), threshold=800_000)


def test_stop_detector_accepts_only_stop_identity_and_fires_on_first_frame() -> None:
    frame = b"\x00" * WAKE_FRAME_BYTES
    handle = _WakeHandle([900_000, 0], model_id="stop-tuntun-v1")
    detector = wakeword.StopDetector(handle, threshold=800_000)

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
                _WakeHandle([900_000], model_id=model_id),
                threshold=800_000,
            )


def test_stop_detector_translates_failures_without_private_leakage() -> None:
    detector = wakeword.StopDetector(
        _PrivateWakeFailureHandle(model_id="stop-tuntun-v1"),
        threshold=500_000,
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
        threshold=500_000,
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
    detector = WakeDetector(_PrivateWakeFailureHandle(), threshold=500_000)

    with pytest.raises(WakeDetectionError, match="^wake-inference-rejected$") as raised:
        detector.process(b"\x00" * WAKE_FRAME_BYTES)

    rendered = f"{raised.value!s} {raised.value!r}"
    assert "private" not in rendered
    assert "sentinel" not in rendered
    assert "child voice" not in rendered
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_wake_detector_translates_non_control_base_exception_without_private_leakage() -> None:
    detector = WakeDetector(_PrivateWakeBaseFailureHandle(), threshold=500_000)

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
    detector = WakeDetector(_WakeControlFlowHandle(error), threshold=500_000)

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
