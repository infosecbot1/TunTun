from __future__ import annotations

import asyncio
import base64
import hashlib
import sys
from collections import deque
from collections.abc import AsyncIterator, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from unicodedata import normalize
from uuid import UUID, uuid4, uuid5

from tuntun_contracts.base import Commitment, Sensitivity
from tuntun_contracts.poc.framing import (
    MAX_FEED_BYTES,
    PttInputMode,
    PttSessionOutcome,
)
from tuntun_contracts.provider import (
    ProviderName,
    ProviderResponse,
    RouteAuthorization,
    SanitizedProviderMessage,
    SanitizedProviderRequest,
)
from tuntun_contracts.speech import (
    AudioFormat,
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
    SpeechChunk,
    TranscriptResult,
)
from tuntun_core.adapters.poc.pcm16_converter import Pcm16Converter
from tuntun_core.services.poc.ports import CorePttEvent, MonotonicClock, PttSendCommit
from tuntun_core.services.poc.session_supervisor import CorePttSessionSupervisor
from tuntun_core.services.poc.voice_turn import VoiceTurnPipeline

TTS_SOURCE_FORMAT = AudioFormat(
    sample_format="s16le",
    sample_rate_hz=24_000,
    channels=1,
    interleaved=False,
    channel_layout="mono",
)
_NAMESPACE = UUID("8fa49e1e-e874-4447-b949-7a0b5a9f61a5")
_NOW = datetime(2026, 9, 1, tzinfo=UTC)
_STDERR_CLASSIFIER_BYTES = 4096


class FakeVoiceError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("fake-voice-rejected")


@dataclass(frozen=True, slots=True)
class FakeVoiceScript:
    utterance: str = "Hello Reachy, please say namaste."
    language: Literal["en", "hi", "hinglish"] = "en"
    response: str = "Namaste. I am ready for the supervised fake loop."
    capture_pcm: bytes = b"\x01\x00\x02\x00\x03\x00\x04\x00"
    source_pcm: bytes = bytes(index % 251 for index in range(960))
    fail_stage: str | None = None

    def __post_init__(self) -> None:
        if self.language not in {"en", "hi", "hinglish"}:
            raise ValueError("invalid-fake-voice-script")
        if (
            type(self.utterance) is not str
            or type(self.response) is not str
            or normalize("NFC", self.utterance) != self.utterance
            or normalize("NFC", self.response) != self.response
            or not self.utterance
            or not self.response
        ):
            raise ValueError("invalid-fake-voice-script")
        if (
            type(self.capture_pcm) is not bytes
            or not self.capture_pcm
            or len(self.capture_pcm) % 2
            or type(self.source_pcm) is not bytes
            or not self.source_pcm
        ):
            raise ValueError("invalid-fake-voice-script")


class FakeVoiceRuntime:
    def __init__(self, script: FakeVoiceScript, *, events: list[str] | None = None) -> None:
        self._script = script
        self.events = [] if events is None else events
        self.cancelled_turns: list[UUID] = []

    async def authorize_transcription(
        self,
        *,
        turn_id: UUID,
        audio_format: AudioFormat,
        pcm: memoryview,
        duration_ms: int,
        language_hints: tuple[Literal["en", "hi"], ...],
    ) -> AuthorizedTranscriptionRequest:
        self.events.append("authorize.stt")
        audio_bytes = len(pcm)
        commitment = _commitment(bytes(pcm), "fake-stt-audio")
        request_id = _request_id(turn_id, "stt")
        return AuthorizedTranscriptionRequest(
            request_id=request_id,
            turn_id=turn_id,
            audio_format=audio_format,
            audio_commitment=commitment,
            audio_bytes=audio_bytes,
            duration_ms=duration_ms,
            language_hints=language_hints,
            route=_route(
                "cloud_stt",
                request_id,
                turn_id=turn_id,
                model="fake-stt",
                commitment=commitment,
                max_input_bytes=max(1, audio_bytes),
                max_input_units=max(1, duration_ms),
            ),
        )

    async def authorize_reasoning(
        self,
        *,
        turn_id: UUID,
        transcript: TranscriptResult,
    ) -> SanitizedProviderRequest:
        self.events.append("authorize.reasoning")
        request_id = _request_id(turn_id, "reasoning")
        commitment = _commitment(transcript.text.encode("utf-8"), "fake-reasoning-text")
        return SanitizedProviderRequest(
            request_id=request_id,
            provider=ProviderName.OPENAI,
            model="fake-llm",
            messages=(SanitizedProviderMessage(role="user", content=transcript.text),),
            allowed_tools=(),
            max_output_tokens=512,
            store=False,
            redaction_receipt_id=_request_id(turn_id, "redaction"),
            route=_route(
                "cloud_reasoning",
                request_id,
                turn_id=turn_id,
                model="fake-llm",
                commitment=commitment,
                max_input_bytes=max(1, len(transcript.text.encode("utf-8"))),
                max_input_units=max(1, len(transcript.text)),
            ),
            timeout_ms=45_000,
        )

    async def authorize_synthesis(
        self,
        *,
        turn_id: UUID,
        response: ProviderResponse,
    ) -> AuthorizedSynthesisRequest:
        self.events.append("authorize.synthesis")
        request_id = _request_id(turn_id, "tts")
        commitment = _commitment(response.text.encode("utf-8"), "fake-tts-text")
        return AuthorizedSynthesisRequest(
            request_id=request_id,
            turn_id=turn_id,
            text=response.text,
            text_commitment=commitment,
            segment_index=0,
            segment_count=1,
            language=response.language,
            dlp_receipt_id=_request_id(turn_id, "dlp"),
            route=_route(
                "cloud_tts",
                request_id,
                turn_id=turn_id,
                model="fake-tts",
                commitment=commitment,
                max_input_bytes=max(1, len(response.text.encode("utf-8"))),
                max_input_units=max(1, len(response.text)),
            ),
        )

    async def transcribe(
        self,
        request: AuthorizedTranscriptionRequest,
        audio: AsyncIterator[bytes],
    ) -> TranscriptResult:
        self.events.append("stt")
        async for _chunk in audio:
            pass
        if self._script.fail_stage == "stt":
            raise FakeVoiceError
        return TranscriptResult(
            request_id=request.request_id,
            text=self._script.utterance,
            language=self._script.language,
            duration_ms=request.duration_ms,
        )

    async def complete(self, request: SanitizedProviderRequest) -> ProviderResponse:
        self.events.append("llm")
        if self._script.fail_stage == "llm":
            raise FakeVoiceError
        return ProviderResponse(
            request_id=request.request_id,
            text=self._script.response,
            language=self._script.language,
            provider_usage_receipt_id=None,
        )

    def synthesize(self, request: AuthorizedSynthesisRequest) -> AsyncIterator[SpeechChunk]:
        return self._synthesize(request)

    async def _synthesize(self, request: AuthorizedSynthesisRequest) -> AsyncIterator[SpeechChunk]:
        self.events.append("tts")
        if self._script.fail_stage == "tts":
            raise FakeVoiceError
        source = b"\x00" if self._script.fail_stage == "conversion" else self._script.source_pcm
        yield SpeechChunk(request_id=request.request_id, sequence=0, pcm=source, final=False)
        yield SpeechChunk(request_id=request.request_id, sequence=1, pcm=b"", final=True)

    async def close_active_transport(self, *, turn_id: UUID) -> None:
        self.events.append("provider.cancel")
        self.cancelled_turns.append(turn_id)


class ScriptedPttInput:
    def __init__(
        self,
        events: Sequence[CorePttEvent] = (CorePttEvent.START, CorePttEvent.SUBMIT),
    ) -> None:
        self._events = deque(events)
        self.closed = False

    async def receive(self) -> CorePttEvent:
        while not self._events:
            await asyncio.sleep(0)
        return self._events.popleft()

    async def close(self) -> None:
        self.closed = True


@dataclass(frozen=True, slots=True)
class SimulatedStderrSummary:
    classification: Literal["empty", "present", "truncated"]
    byte_count: int

    def __repr__(self) -> str:
        return (
            f"SimulatedStderrSummary(classification={self.classification!r}, "
            f"byte_count={self.byte_count})"
        )


class SimulatedEdgeBridge:
    def __init__(self, process: asyncio.subprocess.Process) -> None:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise FakeVoiceError
        self._process = process
        self._stdin = process.stdin
        self._stdout = process.stdout
        self._stderr = process.stderr
        self._stderr_bytes = 0
        self._stderr_truncated = False
        self._stderr_task = asyncio.create_task(self._drain_stderr())
        self._closed = False

    @classmethod
    async def spawn(
        cls,
        *,
        turn_id: UUID,
        input_mode: PttInputMode,
        capture_pcm: bytes,
        edge_command: Sequence[str] | None = None,
    ) -> SimulatedEdgeBridge:
        command = list(edge_command) if edge_command is not None else _default_edge_command()
        command.extend(
            [
                "--turn-id",
                str(turn_id),
                "--input-mode",
                input_mode.value,
                "--capture-hex",
                capture_pcm.hex(),
            ]
        )
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return cls(process)

    @property
    def stderr_summary(self) -> SimulatedStderrSummary:
        if self._stderr_bytes == 0:
            classification: Literal["empty", "present", "truncated"] = "empty"
        elif self._stderr_truncated:
            classification = "truncated"
        else:
            classification = "present"
        return SimulatedStderrSummary(
            classification=classification,
            byte_count=self._stderr_bytes,
        )

    async def receive(self, max_bytes: int) -> bytes:
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FEED_BYTES:
            raise FakeVoiceError
        return await asyncio.wait_for(self._stdout.read(max_bytes), timeout=5.0)

    async def send(self, frame: bytes, *, priority: bool = False) -> PttSendCommit:
        del priority
        if self._closed or type(frame) is not bytes or not frame:
            raise FakeVoiceError
        self._stdin.write(frame)
        await asyncio.wait_for(self._stdin.drain(), timeout=5.0)
        return PttSendCommit.COMMITTED

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with suppress(BaseException):
            self._stdin.close()
        with suppress(BaseException):
            await asyncio.wait_for(self._stdin.wait_closed(), timeout=1.0)
        with suppress(BaseException):
            await asyncio.wait_for(self._process.wait(), timeout=1.0)
        if self._process.returncode is None:
            with suppress(ProcessLookupError):
                self._process.terminate()
            with suppress(BaseException):
                await asyncio.wait_for(self._process.wait(), timeout=1.0)
        if self._process.returncode is None:
            with suppress(ProcessLookupError):
                self._process.kill()
            with suppress(BaseException):
                await asyncio.wait_for(self._process.wait(), timeout=1.0)
        if not self._stderr_task.done():
            self._stderr_task.cancel()
        with suppress(BaseException):
            await self._stderr_task
        transport = getattr(self._process, "_transport", None)
        close_transport = getattr(transport, "close", None)
        if callable(close_transport):
            with suppress(BaseException):
                close_transport()
            await asyncio.sleep(0)

    async def _drain_stderr(self) -> None:
        while True:
            chunk = await self._stderr.read(512)
            if not chunk:
                return
            if self._stderr_bytes + len(chunk) > _STDERR_CLASSIFIER_BYTES:
                self._stderr_truncated = True
                self._stderr_bytes = _STDERR_CLASSIFIER_BYTES
            else:
                self._stderr_bytes += len(chunk)


class _MonotonicClock:
    def __init__(self) -> None:
        self._loop = asyncio.get_running_loop()

    def now(self) -> float:
        return self._loop.time()

    async def sleep_until(self, deadline: float) -> None:
        await asyncio.sleep(max(0.0, deadline - self.now()))


def fake_voice_pipeline(
    script: FakeVoiceScript | None = None,
    *,
    events: list[str] | None = None,
    clock: MonotonicClock | None = None,
) -> tuple[VoiceTurnPipeline, FakeVoiceRuntime]:
    selected = FakeVoiceScript() if script is None else script
    selected_clock = _MonotonicClock() if clock is None else clock
    runtime = FakeVoiceRuntime(selected, events=events)
    return (
        VoiceTurnPipeline(
            stt=runtime,
            llm=runtime,
            tts=runtime,
            authorizer=runtime,
            converter=Pcm16Converter(),
            tts_source_format=TTS_SOURCE_FORMAT,
            clock=selected_clock,
        ),
        runtime,
    )


async def run_fake_simulated_turn(
    script: FakeVoiceScript | None = None,
    *,
    managed_tree: Path | None = None,
    edge_command: Sequence[str] | None = None,
) -> PttSessionOutcome:
    del managed_tree
    selected = FakeVoiceScript() if script is None else script
    clock = _MonotonicClock()
    pipeline, cancellation = fake_voice_pipeline(selected, clock=clock)
    turn_id = uuid4()
    input_mode = PttInputMode.CORE_TERMINAL_TOGGLE
    bridge = await SimulatedEdgeBridge.spawn(
        turn_id=turn_id,
        input_mode=input_mode,
        capture_pcm=selected.capture_pcm,
        edge_command=edge_command,
    )
    supervisor = CorePttSessionSupervisor(
        input_mode=input_mode,
        bridge=bridge,
        pipeline=pipeline,
        provider_cancellation=cancellation,
        input_port=ScriptedPttInput(),
        clock=clock,
    )
    return await supervisor.run(turn_id)


def scan_tree_for_raw_sentinels(root: Path, sentinels: Sequence[bytes]) -> tuple[str, ...]:
    findings: list[str] = []
    normalized = tuple(sentinel for sentinel in sentinels if sentinel)
    if not normalized or not root.exists():
        return ()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if any(sentinel in data for sentinel in normalized):
            findings.append(str(path.relative_to(root)))
    return tuple(findings)


def _default_edge_command() -> list[str]:
    return [sys.executable, "-u", "-m", "tuntun_edge.cli.main", "simulate-ptt"]


def _request_id(turn_id: UUID, purpose: str) -> UUID:
    return uuid5(_NAMESPACE, f"{turn_id}:{purpose}")


def _commitment(raw: bytes, key_id: str) -> Commitment:
    digest = hashlib.sha256(raw).digest()
    return Commitment(
        algorithm="HMAC-SHA-256",
        key_id=key_id,
        value_b64=base64.b64encode(digest).decode("ascii"),
    )


def _route(
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"],
    request_id: UUID,
    *,
    turn_id: UUID,
    model: str,
    commitment: Commitment,
    max_input_bytes: int,
    max_input_units: int,
) -> RouteAuthorization:
    return RouteAuthorization(
        authorization_id=_request_id(request_id, "authorization"),
        request_id=request_id,
        attempt_id=_request_id(request_id, "attempt"),
        purpose=purpose,
        household_id=_request_id(turn_id, "household"),
        subject_id=None,
        session_id=_request_id(turn_id, "session"),
        turn_id=turn_id,
        provider=ProviderName.OPENAI.value,
        model=model,
        request_commitment=commitment,
        max_input_bytes=max_input_bytes,
        max_input_units=max_input_units,
        privacy_receipt_id=_request_id(request_id, "privacy"),
        consent_receipt_ids=(_request_id(request_id, "consent"),),
        budget_reservation_id=_request_id(request_id, "budget"),
        maximum_sensitivity=Sensitivity.PUBLIC,
        expires_at=_NOW + timedelta(minutes=5),
    )
