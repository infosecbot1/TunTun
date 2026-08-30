from __future__ import annotations

import asyncio
import re
import unicodedata
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Literal, cast
from uuid import NAMESPACE_URL, UUID, uuid5

import yaml
from tuntun_contracts.audit import AuditDraft, AuditReceipt
from tuntun_contracts.base import Commitment, Sensitivity, canonical_mapping_bytes
from tuntun_contracts.identity import IdentityDecision, IdentityRequest, IdentityStatus
from tuntun_contracts.ports import AsyncTransactionBoundary
from tuntun_contracts.provider import (
    ProviderName,
    ProviderResponse,
    RouteAuthorization,
    RouteAuthorizationRequest,
    RouteConsumption,
    SanitizedProviderMessage,
    SanitizedProviderRequest,
)
from tuntun_contracts.reachy import ReachyCommand, ReachyReceipt
from tuntun_contracts.speech import (
    AudioFormat,
    AuthorizedSynthesisRequest,
    AuthorizedTranscriptionRequest,
    SpeechChunk,
    TranscriptResult,
)

from .fake_clock import FakeClock
from .fake_providers import (
    ExpectedCall,
    FakeAudit,
    FakeIdentityFusion,
    FakeLanguageModel,
    FakeRouteAuthorizer,
    FakeSpeechToText,
    FakeTextToSpeech,
    ObservedCall,
    ReturnValue,
    UnexpectedCallError,
)
from .fake_reachy import FakeReachy
from .scenario_io import MAX_SCENARIO_BYTES, ScenarioInput

MAX_YAML_TOKENS = 256
MAX_YAML_NODES = 128
MAX_YAML_DEPTH = 8
_SCENARIO_KEYS = frozenset(
    {"schema_version", "name", "identity", "transcript", "response", "language", "outcome"}
)
_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_FIXED_TIME = datetime(2026, 8, 27, tzinfo=UTC)
_ZERO_COMMITMENT = Commitment(
    algorithm="HMAC-SHA-256",
    key_id="scenario-hmac-v1",
    value_b64="A" * 43 + "=",
)


class ScenarioSchemaError(ValueError):
    pass


class _StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _StrictLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str or key in result:
            raise ScenarioSchemaError("invalid-scenario-schema")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    name: str
    identity: Literal["guest"]
    transcript: str
    response: str
    language: Literal["en", "hi", "hinglish"]
    outcome: Literal["completed"]


@dataclass(frozen=True, slots=True)
class ScenarioUsage:
    input_audio_bytes: int
    transcript_characters: int
    response_characters: int
    output_audio_bytes: int

    def to_mapping(self) -> dict[str, int]:
        return {
            "input_audio_bytes": self.input_audio_bytes,
            "output_audio_bytes": self.output_audio_bytes,
            "response_characters": self.response_characters,
            "transcript_characters": self.transcript_characters,
        }


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario: str
    turn_index: int
    turn_id: UUID
    identity: str
    language: str
    outcome: str
    transcript: str
    response: str
    events: tuple[str, ...]
    audit_receipt_ids: tuple[UUID, ...]
    usage: ScenarioUsage

    def to_mapping(self) -> dict[str, object]:
        return {
            "audit_receipt_ids": tuple(str(value) for value in self.audit_receipt_ids),
            "events": self.events,
            "identity": self.identity,
            "language": self.language,
            "outcome": self.outcome,
            "response": self.response,
            "scenario": self.scenario,
            "schema_version": "scenario_result.v1",
            "transcript": self.transcript,
            "turn_id": str(self.turn_id),
            "turn_index": self.turn_index,
            "usage": self.usage.to_mapping(),
        }

    def canonical_json(self) -> bytes:
        return canonical_mapping_bytes(self.to_mapping())


@dataclass(frozen=True, slots=True)
class FoundationResourceEvidence:
    status: Literal["pass", "not_measured"]
    fd_baseline: int | None
    fd_after: int | None
    fd_delta: int | None
    pending_tasks_baseline: int | None
    pending_tasks_after: int | None
    pending_tasks_delta: int | None

    @classmethod
    def not_measured(cls) -> FoundationResourceEvidence:
        return cls("not_measured", None, None, None, None, None, None)

    def to_mapping(self) -> dict[str, object]:
        return {
            "fd_after": self.fd_after,
            "fd_baseline": self.fd_baseline,
            "fd_delta": self.fd_delta,
            "pending_tasks_after": self.pending_tasks_after,
            "pending_tasks_baseline": self.pending_tasks_baseline,
            "pending_tasks_delta": self.pending_tasks_delta,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class B2Evidence:
    status: Literal["pass", "not_measured"] = "not_measured"
    warmup_turns: int | None = None
    terminal_rss_growth_bytes: int | None = None
    peak_rss_growth_bytes: int | None = None
    privacy_block_p95_ms: int | None = None
    private_sentinel_count: int | None = None
    duplicate_effect_count: int | None = None

    def __post_init__(self) -> None:
        values = (
            self.warmup_turns,
            self.terminal_rss_growth_bytes,
            self.peak_rss_growth_bytes,
            self.privacy_block_p95_ms,
            self.private_sentinel_count,
            self.duplicate_effect_count,
        )
        if self.status == "not_measured":
            if any(value is not None for value in values):
                raise ValueError("invalid-b2-evidence")
            return
        if (
            self.status != "pass"
            or self.warmup_turns != 50
            or any(value is None or type(value) is not int or value < 0 for value in values)
        ):
            raise ValueError("invalid-b2-evidence")

    def to_mapping(self) -> dict[str, object]:
        return {
            "duplicate_effect_count": self.duplicate_effect_count,
            "peak_rss_growth_bytes": self.peak_rss_growth_bytes,
            "privacy_block_p95_ms": self.privacy_block_p95_ms,
            "private_sentinel_count": self.private_sentinel_count,
            "status": self.status,
            "terminal_rss_growth_bytes": self.terminal_rss_growth_bytes,
            "warmup_turns": self.warmup_turns,
        }


@dataclass(frozen=True, slots=True)
class ScenarioGateRecord:
    name: str
    turns: int
    result_chain_sha256: str

    def to_mapping(self) -> dict[str, object]:
        return {
            "name": self.name,
            "result_chain_sha256": self.result_chain_sha256,
            "turns": self.turns,
        }


@dataclass(frozen=True, slots=True)
class ScenarioGateDocument:
    scenarios: tuple[ScenarioGateRecord, ...]
    foundation_resources: FoundationResourceEvidence
    b2: B2Evidence = B2Evidence()

    def to_mapping(self) -> dict[str, object]:
        return {
            "b2": self.b2.to_mapping(),
            "foundation_resources": self.foundation_resources.to_mapping(),
            "scenarios": tuple(item.to_mapping() for item in self.scenarios),
            "schema_version": "scenario_gate.v1",
            "status": "pass",
        }

    def canonical_json(self) -> bytes:
        return canonical_mapping_bytes(self.to_mapping())


def _bounded_node_count(node: yaml.nodes.Node, depth: int = 1) -> int:
    if depth > MAX_YAML_DEPTH:
        raise ScenarioSchemaError("invalid-scenario-schema")
    if isinstance(node, yaml.nodes.MappingNode):
        children = [child for pair in node.value for child in pair]
    elif isinstance(node, yaml.nodes.SequenceNode):
        children = list(node.value)
    else:
        children = []
    total = 1 + sum(_bounded_node_count(child, depth + 1) for child in children)
    if total > MAX_YAML_NODES:
        raise ScenarioSchemaError("invalid-scenario-schema")
    return total


def _strict_text(value: object, *, maximum: int, prefix: str | None = None) -> str:
    if type(value) is not str:
        raise ScenarioSchemaError("invalid-scenario-schema")
    try:
        normalized = unicodedata.normalize("NFC", value)
        encoded_length = len(value.encode("utf-8"))
    except UnicodeError as error:
        raise ScenarioSchemaError("invalid-scenario-schema") from error
    if (
        not value
        or len(value) > maximum
        or encoded_length > maximum * 4
        or value != normalized
        or not value.isprintable()
        or (prefix is not None and not value.startswith(prefix))
    ):
        raise ScenarioSchemaError("invalid-scenario-schema")
    return value


def parse_scenario(value: ScenarioInput) -> ScenarioSpec:
    if not 1 <= len(value.raw) <= MAX_SCENARIO_BYTES:
        raise ScenarioSchemaError("invalid-scenario-schema")
    try:
        text = value.raw.decode("utf-8", errors="strict")
        tokens = list(yaml.scan(text, Loader=_StrictLoader))
        forbidden = (
            yaml.tokens.AliasToken,
            yaml.tokens.AnchorToken,
            yaml.tokens.DirectiveToken,
            yaml.tokens.TagToken,
        )
        if len(tokens) > MAX_YAML_TOKENS or any(isinstance(token, forbidden) for token in tokens):
            raise ScenarioSchemaError("invalid-scenario-schema")
        node = yaml.compose(text, Loader=_StrictLoader)
        if node is None:
            raise ScenarioSchemaError("invalid-scenario-schema")
        _bounded_node_count(node)
        raw = yaml.load(text, Loader=_StrictLoader)
    except (
        UnicodeError,
        yaml.YAMLError,
        RecursionError,
        ValueError,
        OverflowError,
    ) as error:
        raise ScenarioSchemaError("invalid-scenario-schema") from error
    if type(raw) is not dict or set(raw) != _SCENARIO_KEYS:
        raise ScenarioSchemaError("invalid-scenario-schema")
    schema_version = _strict_text(raw["schema_version"], maximum=3)
    name = _strict_text(raw["name"], maximum=64)
    identity = _strict_text(raw["identity"], maximum=8)
    transcript = _strict_text(raw["transcript"], maximum=256, prefix="synthetic-")
    response = _strict_text(raw["response"], maximum=256, prefix="synthetic-")
    language = _strict_text(raw["language"], maximum=8)
    outcome = _strict_text(raw["outcome"], maximum=16)
    if (
        schema_version != "1.0"
        or _NAME_PATTERN.fullmatch(name) is None
        or value.normalized_name.rsplit("/", 1)[-1] != f"{name}.yaml"
        or identity != "guest"
        or language not in {"en", "hi", "hinglish"}
        or outcome != "completed"
    ):
        raise ScenarioSchemaError("invalid-scenario-schema")
    return ScenarioSpec(
        name=name,
        identity="guest",
        transcript=transcript,
        response=response,
        language=cast(Literal["en", "hi", "hinglish"], language),
        outcome="completed",
    )


class _Boundary:
    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


@dataclass(frozen=True, slots=True)
class ScenarioPorts:
    stt: FakeSpeechToText
    identity: FakeIdentityFusion
    llm: FakeLanguageModel
    tts: FakeTextToSpeech
    route_authorizer: FakeRouteAuthorizer
    reachy: FakeReachy
    audit: FakeAudit

    def assert_exhausted(self) -> None:
        self.stt.assert_exhausted()
        self.identity.assert_exhausted()
        self.llm.assert_exhausted()
        self.tts.assert_exhausted()
        self.route_authorizer.assert_exhausted()
        self.reachy.assert_exhausted()
        self.audit.assert_exhausted()


@dataclass(frozen=True, slots=True)
class _PreparedTurn:
    ports: ScenarioPorts
    boundary: AsyncTransactionBoundary
    wav_bytes: bytes
    stt_route_request: RouteAuthorizationRequest
    stt_request: AuthorizedTranscriptionRequest
    stt_consumption: RouteConsumption
    identity_request: IdentityRequest
    reasoning_route_request: RouteAuthorizationRequest
    provider_request: SanitizedProviderRequest
    reasoning_consumption: RouteConsumption
    tts_route_request: RouteAuthorizationRequest
    synthesis_request: AuthorizedSynthesisRequest
    tts_consumption: RouteConsumption
    reachy_command: ReachyCommand
    audit_draft: AuditDraft


@dataclass(frozen=True, slots=True)
class SyntheticTranscribedTurn:
    text: str
    stt_language: Literal["hinglish"] = "hinglish"
    explicit_reply_language: None = None


@dataclass(frozen=True, slots=True)
class SyntheticProviderTurnContext:
    messages: tuple[dict[str, str], ...]
    reply_mode: Literal["hinglish"] = "hinglish"
    prompt_bundle_sha256: str = "0" * 64


class GuestContextProvider:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def prepare(
        self,
        turn_id: UUID,
        transcript: object,
    ) -> SyntheticProviderTurnContext:
        text = getattr(transcript, "text", None)
        if (
            not isinstance(turn_id, UUID)
            or type(text) is not str
            or not text.startswith("synthetic-")
        ):
            raise UnexpectedCallError("unexpected-call")
        self._events.append("identity.guest")
        return SyntheticProviderTurnContext(
            messages=(
                {"role": "system", "content": "synthetic-guest-context"},
                {"role": "user", "content": text},
            )
        )


class GuestWorkflowPorts:
    def __init__(self, events: list[str], wav_bytes: bytes) -> None:
        self._events = events
        self._wav_bytes = wav_bytes
        self._answer = "synthetic-namaste-welcome"
        self._pcm = UUID("00000000-0000-0000-0000-000000000902").bytes

    async def start(self, turn_id: UUID) -> None:
        if not isinstance(turn_id, UUID):
            raise UnexpectedCallError("unexpected-call")
        self._events.append("session.start")

    async def transcribe(self, wav_bytes: bytes) -> Any:
        if wav_bytes != self._wav_bytes:
            raise UnexpectedCallError("unexpected-call")
        self._events.extend(("stt.reserve", "stt.authorize", "stt.call"))
        return SyntheticTranscribedTurn(text="synthetic-namaste-hello")

    async def guest_identity(self) -> str:
        self._events.append("identity.guest")
        return "guest"

    async def generate(self, *arguments: object) -> str:
        if len(arguments) not in {1, 2}:
            raise UnexpectedCallError("unexpected-call")
        if len(arguments) == 2 and (
            getattr(arguments[0], "text", None) != "synthetic-namaste-hello"
            or arguments[1] != "guest"
        ):
            raise UnexpectedCallError("unexpected-call")
        if len(arguments) == 1 and not isinstance(arguments[0], SyntheticProviderTurnContext):
            raise UnexpectedCallError("unexpected-call")
        self._events.extend(
            ("reasoning.sanitize", "reasoning.reserve", "reasoning.authorize", "reasoning.call")
        )
        return self._answer

    async def synthesize(self, answer: str) -> bytes:
        if answer != self._answer:
            raise UnexpectedCallError("unexpected-call")
        self._events.extend(("tts.dlp", "tts.reserve", "tts.authorize", "tts.call"))
        return self._pcm

    async def play(self, turn_id: UUID, pcm: bytes) -> None:
        if not isinstance(turn_id, UUID) or pcm != self._pcm:
            raise UnexpectedCallError("unexpected-call")
        self._events.append("reachy.play")

    async def finish(self, turn_id: UUID) -> None:
        if not isinstance(turn_id, UUID):
            raise UnexpectedCallError("unexpected-call")
        self._events.append("turn.clear")


@dataclass(frozen=True, slots=True)
class GuestScenario:
    ports: GuestWorkflowPorts
    wav_bytes: bytes
    events: list[str]
    context_provider: GuestContextProvider


def _identifier(name: str, turn_index: int, label: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"tuntun:{name}:{turn_index}:{label}")


def _route(
    spec: ScenarioSpec,
    turn_index: int,
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"],
    request_id: UUID,
    turn_id: UUID,
    household_id: UUID,
    session_id: UUID,
) -> tuple[RouteAuthorizationRequest, RouteAuthorization, RouteConsumption]:
    attempt_id = _identifier(spec.name, turn_index, f"{purpose}:attempt")
    authorization_id = _identifier(spec.name, turn_index, f"{purpose}:authorization")
    model = {
        "cloud_stt": "synthetic-stt",
        "cloud_reasoning": "synthetic-llm",
        "cloud_tts": "synthetic-tts",
    }[purpose]
    maximum_bytes = 16 if purpose == "cloud_stt" else 4_096
    common: dict[str, Any] = {
        "request_id": request_id,
        "attempt_id": attempt_id,
        "purpose": purpose,
        "household_id": household_id,
        "subject_id": None,
        "session_id": session_id,
        "turn_id": turn_id,
        "provider": "openai",
        "model": model,
        "request_commitment": _ZERO_COMMITMENT,
        "max_input_bytes": maximum_bytes,
        "max_input_units": 4_096,
        "privacy_receipt_id": _identifier(spec.name, turn_index, f"{purpose}:privacy"),
        "consent_receipt_ids": (_identifier(spec.name, turn_index, f"{purpose}:consent"),),
        "budget_reservation_id": _identifier(spec.name, turn_index, f"{purpose}:budget"),
        "maximum_sensitivity": Sensitivity.PUBLIC,
    }
    request = RouteAuthorizationRequest(**common)
    authorization = RouteAuthorization(
        authorization_id=authorization_id,
        expires_at=_FIXED_TIME + timedelta(minutes=5),
        **common,
    )
    consumption = RouteConsumption(
        request_id=request_id,
        attempt_id=attempt_id,
        purpose=purpose,
        household_id=household_id,
        subject_id=None,
        session_id=session_id,
        turn_id=turn_id,
        provider="openai",
        model=model,
        request_commitment=_ZERO_COMMITMENT,
        input_bytes=maximum_bytes,
        input_units=1,
        consumed_at=_FIXED_TIME,
    )
    return request, authorization, consumption


def _prepare_turn(
    spec: ScenarioSpec,
    turn_index: int,
    observer: Callable[[ObservedCall], None],
) -> _PreparedTurn:
    turn_id = _identifier(spec.name, turn_index, "turn")
    household_id = _identifier(spec.name, turn_index, "household")
    session_id = _identifier(spec.name, turn_index, "session")
    wav_bytes = _identifier(spec.name, turn_index, "audio").bytes
    stt_request_id = _identifier(spec.name, turn_index, "stt:request")
    reasoning_request_id = _identifier(spec.name, turn_index, "reasoning:request")
    tts_request_id = _identifier(spec.name, turn_index, "tts:request")
    stt_route_request, stt_route, stt_consumption = _route(
        spec, turn_index, "cloud_stt", stt_request_id, turn_id, household_id, session_id
    )
    reasoning_route_request, reasoning_route, reasoning_consumption = _route(
        spec,
        turn_index,
        "cloud_reasoning",
        reasoning_request_id,
        turn_id,
        household_id,
        session_id,
    )
    tts_route_request, tts_route, tts_consumption = _route(
        spec, turn_index, "cloud_tts", tts_request_id, turn_id, household_id, session_id
    )
    stt_request = AuthorizedTranscriptionRequest(
        request_id=stt_request_id,
        turn_id=turn_id,
        audio_format=AudioFormat(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=1,
            interleaved=True,
            channel_layout="mono",
        ),
        audio_commitment=_ZERO_COMMITMENT,
        audio_bytes=len(wav_bytes),
        duration_ms=1,
        language_hints=("hi", "en"),
        route=stt_route,
    )
    transcript = TranscriptResult(
        request_id=stt_request_id,
        text=spec.transcript,
        language=spec.language,
        duration_ms=1,
    )
    identity_request = IdentityRequest(
        household_id=household_id,
        session_id=session_id,
        evidence=(),
    )
    identity = IdentityDecision(
        status=IdentityStatus.UNKNOWN,
        subject_id=None,
        reason_code="synthetic.guest",
        expires_at=_FIXED_TIME + timedelta(minutes=5),
    )
    provider_request = SanitizedProviderRequest(
        request_id=reasoning_request_id,
        provider=ProviderName.OPENAI,
        model="synthetic-llm",
        messages=(SanitizedProviderMessage(role="user", content=spec.transcript),),
        allowed_tools=(),
        max_output_tokens=128,
        redaction_receipt_id=_identifier(spec.name, turn_index, "reasoning:redaction"),
        route=reasoning_route,
        timeout_ms=1_000,
    )
    response = ProviderResponse(
        request_id=reasoning_request_id,
        text=spec.response,
        language=spec.language,
        provider_usage_receipt_id=_identifier(spec.name, turn_index, "reasoning:usage"),
    )
    synthesis_request = AuthorizedSynthesisRequest(
        request_id=tts_request_id,
        turn_id=turn_id,
        text=spec.response,
        text_commitment=_ZERO_COMMITMENT,
        segment_index=0,
        segment_count=1,
        language=spec.language,
        dlp_receipt_id=_identifier(spec.name, turn_index, "tts:dlp"),
        route=tts_route,
    )
    speech_chunk = SpeechChunk(
        request_id=tts_request_id,
        sequence=0,
        pcm=_identifier(spec.name, turn_index, "speech").bytes,
        final=True,
    )
    reachy_command = ReachyCommand(
        command_id=_identifier(spec.name, turn_index, "reachy:command"),
        turn_id=turn_id,
        kind="playback",
        state=None,
        media_stream_id=_identifier(spec.name, turn_index, "reachy:stream"),
        gesture_id=None,
        expires_at=_FIXED_TIME + timedelta(seconds=5),
    )
    reachy_receipt = ReachyReceipt(
        command_id=reachy_command.command_id,
        accepted=True,
        reason_code="synthetic.accepted",
    )
    audit_draft = AuditDraft(
        event_id=_identifier(spec.name, turn_index, "audit:event"),
        occurred_at=_FIXED_TIME,
        actor_pseudonym="guest",
        action_code="conversation.completed",
        outcome=spec.outcome,
        reason_code="synthetic.completed",
        correlation_id=turn_id,
        payload_commitment=_ZERO_COMMITMENT,
    )
    audit_receipt = AuditReceipt(
        receipt_id=_identifier(spec.name, turn_index, "audit:receipt"),
        ordinal=1,
        public_hash_hex="0" * 64,
        hmac_key_id="scenario-hmac-v1",
        hmac_b64="A" * 43 + "=",
        occurred_at=_FIXED_TIME,
    )
    boundary = _Boundary()
    route_expectations = (
        ExpectedCall("route.authorize", (stt_route_request,), ReturnValue(stt_route)),
        ExpectedCall(
            "route.consume",
            (stt_route.authorization_id, stt_consumption),
            ReturnValue(None),
        ),
        ExpectedCall("route.authorize", (reasoning_route_request,), ReturnValue(reasoning_route)),
        ExpectedCall(
            "route.consume",
            (reasoning_route.authorization_id, reasoning_consumption),
            ReturnValue(None),
        ),
        ExpectedCall("route.authorize", (tts_route_request,), ReturnValue(tts_route)),
        ExpectedCall(
            "route.consume",
            (tts_route.authorization_id, tts_consumption),
            ReturnValue(None),
        ),
    )
    ports = ScenarioPorts(
        stt=FakeSpeechToText(
            (ExpectedCall("stt.transcribe", (stt_request, wav_bytes), ReturnValue(transcript)),),
            observer,
        ),
        identity=FakeIdentityFusion(
            (ExpectedCall("identity.resolve", (identity_request,), ReturnValue(identity)),),
            observer,
        ),
        llm=FakeLanguageModel(
            (ExpectedCall("llm.complete", (provider_request,), ReturnValue(response)),),
            observer,
        ),
        tts=FakeTextToSpeech(
            (ExpectedCall("tts.synthesize", (synthesis_request,), ReturnValue((speech_chunk,))),),
            observer,
        ),
        route_authorizer=FakeRouteAuthorizer(route_expectations, observer),
        reachy=FakeReachy(
            (ExpectedCall("reachy.send", (reachy_command,), ReturnValue(reachy_receipt)),),
            observer,
        ),
        audit=FakeAudit(
            (ExpectedCall("audit.append", (boundary, audit_draft), ReturnValue(audit_receipt)),),
            observer,
        ),
    )
    return _PreparedTurn(
        ports=ports,
        boundary=boundary,
        wav_bytes=wav_bytes,
        stt_route_request=stt_route_request,
        stt_request=stt_request,
        stt_consumption=stt_consumption,
        identity_request=identity_request,
        reasoning_route_request=reasoning_route_request,
        provider_request=provider_request,
        reasoning_consumption=reasoning_consumption,
        tts_route_request=tts_route_request,
        synthesis_request=synthesis_request,
        tts_consumption=tts_consumption,
        reachy_command=reachy_command,
        audit_draft=audit_draft,
    )


async def _audio(value: bytes) -> AsyncIterator[bytes]:
    yield value


class ScenarioRunner:
    def run(self, value: ScenarioInput, *, turn_index: int = 0) -> ScenarioResult:
        return asyncio.run(self.run_async(value, turn_index=turn_index))

    async def run_async(self, value: ScenarioInput, *, turn_index: int = 0) -> ScenarioResult:
        if turn_index < 0 or turn_index > 9_999:
            raise ValueError("invalid-turn-index")
        spec = parse_scenario(value)
        observed: list[ObservedCall] = []
        prepared = _prepare_turn(spec, turn_index, observed.append)
        clock = FakeClock(_FIXED_TIME)
        if clock.now() != _FIXED_TIME:
            raise AssertionError("clock-mismatch")
        ports = prepared.ports
        stt_route = await ports.route_authorizer.authorize(prepared.stt_route_request)
        if stt_route != prepared.stt_request.route:
            raise AssertionError("route-mismatch")
        transcript = await ports.stt.transcribe(prepared.stt_request, _audio(prepared.wav_bytes))
        await ports.route_authorizer.consume(stt_route.authorization_id, prepared.stt_consumption)
        identity = await ports.identity.resolve(prepared.identity_request)
        reasoning_route = await ports.route_authorizer.authorize(prepared.reasoning_route_request)
        if reasoning_route != prepared.provider_request.route:
            raise AssertionError("route-mismatch")
        response = await ports.llm.complete(prepared.provider_request)
        await ports.route_authorizer.consume(
            reasoning_route.authorization_id,
            prepared.reasoning_consumption,
        )
        tts_route = await ports.route_authorizer.authorize(prepared.tts_route_request)
        if tts_route != prepared.synthesis_request.route:
            raise AssertionError("route-mismatch")
        chunks = [chunk async for chunk in ports.tts.synthesize(prepared.synthesis_request)]
        if not chunks or not chunks[-1].final:
            raise AssertionError("incomplete-speech-stream")
        await ports.route_authorizer.consume(tts_route.authorization_id, prepared.tts_consumption)
        reachy_receipt = await ports.reachy.send(prepared.reachy_command)
        if not reachy_receipt.accepted:
            raise AssertionError("reachy-rejected")
        audit_receipt = await ports.audit.append(prepared.boundary, prepared.audit_draft)
        await prepared.boundary.commit()
        ports.assert_exhausted()
        events = ("wake.detected", "audio.synthetic", *(call.operation for call in observed))
        return ScenarioResult(
            scenario=spec.name,
            turn_index=turn_index,
            turn_id=prepared.stt_request.turn_id,
            identity=spec.identity if identity.status is IdentityStatus.UNKNOWN else "invalid",
            language=response.language,
            outcome=spec.outcome,
            transcript=transcript.text,
            response=response.text,
            events=events,
            audit_receipt_ids=(audit_receipt.receipt_id,),
            usage=ScenarioUsage(
                input_audio_bytes=len(prepared.wav_bytes),
                transcript_characters=len(transcript.text),
                response_characters=len(response.text),
                output_audio_bytes=sum(len(chunk.pcm) for chunk in chunks),
            ),
        )


def guest_hinglish_scenario(*, turn_index: int = 0) -> GuestScenario:
    if turn_index < 0 or turn_index > 9_999:
        raise ValueError("invalid-turn-index")
    events: list[str] = []
    wav_bytes = _identifier("guest-hinglish", turn_index, "audio").bytes
    return GuestScenario(
        ports=GuestWorkflowPorts(events, wav_bytes),
        wav_bytes=wav_bytes,
        events=events,
        context_provider=GuestContextProvider(events),
    )


def result_chain(results: tuple[ScenarioResult, ...]) -> str:
    digest = sha256()
    for result in results:
        canonical = result.canonical_json()
        digest.update(len(canonical).to_bytes(8, byteorder="big"))
        digest.update(canonical)
    return digest.hexdigest()
