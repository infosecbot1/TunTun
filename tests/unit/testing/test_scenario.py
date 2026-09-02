from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import UUID

import pytest
from tuntun_contracts.budget import BudgetAccountingContext
from tuntun_contracts.identity import IdentityDecision, IdentityRequest, IdentityStatus
from tuntun_contracts.ports import (
    ActionProviderPort,
    AsyncTransactionBoundary,
    AuditPort,
    AuthenticationPort,
    BudgetPort,
    ClockPort,
    IdentityFusionPort,
    LanguageModelPort,
    MemoryProposalServicePort,
    MemoryRepositoryPort,
    PolicyEnginePort,
    ReachyPort,
    RouteAuthorizerPort,
    SpeechToTextPort,
    TextToSpeechPort,
)
from tuntun_contracts.provider import RouteAuthorization, RouteConsumption
from tuntun_contracts.speech import AuthorizedSynthesisRequest, SpeechChunk
from tuntun_testing.fake_clock import FakeClock
from tuntun_testing.fake_providers import (
    ExpectedCall,
    FakeActionProvider,
    FakeAudit,
    FakeAuthentication,
    FakeBudget,
    FakeIdentityFusion,
    FakeLanguageModel,
    FakeMemoryProposalService,
    FakeMemoryRepository,
    FakePolicyEngine,
    FakeRouteAuthorizer,
    FakeSpeechToText,
    FakeTextToSpeech,
    ObservedCall,
    RaiseError,
    ReturnValue,
    ScriptExhaustionError,
    UnexpectedCallError,
)
from tuntun_testing.fake_reachy import FakeReachy
from tuntun_testing.scenario import B2Evidence, guest_hinglish_scenario, parse_scenario
from tuntun_testing.scenario_io import ScenarioInput

_VALID_SCENARIO = (
    b"schema_version: '1.0'\n"
    b"name: guest-hinglish\n"
    b"identity: guest\n"
    b"transcript: synthetic-a\n"
    b"response: synthetic-b\n"
    b"language: hinglish\n"
    b"outcome: completed\n"
)


def _input(raw: bytes, name: str = "guest-hinglish.yaml") -> ScenarioInput:
    return ScenarioInput(name, raw, 1, 1)


def _accept_exact_ports(
    clock: ClockPort,
    stt: SpeechToTextPort,
    tts: TextToSpeechPort,
    llm: LanguageModelPort,
    identity: IdentityFusionPort,
    memory: MemoryRepositoryPort,
    proposal: MemoryProposalServicePort,
    policy: PolicyEnginePort,
    authentication: AuthenticationPort,
    action: ActionProviderPort,
    audit: AuditPort[AsyncTransactionBoundary],
    budget: BudgetPort,
    route: RouteAuthorizerPort,
    reachy: ReachyPort,
) -> None:
    assert all(
        value is not None
        for value in (
            clock,
            stt,
            tts,
            llm,
            identity,
            memory,
            proposal,
            policy,
            authentication,
            action,
            audit,
            budget,
            route,
            reachy,
        )
    )


def test_all_fakes_satisfy_the_frozen_task_5_ports() -> None:
    _accept_exact_ports(
        FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
        FakeSpeechToText(()),
        FakeTextToSpeech(()),
        FakeLanguageModel(()),
        FakeIdentityFusion(()),
        FakeMemoryRepository(()),
        FakeMemoryProposalService(()),
        FakePolicyEngine(()),
        FakeAuthentication(()),
        FakeActionProvider(()),
        FakeAudit(()),
        FakeBudget(()),
        FakeRouteAuthorizer(()),
        FakeReachy(()),
    )


def test_fake_clock_orders_callbacks_and_returns_immutable_calls() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    observed: list[str] = []
    cancelled = clock.call_later(1.0, lambda: observed.append("cancelled"))
    clock.call_later(1.0, lambda: observed.append("first"))
    clock.call_later(1.0, lambda: observed.append("second"))
    cancelled.cancel()
    clock.advance(1.0)
    assert observed == ["first", "second"]
    assert clock.now() == datetime(2026, 8, 27, 0, 0, 1, tzinfo=UTC)
    assert clock.monotonic() == 1.0
    assert clock.calls == ("now", "monotonic")
    with pytest.raises(ValueError, match="finite"):
        clock.advance(float("nan"))
    with pytest.raises(ValueError, match="timezone-aware"):
        FakeClock(datetime(2026, 8, 27))


def test_fake_clock_reentrant_advance_preserves_max_reached_time() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    clock.call_later(1.0, lambda: clock.advance(5.0))

    clock.advance(1.0)

    assert clock.monotonic() == 6.0
    assert clock.now() == datetime(2026, 8, 27, 0, 0, 6, tzinfo=UTC)


@pytest.mark.asyncio
async def test_scripted_fake_checks_arguments_faults_and_exhaustion() -> None:
    request = cast(IdentityRequest, object())
    other = cast(IdentityRequest, object())
    decision = IdentityDecision(
        status=IdentityStatus.UNKNOWN,
        subject_id=None,
        reason_code="synthetic.guest",
        expires_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    fake = FakeIdentityFusion(
        (ExpectedCall("identity.resolve", (request,), ReturnValue(decision)),)
    )
    with pytest.raises(UnexpectedCallError, match="unexpected-call"):
        await fake.resolve(other)
    before_calls = fake.calls
    assert before_calls == ()
    assert await fake.resolve(request) == decision
    fake.assert_exhausted()
    observed = fake.calls[0]
    with pytest.raises(FrozenInstanceError):
        observed.operation = "changed"  # type: ignore[misc]

    timeout = FakeIdentityFusion(
        (ExpectedCall("identity.resolve", (request,), RaiseError(TimeoutError())),)
    )
    with pytest.raises(TimeoutError):
        await timeout.resolve(request)
    timeout.assert_exhausted()

    malformed = FakeIdentityFusion(
        (ExpectedCall("identity.resolve", (request,), ReturnValue(object())),)
    )
    assert await malformed.resolve(request) is not decision
    malformed.assert_exhausted()

    pending = FakeIdentityFusion(
        (ExpectedCall("identity.resolve", (request,), ReturnValue(decision)),)
    )
    with pytest.raises(ScriptExhaustionError, match="script-not-exhausted"):
        pending.assert_exhausted()
    assert "request" not in repr(pending)


@pytest.mark.asyncio
async def test_fake_budget_scripts_accounting_context() -> None:
    route = cast(RouteAuthorization, object())
    consumption = cast(RouteConsumption, object())
    context = cast(BudgetAccountingContext, object())
    fake = FakeBudget(
        (
            ExpectedCall(
                "budget.require_accounting_context",
                (route, consumption),
                ReturnValue(context),
            ),
        )
    )

    assert await fake.require_accounting_context(route, consumption) is context
    fake.assert_exhausted()
    assert fake.calls == (
        ObservedCall("budget.require_accounting_context", (route, consumption)),
    )


@pytest.mark.asyncio
async def test_abandoned_tts_stream_is_not_silently_exhausted() -> None:
    request = cast(AuthorizedSynthesisRequest, object())
    chunk = SpeechChunk(
        request_id=UUID("00000000-0000-0000-0000-000000000901"),
        sequence=0,
        pcm=b"x",
        final=True,
    )
    fake = FakeTextToSpeech((ExpectedCall("tts.synthesize", (request,), ReturnValue((chunk,))),))
    stream = fake.synthesize(request)
    with pytest.raises(ScriptExhaustionError, match="stream-not-exhausted"):
        fake.assert_exhausted()
    assert [item async for item in stream] == [chunk]
    fake.assert_exhausted()

    partial = FakeTextToSpeech(
        (ExpectedCall("tts.synthesize", (request,), ReturnValue((chunk, chunk))),)
    )
    partial_stream = cast(AsyncGenerator[SpeechChunk, None], partial.synthesize(request))
    assert await anext(partial_stream) == chunk
    await partial_stream.aclose()
    with pytest.raises(ScriptExhaustionError, match="stream-not-exhausted"):
        partial.assert_exhausted()


@pytest.mark.parametrize(
    "raw",
    [
        _VALID_SCENARIO.replace(
            b"name: guest-hinglish\n",
            b"name: guest-hinglish\nname: guest-hinglish\n",
        ),
        _VALID_SCENARIO.replace(
            b"transcript: synthetic-a\nresponse: synthetic-b\n",
            b"transcript: &text synthetic-a\nresponse: *text\n",
        ),
        _VALID_SCENARIO.replace(b"'1.0'", b"!!str '1.0'"),
        b"%YAML 1.2\n---\n" + _VALID_SCENARIO,
        _VALID_SCENARIO.replace(b"'1.0'", b"'2.0'"),
        _VALID_SCENARIO.replace(b"synthetic-a", b'"synthetic-\\uD800"'),
        _VALID_SCENARIO.replace(b"synthetic-a", b"9" * 5_000),
        _VALID_SCENARIO.replace(b"synthetic-a", b"2026-99-99"),
        b"\xff",
        b"#" * 65_537,
    ],
)
def test_strict_yaml_rejects_noncanonical_or_ambiguous_documents(raw: bytes) -> None:
    with pytest.raises(ValueError, match="invalid-scenario-schema"):
        parse_scenario(_input(raw))


def test_guest_hinglish_downstream_api_is_stable() -> None:
    guest = guest_hinglish_scenario()
    assert len(guest.wav_bytes) == 16
    assert guest.events == []
    assert callable(guest.context_provider.prepare)
    assert isinstance(ObservedCall("operation", ()), ObservedCall)
    asyncio.run(FakeClock(datetime(2026, 8, 27, tzinfo=UTC)).sleep(0))


def test_b2_placeholder_is_exact_and_fillable_without_a_schema_change() -> None:
    assert B2Evidence().to_mapping() == {
        "duplicate_effect_count": None,
        "peak_rss_growth_bytes": None,
        "privacy_block_p95_ms": None,
        "private_sentinel_count": None,
        "status": "not_measured",
        "terminal_rss_growth_bytes": None,
        "warmup_turns": None,
    }
    measured = B2Evidence(
        status="pass",
        warmup_turns=50,
        terminal_rss_growth_bytes=32 * 1024 * 1024,
        peak_rss_growth_bytes=128 * 1024 * 1024,
        privacy_block_p95_ms=250,
        private_sentinel_count=0,
        duplicate_effect_count=0,
    )
    assert measured.to_mapping()["warmup_turns"] == 50
    with pytest.raises(ValueError, match="invalid-b2-evidence"):
        B2Evidence(status="pass")
    with pytest.raises(ValueError, match="invalid-b2-evidence"):
        B2Evidence(warmup_turns=50)
    with pytest.raises(ValueError, match="invalid-b2-evidence"):
        B2Evidence(
            status=cast(Literal["pass", "not_measured"], "invalid"),
            warmup_turns=50,
            terminal_rss_growth_bytes=0,
            peak_rss_growth_bytes=0,
            privacy_block_p95_ms=0,
            private_sentinel_count=0,
            duplicate_effect_count=0,
        )
    with pytest.raises(ValueError, match="invalid-b2-evidence"):
        B2Evidence(
            status="pass",
            warmup_turns=49,
            terminal_rss_growth_bytes=0,
            peak_rss_growth_bytes=0,
            privacy_block_p95_ms=0,
            private_sentinel_count=0,
            duplicate_effect_count=0,
        )


@pytest.mark.asyncio
async def test_guest_hinglish_drives_task_07_and_task_14_downstream_shapes() -> None:
    guest = guest_hinglish_scenario()
    turn_id = UUID("00000000-0000-0000-0000-000000000903")
    await guest.ports.start(turn_id)
    transcript = await guest.ports.transcribe(guest.wav_bytes)
    identity = await guest.ports.guest_identity()
    answer = await guest.ports.generate(transcript, identity)
    pcm = await guest.ports.synthesize(answer)
    await guest.ports.play(turn_id, pcm)
    await guest.ports.finish(turn_id)
    assert guest.events == [
        "session.start",
        "stt.reserve",
        "stt.authorize",
        "stt.call",
        "identity.guest",
        "reasoning.sanitize",
        "reasoning.reserve",
        "reasoning.authorize",
        "reasoning.call",
        "tts.dlp",
        "tts.reserve",
        "tts.authorize",
        "tts.call",
        "reachy.play",
        "turn.clear",
    ]

    personalized = guest_hinglish_scenario(turn_index=1)
    second_transcript = await personalized.ports.transcribe(personalized.wav_bytes)
    context = await personalized.context_provider.prepare(turn_id, second_transcript)
    assert context.reply_mode == "hinglish"
    assert await personalized.ports.generate(context) == "synthetic-namaste-welcome"
    assert personalized.events[:4] == [
        "stt.reserve",
        "stt.authorize",
        "stt.call",
        "identity.guest",
    ]
