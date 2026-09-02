from __future__ import annotations

import asyncio
import unicodedata
from collections.abc import AsyncGenerator, AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import uuid4

import pytest
from tuntun_contracts.base import Commitment, Sensitivity
from tuntun_contracts.budget import LlmUsageUnits, SttUsageUnits, TtsUsageUnits
from tuntun_contracts.speech import SpeechChunk
from tuntun_core.services.providers.attempts import (
    AttemptRunner,
    AttemptTemplate,
    RetryPolicy,
    TransientProviderError,
)
from tuntun_core.services.providers.gateway import (
    ProviderNotSentCancellation,
    ProviderNotSentError,
)
from tuntun_testing.fake_clock import FakeClock
from tuntun_testing.fake_providers import (
    RecordingBudget,
    RecordingRouteAuthorizer,
    RecordingTurnAttempts,
)

WAIT_SECONDS = 1.0


async def _collect_speech(stream: AsyncIterator[SpeechChunk]) -> list[SpeechChunk]:
    return [chunk async for chunk in stream]


def _reasoning_template() -> AttemptTemplate:
    return AttemptTemplate(
        request_id=uuid4(),
        purpose="cloud_reasoning",
        household_id=uuid4(),
        subject_id=None,
        session_id=uuid4(),
        turn_id=uuid4(),
        provider="openai",
        model="gpt-5.6-sol",
        request_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="route-hmac-v1",
            value_b64="A" * 43 + "=",
        ),
        max_input_bytes=32_000,
        max_input_units=8_000,
        input_bytes=8_000,
        input_units=2_000,
        privacy_receipt_id=uuid4(),
        consent_receipt_ids=(uuid4(),),
        maximum_sensitivity=Sensitivity.HOUSEHOLD,
        month_key="2026-08",
        category="llm",
        usage_ceiling=LlmUsageUnits(
            category="llm",
            input_tokens=8_000,
            output_tokens=4_000,
        ),
    )


def _tts_template() -> AttemptTemplate:
    return AttemptTemplate(
        request_id=uuid4(),
        purpose="cloud_tts",
        household_id=uuid4(),
        subject_id=None,
        session_id=uuid4(),
        turn_id=uuid4(),
        provider="openai",
        model="tts-1",
        request_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="route-hmac-v1",
            value_b64="A" * 43 + "=",
        ),
        max_input_bytes=4_096,
        max_input_units=4_096,
        input_bytes=12,
        input_units=12,
        privacy_receipt_id=uuid4(),
        consent_receipt_ids=(uuid4(),),
        maximum_sensitivity=Sensitivity.HOUSEHOLD,
        month_key="2026-08",
        category="tts",
        usage_ceiling=TtsUsageUnits(category="tts", characters=4_096),
    )


def _stt_template() -> AttemptTemplate:
    return AttemptTemplate(
        request_id=uuid4(),
        purpose="cloud_stt",
        household_id=uuid4(),
        subject_id=None,
        session_id=uuid4(),
        turn_id=uuid4(),
        provider="openai",
        model="gpt-transcribe",
        request_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="route-hmac-v1",
            value_b64="A" * 43 + "=",
        ),
        max_input_bytes=8_388_608,
        max_input_units=90_000,
        input_bytes=1_024,
        input_units=500,
        privacy_receipt_id=uuid4(),
        consent_receipt_ids=(uuid4(),),
        maximum_sensitivity=Sensitivity.PERSONAL,
        month_key="2026-08",
        category="stt",
        usage_ceiling=SttUsageUnits(category="stt", audio_millis=90_000),
    )


@pytest.mark.parametrize("purpose", ("web_search", "experimental_web_search"))
def test_search_attempt_purposes_fail_closed_with_controlled_error(purpose: str) -> None:
    with pytest.raises(ValueError, match="attempt_budget_purpose_mismatch"):
        replace(
            _reasoning_template(),
            purpose=cast(
                Literal["cloud_stt", "cloud_reasoning", "cloud_tts"],
                purpose,
            ),
        )


class _BlockingSettlementBudget(RecordingBudget):
    def __init__(self, clock: FakeClock) -> None:
        super().__init__(clock)
        self.settle_started = asyncio.Event()
        self.allow_settle = asyncio.Event()

    async def settle(self, request):
        self.settle_started.set()
        await self.allow_settle.wait()
        return await super().settle(request)


class _BlockingReleaseBudget(RecordingBudget):
    def __init__(self, clock: FakeClock) -> None:
        super().__init__(clock)
        self.release_started = asyncio.Event()
        self.allow_release = asyncio.Event()

    async def release_unsent(self, reservation_id, attempt_id, proof):
        self.release_started.set()
        await self.allow_release.wait()
        return await super().release_unsent(reservation_id, attempt_id, proof)


def test_retry_policy_rejects_global_attempt_counts_above_two() -> None:
    with pytest.raises(ValueError, match="invalid retry policy"):
        RetryPolicy(max_attempts=3, base_delay_ms=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("run", "stream"))
async def test_stt_attempt_policy_above_one_fails_before_reservation(
    mode: Literal["run", "stream"],
) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    invoked = False

    async def invoke_run(_route, _consumption) -> str:
        nonlocal invoked
        invoked = True
        return "unreachable"

    def invoke_stream(_route, _consumption) -> AsyncIterator[SpeechChunk]:
        async def source() -> AsyncIterator[SpeechChunk]:
            nonlocal invoked
            invoked = True
            yield SpeechChunk(request_id=uuid4(), sequence=0, pcm=b"pcm", final=False)

        return source()

    with pytest.raises(ValueError, match="retry_policy_exceeds_purpose_ceiling"):
        if mode == "run":
            await runner.run(
                _stt_template(),
                RetryPolicy(max_attempts=2, base_delay_ms=1),
                invoke_run,
            )
        else:
            await _collect_speech(
                runner.stream(
                    _stt_template(),
                    RetryPolicy(max_attempts=2, base_delay_ms=1),
                    invoke_stream,
                )
            )

    assert invoked is False
    assert budget.reservation_ids == []
    assert attempts.tracked == []


@pytest.mark.asyncio
async def test_reasoning_retry_has_distinct_authorization_and_reservation() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    authority = RecordingRouteAuthorizer(clock)
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(authority=authority, budget=budget, turn_attempts=attempts, clock=clock)
    calls = 0
    template = _reasoning_template()

    async def invoke(route, _supplied) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TransientProviderError(503, "never_sent", "connect_failed")
        await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
        budget.record_exact_usage(route.attempt_id)
        return "ok"

    result = await runner.run(
        template=template,
        policy=RetryPolicy(max_attempts=2, base_delay_ms=1),
        invoke=invoke,
    )

    assert result == "ok"
    assert len(set(authority.attempt_ids)) == 2
    assert len(set(budget.reservation_ids)) == 2
    assert len(budget.released_pairs) == 1
    assert budget.conservative_settlements == []
    assert len(attempts.tracked) == 2
    assert attempts.completed == attempts.tracked
    assert attempts.all_completions_after_budget_commit(budget)


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition", ("sent", "unknown"))
async def test_reasoning_sent_or_unknown_retryable_failure_never_retries(
    disposition: Literal["sent", "unknown"],
) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    authority = RecordingRouteAuthorizer(clock)
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(authority=authority, budget=budget, turn_attempts=attempts, clock=clock)
    calls = 0

    async def invoke(route, _supplied) -> str:
        nonlocal calls
        calls += 1
        if disposition == "sent":
            await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
        raise TransientProviderError(503, disposition, "http_503")

    with pytest.raises(TransientProviderError, match="http_503"):
        await runner.run(
            template=_reasoning_template(),
            policy=RetryPolicy(max_attempts=2, base_delay_ms=1),
            invoke=invoke,
        )

    assert calls == 1
    assert len(authority.attempt_ids) == 1
    assert len(budget.reservation_ids) == 1
    assert budget.released_pairs == set()
    assert len(budget.conservative_settlements) == 1
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cause",
    (PermissionError("receipt mismatch"), RuntimeError("mark sent failed")),
)
async def test_gateway_pre_network_failure_releases_reservation_without_egress(
    cause: Exception,
) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    network_calls = 0

    async def fail_before_network(route, _consumption) -> str:
        raise ProviderNotSentError(
            route.budget_reservation_id,
            route.attempt_id,
            "claim_or_mark_sent_failed_before_network",
            cause,
        )

    with pytest.raises(type(cause), match=str(cause)):
        await runner.run(
            _reasoning_template(),
            RetryPolicy(max_attempts=1, base_delay_ms=1),
            fail_before_network,
        )
    assert network_calls == 0
    assert budget.released_pairs == set(budget.terminal_pairs)
    assert budget.conservative_settlements == []
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ("error", "cancellation"))
async def test_run_provider_not_sent_scope_mismatch_settles_active_without_retry(
    kind: Literal["error", "cancellation"],
) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    authority = RecordingRouteAuthorizer(clock)
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(authority, budget, attempts, clock)
    calls = 0

    async def invoke(_route, _consumption) -> str:
        nonlocal calls
        calls += 1
        if kind == "cancellation":
            raise ProviderNotSentCancellation(
                uuid4(),
                uuid4(),
                "claim_cancelled_before_network",
                asyncio.CancelledError("wrong scoped cancellation"),
            )
        raise ProviderNotSentError(
            uuid4(),
            uuid4(),
            "claim_failed_before_network",
            RuntimeError("wrong scoped failure"),
        )

    with pytest.raises(PermissionError, match="provider_unsent_scope_mismatch"):
        await runner.run(
            _reasoning_template(),
            RetryPolicy(max_attempts=2, base_delay_ms=1),
            invoke,
        )

    assert calls == 1
    assert len(authority.attempt_ids) == 1
    assert len(budget.reservation_ids) == 1
    assert budget.released_pairs == set()
    assert budget.conservative_settlements == [budget.reservation_ids[0]]
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ("error", "cancellation"))
async def test_stream_provider_not_sent_scope_mismatch_settles_active_without_retry(
    kind: Literal["error", "cancellation"],
) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    authority = RecordingRouteAuthorizer(clock)
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(authority, budget, attempts, clock)
    template = _tts_template()
    calls = 0

    def invoke(_route, _consumption) -> AsyncIterator[SpeechChunk]:
        nonlocal calls
        calls += 1

        async def source() -> AsyncIterator[SpeechChunk]:
            if kind == "cancellation":
                raise ProviderNotSentCancellation(
                    uuid4(),
                    uuid4(),
                    "claim_cancelled_before_network",
                    asyncio.CancelledError("wrong scoped cancellation"),
                )
            raise ProviderNotSentError(
                uuid4(),
                uuid4(),
                "claim_failed_before_network",
                RuntimeError("wrong scoped failure"),
            )
            if False:
                yield SpeechChunk(
                    request_id=template.request_id,
                    sequence=0,
                    pcm=b"unreachable",
                    final=False,
                )

        return source()

    with pytest.raises(PermissionError, match="provider_unsent_scope_mismatch"):
        await _collect_speech(
            runner.stream(template, RetryPolicy(max_attempts=2, base_delay_ms=1), invoke)
        )

    assert calls == 1
    assert len(authority.attempt_ids) == 1
    assert len(budget.reservation_ids) == 1
    assert budget.released_pairs == set()
    assert budget.conservative_settlements == [budget.reservation_ids[0]]
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
async def test_stt_local_byte_mismatch_releases_without_network_or_ledger() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    network_calls = 0

    async def invoke(_route, _consumption) -> str:
        nonlocal network_calls
        body = b"short"
        declared_bytes = len(body) + 1
        if len(body) != declared_bytes:
            raise ValueError("WAV byte count mismatch")
        network_calls += 1
        return "unreachable"

    with pytest.raises(ValueError, match="WAV byte count mismatch"):
        await runner.run(
            _stt_template(),
            RetryPolicy(max_attempts=1, base_delay_ms=1),
            invoke,
        )
    assert network_calls == 0
    assert budget.released_pairs == budget.terminal_pairs
    assert budget.conservative_settlements == []
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
async def test_tts_local_non_nfc_releases_without_network_or_ledger() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()
    network_calls = 0

    def invoke(_route, _consumption) -> AsyncIterator[SpeechChunk]:
        async def source() -> AsyncIterator[SpeechChunk]:
            nonlocal network_calls
            text = "e\u0301"
            if unicodedata.normalize("NFC", text) != text:
                raise ValueError("tts_text_must_be_bounded_nfc")
            network_calls += 1
            if False:
                yield SpeechChunk(
                    request_id=template.request_id,
                    sequence=0,
                    pcm=b"unreachable",
                    final=False,
                )

        return source()

    with pytest.raises(ValueError, match="tts_text_must_be_bounded_nfc"):
        await _collect_speech(
            runner.stream(template, RetryPolicy(max_attempts=1, base_delay_ms=1), invoke)
        )
    assert network_calls == 0
    assert budget.released_pairs == budget.terminal_pairs
    assert budget.conservative_settlements == []
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
async def test_stt_never_retries_after_upload() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    runner = AttemptRunner(
        RecordingRouteAuthorizer(clock),
        budget,
        RecordingTurnAttempts(budget),
        clock,
    )
    template = _stt_template()

    async def fail(route, _supplied) -> str:
        await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
        raise TransientProviderError(503, "sent", "http_503")

    with pytest.raises(TransientProviderError):
        await runner.run(
            template=template,
            policy=RetryPolicy(max_attempts=1, base_delay_ms=1),
            invoke=fail,
        )


@pytest.mark.asyncio
async def test_stream_terminal_marker_is_budget_and_turn_completion_barrier() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = _BlockingSettlementBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()

    def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
        async def source() -> AsyncIterator[SpeechChunk]:
            await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
            yield SpeechChunk(request_id=template.request_id, sequence=0, pcm=b"pcm", final=False)
            budget.record_exact_usage(route.attempt_id)
            yield SpeechChunk(request_id=template.request_id, sequence=1, pcm=b"", final=True)

        return source()

    stream = cast(
        AsyncGenerator[SpeechChunk, None],
        runner.stream(template, RetryPolicy(max_attempts=1, base_delay_ms=1), invoke),
    )
    first = await asyncio.wait_for(anext(stream), WAIT_SECONDS)
    assert first.pcm == b"pcm" and not budget.terminal_pairs
    terminal_task = asyncio.create_task(anext(stream))
    await asyncio.wait_for(budget.settle_started.wait(), WAIT_SECONDS)
    assert not terminal_task.done() and attempts.completed == []
    budget.allow_settle.set()
    terminal = await asyncio.wait_for(terminal_task, WAIT_SECONDS)
    assert terminal.final and terminal.pcm == b""
    assert len(budget.terminal_pairs) == len(attempts.completed) == 1
    await asyncio.wait_for(stream.aclose(), WAIT_SECONDS)
    assert len(budget.terminal_pairs) == len(attempts.completed) == 1


@pytest.mark.asyncio
async def test_stream_retries_only_never_sent_before_first_chunk() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    authority = RecordingRouteAuthorizer(clock)
    runner = AttemptRunner(authority, budget, attempts, clock)
    template = _tts_template()
    calls = 0

    def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
        nonlocal calls
        calls += 1
        this_attempt = calls

        async def source() -> AsyncIterator[SpeechChunk]:
            if this_attempt == 1:
                raise TransientProviderError(503, "never_sent", "connect_failed")
            await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
            yield SpeechChunk(request_id=template.request_id, sequence=0, pcm=b"pcm", final=False)
            budget.record_exact_usage(route.attempt_id)
            yield SpeechChunk(request_id=template.request_id, sequence=1, pcm=b"", final=True)

        return source()

    chunks = await asyncio.wait_for(
        _collect_speech(
            runner.stream(template, RetryPolicy(max_attempts=2, base_delay_ms=1), invoke)
        ),
        WAIT_SECONDS,
    )
    assert calls == 2 and chunks[-1].final
    assert len(set(authority.attempt_ids)) == len(set(budget.reservation_ids)) == 2
    assert len(budget.released_pairs) == 1
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition", ("sent", "unknown"))
async def test_stream_sent_or_unknown_failure_before_pcm_never_retries(
    disposition: Literal["sent", "unknown"],
) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()
    calls = 0

    def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
        nonlocal calls
        calls += 1

        async def source() -> AsyncIterator[SpeechChunk]:
            await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
            if False:
                yield SpeechChunk(
                    request_id=template.request_id,
                    sequence=0,
                    pcm=b"unreachable",
                    final=False,
                )
            raise TransientProviderError(503, disposition, "http_503")

        return source()

    with pytest.raises(TransientProviderError):
        await asyncio.wait_for(
            _collect_speech(
                runner.stream(template, RetryPolicy(max_attempts=2, base_delay_ms=1), invoke)
            ),
            WAIT_SECONDS,
        )
    assert calls == 1 and not budget.released_pairs
    assert len(budget.conservative_settlements) == 1
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ("error", "cancellation"))
@pytest.mark.parametrize("marked_sent", (False, True))
async def test_stream_typed_pre_network_failure_terminalizes_once_without_retry(
    kind: Literal["error", "cancellation"],
    marked_sent: bool,
) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()
    calls = 0

    def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
        nonlocal calls
        calls += 1

        async def source() -> AsyncIterator[SpeechChunk]:
            if marked_sent:
                await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
            if kind == "cancellation":
                cause = asyncio.CancelledError("synthetic pre-network cancellation")
                raise ProviderNotSentCancellation(
                    route.budget_reservation_id,
                    route.attempt_id,
                    "mark_sent_cancelled_before_network",
                    cause,
                )
            cause = RuntimeError("synthetic pre-network failure")
            raise ProviderNotSentError(
                route.budget_reservation_id,
                route.attempt_id,
                "mark_sent_failed_before_network",
                cause,
            )
            if False:
                yield SpeechChunk(
                    request_id=template.request_id,
                    sequence=0,
                    pcm=b"unreachable",
                    final=False,
                )

        return source()

    async def collect() -> list[SpeechChunk]:
        return [
            chunk
            async for chunk in runner.stream(
                template,
                RetryPolicy(max_attempts=2, base_delay_ms=1),
                invoke,
            )
        ]

    if kind == "cancellation":
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(collect(), WAIT_SECONDS)
    else:
        with pytest.raises(RuntimeError, match="synthetic pre-network failure"):
            await asyncio.wait_for(collect(), WAIT_SECONDS)
    assert calls == 1 and len(budget.terminal_pairs) == 1
    assert bool(budget.released_pairs) is (not marked_sent)
    assert len(budget.conservative_settlements) == int(marked_sent)
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("run", "stream"))
async def test_cancellation_during_typed_pre_network_terminalization_wins(
    mode: Literal["run", "stream"],
) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = _BlockingReleaseBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)

    def failure(route) -> ProviderNotSentError:
        return ProviderNotSentError(
            route.budget_reservation_id,
            route.attempt_id,
            "validation_failed_before_network",
            RuntimeError("original provider failure"),
        )

    if mode == "run":

        async def invoke(route, _consumption) -> str:
            raise failure(route)

        task = asyncio.create_task(
            runner.run(
                _reasoning_template(),
                RetryPolicy(max_attempts=1, base_delay_ms=1),
                invoke,
            )
        )
    else:
        template = _tts_template()

        def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
            async def source() -> AsyncIterator[SpeechChunk]:
                raise failure(route)
                if False:
                    yield SpeechChunk(
                        request_id=template.request_id,
                        sequence=0,
                        pcm=b"unreachable",
                        final=False,
                    )

            return source()

        task = asyncio.create_task(
            _collect_speech(
                runner.stream(template, RetryPolicy(max_attempts=1, base_delay_ms=1), invoke)
            )
        )
    await asyncio.wait_for(budget.release_started.wait(), WAIT_SECONDS)
    task.cancel()
    budget.allow_release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, WAIT_SECONDS)
    assert budget.released_pairs == budget.terminal_pairs
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
async def test_stream_synchronous_local_validation_failure_releases_without_retry() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()
    calls = 0

    def invoke(_route, _consumption) -> AsyncIterator[SpeechChunk]:
        nonlocal calls
        calls += 1
        raise RuntimeError("synchronous adapter construction failure")

    async def collect() -> list[SpeechChunk]:
        return [
            chunk
            async for chunk in runner.stream(
                template,
                RetryPolicy(max_attempts=2, base_delay_ms=1),
                invoke,
            )
        ]

    with pytest.raises(RuntimeError, match="synchronous adapter construction failure"):
        await asyncio.wait_for(collect(), WAIT_SECONDS)
    assert calls == 1 and budget.released_pairs == budget.terminal_pairs
    assert budget.conservative_settlements == []
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
async def test_stream_denied_never_sent_release_settles_and_never_retries() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()
    calls = 0

    def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
        nonlocal calls
        calls += 1

        async def source() -> AsyncIterator[SpeechChunk]:
            await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
            raise TransientProviderError(503, "never_sent", "stale_unsent_claim")
            if False:
                yield SpeechChunk(
                    request_id=template.request_id,
                    sequence=0,
                    pcm=b"unreachable",
                    final=False,
                )

        return source()

    async def collect() -> list[SpeechChunk]:
        return [
            chunk
            async for chunk in runner.stream(
                template,
                RetryPolicy(max_attempts=2, base_delay_ms=1),
                invoke,
            )
        ]

    with pytest.raises(TransientProviderError):
        await asyncio.wait_for(collect(), WAIT_SECONDS)
    assert calls == 1 and not budget.released_pairs
    assert len(budget.conservative_settlements) == 1
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
async def test_stream_after_first_pcm_never_retries_even_never_sent_error() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()
    closed = asyncio.Event()
    calls = 0

    def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
        nonlocal calls
        calls += 1

        async def source() -> AsyncIterator[SpeechChunk]:
            try:
                await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
                yield SpeechChunk(
                    request_id=template.request_id,
                    sequence=0,
                    pcm=b"pcm",
                    final=False,
                )
                raise TransientProviderError(503, "never_sent", "contradictory")
            finally:
                closed.set()

        return source()

    stream = cast(
        AsyncGenerator[SpeechChunk, None],
        runner.stream(template, RetryPolicy(max_attempts=2, base_delay_ms=1), invoke),
    )
    assert (await asyncio.wait_for(anext(stream), WAIT_SECONDS)).pcm == b"pcm"
    with pytest.raises(TransientProviderError):
        await asyncio.wait_for(anext(stream), WAIT_SECONDS)
    assert closed.is_set() and calls == 1 and not budget.released_pairs
    assert len(budget.conservative_settlements) == 1
    assert attempts.completed == attempts.tracked


@pytest.mark.asyncio
async def test_stream_backpressure_never_prefetches_second_pcm_chunk() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()
    second_requested = asyncio.Event()
    allow_second = asyncio.Event()

    def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
        async def source() -> AsyncIterator[SpeechChunk]:
            await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
            yield SpeechChunk(
                request_id=template.request_id,
                sequence=0,
                pcm=b"a" * 65_536,
                final=False,
            )
            second_requested.set()
            await allow_second.wait()
            yield SpeechChunk(
                request_id=template.request_id,
                sequence=1,
                pcm=b"b" * 65_536,
                final=False,
            )
            budget.record_exact_usage(route.attempt_id)
            yield SpeechChunk(request_id=template.request_id, sequence=2, pcm=b"", final=True)

        return source()

    stream = cast(
        AsyncGenerator[SpeechChunk, None],
        runner.stream(template, RetryPolicy(max_attempts=1, base_delay_ms=1), invoke),
    )
    first = await asyncio.wait_for(anext(stream), WAIT_SECONDS)
    assert len(first.pcm) == 65_536 and not second_requested.is_set()
    second_task = asyncio.create_task(anext(stream))
    await asyncio.wait_for(second_requested.wait(), WAIT_SECONDS)
    assert not second_task.done()
    allow_second.set()
    second = await asyncio.wait_for(second_task, WAIT_SECONDS)
    assert len(second.pcm) == 65_536
    terminal = await asyncio.wait_for(anext(stream), WAIT_SECONDS)
    assert terminal.final and terminal.pcm == b""
    await asyncio.wait_for(stream.aclose(), WAIT_SECONDS)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "chunks",
    (
        ((False, b"pcm"),),
        ((False, b"pcm"), (True, b""), (True, b"")),
        ((False, b"pcm"), (True, b"unexpected")),
    ),
)
async def test_stream_invalid_terminal_protocol_settles_once_and_exposes_no_final(
    chunks: tuple[tuple[bool, bytes], ...],
) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = RecordingBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()
    closed = asyncio.Event()

    def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
        async def source() -> AsyncIterator[SpeechChunk]:
            try:
                await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
                for sequence, (final, pcm) in enumerate(chunks):
                    yield SpeechChunk(
                        request_id=template.request_id,
                        sequence=sequence,
                        pcm=pcm,
                        final=final,
                    )
            finally:
                closed.set()

        return source()

    observed: list[SpeechChunk] = []

    async def collect_invalid() -> None:
        async for chunk in runner.stream(
            template,
            RetryPolicy(max_attempts=1, base_delay_ms=1),
            invoke,
        ):
            observed.append(chunk)

    with pytest.raises((ValueError, RuntimeError)):
        await asyncio.wait_for(collect_invalid(), WAIT_SECONDS)
    assert closed.is_set() and not any(chunk.final for chunk in observed)
    assert len(budget.conservative_settlements) == 1
    assert len(budget.terminal_pairs) == len(attempts.completed) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("stop_mode", ("aclose", "cancel"))
async def test_stream_close_or_cancel_shields_one_terminal_settlement(stop_mode: str) -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    budget = _BlockingSettlementBudget(clock)
    attempts = RecordingTurnAttempts(budget)
    runner = AttemptRunner(RecordingRouteAuthorizer(clock), budget, attempts, clock)
    template = _tts_template()
    source_waiting = asyncio.Event()
    source_closed = asyncio.Event()
    never = asyncio.Event()

    def invoke(route, _consumption) -> AsyncIterator[SpeechChunk]:
        async def source() -> AsyncIterator[SpeechChunk]:
            try:
                await budget.mark_sent(route.budget_reservation_id, route.attempt_id)
                yield SpeechChunk(
                    request_id=template.request_id,
                    sequence=0,
                    pcm=b"pcm",
                    final=False,
                )
                source_waiting.set()
                await never.wait()
            finally:
                source_closed.set()

        return source()

    stream = cast(
        AsyncGenerator[SpeechChunk, None],
        runner.stream(template, RetryPolicy(max_attempts=2, base_delay_ms=1), invoke),
    )
    assert (await asyncio.wait_for(anext(stream), WAIT_SECONDS)).pcm == b"pcm"
    if stop_mode == "aclose":
        stop_task = asyncio.create_task(stream.aclose())
    else:
        stop_task = asyncio.create_task(anext(stream))
        await asyncio.wait_for(source_waiting.wait(), WAIT_SECONDS)
        stop_task.cancel()
    await asyncio.wait_for(source_closed.wait(), WAIT_SECONDS)
    await asyncio.wait_for(budget.settle_started.wait(), WAIT_SECONDS)
    assert not stop_task.done() and attempts.completed == []
    budget.allow_settle.set()
    if stop_mode == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(stop_task, WAIT_SECONDS)
    else:
        await asyncio.wait_for(stop_task, WAIT_SECONDS)
    assert len(budget.conservative_settlements) == 1
    assert len(budget.reservation_ids) == 1 and not budget.released_pairs
    assert attempts.completed == attempts.tracked
