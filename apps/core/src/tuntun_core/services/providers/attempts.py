from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from typing import Any, Literal, TypeVar
from uuid import UUID, uuid4

from tuntun_contracts.base import Commitment, Sensitivity
from tuntun_contracts.budget import (
    BudgetReservationRequest,
    BudgetSettlementRequest,
    TransportProof,
    UsageUnits,
)
from tuntun_contracts.provider import (
    RouteAuthorization,
    RouteAuthorizationRequest,
    RouteConsumption,
)
from tuntun_contracts.speech import SpeechChunk
from tuntun_core.services.providers.gateway import (
    ProviderNotSentCancellation,
    ProviderNotSentError,
)

ResultT = TypeVar("ResultT")
_SUPPORTED_PURPOSES = frozenset({"cloud_stt", "cloud_reasoning", "cloud_tts"})
_RETRYABLE_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504})
_CATEGORY_BY_PURPOSE = {
    "cloud_stt": "stt",
    "cloud_reasoning": "llm",
    "cloud_tts": "tts",
}
_MAX_ATTEMPTS_BY_PURPOSE = {
    "cloud_stt": 1,
    "cloud_reasoning": 2,
    "cloud_tts": 2,
}


class TransientProviderError(RuntimeError):
    def __init__(
        self,
        status_code: int,
        disposition: Literal["never_sent", "sent", "unknown"],
        evidence_code: str,
    ) -> None:
        super().__init__(evidence_code)
        self.status_code = status_code
        self.disposition = disposition
        self.evidence_code = evidence_code


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int
    base_delay_ms: int

    def __post_init__(self) -> None:
        if (
            type(self.max_attempts) is not int
            or not 1 <= self.max_attempts <= 2
            or type(self.base_delay_ms) is not int
            or not 0 <= self.base_delay_ms <= 60_000
        ):
            raise ValueError("invalid retry policy")


@dataclass(frozen=True, slots=True)
class AttemptTemplate:
    request_id: UUID
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]
    household_id: UUID
    subject_id: UUID | None
    session_id: UUID
    turn_id: UUID
    provider: Literal["openai", "qwen"]
    model: str
    request_commitment: Commitment
    max_input_bytes: int
    max_input_units: int
    input_bytes: int
    input_units: int
    privacy_receipt_id: UUID
    consent_receipt_ids: tuple[UUID, ...]
    maximum_sensitivity: Sensitivity
    month_key: str
    category: Literal["stt", "llm", "tts"]
    usage_ceiling: UsageUnits

    def __post_init__(self) -> None:
        category = _CATEGORY_BY_PURPOSE.get(self.purpose)
        if category is None or category != self.category or self.usage_ceiling.category != category:
            raise ValueError("attempt_budget_purpose_mismatch")
        if (
            self.input_bytes > self.max_input_bytes
            or self.input_units > self.max_input_units
            or self.input_bytes < 0
            or self.input_units < 0
        ):
            raise ValueError("attempt_input_outside_route_bounds")


@dataclass(slots=True)
class _AttemptState:
    route: RouteAuthorization
    consumption: RouteConsumption
    tracked: bool
    terminalized: bool = False


class AttemptRunner:
    def __init__(self, authority: Any, budget: Any, turn_attempts: Any, clock: Any) -> None:
        self._authority = authority
        self._budget = budget
        self._turn_attempts = turn_attempts
        self._clock = clock

    async def run(
        self,
        template: AttemptTemplate,
        policy: RetryPolicy,
        invoke: Callable[[RouteAuthorization, RouteConsumption], Awaitable[ResultT]],
    ) -> ResultT:
        if type(template) is not AttemptTemplate:
            raise TypeError("template must be an exact AttemptTemplate")
        if type(policy) is not RetryPolicy:
            raise TypeError("policy must be an exact RetryPolicy")
        self._validate_policy(template, policy)
        for attempt_index in range(policy.max_attempts):
            state = await self._prepare_attempt(template)
            try:
                result = await invoke(state.route, state.consumption)
            except ProviderNotSentCancellation as error:
                await self._handle_not_sent(state, error)
                raise error.cause from None
            except ProviderNotSentError as error:
                await self._handle_not_sent(state, error)
                raise error.cause from None
            except TransientProviderError as error:
                terminal = await self._terminalize_transient(state, error)
                if (
                    error.disposition == "never_sent"
                    and terminal == "released"
                    and self._retryable(error)
                    and attempt_index + 1 < policy.max_attempts
                ):
                    await self._delay(policy, attempt_index)
                    continue
                raise
            except asyncio.CancelledError:
                await self._release_or_settle(state, "cancelled_before_success")
                raise
            except BaseException as error:
                await self._release_or_settle(state, type(error).__name__)
                raise
            await self._settle(state)
            return result
        raise RuntimeError("retry policy exhausted")

    async def stream(
        self,
        template: AttemptTemplate,
        policy: RetryPolicy,
        invoke: Callable[[RouteAuthorization, RouteConsumption], AsyncIterator[SpeechChunk]],
    ) -> AsyncIterator[SpeechChunk]:
        if type(template) is not AttemptTemplate:
            raise TypeError("template must be an exact AttemptTemplate")
        if type(policy) is not RetryPolicy:
            raise TypeError("policy must be an exact RetryPolicy")
        self._validate_policy(template, policy)
        attempt_index = 0
        while attempt_index < policy.max_attempts:
            state = await self._prepare_attempt(template)
            first_payload_sent = False
            expected_sequence = 0
            try:
                stream = invoke(state.route, state.consumption)
            except ProviderNotSentCancellation as error:
                await self._handle_not_sent(state, error)
                raise error.cause from None
            except ProviderNotSentError as error:
                await self._handle_not_sent(state, error)
                raise error.cause from None
            except BaseException as error:
                await self._release_or_settle(state, type(error).__name__)
                raise

            iterator = stream.__aiter__()
            while True:
                try:
                    chunk = await iterator.__anext__()
                except StopAsyncIteration as error:
                    await self._aclose(iterator)
                    await self._release_or_settle(state, "stream_closed_without_terminal")
                    raise RuntimeError("provider_stream_missing_terminal_chunk") from error
                except ProviderNotSentCancellation as error:
                    await self._handle_not_sent(state, error)
                    raise error.cause from None
                except ProviderNotSentError as error:
                    await self._handle_not_sent(state, error)
                    raise error.cause from None
                except TransientProviderError as error:
                    terminal = await self._terminalize_transient(state, error)
                    if (
                        not first_payload_sent
                        and error.disposition == "never_sent"
                        and terminal == "released"
                        and self._retryable(error)
                        and attempt_index + 1 < policy.max_attempts
                    ):
                        await self._aclose(iterator)
                        await self._delay(policy, attempt_index)
                        attempt_index += 1
                        break
                    raise
                except (asyncio.CancelledError, GeneratorExit):
                    await self._release_or_settle(state, "stream_cancelled")
                    raise
                except BaseException as error:
                    await self._release_or_settle(state, type(error).__name__)
                    raise

                if type(chunk) is not SpeechChunk:
                    await self._release_or_settle(state, "invalid_speech_chunk")
                    raise TypeError("invalid speech chunk")
                if chunk.request_id != template.request_id or chunk.sequence != expected_sequence:
                    await self._release_or_settle(state, "speech_chunk_sequence_mismatch")
                    raise ValueError("speech chunk sequence mismatch")
                expected_sequence += 1
                if chunk.final:
                    if chunk.pcm or not first_payload_sent:
                        await self._aclose(iterator)
                        await self._release_or_settle(state, "invalid_terminal_speech_chunk")
                        raise ValueError("invalid terminal speech chunk")
                    try:
                        extra = await iterator.__anext__()
                    except StopAsyncIteration:
                        pass
                    else:
                        del extra
                        await self._aclose(iterator)
                        await self._release_or_settle(state, "duplicate_terminal_speech_chunk")
                        raise RuntimeError("provider_stream_extra_after_terminal")
                    await self._settle(state)
                    try:
                        yield chunk
                    finally:
                        await self._aclose(iterator)
                    return
                if not chunk.pcm:
                    await self._release_or_settle(state, "empty_nonterminal_speech_chunk")
                    raise ValueError("empty nonterminal speech chunk")
                first_payload_sent = True
                try:
                    yield chunk
                except (asyncio.CancelledError, GeneratorExit):
                    await self._aclose(iterator)
                    await self._release_or_settle(state, "stream_cancelled_after_payload")
                    raise
            else:
                return
            continue
        raise RuntimeError("retry policy exhausted")

    async def _prepare_attempt(self, template: AttemptTemplate) -> _AttemptState:
        attempt_id = uuid4()
        reservation = await self._budget.reserve(
            BudgetReservationRequest(
                household_id=template.household_id,
                turn_id=template.turn_id,
                request_id=template.request_id,
                attempt_id=attempt_id,
                provider=template.provider,
                model=template.model,
                category=template.category,
                usage_ceiling=template.usage_ceiling,
                month_key=template.month_key,
            )
        )
        if reservation.outcome not in {"allow", "allow_soft_warning"}:
            raise PermissionError(reservation.outcome)
        tracked = False
        try:
            self._turn_attempts.track_reservation(
                template.turn_id,
                reservation.reservation_id,
                attempt_id,
            )
            tracked = True
            route = await self._authority.authorize(
                RouteAuthorizationRequest(
                    request_id=template.request_id,
                    attempt_id=attempt_id,
                    purpose=template.purpose,
                    household_id=template.household_id,
                    subject_id=template.subject_id,
                    session_id=template.session_id,
                    turn_id=template.turn_id,
                    provider=template.provider,
                    model=template.model,
                    request_commitment=template.request_commitment,
                    max_input_bytes=template.max_input_bytes,
                    max_input_units=template.max_input_units,
                    privacy_receipt_id=template.privacy_receipt_id,
                    consent_receipt_ids=template.consent_receipt_ids,
                    budget_reservation_id=reservation.reservation_id,
                    maximum_sensitivity=template.maximum_sensitivity,
                )
            )
            consumption = RouteConsumption(
                request_id=template.request_id,
                attempt_id=attempt_id,
                purpose=template.purpose,
                household_id=template.household_id,
                subject_id=template.subject_id,
                session_id=template.session_id,
                turn_id=template.turn_id,
                provider=template.provider,
                model=template.model,
                request_commitment=template.request_commitment,
                input_bytes=template.input_bytes,
                input_units=template.input_units,
                consumed_at=self._clock.now(),
            )
            return _AttemptState(route, consumption, tracked=True)
        except BaseException:
            fallback = _AttemptState(
                route=RouteAuthorization(
                    authorization_id=uuid4(),
                    request_id=template.request_id,
                    attempt_id=attempt_id,
                    purpose=template.purpose,
                    household_id=template.household_id,
                    subject_id=template.subject_id,
                    session_id=template.session_id,
                    turn_id=template.turn_id,
                    provider=template.provider,
                    model=template.model,
                    request_commitment=template.request_commitment,
                    max_input_bytes=template.max_input_bytes,
                    max_input_units=template.max_input_units,
                    privacy_receipt_id=template.privacy_receipt_id,
                    consent_receipt_ids=template.consent_receipt_ids,
                    budget_reservation_id=reservation.reservation_id,
                    maximum_sensitivity=template.maximum_sensitivity,
                    expires_at=reservation.expires_at,
                ),
                consumption=RouteConsumption(
                    request_id=template.request_id,
                    attempt_id=attempt_id,
                    purpose=template.purpose,
                    household_id=template.household_id,
                    subject_id=template.subject_id,
                    session_id=template.session_id,
                    turn_id=template.turn_id,
                    provider=template.provider,
                    model=template.model,
                    request_commitment=template.request_commitment,
                    input_bytes=template.input_bytes,
                    input_units=template.input_units,
                    consumed_at=self._clock.now(),
                ),
                tracked=tracked,
            )
            await self._release_or_settle(fallback, "attempt_prepare_failed")
            raise

    async def _settle(self, state: _AttemptState) -> None:
        if state.terminalized:
            return

        async def terminal() -> None:
            await self._budget.settle(
                BudgetSettlementRequest(
                    reservation_id=state.route.budget_reservation_id,
                    attempt_id=state.route.attempt_id,
                )
            )
            self._complete(state)
            state.terminalized = True

        await self._shield_terminal(terminal())

    async def _release_or_settle(self, state: _AttemptState, evidence_code: str) -> str:
        if state.terminalized:
            return "already_terminal"

        async def release() -> None:
            await self._budget.release_unsent(
                state.route.budget_reservation_id,
                state.route.attempt_id,
                TransportProof(
                    reservation_id=state.route.budget_reservation_id,
                    attempt_id=state.route.attempt_id,
                    disposition="never_sent",
                    evidence_code=evidence_code,
                    observed_at=self._clock.now(),
                ),
            )
            self._complete(state)
            state.terminalized = True

        try:
            await self._shield_terminal(release())
            return "released"
        except PermissionError:
            await self._settle(state)
            return "settled_after_unsent"

    async def _handle_not_sent(
        self,
        state: _AttemptState,
        error: ProviderNotSentCancellation | ProviderNotSentError,
    ) -> None:
        if (
            error.reservation_id != state.route.budget_reservation_id
            or error.attempt_id != state.route.attempt_id
        ):
            await self._settle(state)
            raise PermissionError("provider_unsent_scope_mismatch") from None
        await self._release_or_settle(state, error.evidence_code)

    async def _terminalize_transient(
        self,
        state: _AttemptState,
        error: TransientProviderError,
    ) -> str:
        if error.disposition == "never_sent":
            return await self._release_or_settle(state, error.evidence_code)
        await self._settle(state)
        return "settled"

    def _complete(self, state: _AttemptState) -> None:
        if not state.tracked:
            return
        self._turn_attempts.complete_reservation(
            state.route.turn_id,
            state.route.budget_reservation_id,
            state.route.attempt_id,
        )

    @staticmethod
    def _retryable(error: TransientProviderError) -> bool:
        return error.status_code in _RETRYABLE_STATUS

    @staticmethod
    def _validate_policy(template: AttemptTemplate, policy: RetryPolicy) -> None:
        if policy.max_attempts > _MAX_ATTEMPTS_BY_PURPOSE[template.purpose]:
            raise ValueError("retry_policy_exceeds_purpose_ceiling")

    @staticmethod
    async def _delay(policy: RetryPolicy, attempt_index: int) -> None:
        if policy.base_delay_ms:
            await asyncio.sleep((policy.base_delay_ms / 1_000) * (2**attempt_index))

    @staticmethod
    async def _shield_terminal(awaitable: Coroutine[Any, Any, None]) -> None:
        task: asyncio.Task[None] = asyncio.create_task(awaitable)
        cancellation: asyncio.CancelledError | None = None
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError as error:
                if cancellation is None:
                    cancellation = error
        task.result()
        if cancellation is not None:
            raise cancellation

    @staticmethod
    async def _aclose(iterator: AsyncIterator[SpeechChunk]) -> None:
        close = getattr(iterator, "aclose", None)
        if close is not None:
            await close()
