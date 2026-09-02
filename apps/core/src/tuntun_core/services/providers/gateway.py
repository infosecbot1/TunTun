from __future__ import annotations

import asyncio
import unicodedata
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal, cast
from uuid import UUID

from tuntun_contracts.budget import ProviderUsageReceiptV1, UsageUnits


class ProviderNotSentError(Exception):
    def __init__(
        self,
        reservation_id: UUID,
        attempt_id: UUID,
        evidence_code: str,
        cause: Exception,
    ) -> None:
        super().__init__("provider_network_not_started")
        self.reservation_id = reservation_id
        self.attempt_id = attempt_id
        self.evidence_code = evidence_code
        self.cause = cause


class ProviderNotSentCancellation(asyncio.CancelledError):
    def __init__(
        self,
        reservation_id: UUID,
        attempt_id: UUID,
        evidence_code: str,
        cause: asyncio.CancelledError,
    ) -> None:
        super().__init__("provider_network_not_started")
        self.reservation_id = reservation_id
        self.attempt_id = attempt_id
        self.evidence_code = evidence_code
        self.cause = cause


@dataclass(frozen=True, slots=True)
class ProviderUsageObservation:
    reported_usage: UsageUnits | None
    provider_response_identifier: str
    evidence_state: Literal[
        "exact",
        "missing_within_authorized_ceiling",
        "invalid_or_over_ceiling",
    ] = "exact"

    def __post_init__(self) -> None:
        value = self.provider_response_identifier
        try:
            encoded = value.encode("utf-8", errors="strict")
        except (AttributeError, UnicodeError) as error:
            raise ValueError("provider response identifier invalid") from error
        if (
            value != unicodedata.normalize("NFC", value)
            or not 1 <= len(encoded) <= 256
            or any(
                unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
                for character in value
            )
        ):
            raise ValueError("provider response identifier invalid")


@dataclass(frozen=True, slots=True)
class GatewayResult[T]:
    value: T
    provider_usage_receipt_id: UUID | None


@dataclass(slots=True)
class _TerminalState:
    done: bool = False
    outcome: str | None = None


@dataclass(slots=True)
class GatewayStreamLease[T]:
    response: T
    _finalize: Callable[[], Awaitable[UUID]]
    provider_usage_receipt_id: UUID | None = None
    _finalize_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def finalize(self) -> UUID:
        async with self._finalize_lock:
            if self.provider_usage_receipt_id is not None:
                return self.provider_usage_receipt_id
            receipt_id = await self._finalize()
            self.provider_usage_receipt_id = receipt_id
            return receipt_id


class ProviderUsageUnknownError(RuntimeError):
    pass


class ProviderGateway:
    _SUPPORTED_PURPOSES = frozenset({"cloud_stt", "cloud_reasoning", "cloud_tts"})

    def __init__(
        self,
        authorizations: Any,
        budget: Any,
        calls: Any,
        evidence: Any,
        clock: Any,
    ) -> None:
        self._authorizations = authorizations
        self._budget = budget
        self._calls = calls
        self._evidence = evidence
        self._clock = clock

    @property
    def calls(self) -> Any:
        return self._calls

    @property
    def supported_purposes(self) -> frozenset[str]:
        return self._SUPPORTED_PURPOSES

    async def _claim(
        self,
        route: Any,
        consumption: Any,
        redaction_receipt_id: UUID | None,
    ) -> tuple[UUID, Any]:
        stage = "consume"
        try:
            await self._authorizations.consume(route.authorization_id, consumption)
            stage = "claim"
            call_id = await self._calls.begin(route, consumption, redaction_receipt_id)
            stage = "mark_sent"
            await self._budget.mark_sent(route.budget_reservation_id, route.attempt_id)
        except asyncio.CancelledError as error:
            raise ProviderNotSentCancellation(
                route.budget_reservation_id,
                route.attempt_id,
                f"{stage}_cancelled_before_network",
                error,
            ) from error
        except Exception as error:
            raise ProviderNotSentError(
                route.budget_reservation_id,
                route.attempt_id,
                f"{stage}_failed_before_network",
                error,
            ) from error
        try:
            accounting = await self._budget.require_accounting_context(route, consumption)
        except BaseException:
            await self._finish_durably(_TerminalState(), call_id, "failed", route, None)
            raise
        return call_id, accounting

    @staticmethod
    def _resolve_billable(
        accounting: Any,
        observation: ProviderUsageObservation,
    ) -> tuple[str, UsageUnits]:
        if observation.evidence_state == "invalid_or_over_ceiling":
            raise ValueError("provider accounting evidence invalid")
        if accounting.primary_accounting_basis == "request_bound_exact":
            if observation.evidence_state != "exact" or observation.reported_usage is not None:
                raise ValueError("request-bound route supplied response usage")
            return "request_bound_exact", accounting.usage_ceiling
        if observation.evidence_state == "exact":
            if (
                observation.reported_usage is None
                or observation.reported_usage.category != accounting.category
            ):
                raise ValueError("exact provider usage unavailable")
            return "provider_reported_exact", observation.reported_usage
        if (
            observation.evidence_state == "missing_within_authorized_ceiling"
            and accounting.missing_evidence_policy == "conservative_full_reservation"
        ):
            return "conservative_full_reservation", accounting.usage_ceiling
        raise ValueError("provider accounting evidence unavailable")

    async def _finish_durably(
        self,
        terminal: _TerminalState,
        call_id: UUID,
        outcome: str,
        route: Any,
        receipt: ProviderUsageReceiptV1 | None,
    ) -> None:
        if terminal.outcome is None:
            terminal.outcome = outcome
        elif terminal.outcome != outcome:
            raise RuntimeError("provider_call_terminal_outcome_conflict")
        cancellation = None
        for attempt in range(2):
            operation = asyncio.create_task(
                self._calls.finish(call_id, outcome, route, receipt),
                name=f"provider-call-finish-{outcome}",
            )
            while not operation.done():
                try:
                    await asyncio.shield(operation)
                except asyncio.CancelledError as error:
                    if cancellation is None:
                        cancellation = error
            try:
                operation.result()
            except asyncio.CancelledError as error:
                if cancellation is None:
                    cancellation = error
                if attempt == 0:
                    continue
                raise
            terminal.done = True
            if cancellation is not None:
                raise cancellation
            return
        raise RuntimeError("provider_call_finish_unconfirmed")

    async def _finish_success(
        self,
        terminal: _TerminalState,
        call_id: UUID,
        route: Any,
        accounting: Any,
        observation: ProviderUsageObservation,
    ) -> ProviderUsageReceiptV1:
        try:
            accounting_basis, billable_usage = self._resolve_billable(accounting, observation)
            receipt = self._evidence.attest_provider_usage(
                call_id=call_id,
                route=route,
                category=accounting.category,
                accounting_basis=accounting_basis,
                billable_usage=billable_usage,
                provider_response_identifier=observation.provider_response_identifier,
            )
        except Exception as error:
            await self._finish_durably(terminal, call_id, "succeeded", route, None)
            raise ProviderUsageUnknownError("provider_usage_invalid_unknown_overage") from error
        await self._finish_durably(terminal, call_id, "succeeded", route, receipt)
        return cast(ProviderUsageReceiptV1, receipt)

    async def send[T](
        self,
        route: Any,
        consumption: Any,
        redaction_receipt_id: UUID | None,
        invoke: Callable[[], Awaitable[T]],
        observe: Callable[[T], Awaitable[ProviderUsageObservation]],
    ) -> GatewayResult[T]:
        call_id, accounting = await self._claim(route, consumption, redaction_receipt_id)
        terminal = _TerminalState()
        try:
            await self._calls.mark_network_invocation_starting(call_id)
            value = await invoke()
            try:
                observation = await observe(value)
            except asyncio.CancelledError:
                await self._finish_durably(terminal, call_id, "succeeded", route, None)
                raise
            except BaseException as error:
                await self._finish_durably(terminal, call_id, "succeeded", route, None)
                raise ProviderUsageUnknownError("provider_usage_invalid_unknown_overage") from error
            receipt = await self._finish_success(terminal, call_id, route, accounting, observation)
            return GatewayResult(value, receipt.receipt_id)
        except asyncio.CancelledError:
            if terminal.outcome is None:
                await self._finish_durably(terminal, call_id, "cancelled", route, None)
            raise
        except BaseException:
            if terminal.outcome is None:
                await self._finish_durably(terminal, call_id, "ambiguous", route, None)
            raise

    @asynccontextmanager
    async def open_stream[T](
        self,
        route: Any,
        consumption: Any,
        redaction_receipt_id: UUID | None,
        open_response: Callable[[], AbstractAsyncContextManager[T]],
        observe: Callable[[T], Awaitable[ProviderUsageObservation]],
    ) -> AsyncIterator[GatewayStreamLease[T]]:
        call_id, accounting = await self._claim(route, consumption, redaction_receipt_id)
        terminal = _TerminalState()
        try:
            await self._calls.mark_network_invocation_starting(call_id)
            async with open_response() as response:

                async def finalize() -> UUID:
                    nonlocal terminal
                    if terminal.outcome is not None:
                        raise RuntimeError("provider stream already terminal")
                    try:
                        observation = await observe(response)
                    except asyncio.CancelledError:
                        await self._finish_durably(terminal, call_id, "succeeded", route, None)
                        raise
                    except BaseException as error:
                        await self._finish_durably(terminal, call_id, "succeeded", route, None)
                        raise ProviderUsageUnknownError(
                            "provider_usage_invalid_unknown_overage"
                        ) from error
                    receipt = await self._finish_success(
                        terminal,
                        call_id,
                        route,
                        accounting,
                        observation,
                    )
                    return receipt.receipt_id

                lease = GatewayStreamLease(response, finalize)
                yield lease
                if terminal.outcome is None:
                    await self._finish_durably(terminal, call_id, "ambiguous", route, None)
                    raise ProviderUsageUnknownError(
                        "provider_stream_closed_before_finalize_unknown_overage"
                    )
        except asyncio.CancelledError:
            if terminal.outcome is None:
                await self._finish_durably(terminal, call_id, "cancelled", route, None)
            raise
        except BaseException:
            if terminal.outcome is None:
                await self._finish_durably(terminal, call_id, "ambiguous", route, None)
            raise
