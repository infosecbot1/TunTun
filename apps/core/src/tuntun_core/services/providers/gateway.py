import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TypeVar
from uuid import UUID

from tuntun_contracts.ports import BudgetPort, RouteAuthorizerPort
from tuntun_contracts.provider import RouteAuthorization, RouteConsumption
from tuntun_core.services.providers.call_repository import ProviderCallRepository

T = TypeVar("T")
_SUPPORTED_PURPOSES = frozenset({"cloud_stt", "cloud_reasoning", "cloud_tts"})


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


class ProviderGateway:
    def __init__(
        self,
        authorizations: RouteAuthorizerPort,
        budget: BudgetPort,
        calls: ProviderCallRepository,
    ) -> None:
        self._authorizations = authorizations
        self._budget = budget
        self._calls = calls

    @property
    def calls(self) -> ProviderCallRepository:
        return self._calls

    @property
    def supported_purposes(self) -> frozenset[str]:
        return _SUPPORTED_PURPOSES

    async def _claim(
        self,
        route: RouteAuthorization,
        consumption: RouteConsumption,
        redaction_receipt_id: UUID | None,
    ) -> UUID:
        stage = "consume"
        try:
            await self._authorizations.consume(route.authorization_id, consumption)
            stage = "claim"
            call_id = await self._calls.begin(
                route,
                consumption,
                redaction_receipt_id,
            )
            stage = "mark_sent"
            # If mark_sent fails or is cancelled, keep claim_begun/started open.
            await self._budget.mark_sent(
                route.budget_reservation_id,
                route.attempt_id,
            )
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
        return call_id

    async def send(
        self,
        route: RouteAuthorization,
        consumption: RouteConsumption,
        redaction_receipt_id: UUID | None,
        invoke: Callable[[], Awaitable[T]],
    ) -> T:
        call_id = await self._claim(route, consumption, redaction_receipt_id)
        try:
            await self._calls.mark_network_invocation_starting(call_id)
            result = await invoke()
        except asyncio.CancelledError:
            await self._calls.finish(call_id, "cancelled")
            raise
        except BaseException:
            await self._calls.finish(call_id, "ambiguous")
            raise
        await self._calls.finish(call_id, "succeeded")
        return result

    @asynccontextmanager
    async def open_stream(
        self,
        route: RouteAuthorization,
        consumption: RouteConsumption,
        redaction_receipt_id: UUID | None,
        open_response: Callable[[], AbstractAsyncContextManager[T]],
    ) -> AsyncIterator[T]:
        call_id = await self._claim(route, consumption, redaction_receipt_id)
        try:
            await self._calls.mark_network_invocation_starting(call_id)
            async with open_response() as response:
                yield response
        except asyncio.CancelledError:
            await self._calls.finish(call_id, "cancelled")
            raise
        except BaseException:
            await self._calls.finish(call_id, "ambiguous")
            raise
        await self._calls.finish(call_id, "succeeded")
