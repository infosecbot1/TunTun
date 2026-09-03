from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, cast
from uuid import UUID, uuid5

from tuntun_core.adapters.sqlcipher.subject_revocation_effect_repository import (
    DownstreamEffectReceipt,
    EffectClaim,
)
from tuntun_core.services.identity.subject_revocation import CapabilityStagePort
from tuntun_core.services.transactions.identity_uow import (
    IdentityUnitOfWork,
    IdentityUnitOfWorkFactory,
)

ALLOWED_DOWNSTREAM_DISPOSITIONS = frozenset(
    {
        "none_open",
        "cancelled",
        "conservatively_settled",
        "completed_once",
        "not_installed_no_authority",
    }
)


@dataclass(frozen=True, slots=True)
class DeferredEffect:
    leased_until: datetime


class LeaseFenceLost(RuntimeError):
    pass


class ClockPort(Protocol):
    def now(self) -> datetime: ...

    async def sleep_until(self, deadline: datetime) -> None: ...


class EffectRepositoryPort(Protocol):
    async def claim(
        self,
        idempotency_key: UUID,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        lease_owner: UUID,
        now: datetime,
    ) -> EffectClaim: ...

    async def completed(self, idempotency_key: UUID) -> DownstreamEffectReceipt | None: ...

    async def renew(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        now: datetime,
    ) -> bool: ...

    async def complete(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        downstream: DownstreamEffectReceipt,
        now: datetime,
    ) -> None: ...

    async def abandon(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        reason_code: str,
        now: datetime,
    ) -> None: ...

    async def recover_stale(self, now: datetime) -> int: ...


class NetworkRevocationSummaryPort(Protocol):
    network_started_reservation_ids: tuple[UUID, ...]
    downstream_effect_receipt: DownstreamEffectReceipt
    reservations_settled_atomically: bool


class ProviderCallsRevocationPort(Protocol):
    async def reconcile_revoked_subject_once(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
    ) -> NetworkRevocationSummaryPort: ...


class BudgetReservationsRevocationPort(Protocol):
    async def settle_conservative_once(
        self,
        reservation_ids: tuple[UUID, ...],
        *,
        idempotency_key: UUID,
    ) -> None: ...


class SearchAttemptsRevocationPort(Protocol):
    async def reconcile_revocation_once(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
    ) -> DownstreamEffectReceipt: ...


class SearchRevocationUnitOfWork(IdentityUnitOfWork, Protocol):
    experimental_search_attempts: SearchAttemptsRevocationPort


class LeaseHeartbeatRunner:
    def __init__(self, clock: ClockPort) -> None:
        self._clock = clock

    def now(self) -> datetime:
        return self._clock.now()

    async def run[ResultT](
        self,
        operation: Callable[[], Awaitable[ResultT]],
        *,
        renew: Callable[[datetime], Awaitable[bool]],
        interval_seconds: int,
    ) -> ResultT:
        async def invoke() -> ResultT:
            return await operation()

        task: asyncio.Task[ResultT] = asyncio.create_task(invoke())
        tick: asyncio.Task[None] | None = None
        try:
            while True:
                tick = asyncio.create_task(
                    self._clock.sleep_until(
                        self._clock.now() + timedelta(seconds=interval_seconds),
                    )
                )
                done, _pending = await asyncio.wait(
                    {task, tick},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if task in done:
                    tick.cancel()
                    await asyncio.gather(tick, return_exceptions=True)
                    return task.result()
                if not await renew(self._clock.now()):
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise LeaseFenceLost("revocation_lease_fence_lost")
        except BaseException:
            if tick is not None and not tick.done():
                tick.cancel()
                await asyncio.gather(tick, return_exceptions=True)
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            raise


class _OnceHandler:
    family: str

    def __init__(self, effects: EffectRepositoryPort, heartbeats: LeaseHeartbeatRunner) -> None:
        self._effects = effects
        self._heartbeats = heartbeats

    @property
    def effect_repository(self) -> EffectRepositoryPort:
        return self._effects

    def require_stage_match(self) -> None:
        return None

    async def reconcile_started_once(
        self,
        *,
        event_id: UUID,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
        lease_owner: UUID,
        now: datetime,
    ) -> str | DeferredEffect:
        del now
        claim = await self._effects.claim(
            idempotency_key,
            event_id=event_id,
            family=self.family,
            subject_id=subject_id,
            through_generation=through_generation,
            lease_owner=lease_owner,
            now=self._heartbeats.now(),
        )
        if claim.status == "completed":
            if claim.downstream is None:
                raise RuntimeError("revocation_effect_completed_receipt_missing")
            return claim.downstream.disposition
        if claim.status == "busy":
            if claim.leased_until is None:
                raise RuntimeError("revocation_effect_live_lease_missing")
            return DeferredEffect(claim.leased_until)
        if claim.fencing_token is None:
            raise RuntimeError("revocation_effect_fence_missing")
        fencing_token = claim.fencing_token
        try:
            downstream = await self._heartbeats.run(
                lambda: self._apply(
                    event_id,
                    subject_id,
                    through_generation,
                    idempotency_key,
                ),
                renew=lambda heartbeat_now: self._effects.renew(
                    idempotency_key,
                    lease_owner,
                    fencing_token,
                    heartbeat_now,
                ),
                interval_seconds=10,
            )
            expected = (
                event_id,
                self.family,
                subject_id,
                through_generation,
                idempotency_key,
            )
            actual = (
                downstream.event_id,
                downstream.family,
                downstream.subject_id,
                downstream.through_generation,
                downstream.idempotency_key,
            )
            if actual != expected:
                raise RuntimeError("revocation_downstream_receipt_scope_mismatch")
            if downstream.disposition not in ALLOWED_DOWNSTREAM_DISPOSITIONS:
                raise RuntimeError("invalid_subject_revocation_disposition")
        except LeaseFenceLost:
            raise
        except Exception as error:
            await self._effects.abandon(
                idempotency_key,
                lease_owner,
                fencing_token,
                f"handler_error:{type(error).__name__}",
                self._heartbeats.now(),
            )
            raise
        await self._effects.complete(
            idempotency_key,
            lease_owner,
            fencing_token,
            downstream,
            self._heartbeats.now(),
        )
        return downstream.disposition

    async def _apply(
        self,
        event_id: UUID,
        subject_id: UUID,
        through_generation: int,
        key: UUID,
    ) -> DownstreamEffectReceipt:
        raise NotImplementedError


class ProviderRouteRevocationHandler(_OnceHandler):
    family = "provider_routes"

    def __init__(
        self,
        effects: EffectRepositoryPort,
        heartbeats: LeaseHeartbeatRunner,
        uow_factory: IdentityUnitOfWorkFactory,
        provider_calls: ProviderCallsRevocationPort | None = None,
        budget_reservations: BudgetReservationsRevocationPort | None = None,
    ) -> None:
        super().__init__(effects, heartbeats)
        self._uow = uow_factory
        self._provider_calls = provider_calls
        self._budget_reservations = budget_reservations

    async def _apply(
        self,
        event_id: UUID,
        subject_id: UUID,
        through_generation: int,
        key: UUID,
    ) -> DownstreamEffectReceipt:
        if self._provider_calls is not None:
            summary = await self._provider_calls.reconcile_revoked_subject_once(
                event_id=event_id,
                family=self.family,
                subject_id=subject_id,
                through_generation=through_generation,
                idempotency_key=key,
            )
            if not summary.reservations_settled_atomically:
                if self._budget_reservations is None:
                    raise RuntimeError("provider_route_budget_revocation_port_required")
                await self._budget_reservations.settle_conservative_once(
                    summary.network_started_reservation_ids,
                    idempotency_key=key,
                )
            return summary.downstream_effect_receipt
        async with self._uow() as uow:
            provider_calls = uow.provider_calls
            await uow.rollback()
        summary = cast(
            NetworkRevocationSummaryPort,
            await provider_calls.reconcile_revoked_subject_once(
                event_id=event_id,
                family=self.family,
                subject_id=subject_id,
                through_generation=through_generation,
                idempotency_key=key,
            ),
        )
        async with self._uow() as uow:
            await uow.budget_reservations.settle_conservative_once(
                summary.network_started_reservation_ids,
                idempotency_key=key,
            )
            await uow.commit()
        return summary.downstream_effect_receipt


class SearchAuthorityRevocationHandler(_OnceHandler):
    family = "search_capabilities"

    def __init__(
        self,
        effects: EffectRepositoryPort,
        heartbeats: LeaseHeartbeatRunner,
        uow_factory: IdentityUnitOfWorkFactory,
        feature_state: Literal["absent", "present"] = "present",
        capability_stage: CapabilityStagePort | None = None,
        owning_revision: str = "search_0001_experimental_search",
    ) -> None:
        super().__init__(effects, heartbeats)
        self._uow = uow_factory
        self.feature_state = feature_state
        self._stage = capability_stage
        self.owning_revision = owning_revision

    async def _apply(
        self,
        event_id: UUID,
        subject_id: UUID,
        through_generation: int,
        key: UUID,
    ) -> DownstreamEffectReceipt:
        if self.feature_state == "absent":
            return DownstreamEffectReceipt(
                uuid5(key, "absent-search-noop"),
                key,
                event_id,
                self.family,
                subject_id,
                through_generation,
                "none_open",
            )
        async with self._uow() as uow:
            search_uow = cast(SearchRevocationUnitOfWork, uow)
            receipt = await search_uow.experimental_search_attempts.reconcile_revocation_once(
                event_id=event_id,
                family=self.family,
                subject_id=subject_id,
                through_generation=through_generation,
                idempotency_key=key,
            )
            await uow.commit()
        return receipt

    def require_stage_match(self) -> None:
        if self.feature_state == "absent" and self._stage is not None:
            self._stage.require_schema_and_facade_absent(self.family, self.owning_revision)


class NotInstalledAuthorityRevocationHandler(_OnceHandler):
    _ALLOWED = {"action_authorities": "0003_authentication", "memory_authorities": "0004_memory"}

    def __init__(
        self,
        effects: EffectRepositoryPort,
        heartbeats: LeaseHeartbeatRunner,
        capability_stage: CapabilityStagePort,
        *,
        family: Literal["action_authorities", "memory_authorities"],
        owning_revision: Literal["0003_authentication", "0004_memory"],
    ) -> None:
        if self._ALLOWED.get(family) != owning_revision:
            raise ValueError("closed not-installed revocation family required")
        super().__init__(effects, heartbeats)
        self.family = family
        self._stage = capability_stage
        self.owning_revision = owning_revision

    async def _apply(
        self,
        event_id: UUID,
        subject_id: UUID,
        through_generation: int,
        key: UUID,
    ) -> DownstreamEffectReceipt:
        self._stage.require_schema_and_facade_absent(self.family, self.owning_revision)
        return DownstreamEffectReceipt(
            uuid5(key, "not-installed-no-authority"),
            key,
            event_id,
            self.family,
            subject_id,
            through_generation,
            "not_installed_no_authority",
        )

    def require_stage_match(self) -> None:
        self._stage.require_schema_and_facade_absent(self.family, self.owning_revision)
