from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from tuntun_core.adapters.sqlcipher.subject_revocation_outbox_repository import OutboxClaim
from tuntun_core.services.identity.subject_revocation_handlers import (
    LeaseFenceLost,
    LeaseHeartbeatRunner,
)
from tuntun_core.services.identity.subject_revocation_processor import (
    DeferredRevocationProcessing,
    SubjectRevocationProcessingReceipt,
    SubjectRevocationProcessor,
)

MAX_SAFE_STARTUP_BACKLOG = 10_000
PERIODIC_DRAIN_SECONDS = 30
STARTUP_RECOVERY_WAIT_SECONDS = 31
MAX_COMPLETED_EVENT_DIAGNOSTICS = 1024


class OutboxRepositoryPort(Protocol):
    async def recover_expired(self, now: datetime) -> int: ...

    async def claim_next(self, now: datetime, lease_owner: UUID) -> OutboxClaim | None: ...

    async def renew(
        self,
        event_id: UUID,
        lease_owner: UUID,
        fencing_token: int,
        now: datetime,
    ) -> bool: ...

    async def complete(
        self,
        event_id: UUID,
        receipt_id: UUID,
        lease_owner: UUID,
        fencing_token: int,
        now: datetime,
    ) -> None: ...

    async def retry_pending(
        self,
        event_id: UUID,
        lease_owner: UUID,
        fencing_token: int,
        reason_code: str,
        now: datetime,
    ) -> None: ...

    async def defer_until(
        self,
        event_id: UUID,
        lease_owner: UUID,
        fencing_token: int,
        leased_until: datetime,
        now: datetime,
    ) -> None: ...

    async def earliest_live_expiry(self) -> datetime | None: ...

    async def pending_count(self) -> int: ...


class ClockPort(Protocol):
    def now(self) -> datetime: ...

    async def sleep_until(self, deadline: datetime) -> None: ...


class StopEventPort(Protocol):
    def is_set(self) -> bool: ...


class SubjectRevocationWorker:
    def __init__(
        self,
        repository: OutboxRepositoryPort,
        processor: SubjectRevocationProcessor,
        heartbeats: LeaseHeartbeatRunner,
        clock: ClockPort,
    ) -> None:
        self._repository = repository
        self._processor = processor
        self._heartbeats = heartbeats
        self._clock = clock
        self._kick = asyncio.Event()
        self._running = asyncio.Event()
        self.completed_event_ids: tuple[UUID, ...] = ()

    @property
    def available(self) -> bool:
        return bool(self._processor.available)

    def offer_nowait(self) -> None:
        self._kick.set()

    async def _drain_available(self) -> int:
        processed = 0
        await self._repository.recover_expired(self._clock.now())
        await self._processor.recover_stale_effect_claims(self._clock.now())
        while claim := await self._repository.claim_next(self._clock.now(), uuid4()):
            receipt = await self._process_claim(claim)
            if receipt is not None:
                processed += 1
                self.completed_event_ids = (*self.completed_event_ids, claim.event.id)[
                    -MAX_COMPLETED_EVENT_DIAGNOSTICS:
                ]
        return processed

    async def _process_claim(
        self,
        claim: OutboxClaim,
    ) -> SubjectRevocationProcessingReceipt | None:
        event = claim.event
        try:
            result = await self._heartbeats.run(
                lambda: self._processor.reconcile_once(
                    event,
                    idempotency_key=event.id,
                    lease_owner=claim.lease_owner,
                    now=self._clock.now(),
                ),
                renew=lambda heartbeat_now: self._repository.renew(
                    event.id,
                    claim.lease_owner,
                    claim.fencing_token,
                    heartbeat_now,
                ),
                interval_seconds=10,
            )
            if isinstance(result, DeferredRevocationProcessing):
                await self._repository.defer_until(
                    event.id,
                    claim.lease_owner,
                    claim.fencing_token,
                    result.leased_until,
                    self._clock.now(),
                )
                return None
            await self._repository.complete(
                event.id,
                result.id,
                claim.lease_owner,
                claim.fencing_token,
                self._clock.now(),
            )
            return result
        except LeaseFenceLost:
            raise
        except Exception as error:
            await asyncio.shield(
                self._repository.retry_pending(
                    event.id,
                    claim.lease_owner,
                    claim.fencing_token,
                    f"processor_error:{type(error).__name__}",
                    self._clock.now(),
                )
            )
            raise

    async def recover_and_drain_before_ready(self) -> None:
        if not self.available:
            raise RuntimeError("subject revocation worker unavailable")
        if await self._repository.pending_count() > MAX_SAFE_STARTUP_BACKLOG:
            raise RuntimeError("subject revocation backlog unsafe")
        deadline = self._clock.now() + timedelta(seconds=STARTUP_RECOVERY_WAIT_SECONDS)
        while await self._repository.pending_count() != 0:
            await self._drain_available()
            if await self._repository.pending_count() == 0:
                break
            expiry = await self._repository.earliest_live_expiry()
            if expiry is None or expiry > deadline:
                raise RuntimeError("subject revocation backlog unsafe")
            await self._clock.sleep_until(expiry)

    async def run_periodically(
        self,
        stop: StopEventPort,
        on_fatal: Callable[[BaseException], object],
    ) -> None:
        if not self.available:
            raise RuntimeError("subject revocation worker unavailable")
        self._running.set()
        try:
            while not stop.is_set():
                with suppress(TimeoutError):
                    await asyncio.wait_for(self._kick.wait(), timeout=PERIODIC_DRAIN_SECONDS)
                self._kick.clear()
                await self._drain_available()
        except BaseException as error:
            on_fatal(error)
            raise

    async def run_one_periodic_drain(self) -> int:
        return await self._drain_available()

    async def wait_running(self) -> None:
        await self._running.wait()

    async def wait_until_idle(self) -> None:
        while self._kick.is_set() or await self._repository.pending_count():
            await asyncio.sleep(0)
