# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest
import tuntun_core.workers.subject_revocation_worker as worker_module
from tuntun_core.adapters.sqlcipher.subject_revocation_outbox_repository import (
    SubjectRevocationOutboxRepository,
)
from tuntun_core.services.identity.subject_revocation_processor import SubjectRevocationProcessor
from tuntun_core.workers.subject_revocation_worker import SubjectRevocationWorker


async def _wait_for_outbox_lease_at_or_after(
    repository: SubjectRevocationOutboxRepository,
    event_id: UUID,
    expected_floor: datetime,
    description: str,
) -> datetime:
    async def poll() -> datetime:
        while True:
            lease_expires_at = await repository.lease_expires_at(event_id)
            if lease_expires_at is not None and lease_expires_at >= expected_floor:
                return lease_expires_at
            await asyncio.sleep(0)

    try:
        return await asyncio.wait_for(poll(), timeout=1.0)
    except TimeoutError as error:
        state = await repository.state(event_id)
        takeover_count = repository.takeover_count(event_id)
        raise AssertionError(
            f"timed out waiting for {description}; state={state} takeovers={takeover_count}"
        ) from error


@pytest.mark.asyncio
async def test_immediate_restart_defers_live_claim_nonfatally_then_becomes_ready_at_expiry(
    file_backed_revocation_outbox_uow_factory,
    processing_event_factory,
    revocation_processor,
    clock,
) -> None:
    event = processing_event_factory("unexpired", seconds_remaining=30)
    repository = SubjectRevocationOutboxRepository(file_backed_revocation_outbox_uow_factory)
    worker = SubjectRevocationWorker(repository, revocation_processor, clock.heartbeats, clock)
    recovery = asyncio.create_task(worker.recover_and_drain_before_ready())

    await clock.advance_and_flush(seconds=29)
    assert not recovery.done()
    assert await repository.state(event.id) == "processing"
    assert repository.takeover_count(event.id) == 0
    await clock.advance_and_flush(seconds=1)
    await recovery

    assert await repository.state(event.id) == "completed"
    assert revocation_processor.receipts_for(event.id) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ("renew", "complete", "retry_pending", "defer_until"))
async def test_stale_outbox_lease_cannot_be_renewed_completed_retried_or_deferred(
    file_backed_revocation_outbox_uow_factory,
    processing_event_factory,
    clock,
    operation,
) -> None:
    event = processing_event_factory(f"expired-{operation}", seconds_remaining=-1)
    assert event.lease_owner is not None
    repository = SubjectRevocationOutboxRepository(file_backed_revocation_outbox_uow_factory)

    if operation == "renew":
        renewed = await repository.renew(
            event.id,
            event.lease_owner,
            event.fencing_token,
            clock.now(),
        )
        assert renewed is False
    elif operation == "complete":
        with pytest.raises(RuntimeError, match="subject_revocation_claim_lost"):
            await repository.complete(
                event.id,
                uuid4(),
                event.lease_owner,
                event.fencing_token,
                clock.now(),
            )
    elif operation == "retry_pending":
        with pytest.raises(RuntimeError, match="subject_revocation_claim_lost"):
            await repository.retry_pending(
                event.id,
                event.lease_owner,
                event.fencing_token,
                "processor_error:RuntimeError",
                clock.now(),
            )
    else:
        with pytest.raises(RuntimeError, match="subject_revocation_claim_lost"):
            await repository.defer_until(
                event.id,
                event.lease_owner,
                event.fencing_token,
                clock.now() + timedelta(seconds=30),
                clock.now(),
            )

    assert await repository.state(event.id) == "processing"


@pytest.mark.asyncio
async def test_two_workers_do_not_steal_seventy_five_second_call_with_heartbeats(
    two_revocation_workers,
    long_running_downstream,
    clock,
) -> None:
    first, second = two_revocation_workers
    event = await long_running_downstream.enqueue(duration_seconds=75)
    first_run = asyncio.create_task(first.run_one_periodic_drain())
    await _wait_for_outbox_lease_at_or_after(
        first.repository,
        event.id,
        clock.now() + timedelta(seconds=30),
        "initial worker claim",
    )
    await asyncio.wait_for(
        clock.wait_for_sleep_deadline_at_or_after(
            clock.now() + timedelta(seconds=10),
            count=2,
        ),
        timeout=1.0,
    )
    for seconds in (11, 20, 20, 20):
        clock.advance(seconds=seconds)
        await _wait_for_outbox_lease_at_or_after(
            first.repository,
            event.id,
            clock.now() + timedelta(seconds=30),
            f"heartbeat renewal after +{seconds}s clock advance",
        )
        await asyncio.wait_for(
            clock.wait_for_sleep_deadline_at_or_after(
                clock.now() + timedelta(seconds=10),
                count=2,
            ),
            timeout=1.0,
        )
        await second.run_one_periodic_drain()
    clock.advance(seconds=4)
    await asyncio.wait_for(first_run, timeout=1.0)

    assert long_running_downstream.keys == (
        long_running_downstream.fixed_key(event.id, "provider_routes"),
    )
    assert long_running_downstream.side_effect_count == 1
    assert two_revocation_workers.stale_fence_completions == 0


@pytest.mark.asyncio
async def test_crashed_worker_expires_then_second_worker_reopens_exact_receipt_and_fences_late_completion(  # noqa: E501
    two_revocation_workers,
    crash_after_downstream_commit,
    clock,
) -> None:
    first, second = two_revocation_workers
    event, old_claim, receipt = await crash_after_downstream_commit(first)

    await second.run_one_periodic_drain()
    assert second.completed_event_ids == ()
    await clock.advance_and_flush(seconds=30)
    await second.run_one_periodic_drain()

    assert second.completed_event_ids == (event.id,)
    assert crash_after_downstream_commit.effect_count(receipt.idempotency_key) == 1
    with pytest.raises(RuntimeError, match="subject_revocation_claim_lost"):
        await first.complete_with_stale_fence(old_claim, receipt)


@pytest.mark.asyncio
async def test_completed_event_ids_are_bounded_test_diagnostics(
    task1_identity_runtime,
    monkeypatch,
) -> None:
    monkeypatch.setattr(worker_module, "MAX_COMPLETED_EVENT_DIAGNOSTICS", 2)
    runtime = await task1_identity_runtime.start_without_initial_drain()
    events = []
    for _ in range(3):
        event = await runtime.enqueue_event()
        await runtime.revocation_worker.run_one_periodic_drain()
        events.append(event.id)

    assert runtime.revocation_worker.completed_event_ids == tuple(events[-2:])


@pytest.mark.asyncio
async def test_startup_does_not_report_ready_when_revocation_drain_fails(
    task1_identity_bootstrap,
    revocation_processor,
    clock,
) -> None:
    revocation_processor.fail(RuntimeError("reconciliation unavailable"))

    with pytest.raises(RuntimeError, match="reconciliation unavailable"):
        await task1_identity_bootstrap.start()

    assert task1_identity_bootstrap.ready is False


@pytest.mark.asyncio
async def test_committed_revocation_live_kick_completes_without_process_restart(
    task1_identity_runtime,
    active_subject_with_task1_started_authorities,
    revoke_profile_grant,
) -> None:
    runtime = await task1_identity_runtime.start()
    assert isinstance(runtime.revocation_worker, SubjectRevocationWorker)
    assert isinstance(runtime.revocation_processor, SubjectRevocationProcessor)

    event = await runtime.revoke_profile(
        active_subject_with_task1_started_authorities,
        revoke_profile_grant,
    )
    await runtime.revocation_worker.wait_until_idle()

    assert await runtime.revocation_outbox.state(event.id) == "completed"
    assert runtime.process_restart_count == 0
    assert runtime.revocation_processor.receipts_for(event.id) == 1  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_live_processor_error_requeues_event_and_fails_runtime_readiness(
    task1_identity_runtime,
    active_subject_with_task1_started_authorities,
    revoke_profile_grant,
) -> None:
    runtime = await task1_identity_runtime.start()
    runtime.revocation_processor.fail_family(
        "search_capabilities",
        RuntimeError("search cancellation unavailable"),
    )
    event = await runtime.revoke_profile(
        active_subject_with_task1_started_authorities,
        revoke_profile_grant,
    )

    with pytest.raises(RuntimeError, match="search cancellation unavailable"):
        await runtime.wait_for_revocation_worker_failure()

    assert runtime.ready is False
    assert await runtime.revocation_outbox.state(event.id) == "pending"
    assert await runtime.revocation_outbox.last_error(event.id) == "processor_error:RuntimeError"


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe_state", ("worker_unavailable", "backlog_over_limit"))
async def test_identity_readiness_fails_for_unavailable_worker_or_unsafe_backlog(
    task1_identity_bootstrap,
    unsafe_state,
) -> None:
    task1_identity_bootstrap.configure_revocation_state(unsafe_state)

    with pytest.raises(
        RuntimeError,
        match="subject revocation worker unavailable|subject revocation backlog unsafe",
    ):
        await task1_identity_bootstrap.start()

    assert task1_identity_bootstrap.ready is False
