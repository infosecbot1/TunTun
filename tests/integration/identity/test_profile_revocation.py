# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import pytest
from tuntun_core.adapters.sqlcipher.subject_revocation_outbox_repository import (
    SubjectRevocationOutboxRepository,
)
from tuntun_core.workers.subject_revocation_worker import SubjectRevocationWorker

AUTHORITY_FAMILIES = frozenset(
    {
        "sessions",
        "consents",
        "enrollments",
        "biometric_templates",
        "provider_routes",
        "search_capabilities",
        "action_authorities",
        "memory_authorities",
    }
)


@pytest.mark.asyncio
async def test_profile_revocation_advances_generation_and_revokes_every_authority_in_one_commit(
    identity_mutations,
    active_subject_with_task1_authorities,
    revoke_profile_grant,
    subject_authority_snapshot,
) -> None:
    subject = active_subject_with_task1_authorities
    before = await subject_authority_snapshot(subject.id)

    revoked = await identity_mutations.revoke_profile(
        subject.revoke_command, revoke_profile_grant.id
    )
    after = await subject_authority_snapshot(subject.id)
    event = await subject_authority_snapshot.revocation_outbox_event(
        subject.id,
        revoked.authority_generation,
    )

    assert revoked.authority_generation == before.authority_generation + 1
    assert revoked.active is False and revoked.revoked_at is not None
    assert after.invalidated_families == AUTHORITY_FAMILIES
    assert event.event_key == f"subject-revoked:{subject.id}:{revoked.authority_generation}"
    assert event.subject_id == subject.id
    assert event.new_authority_generation == revoked.authority_generation
    assert event.state == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault_after",
    [
        "sessions",
        "consents",
        "enrollments",
        "biometric_templates",
        "provider_routes",
        "search_capabilities",
        "action_authorities",
        "memory_authorities",
        "outbox",
        "audit",
    ],
)
async def test_revocation_fault_rolls_back_profile_authorities_and_outbox_together(
    identity_mutations,
    active_subject_with_task1_authorities,
    revoke_profile_grant,
    subject_authority_snapshot,
    revocation_faults,
    fault_after,
) -> None:
    subject = active_subject_with_task1_authorities
    before = await subject_authority_snapshot(subject.id)
    revocation_faults.raise_after(fault_after)

    with pytest.raises(RuntimeError, match="injected_revocation_fault"):
        await identity_mutations.revoke_profile(subject.revoke_command, revoke_profile_grant.id)

    after = await subject_authority_snapshot(subject.id)
    assert after.profile == before.profile
    assert after.active_authorities == before.active_authorities
    assert await subject_authority_snapshot.revocation_outbox_events(subject.id) == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("winner", ["revoke", "consume"])
async def test_revoke_vs_consume_has_one_sqlcipher_linearization_point(
    revoke_consume_race,
    network_capture,
    effect_capture,
    winner,
) -> None:
    result = await revoke_consume_race.run(first=winner)

    if winner == "revoke":
        assert result.consume_error == "current_subject_authority_required"
        assert network_capture == [] and effect_capture == []
    else:
        assert result.claim_committed_before_revocation is True
        assert result.post_commit_disposition in {
            "cancelled",
            "conservatively_settled",
            "completed_once",
        }
        assert result.replay_attempts == 0


@pytest.mark.asyncio
async def test_restart_rejects_every_pre_revocation_authority_generation(
    restarted_identity_runtime,
    revoked_subject_fixture,
) -> None:
    stale = revoked_subject_fixture.pre_revocation_authorities
    outcomes = await restarted_identity_runtime.try_each(stale)

    assert set(outcomes) == AUTHORITY_FAMILIES
    assert all(item.error == "current_subject_authority_required" for item in outcomes.values())
    assert restarted_identity_runtime.network_capture == []


@pytest.mark.asyncio
async def test_revocation_outbox_reconciles_started_work_once_after_restart(
    crash_after_profile_revocation_commit,
    restarted_identity_runtime,
) -> None:
    assert isinstance(
        restarted_identity_runtime.revocation_outbox, SubjectRevocationOutboxRepository
    )
    assert isinstance(restarted_identity_runtime.revocation_worker, SubjectRevocationWorker)

    event_id = await crash_after_profile_revocation_commit()
    first = await restarted_identity_runtime.drain_subject_revocations()
    second = await restarted_identity_runtime.drain_subject_revocations()

    assert first.completed_event_ids == (event_id,)
    assert second.completed_event_ids == ()
    assert restarted_identity_runtime.audit_count(event_id) == 1
