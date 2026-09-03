# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import asyncio
from datetime import timedelta
from uuid import uuid4

import pytest
from tuntun_core.domain.profile import (
    ConsentPurpose,
    ConsentReceipt,
    GrantConsent,
    ProfileClass,
    RevokeConsent,
)
from tuntun_core.services.actions.parameter_binding import (
    ActionParameterBindingVerifier,
    consent_parameters,
)
from tuntun_core.services.identity.consent import (
    CloudRouteConsentRevocationHandler,
    ConsentDenied,
)

from tests.identity_support import COMMITMENT_ROOT, _grant_consent_command, _revoke_consent_command


@pytest.mark.asyncio
async def test_adult_must_consent_for_self(
    identity_mutations,
    adult_a,
    adult_b,
    adult_a_grant,
) -> None:
    command = GrantConsent(
        subject_id=adult_b.id,
        actor_id=adult_a.id,
        purpose=ConsentPurpose.CLOUD_STT,
        action_binding=adult_a_grant.binding,
    )

    with pytest.raises(ConsentDenied, match="adult_self_consent_required"):
        await identity_mutations.grant_consent(command, adult_a_grant.id)


@pytest.mark.asyncio
async def test_guardian_may_consent_for_child(
    identity_mutations,
    guardian,
    child,
    guardian_grant,
) -> None:
    command = GrantConsent(
        subject_id=child.id,
        actor_id=guardian.id,
        purpose=ConsentPurpose.FACE,
        guardian_generation=child.guardian_generation,
        action_binding=guardian_grant.binding,
    )

    receipt = await identity_mutations.grant_consent(command, guardian_grant.id)

    assert receipt.subject_id == child.id
    assert receipt.guardian_id == guardian.id
    assert receipt.granted is True


def test_action_parameter_commitment_key_id_substitution_is_rejected(
    identity_env,
    adult_a,
) -> None:
    command = _grant_consent_command(
        identity_env,
        adult_a,
        adult_a.id,
        ConsentPurpose.CLOUD_STT,
    )
    forged_commitment = command.action_binding.parameter_commitment.model_copy(
        update={"key_id": "old-action-parameters-test-v0"}
    )
    forged_binding = command.action_binding.model_copy(
        update={"parameter_commitment": forged_commitment}
    )

    with pytest.raises(PermissionError, match="action_parameter_key_mismatch"):
        ActionParameterBindingVerifier(
            COMMITMENT_ROOT,
            key_id="test-action-key",
        ).require(
            forged_binding,
            action_name="consent.grant",
            resource_type="consent",
            resource_id=adult_a.id,
            actor_id=adult_a.id,
            parameters=consent_parameters(command),
        )


@pytest.mark.asyncio
async def test_subject_current_consent_pointer_tracks_first_grant(
    identity_env,
    identity_mutations,
    adult_without_personalization_consent,
) -> None:
    subject = adult_without_personalization_consent
    command = _grant_consent_command(
        identity_env,
        subject,
        subject.id,
        ConsentPurpose.CLOUD_STT,
    )
    grant = identity_env.grant_for(subject.id, command.action_binding)

    receipt = await identity_mutations.grant_consent(command, grant.id)

    assert identity_env.profiles[subject.id].current_consent_receipt_ids == (receipt.id,)


@pytest.mark.asyncio
async def test_subject_current_consent_pointer_replaces_only_same_purpose_on_supersede_and_revoke(
    identity_env,
    identity_mutations,
    adult_without_personalization_consent,
) -> None:
    subject = adult_without_personalization_consent
    stt_grant = _grant_consent_command(
        identity_env,
        subject,
        subject.id,
        ConsentPurpose.CLOUD_STT,
    )
    stt_handle = identity_env.grant_for(subject.id, stt_grant.action_binding)
    first_stt = await identity_mutations.grant_consent(stt_grant, stt_handle.id)
    tts_grant = _grant_consent_command(
        identity_env,
        subject,
        subject.id,
        ConsentPurpose.CLOUD_TTS,
    )
    tts_handle = identity_env.grant_for(subject.id, tts_grant.action_binding)
    tts = await identity_mutations.grant_consent(tts_grant, tts_handle.id)
    stt_supersede = _grant_consent_command(
        identity_env,
        subject,
        subject.id,
        ConsentPurpose.CLOUD_STT,
        expected_latest_receipt_id=first_stt.id,
    )
    stt_supersede_handle = identity_env.grant_for(subject.id, stt_supersede.action_binding)

    second_stt = await identity_mutations.grant_consent(
        stt_supersede,
        stt_supersede_handle.id,
    )

    assert set(identity_env.profiles[subject.id].current_consent_receipt_ids) == {
        second_stt.id,
        tts.id,
    }
    revoke = _revoke_consent_command(
        subject,
        subject.id,
        ConsentPurpose.CLOUD_STT,
        second_stt.id,
        policy_version=second_stt.policy_version,
        disclosure_version=second_stt.disclosure_version,
    )
    revoke_handle = identity_env.grant_for(subject.id, revoke.action_binding)

    revoked = await identity_mutations.revoke_consent(revoke, revoke_handle.id)

    assert revoked.granted is False
    assert identity_env.profiles[subject.id].current_consent_receipt_ids == (tts.id,)


@pytest.mark.asyncio
async def test_subject_current_consent_pointer_rolls_back_with_receipt_insert(
    identity_env,
    identity_mutations,
    adult_without_personalization_consent,
    revocation_faults,
) -> None:
    subject = adult_without_personalization_consent
    before = identity_env.profiles[subject.id].current_consent_receipt_ids
    command = _grant_consent_command(
        identity_env,
        subject,
        subject.id,
        ConsentPurpose.CLOUD_STT,
    )
    grant = identity_env.grant_for(subject.id, command.action_binding)
    revocation_faults.raise_after("audit")

    with pytest.raises(RuntimeError, match="injected_revocation_fault"):
        await identity_mutations.grant_consent(command, grant.id)

    assert identity_env.profiles[subject.id].current_consent_receipt_ids == before
    assert not [
        receipt
        for receipt in identity_env.consents
        if receipt.subject_id == subject.id and receipt.purpose is ConsentPurpose.CLOUD_STT
    ]


@pytest.mark.asyncio
async def test_subject_current_consent_pointer_refuses_more_than_eight_current_receipts(
    identity_env,
    identity_mutations,
) -> None:
    full_pointer = tuple(uuid4() for _ in range(8))
    subject = identity_env.profile_factory(
        ProfileClass.ADULT,
        name="adult-full-current-consent-pointer",
        current_consent_receipt_ids=full_pointer,
    )
    command = _grant_consent_command(
        identity_env,
        subject,
        subject.id,
        ConsentPurpose.CLOUD_STT,
    )
    grant = identity_env.grant_for(subject.id, command.action_binding)

    with pytest.raises(RuntimeError, match="current_consent_pointer_full"):
        await identity_mutations.grant_consent(command, grant.id)

    assert identity_env.profiles[subject.id].current_consent_receipt_ids == full_pointer


@pytest.mark.asyncio
async def test_same_clock_same_purpose_receipts_are_strictly_ordered(
    identity_env,
    identity_mutations,
    adult_without_personalization_consent,
    now,
) -> None:
    subject = adult_without_personalization_consent
    first_command = _grant_consent_command(
        identity_env,
        subject,
        subject.id,
        ConsentPurpose.CLOUD_STT,
    )
    first_handle = identity_env.grant_for(subject.id, first_command.action_binding)
    first = await identity_mutations.grant_consent(first_command, first_handle.id)
    revoke_command = _revoke_consent_command(
        subject,
        subject.id,
        ConsentPurpose.CLOUD_STT,
        first.id,
        policy_version=first.policy_version,
        disclosure_version=first.disclosure_version,
    )
    revoke_handle = identity_env.grant_for(subject.id, revoke_command.action_binding)
    revoked = await identity_mutations.revoke_consent(revoke_command, revoke_handle.id)
    regrant_command = _grant_consent_command(
        identity_env,
        subject,
        subject.id,
        ConsentPurpose.CLOUD_STT,
        expected_latest_receipt_id=revoked.id,
    )
    regrant_handle = identity_env.grant_for(subject.id, regrant_command.action_binding)

    regranted = await identity_mutations.grant_consent(regrant_command, regrant_handle.id)

    assert now == first.created_at
    assert first.created_at < revoked.created_at < regranted.created_at
    assert identity_env.consent_repo._latest(subject.id, ConsentPurpose.CLOUD_STT) == regranted


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.K2, ProfileClass.N1])
async def test_current_guardian_controls_separate_child_durable_memory_consent(
    identity_mutations,
    child_profile_factory,
    guardian,
    child_memory_consent_grant_factory,
    profile_class,
) -> None:
    child = child_profile_factory(profile_class=profile_class, guardian_id=guardian.id)
    grant = child_memory_consent_grant_factory(child)

    receipt = await identity_mutations.grant_consent(
        GrantConsent(
            subject_id=child.id,
            actor_id=guardian.id,
            purpose=ConsentPurpose.CHILD_DURABLE_MEMORY,
            guardian_generation=child.guardian_generation,
            action_binding=grant.binding,
        ),
        grant.id,
    )

    assert receipt.purpose is ConsentPurpose.CHILD_DURABLE_MEMORY
    assert (receipt.guardian_id, receipt.guardian_generation) == (
        guardian.id,
        child.guardian_generation,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.OWNER, ProfileClass.ADULT])
async def test_adult_profile_cannot_create_child_memory_consent(
    consent_service,
    adult_child_memory_command_factory,
    actor_auth_factory,
    consent_repository_spy,
    profile_class,
) -> None:
    command = adult_child_memory_command_factory(profile_class=profile_class)

    with pytest.raises(ConsentDenied, match="child_durable_memory_guardian_consent_required"):
        await consent_service.grant(
            command, actor_auth_factory(command.actor_id, command.action_binding)
        )

    assert consent_repository_spy.read_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke"])
@pytest.mark.parametrize("stale_case", ["reassigned_guardian", "old_generation"])
async def test_stale_or_reassigned_guardian_cannot_manage_child_consent(
    consent_service,
    stale_child_consent_command_factory,
    guardian_auth_factory,
    consent_repository_spy,
    operation,
    stale_case,
) -> None:
    command = stale_child_consent_command_factory(operation=operation, stale_case=stale_case)
    auth = guardian_auth_factory(command.action_binding)

    with pytest.raises(ConsentDenied, match="current_primary_guardian_required"):
        await getattr(consent_service, operation)(command, auth)

    assert consent_repository_spy.read_count == 0


@pytest.mark.asyncio
async def test_adult_web_search_grant_and_revoke_are_subject_self_only(
    identity_mutations,
    adult_a,
    adult_web_search_grant,
    adult_web_search_revoke_grant_factory,
) -> None:
    granted = await identity_mutations.grant_consent(
        GrantConsent(
            subject_id=adult_a.id,
            actor_id=adult_a.id,
            purpose=ConsentPurpose.WEB_SEARCH,
            action_binding=adult_web_search_grant.binding,
        ),
        adult_web_search_grant.id,
    )
    assert granted.purpose is ConsentPurpose.WEB_SEARCH and granted.guardian_id is None

    revoke_grant = adult_web_search_revoke_grant_factory(granted)
    revoked = await identity_mutations.revoke_consent(
        RevokeConsent(
            subject_id=adult_a.id,
            actor_id=adult_a.id,
            purpose=ConsentPurpose.WEB_SEARCH,
            expected_latest_receipt_id=granted.id,
            policy_version=granted.policy_version,
            disclosure_version=granted.disclosure_version,
            action_binding=revoke_grant.binding,
        ),
        revoke_grant.id,
    )

    assert revoked.purpose is ConsentPurpose.WEB_SEARCH and revoked.granted is False


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke"])
async def test_one_adult_cannot_manage_another_adults_web_search_consent(
    consent_service,
    cross_adult_search_command_factory,
    actor_auth_factory,
    consent_repository_spy,
    operation,
) -> None:
    command = cross_adult_search_command_factory(operation=operation)
    auth = actor_auth_factory(command.actor_id, command.action_binding)

    with pytest.raises(ConsentDenied, match="web_search_adult_self_consent_required"):
        await getattr(consent_service, operation)(command, auth)

    assert consent_repository_spy.read_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("profile_class", [ProfileClass.K2, ProfileClass.N1])
@pytest.mark.parametrize("operation", ["grant", "revoke"])
async def test_child_web_search_consent_is_denied_before_receipt_lookup(
    consent_service,
    child_search_command_factory,
    guardian_auth_factory,
    consent_repository_spy,
    profile_class,
    operation,
) -> None:
    command = child_search_command_factory(profile_class=profile_class, operation=operation)
    auth = guardian_auth_factory(command.action_binding)

    with pytest.raises(ConsentDenied, match="web_search_adult_self_consent_required"):
        await getattr(consent_service, operation)(command, auth)

    assert consent_repository_spy.read_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke"])
@pytest.mark.parametrize(
    "field",
    [
        "subject_id",
        "actor_id",
        "purpose",
        "expected_latest_receipt_id",
        "guardian_generation",
        "policy_version",
        "disclosure_version",
    ],
)
async def test_consent_command_substitution_cannot_reuse_valid_grant(
    consent_service,
    bound_consent_command_factory,
    actor_auth_factory,
    repository_spies,
    operation,
    field,
) -> None:
    command = bound_consent_command_factory(operation=operation)
    auth = actor_auth_factory(command.actor_id, command.action_binding)
    substituted = bound_consent_command_factory(
        operation=operation,
        changed_field=field,
        keep_binding=command.action_binding,
    )

    with pytest.raises(ConsentDenied, match="consent_action_binding_mismatch"):
        await getattr(consent_service, operation)(substituted, auth)

    assert repository_spies.profile_reads == 0 and repository_spies.consent_reads == 0


@pytest.mark.asyncio
async def test_grant_binding_cannot_execute_revoke(
    consent_service,
    bound_consent_command_factory,
    actor_auth_factory,
    repository_spies,
) -> None:
    grant_command = bound_consent_command_factory(operation="grant")
    auth = actor_auth_factory(grant_command.actor_id, grant_command.action_binding)

    with pytest.raises(ConsentDenied, match="consent_action_binding_mismatch"):
        await consent_service.revoke(grant_command, auth)

    assert repository_spies.profile_reads == 0 and repository_spies.consent_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke"])
async def test_consent_passkey_consumed_at_must_not_be_future(
    consent_service,
    bound_consent_command_factory,
    actor_auth_factory,
    repository_spies,
    now,
    operation,
) -> None:
    command = bound_consent_command_factory(operation=operation)
    auth = actor_auth_factory(command.actor_id, command.action_binding).model_copy(
        update={"consumed_at": now + timedelta(seconds=1)}
    )

    with pytest.raises(ConsentDenied, match="fresh_passkey_required"):
        await getattr(consent_service, operation)(command, auth)

    assert repository_spies.profile_reads == 0 and repository_spies.consent_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke"])
@pytest.mark.parametrize(
    ("forgery", "expected_error"),
    [
        ("source", "subject_bound_passkey_required"),
        ("binding", "subject_bound_passkey_required"),
        ("actor", "authenticated_actor_mismatch"),
    ],
)
async def test_consent_requires_fresh_subject_bound_passkey_before_receipt_access(
    consent_service,
    bound_consent_command_factory,
    actor_auth_factory,
    repository_spies,
    operation,
    forgery,
    expected_error,
) -> None:
    command = bound_consent_command_factory(operation=operation)
    auth = actor_auth_factory(command.actor_id, command.action_binding)
    if forgery == "source":
        auth = auth.model_copy(update={"assurance_source": "voice"})
    elif forgery == "binding":
        other = bound_consent_command_factory(operation=operation, changed_field="purpose")
        auth = auth.model_copy(update={"binding": other.action_binding})
    else:
        auth = auth.model_copy(update={"subject_id": uuid4()})

    with pytest.raises(ConsentDenied, match=expected_error):
        await getattr(consent_service, operation)(command, auth)

    assert repository_spies.profile_reads == 0 and repository_spies.consent_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "operation"),
    [("grant_in_uow", "grant"), ("revoke_in_uow", "revoke")],
)
async def test_consent_in_uow_methods_reject_cross_scope_uow_before_receipt_access(
    identity_env,
    consent_service,
    mutation_scope,
    bound_consent_command_factory,
    actor_auth_factory,
    repository_spies,
    method_name,
    operation,
) -> None:
    command = bound_consent_command_factory(operation=operation)
    auth = actor_auth_factory(command.actor_id, command.action_binding)

    async with mutation_scope.open() as active_uow:
        async with identity_env.uow_factory() as other_uow:
            assert active_uow is not other_uow
            with pytest.raises(RuntimeError, match="consent_uow_scope_mismatch"):
                await getattr(consent_service, method_name)(other_uow, command, auth)
            await other_uow.rollback()
        await active_uow.rollback()

    assert repository_spies.profile_reads == 0 and repository_spies.consent_reads == 0


@pytest.mark.asyncio
async def test_consent_grant_and_revoke_in_uow_use_active_transaction_scope(
    identity_env,
    identity_mutations,
    consent_service,
    mutation_scope,
    adult_a,
) -> None:
    grant_command = _grant_consent_command(
        identity_env,
        adult_a,
        adult_a.id,
        ConsentPurpose.CLOUD_TTS,
    )
    grant_auth = identity_env.auth_context(adult_a.id, grant_command.action_binding)

    async with mutation_scope.open() as uow:
        granted = await consent_service.grant_in_uow(uow, grant_command, grant_auth)
        await uow.commit()

    assert granted.granted is True
    revoke_command = _revoke_consent_command(
        adult_a,
        adult_a.id,
        ConsentPurpose.CLOUD_TTS,
        granted.id,
        policy_version=granted.policy_version,
        disclosure_version=granted.disclosure_version,
    )
    revoke_grant = identity_env.grant_for(adult_a.id, revoke_command.action_binding)
    revoked = await identity_mutations.revoke_consent(revoke_command, revoke_grant.id)

    assert revoked.granted is False


@pytest.mark.asyncio
async def test_consent_public_current_helpers_preserve_household_and_boolean_denials(
    identity_env,
    consent_service,
    adult_a,
    now,
) -> None:
    receipt = identity_env.install_consent(adult_a, adult_a.id, ConsentPurpose.CLOUD_TTS)

    assert (
        await consent_service.require_current_hmac_valid(
            adult_a.household_id,
            adult_a.id,
            ConsentPurpose.CLOUD_TTS,
            now,
        )
    ).id == receipt.id
    with pytest.raises(ConsentDenied, match="consent_household_mismatch"):
        await consent_service.require_current_hmac_valid(
            uuid4(),
            adult_a.id,
            ConsentPurpose.CLOUD_TTS,
            now,
        )
    assert await consent_service.is_current(adult_a.id, ConsentPurpose.CLOUD_TTS, now) is True
    assert await consent_service.is_current(adult_a.id, ConsentPurpose.WEB_SEARCH, now) is False


@pytest.mark.asyncio
async def test_cloud_route_consent_revocation_handler_invalidates_only_revoked_subject_purpose(
    identity_env,
    adult_a,
    now,
) -> None:
    class RecordingRouteAuthorizations:
        def __init__(self) -> None:
            self.calls: list[tuple[object, object, str, object]] = []

        async def invalidate_subject_purpose_in_uow(
            self,
            uow,
            subject_id,
            purpose,
            timestamp,
        ) -> None:
            self.calls.append((uow, subject_id, purpose, timestamp))

    routes = RecordingRouteAuthorizations()
    handler = CloudRouteConsentRevocationHandler(routes)
    uow = object()
    receipt = identity_env.install_consent(adult_a, adult_a.id, ConsentPurpose.CLOUD_REASONING)

    await handler.apply_in_uow(uow, receipt, object(), now)

    assert routes.calls == [(uow, adult_a.id, ConsentPurpose.CLOUD_REASONING.value, now)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forgery", ["cross_adult_actor", "guardian_actor", "legacy_restored_guardian"]
)
@pytest.mark.parametrize("profile_class", [ProfileClass.OWNER, ProfileClass.ADULT])
async def test_web_search_use_rejects_hmac_valid_non_self_receipt(
    consent_service,
    hmac_valid_search_receipt_factory,
    adult_subject_factory,
    consent_repository,
    now,
    forgery,
    profile_class,
) -> None:
    subject = adult_subject_factory(profile_class)
    await consent_repository.install_latest(
        hmac_valid_search_receipt_factory(subject=subject, forgery=forgery)
    )

    with pytest.raises(ConsentDenied, match="web_search_adult_self_receipt_required"):
        await consent_service.require_current(subject.id, ConsentPurpose.WEB_SEARCH, now)


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", [ConsentPurpose.CLOUD_STT, ConsentPurpose.PERSONALIZATION])
@pytest.mark.parametrize("forgery", ["cross_adult_actor", "restored_guardian_lineage"])
async def test_any_adult_consent_use_rejects_hmac_valid_non_self_receipt(
    consent_service,
    consent_repository,
    adult_subject_factory,
    identity_env,
    now,
    purpose,
    forgery,
) -> None:
    subject = adult_subject_factory(ProfileClass.ADULT)
    actor_id = identity_env.adult_b.id if forgery == "cross_adult_actor" else subject.id
    guardian_id = None if forgery == "cross_adult_actor" else identity_env.guardian.id
    guardian_generation = None if guardian_id is None else 1
    fields = (
        subject.household_id,
        subject.id,
        purpose,
        actor_id,
        guardian_id,
        guardian_generation,
        True,
        "phase1-v1",
        "phase1-disclosure-v1",
        now,
        None,
    )
    key_id, receipt_hmac = identity_env.signer.sign_fields("subject_consent_receipt", fields)
    await consent_repository.install_latest(
        ConsentReceipt(
            id=uuid4(),
            household_id=subject.household_id,
            subject_id=subject.id,
            actor_id=actor_id,
            guardian_id=guardian_id,
            guardian_generation=guardian_generation,
            purpose=purpose,
            granted=True,
            policy_version="phase1-v1",
            disclosure_version="phase1-disclosure-v1",
            commitment_key_id=key_id,
            receipt_hmac=receipt_hmac,
            created_at=now,
            expires_at=None,
        )
    )

    with pytest.raises(ConsentDenied, match="adult_self_consent_receipt_required"):
        await consent_service.require_current(subject.id, purpose, now)


@pytest.mark.asyncio
async def test_subject_receipt_hmac_cannot_cross_household_subject_or_purpose(
    identity_mutations,
    consent_service,
    adult_a,
    adult_a_grant,
    receipt_tamper,
) -> None:
    receipt = await identity_mutations.grant_consent(
        GrantConsent(
            subject_id=adult_a.id,
            actor_id=adult_a.id,
            purpose=ConsentPurpose.CLOUD_REASONING,
            action_binding=adult_a_grant.binding,
        ),
        adult_a_grant.id,
    )

    for changed in receipt_tamper.each(
        receipt,
        fields=("household_id", "subject_id", "purpose", "guardian_id", "guardian_generation"),
    ):
        with pytest.raises(ConsentDenied, match="consent_receipt_hmac_invalid"):
            await consent_service.verify_receipt(changed)


@pytest.mark.asyncio
async def test_public_verify_receipt_rejects_hmac_valid_web_search_non_self(
    consent_service,
    hmac_valid_search_receipt_factory,
    adult_subject_factory,
) -> None:
    subject = adult_subject_factory(ProfileClass.ADULT)
    receipt = hmac_valid_search_receipt_factory(subject=subject, forgery="cross_adult_actor")

    with pytest.raises(ConsentDenied, match="web_search_adult_self_receipt_required"):
        await consent_service.verify_receipt(receipt)


@pytest.mark.asyncio
async def test_public_verify_receipt_rejects_hmac_valid_no_guardian_non_self_actor(
    consent_service,
    identity_env,
    adult_a,
    adult_b,
    now,
) -> None:
    fields = (
        adult_a.household_id,
        adult_a.id,
        ConsentPurpose.CLOUD_STT,
        adult_b.id,
        None,
        None,
        True,
        "phase1-v1",
        "phase1-disclosure-v1",
        now,
        None,
    )
    key_id, receipt_hmac = identity_env.signer.sign_fields("subject_consent_receipt", fields)
    receipt = ConsentReceipt(
        id=uuid4(),
        household_id=adult_a.household_id,
        subject_id=adult_a.id,
        actor_id=adult_b.id,
        guardian_id=None,
        guardian_generation=None,
        purpose=ConsentPurpose.CLOUD_STT,
        granted=True,
        policy_version="phase1-v1",
        disclosure_version="phase1-disclosure-v1",
        commitment_key_id=key_id,
        receipt_hmac=receipt_hmac,
        created_at=now,
        expires_at=None,
    )

    with pytest.raises(ConsentDenied, match="adult_self_consent_receipt_required"):
        await consent_service.verify_receipt(receipt)


@pytest.mark.asyncio
async def test_public_verify_receipt_fails_closed_for_child_guardian_lineage(
    consent_service,
    identity_env,
    child,
    guardian,
    now,
) -> None:
    fields = (
        child.household_id,
        child.id,
        ConsentPurpose.FACE,
        guardian.id,
        guardian.id,
        child.guardian_generation,
        True,
        "phase1-v1",
        "phase1-disclosure-v1",
        now,
        None,
    )
    key_id, receipt_hmac = identity_env.signer.sign_fields("subject_consent_receipt", fields)
    receipt = ConsentReceipt(
        id=uuid4(),
        household_id=child.household_id,
        subject_id=child.id,
        actor_id=guardian.id,
        guardian_id=guardian.id,
        guardian_generation=child.guardian_generation,
        purpose=ConsentPurpose.FACE,
        granted=True,
        policy_version="phase1-v1",
        disclosure_version="phase1-disclosure-v1",
        commitment_key_id=key_id,
        receipt_hmac=receipt_hmac,
        created_at=now,
        expires_at=None,
    )

    with pytest.raises(ConsentDenied, match="current_primary_guardian_receipt_state_required"):
        await consent_service.verify_receipt(receipt)


@pytest.mark.asyncio
async def test_guest_receipt_is_challenge_and_session_bound(
    guest_consent_service,
    active_guest_disclosure,
    active_session,
    other_session,
    now,
) -> None:
    receipt = await guest_consent_service.accept_challenge(active_guest_disclosure.id, "yes", now)

    assert receipt.expires_at == active_session.expires_at
    await guest_consent_service.require_current(
        active_session.household_id,
        active_session.id,
        ConsentPurpose.CLOUD_STT,
        now,
    )
    await guest_consent_service.require_current_hmac_valid(
        active_session.household_id,
        active_session.id,
        ConsentPurpose.CLOUD_STT,
        now,
    )
    with pytest.raises(ConsentDenied, match="current_guest_session_consent_required"):
        await guest_consent_service.require_current(
            active_session.household_id,
            other_session.id,
            ConsentPurpose.CLOUD_STT,
            now,
        )


@pytest.mark.asyncio
async def test_guest_cannot_mint_consent_without_active_exact_disclosure(
    guest_consent_service,
    expired_guest_disclosure,
    now,
) -> None:
    with pytest.raises(ConsentDenied, match="active_guest_disclosure_challenge_required"):
        await guest_consent_service.accept_challenge(expired_guest_disclosure.id, "yes", now)


@pytest.mark.asyncio
async def test_guest_disclosure_challenge_is_signed_and_exactly_once(
    guest_consent_service,
    active_guest_disclosure,
    tampered_guest_disclosure,
    now,
) -> None:
    with pytest.raises(ConsentDenied, match="active_guest_disclosure_challenge_required"):
        await guest_consent_service.accept_challenge(tampered_guest_disclosure.id, "yes", now)

    results = await asyncio.gather(
        guest_consent_service.accept_challenge(active_guest_disclosure.id, "yes", now),
        guest_consent_service.accept_challenge(active_guest_disclosure.id, "yes", now),
        return_exceptions=True,
    )
    assert sum(not isinstance(item, Exception) for item in results) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["challenge_id", "presentation_receipt_id"])
async def test_guest_receipt_hmac_rejects_restored_lineage_substitution(
    guest_consent_service,
    active_guest_disclosure,
    identity_env,
    active_session,
    now,
    field,
) -> None:
    receipt = await guest_consent_service.accept_challenge(active_guest_disclosure.id, "yes", now)
    replacement = uuid4()
    identity_env.guest_receipts[-1] = receipt.model_copy(update={field: replacement})

    with pytest.raises(ConsentDenied, match="guest_consent_receipt_hmac_invalid"):
        await guest_consent_service.require_current(
            active_session.household_id,
            active_session.id,
            ConsentPurpose.CLOUD_STT,
            now,
        )


@pytest.mark.asyncio
async def test_guest_current_rejects_future_issued_hmac_valid_receipt(
    guest_consent_service,
    active_guest_disclosure,
    identity_env,
    active_session,
    now,
) -> None:
    future = now + timedelta(seconds=1)
    expires_at = active_session.expires_at
    fields = (
        active_session.household_id,
        active_session.id,
        active_guest_disclosure.id,
        active_guest_disclosure.presentation_receipt_id,
        active_guest_disclosure.purpose,
        active_guest_disclosure.disclosure_version,
        True,
        future,
        expires_at,
        None,
    )
    key_id, receipt_hmac = identity_env.signer.sign_fields(
        "guest_session_consent_receipt",
        fields,
    )
    await identity_env.guest_consent_repo.append(
        active_session.household_id,
        active_session.id,
        active_guest_disclosure.id,
        active_guest_disclosure.presentation_receipt_id,
        active_guest_disclosure.purpose,
        active_guest_disclosure.disclosure_version,
        True,
        future,
        expires_at,
        None,
        key_id,
        receipt_hmac,
    )

    with pytest.raises(ConsentDenied, match="current_guest_session_consent_required"):
        await guest_consent_service.require_current(
            active_session.household_id,
            active_session.id,
            ConsentPurpose.CLOUD_STT,
            now,
        )


@pytest.mark.asyncio
async def test_guest_challenge_requires_exact_local_presentation_receipt(
    guest_consent_service,
    active_session,
    other_session_disclosure_receipt,
    now,
) -> None:
    with pytest.raises(ConsentDenied, match="guest_disclosure_presentation_mismatch"):
        await guest_consent_service.issue_challenge(
            active_session.household_id,
            active_session.id,
            ConsentPurpose.CLOUD_REASONING,
            "phase1-disclosure-v1",
            other_session_disclosure_receipt.id,
            now,
        )


@pytest.mark.asyncio
async def test_guest_web_search_is_denied_before_session_or_receipt_lookup(
    guest_consent_service,
    active_session,
    local_disclosure_receipt,
    guest_repository_spies,
    now,
) -> None:
    with pytest.raises(ConsentDenied, match="guest_disclosure_purpose_denied"):
        await guest_consent_service.issue_challenge(
            active_session.household_id,
            active_session.id,
            ConsentPurpose.WEB_SEARCH,
            "phase1-disclosure-v1",
            local_disclosure_receipt.id,
            now,
        )
    with pytest.raises(ConsentDenied, match="guest_disclosure_purpose_denied"):
        await guest_consent_service.require_current(
            active_session.household_id,
            active_session.id,
            ConsentPurpose.WEB_SEARCH,
            now,
        )

    assert guest_repository_spies.session_reads == 0
    assert guest_repository_spies.receipt_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke", "require_current"])
@pytest.mark.parametrize("state", ["inactive", "revoked"])
async def test_subject_consent_operations_require_current_active_profile_before_receipt_access(
    consent_service,
    subject_in_state_factory,
    consent_command_factory,
    actor_auth_factory,
    consent_repository_spy,
    now,
    operation,
    state,
) -> None:
    subject = subject_in_state_factory(state)

    with pytest.raises(ConsentDenied, match="current_active_subject_required"):
        if operation == "require_current":
            await consent_service.require_current(subject.id, ConsentPurpose.CLOUD_REASONING, now)
        else:
            command = consent_command_factory(subject, operation=operation)
            await getattr(consent_service, operation)(
                command, actor_auth_factory(command.action_binding)
            )

    assert consent_repository_spy.read_count == 0
