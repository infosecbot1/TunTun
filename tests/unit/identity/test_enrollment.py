# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from tuntun_contracts.policy import AssuranceLevel
from tuntun_core.domain.profile import Modality, RequestEnrollment
from tuntun_core.services.identity.enrollment import EnrollmentDenied

from tests.identity_support import _cancel_enrollment_command


@pytest.mark.asyncio
async def test_child_reenrollment_defaults_to_180_days(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    child,
    guardian_face_consent,
    owner_passkey_grant_factory,
    calibrated_enrollment_factory,
    clock,
) -> None:
    command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    owner_grant = owner_passkey_grant_factory(command.action_binding)

    session = await enrollment_mutations.request(command, owner_grant.id)

    assert session.consent_receipt_id == guardian_face_consent.id
    assert session.reenrollment_days == 180
    calibrated_enrollment_factory(session)
    async with mutation_scope.open() as uow:
        completed = await enrollment_service.complete_in_uow(
            uow,
            session.id,
            (session.synthetic_template_id,),
            guardian_face_consent,
            clock.now(),
        )
        await uow.commit()

    assert completed.next_reenrollment_reminder_at == clock.now() + timedelta(days=180)
    assert completed.biometric_hard_expires_at == clock.now() + timedelta(days=365)


@pytest.mark.asyncio
async def test_enrollment_request_in_uow_uses_active_scope(
    enrollment_service,
    mutation_scope,
    bound_enrollment_request_factory,
    owner_auth_factory,
) -> None:
    command = bound_enrollment_request_factory()

    async with mutation_scope.open() as uow:
        session = await enrollment_service.request_in_uow(
            uow,
            command,
            owner_auth_factory(command.action_binding),
        )
        await uow.commit()

    assert session.state == "requested"
    assert session.subject_id == command.subject_id
    assert session.consent_receipt_id == command.expected_consent_receipt_id


@pytest.mark.asyncio
async def test_enrollment_in_uow_methods_reject_cross_scope_uow_before_mutation(
    identity_env,
    enrollment_service,
    mutation_scope,
    bound_enrollment_request_factory,
    bound_cancel_enrollment_factory,
    owner_auth_factory,
    guardian_face_consent,
    clock,
) -> None:
    request_command = bound_enrollment_request_factory()
    cancel_command = bound_cancel_enrollment_factory()

    async with mutation_scope.open() as active_uow:
        async with identity_env.uow_factory() as other_uow:
            assert active_uow is not other_uow
            with pytest.raises(RuntimeError, match="enrollment_uow_scope_mismatch"):
                await enrollment_service.request_in_uow(
                    other_uow,
                    request_command,
                    owner_auth_factory(request_command.action_binding),
                )
            with pytest.raises(RuntimeError, match="enrollment_uow_scope_mismatch"):
                await enrollment_service.cancel_in_uow(
                    other_uow,
                    cancel_command,
                    owner_auth_factory(cancel_command.action_binding),
                )
            with pytest.raises(RuntimeError, match="enrollment_uow_scope_mismatch"):
                await enrollment_service.begin_capture_in_uow(
                    other_uow,
                    cancel_command.enrollment_id,
                )
            with pytest.raises(RuntimeError, match="enrollment_uow_scope_mismatch"):
                await enrollment_service.mark_calibrating_in_uow(
                    other_uow,
                    cancel_command.enrollment_id,
                )
            with pytest.raises(RuntimeError, match="enrollment_uow_scope_mismatch"):
                await enrollment_service.complete_in_uow(
                    other_uow,
                    cancel_command.enrollment_id,
                    (),
                    guardian_face_consent,
                    clock.now(),
                )
            await other_uow.rollback()
        await active_uow.rollback()


@pytest.mark.asyncio
async def test_enrollment_begin_capture_and_mark_calibrating_use_active_scope(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    bound_enrollment_request_factory,
    owner_passkey_grant_factory,
) -> None:
    command = bound_enrollment_request_factory()
    grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, grant.id)

    async with mutation_scope.open() as uow:
        capturing = await enrollment_service.begin_capture_in_uow(uow, session.id)
        calibrating = await enrollment_service.mark_calibrating_in_uow(uow, session.id)
        await uow.commit()

    assert capturing.state == "capturing"
    assert calibrating.state == "calibrating"


@pytest.mark.asyncio
async def test_enrollment_cancel_consumes_owner_grant_and_closes_pending_session(
    identity_env,
    enrollment_mutations,
    bound_cancel_enrollment_factory,
    owner_passkey_grant_factory,
    clock,
) -> None:
    command = bound_cancel_enrollment_factory()
    grant = owner_passkey_grant_factory(command.action_binding)
    audit_count = sum(identity_env.audit_count_by_event.values())

    cancelled = await enrollment_mutations.cancel(command, grant.id)

    assert cancelled.state == "cancelled"
    assert cancelled.closed_at == clock.now()
    assert identity_env.enrollments[command.enrollment_id].closed_at == clock.now()
    assert sum(identity_env.audit_count_by_event.values()) == audit_count + 1


@pytest.mark.asyncio
async def test_enrollment_cancel_rejects_session_subject_scope_drift_before_closing(
    identity_env,
    enrollment_mutations,
    bound_cancel_enrollment_factory,
    owner_passkey_grant_factory,
    adult_a,
) -> None:
    command = bound_cancel_enrollment_factory()
    session = identity_env.enrollments[command.enrollment_id]
    identity_env.enrollments[command.enrollment_id] = session.model_copy(
        update={"subject_id": adult_a.id}
    )
    grant = owner_passkey_grant_factory(command.action_binding)

    with pytest.raises(EnrollmentDenied, match="enrollment_scope_mismatch"):
        await enrollment_mutations.cancel(command, grant.id)

    assert identity_env.enrollments[command.enrollment_id].closed_at is None


@pytest.mark.asyncio
async def test_enrollment_cancel_requires_current_owner_authority_after_passkey_binding(
    identity_env,
    enrollment_service,
    mutation_scope,
    bound_cancel_enrollment_factory,
    adult_a,
) -> None:
    base_command = bound_cancel_enrollment_factory()
    session = identity_env.enrollments[base_command.enrollment_id]
    command = _cancel_enrollment_command(identity_env, session, actor_id=adult_a.id)
    auth = identity_env.auth_context(adult_a.id, command.action_binding)

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="fresh_owner_passkey_required"):
            await enrollment_service.cancel_in_uow(uow, command, auth)
        await uow.rollback()

    assert identity_env.enrollments[command.enrollment_id].closed_at is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["identified", "source", "binding", "anonymous", "future", "expired"],
)
async def test_enrollment_request_requires_fresh_bound_owner_passkey_before_profile_read(
    enrollment_service,
    bound_enrollment_request_factory,
    owner_auth_factory,
    enrollment_repository_spy,
    clock,
    failure,
) -> None:
    command = bound_enrollment_request_factory()
    auth = owner_auth_factory(command.action_binding)
    if failure == "identified":
        auth = auth.model_copy(update={"assurance": AssuranceLevel.IDENTIFIED})
    elif failure == "source":
        auth = auth.model_copy(update={"assurance_source": "pin"})
    elif failure == "binding":
        other_binding = auth.binding.model_copy(update={"idempotency_key": uuid4()})
        auth = auth.model_copy(update={"binding": other_binding})
    elif failure == "anonymous":
        auth = auth.model_copy(update={"subject_id": None})
    elif failure == "future":
        auth = auth.model_copy(update={"consumed_at": clock.now() + timedelta(seconds=1)})
    else:
        auth = auth.model_copy(update={"consumed_at": clock.now() - timedelta(seconds=121)})

    with pytest.raises(EnrollmentDenied, match="fresh_owner_passkey_required"):
        await enrollment_service.request(command, auth)

    assert enrollment_repository_spy.read_count == 0 and enrollment_repository_spy.write_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["request", "cancel"])
async def test_enrollment_parameter_substitution_is_rejected_before_mutation(
    enrollment_service,
    enrollment_mutations,
    bound_enrollment_request_factory,
    bound_cancel_enrollment_factory,
    owner_auth_factory,
    owner_passkey_grant_factory,
    enrollment_repository_spy,
    operation,
) -> None:
    if operation == "request":
        command = bound_enrollment_request_factory()
        substituted = bound_enrollment_request_factory(
            changed_field="expected_profile_version",
            keep_binding=command.action_binding,
        )
        with pytest.raises(EnrollmentDenied, match="enrollment_parameter_binding_mismatch"):
            await enrollment_service.request(
                substituted,
                owner_auth_factory(command.action_binding),
            )
    else:
        command = bound_cancel_enrollment_factory()
        substituted = bound_cancel_enrollment_factory(
            changed_field="subject_id",
            keep_binding=command.action_binding,
        )
        grant = owner_passkey_grant_factory(command.action_binding)
        with pytest.raises(EnrollmentDenied, match="enrollment_parameter_binding_mismatch"):
            await enrollment_mutations.cancel(substituted, grant.id)

    assert enrollment_repository_spy.write_count == 0


@pytest.mark.asyncio
async def test_enrollment_request_rejects_stale_profile_version_after_owner_passkey(
    identity_env,
    enrollment_service,
    bound_enrollment_request_factory,
    owner_auth_factory,
    child,
) -> None:
    command = bound_enrollment_request_factory()
    identity_env.enrollment_repo.bump_profile_version(child.id)

    with pytest.raises(EnrollmentDenied, match="enrollment_profile_state_changed"):
        await enrollment_service.request(command, owner_auth_factory(command.action_binding))


@pytest.mark.asyncio
async def test_enrollment_request_rejects_consent_receipt_superseded_after_binding(
    identity_env,
    enrollment_service,
    bound_enrollment_request_factory,
    owner_auth_factory,
    child,
    guardian,
    clock,
) -> None:
    command = bound_enrollment_request_factory()
    clock.advance(seconds=1)
    identity_env.install_consent(child, guardian.id, Modality.FACE.consent_purpose)

    with pytest.raises(EnrollmentDenied, match="enrollment_consent_state_changed"):
        await enrollment_service.request(command, owner_auth_factory(command.action_binding))


@pytest.mark.asyncio
async def test_enrollment_completion_rejects_empty_template_list_before_session_read(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    bound_enrollment_request_factory,
    owner_passkey_grant_factory,
    guardian_face_consent,
    clock,
) -> None:
    command = bound_enrollment_request_factory()
    grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, grant.id)

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="enrollment_template_required"):
            await enrollment_service.complete_in_uow(
                uow,
                session.id,
                (),
                guardian_face_consent,
                clock.now(),
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_enrollment_completion_rejects_expired_session_before_template_approval(
    identity_env,
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    bound_enrollment_request_factory,
    owner_passkey_grant_factory,
    calibrated_enrollment_factory,
    guardian_face_consent,
    clock,
) -> None:
    command = bound_enrollment_request_factory()
    grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, grant.id)
    template_id = calibrated_enrollment_factory(session)
    identity_env.enrollments[session.id] = identity_env.enrollments[session.id].model_copy(
        update={"expires_at": clock.now()}
    )

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="enrollment_session_expired"):
            await enrollment_service.complete_in_uow(
                uow,
                session.id,
                (template_id,),
                guardian_face_consent,
                clock.now(),
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_enrollment_completion_rejects_consent_scope_drift_before_current_recheck(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    bound_enrollment_request_factory,
    owner_passkey_grant_factory,
    calibrated_enrollment_factory,
    guardian_face_consent,
    adult_a,
    clock,
) -> None:
    command = bound_enrollment_request_factory()
    grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, grant.id)
    template_id = calibrated_enrollment_factory(session)
    wrong_subject_receipt = guardian_face_consent.model_copy(update={"subject_id": adult_a.id})

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="enrollment_consent_scope_mismatch"):
            await enrollment_service.complete_in_uow(
                uow,
                session.id,
                (template_id,),
                wrong_subject_receipt,
                clock.now(),
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_reminder_does_not_expire_but_hard_deadline_does(
    enrollment_mutations,
    enrollment_service,
    child,
    guardian_face_consent,
    owner_passkey_grant_factory,
    calibrated_enrollment_factory,
    clock,
) -> None:
    command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    owner_grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, owner_grant.id)
    calibrated_enrollment_factory(session)
    async with enrollment_mutations.mutation_scope.open() as uow:
        await enrollment_service.complete_in_uow(
            uow,
            session.id,
            (session.synthetic_template_id,),
            guardian_face_consent,
            clock.now(),
        )
        await uow.commit()

    clock.advance(days=181)

    assert await enrollment_service.reminders_due(child.household_id, clock.now()) == (child.id,)
    assert (
        await enrollment_service.expire_due_child_templates(
            child.household_id,
            clock.now(),
        )
        == ()
    )

    clock.advance(days=185)

    assert await enrollment_service.expire_due_child_templates(
        child.household_id,
        clock.now(),
    ) == (child.id,)


@pytest.mark.asyncio
async def test_completion_requires_calibrating_state(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    identity_env,
    child,
    guardian_face_consent,
    owner_passkey_grant_factory,
    clock,
) -> None:
    command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    owner_grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, owner_grant.id)
    template_id = identity_env.biometric_template_repo.capture_for_enrollment(session)

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="enrollment_state_mismatch"):
            await enrollment_service.complete_in_uow(
                uow,
                session.id,
                (template_id,),
                guardian_face_consent,
                clock.now(),
            )


@pytest.mark.asyncio
async def test_stale_consent_cannot_complete_enrollment(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    identity_env,
    child,
    guardian,
    guardian_face_consent,
    owner_passkey_grant_factory,
    calibrated_enrollment_factory,
    clock,
) -> None:
    command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    owner_grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, owner_grant.id)
    template_id = calibrated_enrollment_factory(session)
    clock.advance(seconds=1)
    identity_env.install_consent(child, guardian.id, Modality.FACE.consent_purpose)

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="enrollment_consent_state_changed"):
            await enrollment_service.complete_in_uow(
                uow,
                session.id,
                (template_id,),
                guardian_face_consent,
                clock.now(),
            )


@pytest.mark.asyncio
async def test_revoked_consent_cannot_complete_enrollment(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    identity_env,
    child,
    guardian_face_consent,
    owner_passkey_grant_factory,
    calibrated_enrollment_factory,
    clock,
) -> None:
    command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    owner_grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, owner_grant.id)
    template_id = calibrated_enrollment_factory(session)
    revoked_at = clock.now() + timedelta(microseconds=1)
    identity_env.consents.append(
        guardian_face_consent.model_copy(
            update={
                "id": uuid4(),
                "granted": False,
                "created_at": revoked_at,
                "expires_at": revoked_at,
            }
        )
    )

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="enrollment_consent_state_changed"):
            await enrollment_service.complete_in_uow(
                uow,
                session.id,
                (template_id,),
                guardian_face_consent,
                clock.now(),
            )


@pytest.mark.asyncio
async def test_template_substitution_cannot_complete_enrollment(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    identity_env,
    child,
    adult_a,
    guardian_face_consent,
    owner_passkey_grant_factory,
    calibrated_enrollment_factory,
    clock,
) -> None:
    command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    owner_grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, owner_grant.id)
    calibrated_enrollment_factory(session)
    wrong_template_id = identity_env.biometric_template_repo.capture_for_enrollment(
        session,
        template_id=uuid4(),
        subject_id=adult_a.id,
    )

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="enrollment_template_scope_mismatch"):
            await enrollment_service.complete_in_uow(
                uow,
                session.id,
                (wrong_template_id,),
                guardian_face_consent,
                clock.now(),
            )


@pytest.mark.asyncio
async def test_same_session_wrong_template_uuid_cannot_complete_enrollment(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    identity_env,
    child,
    guardian_face_consent,
    owner_passkey_grant_factory,
    calibrated_enrollment_factory,
    clock,
) -> None:
    command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    owner_grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, owner_grant.id)
    calibrated_enrollment_factory(session)
    assert session.synthetic_template_id is not None
    wrong_template_id = uuid4()
    assert wrong_template_id != session.synthetic_template_id
    identity_env.biometric_template_repo.capture_for_enrollment(
        session,
        template_id=wrong_template_id,
    )

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="enrollment_template_scope_mismatch"):
            await enrollment_service.complete_in_uow(
                uow,
                session.id,
                (wrong_template_id,),
                guardian_face_consent,
                clock.now(),
            )


@pytest.mark.asyncio
async def test_fake_enrollment_repository_approval_missing_template_is_atomic(
    enrollment_mutations,
    mutation_scope,
    identity_env,
    child,
    guardian_face_consent,
    owner_passkey_grant_factory,
    clock,
) -> None:
    command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    owner_grant = owner_passkey_grant_factory(command.action_binding)
    session = await enrollment_mutations.request(command, owner_grant.id)
    calibrated = identity_env.enrollment_repo.force_calibrating_for_test(session.id)
    expected_template_id = calibrated.synthetic_template_id
    assert expected_template_id is not None

    async with mutation_scope.open() as uow:
        with pytest.raises(RuntimeError):
            await uow.enrollments.approve(
                session.id,
                (expected_template_id,),
                None,
                None,
                clock.now(),
            )
        await uow.commit()

    assert identity_env.enrollments[session.id].state == "calibrating"


@pytest.mark.asyncio
async def test_template_from_another_enrollment_session_cannot_complete_enrollment(
    enrollment_mutations,
    enrollment_service,
    mutation_scope,
    identity_env,
    child,
    guardian_face_consent,
    owner_passkey_grant_factory,
    calibrated_enrollment_factory,
    clock,
) -> None:
    first_command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    first_grant = owner_passkey_grant_factory(first_command.action_binding)
    first_session = await enrollment_mutations.request(first_command, first_grant.id)
    first_template_id = calibrated_enrollment_factory(first_session)
    second_command = RequestEnrollment(
        subject_id=child.id,
        modality=Modality.FACE,
        expected_profile_version=child.version,
        expected_consent_receipt_id=guardian_face_consent.id,
        action_binding=owner_passkey_grant_factory.binding_for_request(
            child,
            Modality.FACE,
            guardian_face_consent.id,
        ),
    )
    second_grant = owner_passkey_grant_factory(second_command.action_binding)
    second_session = await enrollment_mutations.request(second_command, second_grant.id)
    identity_env.enrollment_repo.force_calibrating_for_test(second_session.id)

    async with mutation_scope.open() as uow:
        with pytest.raises(EnrollmentDenied, match="enrollment_template_scope_mismatch"):
            await enrollment_service.complete_in_uow(
                uow,
                second_session.id,
                (first_template_id,),
                guardian_face_consent,
                clock.now(),
            )
