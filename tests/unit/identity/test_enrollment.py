# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from tuntun_core.domain.profile import Modality, RequestEnrollment
from tuntun_core.services.identity.enrollment import EnrollmentDenied


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
