# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import pytest
from tuntun_core.services.identity.enrollment import EnrollmentDenied


@pytest.mark.asyncio
async def test_biometric_or_pin_cannot_authorize_enrollment(
    enrollment_mutations,
    bound_enrollment_request_factory,
    identified_grant,
) -> None:
    request = bound_enrollment_request_factory()

    with pytest.raises(EnrollmentDenied, match="fresh_owner_passkey_required"):
        await enrollment_mutations.request(request, identified_grant.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "subject_id",
        "modality",
        "expected_profile_version",
        "expected_consent_receipt_id",
        "reenrollment_days",
    ],
)
async def test_enrollment_parameter_substitution_cannot_reuse_owner_grant(
    enrollment_service,
    bound_enrollment_request_factory,
    owner_auth_factory,
    enrollment_repository_spy,
    field,
) -> None:
    request = bound_enrollment_request_factory()
    auth = owner_auth_factory(request.action_binding)
    substituted = bound_enrollment_request_factory(
        changed_field=field,
        keep_binding=request.action_binding,
    )

    with pytest.raises(EnrollmentDenied, match="enrollment_parameter_binding_mismatch"):
        await enrollment_service.request(substituted, auth)

    assert enrollment_repository_spy.read_count == 0
    assert enrollment_repository_spy.write_count == 0


@pytest.mark.asyncio
async def test_stale_enrollment_profile_version_denies_before_enrollment_write(
    enrollment_service,
    bound_enrollment_request_factory,
    owner_auth_factory,
    enrollment_repository_spy,
) -> None:
    request = bound_enrollment_request_factory()
    auth = owner_auth_factory(request.action_binding)
    enrollment_repository_spy.bump_profile_version(request.subject_id)

    with pytest.raises(EnrollmentDenied, match="enrollment_profile_state_changed"):
        await enrollment_service.request(request, auth)

    assert enrollment_repository_spy.write_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["subject_id", "enrollment_id"])
async def test_enrollment_cancel_substitution_denies_before_enrollment_read(
    enrollment_service,
    bound_cancel_enrollment_factory,
    owner_auth_factory,
    enrollment_repository_spy,
    uow,
    field,
) -> None:
    command = bound_cancel_enrollment_factory()
    auth = owner_auth_factory(command.action_binding)
    forged = bound_cancel_enrollment_factory(
        changed_field=field,
        keep_binding=command.action_binding,
    )

    with pytest.raises(EnrollmentDenied, match="enrollment_parameter_binding_mismatch"):
        await enrollment_service.cancel_in_uow(uow, forged, auth)

    assert enrollment_repository_spy.read_count == 0
    assert enrollment_repository_spy.write_count == 0
