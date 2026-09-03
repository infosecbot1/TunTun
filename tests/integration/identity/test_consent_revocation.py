# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_revocation_blocks_the_next_route_authorization(
    route_authorizer,
    identity_mutations,
    adult_a,
    adult_cloud_reasoning_consent,
    passkey_grant_for_revoke_consent,
    cloud_request,
    network_capture,
) -> None:
    revoke = adult_cloud_reasoning_consent.revoke_command
    grant = passkey_grant_for_revoke_consent(revoke)

    await identity_mutations.revoke_consent(revoke, grant.id)

    with pytest.raises(PermissionError, match="consent_required:cloud_reasoning"):
        await route_authorizer.authorize(
            cloud_request.for_subject(adult_a.id).to_route_authorization_request()
        )
    assert network_capture == []


@pytest.mark.asyncio
async def test_guest_needs_session_specific_cloud_acceptance(
    route_authorizer,
    guest_cloud_request,
) -> None:
    with pytest.raises(PermissionError, match="guest_session_consent_required:cloud_reasoning"):
        await route_authorizer.authorize(guest_cloud_request.to_route_authorization_request())
