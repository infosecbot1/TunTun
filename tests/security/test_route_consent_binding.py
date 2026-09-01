from __future__ import annotations

from uuid import uuid4

import pytest
from tuntun_contracts.provider import RouteAuthorizationRequest
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.services.providers.route_authorization import RouteAuthorizationService
from tuntun_testing.fake_clock import FakeClock

from tests.fixtures.provider_routes import PrerequisitesFake


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"household_id": uuid4()},
        {"subject_id": uuid4()},
        {"session_id": uuid4()},
        {"purpose": "cloud_tts"},
        {"consent_receipt_ids": (uuid4(),)},
    ],
)
async def test_consent_evidence_cannot_cross_any_route_scope(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
    change: dict[str, object],
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )

    with pytest.raises(PermissionError, match="route_invalidated:consent"):
        await service.authorize(provider_route_request.model_copy(update=change))


@pytest.mark.asyncio
async def test_subject_evidence_cannot_authorize_guest(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )

    with pytest.raises(PermissionError, match="route_invalidated:consent"):
        await service.authorize(provider_route_request.model_copy(update={"subject_id": None}))


@pytest.mark.asyncio
async def test_guest_disclosure_cannot_authorize_a_subject(
    route_uow_factory: AsyncUnitOfWorkFactory,
    provider_route_prerequisites: PrerequisitesFake,
    route_clock: FakeClock,
    provider_route_request: RouteAuthorizationRequest,
) -> None:
    guest = provider_route_request.model_copy(update={"subject_id": None})
    provider_route_prerequisites.bind_to_request(guest)
    service = RouteAuthorizationService(
        route_uow_factory,
        provider_route_prerequisites,
        route_clock,
    )

    with pytest.raises(PermissionError, match="route_invalidated:consent"):
        await service.authorize(provider_route_request)
