from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from tuntun_contracts.base import Commitment, Sensitivity
from tuntun_contracts.provider import RouteAuthorizationRequest, RouteConsumption
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine
from tuntun_testing.fake_clock import FakeClock


@dataclass(frozen=True, slots=True)
class RouteDatabase:
    engine: Engine
    path: Path
    key: bytes


@pytest.fixture
def route_database(tmp_path: Path) -> Iterator[RouteDatabase]:
    private_dir = Path(os.path.realpath(tmp_path)) / "private"
    private_dir.mkdir(mode=0o700)
    database_path = private_dir / "foundation.db"
    key = bytes(range(32))
    config = Config("apps/core/alembic.ini")
    config.attributes["sqlcipher_path"] = database_path
    config.attributes["sqlcipher_key"] = key
    command.upgrade(config, "head")
    engine = create_sqlcipher_engine(database_path, key)
    try:
        yield RouteDatabase(engine=engine, path=database_path, key=key)
    finally:
        engine.dispose()
        for candidate in (
            database_path,
            Path(f"{database_path}-wal"),
            Path(f"{database_path}-shm"),
        ):
            candidate.unlink(missing_ok=True)


@pytest_asyncio.fixture
async def route_uow_factory(route_database: RouteDatabase) -> Iterator[AsyncUnitOfWorkFactory]:
    factory = AsyncUnitOfWorkFactory(route_database.engine)
    try:
        yield factory
    finally:
        await factory.aclose()


@pytest.fixture
def route_clock() -> FakeClock:
    return FakeClock(datetime(2026, 8, 27, 1, 2, 3, 4, tzinfo=UTC))


@pytest.fixture
def provider_route_request() -> RouteAuthorizationRequest:
    return RouteAuthorizationRequest(
        request_id=uuid4(),
        attempt_id=uuid4(),
        purpose="cloud_reasoning",
        household_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        turn_id=uuid4(),
        provider="openai",
        model="gpt-5.6-sol",
        request_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="route-hmac-v1",
            value_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        max_input_bytes=32_000,
        max_input_units=8_000,
        privacy_receipt_id=uuid4(),
        consent_receipt_ids=(uuid4(),),
        budget_reservation_id=uuid4(),
        maximum_sensitivity=Sensitivity.HOUSEHOLD,
    )


@pytest.fixture
def provider_route_consumption(
    provider_route_request: RouteAuthorizationRequest,
    route_clock: FakeClock,
) -> RouteConsumption:
    request = provider_route_request
    return RouteConsumption(
        request_id=request.request_id,
        attempt_id=request.attempt_id,
        purpose=request.purpose,
        household_id=request.household_id,
        subject_id=request.subject_id,
        session_id=request.session_id,
        turn_id=request.turn_id,
        provider=request.provider,
        model=request.model,
        request_commitment=request.request_commitment,
        input_bytes=8_000,
        input_units=2_000,
        consumed_at=route_clock.now(),
    )


class PrerequisitesFake:
    def __init__(self, request: RouteAuthorizationRequest) -> None:
        self.subject_generation = 7
        self.invalid: str | None = None
        self.call_log: list[str] = []
        self.authorization_checks = 0
        self.transaction_checks = 0
        self.qwen_activation: object | None = None
        self.on_consent: Callable[[], None] | None = None
        self.on_authorization_barrier: Callable[[], None] | None = None
        self.on_consumption_barrier: Callable[[], None] | None = None
        self.bind_to_request(request)

    def bind_to_request(self, request: RouteAuthorizationRequest) -> None:
        self.consent_scope = (
            request.household_id,
            request.subject_id,
            request.session_id,
            request.purpose,
            request.consent_receipt_ids,
        )
        self.privacy_scope = (request.privacy_receipt_id, request.turn_id)
        self.review_scope = (request.provider, request.model, request.purpose)
        self.reservation_scope = request

    def _deny_if(self, name: str) -> None:
        if self.invalid == name:
            raise PermissionError(f"route_invalidated:{name}")

    async def require_current_subject_authority(
        self,
        uow: object,
        household_id: UUID,
        subject_id: UUID | None,
        expected_generation: int | None = None,
    ) -> int | None:
        del uow, household_id
        self.call_log.append("subject_authority")
        self._deny_if("subject_authority")
        if subject_id is None:
            if expected_generation is not None:
                raise PermissionError("route_invalidated:subject_authority")
            return None
        if expected_generation is not None and expected_generation != self.subject_generation:
            raise PermissionError("route_invalidated:subject_authority")
        return self.subject_generation

    async def require_current_consent(
        self,
        uow: object,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        purpose: str,
        receipt_ids: tuple[UUID, ...],
    ) -> None:
        del uow
        self.call_log.append("consent")
        self._deny_if("consent")
        if self.on_consent is not None:
            callback, self.on_consent = self.on_consent, None
            callback()
        if (household_id, subject_id, session_id, purpose, receipt_ids) != self.consent_scope:
            raise PermissionError("route_invalidated:consent")

    async def require_privacy_receipt(
        self,
        uow: object,
        receipt_id: UUID,
        turn_id: UUID,
    ) -> None:
        del uow
        self.call_log.append("privacy")
        self._deny_if("privacy")
        if (receipt_id, turn_id) != self.privacy_scope:
            raise PermissionError("route_invalidated:privacy")

    async def require_provider_review(
        self,
        uow: object,
        provider: str,
        model: str,
        purpose: str,
    ) -> None:
        del uow
        self.call_log.append("provider_review")
        self._deny_if("provider_review")
        if (provider, model, purpose) != self.review_scope:
            raise PermissionError("route_invalidated:provider_review")

    async def require_provider_activation(
        self,
        uow: object,
        provider: str,
        model: str,
        purpose: str,
        expected: object | None = None,
    ) -> object | None:
        del uow, model, purpose
        self.call_log.append("provider_activation")
        self._deny_if("qwen_activation")
        if provider == "openai":
            if expected is not None:
                raise PermissionError("route_invalidated:qwen_activation")
            return None
        if self.qwen_activation is None or (
            expected is not None and expected != self.qwen_activation
        ):
            raise PermissionError("route_invalidated:qwen_activation")
        return self.qwen_activation

    async def require_budget_reservation(
        self,
        uow: object,
        request: RouteAuthorizationRequest,
    ) -> None:
        del uow
        self.call_log.append("budget_reservation")
        self._deny_if("budget_reservation")
        if request != self.reservation_scope:
            raise PermissionError("route_invalidated:budget_reservation")

    def require_authorizable_in_transaction(
        self,
        transaction: Any,
        envelope: object,
        now: datetime,
    ) -> None:
        del envelope, now
        self.call_log.append("authorization_barrier")
        self.authorization_checks += 1
        assert transaction.exec_driver_sql("SELECT 1").scalar_one() == 1
        for invalid in (
            "turn",
            "privacy",
            "provider_review",
            "budget_reservation",
            "qwen_activation",
            "authorization_barrier",
        ):
            self._deny_if(invalid)
        if self.on_authorization_barrier is not None:
            callback, self.on_authorization_barrier = self.on_authorization_barrier, None
            callback()

    def require_consumable_in_transaction(
        self,
        transaction: Any,
        envelope: object,
        consumption: RouteConsumption,
        now: datetime,
    ) -> None:
        del envelope, consumption, now
        self.call_log.append("transaction_barrier")
        self.transaction_checks += 1
        assert transaction.exec_driver_sql("SELECT 1").scalar_one() == 1
        for invalid in (
            "turn",
            "privacy",
            "provider_review",
            "budget_reservation",
            "qwen_activation",
            "transaction_barrier",
        ):
            self._deny_if(invalid)
        if self.on_consumption_barrier is not None:
            callback, self.on_consumption_barrier = self.on_consumption_barrier, None
            callback()


@pytest.fixture
def provider_route_prerequisites(
    provider_route_request: RouteAuthorizationRequest,
) -> PrerequisitesFake:
    return PrerequisitesFake(provider_route_request)
