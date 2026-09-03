# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import inspect
import shutil
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from tuntun_contracts.reachy import SafetyReceipt
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.bootstrap.container import ProductionContainer
from tuntun_core.services.budget.catalog import FxRecord, PriceCatalog, PriceRecord
from tuntun_core.services.budget.evidence import BudgetEvidenceService
from tuntun_core.services.providers.review import RuntimeProviderIdentity
from tuntun_core.services.storage_time import utc_storage

from tests.identity_support import StaticTask1IdentityKeyProvider

PROJECT_ROOT = Path(__file__).parents[3]


class _UnusedRouteAuthorizer:
    async def authorize(self, request):
        raise AssertionError(f"unexpected authorization: {request!r}")

    async def consume(self, authorization_id, consumption) -> None:
        raise AssertionError((authorization_id, consumption))


class _ReachyStartupSafety:
    def __init__(self) -> None:
        self.stopped: list[object] = []

    async def stop_all(self, turn_id):
        self.stopped.append(turn_id)
        return SafetyReceipt(
            turn_id=None,
            playback_stopped=True,
            motion_stopped=True,
            buffers_cleared=True,
        )


class _RuntimeProviderIdentities:
    def require_current(self, provider: str) -> RuntimeProviderIdentity:
        if provider != "openai":
            raise RuntimeError("provider_review_not_current")
        return RuntimeProviderIdentity(
            project_id_commitment_sha256="a" * 64,
            credential_kind="project_service_account",
            admin_key_present=False,
        )


_FUTURE_TABLE_SQL = {
    "action_authorities": "CREATE TABLE action_authorities(id TEXT PRIMARY KEY)",
    "memory_authorities": "CREATE TABLE memory_authorities(id TEXT PRIMARY KEY)",
}


def _price_catalog() -> PriceCatalog:
    start = datetime(2026, 8, 1, tzinfo=UTC)
    end = datetime(2026, 9, 26, tzinfo=UTC)
    return PriceCatalog(
        prices=(
            PriceRecord(
                provider="openai",
                model="gpt-5.6-sol",
                category="llm",
                native_currency="USD",
                input_micro_usd_per_million=4_000_000,
                output_micro_usd_per_million=20_000_000,
                audio_micro_usd_per_minute=0,
                web_search_micro_usd_per_call=0,
                primary_accounting_basis="provider_reported_exact",
                missing_evidence_policy="freeze_unknown_overage",
                pricing_version="openai-2026-08-27",
                effective_at=start,
                expires_at=end,
                source_url="https://developers.openai.com/api/docs/models/gpt-5.6-sol",
                source_sha256="d" * 64,
            ),
        ),
        fx=FxRecord(
            micros_sgd_per_usd=1_500_000,
            fx_version="bootstrap-2026-08-27",
            effective_at=start,
            expires_at=end,
            source="owner_policy",
            source_sha256="e" * 64,
        ),
    )


def _budget_evidence(clock) -> BudgetEvidenceService:
    return BudgetEvidenceService(bytes(range(32)), "budget-evidence-v1", clock)


def _provider_defaults_path(tmp_path: Path) -> Path:
    path = tmp_path / f"provider-defaults-{uuid4()}.yaml"
    shutil.copyfile(PROJECT_ROOT / "config/providers/default.yaml", path)
    path.chmod(0o600)
    return path


def _state_root(tmp_path: Path) -> Path:
    path = tmp_path / f"production-state-{uuid4()}"
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _build_production_container(
    *,
    tmp_path: Path,
    async_uow_factory: AsyncUnitOfWorkFactory,
    clock,
    reachy: _ReachyStartupSafety | None = None,
) -> ProductionContainer:
    return ProductionContainer.build(
        configured_state_root=_state_root(tmp_path),
        reachy=_ReachyStartupSafety() if reachy is None else reachy,
        sqlcipher_uow_factory=async_uow_factory,
        task1_identity_key_provider=StaticTask1IdentityKeyProvider(),
        clock=clock,
        route_authorizer=_UnusedRouteAuthorizer(),
        price_catalog=_price_catalog(),
        runtime_provider_identities=_RuntimeProviderIdentities(),
        budget_evidence=_budget_evidence(clock),
        provider_defaults_path=_provider_defaults_path(tmp_path),
    )


def test_production_container_build_requires_explicit_task1_key_provider() -> None:
    parameter = inspect.signature(ProductionContainer.build).parameters[
        "task1_identity_key_provider"
    ]

    assert parameter.default is inspect.Parameter.empty


@pytest.mark.asyncio
async def test_production_container_starts_task1_runtime_and_drains_revocation_before_readiness(
    migrated_sqlcipher_engine,
    clock,
    tmp_path: Path,
) -> None:
    async_uow_factory = AsyncUnitOfWorkFactory(migrated_sqlcipher_engine.engine)
    event_id = uuid4()
    subject_id = uuid4()
    household_id = uuid4()
    reachy = _ReachyStartupSafety()
    with migrated_sqlcipher_engine.engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) "
            "VALUES(?,?,?,?)",
            (
                str(household_id),
                b"household-label",
                "Asia/Singapore",
                utc_storage(clock.now()),
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO subjects "
            "(id,household_id,guardian_id,guardian_generation,profile_class,"
            "encrypted_display_label,encrypted_persona_traits,current_consent_receipt_ids,"
            "active,authority_generation,version,next_reenrollment_reminder_at,"
            "created_at,updated_at,revoked_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(subject_id),
                str(household_id),
                None,
                0,
                "adult",
                b"profile-label-ciphertext-has-enough-bytes",
                None,
                b"[]",
                0,
                3,
                1,
                None,
                utc_storage(clock.now()),
                utc_storage(clock.now()),
                utc_storage(clock.now()),
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO subject_revocation_outbox "
            "(id,event_key,subject_id,new_authority_generation,state,occurred_at,"
            "attempt_count,fencing_token) VALUES (?,?,?,?, 'pending', ?,0,0)",
            (
                str(event_id),
                f"test.revocation.{event_id}",
                str(subject_id),
                4,
                utc_storage(clock.now()),
            ),
        )

    production = _build_production_container(
        tmp_path=tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        reachy=reachy,
    )
    started = False
    try:
        assert production.task1_identity is not None
        assert production.identity_lifecycle is not None
        assert production.readiness_dependencies[0] is production.identity_lifecycle
        with pytest.raises(RuntimeError, match="identity_revocation_runtime_unhealthy"):
            production.identity_lifecycle.require_ready()

        await production.start()
        started = True

        for dependency in production.readiness_dependencies:
            dependency.require_ready()
        with migrated_sqlcipher_engine.engine.connect() as connection:
            state, receipt_id = connection.exec_driver_sql(
                "SELECT state,reconciliation_receipt_id FROM subject_revocation_outbox WHERE id=?",
                (str(event_id),),
            ).one()
        assert state == "completed"
        assert receipt_id is not None
        assert production.task1_identity.revocation_worker.completed_event_ids == (event_id,)
        assert reachy.stopped == [None]
    finally:
        if started:
            await production.stop()
        else:
            production.core_process_lease.release_after_shutdown()
        await async_uow_factory.aclose()


@pytest.mark.asyncio
async def test_production_container_installs_task1_facades_on_foundation_uow_factory(
    migrated_sqlcipher_engine,
    clock,
    tmp_path: Path,
) -> None:
    async_uow_factory = AsyncUnitOfWorkFactory(migrated_sqlcipher_engine.engine)
    production = _build_production_container(
        tmp_path=tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
    )
    try:
        assert production.task1_identity is not None
        assert production.task1_identity.uow_factory is async_uow_factory
        assert production.core.sqlcipher_uow_factory is async_uow_factory
        async with async_uow_factory() as uow:
            for facade_name in (
                "profiles",
                "consent_receipts",
                "guest_disclosure_challenges",
                "guest_session_consents",
                "sessions",
                "event_receipts",
                "subject_revocation_outbox",
                "subject_revocation_effects",
                "provider_calls",
                "budget_reservations",
            ):
                assert hasattr(uow, facade_name), facade_name
            await uow.rollback()

        class LateFacadeFactory:
            def bind(self, uow):
                return uow

        with pytest.raises(RuntimeError, match="registration"):
            async_uow_factory.register_repository_facades({"late_identity": LateFacadeFactory()})
        with pytest.raises(RuntimeError, match="registration"):
            async_uow_factory.register_commit_signal(
                "late_subject_revocation",
                production.task1_identity.revocation_worker,
            )
    finally:
        production.core_process_lease.release_after_shutdown()
        if production.task1_identity is not None and production.task1_identity.uow_factory is not (
            async_uow_factory
        ):
            await production.task1_identity.uow_factory.aclose()
        await async_uow_factory.aclose()


@pytest.mark.parametrize(
    "future_table",
    ("action_authorities", "memory_authorities"),
)
@pytest.mark.asyncio
async def test_production_container_rejects_stale_task1_not_installed_handlers(
    migrated_sqlcipher_engine,
    clock,
    tmp_path: Path,
    future_table: str,
) -> None:
    async_uow_factory = AsyncUnitOfWorkFactory(migrated_sqlcipher_engine.engine)
    with migrated_sqlcipher_engine.engine.begin() as connection:
        connection.exec_driver_sql(_FUTURE_TABLE_SQL[future_table])

    try:
        with pytest.raises(RuntimeError, match="not_installed_authority_handler_stale"):
            _build_production_container(
                tmp_path=tmp_path,
                async_uow_factory=async_uow_factory,
                clock=clock,
            )
    finally:
        await async_uow_factory.aclose()
