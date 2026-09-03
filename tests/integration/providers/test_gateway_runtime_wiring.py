from __future__ import annotations

import inspect
import shutil
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from tuntun_contracts.budget import BudgetReservationRequest, LlmUsageUnits
from tuntun_core.services.providers.review import SqlcipherCurrentProviderReviews

from tests.identity_support import StaticTask1IdentityKeyProvider

pytest_plugins = ("tests.fixtures.provider_egress",)

PROJECT_ROOT = Path(__file__).parents[3]


class _UnusedRouteAuthorizer:
    async def authorize(self, request):
        raise AssertionError(f"unexpected authorization: {request!r}")

    async def consume(self, authorization_id, consumption) -> None:
        raise AssertionError((authorization_id, consumption))


def _provider_defaults_document(*, soft_limit: int, hard_limit: int, expiry_seconds: int):
    from tuntun_core.services.providers.defaults import ProviderDefaultsDocumentV1

    return ProviderDefaultsDocumentV1.model_validate(
        {
            "schema_version": "tuntun.provider-defaults.v1",
            "budget": {
                "timezone": "Asia/Singapore",
                "soft_limit_micros_sgd": soft_limit,
                "hard_limit_micros_sgd": hard_limit,
                "reservation_expiry_seconds": expiry_seconds,
            },
            "providers": {
                "openai": {
                    "sdk_retries": 0,
                    "telemetry_enabled": False,
                    "dedicated_project_required": True,
                    "provider_hard_limit": {
                        "currency": "USD",
                        "interval": "provider_month",
                        "maximum_threshold_micros_usd": 100_000_000,
                        "enforcement_status": "enforcing",
                        "runtime_admin_key_forbidden": True,
                    },
                },
            },
        },
        strict=True,
    )


def test_production_composition_requires_explicit_provider_defaults_contract() -> None:
    from tuntun_core.bootstrap.container import CoreContainer, ProductionContainer

    core_signature = inspect.signature(CoreContainer)
    assert "provider_defaults" in core_signature.parameters
    assert "hard_limit" not in core_signature.parameters
    assert "soft_limit" not in core_signature.parameters

    build_signature = inspect.signature(ProductionContainer.build)
    provider_defaults_path = build_signature.parameters["provider_defaults_path"]
    assert provider_defaults_path.default is inspect.Parameter.empty
    assert "hard_limit" not in build_signature.parameters
    assert "soft_limit" not in build_signature.parameters


def test_runtime_gateway_uses_exact_budget_evidence_services(
    production_core_container,
) -> None:
    core_container = production_core_container
    assert not hasattr(core_container, "build_provider_gateway")
    assert core_container.provider_gateway.calls is core_container.provider_call_repository
    assert core_container.provider_gateway._evidence is core_container.budget_evidence
    assert core_container.provider_call_repository._evidence is core_container.budget_evidence
    assert core_container.provider_gateway._budget is core_container.budget_guard


def test_production_container_constructs_sqlcipher_provider_review_gate(
    production_container,
) -> None:
    assert type(production_container.core.budget_guard._reviews) is SqlcipherCurrentProviderReviews


@pytest.mark.asyncio
async def test_core_container_uses_provider_defaults_for_budget_limits_and_expiry(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
) -> None:
    from tuntun_core.bootstrap.container import CoreContainer

    provider_defaults = _provider_defaults_document(
        soft_limit=5,
        hard_limit=10,
        expiry_seconds=45,
    )
    container = CoreContainer(
        sqlcipher_uow_factory=async_uow_factory,
        clock=clock,
        route_authorizer=_UnusedRouteAuthorizer(),
        price_catalog=catalog,
        provider_reviews=provider_reviews,
        budget_evidence=budget_evidence,
        provider_defaults=provider_defaults,
    )
    household_id, turn_id = uuid4(), uuid4()

    first = await container.budget_guard.reserve(
        BudgetReservationRequest(
            household_id=household_id,
            turn_id=turn_id,
            request_id=uuid4(),
            attempt_id=uuid4(),
            provider="openai",
            model="gpt-5.6-sol",
            category="llm",
            usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
            month_key="2026-08",
        )
    )
    second = await container.budget_guard.reserve(
        BudgetReservationRequest(
            household_id=household_id,
            turn_id=turn_id,
            request_id=uuid4(),
            attempt_id=uuid4(),
            provider="openai",
            model="gpt-5.6-sol",
            category="llm",
            usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
            month_key="2026-08",
        )
    )

    assert first.expires_at == clock.now() + timedelta(seconds=45)
    assert (first.amount_micros_sgd, first.outcome, second.outcome) == (
        6,
        "allow_soft_warning",
        "deny_hard_limit",
    )


def test_production_container_build_loads_explicit_provider_defaults_path(
    monkeypatch: pytest.MonkeyPatch,
    async_uow_factory,
    clock,
    catalog,
    runtime_provider_identities,
    budget_evidence,
    tmp_path,
) -> None:
    from tuntun_core.bootstrap import container as container_module

    defaults_path = tmp_path / "provider-defaults.yaml"
    loaded_defaults = _provider_defaults_document(
        soft_limit=5,
        hard_limit=10,
        expiry_seconds=45,
    )
    calls: list[Path] = []

    def fake_load_provider_defaults(path: Path):
        calls.append(path)
        return loaded_defaults

    monkeypatch.setattr(
        container_module,
        "load_provider_defaults",
        fake_load_provider_defaults,
    )
    state_root = tmp_path / "production-state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)

    production = container_module.ProductionContainer.build(
        configured_state_root=state_root,
        reachy=object(),
        sqlcipher_uow_factory=async_uow_factory,
        task1_identity_key_provider=StaticTask1IdentityKeyProvider(),
        clock=clock,
        route_authorizer=_UnusedRouteAuthorizer(),
        price_catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        provider_defaults_path=defaults_path,
    )
    try:
        assert calls == [defaults_path]
        assert production.core.budget_guard._hard_limit == 10
        assert production.core.budget_guard._soft_limit == 5
        assert production.core.budget_guard._reservation_expiry == timedelta(seconds=45)
    finally:
        production.core_process_lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_static_provider_defaults_do_not_satisfy_missing_provider_review(
    async_uow_factory,
    clock,
    catalog,
    runtime_provider_identities,
    budget_evidence,
    tmp_path,
) -> None:
    from tuntun_core.bootstrap.container import ProductionContainer

    state_root = tmp_path / "production-state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    defaults_path = tmp_path / "provider-defaults.yaml"
    shutil.copyfile(PROJECT_ROOT / "config/providers/default.yaml", defaults_path)
    defaults_path.chmod(0o600)
    production = ProductionContainer.build(
        configured_state_root=state_root,
        reachy=object(),
        sqlcipher_uow_factory=async_uow_factory,
        task1_identity_key_provider=StaticTask1IdentityKeyProvider(),
        clock=clock,
        route_authorizer=_UnusedRouteAuthorizer(),
        price_catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        provider_defaults_path=defaults_path,
    )
    try:
        with pytest.raises(PermissionError, match="provider_review_not_current"):
            await production.core.budget_guard.reserve(
                BudgetReservationRequest(
                    household_id=uuid4(),
                    turn_id=uuid4(),
                    request_id=uuid4(),
                    attempt_id=uuid4(),
                    provider="openai",
                    model="gpt-5.6-sol",
                    category="llm",
                    usage_ceiling=LlmUsageUnits(category="llm", input_tokens=1, output_tokens=0),
                    month_key="2026-08",
                )
            )
    finally:
        production.core_process_lease.release_after_shutdown()
