from __future__ import annotations

from tuntun_core.services.providers.review import SqlcipherCurrentProviderReviews

pytest_plugins = ("tests.fixtures.provider_egress",)


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
