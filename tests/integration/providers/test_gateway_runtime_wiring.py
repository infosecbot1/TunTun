# tests/integration/providers/test_gateway_runtime_wiring.py
from tuntun_core.services.providers.call_repository import ProviderCallRepository
from tuntun_core.services.providers.redaction_repository import RedactionReceiptRepository

pytest_plugins = ("tests.fixtures.provider_egress",)


def test_task04_container_requires_explicit_budget_injection_before_gateway_activation(
    core_container, budget_port_fake
):
    assert isinstance(core_container.provider_call_repository, ProviderCallRepository)
    assert isinstance(core_container.redaction_receipt_repository, RedactionReceiptRepository)
    assert (
        core_container.provider_call_repository.uow_factory is core_container.sqlcipher_uow_factory
    )
    assert not hasattr(core_container, "provider_gateway")
    gateway = core_container.build_provider_gateway(budget_port_fake)
    assert gateway.calls is core_container.provider_call_repository
