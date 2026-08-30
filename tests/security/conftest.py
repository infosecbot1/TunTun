import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2]))

from assurance_cases import (
    MigrationWorkspace,
    NetworkInventory,
    SharedAssuranceHarness,
)
from model_governance_cases import (
    ConcurrentModelCase,
    GovernedModelCase,
    InstalledModel,
    ScriptedReceiptVerifier,
    ScriptedRuntimeAdapter,
)


@pytest.fixture
def shared_assurance_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> SharedAssuranceHarness:
    return SharedAssuranceHarness(tmp_path / "shared", monkeypatch)


@pytest.fixture
def migration_workspace(tmp_path: Path) -> MigrationWorkspace:
    return MigrationWorkspace.create_linear(tmp_path / "migrations", ("0013", "0014", "0015"))


@pytest.fixture
def network_inventory(tmp_path: Path) -> NetworkInventory:
    return NetworkInventory.complete(
        tmp_path / "network",
        listeners=(("tcp", "127.0.0.1", 8787, 4101, "python", "owner_ingress"),),
    )


@pytest.fixture
def governed_model_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GovernedModelCase:
    case = GovernedModelCase.create(tmp_path / "governed-model", monkeypatch)
    try:
        yield case
    finally:
        case.close()


@pytest.fixture
def installed_model(governed_model_case: GovernedModelCase) -> InstalledModel:
    governed_model_case.install()
    return governed_model_case.as_installed_model()


@pytest.fixture
def runtime_adapter() -> ScriptedRuntimeAdapter:
    return ScriptedRuntimeAdapter()


@pytest.fixture
def failing_runtime_adapter() -> ScriptedRuntimeAdapter:
    adapter = ScriptedRuntimeAdapter()
    adapter.fail_at("load_verified_reader", None)
    return adapter


@pytest.fixture
def runtime_receipt_verifier(runtime_adapter: ScriptedRuntimeAdapter) -> ScriptedReceiptVerifier:
    return ScriptedReceiptVerifier.current(
        domain="tuntun.runtime-model-loader-receipt.v1",
        key_generation=1,
        publisher=runtime_adapter,
    )


@pytest.fixture
def concurrent_model_case(governed_model_case: GovernedModelCase) -> ConcurrentModelCase:
    return governed_model_case.concurrent_view()
