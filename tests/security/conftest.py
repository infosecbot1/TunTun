import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2]))

from assurance_cases import (
    MigrationWorkspace,
    NetworkInventory,
    SharedAssuranceHarness,
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
