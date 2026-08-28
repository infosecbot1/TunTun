import importlib

import pytest


@pytest.mark.parametrize(
    "package_name",
    ["tuntun_core", "tuntun_edge", "tuntun_contracts", "tuntun_testing"],
)
def test_workspace_package_exposes_version(package_name: str) -> None:
    package = importlib.import_module(package_name)
    assert package.__version__ == "0.1.0.dev0"
