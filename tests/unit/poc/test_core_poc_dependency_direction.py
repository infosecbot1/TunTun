from __future__ import annotations

import ast
from pathlib import Path

from tuntun_contracts.base import ContractModel
from tuntun_core.services.poc.ports import CapturedTurn

SERVICE_ROOT = Path("apps/core/src/tuntun_core/services/poc")


def _imports(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
            imported.extend(alias.name for alias in node.names)
    return tuple(imported)


def test_core_poc_services_do_not_depend_on_adapters_edge_or_production_cloud_gates() -> None:
    forbidden_names = {
        "AttemptRunner",
        "BudgetPort",
        "RouteAuthorizationRequest",
        "RouteAuthorizerPort",
    }
    violations: list[str] = []

    for path in sorted(SERVICE_ROOT.glob("*.py")):
        imports = _imports(path)
        for imported in imports:
            if (
                imported == "tuntun_core.adapters"
                or imported.startswith("tuntun_core.adapters.")
                or imported == "tuntun_edge"
                or imported.startswith("tuntun_edge.")
                or imported in forbidden_names
            ):
                violations.append(f"{path}:{imported}")

    assert violations == []


def test_core_poc_foundation_has_no_file_network_or_logging_side_effect_imports() -> None:
    forbidden_roots = {
        "aiohttp",
        "httpx",
        "logging",
        "os",
        "pathlib",
        "requests",
        "socket",
        "structlog",
        "subprocess",
    }
    violations: list[str] = []

    for path in sorted(SERVICE_ROOT.glob("*.py")):
        for imported in _imports(path):
            if imported.split(".", 1)[0] in forbidden_roots:
                violations.append(f"{path}:{imported}")

    assert violations == []


def test_captured_turn_is_deliberately_not_a_serializable_contract_model() -> None:
    assert not issubclass(CapturedTurn, ContractModel)
