# tests/contract/test_dependency_direction.py
from pathlib import Path


def test_domain_services_and_workflows_do_not_import_adapters() -> None:
    root = Path("apps/core/src/tuntun_core")
    violations: list[str] = []
    for area in ("domain", "services", "workflows"):
        for path in (root / area).rglob("*.py") if (root / area).exists() else ():
            if "tuntun_core.adapters" in path.read_text(encoding="utf-8"):
                violations.append(str(path))
    assert violations == []
