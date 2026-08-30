# tests/contract/test_dependency_direction.py
from __future__ import annotations

import ast
from pathlib import Path


def _package_for(path: Path, root: Path) -> tuple[str, ...]:
    relative = path.relative_to(root).with_suffix("")
    module_parts = ("tuntun_core", *relative.parts)
    return module_parts[:-1]


def _from_import_targets(node: ast.ImportFrom, package: tuple[str, ...]) -> tuple[str, ...]:
    if node.level:
        keep = len(package) - (node.level - 1)
        if keep < 0:
            return ()
        base = package[:keep]
    else:
        base = ()
    if node.module:
        base += tuple(node.module.split("."))
    return tuple(".".join((*base, alias.name)) for alias in node.names)


def _adapter_imports(path: Path, root: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = _package_for(path, root)
    targets: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level == 0 and (
                base == "tuntun_core.adapters" or base.startswith("tuntun_core.adapters.")
            ):
                targets.append(base)
            targets.extend(_from_import_targets(node, package))
    return tuple(
        target
        for target in targets
        if target == "tuntun_core.adapters" or target.startswith("tuntun_core.adapters.")
    )


def test_adapter_import_detector_covers_absolute_and_relative_forms(tmp_path: Path) -> None:
    root = tmp_path / "tuntun_core"
    cases = {
        "domain/absolute.py": "import tuntun_core.adapters.openai\n",
        "services/from_package.py": "from tuntun_core import adapters\n",
        "workflows/from_adapter.py": "from tuntun_core.adapters import openai\n",
        "domain/relative.py": "from .. import adapters\n",
        "services/nested/relative.py": "from ...adapters import openai\n",
    }
    for relative, source in cases.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        assert _adapter_imports(path, root), relative

    allowed = root / "domain" / "allowed.py"
    allowed.write_text(
        'TEXT = "tuntun_core.adapters"\n# import tuntun_core.adapters\n',
        encoding="utf-8",
    )
    assert _adapter_imports(allowed, root) == ()


def test_domain_services_and_workflows_do_not_import_adapters() -> None:
    root = Path("apps/core/src/tuntun_core")
    assert root.is_dir()
    violations: list[str] = []
    for area in ("domain", "services", "workflows"):
        area_root = root / area
        for path in area_root.rglob("*.py") if area_root.is_dir() else ():
            for target in _adapter_imports(path, root):
                violations.append(f"{path}: {target}")
    assert violations == []
