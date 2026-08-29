from __future__ import annotations

import ast
import re
import sys
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.assurance_common import (
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        preflight_python_source,
        revalidate_frozen_inventory,
        walk_regular_files,
    )
elif __package__:
    from .assurance_common import (
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        preflight_python_source,
        revalidate_frozen_inventory,
        walk_regular_files,
    )
else:
    from assurance_common import (
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        preflight_python_source,
        revalidate_frozen_inventory,
        walk_regular_files,
    )

TOOL = "import-boundaries"
MAX_AST_NODES = 200_000
DOMAIN = re.compile(r"[a-z][a-z0-9_]{0,63}")
DISTRIBUTION_IMPORT_ALIASES: Mapping[str, frozenset[str]] = MappingProxyType(
    {"pyyaml": frozenset({"yaml"})}
)


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="check_import_boundaries.py")
    parser.add_argument("--root", default=".")
    parser.add_argument("--domain")
    parser.add_argument("--all", action="store_true")
    return parser


def _module_name(path: Path, source_root: Path) -> str:
    relative = path.relative_to(source_root).with_suffix("")
    parts = relative.parts[:-1] if relative.name == "__init__" else relative.parts
    return ".".join(parts)


def _declared_dependencies(document: Mapping[str, object]) -> set[str]:
    project = document.get("project")
    if not isinstance(project, Mapping):
        return set()
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list):
        return set()
    result = set()
    for dependency in dependencies:
        if isinstance(dependency, str):
            name = re.split(r"[<>=!~;\[]", dependency, maxsplit=1)[0]
            normalized = name.strip().replace("-", "_").lower()
            result.add(normalized)
            result.update(DISTRIBUTION_IMPORT_ALIASES.get(normalized, ()))
    return result


def _source_roots(pyproject: Path, document: Mapping[str, object]) -> tuple[Path, ...]:
    tool = document.get("tool")
    configured: object | None = None
    if isinstance(tool, Mapping):
        assurance = tool.get("tuntun-assurance")
        if isinstance(assurance, Mapping):
            configured = assurance.get("src-roots")
    values = configured if isinstance(configured, list) else ["src"]
    roots: list[Path] = []
    for value in values:
        if not isinstance(value, str):
            raise AssuranceInputError(pyproject, "src-root-invalid")
        relative = Path(value)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise AssuranceInputError(pyproject, "src-root-invalid", value)
        roots.append(pyproject.parent / relative)
    return tuple(roots)


def _domain_of(module: str) -> str | None:
    parts = module.split(".")
    if "domain" in parts:
        index = parts.index("domain")
        return parts[index + 1] if index + 1 < len(parts) else None
    if parts and parts[0] in {"vision", "identity", "memory", "conversation"}:
        return parts[0]
    return None


def _resolve_relative(module: str, is_package: bool, level: int, target: str | None) -> str | None:
    package = module if is_package else module.rpartition(".")[0]
    parts = package.split(".") if package else []
    if level < 1 or level > len(parts) + 1:
        return None
    base = parts[: len(parts) - level + 1]
    if target:
        base.extend(target.split("."))
    return ".".join(base)


def _imports(
    module: ast.Module, current: str, is_package: bool, modules: set[str]
) -> Iterable[tuple[str | None, str]]:
    importlib_aliases = {"importlib"}
    import_module_aliases: set[str] = set()
    builtins_aliases: set[str] = set()
    builtin_import_aliases = {"__import__"}
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            importlib_aliases.update(
                alias.asname or alias.name for alias in node.names if alias.name == "importlib"
            )
            builtins_aliases.update(
                alias.asname or alias.name for alias in node.names if alias.name == "builtins"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            import_module_aliases.update(
                alias.asname or alias.name for alias in node.names if alias.name == "import_module"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "builtins":
            builtin_import_aliases.update(
                alias.asname or alias.name for alias in node.names if alias.name == "__import__"
            )
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, "import"
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _resolve_relative(current, is_package, node.level, node.module)
                kind = "relative"
            elif node.module is not None:
                base = node.module
                kind = "from"
            else:
                base = None
                kind = "relative"
            if base is None:
                yield None, kind
                continue
            for alias in node.names:
                candidate = f"{base}.{alias.name}" if alias.name != "*" else base
                yield candidate if _local_resolution(candidate, modules) else base, kind
        elif isinstance(node, ast.Call):
            dynamic = (
                (
                    isinstance(node.func, ast.Name)
                    and node.func.id in (builtin_import_aliases | import_module_aliases)
                )
                or (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in importlib_aliases
                    and node.func.attr == "import_module"
                )
                or (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in builtins_aliases
                    and node.func.attr == "__import__"
                )
            )
            if dynamic:
                if (
                    not node.args
                    or not isinstance(node.args[0], ast.Constant)
                    or not isinstance(node.args[0].value, str)
                ):
                    yield None, "dynamic-import-nonliteral"
                else:
                    yield node.args[0].value, "dynamic"


def _local_resolution(target: str, modules: set[str]) -> bool:
    return any(module == target or module.startswith(target + ".") for module in modules)


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        if (arguments.domain is None) == (not arguments.all):
            raise ValueError("exactly one of --domain or --all is required")
        if arguments.domain is not None and DOMAIN.fullmatch(arguments.domain) is None:
            raise ValueError("domain must be canonical")
        root = lexical_path(arguments.root)
        frozen = tuple(
            walk_regular_files(
                (root,), max_files=MAX_WALK_FILES, max_total_bytes=MAX_WALK_TOTAL_BYTES
            )
        )
        raw_by_path = {item.path: item.raw for item in frozen}
        pyprojects = sorted(path for path in raw_by_path if path.name == "pyproject.toml")
        if not pyprojects:
            raise AssuranceInputError(root, "pyproject-inventory-missing")
        source_roots: list[Path] = []
        dependencies: set[str] = set()
        for pyproject in pyprojects:
            raw = raw_by_path[pyproject]
            try:
                document = tomllib.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
                raise AssuranceInputError(pyproject, "pyproject-parse-failed") from error
            source_roots.extend(_source_roots(pyproject, document))
            dependencies.update(_declared_dependencies(document))
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )

    module_paths: dict[str, tuple[Path, Path]] = {}
    for source_root in source_roots:
        for path in raw_by_path:
            try:
                path.relative_to(source_root)
            except ValueError:
                continue
            if path.suffix != ".py":
                continue
            module = _module_name(path, source_root)
            if not module or module in module_paths:
                return AssuranceResult(
                    TOOL,
                    False,
                    (AssuranceFinding(path, "module-inventory-ambiguous", module),),
                )
            module_paths[module] = (path, source_root)
    if not module_paths:
        return AssuranceResult(TOOL, False, (AssuranceFinding(root, "source-inventory-missing"),))

    modules = set(module_paths)
    local_tops = {module.split(".", 1)[0] for module in modules}
    findings: list[AssuranceFinding] = []
    for module_name, (path, _source_root) in module_paths.items():
        source_domain = _domain_of(module_name)
        if (
            arguments.domain is not None
            and source_domain != arguments.domain
            and arguments.domain not in module_name.split(".")
        ):
            continue
        raw = raw_by_path[path]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return AssuranceResult(TOOL, False, (AssuranceFinding(path, "module-parse-failed"),))
        try:
            preflight_python_source(text)
        except ValueError as error:
            return AssuranceResult(TOOL, False, (AssuranceFinding(path, str(error)),))
        try:
            syntax = ast.parse(text, filename=str(path))
        except (SyntaxError, RecursionError):
            return AssuranceResult(TOOL, False, (AssuranceFinding(path, "module-parse-failed"),))
        if sum(1 for _ in ast.walk(syntax)) > MAX_AST_NODES:
            return AssuranceResult(TOOL, False, (AssuranceFinding(path, "ast-node-limit"),))
        is_package = path.name == "__init__.py"
        for target, kind in _imports(syntax, module_name, is_package, modules):
            if target is None:
                findings.append(AssuranceFinding(path, kind, module_name))
                continue
            top = target.split(".", 1)[0]
            local = _local_resolution(target, modules)
            if kind == "relative" and not local:
                findings.append(AssuranceFinding(path, "unresolved-relative-import", target))
                continue
            if top in local_tops and not local:
                findings.append(AssuranceFinding(path, "unresolved-local-import", target))
                continue
            if not local and top not in sys.stdlib_module_names and top.lower() not in dependencies:
                findings.append(AssuranceFinding(path, "undeclared-third-party-import", target))
                continue
            target_parts = target.split(".")
            source_parts = module_name.split(".")
            if (
                local
                and "adapters" in target_parts
                and any(
                    part in {"domain", "services", "service", "workflow", "workflows"}
                    for part in source_parts
                )
            ):
                findings.append(AssuranceFinding(path, "adapter-import-boundary", target))
            target_domain = _domain_of(target)
            private_target = any(part.startswith("_") or part == "private" for part in target_parts)
            if (
                local
                and source_domain is not None
                and target_domain is not None
                and source_domain != target_domain
                and private_target
            ):
                findings.append(AssuranceFinding(path, "cross-domain-private-import", target))
    try:
        revalidate_frozen_inventory(
            (root,),
            frozen,
            max_files=MAX_WALK_FILES,
            max_total_bytes=MAX_WALK_TOTAL_BYTES,
        )
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
