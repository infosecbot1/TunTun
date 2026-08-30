#!/usr/bin/env python3
"""Fail-closed integrity checks for the Conversation/Reachy execution plan."""

from __future__ import annotations

import argparse
import ast
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

import yaml

try:
    from scripts.materialize_conversation_plan import (
        MaterializationError,
        PlanDocument,
        Snippet,
        foundation_files_from_ref,
        materialize_document,
        parse_plan,
    )
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from materialize_conversation_plan import (  # type: ignore[import-not-found,no-redef]
        MaterializationError,
        PlanDocument,
        Snippet,
        foundation_files_from_ref,
        materialize_document,
        parse_plan,
    )


FOUNDATION_MIGRATION_PATHS = (
    "apps/core/src/tuntun_core/adapters/sqlcipher/connection.py",
    "apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py",
    "tests/integration/storage/test_migrations.py",
)
PYTEST_FIXTURES = {
    "cache",
    "capfd",
    "capfdbinary",
    "caplog",
    "capsys",
    "capsysbinary",
    "doctest_namespace",
    "monkeypatch",
    "pytestconfig",
    "record_property",
    "record_testsuite_property",
    "record_xml_attribute",
    "recwarn",
    "request",
    "tmp_path",
    "tmp_path_factory",
    "tmpdir",
    "tmpdir_factory",
}
MODEL_KEYS = {
    "id",
    "revision",
    "license",
    "provenance",
    "redistribution",
    "approved_purpose",
    "runtime",
    "architecture",
    "input_contract",
    "output_contract",
    "benchmark_gate",
    "review_date",
    "files",
}
MODEL_FILE_KEYS = {"path", "size", "sha256", "url"}
NON_AUTHORIZATION_MARKERS = {
    "asyncio",
    "filterwarnings",
    "parametrize",
    "skip",
    "skipif",
    "usefixtures",
}


def approved_skip_marker_names(marker_names: tuple[str, ...]) -> bool:
    """A skipped test must be in exactly one explicit external-evidence lane."""

    return marker_names in (("reachy_hardware",), ("live_cloud",))


def validate_model_manifest_bytes(content: bytes) -> list[str]:
    """Validate the Foundation-owned closed manifest key surface."""

    errors: list[str] = []
    try:
        document = yaml.safe_load(content)
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        return [f"invalid model manifest YAML: {error}"]
    if type(document) is not dict or set(document) != {"schema_version", "models"}:
        return ["model manifest root keys are not closed"]
    if document.get("schema_version") != "1.0" or type(document.get("models")) is not list:
        return ["model manifest version/models shape is invalid"]
    for model_index, model in enumerate(document["models"]):
        if type(model) is not dict:
            errors.append(f"model {model_index} is not an object")
            continue
        if set(model) != MODEL_KEYS:
            errors.append(
                f"model {model_index} model keys are not closed: {sorted(set(model) ^ MODEL_KEYS)}"
            )
        files = model.get("files")
        if type(files) is not list:
            errors.append(f"model {model_index} files is not a list")
            continue
        for file_index, file_record in enumerate(files):
            if type(file_record) is not dict or set(file_record) != MODEL_FILE_KEYS:
                actual = set(file_record) if type(file_record) is dict else set()
                errors.append(
                    f"model {model_index} file {file_index} file keys are not closed: "
                    f"{sorted(actual ^ MODEL_FILE_KEYS)}"
                )
    return errors


def _python_tree(snippet: Snippet, errors: list[str]) -> ast.Module | None:
    if snippet.language not in {"python", "py"} and not snippet.path.endswith(".py"):
        return None
    try:
        return ast.parse(snippet.body.decode(), filename=snippet.path)
    except (SyntaxError, UnicodeDecodeError) as error:
        errors.append(
            f"Task {snippet.task:02d} {snippet.path}: Python snippet is invalid: {error}"
        )
        return None


def _module_for_path(path: str) -> str | None:
    candidates = (
        "apps/core/src/",
        "apps/edge/src/",
        "packages/contracts/src/",
        "packages/testing/src/",
    )
    for prefix in candidates:
        if path.startswith(prefix) and path.endswith(".py"):
            module = path.removeprefix(prefix).removesuffix(".py").replace("/", ".")
            return module.removesuffix(".__init__")
    if path.startswith("evals/") and path.endswith(".py"):
        return path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
    if path.endswith(".py") and not path.startswith("tests/"):
        return path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
    return None


def _imported_modules(tree: ast.Module) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            result.add(node.module)
            result.update(
                f"{node.module}.{alias.name}"
                for alias in node.names
                if alias.name != "*"
            )
    return result


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _decorator_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _is_fixture(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        _decorator_name(decorator) in {"pytest.fixture", "fixture"}
        for decorator in function.decorator_list
    )


def _parametrized_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if _decorator_name(decorator.func) != "pytest.mark.parametrize" or not decorator.args:
            continue
        first = decorator.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            names.update(part.strip() for part in first.value.split(","))
        elif isinstance(first, (ast.Tuple, ast.List)):
            names.update(
                element.value
                for element in first.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            )
    return names


def _marker_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    names = []
    for decorator in function.decorator_list:
        name = _decorator_name(decorator)
        if name.startswith("pytest.mark."):
            marker = name.removeprefix("pytest.mark.")
            if marker not in NON_AUTHORIZATION_MARKERS:
                names.append(marker)
    return tuple(sorted(names))


def _has_pytest_skip(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and _decorator_name(node.func) == "pytest.skip":
            return True
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            and node is not function
        ):
            continue
    return False


def _has_skip_decorator(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        _decorator_name(decorator) in {"pytest.mark.skip", "pytest.mark.skipif"}
        for decorator in function.decorator_list
    )


def _fixture_placeholder_reason(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    if not function.body or all(isinstance(statement, ast.Pass) for statement in function.body):
        return "empty"
    returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    if not returns or all(node.value is None for node in returns):
        return "empty"
    for returned in returns:
        value = returned.value
        if not isinstance(value, ast.Call):
            continue
        if _decorator_name(value.func) != "SimpleNamespace":
            continue
        if not value.args and not value.keywords:
            return "empty namespace"
        keys = {keyword.arg for keyword in value.keywords}
        if not value.args and keys <= {"fixture_name", "name"}:
            return "name-only namespace"
    return None


def _validate_path_parity(document: PlanDocument, errors: list[str]) -> None:
    for task in document.tasks:
        declared = {declaration.path for declaration in task.declarations}
        staged = set(task.staged_paths)
        snippets = {snippet.path for snippet in task.snippets}
        if declared != staged:
            errors.append(
                f"Task {task.number:02d}: declared/staged path mismatch "
                f"missing={sorted(declared - staged)} extra={sorted(staged - declared)}"
            )
        if declared != snippets:
            errors.append(
                f"Task {task.number:02d}: declared/snippet path mismatch "
                f"missing={sorted(declared - snippets)} extra={sorted(snippets - declared)}"
            )


def _validate_dependencies(document: PlanDocument, errors: list[str]) -> None:
    for task in document.tasks:
        if 3 <= task.number <= 16 and "Foundation Task 13" not in task.depends_on:
            errors.append(
                f"Task {task.number:02d} must depend on accepted Foundation Task 13"
            )


def _validate_foundation(
    foundation_files: dict[str, bytes], errors: list[str], *, required: bool
) -> None:
    if not required:
        return
    for path in FOUNDATION_MIGRATION_PATHS:
        content = foundation_files.get(path)
        if content is None:
            errors.append(f"Foundation Task 13 capability missing: {path}")
            continue
        if not content.strip():
            errors.append(f"Foundation Task 13 capability is empty: {path}")
    connection = foundation_files.get(FOUNDATION_MIGRATION_PATHS[0], b"").lower()
    if connection and b"sqlcipher" not in connection:
        errors.append("Foundation Task 13 SQLCipher engine capability is not evidenced")
    migrations = foundation_files.get(FOUNDATION_MIGRATION_PATHS[1], b"").lower()
    if migrations and b"migration" not in migrations:
        errors.append("Foundation Task 13 migration runner capability is not evidenced")
    tests = foundation_files.get(FOUNDATION_MIGRATION_PATHS[2], b"").lower()
    if tests and (b"migration" not in tests or b"upgrade" not in tests):
        errors.append("Foundation Task 13 migration integration test lacks upgrade coverage")


def _validate_import_ownership(
    document: PlanDocument, foundation_files: dict[str, bytes], errors: list[str]
) -> None:
    owners: dict[str, int] = {}
    for path in foundation_files:
        module = _module_for_path(path)
        if module:
            owners[module] = 0
    for task in document.tasks:
        for declaration in task.declarations:
            if declaration.kind not in {"Create", "Test"}:
                continue
            module = _module_for_path(declaration.path)
            if module:
                owners.setdefault(module, task.number)
    for task in document.tasks:
        for snippet in task.snippets:
            tree = _python_tree(snippet, errors)
            if tree is None:
                continue
            for imported in _imported_modules(tree):
                matches = [
                    (module, owner)
                    for module, owner in owners.items()
                    if imported == module or imported.startswith(module + ".")
                ]
                if not matches:
                    continue
                _, owner = max(matches, key=lambda item: len(item[0]))
                if owner > task.number:
                    errors.append(
                        f"Task {task.number:02d} {snippet.path}: forward import {imported} "
                        f"is owned by Task {owner:02d}"
                    )


def _validate_fixtures_and_skips(document: PlanDocument, errors: list[str]) -> None:
    producers: Counter[str] = Counter()
    consumers: list[tuple[str, str]] = []
    for task in document.tasks:
        for snippet in task.snippets:
            tree = _python_tree(snippet, errors)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == "_NAMES":
                    errors.append(
                        f"Task {task.number:02d} {snippet.path}: "
                        "dynamic fixture name table is forbidden"
                    )
                    break
            for function in (
                node
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                if _is_fixture(function):
                    producers[function.name] += 1
                    reason = _fixture_placeholder_reason(function)
                    if reason:
                        errors.append(
                            f"Task {task.number:02d} {snippet.path}: fixture {function.name} "
                            f"is a placeholder ({reason})"
                        )
                if function.name.startswith("test_") and snippet.path.startswith("tests/"):
                    parametrized = _parametrized_names(function)
                    arguments = (
                        *function.args.posonlyargs,
                        *function.args.args,
                        *function.args.kwonlyargs,
                    )
                    for argument in arguments:
                        if argument.arg not in PYTEST_FIXTURES | parametrized | {"self", "cls"}:
                            consumers.append((argument.arg, snippet.path))
                if _has_pytest_skip(function) or _has_skip_decorator(function):
                    markers = _marker_names(function)
                    if _is_fixture(function) or not approved_skip_marker_names(markers):
                        errors.append(
                            f"Task {task.number:02d} {snippet.path}:{function.name}: "
                            "unapproved pytest skip"
                        )
    for name, path in consumers:
        count = producers[name]
        if count != 1:
            errors.append(f"{path}: fixture {name} has {count} explicit producers")


def _validate_model_and_eval_contracts(document: PlanDocument, errors: list[str]) -> None:
    by_number = {task.number: task for task in document.tasks}
    task_12 = by_number.get(12)
    if task_12 is not None:
        declared = {declaration.path for declaration in task_12.declarations}
        for path in (
            "models/manifest.yaml",
            "apps/core/src/tuntun_core/resources/model-manifest.yaml",
        ):
            if path not in declared:
                errors.append(f"Task 12 must declare and stage {path}")
        offline_test_path = "tests/unit/edge/test_wake_model_offline.py"
        offline_source = next(
            (
                snippet.body.decode(errors="replace")
                for snippet in task_12.snippets
                if snippet.path == offline_test_path
            ),
            "",
        )
        if offline_test_path not in declared or not all(
            token in offline_source
            for token in (
                'monkeypatch.setattr(socket, "socket"',
                'monkeypatch.setattr(socket, "getaddrinfo"',
                "activate",
                "process",
            )
        ):
            errors.append(
                "Task 12 offline wake-model test must block sockets/DNS during activation/inference"
            )
        manifest_snippets = {
            snippet.path: snippet.body
            for snippet in task_12.snippets
            if snippet.path
            in {
                "models/manifest.yaml",
                "apps/core/src/tuntun_core/resources/model-manifest.yaml",
            }
        }
        if len(manifest_snippets) == 2:
            values = tuple(manifest_snippets.values())
            if values[0] != values[1]:
                errors.append("Task 12 repository and packaged manifests are not byte identical")
            errors.extend(
                f"Task 12 {error}"
                for error in validate_model_manifest_bytes(values[0])
            )
        else:
            errors.append("Task 12 must contain two literal byte-identical manifest snippets")
        task_text = task_12.raw_text
        if "runtime_download" in task_text:
            errors.append("Task 12 model manifest contains forbidden key runtime_download")
        benchmark = next(
            (
                snippet.body.decode(errors="replace")
                for snippet in task_12.snippets
                if snippet.path == "tests/hardware/bench_wakeword.py"
            ),
            "",
        )
        for token in (
            "StreamingAudioConverter",
            "WakeDetector",
            "1280",
            "process_time",
            "boot_uuid",
            "inference_count",
            "drop_count",
            "/venvs/apps_venv/bin/python3",
        ):
            if token not in benchmark:
                errors.append(f"Task 12 wake benchmark missing required binding: {token}")
        if "CM4" in benchmark or "^" in benchmark:
            errors.append("Task 12 wake benchmark contains guessed CM4/XOR evidence")
    task_15 = by_number.get(15)
    if task_15 is not None:
        declarations = {declaration.path for declaration in task_15.declarations}
        generator = "evals/generate_bilingual_report_schema.py"
        if generator not in declarations:
            errors.append(f"Task 15 must own {generator}")
        generator_source = next(
            (
                snippet.body.decode(errors="replace")
                for snippet in task_15.snippets
                if snippet.path == generator
            ),
            "",
        )
        for token in (
            "BilingualScoreReportV1.model_json_schema()",
            '"$id"',
            "sort_keys=True",
            "separators=(\",\", \":\")",
        ):
            if token not in generator_source:
                errors.append(f"Task 15 schema generator missing canonical binding: {token}")


def validate_plan_document(
    document: PlanDocument,
    *,
    foundation_files: dict[str, bytes],
    require_foundation_task_13: bool = False,
) -> list[str]:
    """Return every independently actionable plan-integrity error."""

    errors: list[str] = []
    _validate_path_parity(document, errors)
    _validate_dependencies(document, errors)
    _validate_foundation(foundation_files, errors, required=require_foundation_task_13)
    _validate_import_ownership(document, foundation_files, errors)
    _validate_fixtures_and_skips(document, errors)
    _validate_model_and_eval_contracts(document, errors)
    try:
        materialize_document(document, foundation_files=foundation_files)
    except MaterializationError as error:
        errors.append(f"materialization failed: {error}")
    return list(dict.fromkeys(errors))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--foundation-ref", required=True)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--plan",
        type=Path,
        default=Path(
            "docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    root = args.repository_root.resolve()
    plan_path = args.plan if args.plan.is_absolute() else root / args.plan
    foundation = foundation_files_from_ref(root, args.foundation_ref)
    errors = validate_plan_document(
        parse_plan(plan_path),
        foundation_files=foundation,
        require_foundation_task_13=True,
    )
    if errors:
        print(f"conversation plan integrity: FAIL ({len(errors)} errors)")
        for error in errors:
            print(f"- {error}")
        return 1
    print("conversation plan integrity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
