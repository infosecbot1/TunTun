#!/usr/bin/env python3
"""Deterministically materialize the Conversation/Reachy execution plan.

The plan is executable documentation: every fenced file body is applied in task
order to an explicit Foundation git ref.  This module deliberately has no
knowledge of a developer worktree or branch name.
"""

from __future__ import annotations

import argparse
import ast
import configparser
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

import yaml

TASK_HEADING = re.compile(r"^### Task (?P<number>\d{2}):(?P<title>.*)$", re.MULTILINE)
DECLARATION = re.compile(
    r"^- (?P<kind>Create|Modify|Test): `(?P<path>[^`]+)`(?: .*)?$", re.MULTILINE
)
DEPENDENCY = re.compile(r"^\*\*Depends on:\*\* (?P<value>.+)$", re.MULTILINE)
GENERATOR = re.compile(
    r"^- Generate `(?P<name>[a-z0-9][a-z0-9-]{0,63})`: "
    r"`(?P<command>[^`]+)` -> `(?P<output>[^`]+)`$",
    re.MULTILINE,
)
STEP_HEADING = re.compile(
    r"^- \[ \] \*\*(?P<label>Step [^*]+)\*\*.*$", re.MULTILINE | re.IGNORECASE
)
RUN_COMMAND = re.compile(r"^Run(?: on [^:]+)?: `(?P<command>[^`]+)`", re.MULTILINE)
FENCE = re.compile(
    r"^```(?P<language>[^\n]*)\n(?P<body>.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL
)
DIRECTIVE = re.compile(
    r"^# materializer: (?P<operation>append|replace-file|replace-symbol [A-Za-z_]\w*)$"
)
COMMENT_HEADER = re.compile(r"^# (?P<header>.+?)\s*$")
MARKDOWN_HEADER = re.compile(r"^<!--\s*(?P<header>.+?)\s*-->\s*$")
PATH_TOKEN = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
APPEND_WORDS = ("append", "addition", "continued", "extension")
STRUCTURED_SUFFIXES = {".json", ".toml", ".yaml", ".yml"}


class PlanParseError(ValueError):
    """The Markdown plan cannot be parsed without guessing."""


class MaterializationError(ValueError):
    """The plan cannot be materialized truthfully."""


@dataclass(frozen=True)
class Declaration:
    kind: str
    path: str


@dataclass(frozen=True)
class Snippet:
    task: int
    language: str
    path: str
    qualifier: str
    operation: str | None
    body: bytes
    ordinal: int


@dataclass(frozen=True)
class DeterministicGenerator:
    name: str
    argv: tuple[str, ...]
    entry_point: str
    output: str


@dataclass(frozen=True)
class _GeneratorRun:
    returncode: int
    diagnostic: bytes
    output_exceeded: bool


@dataclass(frozen=True)
class Task:
    number: int
    title: str
    depends_on: str
    declarations: tuple[Declaration, ...]
    snippets: tuple[Snippet, ...]
    generators: tuple[DeterministicGenerator, ...]
    staged_paths: tuple[str, ...]
    green_commands: tuple[str, ...]
    raw_text: str


@dataclass(frozen=True)
class PlanDocument:
    tasks: tuple[Task, ...]
    source_commit: str | None = None
    source_path: str | None = None

    def only_tasks(self, numbers: set[int]) -> PlanDocument:
        selected = tuple(task for task in self.tasks if task.number in numbers)
        return replace(self, tasks=selected)


def _normalise_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value != path.as_posix():
        raise PlanParseError(f"unsafe or non-canonical plan path: {value!r}")
    if not PATH_TOKEN.fullmatch(value):
        raise PlanParseError(f"unsupported plan path: {value!r}")
    return value


def _parse_header(line: str) -> tuple[str, str, str | None] | None:
    match = COMMENT_HEADER.fullmatch(line) or MARKDOWN_HEADER.fullmatch(line)
    if match is None:
        return None
    header = match.group("header").strip()
    operation: str | None = None
    if header.startswith("append to "):
        operation = "append"
        header = header.removeprefix("append to ")
    elif header.startswith("replace "):
        operation = "replace-file"
        header = header.removeprefix("replace ")
    qualifier = ""
    if header.endswith(")") and " (" in header:
        header, qualifier = header.rsplit(" (", 1)
        qualifier = qualifier[:-1]
    try:
        path = _normalise_path(header)
    except PlanParseError:
        return None
    return path, qualifier, operation


def _parse_staged_paths(section: str) -> tuple[str, ...]:
    commands: list[tuple[str, ...]] = []
    for fence in FENCE.finditer(section):
        if fence.group("language").strip() not in {"bash", "sh", "shell"}:
            continue
        for line in fence.group("body").splitlines():
            if not line.startswith("git add "):
                continue
            words = shlex.split(line)
            if words[:2] != ["git", "add"] or any(word.startswith("-") for word in words[2:]):
                raise PlanParseError("staging commands must be literal `git add path ...`")
            commands.append(tuple(_normalise_path(word) for word in words[2:]))
    return commands[-1] if commands else ()


def _parse_generators(section: str) -> tuple[DeterministicGenerator, ...]:
    generators: list[DeterministicGenerator] = []
    for match in GENERATOR.finditer(section):
        words = list(shlex.split(match.group("command")))
        script_index: int | None = None
        if len(words) >= 2 and words[0] == "python":
            script_index = 1
        elif len(words) >= 7 and words[:6] == [
            "uv",
            "run",
            "--project",
            "evals",
            "--locked",
            "python",
        ]:
            script_index = 6
        if script_index is None or words[script_index].startswith("-"):
            raise PlanParseError(
                "deterministic generator commands must use Python directly or the locked "
                "evals uv project"
            )
        script = _normalise_path(words[script_index])
        if not script.endswith(".py"):
            raise PlanParseError("deterministic generator entry point must be Python")
        words[script_index] = script
        if any("\x00" in word for word in words[script_index + 1 :]):
            raise PlanParseError("deterministic generator argument contains NUL")
        generators.append(
            DeterministicGenerator(
                name=match.group("name"),
                argv=tuple(words),
                entry_point=script,
                output=_normalise_path(match.group("output")),
            )
        )
    names = [generator.name for generator in generators]
    outputs = [generator.output for generator in generators]
    if len(names) != len(set(names)) or len(outputs) != len(set(outputs)):
        raise PlanParseError("deterministic generator names and outputs must be unique")
    return tuple(generators)


def _parse_green_commands(section: str) -> tuple[str, ...]:
    commands: list[str] = []
    headings = tuple(STEP_HEADING.finditer(section))
    for index, heading in enumerate(headings):
        if "green" not in heading.group("label").casefold():
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(section)
        commands.extend(
            match.group("command") for match in RUN_COMMAND.finditer(section, heading.end(), end)
        )
    return tuple(commands)


def parse_plan_text(source: str) -> PlanDocument:
    """Parse the task/file/snippet grammar used by the authoritative plan."""

    headings = tuple(TASK_HEADING.finditer(source))
    if not headings:
        raise PlanParseError("plan contains no zero-padded Task headings")
    tasks: list[Task] = []
    ordinal = 0
    for index, heading in enumerate(headings):
        start = heading.start()
        end = headings[index + 1].start() if index + 1 < len(headings) else len(source)
        section = source[start:end]
        number = int(heading.group("number"))
        dependency = DEPENDENCY.search(section)
        if dependency is None:
            raise PlanParseError(f"Task {number:02d} has no Depends on line")
        declarations = tuple(
            Declaration(match.group("kind"), _normalise_path(match.group("path")))
            for match in DECLARATION.finditer(section)
        )
        snippets: list[Snippet] = []
        for fence in FENCE.finditer(section):
            language = fence.group("language").strip().casefold()
            if language in {"bash", "sh", "shell"}:
                continue
            lines = fence.group("body").splitlines()
            if not lines:
                continue
            parsed_header = _parse_header(lines[0])
            if parsed_header is None:
                continue
            path, qualifier, operation = parsed_header
            lines = lines[1:]
            if lines:
                directive = DIRECTIVE.fullmatch(lines[0])
                if directive is not None:
                    operation = directive.group("operation")
                    lines = lines[1:]
            ordinal += 1
            body = ("\n".join(lines).rstrip() + "\n").encode()
            snippets.append(
                Snippet(number, language, path, qualifier, operation, body, ordinal)
            )
        tasks.append(
            Task(
                number=number,
                title=heading.group("title").strip(),
                depends_on=dependency.group("value").strip(),
                declarations=declarations,
                snippets=tuple(snippets),
                generators=_parse_generators(section),
                staged_paths=_parse_staged_paths(section),
                green_commands=_parse_green_commands(section),
                raw_text=section,
            )
        )
    numbers = tuple(task.number for task in tasks)
    if len(numbers) != len(set(numbers)):
        raise PlanParseError(f"duplicate task numbers: {numbers}")
    return PlanDocument(tuple(tasks))


def parse_plan(path: Path) -> PlanDocument:
    return parse_plan_text(path.read_text(encoding="utf-8"))


def _replace_python_symbol(source: bytes, symbol: str, replacement: bytes) -> bytes:
    decoded = source.decode()
    tree = ast.parse(decoded)
    candidates = [
        node
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == symbol
    ]
    if len(candidates) != 1:
        raise MaterializationError(
            f"replace-symbol target {symbol!r} occurs {len(candidates)} times"
        )
    node = candidates[0]
    lines = decoded.splitlines(keepends=True)
    return (
        "".join(lines[: node.lineno - 1]).encode()
        + replacement
        + "".join(lines[node.end_lineno :]).encode()
    )


def _validate_file(path: str, content: bytes) -> None:
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MaterializationError(f"{path}: generated content is not UTF-8") from error
    suffix = PurePosixPath(path).suffix.casefold()
    try:
        if suffix == ".py":
            ast.parse(decoded, filename=path)
        elif suffix == ".json":
            json.loads(decoded)
        elif suffix == ".toml":
            tomllib.loads(decoded)
        elif suffix in {".yaml", ".yml"}:
            yaml.safe_load(decoded)
        elif suffix in {".ini", ".service"}:
            parser = configparser.ConfigParser(
                interpolation=None,
                strict=False,
                empty_lines_in_values=False,
            )
            parser.read_string(decoded)
    except (
        SyntaxError,
        ValueError,
        TypeError,
        configparser.Error,
        yaml.YAMLError,
    ) as error:
        message = f"{path}: invalid generated {suffix or 'text'}: {error}"
        raise MaterializationError(message) from error


def _tree_files(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = path.relative_to(root).as_posix()
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        files[_normalise_path(relative)] = path.read_bytes()
    return files


def _run_generator_process(
    argv: tuple[str, ...], *, root: Path, environment: dict[str, str]
) -> _GeneratorRun:
    with (
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
        tempfile.TemporaryDirectory(prefix="tuntun-plan-generator-venv-") as uv_environment,
    ):
        isolated_environment = dict(environment)
        if argv[0] == "uv":
            isolated_environment["UV_PROJECT_ENVIRONMENT"] = uv_environment
        result = subprocess.run(
            argv,
            cwd=root,
            env=isolated_environment,
            check=False,
            stdout=stdout,
            stderr=stderr,
            timeout=15,
        )
        stdout_size = stdout.tell()
        stderr_size = stderr.tell()
        stdout.seek(max(0, stdout_size - 2048))
        stderr.seek(max(0, stderr_size - 2048))
        diagnostic = stdout.read(2048) + stderr.read(2048)
    return _GeneratorRun(
        returncode=result.returncode,
        diagnostic=diagnostic,
        output_exceeded=max(stdout_size, stderr_size) >= 1_048_576,
    )


def _execute_generator_once(
    files: dict[str, bytes], generator: DeterministicGenerator, *, task_number: int
) -> dict[str, bytes]:
    with tempfile.TemporaryDirectory(prefix="tuntun-plan-generator-") as temporary:
        root = Path(temporary)
        write_materialized_tree(root, files)
        argv = (
            (sys.executable, *generator.argv[1:])
            if generator.argv[0] == "python"
            else generator.argv
        )
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        python_paths = (
            str(root),
            str(root / "apps/core/src"),
            str(root / "apps/edge/src"),
            str(root / "packages/contracts/src"),
            str(root / "packages/testing/src"),
        )
        environment["PYTHONPATH"] = os.pathsep.join(python_paths)
        try:
            result = _run_generator_process(argv, root=root, environment=environment)
        except subprocess.TimeoutExpired as error:
            raise MaterializationError(
                f"Task {task_number:02d} generator {generator.name}: exceeded 15 seconds"
            ) from error
        if result.output_exceeded:
            raise MaterializationError(
                f"Task {task_number:02d} generator {generator.name}: "
                "diagnostic output exceeded 1 MiB"
            )
        if result.returncode != 0:
            diagnostic = result.diagnostic.decode(errors="replace")
            raise MaterializationError(
                f"Task {task_number:02d} generator {generator.name}: exit "
                f"{result.returncode}: {diagnostic}"
            )
        generated = _tree_files(root)
    changed = {
        path for path in set(files) | set(generated) if files.get(path) != generated.get(path)
    }
    expected = {generator.output}
    if changed != expected:
        raise MaterializationError(
            f"Task {task_number:02d} generator {generator.name}: undeclared outputs "
            f"changed={sorted(changed)} expected={sorted(expected)}"
        )
    output = generated.get(generator.output)
    if output is None or len(output) > 1_048_576:
        raise MaterializationError(
            f"Task {task_number:02d} generator {generator.name}: output absent or over 1 MiB"
        )
    _validate_file(generator.output, output)
    return generated


def _run_generator_check(
    files: dict[str, bytes],
    generator: DeterministicGenerator,
    *,
    task_number: int,
) -> None:
    if "--write" not in generator.argv:
        return
    check_argv = tuple("--check" if word == "--write" else word for word in generator.argv)

    def execute(candidate: dict[str, bytes]) -> _GeneratorRun:
        with tempfile.TemporaryDirectory(prefix="tuntun-plan-generator-check-") as temporary:
            root = Path(temporary)
            write_materialized_tree(root, candidate)
            before = _tree_files(root)
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["PYTHONPATH"] = os.pathsep.join(
                (
                    str(root),
                    str(root / "apps/core/src"),
                    str(root / "apps/edge/src"),
                    str(root / "packages/contracts/src"),
                    str(root / "packages/testing/src"),
                )
            )
            try:
                command = (
                    (sys.executable, *check_argv[1:])
                    if check_argv[0] == "python"
                    else check_argv
                )
                result = _run_generator_process(
                    command,
                    root=root,
                    environment=environment,
                )
            except subprocess.TimeoutExpired as error:
                raise MaterializationError(
                    f"Task {task_number:02d} generator {generator.name}: "
                    "check exceeded 15 seconds"
                ) from error
            after = _tree_files(root)
        if after != before:
            raise MaterializationError(
                f"Task {task_number:02d} generator {generator.name}: check mutated files"
            )
        if result.output_exceeded:
            raise MaterializationError(
                f"Task {task_number:02d} generator {generator.name}: "
                "check diagnostic output exceeded 1 MiB"
            )
        return result

    clean = execute(files)
    if clean.returncode != 0:
        diagnostic = clean.diagnostic.decode(errors="replace")
        raise MaterializationError(
            f"Task {task_number:02d} generator {generator.name}: check rejected "
            f"generated output: {diagnostic}"
        )
    drifted = dict(files)
    drifted[generator.output] = drifted[generator.output] + b" "
    hostile = execute(drifted)
    if hostile.returncode == 0:
        raise MaterializationError(
            f"Task {task_number:02d} generator {generator.name}: "
            "check accepted controlled output drift"
        )


def _run_deterministic_generators(
    files: dict[str, bytes], generators: tuple[DeterministicGenerator, ...], *, task_number: int
) -> tuple[dict[str, bytes], set[str]]:
    generated_paths: set[str] = set()
    for generator in generators:
        first = _execute_generator_once(files, generator, task_number=task_number)
        second = _execute_generator_once(files, generator, task_number=task_number)
        if first[generator.output] != second[generator.output]:
            raise MaterializationError(
                f"Task {task_number:02d} generator {generator.name}: nondeterministic output"
            )
        _run_generator_check(first, generator, task_number=task_number)
        files = first
        generated_paths.add(generator.output)
    return files, generated_paths


def materialize_document(
    document: PlanDocument, *, foundation_files: dict[str, bytes]
) -> dict[str, bytes]:
    """Apply all task snippets and enforce declarations at each task boundary."""

    files = dict(foundation_files)
    for task in document.tasks:
        declarations = {declaration.path: declaration for declaration in task.declarations}
        if len(declarations) != len(task.declarations):
            raise MaterializationError(f"Task {task.number:02d}: duplicate file declaration")
        existing_at_boundary = set(files)
        for declaration in task.declarations:
            if declaration.kind == "Create" and declaration.path in existing_at_boundary:
                raise MaterializationError(
                    f"Task {task.number:02d} {declaration.path}: declared Create already exists"
                )
            if declaration.kind == "Modify" and declaration.path not in existing_at_boundary:
                raise MaterializationError(
                    f"Task {task.number:02d} {declaration.path}: declared Modify does not exist"
                )
        seen_in_task: set[str] = set()
        for snippet in task.snippets:
            declared = declarations.get(snippet.path)
            if declared is None:
                raise MaterializationError(
                    f"Task {task.number:02d} {snippet.path}: snippet has no declaration"
                )
            current = files.get(snippet.path)
            operation = snippet.operation
            first = snippet.path not in seen_in_task
            if operation is None:
                if first and current is None:
                    operation = "create"
                elif any(word in snippet.qualifier.casefold() for word in APPEND_WORDS):
                    operation = "append"
                else:
                    raise MaterializationError(
                        f"Task {task.number:02d} {snippet.path}: ambiguous existing-file snippet"
                    )
            if operation == "create":
                if current is not None:
                    raise MaterializationError(
                        f"Task {task.number:02d} {snippet.path}: create operation already exists"
                    )
                candidate = snippet.body
            elif operation == "append":
                if current is None:
                    raise MaterializationError(
                        f"Task {task.number:02d} {snippet.path}: append target does not exist"
                    )
                separator = b"" if current.endswith(b"\n\n") else b"\n"
                candidate = current + separator + snippet.body
            elif operation == "replace-file":
                if current is None:
                    raise MaterializationError(
                        f"Task {task.number:02d} {snippet.path}: replace target does not exist"
                    )
                candidate = snippet.body
            elif operation.startswith("replace-symbol "):
                if current is None or not snippet.path.endswith(".py"):
                    raise MaterializationError(
                        f"Task {task.number:02d} {snippet.path}: invalid replace-symbol target"
                    )
                candidate = _replace_python_symbol(
                    current, operation.removeprefix("replace-symbol "), snippet.body
                )
            else:
                raise MaterializationError(
                    f"Task {task.number:02d} {snippet.path}: unsupported operation {operation!r}"
                )
            _validate_file(snippet.path, candidate)
            files[snippet.path] = candidate
            seen_in_task.add(snippet.path)
        for generator in task.generators:
            if generator.output not in declarations:
                raise MaterializationError(
                    f"Task {task.number:02d} generator {generator.name}: output has no declaration"
                )
            if generator.entry_point not in files:
                raise MaterializationError(
                    f"Task {task.number:02d} generator {generator.name}: entry point is absent"
                )
        files, generated_paths = _run_deterministic_generators(
            files, task.generators, task_number=task.number
        )
        seen_in_task.update(generated_paths)
        for declaration in task.declarations:
            if declaration.kind == "Create" and declaration.path not in seen_in_task:
                raise MaterializationError(
                    f"Task {task.number:02d} {declaration.path}: Create has no literal snippet"
                )
            if (
                declaration.kind == "Test"
                and declaration.path not in existing_at_boundary
                and declaration.path not in seen_in_task
            ):
                raise MaterializationError(
                    f"Task {task.number:02d} {declaration.path}: Test has no literal snippet"
                )
    return files


def foundation_files_from_ref(repository_root: Path, foundation_ref: str) -> dict[str, bytes]:
    """Read an explicit git ref without checking it out or trusting a worktree."""

    archive = subprocess.run(
        ["git", "-C", str(repository_root), "archive", "--format=tar", foundation_ref],
        check=True,
        capture_output=True,
    ).stdout
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        for member in bundle.getmembers():
            if not member.isfile():
                continue
            path = _normalise_path(member.name)
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise MaterializationError(f"git archive member cannot be read: {path}")
            files[path] = extracted.read()
    return files


def plan_document_from_ref(
    repository_root: Path, plan_ref: str, plan_path: str
) -> PlanDocument:
    """Parse plan bytes from an explicit committed git object, never the worktree."""

    canonical_path = _normalise_path(plan_path)
    resolved = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "--verify", f"{plan_ref}^{{commit}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    content = subprocess.run(
        ["git", "-C", str(repository_root), "show", f"{resolved}:{canonical_path}"],
        check=True,
        capture_output=True,
    ).stdout
    try:
        source = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PlanParseError(f"committed plan is not UTF-8: {canonical_path}") from error
    return replace(
        parse_plan_text(source), source_commit=resolved, source_path=canonical_path
    )


def write_materialized_tree(destination: Path, files: dict[str, bytes]) -> None:
    if destination.exists() and any(destination.iterdir()):
        raise MaterializationError(f"destination must be absent or empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    for relative, content in sorted(files.items()):
        target = destination.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--foundation-ref", required=True)
    parser.add_argument("--plan-ref", required=True)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--plan-path",
        default=(
            "docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md"
        ),
    )
    parser.add_argument("--destination", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    repository_root = args.repository_root.resolve()
    foundation = foundation_files_from_ref(repository_root, args.foundation_ref)
    document = plan_document_from_ref(repository_root, args.plan_ref, args.plan_path)
    files = materialize_document(document, foundation_files=foundation)
    write_materialized_tree(args.destination.resolve(), files)
    print(
        f"materialized {len(files)} files from Foundation {args.foundation_ref} "
        f"and plan {document.source_commit}:{document.source_path} "
        f"into {args.destination.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
