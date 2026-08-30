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
import re
import shlex
import subprocess
import tarfile
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
class Task:
    number: int
    title: str
    depends_on: str
    declarations: tuple[Declaration, ...]
    snippets: tuple[Snippet, ...]
    staged_paths: tuple[str, ...]
    raw_text: str


@dataclass(frozen=True)
class PlanDocument:
    tasks: tuple[Task, ...]

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
    staged: list[str] = []
    for fence in FENCE.finditer(section):
        if fence.group("language").strip() not in {"bash", "sh", "shell"}:
            continue
        for line in fence.group("body").splitlines():
            if not line.startswith("git add "):
                continue
            words = shlex.split(line)
            if words[:2] != ["git", "add"] or any(word.startswith("-") for word in words[2:]):
                raise PlanParseError("staging commands must be literal `git add path ...`")
            staged.extend(_normalise_path(word) for word in words[2:])
    return tuple(staged)


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
                staged_paths=_parse_staged_paths(section),
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
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--plan",
        type=Path,
        default=Path(
            "docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md"
        ),
    )
    parser.add_argument("--destination", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    repository_root = args.repository_root.resolve()
    plan_path = args.plan if args.plan.is_absolute() else repository_root / args.plan
    foundation = foundation_files_from_ref(repository_root, args.foundation_ref)
    files = materialize_document(parse_plan(plan_path), foundation_files=foundation)
    write_materialized_tree(args.destination.resolve(), files)
    print(
        f"materialized {len(files)} files from Foundation {args.foundation_ref} "
        f"into {args.destination.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
