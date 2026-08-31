#!/usr/bin/env python3
"""Deterministically materialize the Conversation/Reachy execution plan.

The plan is executable documentation: every fenced file body is applied in task
order to an explicit Foundation git ref.  This module deliberately has no
knowledge of a developer worktree or branch name.
"""

from __future__ import annotations

import argparse
import ast
import base64
import configparser
import contextlib
import hashlib
import importlib.metadata
import io
import json
import os
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

import yaml
from packaging.markers import (
    InvalidMarker,
    Marker,
    UndefinedEnvironmentName,
    default_environment,
)
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import sys_tags
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

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
FENCE = re.compile(r"^```(?P<language>[^\n]*)\n(?P<body>.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
DIRECTIVE = re.compile(
    r"^# materializer: (?P<operation>append|replace-file|replace-symbol [A-Za-z_]\w*)$"
)
COMMENT_HEADER = re.compile(r"^# (?P<header>.+?)\s*$")
MARKDOWN_HEADER = re.compile(r"^<!--\s*(?P<header>.+?)\s*-->\s*$")
PATH_TOKEN = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
APPEND_WORDS = ("append", "addition", "continued", "extension")
STRUCTURED_SUFFIXES = {".json", ".toml", ".yaml", ".yml"}
GENERATOR_DIAGNOSTIC_LIMIT = 1_048_576
GENERATOR_TIMEOUT_SECONDS = 15
_DISTRIBUTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_EXACT_VERSION = re.compile(r"==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)")
_SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")


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
class _LockedEvalPolicy:
    project_name: str
    reachable_versions: dict[str, frozenset[str]]
    forbidden_imports: tuple[str, ...]
    registry_artifacts: dict[str, tuple[tuple[str, str], ...]] = field(default_factory=dict)
    registry_distributions: frozenset[str] | None = None
    dependency_graph: dict[str, frozenset[str]] = field(default_factory=dict)
    candidate_projects: dict[str, _CandidateProject] = field(default_factory=dict)


@dataclass(frozen=True)
class _CandidateProject:
    name: str
    version: str
    project_root: str
    source_root: str


@dataclass(frozen=True)
class _CanonicalRequirement:
    name: str
    specifier: str
    marker: str | None
    active: bool
    directory: str | None = None


@dataclass(frozen=True)
class FoundationSnapshot:
    files: dict[str, bytes]
    source_commit: str


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
            snippets.append(Snippet(number, language, path, qualifier, operation, body, ordinal))
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


def _normalise_distribution_name(value: str) -> str:
    return str(canonicalize_name(value))


_EVAL_CANDIDATE_BINDINGS = {
    "tuntun-core": ("../apps/core", "apps/core", "apps/core/src", "tuntun_core"),
    "tuntun-contracts": (
        "../packages/contracts",
        "packages/contracts",
        "packages/contracts/src",
        "tuntun_contracts",
    ),
}
_CANDIDATE_IMPORT_ROOTS = frozenset({"tuntun_core", "tuntun_contracts"})
_FASTTEXT_PREDICT_IMPORT_ROOTS = frozenset({"fasttext", "fasttext_pybind"})
_FASTTEXT_PREDICT_DARWIN_WHEELS = {
    "fasttext_predict-0.9.2.4-cp312-cp312-macosx_11_0_arm64.whl": (
        "99dbfcc3f353da2639fd04fc574a65ff4195b018311f790583147cdc6eb122f4"
    ),
    "fasttext_predict-0.9.2.4-cp312-cp312-macosx_10_13_x86_64.whl": (
        "dcf8661da4f515551523470a745df246121f7e19736fcf3f48f04287963e6279"
    ),
}


def _marker_applies(
    value: object,
    *,
    description: str,
    allow_unselected_extra: bool = False,
) -> bool:
    if value is None:
        return True
    if not isinstance(value, str) or not value.strip():
        raise MaterializationError(f"{description} marker is invalid")
    try:
        marker = Marker(value)
    except InvalidMarker as error:
        raise MaterializationError(f"{description} marker is invalid") from error
    marker_text = str(marker)
    if re.search(r"\b(?:extras|dependency_groups)\b", marker_text) or (
        not allow_unselected_extra and re.search(r"\bextra\b", marker_text)
    ):
        raise MaterializationError(
            f"{description} marker uses an unsupported ambiguous selection context"
        )
    try:
        environment = {key: str(value) for key, value in default_environment().items()}
        if allow_unselected_extra:
            environment["extra"] = ""
        return marker.evaluate(
            environment=environment,
            context="metadata" if allow_unselected_extra else "lock_file",
        )
    except (UndefinedEnvironmentName, KeyError, ValueError) as error:
        raise MaterializationError(f"{description} marker is unsupported") from error


def _canonical_specifier(value: object, *, description: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise MaterializationError(f"{description} specifier is invalid")
    try:
        return str(SpecifierSet(value))
    except InvalidSpecifier as error:
        raise MaterializationError(f"{description} specifier is invalid") from error


def _canonical_requirement_from_text(
    value: object,
    *,
    description: str,
    allow_inactive_optional_extra: bool = False,
) -> _CanonicalRequirement:
    if not isinstance(value, str):
        raise MaterializationError(f"{description} requirement must be a string")
    try:
        requirement = Requirement(value)
    except InvalidRequirement as error:
        raise MaterializationError(f"{description} requirement is invalid: {value!r}") from error
    marker = str(requirement.marker) if requirement.marker is not None else None
    active = _marker_applies(
        marker,
        description=description,
        allow_unselected_extra=allow_inactive_optional_extra,
    )
    if requirement.url is not None:
        raise MaterializationError(f"{description} uses unsupported URL")
    if requirement.extras and not (allow_inactive_optional_extra and not active):
        raise MaterializationError(f"{description} uses unsupported extras")
    return _CanonicalRequirement(
        name=_normalise_distribution_name(requirement.name),
        specifier=str(requirement.specifier),
        marker=marker,
        active=active,
    )


def _canonical_requirement_from_lock_record(
    value: object,
    *,
    description: str,
    allow_directory: bool,
) -> _CanonicalRequirement:
    if not isinstance(value, dict) or not isinstance(value.get("name"), str):
        raise MaterializationError(f"{description} requirement metadata is invalid")
    allowed_keys = {"name", "specifier", "marker"}
    if allow_directory:
        allowed_keys.add("directory")
    unexpected = set(value) - allowed_keys
    if unexpected:
        raise MaterializationError(
            f"{description} requirement metadata has unsupported URL, extras, or source "
            f"fields: {sorted(unexpected)}"
        )
    marker_value = value.get("marker")
    marker = None
    if marker_value is not None:
        if not isinstance(marker_value, str):
            raise MaterializationError(f"{description} requirement marker is invalid")
        try:
            marker = str(Marker(marker_value))
        except InvalidMarker as error:
            raise MaterializationError(f"{description} requirement marker is invalid") from error
    active = _marker_applies(marker, description=description)
    directory = value.get("directory")
    if directory is not None and not isinstance(directory, str):
        raise MaterializationError(f"{description} candidate directory is invalid")
    return _CanonicalRequirement(
        name=_normalise_distribution_name(value["name"]),
        specifier=_canonical_specifier(value.get("specifier"), description=description),
        marker=marker,
        active=active,
        directory=directory,
    )


def _requirement_map(
    requirements: Sequence[_CanonicalRequirement], *, description: str
) -> dict[str, _CanonicalRequirement]:
    result: dict[str, _CanonicalRequirement] = {}
    for requirement in requirements:
        if requirement.name in result:
            raise MaterializationError(
                f"{description} requirement is ambiguously repeated: {requirement.name}"
            )
        result[requirement.name] = requirement
    return result


def _requirement_signature(
    requirement: _CanonicalRequirement,
) -> tuple[str, str, str | None, str | None]:
    return (
        requirement.name,
        requirement.specifier,
        requirement.marker,
        requirement.directory,
    )


def _validate_selected_requirement(
    requirement: _CanonicalRequirement,
    *,
    versions: dict[str, set[str]],
    description: str,
) -> None:
    selected = versions.get(requirement.name)
    if not selected or len(selected) != 1:
        raise MaterializationError(
            f"{description} requirement {requirement.name} has no exact locked version"
        )
    selected_text = next(iter(selected))
    try:
        selected_version = Version(selected_text)
    except InvalidVersion as error:
        raise MaterializationError(
            f"{description} requirement {requirement.name} has invalid locked version"
        ) from error
    specifier = SpecifierSet(requirement.specifier)
    if not specifier.contains(selected_version, prereleases=None):
        raise MaterializationError(
            f"{description} requirement {requirement.name}{specifier} rejects locked "
            f"version {selected_text}"
        )


def _require_nonsymlink_candidate_path(
    root: Path,
    relative: str,
    *,
    description: str,
    directory: bool,
) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.is_symlink():
            raise MaterializationError(f"{description} candidate path contains a symlink")
    resolved_root = root.resolve()
    resolved_candidate = candidate.resolve()
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as error:
        raise MaterializationError(
            f"{description} candidate path escapes materialized root"
        ) from error
    exists = resolved_candidate.is_dir() if directory else resolved_candidate.is_file()
    if not exists:
        kind = "directory" if directory else "file"
        raise MaterializationError(f"{description} candidate {kind} is missing")
    return resolved_candidate


def _candidate_project_policy(
    root: Path,
    *,
    name: str,
    locked_version: str,
    locked_requirements: Sequence[_CanonicalRequirement],
    dependency_graph: dict[str, set[str]],
    complete_dependency_graph: dict[str, set[str]],
    locked_versions: dict[str, set[str]],
) -> tuple[_CandidateProject, tuple[_CanonicalRequirement, ...]]:
    _, project_relative, source_relative, module_name = _EVAL_CANDIDATE_BINDINGS[name]
    project_root = _require_nonsymlink_candidate_path(
        root,
        project_relative,
        description=name,
        directory=True,
    )
    pyproject_path = _require_nonsymlink_candidate_path(
        root,
        f"{project_relative}/pyproject.toml",
        description=name,
        directory=False,
    )
    source_root = _require_nonsymlink_candidate_path(
        root,
        source_relative,
        description=name,
        directory=True,
    )
    for source_member in source_root.rglob("*"):
        if source_member.is_symlink():
            raise MaterializationError(f"{name} candidate source tree contains a symlink")
        try:
            source_member.resolve().relative_to(root.resolve())
        except ValueError as error:
            raise MaterializationError(f"{name} candidate source tree escapes root") from error
    _require_nonsymlink_candidate_path(
        root,
        f"{source_relative}/{module_name}",
        description=name,
        directory=True,
    )
    _require_nonsymlink_candidate_path(
        root,
        f"{source_relative}/{module_name}/__init__.py",
        description=name,
        directory=False,
    )
    try:
        document = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise MaterializationError(f"{name} candidate pyproject metadata is invalid") from error
    project = document.get("project")
    if not isinstance(project, dict) or project.get("name") != name:
        raise MaterializationError(f"{name} candidate project name does not match source binding")
    version_value = project.get("version")
    if not isinstance(version_value, str):
        raise MaterializationError(f"{name} candidate version is invalid")
    try:
        candidate_version = Version(version_value)
        selected_version = Version(locked_version)
    except InvalidVersion as error:
        raise MaterializationError(f"{name} candidate version is invalid") from error
    if candidate_version != selected_version:
        raise MaterializationError(f"{name} candidate version differs from eval lock")
    requires_python = project.get("requires-python")
    try:
        python_specifier = (
            SpecifierSet(requires_python) if isinstance(requires_python, str) else None
        )
    except InvalidSpecifier as error:
        raise MaterializationError(f"{name} candidate requires-python is invalid") from error
    interpreter = Version(".".join(str(value) for value in sys.version_info[:3]))
    if python_specifier is None or not python_specifier.contains(interpreter, prereleases=True):
        raise MaterializationError(
            f"{name} candidate Python requirement rejects the validation interpreter"
        )
    dependency_values = project.get("dependencies", [])
    if not isinstance(dependency_values, list):
        raise MaterializationError(f"{name} candidate dependencies are invalid")
    candidate_requirements = tuple(
        _canonical_requirement_from_text(
            value,
            description=f"{name} candidate dependency",
        )
        for value in dependency_values
    )
    candidate_map = _requirement_map(
        candidate_requirements,
        description=f"{name} candidate dependency",
    )
    lock_map = _requirement_map(
        locked_requirements,
        description=f"{name} locked candidate metadata",
    )
    expected_lock_map = {
        dependency_name: replace(
            requirement,
            directory=(
                _EVAL_CANDIDATE_BINDINGS[dependency_name][0]
                if dependency_name in _EVAL_CANDIDATE_BINDINGS
                else None
            ),
        )
        for dependency_name, requirement in candidate_map.items()
    }
    if {key: _requirement_signature(value) for key, value in expected_lock_map.items()} != {
        key: _requirement_signature(value) for key, value in lock_map.items()
    }:
        raise MaterializationError(f"{name} candidate requirements differ from lock metadata")
    if complete_dependency_graph[name] != set(candidate_map) or dependency_graph[name] != {
        requirement.name for requirement in candidate_requirements if requirement.active
    }:
        raise MaterializationError(f"{name} candidate dependency graph differs from metadata")
    for requirement in candidate_requirements:
        if requirement.active:
            _validate_selected_requirement(
                requirement,
                versions=locked_versions,
                description=f"{name} candidate",
            )
    return (
        _CandidateProject(
            name=name,
            version=locked_version,
            project_root=project_root.relative_to(root.resolve()).as_posix(),
            source_root=source_root.relative_to(root.resolve()).as_posix(),
        ),
        candidate_requirements,
    )


def _locked_eval_import_policy(root: Path) -> _LockedEvalPolicy | None:
    """Validate the eval lock and describe its complete distribution closure."""

    project_path = root / "evals/pyproject.toml"
    lock_path = root / "evals/uv.lock"
    if not project_path.is_file() and not lock_path.is_file():
        return None
    if not project_path.is_file() or not lock_path.is_file():
        raise MaterializationError(
            "locked eval runtime requires both evals/pyproject.toml and evals/uv.lock"
        )
    try:
        project_document = tomllib.loads(project_path.read_text(encoding="utf-8"))
        lock_document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise MaterializationError(f"locked eval runtime metadata is invalid: {error}") from error

    project = project_document.get("project")
    packages = lock_document.get("package")
    if not isinstance(project, dict) or not isinstance(packages, list):
        raise MaterializationError("locked eval runtime metadata lacks project or package records")
    interpreter_requirement = f"=={sys.version_info.major}.{sys.version_info.minor}.*"
    if (
        project.get("requires-python") != interpreter_requirement
        or lock_document.get("requires-python") != interpreter_requirement
    ):
        raise MaterializationError(
            "locked eval Python requirement does not match the validation interpreter"
        )
    if lock_document.get("version") != 1 or lock_document.get("revision") != 3:
        raise MaterializationError("locked eval uv.lock format or revision is unsupported")
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list) or not all(
        isinstance(value, str) for value in dependencies
    ):
        raise MaterializationError("locked eval project dependencies must be strings")
    project_name_value = project.get("name")
    if not isinstance(project_name_value, str):
        raise MaterializationError("locked eval project name is invalid")
    project_name = _normalise_distribution_name(project_name_value)
    declared_requirements = tuple(
        _canonical_requirement_from_text(
            dependency,
            description="locked eval project dependency",
        )
        for dependency in dependencies
    )
    declared_map = _requirement_map(
        declared_requirements,
        description="locked eval project dependency",
    )
    active_declared_names = {
        requirement.name for requirement in declared_requirements if requirement.active
    }

    tool = project_document.get("tool", {})
    uv = tool.get("uv", {}) if isinstance(tool, dict) else {}
    sources = uv.get("sources") if isinstance(uv, dict) else None
    active_candidate_names = active_declared_names & set(_EVAL_CANDIDATE_BINDINGS)
    if active_candidate_names:
        if not isinstance(sources, dict) or set(sources) != active_candidate_names:
            raise MaterializationError(
                "locked eval candidate [tool.uv.sources] must contain only active candidates"
            )
        for name in active_candidate_names:
            source = sources.get(name)
            expected_path = _EVAL_CANDIDATE_BINDINGS[name][0]
            if (
                not isinstance(source, dict)
                or set(source) != {"path", "editable"}
                or source.get("path") != expected_path
                or source.get("editable") is not False
            ):
                raise MaterializationError(
                    f"locked eval candidate source {name} must bind exact path with editable=false"
                )
    elif sources not in (None, {}):
        raise MaterializationError("locked eval source table declares unsupported local candidates")

    locked_versions: dict[str, set[str]] = {}
    locked_records: dict[str, int] = {}
    dependency_graph: dict[str, set[str]] = {}
    complete_dependency_graph: dict[str, set[str]] = {}
    package_records: dict[str, dict[str, object]] = {}
    package_metadata: dict[str, tuple[_CanonicalRequirement, ...]] = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise MaterializationError("locked eval package record is invalid")
        name = _normalise_distribution_name(package["name"])
        locked_records[name] = locked_records.get(name, 0) + 1
        package_records[name] = package
        dependency_graph.setdefault(name, set())
        complete_dependency_graph.setdefault(name, set())
        version = package.get("version")
        if isinstance(version, str):
            locked_versions.setdefault(name, set()).add(version)
        package_dependencies = package.get("dependencies", [])
        if not isinstance(package_dependencies, list):
            raise MaterializationError(f"locked eval package {name} dependencies are invalid")
        for dependency in package_dependencies:
            if not isinstance(dependency, dict) or not isinstance(dependency.get("name"), str):
                raise MaterializationError(
                    f"locked eval package {name} dependency record is invalid"
                )
            if set(dependency) - {"name", "marker"}:
                raise MaterializationError(
                    f"locked eval package {name} dependency record has unsupported source, "
                    "specifier, or extras"
                )
            dependency_name = _normalise_distribution_name(dependency["name"])
            complete_dependency_graph[name].add(dependency_name)
            if _marker_applies(
                dependency.get("marker"),
                description=f"locked eval package {name} dependency {dependency_name}",
            ):
                dependency_graph[name].add(dependency_name)
        metadata = package.get("metadata")
        if metadata is not None:
            if not isinstance(metadata, dict) or set(metadata) != {"requires-dist"}:
                raise MaterializationError(f"locked eval package {name} metadata is invalid")
            requires_dist = metadata.get("requires-dist")
            if not isinstance(requires_dist, list):
                raise MaterializationError(f"locked eval package {name} metadata is invalid")
            package_metadata[name] = tuple(
                _canonical_requirement_from_lock_record(
                    dependency,
                    description=f"locked eval package {name}",
                    allow_directory=(name == project_name or name in active_candidate_names),
                )
                for dependency in requires_dist
            )
        source = package.get("source")
        if not isinstance(source, dict):
            raise MaterializationError(f"locked eval package {name} source is invalid")
        if "editable" in source:
            raise MaterializationError(f"locked eval package {name} editable source is forbidden")
        if "directory" in source and (
            name not in active_candidate_names
            or source != {"directory": _EVAL_CANDIDATE_BINDINGS[name][0]}
        ):
            raise MaterializationError(
                f"locked eval package {name} has an unsupported local directory source"
            )

    if project_name not in dependency_graph:
        raise MaterializationError("locked eval project package is absent from evals/uv.lock")
    if complete_dependency_graph[project_name] != set(declared_map):
        raise MaterializationError(
            "locked eval project complete dependency closure differs from evals/pyproject.toml"
        )
    if dependency_graph[project_name] != active_declared_names:
        raise MaterializationError(
            "locked eval project dependency closure differs from evals/pyproject.toml"
        )
    root_lock_requirements = package_metadata.get(project_name, ())
    root_lock_map = _requirement_map(
        root_lock_requirements,
        description="locked eval project metadata",
    )
    expected_root_lock = {
        name: replace(
            requirement,
            directory=(
                _EVAL_CANDIDATE_BINDINGS[name][0] if name in active_candidate_names else None
            ),
        )
        for name, requirement in declared_map.items()
    }
    if {
        name: _requirement_signature(requirement) for name, requirement in root_lock_map.items()
    } != {
        name: _requirement_signature(requirement)
        for name, requirement in expected_root_lock.items()
    }:
        raise MaterializationError(
            "locked eval project requirement metadata differs from evals/pyproject.toml"
        )

    complete_reachable = {project_name}
    pending = [project_name]
    while pending:
        current = pending.pop()
        for dependency_name in complete_dependency_graph[current]:
            if dependency_name not in complete_dependency_graph:
                raise MaterializationError(
                    f"locked eval dependency {dependency_name} has no package record"
                )
            if dependency_name not in complete_reachable:
                complete_reachable.add(dependency_name)
                pending.append(dependency_name)
    unreachable = set(complete_dependency_graph) - complete_reachable
    if unreachable:
        raise MaterializationError(
            f"locked eval package closure contains undeclared packages: {sorted(unreachable)}"
        )

    reachable = {project_name}
    pending = [project_name]
    while pending:
        current = pending.pop()
        for dependency_name in dependency_graph[current]:
            if dependency_name not in dependency_graph:
                raise MaterializationError(
                    f"locked eval dependency {dependency_name} has no package record"
                )
            if dependency_name not in reachable:
                reachable.add(dependency_name)
                pending.append(dependency_name)
    ambiguous = {
        name: sorted(locked_versions.get(name, set()))
        for name in reachable
        if locked_records.get(name) != 1 or len(locked_versions.get(name, set())) != 1
    }
    if ambiguous:
        raise MaterializationError(
            "every reachable locked eval distribution must have exactly one locked "
            f"version: {ambiguous}"
        )
    for name in reachable:
        selected_text = next(iter(locked_versions[name]))
        try:
            Version(selected_text)
        except InvalidVersion as error:
            raise MaterializationError(
                f"locked eval distribution {name} has an invalid version"
            ) from error
    for requirement in declared_requirements:
        if requirement.active:
            _validate_selected_requirement(
                requirement,
                versions=locked_versions,
                description="locked eval project",
            )

    candidate_projects: dict[str, _CandidateProject] = {}
    for name in sorted(active_candidate_names):
        package = package_records.get(name)
        if package is None:
            raise MaterializationError(f"locked eval candidate {name} has no package record")
        if package.get("source") != {"directory": _EVAL_CANDIDATE_BINDINGS[name][0]}:
            raise MaterializationError(f"locked eval candidate {name} source differs from binding")
        candidate, _ = _candidate_project_policy(
            root,
            name=name,
            locked_version=next(iter(locked_versions[name])),
            locked_requirements=package_metadata.get(name, ()),
            dependency_graph=dependency_graph,
            complete_dependency_graph=complete_dependency_graph,
            locked_versions=locked_versions,
        )
        candidate_projects[name] = candidate

    registry_names = reachable - {project_name} - set(candidate_projects)
    for name in registry_names:
        if package_records[name].get("source") != {"registry": "https://pypi.org/simple"}:
            raise MaterializationError(
                f"locked eval dependency {name} is neither a verified registry distribution "
                "nor an approved candidate source; trustworthy artifact evidence is unavailable"
            )

    registry_artifacts: dict[str, list[tuple[str, str]]] = {}
    for name in sorted(registry_names):
        package = package_records[name]
        artifacts = []
        if isinstance(package.get("sdist"), dict):
            artifacts.append(package["sdist"])
        wheels = package.get("wheels", [])
        if isinstance(wheels, list):
            artifacts.extend(item for item in wheels if isinstance(item, dict))
        verified_records: list[tuple[str, str]] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise MaterializationError(f"locked eval package {name} artifact record is invalid")
            url = artifact.get("url")
            value = artifact.get("hash")
            match = _SHA256.fullmatch(value) if isinstance(value, str) else None
            if (
                not isinstance(url, str)
                or not url.startswith("https://files.pythonhosted.org/")
                or match is None
                or set(match.group(1)) == {"0"}
            ):
                verified_records = []
                break
            verified_records.append((url, match.group(1)))
        if not verified_records:
            raise MaterializationError(
                f"locked eval package {name} lacks trustworthy sha256 artifacts"
            )
        registry_artifacts[name] = verified_records
    missing_artifacts = registry_names - set(registry_artifacts)
    if missing_artifacts:
        raise MaterializationError(
            "locked eval dependencies lack trustworthy artifact evidence: "
            f"{sorted(missing_artifacts)}"
        )
    if "fasttext-wheel" in reachable:
        raise MaterializationError(
            "locked eval runtime uses unreviewed fasttext-wheel instead of fasttext-predict"
        )
    if "fasttext-predict" in reachable:
        if locked_versions.get("fasttext-predict") != {"0.9.2.4"}:
            raise MaterializationError("fasttext-predict must use reviewed version 0.9.2.4")
        observed_fasttext_wheels = {
            url.rsplit("/", 1)[-1]: digest
            for url, digest in registry_artifacts.get("fasttext-predict", ())
            if url.rsplit("/", 1)[-1].endswith(".whl")
        }
        missing_darwin_evidence = {
            filename: digest
            for filename, digest in _FASTTEXT_PREDICT_DARWIN_WHEELS.items()
            if observed_fasttext_wheels.get(filename) != digest
        }
        if missing_darwin_evidence:
            raise MaterializationError(
                "fasttext-predict wheel evidence must include exact reviewed CPython 3.12 "
                "Darwin arm64 and x86_64 artifacts"
            )

    installed_to_imports = importlib.metadata.packages_distributions()
    allowed = reachable
    forbidden: set[str] = set()
    for import_name, distribution_names in installed_to_imports.items():
        if not distribution_names:
            continue
        normalised = {_normalise_distribution_name(name) for name in distribution_names}
        if not normalised <= allowed:
            forbidden.add(import_name.partition(".")[0])
    return _LockedEvalPolicy(
        project_name=project_name,
        reachable_versions={
            name: frozenset(locked_versions.get(name, set())) for name in sorted(reachable)
        },
        forbidden_imports=tuple(sorted(forbidden)),
        registry_artifacts={
            name: tuple(sorted(records)) for name, records in sorted(registry_artifacts.items())
        },
        registry_distributions=frozenset(registry_names),
        dependency_graph={name: frozenset(dependency_graph[name]) for name in sorted(reachable)},
        candidate_projects=candidate_projects,
    )


def _root_locked_import_policy() -> _LockedEvalPolicy:
    """Describe and verify the exact root workspace lock used by direct Python gates."""

    workspace = Path(__file__).resolve().parents[1]
    lock_path = workspace / "uv.lock"
    project_path = workspace / "pyproject.toml"
    if not lock_path.is_file() or not project_path.is_file():
        raise MaterializationError("root locked Python runtime metadata is unavailable")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("version") != 1 or lock.get("revision") != 3:
        raise MaterializationError("root locked Python runtime format is unsupported")
    manifest = lock.get("manifest")
    packages = lock.get("package")
    if not isinstance(manifest, dict) or not isinstance(packages, list):
        raise MaterializationError("root locked Python runtime closure is invalid")
    members = manifest.get("members")
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        raise MaterializationError("root locked Python runtime manifest is invalid")

    dependency_graph: dict[str, set[str]] = {}
    locked_versions: dict[str, set[str]] = {}
    locked_records: dict[str, int] = {}
    virtual_projects: set[str] = set()

    def selected_dependency(item: object) -> str | None:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise MaterializationError("root lock dependency record is invalid")
        if not _marker_applies(
            item.get("marker"),
            description=f"root lock dependency {item['name']}",
        ):
            return None
        return _normalise_distribution_name(item["name"])

    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise MaterializationError("root lock package record is invalid")
        name = _normalise_distribution_name(package["name"])
        locked_records[name] = locked_records.get(name, 0) + 1
        version = package.get("version")
        if isinstance(version, str):
            locked_versions.setdefault(name, set()).add(version)
        source = package.get("source")
        if isinstance(source, dict) and "virtual" in source:
            virtual_projects.add(name)
        dependencies: set[str] = set()
        for item in package.get("dependencies", []):
            selected = selected_dependency(item)
            if selected is not None:
                dependencies.add(selected)
        development = package.get("dev-dependencies", {})
        if isinstance(development, dict):
            for group in development.values():
                if not isinstance(group, list):
                    raise MaterializationError("root lock dependency group is invalid")
                for item in group:
                    selected = selected_dependency(item)
                    if selected is not None:
                        dependencies.add(selected)
        dependency_graph.setdefault(name, set()).update(dependencies)

    reachable = {_normalise_distribution_name(name) for name in members}
    pending = list(reachable)
    while pending:
        name = pending.pop()
        for dependency in dependency_graph.get(name, set()):
            if dependency not in reachable:
                reachable.add(dependency)
                pending.append(dependency)
    if not virtual_projects <= reachable:
        raise MaterializationError("root lock contains an unreachable virtual project")
    ambiguous = {
        name: sorted(locked_versions.get(name, set()))
        for name in reachable
        if locked_records.get(name) != 1 or len(locked_versions.get(name, set())) != 1
    }
    if ambiguous:
        raise MaterializationError(
            f"every reachable root distribution must have exactly one locked version: {ambiguous}"
        )
    project_name = next(iter(virtual_projects), "")
    if not project_name:
        raise MaterializationError("root lock has no virtual workspace project")

    installed_to_imports = importlib.metadata.packages_distributions()
    forbidden: set[str] = set()
    for import_name, distribution_names in installed_to_imports.items():
        normalised = {_normalise_distribution_name(name) for name in distribution_names}
        if not normalised <= reachable:
            forbidden.add(import_name.partition(".")[0])
    policy = _LockedEvalPolicy(
        project_name=project_name,
        reachable_versions={
            name: frozenset(locked_versions.get(name, set())) for name in sorted(reachable)
        },
        forbidden_imports=tuple(sorted(forbidden)),
    )
    _audit_locked_runtime(Path(sys.prefix), policy)
    return policy


def _resolve_process_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if not argv:
        raise MaterializationError("isolated runner requires a non-empty command")
    requested = argv[0]
    executable_name = Path(requested).name
    if executable_name == "uv" and requested != "uv":
        raise MaterializationError("original command token must be exactly 'uv'")
    if requested == "uv":
        executable = shutil.which("uv")
        if executable is None:
            raise MaterializationError("declared locked runtime requires the uv executable")
    elif Path(requested).is_absolute():
        executable = requested
    elif executable_name.startswith("python"):
        executable = sys.executable
    else:
        search_path = os.pathsep.join(
            (str(Path(sys.executable).parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin")
        )
        executable = shutil.which(requested, path=search_path)
        if executable is None:
            raise MaterializationError(f"isolated runner executable is unavailable: {requested}")
    resolved_executable = (
        str(Path(executable).resolve()) if executable_name == "uv" else os.path.abspath(executable)
    )
    return (resolved_executable, *argv[1:])


def _sitecustomize_source(
    *,
    readable_roots: tuple[str, ...],
    writable_roots: tuple[str, ...],
    atomic_output_paths: tuple[str, ...],
    project_python_paths: tuple[str, ...],
    excluded_project_python_paths: tuple[str, ...],
    candidate_import_origins: tuple[tuple[str, str], ...],
    target_platform_system: str,
    target_platform_machine: str,
    forbidden_imports: tuple[str, ...],
    restrict_host_apis: bool,
) -> str:
    host_policy = ""
    if restrict_host_apis:
        host_policy = """
platform.node = _tuntun_deny_host_api
socket.gethostname = _tuntun_deny_host_api
uuid.getnode = _tuntun_deny_host_api
if hasattr(os, "uname"):
    def _tuntun_fixed_uname():
        return os.uname_result(
            (
                _tuntun_target_platform_system,
                "tuntun-isolated",
                "0",
                "deterministic",
                _tuntun_target_platform_machine,
            )
        )
    os.uname = _tuntun_fixed_uname
"""
    return f"""import _io
import builtins
import errno
import importlib
import importlib.util as _tuntun_importlib_util
import io
import os
import platform
import posix as _tuntun_posix
import socket
import stat
import subprocess
import sys
import uuid

_tuntun_readable_roots = tuple({json.dumps(readable_roots)})
_tuntun_writable_roots = tuple({json.dumps(writable_roots)})
_tuntun_atomic_outputs = tuple({json.dumps(atomic_output_paths)})
_tuntun_atomic_staging_paths = tuple(
    os.path.join(os.path.dirname(path), f".{{os.path.basename(path)}}.{{os.getpid()}}.tmp")
    for path in _tuntun_atomic_outputs
)
_tuntun_project_python_paths = tuple({json.dumps(project_python_paths)})
_tuntun_project_python_path_set = frozenset(
    os.path.abspath(path) for path in _tuntun_project_python_paths
)
_tuntun_excluded_project_python_paths = frozenset(
    {json.dumps(excluded_project_python_paths)}
)
_tuntun_candidate_import_origins = tuple({json.dumps(candidate_import_origins)})
_tuntun_target_platform_system = {json.dumps(target_platform_system)}
_tuntun_target_platform_machine = {json.dumps(target_platform_machine)}
_tuntun_forbidden_imports = frozenset({json.dumps(forbidden_imports)})
_tuntun_open = builtins.open
_tuntun_io_open = io.open
_tuntun_file_io = _io.FileIO
_tuntun_os_open = os.open
_tuntun_import = builtins.__import__
_tuntun_import_module = importlib.import_module
_tuntun_stat = os.stat
_tuntun_lstat = os.lstat
_tuntun_listdir = os.listdir
_tuntun_scandir = os.scandir
_tuntun_access = os.access
_tuntun_readlink = os.readlink
_tuntun_mkdir = os.mkdir
_tuntun_unlink = os.unlink
_tuntun_rmdir = os.rmdir
_tuntun_rename = os.rename
_tuntun_replace = os.replace
_tuntun_chmod = os.chmod
_tuntun_truncate = os.truncate
_tuntun_utime = os.utime
_tuntun_chdir = os.chdir
_tuntun_chown = getattr(os, "chown", None)
_tuntun_lchown = getattr(os, "lchown", None)
_tuntun_lchmod = getattr(os, "lchmod", None)
_tuntun_chflags = getattr(os, "chflags", None)
_tuntun_lchflags = getattr(os, "lchflags", None)
_tuntun_setxattr = getattr(os, "setxattr", None)
_tuntun_removexattr = getattr(os, "removexattr", None)
_tuntun_stdlib_tempfile = os.path.join(os.path.dirname(os.__file__), "tempfile.py")

def _tuntun_deny_host_api(*_args, **_kwargs):
    raise RuntimeError("nondeterministic host API forbidden")

def _tuntun_inside(candidate, roots):
    return any(candidate == root or candidate.startswith(root + os.sep) for root in roots)

def _tuntun_resolve(candidate):
    candidate = os.path.abspath(candidate)
    for _iteration in range(40):
        parts = candidate.split(os.sep)
        prefix = os.sep
        changed = False
        for index, part in enumerate(parts[1:], start=1):
            prefix = os.path.join(prefix, part)
            try:
                metadata = _tuntun_lstat(prefix)
            except (FileNotFoundError, NotADirectoryError):
                return candidate
            if not stat.S_ISLNK(metadata.st_mode):
                continue
            target = _tuntun_readlink(prefix)
            suffix = parts[index + 1:]
            if not os.path.isabs(target):
                target = os.path.join(os.path.dirname(prefix), target)
            candidate = os.path.abspath(os.path.join(target, *suffix))
            changed = True
            break
        if not changed:
            return candidate
    raise RuntimeError("isolated path has excessive symlink indirection")

def _tuntun_guard_path(value, *, write=False):
    if isinstance(value, int):
        return
    candidate = _tuntun_resolve(os.fspath(value))
    roots = _tuntun_writable_roots if write else _tuntun_readable_roots
    if candidate == "/dev/null":
        return
    if write and candidate in _tuntun_atomic_staging_paths:
        return
    if not _tuntun_inside(candidate, roots):
        capability = "writable" if write else "readable"
        raise PermissionError(
            f"nondeterministic host path outside isolated {{capability}} roots: {{candidate}}"
        )

def _tuntun_reject_custom_opener(file, args, kwargs):
    positional_opener = args[5] if len(args) > 5 else None
    opener = positional_opener if positional_opener is not None else kwargs.get("opener")
    if opener is None:
        return
    code = getattr(opener, "__code__", None)
    trusted_tempfile_opener = (
        getattr(opener, "__module__", None) == "tempfile"
        and getattr(opener, "__qualname__", None)
        in {{"NamedTemporaryFile.<locals>.opener", "TemporaryFile.<locals>.opener"}}
        and code is not None
        and os.path.abspath(code.co_filename) == os.path.abspath(_tuntun_stdlib_tempfile)
    )
    if not trusted_tempfile_opener:
        raise RuntimeError("custom opener is unsupported by deterministic path policy")
    _tuntun_guard_path(file, write=True)

def _tuntun_reject_descriptor_relative(kwargs, *names):
    if any(kwargs.get(name) is not None for name in names):
        raise RuntimeError("descriptor-relative path is unsupported by deterministic policy")

def _tuntun_reject_mutating_descriptor(value):
    if isinstance(value, int):
        raise RuntimeError("descriptor metadata mutation is forbidden by read-only policy")

def _tuntun_guarded_open(file, mode="r", *args, **kwargs):
    _tuntun_reject_custom_opener(file, args, kwargs)
    _tuntun_guard_path(file, write=any(flag in mode for flag in "wax+"))
    return _tuntun_open(file, mode, *args, **kwargs)

def _tuntun_guarded_io_open(file, mode="r", *args, **kwargs):
    _tuntun_reject_custom_opener(file, args, kwargs)
    _tuntun_guard_path(file, write=any(flag in mode for flag in "wax+"))
    return _tuntun_io_open(file, mode, *args, **kwargs)

class _TuntunGuardedFileIO(_tuntun_file_io):
    def __init__(self, file, mode="r", closefd=True, opener=None):
        if opener is not None:
            raise RuntimeError("custom opener is unsupported by deterministic path policy")
        _tuntun_guard_path(file, write=any(flag in mode for flag in "wax+"))
        super().__init__(file, mode=mode, closefd=closefd, opener=None)

def _tuntun_guarded_os_open(file, flags, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    _tuntun_guard_path(file, write=bool(flags & write_flags))
    return _tuntun_os_open(file, flags, *args, **kwargs)

def _tuntun_guarded_stat(path, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    try:
        _tuntun_guard_path(path)
    except PermissionError as error:
        raise FileNotFoundError(errno.ENOENT, str(error), os.fspath(path)) from error
    return _tuntun_stat(path, *args, **kwargs)

def _tuntun_guarded_lstat(path, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    try:
        _tuntun_guard_path(path)
    except PermissionError as error:
        raise FileNotFoundError(errno.ENOENT, str(error), os.fspath(path)) from error
    return _tuntun_lstat(path, *args, **kwargs)

def _tuntun_guarded_listdir(path="."):
    if isinstance(path, int):
        raise RuntimeError("descriptor-relative path is unsupported by deterministic policy")
    _tuntun_guard_path(path)
    return _tuntun_listdir(path)

def _tuntun_guarded_scandir(path="."):
    if isinstance(path, int):
        raise RuntimeError("descriptor-relative path is unsupported by deterministic policy")
    _tuntun_guard_path(path)
    return _tuntun_scandir(path)

def _tuntun_guarded_access(path, mode, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    _tuntun_guard_path(path, write=bool(mode & os.W_OK))
    return _tuntun_access(path, mode, *args, **kwargs)

def _tuntun_guarded_readlink(path, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    _tuntun_guard_path(path)
    return _tuntun_readlink(path, *args, **kwargs)

def _tuntun_guarded_mkdir(path, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    if not isinstance(path, int):
        candidate = _tuntun_resolve(os.fspath(path))
        if any(
            root.startswith(candidate.rstrip(os.sep) + os.sep)
            for root in _tuntun_writable_roots
        ):
            return _tuntun_mkdir(path, *args, **kwargs)
    _tuntun_guard_path(path, write=True)
    return _tuntun_mkdir(path, *args, **kwargs)

def _tuntun_guarded_unlink(path, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    _tuntun_guard_path(path, write=True)
    return _tuntun_unlink(path, *args, **kwargs)

def _tuntun_guarded_rmdir(path, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    _tuntun_guard_path(path, write=True)
    return _tuntun_rmdir(path, *args, **kwargs)

def _tuntun_guarded_rename(source, destination, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "src_dir_fd", "dst_dir_fd")
    _tuntun_guard_path(source, write=True)
    _tuntun_guard_path(destination, write=True)
    return _tuntun_rename(source, destination, *args, **kwargs)

def _tuntun_guarded_replace(source, destination, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "src_dir_fd", "dst_dir_fd")
    _tuntun_guard_path(source, write=True)
    _tuntun_guard_path(destination, write=True)
    return _tuntun_replace(source, destination, *args, **kwargs)

def _tuntun_guarded_chmod(path, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_chmod(path, *args, **kwargs)

def _tuntun_guarded_truncate(path, *args, **kwargs):
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_truncate(path, *args, **kwargs)

def _tuntun_guarded_utime(path, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_utime(path, *args, **kwargs)

def _tuntun_guarded_chown(path, *args, **kwargs):
    _tuntun_reject_descriptor_relative(kwargs, "dir_fd")
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_chown(path, *args, **kwargs)

def _tuntun_guarded_lchown(path, *args, **kwargs):
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_lchown(path, *args, **kwargs)

def _tuntun_guarded_lchmod(path, *args, **kwargs):
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_lchmod(path, *args, **kwargs)

def _tuntun_guarded_chflags(path, *args, **kwargs):
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_chflags(path, *args, **kwargs)

def _tuntun_guarded_lchflags(path, *args, **kwargs):
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_lchflags(path, *args, **kwargs)

def _tuntun_guarded_setxattr(path, *args, **kwargs):
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_setxattr(path, *args, **kwargs)

def _tuntun_guarded_removexattr(path, *args, **kwargs):
    _tuntun_reject_mutating_descriptor(path)
    _tuntun_guard_path(path, write=True)
    return _tuntun_removexattr(path, *args, **kwargs)

def _tuntun_deny_descriptor_mutation(*_args, **_kwargs):
    raise RuntimeError("descriptor metadata mutation is forbidden by read-only policy")

def _tuntun_guarded_chdir(path):
    if isinstance(path, int):
        raise RuntimeError("descriptor-relative path is unsupported by deterministic policy")
    _tuntun_guard_path(path)
    return _tuntun_chdir(path)

def _tuntun_guarded_fchdir(_descriptor):
    raise RuntimeError("descriptor-relative path is unsupported by deterministic policy")

def _tuntun_guarded_popen(args, *other_args, **kwargs):
    raise RuntimeError("nondeterministic host subprocess creation forbidden")

def _tuntun_locked_import(name, *args, **kwargs):
    top_level = name.partition(".")[0]
    if top_level in _tuntun_forbidden_imports:
        raise RuntimeError(
            f"locked eval environment forbids undeclared distribution import: {{top_level}}"
        )
    return _tuntun_import(name, *args, **kwargs)

def _tuntun_locked_import_module(name, package=None):
    candidate = name.lstrip(".").partition(".")[0]
    if candidate in _tuntun_forbidden_imports:
        raise RuntimeError(
            f"locked eval environment forbids undeclared distribution import: {{candidate}}"
        )
    return _tuntun_import_module(name, package)

builtins.open = _tuntun_guarded_open
io.open = _tuntun_guarded_io_open
_io.open = _tuntun_guarded_open
_io.FileIO = _TuntunGuardedFileIO
io.FileIO = _TuntunGuardedFileIO
os.open = _tuntun_guarded_os_open
os.stat = _tuntun_guarded_stat
os.lstat = _tuntun_guarded_lstat
os.listdir = _tuntun_guarded_listdir
os.scandir = _tuntun_guarded_scandir
os.access = _tuntun_guarded_access
os.readlink = _tuntun_guarded_readlink
os.mkdir = _tuntun_guarded_mkdir
os.unlink = _tuntun_guarded_unlink
os.remove = _tuntun_guarded_unlink
os.rmdir = _tuntun_guarded_rmdir
os.rename = _tuntun_guarded_rename
os.replace = _tuntun_guarded_replace
os.chmod = _tuntun_guarded_chmod
os.truncate = _tuntun_guarded_truncate
os.utime = _tuntun_guarded_utime
if hasattr(os, "chown"):
    os.chown = _tuntun_guarded_chown
if hasattr(os, "lchown"):
    os.lchown = _tuntun_guarded_lchown
if hasattr(os, "lchmod"):
    os.lchmod = _tuntun_guarded_lchmod
if hasattr(os, "chflags"):
    os.chflags = _tuntun_guarded_chflags
if hasattr(os, "lchflags"):
    os.lchflags = _tuntun_guarded_lchflags
if hasattr(os, "setxattr"):
    os.setxattr = _tuntun_guarded_setxattr
if hasattr(os, "removexattr"):
    os.removexattr = _tuntun_guarded_removexattr
for _tuntun_descriptor_mutation in ("fchmod", "fchown", "ftruncate"):
    if hasattr(os, _tuntun_descriptor_mutation):
        setattr(os, _tuntun_descriptor_mutation, _tuntun_deny_descriptor_mutation)
os.chdir = _tuntun_guarded_chdir
if hasattr(os, "fchdir"):
    os.fchdir = _tuntun_guarded_fchdir
os.symlink = _tuntun_deny_host_api
os.link = _tuntun_deny_host_api
subprocess.Popen = _tuntun_guarded_popen
os.system = _tuntun_deny_host_api
for _tuntun_escape_name in (
    "fork", "forkpty", "setsid", "setpgid", "posix_spawn", "posix_spawnp",
    "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
):
    if hasattr(os, _tuntun_escape_name):
        setattr(os, _tuntun_escape_name, _tuntun_deny_host_api)
    if hasattr(_tuntun_posix, _tuntun_escape_name):
        setattr(_tuntun_posix, _tuntun_escape_name, _tuntun_deny_host_api)
socket.getaddrinfo = _tuntun_deny_host_api
socket.create_connection = _tuntun_deny_host_api
socket.socket.connect = _tuntun_deny_host_api
socket.socket.connect_ex = _tuntun_deny_host_api
socket.socket.sendto = _tuntun_deny_host_api
if hasattr(socket.socket, "sendmsg"):
    socket.socket.sendmsg = _tuntun_deny_host_api
for _tuntun_guarded_name in (
    "open", "stat", "lstat", "listdir", "scandir", "access", "readlink", "mkdir",
    "unlink", "remove", "rmdir", "rename", "replace", "chmod", "truncate", "utime",
    "chown", "lchown", "lchmod", "chflags", "lchflags", "setxattr", "removexattr",
    "fchmod", "fchown", "ftruncate", "chdir", "fchdir",
):
    if hasattr(os, _tuntun_guarded_name):
        setattr(_tuntun_posix, _tuntun_guarded_name, getattr(os, _tuntun_guarded_name))
builtins.__import__ = _tuntun_locked_import
importlib.import_module = _tuntun_locked_import_module
{host_policy}
sys.path[:] = [
    path for path in sys.path
    if path
    and os.path.abspath(path) not in _tuntun_excluded_project_python_paths
    and os.path.abspath(path) not in _tuntun_project_python_path_set
]
for _tuntun_project_python_path in _tuntun_project_python_paths:
    if _tuntun_project_python_path not in sys.path:
        sys.path.append(_tuntun_project_python_path)
for _tuntun_candidate_module, _tuntun_expected_origin in _tuntun_candidate_import_origins:
    _tuntun_spec = _tuntun_importlib_util.find_spec(_tuntun_candidate_module)
    if (
        _tuntun_spec is None
        or _tuntun_spec.origin is None
        or os.path.realpath(_tuntun_spec.origin) != os.path.realpath(_tuntun_expected_origin)
    ):
        raise ImportError(
            f"candidate import origin mismatch: {{_tuntun_candidate_module}}"
        )
"""


def _prepare_verified_wheelhouse(root: Path, wheelhouse: Path, policy: _LockedEvalPolicy) -> None:
    """Copy complete lock-hashed wheel archives into a private offline wheelhouse."""

    artifact_source = root / ".tuntun" / "locked-wheels"
    wheelhouse.mkdir(mode=0o700, exist_ok=True)
    for name, expected_records in policy.registry_artifacts.items():
        matched = False
        for url, expected_digest in expected_records:
            filename = url.rsplit("/", 1)[-1]
            if not filename.endswith(".whl"):
                continue
            try:
                distribution, version, _, wheel_tags = parse_wheel_filename(filename)
            except InvalidWheelFilename:
                continue
            if (
                _normalise_distribution_name(distribution) != name
                or str(version) not in policy.reachable_versions.get(name, frozenset())
                or not wheel_tags.intersection(sys_tags())
            ):
                continue
            candidate = artifact_source / filename
            if not candidate.is_file():
                continue
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if digest != expected_digest:
                raise MaterializationError(
                    f"locked registry wheel archive for {name} has a sha256 mismatch"
                )
            shutil.copy2(candidate, wheelhouse / filename)
            matched = True
            break
        if not matched:
            raise MaterializationError(
                f"locked registry wheel archive for {name} is missing from the "
                "verified offline wheelhouse"
            )


def _run_verified_installer_command(
    command: Sequence[str], *, environment: dict[str, str], cwd: Path
) -> None:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise MaterializationError(
            f"verified offline installer could not start: {error}"
        ) from error
    try:
        stdout, stderr = process.communicate(timeout=45)
    except subprocess.TimeoutExpired as error:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise MaterializationError("verified offline installer exceeded 45 seconds") from error
    diagnostic = (stdout + stderr)[-16_384:]
    if process.returncode != 0:
        raise MaterializationError(
            "verified offline installer failed: " + diagnostic.decode(errors="replace")
        )


def _install_verified_wheelhouse(
    wheelhouse: Path,
    runtime_environment: Path,
    policy: _LockedEvalPolicy,
    *,
    uv_cache: Path,
    temporary_root: Path,
    home: Path,
) -> None:
    """Install lock-hashed wheels with uv's complete standard wheel semantics."""

    uv_executable = shutil.which("uv")
    if uv_executable is None:
        raise MaterializationError("verified offline installer requires the uv executable")
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": str(temporary_root),
        "UV_CACHE_DIR": str(uv_cache),
        "UV_LINK_MODE": "copy",
        "UV_NO_INDEX": "1",
        "UV_OFFLINE": "1",
        "UV_PYTHON_DOWNLOADS": "never",
    }
    _run_verified_installer_command(
        (
            str(Path(uv_executable).resolve()),
            "venv",
            "--no-project",
            "--python",
            sys.executable,
            "--no-python-downloads",
            "--offline",
            "--no-config",
            str(runtime_environment),
        ),
        environment=environment,
        cwd=runtime_environment.parent,
    )
    runtime_python = runtime_environment / "bin/python"
    if not runtime_python.is_file():
        raise MaterializationError("verified offline installer did not create exact Python")

    requirements: list[str] = []
    discovered: set[str] = set()
    for wheel in sorted(wheelhouse.glob("*.whl")):
        try:
            distribution, version, _, wheel_tags = parse_wheel_filename(wheel.name)
        except InvalidWheelFilename as error:
            raise MaterializationError(
                f"verified offline wheel filename is invalid: {wheel.name}"
            ) from error
        name = _normalise_distribution_name(distribution)
        if name in discovered or not wheel_tags.intersection(sys_tags()):
            raise MaterializationError(
                f"verified offline wheel selection is ambiguous or incompatible: {wheel.name}"
            )
        if str(version) not in policy.reachable_versions.get(name, frozenset()):
            raise MaterializationError(
                f"verified offline wheel version is outside locked closure: {wheel.name}"
            )
        discovered.add(name)
        requirements.append(
            f"{name}=={version} --hash=sha256:{hashlib.sha256(wheel.read_bytes()).hexdigest()}"
        )
    expected = (
        set(policy.registry_distributions)
        if policy.registry_distributions is not None
        else set(policy.reachable_versions) - {policy.project_name}
    )
    if discovered != expected:
        raise MaterializationError(
            "verified offline wheel closure differs from lock: "
            f"missing={sorted(expected - discovered)} extra={sorted(discovered - expected)}"
        )
    if requirements:
        requirement_path = runtime_environment.parent / "locked-requirements.txt"
        requirement_path.write_text("\n".join(requirements) + "\n", encoding="utf-8")
        _run_verified_installer_command(
            (
                str(Path(uv_executable).resolve()),
                "pip",
                "install",
                "--python",
                str(runtime_python),
                "--offline",
                "--no-index",
                "--find-links",
                str(wheelhouse),
                "--no-deps",
                "--require-hashes",
                "--only-binary",
                ":all:",
                "--exact",
                "--strict",
                "--link-mode",
                "copy",
                "--cache-dir",
                str(uv_cache),
                "--no-python-downloads",
                "-r",
                str(requirement_path),
            ),
            environment=environment,
            cwd=runtime_environment.parent,
        )


def _audit_locked_runtime(
    runtime_environment: Path,
    policy: _LockedEvalPolicy,
    *,
    verify_files: bool = False,
) -> None:
    site_packages = tuple(runtime_environment.glob("lib/python*/site-packages"))
    if len(site_packages) != 1:
        raise MaterializationError("locked offline runtime site-packages cannot be established")
    installed: dict[str, list[str]] = {}
    installed_distributions: dict[str, importlib.metadata.Distribution] = {}
    installed_import_roots: dict[str, set[str]] = {}
    recorded_site_files: set[Path] = set()
    runtime_root = runtime_environment.resolve()
    site_root = site_packages[0].resolve()
    for distribution in importlib.metadata.distributions(path=[str(site_root)]):
        name = distribution.metadata.get("Name")
        normalised_name: str | None = None
        if isinstance(name, str):
            normalised_name = _normalise_distribution_name(name)
            installed.setdefault(normalised_name, []).append(distribution.version)
            installed_distributions[normalised_name] = distribution
            installed_import_roots.setdefault(normalised_name, set())
        if verify_files:
            files = distribution.files
            if files is None or not files:
                raise MaterializationError("locked runtime distribution has no complete RECORD")
            for record in files:
                located = Path(str(distribution.locate_file(record))).resolve()
                try:
                    located.relative_to(runtime_root)
                except ValueError as error:
                    raise MaterializationError(
                        f"locked runtime RECORD escapes private environment: {record}"
                    ) from error
                if not located.is_file():
                    raise MaterializationError(f"locked runtime RECORD file is missing: {record}")
                with contextlib.suppress(ValueError):
                    relative = located.relative_to(site_root)
                    recorded_site_files.add(located)
                    if (
                        normalised_name is not None
                        and relative.parts
                        and ".dist-info" not in relative.parts[0]
                    ):
                        import_root = relative.parts[0].partition(".")[0]
                        if import_root.isidentifier():
                            installed_import_roots[normalised_name].add(import_root)
                if record.size is not None and located.stat().st_size != record.size:
                    raise MaterializationError(f"locked runtime RECORD size differs: {record}")
                if record.hash is not None:
                    try:
                        digest = hashlib.new(record.hash.mode, located.read_bytes()).digest()
                    except ValueError as error:
                        raise MaterializationError(
                            f"locked runtime RECORD hash algorithm is unsupported: {record}"
                        ) from error
                    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                    if encoded != record.hash.value:
                        raise MaterializationError(f"locked runtime RECORD hash differs: {record}")
                elif not str(record).endswith(".dist-info/RECORD"):
                    raise MaterializationError(f"locked runtime RECORD hash is absent: {record}")
    duplicates = {name for name, versions in installed.items() if len(versions) != 1}
    expected = (
        set(policy.registry_distributions)
        if policy.registry_distributions is not None
        else set(policy.reachable_versions) - {policy.project_name}
    )
    extras = set(installed) - expected
    if duplicates or extras:
        raise MaterializationError(
            "locked runtime distribution closure has "
            f"duplicates={sorted(duplicates)} extras={sorted(extras)}"
        )
    for name in sorted(expected):
        versions = policy.reachable_versions.get(name, frozenset())
        if not versions:
            raise MaterializationError(
                f"locked reachable distribution {name} lacks an exact version"
            )
        installed_versions = installed.get(name)
        if installed_versions is None:
            raise MaterializationError(
                f"locked reachable distribution {name} is missing from the offline runtime"
            )
        installed_version = installed_versions[0]
        if installed_version not in versions:
            raise MaterializationError(
                f"locked reachable distribution {name} has runtime version {installed_version}, "
                f"expected {sorted(versions)}"
            )
    if set(installed) != expected:
        raise MaterializationError("locked runtime installed distribution closure is incomplete")
    if policy.registry_distributions is not None:
        candidate_collisions = {
            name: sorted(import_roots & _CANDIDATE_IMPORT_ROOTS)
            for name, import_roots in installed_import_roots.items()
            if import_roots & _CANDIDATE_IMPORT_ROOTS
        }
        if candidate_collisions:
            raise MaterializationError(
                f"locked registry wheel owns a candidate import root: {candidate_collisions}"
            )
        if "fasttext-predict" in expected and (
            frozenset(installed_import_roots.get("fasttext-predict", set()))
            != _FASTTEXT_PREDICT_IMPORT_ROOTS
            or policy.dependency_graph.get("fasttext-predict", frozenset())
        ):
            raise MaterializationError(
                "fasttext-predict installed API/offline closure differs from reviewed evidence"
            )
        selected_versions = {
            name: set(versions) for name, versions in policy.reachable_versions.items()
        }
        for name in sorted(expected):
            distribution = installed_distributions[name]
            requirement_values = distribution.requires or []
            requirements = tuple(
                _canonical_requirement_from_text(
                    value,
                    description=f"locked runtime {name} METADATA Requires-Dist",
                    allow_inactive_optional_extra=True,
                )
                for value in requirement_values
            )
            active = tuple(requirement for requirement in requirements if requirement.active)
            if {requirement.name for requirement in active} != set(
                policy.dependency_graph.get(name, frozenset())
            ):
                raise MaterializationError(
                    f"locked runtime {name} METADATA requirement graph differs from eval lock"
                )
            for requirement in active:
                _validate_selected_requirement(
                    requirement,
                    versions=selected_versions,
                    description=f"locked runtime {name} METADATA",
                )
    if verify_files:
        actual_site_files = {
            path.resolve()
            for path in site_root.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        }
        uv_bootstrap_files = {
            site_root / "_virtualenv.pth",
            site_root / "_virtualenv.py",
        }
        allowed_site_files = recorded_site_files | {
            path for path in uv_bootstrap_files if path.is_file()
        }
        if actual_site_files != allowed_site_files:
            unrecorded = sorted(
                str(path.relative_to(site_root)) for path in actual_site_files - allowed_site_files
            )
            missing = sorted(
                str(path.relative_to(site_root)) for path in allowed_site_files - actual_site_files
            )
            raise MaterializationError(
                "locked runtime installed file closure differs from wheel RECORDs: "
                f"unrecorded={unrecorded} missing={missing}"
            )


def _runtime_file_manifest(runtime_environment: Path) -> dict[str, tuple[int, str]]:
    root = runtime_environment.resolve()
    return {
        path.relative_to(root).as_posix(): (
            path.stat().st_mode,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _uv_run_runtime(command: Sequence[str]) -> str | None:
    """Classify the only uv wrappers whose executed runtime can be audited exactly."""

    if Path(command[0]).name != "uv":
        return None
    if len(command) < 3 or command[1] != "run":
        raise MaterializationError("declared uv runtime must execute uv run")
    if tuple(command[2:5]) == ("--project", "evals", "--locked"):
        if len(command) < 6 or command[5].startswith("-"):
            raise MaterializationError(
                "declared eval uv runtime is outside the closed invocation grammar"
            )
        return "eval"
    if command[2] == "--locked":
        if len(command) < 4 or command[3].startswith("-"):
            raise MaterializationError(
                "declared root uv runtime is outside the closed invocation grammar"
            )
        return "root"
    if not command[2].startswith("-"):
        return "root"
    raise MaterializationError("declared uv runtime is outside the closed invocation grammar")


def run_isolated_process(
    argv: Sequence[str],
    *,
    root: Path,
    timeout_seconds: float = GENERATOR_TIMEOUT_SECONDS,
    diagnostic_limit: int = GENERATOR_DIAGNOSTIC_LIMIT,
    restrict_host_apis: bool = True,
    forbidden_imports: Sequence[str] = (),
    writable_paths: Sequence[str | Path] = (),
    atomic_output_paths: Sequence[str | Path] = (),
) -> _GeneratorRun:
    """Constrain trusted plan code for deterministic validation.

    This is intentionally not an operating-system security sandbox. The policy
    removes ordinary Python host-state and process escape APIs; untrusted native
    code must not be executed through this validator.
    """

    command = _resolve_process_argv(argv)
    uv_runtime = _uv_run_runtime(command)
    is_uv = uv_runtime is not None
    is_eval_uv = uv_runtime == "eval"
    locked_policy = _locked_eval_import_policy(root) if is_eval_uv else None
    if is_eval_uv and locked_policy is None:
        raise MaterializationError("declared eval uv runtime has no materialized eval lock")
    root_policy = None if is_eval_uv else _root_locked_import_policy()
    if is_uv and not is_eval_uv:
        trusted_workspace = Path(__file__).resolve().parents[1]
        for relative in ("pyproject.toml", "uv.lock"):
            candidate = root / relative
            trusted = trusted_workspace / relative
            if not candidate.is_file() or candidate.read_bytes() != trusted.read_bytes():
                raise MaterializationError(
                    f"declared root uv runtime does not match the trusted root lock: {relative}"
                )
    policy_imports = locked_policy.forbidden_imports if locked_policy is not None else ()
    root_imports = root_policy.forbidden_imports if root_policy is not None else ()
    effective_forbidden = tuple(
        sorted(set(policy_imports) | set(root_imports) | set(forbidden_imports))
    )

    with tempfile.TemporaryDirectory(prefix="tuntun-plan-isolated-runtime-") as temporary:
        runtime = Path(temporary)
        locked_runtime_manifest: dict[str, tuple[int, str]] | None = None
        policy_root = runtime / "policy"
        home = runtime / "home"
        temporary_root = runtime / "tmp"
        runtime_environment = runtime / "uv-project"
        uv_cache = runtime / "uv-cache"
        wheelhouse = runtime / "wheelhouse"
        evidence_root = runtime / "evidence"
        for directory in (
            policy_root,
            home,
            temporary_root,
            uv_cache,
            wheelhouse,
            evidence_root,
        ):
            directory.mkdir(mode=0o700)
        if locked_policy is not None:
            _prepare_verified_wheelhouse(root, wheelhouse, locked_policy)
            _install_verified_wheelhouse(
                wheelhouse,
                runtime_environment,
                locked_policy,
                uv_cache=uv_cache,
                temporary_root=temporary_root,
                home=home,
            )
            _audit_locked_runtime(runtime_environment, locked_policy, verify_files=True)
            locked_runtime_manifest = _runtime_file_manifest(runtime_environment)
        python_roots = {
            Path(sys.executable).resolve().parent,
            Path(sys.prefix).resolve(),
            Path(sys.base_prefix).resolve(),
        }
        readable_roots = tuple(
            sorted(
                str(path)
                for path in {
                    root.absolute(),
                    root.resolve(),
                    runtime.absolute(),
                    runtime.resolve(),
                    *python_roots,
                }
            )
        )
        selected_writable_roots = {
            home.absolute(),
            home.resolve(),
            temporary_root.absolute(),
            temporary_root.resolve(),
            evidence_root.absolute(),
            evidence_root.resolve(),
        }
        for selected in writable_paths:
            candidate = (
                (root / selected).resolve()
                if not Path(selected).is_absolute()
                else Path(selected).resolve()
            )
            try:
                candidate.relative_to(root.resolve())
            except ValueError as error:
                raise MaterializationError(
                    f"isolated writable path escapes materialized root: {selected}"
                ) from error
            selected_writable_roots.add(candidate)
        writable_roots = tuple(sorted(str(path) for path in selected_writable_roots))
        selected_atomic_outputs: set[Path] = set()
        for selected in atomic_output_paths:
            candidate = (
                (root / selected).resolve()
                if not Path(selected).is_absolute()
                else Path(selected).resolve()
            )
            try:
                candidate.relative_to(root.resolve())
            except ValueError as error:
                raise MaterializationError(
                    f"isolated atomic output escapes materialized root: {selected}"
                ) from error
            if candidate not in selected_writable_roots:
                raise MaterializationError(
                    f"isolated atomic output is not a declared writable path: {selected}"
                )
            selected_atomic_outputs.add(candidate)
        if locked_policy is not None:
            candidate_python_paths = tuple(
                root / locked_policy.candidate_projects[name].source_root
                for name in _EVAL_CANDIDATE_BINDINGS
                if name in locked_policy.candidate_projects
            )
            selected_project_paths = (*candidate_python_paths, root)
            candidate_import_origins = tuple(
                (
                    _EVAL_CANDIDATE_BINDINGS[name][3],
                    str(
                        (
                            root
                            / locked_policy.candidate_projects[name].source_root
                            / _EVAL_CANDIDATE_BINDINGS[name][3]
                            / "__init__.py"
                        ).resolve()
                    ),
                )
                for name in _EVAL_CANDIDATE_BINDINGS
                if name in locked_policy.candidate_projects
            )
        else:
            selected_project_paths = (
                root,
                root / "apps/core/src",
                root / "apps/edge/src",
                root / "packages/contracts/src",
                root / "packages/testing/src",
            )
            candidate_import_origins = ()
        project_python_paths = tuple(
            str(path.resolve()) for path in selected_project_paths if path.is_dir()
        )
        project_source_suffixes = {
            ("apps", "core", "src"),
            ("apps", "edge", "src"),
            ("packages", "contracts", "src"),
            ("packages", "testing", "src"),
        }
        excluded_project_python_paths: set[str] = set()
        candidate_project_paths = {Path(path).absolute() for path in project_python_paths} | {
            Path(path).resolve() for path in project_python_paths
        }
        for raw_path in sys.path:
            if not raw_path:
                continue
            absolute = Path(raw_path).absolute()
            resolved = Path(raw_path).resolve()
            if not any(
                tuple(candidate.parts[-len(suffix) :]) == suffix
                for candidate in (absolute, resolved)
                for suffix in project_source_suffixes
            ):
                continue
            if absolute not in candidate_project_paths:
                excluded_project_python_paths.add(str(absolute))
            if resolved not in candidate_project_paths:
                excluded_project_python_paths.add(str(resolved))
        marker_environment = default_environment()
        (policy_root / "sitecustomize.py").write_text(
            _sitecustomize_source(
                readable_roots=readable_roots,
                writable_roots=writable_roots,
                atomic_output_paths=tuple(sorted(str(path) for path in selected_atomic_outputs)),
                project_python_paths=project_python_paths,
                excluded_project_python_paths=tuple(sorted(excluded_project_python_paths)),
                candidate_import_origins=candidate_import_origins,
                target_platform_system=marker_environment["platform_system"],
                target_platform_machine=marker_environment["platform_machine"],
                forbidden_imports=effective_forbidden,
                restrict_host_apis=restrict_host_apis,
            ),
            encoding="utf-8",
        )
        uv_executable = shutil.which("uv")
        path_entries = (
            [str(runtime_environment / "bin")]
            if is_eval_uv
            else [
                str(Path(sys.executable).parent),
                "/usr/bin",
                "/bin",
                "/usr/sbin",
                "/sbin",
            ]
        )
        if uv_executable is not None and not is_eval_uv:
            path_entries.insert(1, str(Path(uv_executable).resolve().parent))
        environment = {
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.pathsep.join(path_entries),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": str(policy_root),
            "PYTHONSAFEPATH": "1",
            "SOURCE_DATE_EPOCH": "0",
            "TMPDIR": str(temporary_root),
            "TZ": "UTC",
            "UV_CACHE_DIR": str(uv_cache),
            "UV_FIND_LINKS": str(wheelhouse),
            "UV_LINK_MODE": "copy",
            "UV_NO_INDEX": "1",
            "UV_NO_SYNC": "1",
            "UV_OFFLINE": "1",
            "UV_PROJECT_ENVIRONMENT": str(
                runtime_environment if is_eval_uv else Path(sys.prefix).resolve()
            ),
            "UV_LOCKED": "1",
            "UV_PYTHON": str(runtime_environment / "bin/python") if is_eval_uv else sys.executable,
            "UV_PYTHON_DOWNLOADS": "never",
        }
        try:
            process = subprocess.Popen(
                command,
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as error:
            raise MaterializationError(
                f"isolated runner could not execute {command[0]}: {error}"
            ) from error
        if process.stdout is None or process.stderr is None:
            raise MaterializationError("isolated runner diagnostic pipes are unavailable")

        def terminate_before_reap() -> None:
            # The direct child is deliberately left unreaped until the complete
            # owned process group has been signalled. Detachment APIs are denied
            # inside the child policy, so every descendant remains in this group.
            try:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            finally:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        stream_selector = selectors.DefaultSelector()
        stream_selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        stream_selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        totals = {"stdout": 0, "stderr": 0}
        tails = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout_seconds
        output_exceeded = False

        try:
            while stream_selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout_seconds)
                for key, _ in stream_selector.select(min(remaining, 0.05)):
                    file_object = key.fileobj
                    descriptor = (
                        file_object if isinstance(file_object, int) else file_object.fileno()
                    )
                    chunk = os.read(descriptor, 65_536)
                    if not chunk:
                        stream_selector.unregister(file_object)
                        continue
                    name = key.data
                    totals[name] += len(chunk)
                    tails[name].extend(chunk)
                    if len(tails[name]) > 16_384:
                        del tails[name][:-16_384]
                    if totals[name] > diagnostic_limit:
                        output_exceeded = True
                        break
                if output_exceeded:
                    terminate_before_reap()
                    break
            if output_exceeded:
                returncode = process.returncode if process.returncode is not None else -9
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout_seconds)
                returncode = process.wait(timeout=remaining)
                if is_eval_uv and locked_policy is not None:
                    _audit_locked_runtime(runtime_environment, locked_policy, verify_files=True)
                    if _runtime_file_manifest(runtime_environment) != locked_runtime_manifest:
                        raise MaterializationError(
                            "locked runtime files changed while executing declared command"
                        )
        except BaseException:
            if process.returncode is None:
                terminate_before_reap()
            raise
        finally:
            stream_selector.close()
            for stream in (process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()
        diagnostic = bytes(tails["stdout"] + tails["stderr"])
    return _GeneratorRun(
        returncode=returncode,
        diagnostic=diagnostic,
        output_exceeded=output_exceeded,
    )


def _run_generator_process(
    argv: tuple[str, ...],
    *,
    root: Path,
    environment: dict[str, str],
    timeout_seconds: float | None = None,
    diagnostic_limit: int = GENERATOR_DIAGNOSTIC_LIMIT,
    restrict_host_apis: bool = True,
    writable_paths: Sequence[str | Path] = (),
) -> _GeneratorRun:
    del environment
    return run_isolated_process(
        argv,
        root=root,
        timeout_seconds=(GENERATOR_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds),
        diagnostic_limit=diagnostic_limit,
        restrict_host_apis=restrict_host_apis,
        writable_paths=writable_paths,
    )


def _generator_environment(root: Path) -> dict[str, str]:
    python_paths = (
        str(root),
        str(root / "apps/core/src"),
        str(root / "apps/edge/src"),
        str(root / "packages/contracts/src"),
        str(root / "packages/testing/src"),
    )
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONPATH": os.pathsep.join(python_paths),
        "SOURCE_DATE_EPOCH": "0",
        "TZ": "UTC",
    }


def _resolved_generator_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    # Preserve the declared token until the isolated runner has enforced the
    # canonical-wrapper policy; resolution happens exactly once there.
    return argv


def run_materialized_python(
    arguments: Sequence[str],
    *,
    root: Path,
    timeout_seconds: float = 15,
    diagnostic_limit: int = GENERATOR_DIAGNOSTIC_LIMIT,
    restrict_host_apis: bool = True,
    forbidden_imports: Sequence[str] = (),
) -> _GeneratorRun:
    """Run materialized Python under the deterministic offline policy."""

    return run_isolated_process(
        (sys.executable, *arguments),
        root=root,
        timeout_seconds=timeout_seconds,
        diagnostic_limit=diagnostic_limit,
        restrict_host_apis=restrict_host_apis,
        forbidden_imports=forbidden_imports,
    )


def _execute_generator_once(
    files: dict[str, bytes], generator: DeterministicGenerator, *, task_number: int
) -> dict[str, bytes]:
    with tempfile.TemporaryDirectory(prefix="tuntun-plan-generator-") as temporary:
        root = Path(temporary)
        write_materialized_tree(root, files)
        argv = _resolved_generator_argv(generator.argv)
        try:
            result = run_isolated_process(
                argv,
                root=root,
                writable_paths=(generator.output,),
                atomic_output_paths=(generator.output,),
            )
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
            if "outside isolated writable roots" in diagnostic:
                raise MaterializationError(
                    f"Task {task_number:02d} generator {generator.name}: "
                    f"undeclared outputs rejected: {diagnostic}"
                )
            raise MaterializationError(
                f"Task {task_number:02d} generator {generator.name}: exit "
                f"{result.returncode}: {diagnostic}"
            )
        output_path = root / generator.output
        staging_residue = tuple(output_path.parent.glob(f".{output_path.name}.*.tmp"))
        if staging_residue:
            raise MaterializationError(
                f"Task {task_number:02d} generator {generator.name}: "
                "atomic staging residue was not removed"
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
            try:
                command = _resolved_generator_argv(check_argv)
                result = run_isolated_process(command, root=root)
            except subprocess.TimeoutExpired as error:
                raise MaterializationError(
                    f"Task {task_number:02d} generator {generator.name}: check exceeded 15 seconds"
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


def foundation_snapshot_from_ref(repository_root: Path, foundation_ref: str) -> FoundationSnapshot:
    """Resolve and archive one immutable Foundation commit object."""

    resolved = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "rev-parse",
            "--verify",
            f"{foundation_ref}^{{commit}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    archive = subprocess.run(
        ["git", "-C", str(repository_root), "archive", "--format=tar", resolved],
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
    return FoundationSnapshot(files=files, source_commit=resolved)


def foundation_files_from_ref(repository_root: Path, foundation_ref: str) -> dict[str, bytes]:
    """Compatibility wrapper returning files from one immutable Foundation commit."""

    return foundation_snapshot_from_ref(repository_root, foundation_ref).files


def plan_document_from_ref(repository_root: Path, plan_ref: str, plan_path: str) -> PlanDocument:
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
    return replace(parse_plan_text(source), source_commit=resolved, source_path=canonical_path)


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
    foundation = foundation_snapshot_from_ref(repository_root, args.foundation_ref)
    document = plan_document_from_ref(repository_root, args.plan_ref, args.plan_path)
    files = materialize_document(document, foundation_files=foundation.files)
    write_materialized_tree(args.destination.resolve(), files)
    print(
        f"materialized {len(files)} files from Foundation {foundation.source_commit} "
        f"and plan {document.source_commit}:{document.source_path} "
        f"into {args.destination.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
