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
import contextlib
import importlib.metadata
import io
import json
import os
import re
import selectors
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
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
    return re.sub(r"[-_.]+", "-", value).casefold()


def _locked_eval_import_policy(root: Path) -> tuple[str, ...]:
    """Validate the eval lock and return installed imports outside its closure."""

    project_path = root / "evals/pyproject.toml"
    lock_path = root / "evals/uv.lock"
    if not project_path.is_file() and not lock_path.is_file():
        return ()
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
    declared_dependencies: dict[str, str | None] = {}
    for dependency in dependencies:
        match = _DISTRIBUTION_NAME.match(dependency.strip())
        if match is None:
            raise MaterializationError(f"locked eval project dependency is invalid: {dependency!r}")
        name = _normalise_distribution_name(match.group())
        exact_match = _EXACT_VERSION.search(dependency)
        declared_dependencies[name] = exact_match.group(1) if exact_match is not None else None

    locked_versions: dict[str, set[str]] = {}
    dependency_graph: dict[str, set[str]] = {}
    root_metadata_dependencies: set[str] = set()
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise MaterializationError("locked eval package record is invalid")
        name = _normalise_distribution_name(package["name"])
        dependency_graph.setdefault(name, set())
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
            dependency_graph[name].add(_normalise_distribution_name(dependency["name"]))
        if name == project_name:
            metadata = package.get("metadata")
            if isinstance(metadata, dict):
                requires_dist = metadata.get("requires-dist", [])
                if not isinstance(requires_dist, list):
                    raise MaterializationError("locked eval project dependency metadata is invalid")
                for dependency in requires_dist:
                    if not isinstance(dependency, dict) or not isinstance(
                        dependency.get("name"), str
                    ):
                        raise MaterializationError(
                            "locked eval project dependency metadata record is invalid"
                        )
                    root_metadata_dependencies.add(_normalise_distribution_name(dependency["name"]))
        source = package.get("source")
        if isinstance(source, dict) and source.get("registry") is not None:
            artifacts = []
            if isinstance(package.get("sdist"), dict):
                artifacts.append(package["sdist"])
            wheels = package.get("wheels", [])
            if isinstance(wheels, list):
                artifacts.extend(item for item in wheels if isinstance(item, dict))
            hashes = [item.get("hash") for item in artifacts]
            if not hashes or any(
                not isinstance(value, str)
                or (match := _SHA256.fullmatch(value)) is None
                or set(match.group(1)) == {"0"}
                for value in hashes
            ):
                raise MaterializationError(
                    f"locked eval package {name} lacks trustworthy sha256 artifacts"
                )

    if project_name not in dependency_graph:
        raise MaterializationError("locked eval project package is absent from evals/uv.lock")
    declared_names = set(declared_dependencies)
    if dependency_graph[project_name] != declared_names or (
        root_metadata_dependencies and root_metadata_dependencies != declared_names
    ):
        raise MaterializationError(
            "locked eval project dependency closure differs from evals/pyproject.toml"
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
    unreachable = set(dependency_graph) - reachable
    if unreachable:
        raise MaterializationError(
            f"locked eval package closure contains undeclared packages: {sorted(unreachable)}"
        )

    for name, exact_version in declared_dependencies.items():
        versions = locked_versions.get(name)
        if not versions:
            raise MaterializationError(
                f"locked eval dependency {name} is absent from evals/uv.lock"
            )
        if exact_version is not None and exact_version not in versions:
            raise MaterializationError(
                f"locked eval dependency {name} version differs between project and lock"
            )

    installed_to_imports = importlib.metadata.packages_distributions()
    for distribution_name in sorted(reachable):
        versions = locked_versions.get(distribution_name, set())
        if not versions:
            continue
        try:
            installed_version = importlib.metadata.version(distribution_name)
        except importlib.metadata.PackageNotFoundError:
            continue
        if installed_version not in versions:
            raise MaterializationError(
                f"locked eval dependency {distribution_name} version {versions} does not "
                f"match runtime {installed_version}"
            )

    allowed = reachable
    forbidden: set[str] = set()
    for import_name, distribution_names in installed_to_imports.items():
        if not distribution_names:
            continue
        normalised = {_normalise_distribution_name(name) for name in distribution_names}
        if not normalised <= allowed:
            forbidden.add(import_name.partition(".")[0])
    return tuple(sorted(forbidden))


def _run_generator_process(
    argv: tuple[str, ...],
    *,
    root: Path,
    environment: dict[str, str],
    timeout_seconds: float | None = None,
    diagnostic_limit: int = GENERATOR_DIAGNOSTIC_LIMIT,
    restrict_host_apis: bool = True,
) -> _GeneratorRun:
    effective_timeout = GENERATOR_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    forbidden_imports = _locked_eval_import_policy(root)
    with tempfile.TemporaryDirectory(prefix="tuntun-plan-generator-runtime-") as isolated_runtime:
        runtime = Path(isolated_runtime)
        policy = runtime / "policy"
        if restrict_host_apis or forbidden_imports:
            policy.mkdir(mode=0o700)
            host_policy = ""
            if restrict_host_apis:
                host_policy = """
_tuntun_host_files = frozenset({
    "/etc/hostname",
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    "/proc/sys/kernel/hostname",
    "/Library/Preferences/SystemConfiguration/preferences.plist",
    "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist",
    "/var/db/SystemKey",
})
_tuntun_host_commands = frozenset({
    "hostname", "ioreg", "scutil", "system_profiler", "sysctl", "uname"
})
_tuntun_open = builtins.open
_tuntun_io_open = io.open
_tuntun_popen = subprocess.Popen

def _tuntun_guard_path(value):
    try:
        candidate = os.path.realpath(os.fspath(value))
    except TypeError:
        return
    if candidate in _tuntun_host_files:
        raise RuntimeError("nondeterministic host identity file forbidden")

def _tuntun_guard_command(command):
    if isinstance(command, (list, tuple)) and command:
        executable = os.path.basename(os.fspath(command[0])).casefold()
    elif isinstance(command, (str, bytes)):
        decoded = os.fsdecode(command).casefold()
        executable = next(
            (name for name in _tuntun_host_commands if name in decoded), ""
        )
    else:
        executable = ""
    if executable in _tuntun_host_commands:
        raise RuntimeError("nondeterministic host identity command forbidden")

def _tuntun_guarded_open(file, *args, **kwargs):
    _tuntun_guard_path(file)
    return _tuntun_open(file, *args, **kwargs)

def _tuntun_guarded_io_open(file, *args, **kwargs):
    _tuntun_guard_path(file)
    return _tuntun_io_open(file, *args, **kwargs)

def _tuntun_guarded_popen(args, *other_args, **kwargs):
    _tuntun_guard_command(args)
    return _tuntun_popen(args, *other_args, **kwargs)

def _tuntun_guarded_system(command):
    _tuntun_guard_command(command)
    return _tuntun_deny_host_api()

builtins.open = _tuntun_guarded_open
io.open = _tuntun_guarded_io_open
subprocess.Popen = _tuntun_guarded_popen
os.system = _tuntun_guarded_system
platform.node = _tuntun_deny_host_api
socket.gethostname = _tuntun_deny_host_api
socket.getaddrinfo = _tuntun_deny_host_api
socket.create_connection = _tuntun_deny_host_api
uuid.getnode = _tuntun_deny_host_api
if hasattr(os, "uname"):
    os.uname = _tuntun_deny_host_api
"""
            (policy / "sitecustomize.py").write_text(
                f"""import builtins
import io
import os
import platform
import socket
import subprocess
import uuid

def _tuntun_deny_host_api(*_args, **_kwargs):
    raise RuntimeError("nondeterministic host API forbidden")

{host_policy}
_tuntun_forbidden_imports = frozenset({json.dumps(forbidden_imports)})
_tuntun_import = builtins.__import__

def _tuntun_locked_import(name, *args, **kwargs):
    top_level = name.partition(".")[0]
    if top_level in _tuntun_forbidden_imports:
        raise RuntimeError(
            f"locked eval environment forbids undeclared distribution import: {{top_level}}"
        )
    return _tuntun_import(name, *args, **kwargs)

builtins.__import__ = _tuntun_locked_import
for _key in ("UV_CACHE_DIR", "UV_PROJECT_ENVIRONMENT", "UV_PYTHON"):
    os.environ.pop(_key, None)
""",
                encoding="utf-8",
            )
        isolated_environment = dict(environment)
        isolated_environment.update(
            {
                "HOME": str(runtime / "home"),
                "TMPDIR": str(runtime / "tmp"),
                "UV_CACHE_DIR": str(runtime / "uv-cache"),
                "XDG_CACHE_HOME": str(runtime / "xdg-cache"),
            }
        )
        existing_python_path = isolated_environment.get("PYTHONPATH", "")
        isolated_environment["PYTHONPATH"] = os.pathsep.join(
            value
            for value in (
                str(policy) if restrict_host_apis or forbidden_imports else "",
                existing_python_path,
            )
            if value
        )
        for directory in (
            isolated_environment["HOME"],
            isolated_environment["TMPDIR"],
            isolated_environment["UV_CACHE_DIR"],
            isolated_environment["XDG_CACHE_HOME"],
        ):
            Path(directory).mkdir(parents=True, exist_ok=True)
        process = subprocess.Popen(
            argv,
            cwd=root,
            env=isolated_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:
            raise MaterializationError("generator diagnostic pipes are unavailable")
        stream_selector = selectors.DefaultSelector()
        stream_selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        stream_selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        totals = {"stdout": 0, "stderr": 0}
        tails = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + effective_timeout
        output_exceeded = False

        def terminate() -> None:
            # The direct child may have already exited while a descendant keeps
            # a diagnostic pipe open.  Its process-group ID remains the direct
            # child's PID, so always kill the group before reaping the parent.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            if process.poll() is None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        try:
            while stream_selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, effective_timeout)
                for key, _ in stream_selector.select(min(remaining, 0.25)):
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
                    if len(tails[name]) > 2048:
                        del tails[name][:-2048]
                    if totals[name] > diagnostic_limit:
                        output_exceeded = True
                        break
                if output_exceeded:
                    terminate()
                    break
            if output_exceeded:
                returncode = process.returncode if process.returncode is not None else -9
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, effective_timeout)
                returncode = process.wait(timeout=remaining)
        except BaseException:
            terminate()
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
    if argv[0] == "uv":
        # The runtime policy verifies the selected interpreter's imported
        # distribution closure and versions against the materialized eval lock.
        # Running uv here would require a mutable cache or network bootstrap;
        # both are forbidden during deterministic plan validation.
        return (sys.executable, *argv[6:])
    return (sys.executable, *argv[1:])


def run_materialized_python(
    arguments: Sequence[str],
    *,
    root: Path,
    timeout_seconds: float = 15,
    diagnostic_limit: int = GENERATOR_DIAGNOSTIC_LIMIT,
    restrict_host_apis: bool = True,
) -> _GeneratorRun:
    """Run materialized Python under the deterministic offline policy."""

    return _run_generator_process(
        (sys.executable, *arguments),
        root=root,
        environment=_generator_environment(root),
        timeout_seconds=timeout_seconds,
        diagnostic_limit=diagnostic_limit,
        restrict_host_apis=restrict_host_apis,
    )


def _execute_generator_once(
    files: dict[str, bytes], generator: DeterministicGenerator, *, task_number: int
) -> dict[str, bytes]:
    with tempfile.TemporaryDirectory(prefix="tuntun-plan-generator-") as temporary:
        root = Path(temporary)
        write_materialized_tree(root, files)
        argv = _resolved_generator_argv(generator.argv)
        environment = _generator_environment(root)
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
            environment = _generator_environment(root)
            try:
                command = _resolved_generator_argv(check_argv)
                result = _run_generator_process(
                    command,
                    root=root,
                    environment=environment,
                )
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
