from __future__ import annotations

import argparse
import asyncio
import base64
import errno
import gc
import inspect
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any, Never

MIN_TURNS = 1
MAX_TURNS = 10_000
MAX_TOTAL_TURNS = 10_000
_CHILD_TIMEOUT_SECONDS = 120.0
_CHILD_CLEANUP_SECONDS = 5.0
_CHILD_POLL_SECONDS = 0.01
_CHILD_SIGNAL_SETTLE_SECONDS = 0.05
_MAX_CHILD_OUTPUT_BYTES = 65_536
# Includes base64 plus canonical metadata for all 32 maximum-size scenario inputs.
_MAX_CHILD_CONFIGURATION_BYTES = 4_194_304
_MAX_SCENARIO_BYTES = 65_536
_MAX_SCENARIOS = 32
_SCENARIO_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CHILD_BOOTSTRAP = """
from __future__ import annotations

import os
import resource
import runpy
import signal
import socket
import sys
import time
from pathlib import Path


class _NetworkDeniedError(RuntimeError):
    pass


def _deny(*_args: object, **_kwargs: object) -> None:
    raise _NetworkDeniedError("network access denied")


_original_socket = socket.socket


class _GuardedSocket(_original_socket):
    def __new__(
        cls,
        family: int = socket.AF_INET,
        type: int = socket.SOCK_STREAM,
        proto: int = 0,
        fileno: int | None = None,
    ) -> object:
        if family != socket.AF_UNIX:
            raise _NetworkDeniedError("network access denied")
        return _original_socket.__new__(cls, family, type, proto, fileno)


def _audit_hook(event: str, args: tuple[object, ...]) -> None:
    if event in {
        "socket.bind",
        "socket.connect",
        "socket.getaddrinfo",
        "socket.gethostbyaddr",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.getnameinfo",
        "socket.sendto",
    }:
        raise _NetworkDeniedError("network access denied")
    if event == "socket.__new__" and len(args) >= 2 and args[1] != socket.AF_UNIX:
        raise _NetworkDeniedError("network access denied")


socket.socket = _GuardedSocket
for _name in (
    "create_connection",
    "getaddrinfo",
    "getfqdn",
    "gethostbyaddr",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostname",
    "getnameinfo",
):
    setattr(socket, _name, _deny)
sys.addaudithook(_audit_hook)

worker_pid = os.fork()
if worker_pid:
    while True:
        waited_pid, worker_status = os.waitpid(worker_pid, os.WNOHANG)
        if waited_pid:
            worker_code = os.waitstatus_to_exitcode(worker_status)
            message = (
                "scenario-gate: invalid-input\\n"
                if worker_code == 2
                else "scenario-gate: failed\\n"
            )
            sys.stderr.write(message)
            sys.stderr.flush()
            while True:
                signal.pause()
        time.sleep(0.01)

script, nonce, limit_text, site_packages, code_root, *workspace_roots = sys.argv[1:]
limit = int(limit_text)
script_path = Path(script)
code_root_path = Path(code_root)
expected_site_packages = (
    Path(sys.executable).parent.parent
    / "lib"
    / f"python{sys.version_info.major}.{sys.version_info.minor}"
    / "site-packages"
)
expected_workspace_roots = (
    code_root_path / "packages/testing/src",
    code_root_path / "packages/contracts/src",
    code_root_path / "apps/core/src",
)
if (
    limit != 65536
    or script_path != code_root_path / "scripts/run_scenarios.py"
    or Path(site_packages) != expected_site_packages
    or tuple(Path(item) for item in workspace_roots) != expected_workspace_roots
    or not all(
        path.is_absolute() and path.is_dir()
        for path in (expected_site_packages, *expected_workspace_roots)
    )
):
    raise SystemExit(97)

_soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
bounded = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
resource.setrlimit(resource.RLIMIT_FSIZE, (bounded, bounded))
if len(nonce) != 64 or any(character not in "0123456789abcdef" for character in nonce):
    raise SystemExit(97)
for _path in (*expected_workspace_roots, expected_site_packages):
    sys.path.append(str(_path))
namespace = runpy.run_path(str(script_path), run_name="_tuntun_scenario_child")
raise SystemExit(namespace["_child_main_from_stdin"](nonce))
"""


@dataclass(frozen=True, slots=True)
class _PreparedGateInvocation:
    values: argparse.Namespace
    inputs: tuple[Any, ...]
    input_references: tuple[dict[str, str], ...]
    invocation: dict[str, Any]
    invocation_commitment: str


@dataclass(frozen=True, slots=True)
class _SnapshotInput:
    normalized_name: str
    raw: bytes
    device: int
    inode: int


_StableIdentity = tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _DirectorySnapshot:
    identity: _StableIdentity
    entries: tuple[tuple[str, _StableIdentity], ...]


class _InputFailure(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise _InputFailure("invalid-input")


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = _Parser(prog="run_scenarios.py", add_help=True)
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--turns", type=int, required=True)
    parser.add_argument("--assert-resource-bounds", action="store_true")
    parser.add_argument("--json", action="store_true")
    values = parser.parse_args(argv)
    if not MIN_TURNS <= values.turns <= MAX_TURNS:
        raise _InputFailure("invalid-input")
    return values


def _fd_count() -> int:
    directory = next((path for path in ("/proc/self/fd", "/dev/fd") if os.path.isdir(path)), None)
    if directory is None:
        raise RuntimeError("fd-measurement-unavailable")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        entries = tuple(name for name in os.listdir(descriptor) if name.isdecimal())
        return len(entries) - (1 if str(descriptor) in entries else 0)
    finally:
        os.close(descriptor)


def _pending_task_count() -> int:
    current = asyncio.current_task()
    return sum(1 for task in asyncio.all_tasks() if task is not current and not task.done())


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-json-key")
        result[key] = value
    return result


def _reject_json_number(_value: str) -> Never:
    raise ValueError("invalid-json-number")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_json_object(
    raw: bytes,
    *,
    maximum: int = _MAX_CHILD_OUTPUT_BYTES,
) -> dict[str, Any]:
    if not 2 <= len(raw) <= maximum or not raw.endswith(b"\n"):
        raise ValueError("invalid-child-output")
    payload = raw[:-1]
    value = json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_unique_json_object,
        parse_float=_reject_json_number,
        parse_constant=_reject_json_number,
    )
    if type(value) is not dict:
        raise ValueError("invalid-child-output")
    if _canonical_bytes(value) != payload:
        raise ValueError("invalid-child-output")
    return value


def _snapshot_fail() -> _InputFailure:
    return _InputFailure("invalid-input")


def _validate_snapshot_part(part: str) -> str:
    if (
        not part
        or part in {".", ".."}
        or part != unicodedata.normalize("NFC", part)
        or len(part.encode("utf-8")) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in part)
    ):
        raise _snapshot_fail()
    return part


def _snapshot_relative_parts(path: Path, trusted_root: Path) -> tuple[str, ...]:
    if not trusted_root.is_absolute():
        raise _snapshot_fail()
    if path.is_absolute():
        try:
            relative = path.relative_to(trusted_root)
        except ValueError as error:
            raise _snapshot_fail() from error
    else:
        relative = path
    parts = tuple(_validate_snapshot_part(part) for part in relative.parts)
    if not parts or len(PurePosixPath(*parts).as_posix().encode("utf-8")) > 4_096:
        raise _snapshot_fail()
    return parts


def _open_snapshot_root(trusted_root: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for part in trusted_root.parts[1:]:
            next_descriptor = os.open(
                _validate_snapshot_part(part),
                flags,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_snapshot_parent(trusted_root: Path, parts: tuple[str, ...]) -> tuple[int, str]:
    descriptor = _open_snapshot_root(trusted_root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _snapshot_identity(value: os.stat_result) -> _StableIdentity:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _snapshot_read_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 65_536))
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            raise
        if not chunk:
            raise _snapshot_fail()
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise _snapshot_fail()
    return b"".join(chunks)


def _read_snapshot_child(
    parent_descriptor: int,
    name: str,
    normalized_name: str,
    *,
    expected_identity: _StableIdentity | None = None,
) -> _SnapshotInput:
    descriptor = -1
    try:
        if _validate_snapshot_part(name) != name or not name.endswith(".yaml"):
            raise _snapshot_fail()
        before_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if expected_identity is not None and _snapshot_identity(before_path) != expected_identity:
            raise _snapshot_fail()
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_descriptor,
        )
        before_fd = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_fd.st_mode)
            or before_fd.st_nlink != 1
            or not 1 <= before_fd.st_size <= _MAX_SCENARIO_BYTES
            or _snapshot_identity(before_path) != _snapshot_identity(before_fd)
        ):
            raise _snapshot_fail()
        raw = _snapshot_read_exact(descriptor, before_fd.st_size)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            _snapshot_identity(before_fd) != _snapshot_identity(after_fd)
            or _snapshot_identity(before_fd) != _snapshot_identity(after_path)
            or after_fd.st_nlink != 1
        ):
            raise _snapshot_fail()
        return _SnapshotInput(normalized_name, raw, after_fd.st_dev, after_fd.st_ino)
    except (OSError, UnicodeError) as error:
        raise _snapshot_fail() from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_snapshot_input(path: Path, trusted_root: Path) -> _SnapshotInput:
    parent_descriptor = -1
    try:
        parts = _snapshot_relative_parts(path, trusted_root)
        parent_descriptor, name = _open_snapshot_parent(trusted_root, parts)
        return _read_snapshot_child(
            parent_descriptor,
            name,
            PurePosixPath(*parts).as_posix(),
        )
    except (OSError, UnicodeError) as error:
        raise _snapshot_fail() from error
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _open_snapshot_directory(directory: Path, trusted_root: Path) -> int:
    descriptor = -1
    try:
        parts = _snapshot_relative_parts(directory, trusted_root)
        descriptor = _open_snapshot_root(trusted_root)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        for part in parts:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except (OSError, UnicodeError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise _snapshot_fail() from error


def _snapshot_directory(descriptor: int) -> _DirectorySnapshot:
    scan_descriptor = -1
    try:
        before = _snapshot_identity(os.fstat(descriptor))
        scan_descriptor = os.open(
            ".",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        collected: list[str] = []
        with os.scandir(scan_descriptor) as entries:
            for entry in entries:
                if len(collected) == _MAX_SCENARIOS:
                    raise _snapshot_fail()
                collected.append(entry.name)
        names = tuple(sorted(collected, key=lambda item: item.encode("utf-8")))
        if not names or any(
            _validate_snapshot_part(name) != name or not name.endswith(".yaml")
            for name in names
        ):
            raise _snapshot_fail()
        frozen_entries = tuple(
            (
                name,
                _snapshot_identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)),
            )
            for name in names
        )
        after = _snapshot_identity(os.fstat(descriptor))
        if after != before:
            raise _snapshot_fail()
        return _DirectorySnapshot(after, frozen_entries)
    except (OSError, UnicodeError) as error:
        raise _snapshot_fail() from error
    finally:
        if scan_descriptor >= 0:
            os.close(scan_descriptor)


def _load_default_snapshot_inputs(
    trusted_root: Path,
    default_directory: Path,
) -> tuple[_SnapshotInput, ...]:
    descriptor = -1
    rebound_descriptor = -1
    try:
        parts = _snapshot_relative_parts(default_directory, trusted_root)
        descriptor = _open_snapshot_directory(default_directory, trusted_root)
        before = _snapshot_directory(descriptor)
        loaded = tuple(
            _read_snapshot_child(
                descriptor,
                name,
                PurePosixPath(*parts, name).as_posix(),
                expected_identity=identity,
            )
            for name, identity in before.entries
        )
        after = _snapshot_directory(descriptor)
        rebound_descriptor = _open_snapshot_directory(default_directory, trusted_root)
        if (
            after != before
            or _snapshot_identity(os.fstat(rebound_descriptor)) != before.identity
        ):
            raise _snapshot_fail()
        return loaded
    except (OSError, UnicodeError) as error:
        raise _snapshot_fail() from error
    finally:
        if rebound_descriptor >= 0:
            os.close(rebound_descriptor)
        if descriptor >= 0:
            os.close(descriptor)


def _snapshot_scenario_inputs(
    paths: Sequence[Path],
    *,
    trusted_root: Path,
    default_directory: Path,
) -> tuple[_SnapshotInput, ...]:
    requested = tuple(islice(paths, _MAX_SCENARIOS + 1))
    if len(requested) > _MAX_SCENARIOS:
        raise _snapshot_fail()
    loaded = (
        tuple(_read_snapshot_input(path, trusted_root) for path in requested)
        if requested
        else _load_default_snapshot_inputs(trusted_root, default_directory)
    )
    names = [item.normalized_name for item in loaded]
    folded_names = [unicodedata.normalize("NFC", name).casefold() for name in names]
    logical_names = [name.rsplit("/", 1)[-1].removesuffix(".yaml") for name in names]
    folded_logical_names = [name.casefold() for name in logical_names]
    identities = [(item.device, item.inode) for item in loaded]
    if (
        len(names) != len(set(names))
        or len(folded_names) != len(set(folded_names))
        or len(logical_names) != len(set(logical_names))
        or len(folded_logical_names) != len(set(folded_logical_names))
        or len(identities) != len(set(identities))
    ):
        raise _snapshot_fail()
    return tuple(sorted(loaded, key=lambda item: item.normalized_name.encode("utf-8")))


def _runtime_import_paths(code_root: Path, executable: str) -> tuple[Path, tuple[Path, ...]]:
    site_packages = (
        Path(executable).absolute().parent.parent
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    workspace_roots = (
        code_root / "packages/testing/src",
        code_root / "packages/contracts/src",
        code_root / "apps/core/src",
    )
    if not all(path.is_absolute() and path.is_dir() for path in (site_packages, *workspace_roots)):
        raise ValueError("invalid-runtime-path")
    return site_packages, workspace_roots


def _prepare_gate_invocation(
    argv: Sequence[str],
    repository_root: Path,
) -> _PreparedGateInvocation:
    values = _arguments(argv)
    inputs = _snapshot_scenario_inputs(
        tuple(Path(item) for item in values.scenario),
        trusted_root=repository_root,
        default_directory=Path("tests/fixtures/scenarios"),
    )
    if len(inputs) * values.turns > MAX_TOTAL_TURNS:
        raise _InputFailure("invalid-input")
    references: list[dict[str, str]] = []
    for value in inputs:
        normalized_path = value.normalized_name
        scenario = normalized_path.rsplit("/", 1)[-1].removesuffix(".yaml")
        if _SCENARIO_NAME_PATTERN.fullmatch(scenario) is None:
            raise _InputFailure("invalid-input")
        references.append(
            {
                "content_sha256": sha256(value.raw).hexdigest(),
                "path": normalized_path,
                "scenario": scenario,
            }
        )
    invocation: dict[str, Any] = {
        "assert_resource_bounds": values.assert_resource_bounds,
        "inputs": references,
        "json_output": values.json,
        "schema_version": "scenario_invocation.v1",
        "turns": values.turns,
    }
    return _PreparedGateInvocation(
        values=values,
        inputs=inputs,
        input_references=tuple(references),
        invocation=invocation,
        invocation_commitment=sha256(_canonical_bytes(invocation)).hexdigest(),
    )


def _valid_b2(value: Any) -> bool:
    keys = {
        "duplicate_effect_count",
        "peak_rss_growth_bytes",
        "privacy_block_p95_ms",
        "private_sentinel_count",
        "status",
        "terminal_rss_growth_bytes",
        "warmup_turns",
    }
    if type(value) is not dict or set(value) != keys:
        return False
    metrics = tuple(value[key] for key in keys - {"status"})
    if value["status"] == "not_measured":
        return all(item is None for item in metrics)
    return (
        value["status"] == "pass"
        and value["warmup_turns"] == 50
        and all(type(item) is int and item >= 0 for item in metrics)
    )


def _valid_foundation_resources(value: Any, *, measured: bool) -> bool:
    keys = {
        "fd_after",
        "fd_baseline",
        "fd_delta",
        "pending_tasks_after",
        "pending_tasks_baseline",
        "pending_tasks_delta",
        "status",
    }
    if type(value) is not dict or set(value) != keys:
        return False
    metrics = tuple(value[key] for key in keys - {"status"})
    if not measured:
        return value["status"] == "not_measured" and all(item is None for item in metrics)
    return (
        value["status"] == "pass"
        and all(type(item) is int and item >= 0 for item in metrics)
        and value["fd_delta"] == 0
        and value["pending_tasks_delta"] == 0
        and value["fd_after"] == value["fd_baseline"]
        and value["pending_tasks_after"] == value["pending_tasks_baseline"]
    )


def _valid_scenario_records(
    value: Any,
    *,
    turns: int,
    input_references: tuple[dict[str, str], ...],
) -> bool:
    if type(value) is not list or len(value) != len(input_references):
        return False
    for item, reference in zip(value, input_references, strict=True):
        if type(item) is not dict or set(item) != {"name", "result_chain_sha256", "turns"}:
            return False
        name = item["name"]
        digest = item["result_chain_sha256"]
        if (
            type(name) is not str
            or _SCENARIO_NAME_PATTERN.fullmatch(name) is None
            or name != reference["scenario"]
            or type(digest) is not str
            or _DIGEST_PATTERN.fullmatch(digest) is None
            or type(item["turns"]) is not int
            or item["turns"] != turns
        ):
            return False
    return True


def _valid_gate_document(value: Any, prepared: _PreparedGateInvocation) -> bool:
    if type(value) is not dict:
        return False
    return not (
        set(value) != {"b2", "foundation_resources", "scenarios", "schema_version", "status"}
        or value["schema_version"] != "scenario_gate.v1"
        or value["status"] != "pass"
        or not _valid_b2(value["b2"])
        or not _valid_foundation_resources(
            value["foundation_resources"],
            measured=prepared.values.assert_resource_bounds,
        )
        or not _valid_scenario_records(
            value["scenarios"],
            turns=prepared.values.turns,
            input_references=prepared.input_references,
        )
    )


def _validated_gate_envelope(
    raw: bytes,
    prepared: _PreparedGateInvocation,
    nonce: str,
) -> bytes:
    envelope = _canonical_json_object(raw)
    if (
        set(envelope)
        != {
            "document",
            "input_references",
            "invocation_commitment",
            "nonce",
            "schema_version",
        }
        or envelope["schema_version"] != "scenario_supervisor_envelope.v1"
        or envelope["nonce"] != nonce
        or envelope["invocation_commitment"] != prepared.invocation_commitment
        or envelope["input_references"] != list(prepared.input_references)
        or not _valid_gate_document(envelope["document"], prepared)
    ):
        raise ValueError("invalid-child-output")
    if prepared.values.json:
        return _canonical_bytes(envelope["document"]) + b"\n"
    return b"scenario-gate: PASS\n"


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        process.kill()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("child-cleanup-timeout")
    time.sleep(min(_CHILD_SIGNAL_SETTLE_SECONDS, remaining))
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("child-cleanup-timeout")
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("child-cleanup-timeout") from error
        process.wait(timeout=remaining)
    while True:
        try:
            os.killpg(process.pid, 0)
        except (PermissionError, ProcessLookupError):
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("child-cleanup-timeout")
        time.sleep(min(_CHILD_POLL_SECONDS, remaining))


def _run_bounded_process(
    command: Sequence[str],
    *,
    payload: bytes,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    with (
        tempfile.TemporaryFile(mode="w+b") as stdin_file,
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        if len(payload) > _MAX_CHILD_CONFIGURATION_BYTES:
            raise ValueError("child-configuration-limit-exceeded")
        stdin_file.write(payload + b"\n")
        stdin_file.seek(0)
        process = subprocess.Popen(
            command,
            stdin=stdin_file,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=cwd,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
        runtime_deadline = time.monotonic() + _CHILD_TIMEOUT_SECONDS
        completed_frame = False
        try:
            while True:
                stdout_size = os.fstat(stdout_file.fileno()).st_size
                stderr_size = os.fstat(stderr_file.fileno()).st_size
                if (
                    stdout_size > _MAX_CHILD_OUTPUT_BYTES
                    or stderr_size > _MAX_CHILD_OUTPUT_BYTES
                ):
                    break
                if stdout_size:
                    stdout_file.seek(stdout_size - 1)
                    if stdout_file.read(1) == b"\n":
                        completed_frame = True
                        break
                if stderr_size:
                    stderr_file.seek(stderr_size - 1)
                    if stderr_file.read(1) == b"\n":
                        break
                remaining = runtime_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, _CHILD_TIMEOUT_SECONDS)
                time.sleep(min(_CHILD_POLL_SECONDS, remaining))
        finally:
            _terminate_process_group(
                process,
                deadline=time.monotonic() + _CHILD_CLEANUP_SECONDS,
            )
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(_MAX_CHILD_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(_MAX_CHILD_OUTPUT_BYTES + 1)
    if len(stdout) > _MAX_CHILD_OUTPUT_BYTES or len(stderr) > _MAX_CHILD_OUTPUT_BYTES:
        raise ValueError("child-output-limit-exceeded")
    return subprocess.CompletedProcess(
        command,
        0 if completed_frame else 1,
        stdout,
        stderr,
    )


async def _execute(
    inputs: tuple[Any, ...],
    turns: int,
    assert_resource_bounds: bool,
    turn_observer: Callable[[int], object] | None,
) -> tuple[tuple[Any, ...], Any]:
    from tuntun_testing.scenario import (
        FoundationResourceEvidence,
        ScenarioGateRecord,
        ScenarioRunner,
        result_chain,
    )

    await asyncio.sleep(0)
    gc.collect()
    fd_baseline = _fd_count() if assert_resource_bounds else None
    task_baseline = _pending_task_count() if assert_resource_bounds else None
    for value in inputs:
        await ScenarioRunner().run_async(value, turn_index=0)
    await asyncio.sleep(0)
    gc.collect()
    if assert_resource_bounds:
        if fd_baseline is None or task_baseline is None:
            raise AssertionError("resource-measurement-missing")
        if _fd_count() != fd_baseline or _pending_task_count() != task_baseline:
            raise AssertionError("resource-bound-failed")
    records: list[Any] = []
    global_turn = 0
    for value in inputs:
        results = []
        for turn_index in range(turns):
            results.append(await ScenarioRunner().run_async(value, turn_index=turn_index))
            if turn_observer is not None:
                observed = turn_observer(global_turn)
                if inspect.isawaitable(observed):
                    await observed
            global_turn += 1
        records.append(
            ScenarioGateRecord(
                name=results[0].scenario,
                turns=turns,
                result_chain_sha256=result_chain(tuple(results)),
            )
        )
    await asyncio.sleep(0)
    gc.collect()
    if assert_resource_bounds:
        fd_after = _fd_count()
        task_after = _pending_task_count()
        if fd_baseline is None or task_baseline is None:
            raise AssertionError("resource-measurement-missing")
        evidence = FoundationResourceEvidence(
            status="pass",
            fd_baseline=fd_baseline,
            fd_after=fd_after,
            fd_delta=fd_after - fd_baseline,
            pending_tasks_baseline=task_baseline,
            pending_tasks_after=task_after,
            pending_tasks_delta=task_after - task_baseline,
        )
        if evidence.fd_delta != 0 or evidence.pending_tasks_delta != 0:
            raise AssertionError("resource-bound-failed")
    else:
        evidence = FoundationResourceEvidence.not_measured()
    return tuple(records), evidence


def _build_gate_document(
    inputs: tuple[Any, ...],
    values: argparse.Namespace,
    turn_observer: Callable[[int], object] | None,
) -> Any:
    from tuntun_testing.scenario import ScenarioGateDocument

    records, evidence = asyncio.run(
        _execute(
            inputs,
            values.turns,
            values.assert_resource_bounds,
            turn_observer,
        )
    )
    return ScenarioGateDocument(scenarios=records, foundation_resources=evidence)


def _run_gate_in_process(
    argv: Sequence[str],
    *,
    _after_guard: Callable[[], object] | None = None,
    _turn_observer: Callable[[int], object] | None = None,
    _repository_root: Path | None = None,
) -> int:
    try:
        values = _arguments(argv)
    except _InputFailure:
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    try:
        from tuntun_testing.network_guard import install_network_guard

        install_network_guard()
        if _after_guard is not None:
            guarded_result = _after_guard()
            if inspect.isawaitable(guarded_result):
                raise AssertionError("invalid-guard-hook")
        from tuntun_testing.scenario import ScenarioSchemaError
        from tuntun_testing.scenario_io import (
            ScenarioInputError,
            load_scenario_inputs,
        )
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    try:
        repository_root = (
            Path(__file__).absolute().parent.parent
            if _repository_root is None
            else _repository_root
        )
        default_directory = Path("tests/fixtures/scenarios")
        inputs = load_scenario_inputs(
            (Path(item) for item in values.scenario),
            trusted_root=repository_root,
            default_directory=default_directory,
        )
        if len(inputs) * values.turns > MAX_TOTAL_TURNS:
            raise _InputFailure("invalid-input")
        document = _build_gate_document(inputs, values, _turn_observer)
        if values.json:
            sys.stdout.buffer.write(document.canonical_json() + b"\n")
        else:
            print("scenario-gate: PASS")
        return 0
    except (_InputFailure, ScenarioInputError, ScenarioSchemaError):
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1


def _run_gate_child(argv: Sequence[str], repository_root: Path) -> int:
    try:
        prepared = _prepare_gate_invocation(argv, repository_root)
    except (_InputFailure, ValueError):
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    try:
        nonce = secrets.token_hex(32)
        code_root = Path(__file__).absolute().parent.parent
        site_packages, workspace_roots = _runtime_import_paths(code_root, sys.executable)
        configuration = {
            "inputs": [
                {
                    **reference,
                    "raw_b64": base64.b64encode(value.raw).decode("ascii"),
                }
                for reference, value in zip(
                    prepared.input_references,
                    prepared.inputs,
                    strict=True,
                )
            ],
            "invocation": prepared.invocation,
            "invocation_commitment": prepared.invocation_commitment,
            "nonce": nonce,
            "schema_version": "scenario_child_config.v1",
        }
        result = _run_bounded_process(
            (
                sys.executable,
                "-I",
                "-S",
                "-c",
                _CHILD_BOOTSTRAP,
                str(Path(__file__).absolute()),
                nonce,
                str(_MAX_CHILD_OUTPUT_BYTES),
                str(site_packages),
                str(code_root),
                *(str(path) for path in workspace_roots),
            ),
            payload=_canonical_bytes(configuration),
            cwd=repository_root,
            environment={},
        )
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    if result.returncode == 0 and result.stderr == b"":
        try:
            sys.stdout.buffer.write(_validated_gate_envelope(result.stdout, prepared, nonce))
            return 0
        except BaseException:
            print("scenario-gate: failed", file=sys.stderr)
            return 1
    if (
        result.stdout == b""
        and result.stderr == b"scenario-gate: invalid-input\n"
    ):
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    print("scenario-gate: failed", file=sys.stderr)
    return 1


def _child_main_from_stdin(expected_nonce: str) -> int:
    try:
        raw = sys.stdin.buffer.readline(_MAX_CHILD_CONFIGURATION_BYTES + 2)
        if (
            len(raw) > _MAX_CHILD_CONFIGURATION_BYTES + 1
            or not raw.endswith(b"\n")
            or sys.stdin.buffer.read(1) != b""
        ):
            raise ValueError("invalid-child-configuration")
        configuration = _canonical_json_object(
            raw,
            maximum=_MAX_CHILD_CONFIGURATION_BYTES + 1,
        )
        invocation = configuration["invocation"]
        invocation_inputs = invocation["inputs"]
        configured_inputs = configuration["inputs"]
        if (
            set(configuration)
            != {
                "inputs",
                "invocation",
                "invocation_commitment",
                "nonce",
                "schema_version",
            }
            or configuration["schema_version"] != "scenario_child_config.v1"
            or configuration["nonce"] != expected_nonce
            or type(configuration["nonce"]) is not str
            or _DIGEST_PATTERN.fullmatch(configuration["nonce"]) is None
            or type(invocation) is not dict
            or set(invocation)
            != {
                "assert_resource_bounds",
                "inputs",
                "json_output",
                "schema_version",
                "turns",
            }
            or invocation["schema_version"] != "scenario_invocation.v1"
            or type(invocation["assert_resource_bounds"]) is not bool
            or type(invocation["json_output"]) is not bool
            or type(invocation["turns"]) is not int
            or not MIN_TURNS <= invocation["turns"] <= MAX_TURNS
            or type(invocation_inputs) is not list
            or type(configured_inputs) is not list
            or not 1 <= len(invocation_inputs) == len(configured_inputs) <= 32
            or len(invocation_inputs) * invocation["turns"] > MAX_TOTAL_TURNS
            or type(configuration["invocation_commitment"]) is not str
            or _DIGEST_PATTERN.fullmatch(configuration["invocation_commitment"])
            is None
            or configuration["invocation_commitment"]
            != sha256(_canonical_bytes(invocation)).hexdigest()
        ):
            raise ValueError("invalid-child-configuration")
        from tuntun_testing.scenario_io import ScenarioInput

        inputs: list[Any] = []
        references: list[dict[str, str]] = []
        for index, (reference, configured) in enumerate(
            zip(invocation_inputs, configured_inputs, strict=True),
            start=1,
        ):
            if (
                type(reference) is not dict
                or set(reference) != {"content_sha256", "path", "scenario"}
                or type(configured) is not dict
                or set(configured) != {"content_sha256", "path", "raw_b64", "scenario"}
                or {key: configured[key] for key in reference} != reference
                or type(reference["path"]) is not str
                or reference["path"].startswith("/")
                or not 1 <= len(reference["path"].encode("utf-8")) <= 4_096
                or reference["path"] != unicodedata.normalize("NFC", reference["path"])
                or any(
                    part in {"", ".", ".."}
                    or len(part.encode("utf-8")) > 255
                    or any(ord(character) < 32 or ord(character) == 127 for character in part)
                    for part in reference["path"].split("/")
                )
                or type(reference["scenario"]) is not str
                or _SCENARIO_NAME_PATTERN.fullmatch(reference["scenario"]) is None
                or reference["path"].rsplit("/", 1)[-1]
                != f"{reference['scenario']}.yaml"
                or type(reference["content_sha256"]) is not str
                or _DIGEST_PATTERN.fullmatch(reference["content_sha256"]) is None
                or type(configured["raw_b64"]) is not str
            ):
                raise ValueError("invalid-child-configuration")
            decoded = base64.b64decode(configured["raw_b64"], validate=True)
            if (
                not 1 <= len(decoded) <= _MAX_SCENARIO_BYTES
                or sha256(decoded).hexdigest() != reference["content_sha256"]
            ):
                raise ValueError("invalid-child-configuration")
            references.append(reference)
            inputs.append(
                ScenarioInput(
                    normalized_name=reference["path"],
                    raw=decoded,
                    device=0,
                    inode=index,
                )
            )
        if references != invocation_inputs:
            raise ValueError("invalid-child-configuration")
        values = argparse.Namespace(
            assert_resource_bounds=invocation["assert_resource_bounds"],
            json=invocation["json_output"],
            scenario=[],
            turns=invocation["turns"],
        )
    except BaseException:
        return 1
    try:
        from tuntun_testing.scenario import ScenarioSchemaError

        document = _build_gate_document(tuple(inputs), values, None)
    except (ScenarioSchemaError, _InputFailure):
        return 2
    except BaseException:
        return 1
    envelope = {
        "document": document.to_mapping(),
        "input_references": references,
        "invocation_commitment": configuration["invocation_commitment"],
        "nonce": expected_nonce,
        "schema_version": "scenario_supervisor_envelope.v1",
    }
    try:
        sys.stdout.buffer.write(_canonical_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()
        while True:
            signal.pause()
    except BaseException:
        return 1


def main(
    argv: Sequence[str] | None = None,
    *,
    _after_guard: Callable[[], object] | None = None,
    _turn_observer: Callable[[int], object] | None = None,
    _repository_root: Path | None = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _after_guard is not None or _turn_observer is not None:
        return _run_gate_in_process(
            arguments,
            _after_guard=_after_guard,
            _turn_observer=_turn_observer,
            _repository_root=_repository_root,
        )
    try:
        _arguments(arguments)
    except _InputFailure:
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    repository_root = (
        Path(__file__).absolute().parent.parent if _repository_root is None else _repository_root
    )
    return _run_gate_child(arguments, repository_root)


if __name__ == "__main__":
    raise SystemExit(main())
