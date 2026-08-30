from __future__ import annotations

import base64
import errno
import importlib.util
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Never
from uuid import UUID

import typer

_SIMULATION_TIMEOUT_SECONDS = 120.0
_SIMULATION_CLEANUP_SECONDS = 5.0
_SIMULATION_POLL_SECONDS = 0.01
_SIMULATION_SIGNAL_SETTLE_SECONDS = 0.05
_MAX_SIMULATION_OUTPUT_BYTES = 65_536
_MAX_SIMULATION_CONFIGURATION_BYTES = 1_048_576
_SCENARIO_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SIMULATE_BOOTSTRAP = """
from __future__ import annotations

import os
import resource
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
                "simulation-extra-required\\n"
                if worker_code == 3
                else "simulation-invalid-input\\n"
            )
            sys.stderr.write(message)
            sys.stderr.flush()
            while True:
                signal.pause()
        time.sleep(0.01)

nonce, limit_text, site_packages, code_root, *workspace_roots = sys.argv[1:]
limit = int(limit_text)
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
    or tuple(Path(item) for item in workspace_roots) != expected_workspace_roots
    or Path(site_packages) != expected_site_packages
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
"""
_SIMULATE_CHILD_CODE = """
import base64
import json
import os
import signal
import sys
import unicodedata
from hashlib import sha256

try:
    from tuntun_testing.scenario import ScenarioRunner
    from tuntun_testing.scenario_io import ScenarioInput

    raw = sys.stdin.buffer.readline(1048578)
    if len(raw) > 1048577 or not raw.endswith(b"\\n") or sys.stdin.buffer.read(1) != b"":
        raise ValueError("invalid-child-configuration")
    configuration = json.loads(raw)
    canonical_configuration = json.dumps(
        configuration,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if canonical_configuration != raw[:-1]:
        raise ValueError("invalid-child-configuration")
    invocation = configuration["invocation"]
    reference = invocation["input"]
    configured_input = configuration["input"]
    if (
        type(configuration) is not dict
        or set(configuration)
        != {"input", "invocation", "invocation_commitment", "nonce", "schema_version"}
        or configuration["schema_version"] != "simulation_child_config.v1"
        or configuration["nonce"] != nonce
        or type(configuration["nonce"]) is not str
        or len(configuration["nonce"]) != 64
        or any(character not in "0123456789abcdef" for character in configuration["nonce"])
        or type(invocation) is not dict
        or set(invocation) != {"input", "json_output", "schema_version"}
        or invocation["schema_version"] != "simulation_invocation.v1"
        or type(invocation["json_output"]) is not bool
        or type(reference) is not dict
        or set(reference) != {"content_sha256", "path", "scenario"}
        or type(reference["content_sha256"]) is not str
        or len(reference["content_sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in reference["content_sha256"])
        or type(reference["path"]) is not str
        or not 1 <= len(reference["path"].encode("utf-8")) <= 4096
        or reference["path"].startswith("/")
        or reference["path"] != unicodedata.normalize("NFC", reference["path"])
        or any(
            part in {"", ".", ".."}
            or len(part.encode("utf-8")) > 255
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
            for part in reference["path"].split("/")
        )
        or type(reference["scenario"]) is not str
        or not 2 <= len(reference["scenario"]) <= 64
        or reference["scenario"][0] not in "abcdefghijklmnopqrstuvwxyz"
        or not all(
            character in "abcdefghijklmnopqrstuvwxyz0123456789-"
            for character in reference["scenario"]
        )
        or reference["path"].rsplit("/", 1)[-1] != reference["scenario"] + ".yaml"
        or type(configured_input) is not dict
        or set(configured_input) != {"content_sha256", "path", "raw_b64", "scenario"}
        or {key: configured_input[key] for key in reference} != reference
        or type(configured_input["raw_b64"]) is not str
        or type(configuration["invocation_commitment"]) is not str
        or len(configuration["invocation_commitment"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in configuration["invocation_commitment"]
        )
        or configuration["invocation_commitment"] != sha256(
            json.dumps(
                invocation,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    ):
        raise ValueError("invalid-child-configuration")
    scenario_raw = base64.b64decode(configured_input["raw_b64"], validate=True)
    if (
        not 1 <= len(scenario_raw) <= 65536
        or sha256(scenario_raw).hexdigest() != reference["content_sha256"]
    ):
        raise ValueError("invalid-child-configuration")
    scenario_input = ScenarioInput(
        normalized_name=reference["path"],
        raw=scenario_raw,
        device=0,
        inode=1,
    )
    result = ScenarioRunner().run(scenario_input)
    envelope = {
        "document": result.to_mapping(),
        "input_reference": reference,
        "invocation_commitment": configuration["invocation_commitment"],
        "nonce": nonce,
        "schema_version": "simulation_supervisor_envelope.v1",
    }
    sys.stdout.write(
        json.dumps(
            envelope,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\\n"
    )
    sys.stdout.flush()
    while True:
        signal.pause()
except ImportError:
    raise SystemExit(3)
except BaseException:
    raise SystemExit(2)
"""


@dataclass(frozen=True, slots=True)
class _PreparedSimulationInvocation:
    input_reference: dict[str, str]
    invocation: dict[str, Any]
    invocation_commitment: str
    raw: bytes


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
    maximum: int = _MAX_SIMULATION_OUTPUT_BYTES,
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


def _validate_path_part(part: str) -> str:
    if (
        not part
        or part in {".", ".."}
        or part != unicodedata.normalize("NFC", part)
        or len(part.encode("utf-8")) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in part)
    ):
        raise ValueError("invalid-scenario-input")
    return part


def _relative_path_parts(path: Path, trusted_root: Path) -> tuple[str, ...]:
    if not trusted_root.is_absolute():
        raise ValueError("invalid-scenario-input")
    if path.is_absolute():
        try:
            relative = path.relative_to(trusted_root)
        except ValueError as error:
            raise ValueError("invalid-scenario-input") from error
    else:
        relative = path
    parts = tuple(_validate_path_part(part) for part in relative.parts)
    if not parts or len("/".join(parts).encode("utf-8")) > 4_096:
        raise ValueError("invalid-scenario-input")
    return parts


def _open_trusted_root(trusted_root: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for part in trusted_root.parts[1:]:
            next_descriptor = os.open(_validate_path_part(part), flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_exact(descriptor: int, size: int) -> bytes:
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
            raise ValueError("invalid-scenario-input")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ValueError("invalid-scenario-input")
    return b"".join(chunks)


def _stable_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _snapshot_scenario(path: Path, trusted_root: Path) -> tuple[str, bytes]:
    root_descriptor = -1
    descriptor = -1
    try:
        parts = _relative_path_parts(path, trusted_root)
        root_descriptor = _open_trusted_root(trusted_root)
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        for part in parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=root_descriptor)
            os.close(root_descriptor)
            root_descriptor = next_descriptor
        name = parts[-1]
        if not name.endswith(".yaml"):
            raise ValueError("invalid-scenario-input")
        before_path = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=root_descriptor,
        )
        before_fd = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_fd.st_mode)
            or before_fd.st_nlink != 1
            or not 1 <= before_fd.st_size <= 65_536
            or _stable_identity(before_path) != _stable_identity(before_fd)
        ):
            raise ValueError("invalid-scenario-input")
        raw = _read_exact(descriptor, before_fd.st_size)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if (
            _stable_identity(before_fd) != _stable_identity(after_fd)
            or _stable_identity(before_fd) != _stable_identity(after_path)
            or after_fd.st_nlink != 1
        ):
            raise ValueError("invalid-scenario-input")
        return "/".join(parts), raw
    except (OSError, UnicodeError) as error:
        raise ValueError("invalid-scenario-input") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)


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


def _prepare_simulation_invocation(
    scenario: Path,
    *,
    json_output: bool,
    repository_root: Path,
) -> _PreparedSimulationInvocation:
    normalized_path, raw = _snapshot_scenario(scenario, repository_root)
    scenario_name = normalized_path.rsplit("/", 1)[-1].removesuffix(".yaml")
    if _SCENARIO_NAME_PATTERN.fullmatch(scenario_name) is None:
        raise ValueError("invalid-scenario-input")
    reference = {
        "content_sha256": sha256(raw).hexdigest(),
        "path": normalized_path,
        "scenario": scenario_name,
    }
    invocation: dict[str, Any] = {
        "input": reference,
        "json_output": json_output,
        "schema_version": "simulation_invocation.v1",
    }
    return _PreparedSimulationInvocation(
        input_reference=reference,
        invocation=invocation,
        invocation_commitment=sha256(_canonical_bytes(invocation)).hexdigest(),
        raw=raw,
    )


def _valid_text(value: Any, *, maximum: int, prefix: str | None = None) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and len(value.encode("utf-8")) <= maximum * 4
        and value == unicodedata.normalize("NFC", value)
        and value.isprintable()
        and (prefix is None or value.startswith(prefix))
    )


def _valid_uuid(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _valid_usage(value: Any) -> bool:
    keys = {
        "input_audio_bytes",
        "output_audio_bytes",
        "response_characters",
        "transcript_characters",
    }
    return (
        type(value) is dict
        and set(value) == keys
        and all(type(value[key]) is int and 0 <= value[key] <= 1_000_000 for key in keys)
    )


def _valid_simulation_document(
    value: Any,
    prepared: _PreparedSimulationInvocation,
) -> bool:
    if type(value) is not dict:
        return False
    keys = {
        "audit_receipt_ids",
        "events",
        "identity",
        "language",
        "outcome",
        "response",
        "scenario",
        "schema_version",
        "transcript",
        "turn_id",
        "turn_index",
        "usage",
    }
    audit_ids = value.get("audit_receipt_ids")
    events = value.get("events")
    scenario = value.get("scenario")
    return not (
        set(value) != keys
        or value["schema_version"] != "scenario_result.v1"
        or type(scenario) is not str
        or _SCENARIO_NAME_PATTERN.fullmatch(scenario) is None
        or scenario != prepared.input_reference["scenario"]
        or value["identity"] != "guest"
        or value["language"] not in {"en", "hi", "hinglish"}
        or value["outcome"] != "completed"
        or not _valid_text(value["transcript"], maximum=256, prefix="synthetic-")
        or not _valid_text(value["response"], maximum=256, prefix="synthetic-")
        or type(value["turn_index"]) is not int
        or value["turn_index"] != 0
        or not _valid_uuid(value["turn_id"])
        or type(audit_ids) is not list
        or not 1 <= len(audit_ids) <= 16
        or not all(_valid_uuid(item) for item in audit_ids)
        or type(events) is not list
        or not 1 <= len(events) <= 64
        or not all(type(item) is str and _EVENT_PATTERN.fullmatch(item) for item in events)
        or not _valid_usage(value["usage"])
    )


def _validated_simulation_envelope(
    raw: bytes,
    prepared: _PreparedSimulationInvocation,
    nonce: str,
    *,
    json_output: bool,
) -> bytes:
    envelope = _canonical_json_object(raw)
    if (
        set(envelope)
        != {
            "document",
            "input_reference",
            "invocation_commitment",
            "nonce",
            "schema_version",
        }
        or envelope["schema_version"] != "simulation_supervisor_envelope.v1"
        or envelope["nonce"] != nonce
        or envelope["invocation_commitment"] != prepared.invocation_commitment
        or envelope["input_reference"] != prepared.input_reference
        or not _valid_simulation_document(envelope["document"], prepared)
    ):
        raise ValueError("invalid-child-output")
    if json_output:
        return _canonical_bytes(envelope["document"]) + b"\n"
    return b"simulation: PASS\n"


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
    time.sleep(min(_SIMULATION_SIGNAL_SETTLE_SECONDS, remaining))
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
        time.sleep(min(_SIMULATION_POLL_SECONDS, remaining))


def _run_simulation_child(
    *,
    repository_root: Path,
    configuration: bytes,
) -> subprocess.CompletedProcess[bytes]:
    if len(configuration) > _MAX_SIMULATION_CONFIGURATION_BYTES:
        raise ValueError("child-configuration-limit-exceeded")
    configuration_value = _canonical_json_object(
        configuration + b"\n",
        maximum=_MAX_SIMULATION_CONFIGURATION_BYTES + 1,
    )
    nonce = configuration_value.get("nonce")
    if type(nonce) is not str or _DIGEST_PATTERN.fullmatch(nonce) is None:
        raise ValueError("invalid-child-configuration")
    site_packages, workspace_roots = _runtime_import_paths(repository_root, sys.executable)
    with (
        tempfile.TemporaryFile(mode="w+b") as stdin_file,
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        stdin_file.write(configuration + b"\n")
        stdin_file.seek(0)
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                _SIMULATE_BOOTSTRAP + _SIMULATE_CHILD_CODE,
                nonce,
                str(_MAX_SIMULATION_OUTPUT_BYTES),
                str(site_packages),
                str(repository_root),
                *(str(path) for path in workspace_roots),
            ],
            stdin=stdin_file,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=repository_root,
            env={},
            close_fds=True,
            start_new_session=True,
        )
        runtime_deadline = time.monotonic() + _SIMULATION_TIMEOUT_SECONDS
        completed_frame = False
        try:
            while True:
                stdout_size = os.fstat(stdout_file.fileno()).st_size
                stderr_size = os.fstat(stderr_file.fileno()).st_size
                if (
                    stdout_size > _MAX_SIMULATION_OUTPUT_BYTES
                    or stderr_size > _MAX_SIMULATION_OUTPUT_BYTES
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
                    raise subprocess.TimeoutExpired(process.args, _SIMULATION_TIMEOUT_SECONDS)
                time.sleep(min(_SIMULATION_POLL_SECONDS, remaining))
        finally:
            _terminate_process_group(
                process,
                deadline=time.monotonic() + _SIMULATION_CLEANUP_SECONDS,
            )
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(_MAX_SIMULATION_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(_MAX_SIMULATION_OUTPUT_BYTES + 1)
    if len(stdout) > _MAX_SIMULATION_OUTPUT_BYTES or len(stderr) > _MAX_SIMULATION_OUTPUT_BYTES:
        raise ValueError("child-output-limit-exceeded")
    return subprocess.CompletedProcess(
        process.args,
        0 if completed_frame else 1,
        stdout,
        stderr,
    )


def simulate(
    scenario: Annotated[Path, typer.Option("--scenario")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run one synthetic repository scenario with the optional simulation extra."""
    try:
        simulation_available = importlib.util.find_spec("tuntun_testing") is not None
    except BaseException:
        typer.echo("simulation-invalid-input", err=True)
        raise typer.Exit(2) from None
    if not simulation_available:
        typer.echo("simulation-extra-required", err=True)
        raise typer.Exit(2) from None
    repository_root = Path(__file__).absolute().parents[6]
    try:
        prepared = _prepare_simulation_invocation(
            scenario,
            json_output=json_output,
            repository_root=repository_root,
        )
        nonce = os.urandom(32).hex()
        configuration = {
            "input": {
                **prepared.input_reference,
                "raw_b64": base64.b64encode(prepared.raw).decode("ascii"),
            },
            "invocation": prepared.invocation,
            "invocation_commitment": prepared.invocation_commitment,
            "nonce": nonce,
            "schema_version": "simulation_child_config.v1",
        }
        result = _run_simulation_child(
            repository_root=repository_root,
            configuration=_canonical_bytes(configuration),
        )
        if result.returncode == 0 and result.stderr == b"":
            output = _validated_simulation_envelope(
                result.stdout,
                prepared,
                nonce,
                json_output=json_output,
            )
        else:
            output = None
    except BaseException:
        typer.echo("simulation-invalid-input", err=True)
        raise typer.Exit(2) from None
    if output is not None:
        typer.echo(output.decode("utf-8"), nl=False)
        return
    if (
        result.stdout == b""
        and result.stderr == b"simulation-extra-required\n"
    ):
        typer.echo("simulation-extra-required", err=True)
        raise typer.Exit(2) from None
    typer.echo("simulation-invalid-input", err=True)
    raise typer.Exit(2) from None
