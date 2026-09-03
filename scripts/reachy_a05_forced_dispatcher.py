#!/usr/bin/env python3
"""Software-only Reachy A0.5 OpenSSH forced-command dispatcher.

The dispatcher is deliberately small and standard-library-only.  It consumes one
canonical length-prefixed JSON command, validates the canonical Task-0 remote
state record under the fixed owner-local root, and stages artifact bytes only
from the same forced-command stdin stream in manifest order.  ``run_ptt`` emits
the core bridge's ready response and then execs the validated active generation.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import fcntl
import hashlib
import hmac
import io
import json
import os
import pwd
import secrets
import select
import stat
import sys
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from struct import Struct
from typing import BinaryIO, Final, NoReturn, TextIO, TypeAlias, cast
from uuid import UUID

JsonValue: TypeAlias = (  # noqa: UP040
    None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]  # noqa: UP040
ExecHandoff: TypeAlias = Callable[[tuple[str, ...], int], None]  # noqa: UP040

FRAME_PREFIX: Final = Struct(">I")
MAX_REQUEST_BYTES: Final = 65_536
MAX_RESPONSE_BYTES: Final = 4_096
MAX_STATE_BYTES: Final = 65_536
MAX_ARTIFACTS: Final = 32
MAX_ARTIFACT_BYTES: Final = 32 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES: Final = 256 * 1024 * 1024
MAX_ARTIFACT_PATH_BYTES: Final = 512
MAX_ARTIFACT_PATH_DEPTH: Final = 16
MAX_GENERATION_ENTRIES: Final = MAX_ARTIFACTS * (MAX_ARTIFACT_PATH_DEPTH + 1)
MAX_IMPORT_SNAPSHOT_ENTRIES: Final = 4_096
MAX_JSON_INT: Final = 2**53 - 1
READ_CHUNK_BYTES: Final = 8192
STREAM_EOF_SECONDS: Final = 1.0

REMOTE_STATE_SCHEMA_VERSION: Final = "tuntun.reachy-a05-remote-state.v1"
DISPATCHER_PROTOCOL_VERSION: Final = "tuntun.reachy-a05-dispatcher.v1"
BUNDLE_MANIFEST_SCHEMA_VERSION: Final = "tuntun.reachy-a05-bundle-manifest.v1"
BUNDLE_DESCRIPTOR_SCHEMA_VERSION: Final = "tuntun.reachy-a05-bundle.v1"

STATE_FILENAME: Final = "remote-state.json"
LOCK_FILENAME: Final = ".remote-state.lock"
STAGING_DIRNAME: Final = ".staging"
GENERATIONS_DIRNAME: Final = "generations"
DISPATCHER_BASENAME: Final = "reachy_a05_forced_dispatcher.py"

REQUEST_KEYS: Final = frozenset(
    {
        "version",
        "operation_id",
        "verb",
        "commissioning_id",
        "expected_state_generation",
        "payload",
    }
)
RESPONSE_KEYS: Final = frozenset(
    {"version", "operation_id", "ok", "state_generation", "status", "payload"}
)
STATE_KEYS: Final = frozenset({"schema_version", "deployment"})
DEPLOYMENT_KEYS: Final = frozenset(
    {
        "commissioning_id",
        "state_generation",
        "status",
        "issued_at",
        "expires_at",
        "boot_identity_sha256",
        "capability_report_sha256",
        "ptt_input_mode",
        "runtime",
        "ssh_principal",
        "remote_home",
        "remote_root",
        "dispatcher_path",
        "dispatcher_protocol_version",
        "dispatcher_sha256",
        "authorized_key_line_sha256",
        "staged_bundle_sha256",
        "active_bundle_sha256",
    }
)
RUNTIME_KEYS: Final = frozenset(
    {
        "python_executable",
        "python_version",
        "python_abi",
        "selected_wheel_tag",
        "target_tag_set_sha256",
        "sdk_version",
        "sdk_artifact_sha256",
        "daemon_version",
        "daemon_artifact_sha256",
        "runtime_inventory_sha256",
    }
)
STATUS_PAYLOAD_KEYS: Final = frozenset(
    {
        "active_bundle_sha256",
        "authorized_key_line_sha256",
        "boot_identity_sha256",
        "capability_report_sha256",
        "dispatcher_protocol_version",
        "dispatcher_sha256",
        "runtime_inventory_sha256",
        "staged_bundle_sha256",
    }
)
STAGE_PAYLOAD_KEYS: Final = frozenset({"bundle_sha256", "artifacts"})
ARTIFACT_RECORD_KEYS: Final = frozenset({"path", "size", "sha256", "executable"})
MANIFEST_KEYS: Final = frozenset({"schema_version", "entrypoint", "artifacts"})
BUNDLE_SHA_PAYLOAD_KEYS: Final = frozenset({"bundle_sha256"})
RUN_PTT_PAYLOAD_KEYS: Final = frozenset({"turn_id", "input_mode"})

VERBS: Final = frozenset({"status", "stage", "activate", "run_ptt", "remove", "verify_absent"})
STATUSES: Final = frozenset({"commissioned", "staged", "active", "removed", "revoked"})
PTT_INPUT_MODES: Final = frozenset({"reachy_local", "core_terminal_toggle"})
PYTHON_ABIS: Final = frozenset({"cp311", "cp312"})
ALLOWED_PTT_MODULES: Final = frozenset({"tuntun_edge.cli.ptt", "tuntun_edge.poc.reachy_ptt"})
FORBIDDEN_ARGV_ITEMS: Final = frozenset(
    {"sh", "bash", "zsh", "fish", "curl", "wget", "pip", "pip3", "ensurepip"}
)

_SHA256_HEX: Final = frozenset("0123456789abcdef")
_LOWER_ASCII: Final = frozenset("abcdefghijklmnopqrstuvwxyz")
_UPPER_ASCII: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ASCII_DIGITS: Final = frozenset("0123456789")
_PORTABLE_PATH_CHARS: Final = _LOWER_ASCII | _UPPER_ASCII | _ASCII_DIGITS | frozenset("._+-")
_PRINCIPAL_FIRST_CHARS: Final = _LOWER_ASCII | frozenset("_")
_PRINCIPAL_REST_CHARS: Final = _PRINCIPAL_FIRST_CHARS | _ASCII_DIGITS | frozenset("-")
_VERSION_FIRST_CHARS: Final = _LOWER_ASCII | _UPPER_ASCII | _ASCII_DIGITS
_VERSION_REST_CHARS: Final = _VERSION_FIRST_CHARS | frozenset("._+!-")
_O_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_DARWIN_RENAME_EXCL: Final = 0x4
_DARWIN_RENAME_SWAP: Final = 0x2
_LINUX_RENAME_NOREPLACE: Final = 1
_LINUX_RENAME_EXCHANGE: Final = 2
_LINUX_F_ADD_SEALS: Final = 1033
_LINUX_F_GET_SEALS: Final = 1034
_LINUX_F_SEAL_SEAL: Final = 0x0001
_LINUX_F_SEAL_SHRINK: Final = 0x0002
_LINUX_F_SEAL_GROW: Final = 0x0004
_LINUX_F_SEAL_WRITE: Final = 0x0008


class DispatcherRejected(PermissionError):
    """Content-free dispatcher rejection."""

    def __init__(self, code: str = "rejected") -> None:
        self.code = code
        super().__init__("reachy-a05-dispatcher-rejected")

    def __repr__(self) -> str:
        return f"DispatcherRejected(code={self.code!r})"


def _rename_with_atomic_flag(
    source_directory_fd: int,
    source: str,
    destination_directory_fd: int,
    destination: str,
    *,
    darwin_flag: int,
    linux_flag: int,
) -> None:
    if (
        type(source_directory_fd) is not int
        or source_directory_fd < 0
        or type(destination_directory_fd) is not int
        or destination_directory_fd < 0
        or type(source) is not str
        or type(destination) is not str
        or not source
        or not destination
        or source == destination
        or "/" in source
        or "/" in destination
        or "\x00" in source
        or "\x00" in destination
    ):
        raise ValueError("atomic exchange arguments are invalid")
    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        try:
            renamer = library.renameatx_np
        except AttributeError:
            raise OSError(errno.ENOTSUP, "atomic exchange is unavailable") from None
        renamer.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renamer.restype = ctypes.c_int
        arguments = (
            source_directory_fd,
            source_bytes,
            destination_directory_fd,
            destination_bytes,
            darwin_flag,
        )
    elif sys.platform.startswith("linux"):
        try:
            renamer = library.renameat2
        except AttributeError:
            raise OSError(errno.ENOTSUP, "atomic exchange is unavailable") from None
        renamer.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renamer.restype = ctypes.c_int
        arguments = (
            source_directory_fd,
            source_bytes,
            destination_directory_fd,
            destination_bytes,
            linux_flag,
        )
    else:
        raise OSError(errno.ENOTSUP, "atomic exchange is unsupported")
    ctypes.set_errno(0)
    if renamer(*arguments) != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(error_number, os.strerror(error_number), destination)
        raise OSError(error_number, os.strerror(error_number), source, destination)


def _rename_exchange(directory_fd: int, source: str, destination: str) -> None:
    _rename_with_atomic_flag(
        directory_fd,
        source,
        directory_fd,
        destination,
        darwin_flag=_DARWIN_RENAME_SWAP,
        linux_flag=_LINUX_RENAME_EXCHANGE,
    )


def _rename_noreplace(
    source_directory_fd: int,
    source: str,
    destination_directory_fd: int,
    destination: str,
) -> None:
    _rename_with_atomic_flag(
        source_directory_fd,
        source,
        destination_directory_fd,
        destination,
        darwin_flag=_DARWIN_RENAME_EXCL,
        linux_flag=_LINUX_RENAME_NOREPLACE,
    )


@dataclass(frozen=True, slots=True)
class _Request:
    operation_id: str
    verb: str
    commissioning_id: str
    expected_state_generation: int
    payload: JsonObject


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _FileIdentity:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=stat.S_IMODE(value.st_mode),
            uid=value.st_uid,
            links=value.st_nlink,
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            changed_ns=value.st_ctime_ns,
        )


@dataclass(frozen=True, slots=True)
class _StageArtifact:
    path: str
    parts: tuple[str, ...]
    size: int
    sha256: str
    executable: bool

    def address_record(self) -> JsonObject:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "executable": self.executable,
        }


@dataclass(frozen=True, slots=True)
class _StagePlan:
    bundle_sha256: str
    artifacts: tuple[_StageArtifact, ...]

    @property
    def manifest_artifact(self) -> _StageArtifact:
        for artifact in self.artifacts:
            if artifact.path == "manifest.json":
                return artifact
        _reject("stage-manifest")

    def bundle_descriptor(self) -> JsonObject:
        return {
            "schema_version": BUNDLE_DESCRIPTOR_SCHEMA_VERSION,
            "manifest_sha256": self.manifest_artifact.sha256,
            "artifacts": [artifact.address_record() for artifact in self.artifacts],
        }


@dataclass(frozen=True, slots=True)
class _ExecutableHandoff:
    argv: tuple[str, ...]
    entrypoint_module: str
    manifest_bytes: bytes
    generation_path: Path
    generation_fd: int
    generation_identity: _FileIdentity
    executable_fd: int
    executable_identity: _FileIdentity
    executable_sha256: str


@dataclass(frozen=True, slots=True)
class _DispatchOutcome:
    response: bytes
    handoff: _ExecutableHandoff | None = None


class _LockedRoot:
    def __init__(self, root: Path) -> None:
        self.root = _absolute_lexical_path(root)
        self.root_fd = -1
        self.lock_fd = -1

    def __enter__(self) -> _LockedRoot:
        try:
            self.root_fd = _open_owner_directory_path(self.root)
            root_stat = os.fstat(self.root_fd)
            named_root = os.stat(self.root, follow_symlinks=False)
            if _FileIdentity.from_stat(root_stat) != _FileIdentity.from_stat(named_root):
                _reject("root-race")
            self.lock_fd = os.open(
                LOCK_FILENAME,
                os.O_RDWR | _required_os_flag(_O_CLOEXEC) | _required_os_flag(_O_NOFOLLOW),
                dir_fd=self.root_fd,
            )
            lock_stat = os.fstat(self.lock_fd)
            _require_owner_regular(lock_stat, expected_mode=0o600, max_bytes=0, allow_empty=True)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
            named_lock = os.stat(LOCK_FILENAME, dir_fd=self.root_fd, follow_symlinks=False)
            if _FileIdentity.from_stat(named_lock) != _FileIdentity.from_stat(lock_stat):
                _reject("lock-race")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: object,
    ) -> None:
        with contextlib.suppress(OSError):
            if self.lock_fd >= 0:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        for descriptor in (self.lock_fd, self.root_fd):
            with contextlib.suppress(OSError):
                if descriptor >= 0:
                    os.close(descriptor)
        self.lock_fd = -1
        self.root_fd = -1


def current_dispatcher_sha256() -> str:
    """Return the SHA-256 commitment for the dispatcher script bytes."""

    hasher = hashlib.sha256()
    with Path(__file__).open("rb") as script:
        for chunk in iter(lambda: script.read(READ_CHUNK_BYTES), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def dispatch_frame(
    raw_exchange: bytes,
    *,
    remote_root: Path | None = None,
    environ: Mapping[str, str] | None = None,
    exec_handoff: ExecHandoff | None = None,
) -> bytes:
    """Dispatch a closed byte-string exchange for tests and loopback callers."""

    request, artifact_stream = _parse_request_from_closed_bytes(raw_exchange)
    outcome = _dispatch_request(
        request,
        remote_root=_resolve_remote_root(remote_root),
        environ={} if environ is None else environ,
        artifact_stream=artifact_stream,
        closed_artifact_stream=True,
        enforce_process_identity=False,
    )
    try:
        if outcome.handoff is not None and exec_handoff is not None:
            exec_handoff(outcome.handoff.argv, outcome.handoff.executable_fd)
        return outcome.response
    finally:
        if outcome.handoff is not None:
            _close_handoff(outcome.handoff)


def main(
    argv: Sequence[str] | None = None,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run as an OpenSSH forced command."""

    real_argv = sys.argv if argv is None else argv
    input_stream = sys.stdin.buffer if stdin is None else stdin
    output_stream = sys.stdout.buffer if stdout is None else stdout
    error_stream = sys.stderr if stderr is None else stderr
    outcome: _DispatchOutcome | None = None
    try:
        if len(real_argv) != 1:
            _reject("argv")
        request = _read_request_from_stdin(input_stream)
        outcome = _dispatch_request(
            request,
            remote_root=_resolve_remote_root(None),
            environ=os.environ,
            artifact_stream=input_stream,
            closed_artifact_stream=False,
            enforce_process_identity=True,
        )
        output_stream.write(outcome.response)
        output_stream.flush()
        if outcome.handoff is not None:
            _exec_handoff(outcome.handoff)
        return 0
    except BaseException:
        with contextlib.suppress(BaseException):
            error_stream.write("reachy-a05-dispatcher-rejected\n")
            error_stream.flush()
        return 1
    finally:
        if outcome is not None and outcome.handoff is not None:
            _close_handoff(outcome.handoff)


def _parse_request_from_closed_bytes(raw_exchange: bytes) -> tuple[_Request, BinaryIO]:
    if type(raw_exchange) is not bytes or len(raw_exchange) < FRAME_PREFIX.size:
        _reject("frame")
    declared_length = FRAME_PREFIX.unpack(raw_exchange[: FRAME_PREFIX.size])[0]
    if not 1 <= declared_length <= MAX_REQUEST_BYTES:
        _reject("frame-size")
    body_start = FRAME_PREFIX.size
    body_end = body_start + declared_length
    if len(raw_exchange) < body_end:
        _reject("frame-eof")
    request = _parse_request_body(raw_exchange[body_start:body_end])
    tail = raw_exchange[body_end:]
    if request.verb != "stage" and tail:
        _reject("frame-extra")
    return request, io.BytesIO(tail)


def _read_request_from_stdin(stdin: BinaryIO) -> _Request:
    header = _read_exact(stdin, FRAME_PREFIX.size)
    declared_length = FRAME_PREFIX.unpack(header)[0]
    if not 1 <= declared_length <= MAX_REQUEST_BYTES:
        _reject("frame-size")
    request = _parse_request_body(_read_exact(stdin, declared_length))
    if request.verb not in {"stage", "run_ptt"}:
        _require_stream_eof(stdin)
    return request


def _dispatch_request(
    request: _Request,
    *,
    remote_root: Path,
    environ: Mapping[str, str],
    artifact_stream: BinaryIO,
    closed_artifact_stream: bool,
    enforce_process_identity: bool,
) -> _DispatchOutcome:
    _require_empty_original_command(environ)
    with _LockedRoot(remote_root) as locked:
        state = _read_state_locked(locked.root_fd, locked.root)
        deployment = _deployment(state)
        if enforce_process_identity:
            _require_process_identity(deployment, locked.root)
        if not hmac.compare_digest(
            request.commissioning_id,
            _require_str(deployment["commissioning_id"]),
        ):
            _reject("commissioning")
        return _dispatch_locked(
            locked,
            request,
            state,
            artifact_stream=artifact_stream,
            closed_artifact_stream=closed_artifact_stream,
        )


def _dispatch_locked(
    locked: _LockedRoot,
    request: _Request,
    state: JsonObject,
    *,
    artifact_stream: BinaryIO,
    closed_artifact_stream: bool,
) -> _DispatchOutcome:
    if request.verb == "status":
        return _handle_status(request, state)
    if request.verb == "stage":
        return _handle_stage(
            locked,
            request,
            state,
            artifact_stream=artifact_stream,
            closed_artifact_stream=closed_artifact_stream,
        )
    if request.verb == "activate":
        return _handle_activate(locked, request, state)
    if request.verb == "run_ptt":
        return _handle_run_ptt(locked.root, request, state)
    if request.verb == "remove":
        return _handle_remove(locked, request, state)
    if request.verb == "verify_absent":
        return _handle_verify_absent(locked, request, state)
    _reject("verb")


def _handle_status(request: _Request, state: JsonObject) -> _DispatchOutcome:
    _require_exact_keys(request.payload, frozenset())
    return _DispatchOutcome(_response(request, state, _status_payload(state)))


def _handle_stage(
    locked: _LockedRoot,
    request: _Request,
    state: JsonObject,
    *,
    artifact_stream: BinaryIO,
    closed_artifact_stream: bool,
) -> _DispatchOutcome:
    plan = _parse_stage_payload(request.payload)
    deployment = _deployment(state)
    current_generation = _require_generation(deployment["state_generation"])
    staged_generation = _optional_sha256(deployment["staged_bundle_sha256"])
    active_generation = _optional_sha256(deployment["active_bundle_sha256"])
    if staged_generation == plan.bundle_sha256 or active_generation == plan.bundle_sha256:
        _validate_bundle_directory(locked.root / GENERATIONS_DIRNAME / plan.bundle_sha256)
        _consume_stage_artifacts(plan, artifact_stream)
        _reject_if_artifact_tail(artifact_stream, closed_artifact_stream=closed_artifact_stream)
        return _DispatchOutcome(_response(request, state, _stage_payload_from_state(state)))
    if request.expected_state_generation != current_generation:
        _reject("cas")

    _materialize_generation(
        locked,
        plan,
        operation_id=request.operation_id,
        artifact_stream=artifact_stream,
        closed_artifact_stream=closed_artifact_stream,
    )
    published = _publish_state(
        locked.root_fd,
        locked.root,
        _state_with_deployment(
            state,
            {
                "state_generation": current_generation + 1,
                "status": "staged",
                "staged_bundle_sha256": plan.bundle_sha256,
                "active_bundle_sha256": None,
            },
        ),
        expected_current=state,
    )
    return _DispatchOutcome(_response(request, published, _stage_payload_from_state(published)))


def _handle_activate(locked: _LockedRoot, request: _Request, state: JsonObject) -> _DispatchOutcome:
    bundle_sha256 = _parse_bundle_sha_payload(request.payload)
    deployment = _deployment(state)
    current_generation = _require_generation(deployment["state_generation"])
    active_generation = _optional_sha256(deployment["active_bundle_sha256"])
    if active_generation == bundle_sha256:
        _validate_bundle_directory(locked.root / GENERATIONS_DIRNAME / bundle_sha256)
        return _DispatchOutcome(_response(request, state, _stage_payload_from_state(state)))
    if request.expected_state_generation != current_generation:
        _reject("cas")
    if _optional_sha256(deployment["staged_bundle_sha256"]) != bundle_sha256:
        _reject("activate-state")

    _validate_bundle_directory(locked.root / GENERATIONS_DIRNAME / bundle_sha256)
    published = _publish_state(
        locked.root_fd,
        locked.root,
        _state_with_deployment(
            state,
            {
                "state_generation": current_generation + 1,
                "status": "active",
                "staged_bundle_sha256": None,
                "active_bundle_sha256": bundle_sha256,
            },
        ),
        expected_current=state,
    )
    return _DispatchOutcome(_response(request, published, _stage_payload_from_state(published)))


def _handle_run_ptt(root: Path, request: _Request, state: JsonObject) -> _DispatchOutcome:
    _require_exact_keys(request.payload, RUN_PTT_PAYLOAD_KEYS)
    deployment = _deployment(state)
    current_generation = _require_generation(deployment["state_generation"])
    if request.expected_state_generation != current_generation:
        _reject("cas")
    if _require_str(deployment["status"]) != "active":
        _reject("ptt-state")
    turn_id = _canonical_uuid(_require_str(request.payload["turn_id"]))
    input_mode = _require_str(request.payload["input_mode"])
    if input_mode not in PTT_INPUT_MODES or input_mode != _require_str(
        deployment["ptt_input_mode"]
    ):
        _reject("ptt-mode")
    active_generation = _optional_sha256(deployment["active_bundle_sha256"])
    if active_generation is None:
        _reject("ptt-generation")
    generation = root / GENERATIONS_DIRNAME / active_generation
    generation_fd = -1
    executable_fd = -1
    try:
        generation_fd = _open_owner_directory_path(generation)
        generation_identity = _FileIdentity.from_stat(os.fstat(generation_fd))
        manifest = _validate_bundle_directory(generation)
        _revalidate_owner_directory_path(generation, generation_fd, generation_identity)
        entrypoint = _entrypoint_from_manifest(manifest)
        executable_records = [
            record
            for record in _require_artifact_records(manifest["artifacts"])
            if _require_str(record["path"]) == entrypoint[0]
        ]
        if len(executable_records) != 1:
            _reject("entrypoint-executable")
        executable_sha256 = _require_sha256(executable_records[0]["sha256"])
        executable_fd, executable_identity = _open_validated_executable_at(
            generation_fd,
            entrypoint[0],
            executable_sha256,
        )
        _revalidate_owner_directory_path(generation, generation_fd, generation_identity)
        executable = generation / entrypoint[0]
        argv = (
            str(executable),
            *entrypoint[1:],
            "--turn-id",
            turn_id,
            "--input-mode",
            input_mode,
        )
        _validate_exec_argv(argv)
        ready: JsonObject = {"ready": True, "input_mode": input_mode}
        result = _DispatchOutcome(
            _response(request, state, ready),
            handoff=_ExecutableHandoff(
                argv=argv,
                entrypoint_module=entrypoint[2],
                manifest_bytes=_canonical_bytes(manifest),
                generation_path=generation,
                generation_fd=generation_fd,
                generation_identity=generation_identity,
                executable_fd=executable_fd,
                executable_identity=executable_identity,
                executable_sha256=executable_sha256,
            ),
        )
        generation_fd = -1
        executable_fd = -1
        return result
    finally:
        for descriptor in (executable_fd, generation_fd):
            with contextlib.suppress(OSError):
                if descriptor >= 0:
                    os.close(descriptor)


def _handle_remove(locked: _LockedRoot, request: _Request, state: JsonObject) -> _DispatchOutcome:
    bundle_sha256 = _parse_bundle_sha_payload(request.payload)
    deployment = _deployment(state)
    current_generation = _require_generation(deployment["state_generation"])
    generation_path = locked.root / GENERATIONS_DIRNAME / bundle_sha256
    active_generation = _optional_sha256(deployment["active_bundle_sha256"])
    staged_generation = _optional_sha256(deployment["staged_bundle_sha256"])
    already_absent = (
        active_generation != bundle_sha256
        and staged_generation != bundle_sha256
        and not _exists_no_follow(generation_path)
    )
    if already_absent:
        payload: JsonObject = {
            "active_bundle_sha256": active_generation,
            "staged_bundle_sha256": staged_generation,
            "verified_absent": bundle_sha256,
        }
        return _DispatchOutcome(_response(request, state, payload))
    if request.expected_state_generation != current_generation:
        _reject("cas")

    updates: JsonObject = {
        "state_generation": current_generation + 1,
        "active_bundle_sha256": None if active_generation == bundle_sha256 else active_generation,
        "staged_bundle_sha256": None if staged_generation == bundle_sha256 else staged_generation,
    }
    if updates["active_bundle_sha256"] is None and updates["staged_bundle_sha256"] is None:
        updates["status"] = "removed"
    elif updates["active_bundle_sha256"] is not None:
        updates["status"] = "active"
    else:
        updates["status"] = "staged"
    published = _publish_state(
        locked.root_fd,
        locked.root,
        _state_with_deployment(state, updates),
        expected_current=state,
    )
    _safe_remove_generation(locked.root, bundle_sha256)
    payload = _stage_payload_from_state(published)
    payload["verified_absent"] = bundle_sha256
    return _DispatchOutcome(_response(request, published, payload))


def _handle_verify_absent(
    locked: _LockedRoot,
    request: _Request,
    state: JsonObject,
) -> _DispatchOutcome:
    bundle_sha256 = _parse_bundle_sha_payload(request.payload)
    deployment = _deployment(state)
    if request.expected_state_generation != _require_generation(deployment["state_generation"]):
        _reject("cas")
    active_bundle_sha256 = _optional_sha256(deployment["active_bundle_sha256"])
    staged_bundle_sha256 = _optional_sha256(deployment["staged_bundle_sha256"])
    if bundle_sha256 in {active_bundle_sha256, staged_bundle_sha256}:
        _reject("state-reference")
    generations_fd = -1
    staging_fd = -1
    try:
        generations_fd = _open_optional_owner_directory_at(
            locked.root_fd,
            GENERATIONS_DIRNAME,
        )
        if generations_fd >= 0 and _entry_exists_at(generations_fd, bundle_sha256):
            _reject("present")
        staging_fd = _open_optional_owner_directory_at(locked.root_fd, STAGING_DIRNAME)
        if staging_fd >= 0:
            staging_before = _FileIdentity.from_stat(os.fstat(staging_fd))
            count = 0
            with os.scandir(staging_fd) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_GENERATION_ENTRIES:
                        _reject("staging-count")
                    info = os.stat(entry.name, dir_fd=staging_fd, follow_symlinks=False)
                    _require_owner_directory_stat(info)
                    if bundle_sha256 in entry.name:
                        _reject("present")
            if _FileIdentity.from_stat(os.fstat(staging_fd)) != staging_before:
                _reject("staging-race")
            _revalidate_owner_directory_at(locked.root_fd, STAGING_DIRNAME, staging_fd)
        if generations_fd >= 0 and _entry_exists_at(generations_fd, bundle_sha256):
            _reject("present")
        if generations_fd >= 0:
            _revalidate_owner_directory_at(
                locked.root_fd,
                GENERATIONS_DIRNAME,
                generations_fd,
            )
    finally:
        for descriptor in (staging_fd, generations_fd):
            with contextlib.suppress(OSError):
                if descriptor >= 0:
                    os.close(descriptor)
    payload: JsonObject = {
        "active_bundle_sha256": active_bundle_sha256,
        "staged_bundle_sha256": staged_bundle_sha256,
        "verified_absent": bundle_sha256,
    }
    return _DispatchOutcome(_response(request, state, payload))


def _parse_request_body(body: bytes) -> _Request:
    decoded = _parse_json_object(body, max_bytes=MAX_REQUEST_BYTES)
    _require_exact_keys(decoded, REQUEST_KEYS)
    if _require_int(decoded["version"], minimum=1, maximum=1) != 1:
        _reject("version")
    operation_id = _canonical_uuid(_require_str(decoded["operation_id"]))
    verb = _require_str(decoded["verb"])
    if verb not in VERBS:
        _reject("verb")
    commissioning_id = _canonical_uuid(_require_str(decoded["commissioning_id"]))
    expected_state_generation = _require_generation(decoded["expected_state_generation"])
    payload = _require_object(decoded["payload"])
    return _Request(
        operation_id=operation_id,
        verb=verb,
        commissioning_id=commissioning_id,
        expected_state_generation=expected_state_generation,
        payload=payload,
    )


def _response(request: _Request, state: JsonObject, payload: JsonObject) -> bytes:
    deployment = _deployment(state)
    body: JsonObject = {
        "version": 1,
        "operation_id": request.operation_id,
        "ok": True,
        "state_generation": _require_generation(deployment["state_generation"]),
        "status": _require_status(deployment["status"]),
        "payload": payload,
    }
    _require_exact_keys(body, RESPONSE_KEYS)
    raw = _canonical_bytes(body)
    if not 1 <= len(raw) <= MAX_RESPONSE_BYTES:
        _reject("response-size")
    return FRAME_PREFIX.pack(len(raw)) + raw


def _status_payload(state: JsonObject) -> JsonObject:
    deployment = _deployment(state)
    runtime = _runtime(deployment)
    payload: JsonObject = {
        "active_bundle_sha256": _optional_sha256(deployment["active_bundle_sha256"]),
        "authorized_key_line_sha256": _require_sha256(deployment["authorized_key_line_sha256"]),
        "boot_identity_sha256": _require_sha256(deployment["boot_identity_sha256"]),
        "capability_report_sha256": _require_sha256(deployment["capability_report_sha256"]),
        "dispatcher_protocol_version": _require_str(deployment["dispatcher_protocol_version"]),
        "dispatcher_sha256": _require_sha256(deployment["dispatcher_sha256"]),
        "runtime_inventory_sha256": _require_sha256(runtime["runtime_inventory_sha256"]),
        "staged_bundle_sha256": _optional_sha256(deployment["staged_bundle_sha256"]),
    }
    _require_exact_keys(payload, STATUS_PAYLOAD_KEYS)
    return payload


def _stage_payload_from_state(state: JsonObject) -> JsonObject:
    deployment = _deployment(state)
    return {
        "active_bundle_sha256": _optional_sha256(deployment["active_bundle_sha256"]),
        "staged_bundle_sha256": _optional_sha256(deployment["staged_bundle_sha256"]),
    }


def _parse_stage_payload(payload: JsonObject) -> _StagePlan:
    _require_exact_keys(payload, STAGE_PAYLOAD_KEYS)
    bundle_sha256 = _require_sha256(payload["bundle_sha256"])
    artifact_values = _require_list(payload["artifacts"])
    if not 1 <= len(artifact_values) <= MAX_ARTIFACTS:
        _reject("artifact-count")

    artifacts: list[_StageArtifact] = []
    seen_paths: set[str] = set()
    total_size = 0
    for value in artifact_values:
        artifact_object = _require_object(value)
        _require_exact_keys(artifact_object, ARTIFACT_RECORD_KEYS)
        path = _require_str(artifact_object["path"])
        parts = _relative_path_parts(path)
        if path in seen_paths:
            _reject("artifact-duplicate")
        seen_paths.add(path)
        size = _require_int(artifact_object["size"], minimum=0, maximum=MAX_ARTIFACT_BYTES)
        total_size += size
        if total_size > MAX_TOTAL_ARTIFACT_BYTES:
            _reject("artifact-total")
        sha256 = _require_sha256(artifact_object["sha256"])
        executable = _require_bool(artifact_object["executable"])
        artifacts.append(
            _StageArtifact(
                path=path,
                parts=parts,
                size=size,
                sha256=sha256,
                executable=executable,
            )
        )
    plan = _StagePlan(bundle_sha256=bundle_sha256, artifacts=tuple(artifacts))
    if "manifest.json" not in seen_paths:
        _reject("stage-manifest")
    computed = hashlib.sha256(_canonical_bytes(plan.bundle_descriptor())).hexdigest()
    if not hmac.compare_digest(computed, bundle_sha256):
        _reject("bundle-digest")
    return plan


def _parse_bundle_sha_payload(payload: JsonObject) -> str:
    _require_exact_keys(payload, BUNDLE_SHA_PAYLOAD_KEYS)
    return _require_sha256(payload["bundle_sha256"])


def _materialize_generation(
    locked: _LockedRoot,
    plan: _StagePlan,
    *,
    operation_id: str,
    artifact_stream: BinaryIO,
    closed_artifact_stream: bool,
) -> None:
    root = locked.root
    generations = root / GENERATIONS_DIRNAME
    _ensure_owner_directory_path(generations)
    staging_parent = root / STAGING_DIRNAME
    _ensure_owner_directory_path(staging_parent)
    temp = staging_parent / f"{operation_id}.{plan.bundle_sha256}"
    final = generations / plan.bundle_sha256
    if _exists_no_follow(final):
        _validate_bundle_directory(final)
        _consume_stage_artifacts(plan, artifact_stream)
        _reject_if_artifact_tail(artifact_stream, closed_artifact_stream=closed_artifact_stream)
        _cleanup_empty_directory(staging_parent)
        return
    if _exists_no_follow(temp):
        _safe_remove_tree(temp)
    try:
        _ensure_owner_directory_path(temp)
        for artifact in plan.artifacts:
            _write_artifact_from_stream(temp, artifact, artifact_stream)
        _reject_if_artifact_tail(artifact_stream, closed_artifact_stream=closed_artifact_stream)
        _validate_bundle_directory(temp, expected_bundle=plan.bundle_sha256)
        _fsync_directory(temp)
        _promote_generation(locked.root_fd, temp.name, final.name)
        _validate_bundle_directory(final)
    except BaseException:
        with contextlib.suppress(DispatcherRejected, OSError):
            if _exists_no_follow(temp):
                _safe_remove_tree(temp)
        with contextlib.suppress(OSError):
            _cleanup_empty_directory(staging_parent)
        raise
    _cleanup_empty_directory(staging_parent)


def _promote_generation(root_fd: int, staging_name: str, generation_name: str) -> None:
    staging_fd = -1
    generations_fd = -1
    candidate_fd = -1
    try:
        staging_fd = _open_optional_owner_directory_at(root_fd, STAGING_DIRNAME)
        generations_fd = _open_optional_owner_directory_at(root_fd, GENERATIONS_DIRNAME)
        if staging_fd < 0 or generations_fd < 0:
            _reject("generation-parent")
        candidate_fd = os.open(
            staging_name,
            os.O_RDONLY
            | _required_os_flag(_O_CLOEXEC)
            | _required_os_flag(_O_DIRECTORY)
            | _required_os_flag(_O_NOFOLLOW),
            dir_fd=staging_fd,
        )
        candidate_identity = _FileIdentity.from_stat(os.fstat(candidate_fd))
        _require_owner_directory_stat(os.fstat(candidate_fd))
        named_candidate = os.stat(
            staging_name,
            dir_fd=staging_fd,
            follow_symlinks=False,
        )
        if _FileIdentity.from_stat(named_candidate) != candidate_identity:
            _reject("generation-race")
        os.fsync(candidate_fd)
        os.fsync(staging_fd)
        os.fsync(generations_fd)
        if _entry_exists_at(generations_fd, generation_name):
            _reject("generation-present")
        try:
            _rename_noreplace(
                staging_fd,
                staging_name,
                generations_fd,
                generation_name,
            )
        except FileExistsError:
            _reject("generation-present")
        promoted = os.stat(
            generation_name,
            dir_fd=generations_fd,
            follow_symlinks=False,
        )
        opened_after = os.fstat(candidate_fd)
        _require_owner_directory_stat(opened_after)
        if _FileIdentity.from_stat(promoted) != _FileIdentity.from_stat(
            opened_after
        ) or _entry_exists_at(staging_fd, staging_name):
            _reject("generation-race")
        os.fsync(staging_fd)
        os.fsync(generations_fd)
        os.fsync(root_fd)
    except DispatcherRejected:
        raise
    except (OSError, ValueError):
        _reject("generation-promote")
    finally:
        for descriptor in (candidate_fd, generations_fd, staging_fd):
            with contextlib.suppress(OSError):
                if descriptor >= 0:
                    os.close(descriptor)


def _consume_stage_artifacts(plan: _StagePlan, artifact_stream: BinaryIO) -> None:
    for artifact in plan.artifacts:
        _hash_artifact_stream(artifact, artifact_stream, output_fd=None)


def _write_artifact_from_stream(
    base: Path,
    artifact: _StageArtifact,
    artifact_stream: BinaryIO,
) -> None:
    parent = base
    for part in artifact.parts[:-1]:
        parent = parent / part
        _ensure_owner_directory_path(parent)
    mode = 0o700 if artifact.executable else 0o600
    parent_fd = -1
    fd = -1
    try:
        parent_fd = _open_owner_directory_path(parent)
        fd = os.open(
            artifact.parts[-1],
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | _required_os_flag(_O_CLOEXEC)
            | _required_os_flag(_O_NOFOLLOW),
            mode,
            dir_fd=parent_fd,
        )
        os.fchmod(fd, mode)
        _hash_artifact_stream(artifact, artifact_stream, output_fd=fd)
        os.fsync(fd)
        info = os.fstat(fd)
        _require_owner_regular(
            info,
            expected_mode=mode,
            max_bytes=artifact.size,
            allow_empty=True,
        )
        if info.st_size != artifact.size:
            _reject("artifact-size")
        named = os.stat(artifact.parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if _FileIdentity.from_stat(named) != _FileIdentity.from_stat(info):
            _reject("artifact-race")
        os.fsync(parent_fd)
    except DispatcherRejected:
        raise
    except OSError:
        _reject("artifact-write")
    finally:
        with contextlib.suppress(OSError):
            if fd >= 0:
                os.close(fd)
        with contextlib.suppress(OSError):
            if parent_fd >= 0:
                os.close(parent_fd)


def _hash_artifact_stream(
    artifact: _StageArtifact,
    artifact_stream: BinaryIO,
    *,
    output_fd: int | None,
) -> None:
    hasher = hashlib.sha256()
    remaining = artifact.size
    while remaining:
        chunk = artifact_stream.read(min(READ_CHUNK_BYTES, remaining))
        if chunk == b"":
            _reject("artifact-eof")
        if type(chunk) is not bytes:
            _reject("artifact-stream")
        hasher.update(chunk)
        if output_fd is not None:
            _write_all_fd(output_fd, chunk)
        remaining -= len(chunk)
    if not hmac.compare_digest(hasher.hexdigest(), artifact.sha256):
        _reject("artifact-digest")


def _reject_if_artifact_tail(
    artifact_stream: BinaryIO,
    *,
    closed_artifact_stream: bool,
) -> None:
    if closed_artifact_stream:
        if artifact_stream.read(1) != b"":
            _reject("artifact-extra")
        return
    _require_stream_eof(artifact_stream)


def _validate_bundle_directory(path: Path, *, expected_bundle: str | None = None) -> JsonObject:
    _require_owner_directory_path(path)
    manifest_raw = _read_generation_member(
        path,
        "manifest.json",
        expected_mode=0o600,
        allow_empty=False,
    )
    manifest = _parse_json_object(manifest_raw, max_bytes=MAX_ARTIFACT_BYTES)
    _require_exact_keys(manifest, MANIFEST_KEYS)
    if _require_str(manifest["schema_version"]) != BUNDLE_MANIFEST_SCHEMA_VERSION:
        _reject("manifest-schema")
    records = _require_artifact_records(manifest["artifacts"])
    _entrypoint_from_manifest(manifest)

    declared_records: list[JsonObject] = []
    allowed_paths = {"manifest.json"}
    for record in records:
        relative = _require_str(record["path"])
        executable = _require_bool(record["executable"])
        raw = _read_generation_member(
            path,
            relative,
            expected_mode=0o700 if executable else 0o600,
            allow_empty=True,
        )
        size = _require_int(record["size"], minimum=0, maximum=MAX_ARTIFACT_BYTES)
        sha256 = _require_sha256(record["sha256"])
        if len(raw) != size or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), sha256):
            _reject("generation-digest")
        declared_records.append(record)
        allowed_paths.add(relative)

    _reject_unmanifested_generation_entries(path, allowed_paths)
    manifest_artifact: JsonObject = {
        "path": "manifest.json",
        "size": len(manifest_raw),
        "sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "executable": False,
    }
    descriptor: JsonObject = {
        "schema_version": BUNDLE_DESCRIPTOR_SCHEMA_VERSION,
        "manifest_sha256": _require_sha256(manifest_artifact["sha256"]),
        "artifacts": [manifest_artifact, *declared_records],
    }
    bundle_sha256 = path.name if expected_bundle is None else expected_bundle
    if not _is_sha256(bundle_sha256):
        _reject("generation-name")
    actual_bundle = hashlib.sha256(_canonical_bytes(descriptor)).hexdigest()
    if not hmac.compare_digest(actual_bundle, bundle_sha256):
        _reject("bundle-digest")
    return manifest


def _require_artifact_records(value: JsonValue) -> list[JsonObject]:
    records = _require_list(value)
    if not 1 <= len(records) <= MAX_ARTIFACTS - 1:
        _reject("manifest-artifacts")
    result: list[JsonObject] = []
    seen_paths: set[str] = set()
    total_size = 0
    for record_value in records:
        record = _require_object(record_value)
        _require_exact_keys(record, ARTIFACT_RECORD_KEYS)
        relative = _require_str(record["path"])
        if relative == "manifest.json":
            _reject("manifest-artifacts")
        _relative_path_parts(relative)
        if relative in seen_paths:
            _reject("manifest-duplicate")
        seen_paths.add(relative)
        size = _require_int(record["size"], minimum=0, maximum=MAX_ARTIFACT_BYTES)
        total_size += size
        if total_size > MAX_TOTAL_ARTIFACT_BYTES:
            _reject("manifest-total")
        _require_sha256(record["sha256"])
        _require_bool(record["executable"])
        result.append(record)
    return result


def _entrypoint_from_manifest(manifest: JsonObject) -> tuple[str, ...]:
    entrypoint_value = _require_list(manifest["entrypoint"])
    entrypoint = tuple(_require_str(item) for item in entrypoint_value)
    if len(entrypoint) != 3:
        _reject("entrypoint")
    executable, module_flag, module = entrypoint
    _relative_path_parts(executable)
    if module_flag != "-m" or module not in ALLOWED_PTT_MODULES:
        _reject("entrypoint-module")
    _validate_exec_argv(entrypoint)
    records = _require_artifact_records(manifest["artifacts"])
    executable_records = [
        record
        for record in records
        if _require_str(record["path"]) == executable and _require_bool(record["executable"])
    ]
    if len(executable_records) != 1:
        _reject("entrypoint-executable")
    return entrypoint


def _read_generation_member(
    base: Path,
    relative: str,
    *,
    expected_mode: int,
    allow_empty: bool,
) -> bytes:
    path = _generation_member_path(base, relative)
    return _read_regular_file_path(
        path,
        max_bytes=MAX_ARTIFACT_BYTES,
        expected_mode=expected_mode,
        allow_empty=allow_empty,
    )


def _generation_member_path(base: Path, relative: str) -> Path:
    parts = _relative_path_parts(relative)
    parent = base
    for part in parts[:-1]:
        parent = parent / part
        _require_owner_directory_path(parent)
    return base.joinpath(*parts)


def _reject_unmanifested_generation_entries(base: Path, allowed_paths: set[str]) -> None:
    allowed_directories: set[str] = set()
    for allowed_path in allowed_paths:
        parts = allowed_path.split("/")
        for length in range(1, len(parts)):
            allowed_directories.add("/".join(parts[:length]))
    base_fd = -1
    visited = [0]

    def walk(directory_fd: int, prefix: str, depth: int) -> None:
        if depth > MAX_ARTIFACT_PATH_DEPTH:
            _reject("generation-depth")
        directory_before = _FileIdentity.from_stat(os.fstat(directory_fd))
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                name = entry.name
                if (
                    not name
                    or name in {".", ".."}
                    or "/" in name
                    or len(name) > 255
                    or not name.isascii()
                    or any(character not in _PORTABLE_PATH_CHARS for character in name)
                ):
                    _reject("generation-path")
                visited[0] += 1
                if visited[0] > MAX_GENERATION_ENTRIES:
                    _reject("generation-count")
                relative = name if not prefix else f"{prefix}/{name}"
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    _require_owner_directory_stat(info)
                    if relative not in allowed_directories:
                        _reject("generation-extra")
                    child_fd = -1
                    try:
                        child_fd = os.open(
                            name,
                            os.O_RDONLY
                            | _required_os_flag(_O_CLOEXEC)
                            | _required_os_flag(_O_DIRECTORY)
                            | _required_os_flag(_O_NOFOLLOW),
                            dir_fd=directory_fd,
                        )
                        opened = os.fstat(child_fd)
                        if _FileIdentity.from_stat(opened) != _FileIdentity.from_stat(info):
                            _reject("generation-race")
                        walk(child_fd, relative, depth + 1)
                        named_after = os.stat(
                            name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                        if _FileIdentity.from_stat(named_after) != _FileIdentity.from_stat(
                            os.fstat(child_fd)
                        ):
                            _reject("generation-race")
                    finally:
                        with contextlib.suppress(OSError):
                            if child_fd >= 0:
                                os.close(child_fd)
                    continue
                _require_owner_regular(
                    info,
                    expected_mode=None,
                    max_bytes=MAX_ARTIFACT_BYTES,
                    allow_empty=True,
                )
                if relative not in allowed_paths:
                    _reject("generation-extra")
        if _FileIdentity.from_stat(os.fstat(directory_fd)) != directory_before:
            _reject("generation-race")

    try:
        base_fd = _open_owner_directory_path(base)
        base_identity = _FileIdentity.from_stat(os.fstat(base_fd))
        walk(base_fd, "", 1)
        reopened_fd = _open_owner_directory_path(base)
        try:
            if _FileIdentity.from_stat(os.fstat(reopened_fd)) != base_identity:
                _reject("generation-race")
        finally:
            os.close(reopened_fd)
    except DispatcherRejected:
        raise
    except OSError:
        _reject("generation-walk")
    finally:
        with contextlib.suppress(OSError):
            if base_fd >= 0:
                os.close(base_fd)


def _safe_remove_generation(root: Path, bundle_sha256: str) -> None:
    generation = root / GENERATIONS_DIRNAME / bundle_sha256
    if not _exists_no_follow(generation):
        return
    _safe_remove_tree(generation)
    _fsync_directory(root / GENERATIONS_DIRNAME)


def _safe_remove_tree(path: Path) -> None:
    parent_fd = -1
    try:
        parent_fd = _open_owner_directory_path(path.parent)
        _safe_remove_entry_at(parent_fd, path.name, visited=[0])
        os.fsync(parent_fd)
    except FileNotFoundError:
        return
    except DispatcherRejected:
        raise
    except OSError:
        _reject("remove")
    finally:
        with contextlib.suppress(OSError):
            if parent_fd >= 0:
                os.close(parent_fd)


def _safe_remove_entry_at(parent_fd: int, name: str, *, visited: list[int]) -> None:
    if not name or "/" in name or name in {".", ".."}:
        _reject("remove-path")
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    visited[0] += 1
    if visited[0] > MAX_GENERATION_ENTRIES:
        _reject("remove-count")
    if stat.S_ISREG(before.st_mode):
        _require_owner_regular(
            before,
            expected_mode=None,
            max_bytes=MAX_ARTIFACT_BYTES,
            allow_empty=True,
        )
        os.unlink(name, dir_fd=parent_fd)
        return
    if not stat.S_ISDIR(before.st_mode):
        _reject("remove-special")
    _require_owner_directory_stat(before)
    child_fd = -1
    try:
        child_fd = os.open(
            name,
            os.O_RDONLY
            | _required_os_flag(_O_CLOEXEC)
            | _required_os_flag(_O_DIRECTORY)
            | _required_os_flag(_O_NOFOLLOW),
            dir_fd=parent_fd,
        )
        opened = os.fstat(child_fd)
        if _FileIdentity.from_stat(opened) != _FileIdentity.from_stat(before):
            _reject("remove-race")
        with os.scandir(child_fd) as entries:
            for entry in entries:
                _safe_remove_entry_at(child_fd, entry.name, visited=visited)
        after = os.fstat(child_fd)
        named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _FileIdentity.from_stat(named_after) != _FileIdentity.from_stat(after):
            _reject("remove-race")
        os.fsync(child_fd)
        os.rmdir(name, dir_fd=parent_fd)
    finally:
        with contextlib.suppress(OSError):
            if child_fd >= 0:
                os.close(child_fd)


def _read_state_locked(root_fd: int, root: Path) -> JsonObject:
    raw = _read_regular_file_at(
        root_fd,
        STATE_FILENAME,
        max_bytes=MAX_STATE_BYTES,
        expected_mode=0o600,
        allow_empty=False,
    )
    return _validate_state_raw(raw, root)


def _publish_state(
    root_fd: int,
    root: Path,
    state: JsonObject,
    *,
    expected_current: JsonObject,
) -> JsonObject:
    validated = _validate_state_object(state, root)
    raw = _canonical_bytes(validated)
    expected_raw = _canonical_bytes(_validate_state_object(expected_current, root))
    if not 1 <= len(raw) <= MAX_STATE_BYTES:
        _reject("state-size")
    observed = _read_state_locked(root_fd, root)
    if not hmac.compare_digest(_canonical_bytes(observed), expected_raw):
        _reject("state-cas")
    temp_name = f".remote-state.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    fd = -1
    temp_present = False
    exchanged = False

    def named_state_matches(name: str, expected: bytes) -> bool:
        try:
            actual = _read_regular_file_at(
                root_fd,
                name,
                max_bytes=MAX_STATE_BYTES,
                expected_mode=0o600,
                allow_empty=False,
            )
            _validate_state_raw(actual, root)
        except (DispatcherRejected, OSError, ValueError):
            return False
        return hmac.compare_digest(actual, expected)

    def restore_previous_state(code: str) -> NoReturn:
        nonlocal exchanged
        try:
            _rename_exchange(root_fd, temp_name, STATE_FILENAME)
            os.fsync(root_fd)
            exchanged = False
        except (OSError, ValueError):
            _reject("state-rollback")
        _reject(code)

    try:
        fd = os.open(
            temp_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | _required_os_flag(_O_CLOEXEC)
            | _required_os_flag(_O_NOFOLLOW),
            0o600,
            dir_fd=root_fd,
        )
        temp_present = True
        os.fchmod(fd, 0o600)
        _write_all_fd(fd, raw)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        _rename_exchange(root_fd, temp_name, STATE_FILENAME)
        exchanged = True
        if not named_state_matches(STATE_FILENAME, raw) or not named_state_matches(
            temp_name, expected_raw
        ):
            restore_previous_state("state-cas")
        try:
            os.fsync(root_fd)
        except OSError:
            restore_previous_state("state-publish")
        if not named_state_matches(STATE_FILENAME, raw) or not named_state_matches(
            temp_name, expected_raw
        ):
            restore_previous_state("state-cas")
        os.unlink(temp_name, dir_fd=root_fd)
        temp_present = False
        exchanged = False
        os.fsync(root_fd)
    except DispatcherRejected:
        raise
    except (OSError, ValueError):
        if exchanged:
            restore_previous_state("state-publish")
        _reject("state-publish")
    finally:
        with contextlib.suppress(OSError):
            if fd >= 0:
                os.close(fd)
        if temp_present and not exchanged:
            with contextlib.suppress(OSError):
                os.unlink(temp_name, dir_fd=root_fd)
    published = _read_state_locked(root_fd, root)
    if not hmac.compare_digest(_canonical_bytes(published), raw):
        _reject("state-publish")
    return published


def _validate_state_raw(raw: bytes, root: Path) -> JsonObject:
    return _validate_state_object(_parse_json_object(raw, max_bytes=MAX_STATE_BYTES), root)


def _validate_state_object(state: JsonObject, root: Path) -> JsonObject:
    _require_exact_keys(state, STATE_KEYS)
    if _require_str(state["schema_version"]) != REMOTE_STATE_SCHEMA_VERSION:
        _reject("state-schema")
    deployment = _deployment(state)
    _validate_deployment(deployment, root)
    return state


def _validate_deployment(deployment: JsonObject, root: Path) -> None:
    _require_exact_keys(deployment, DEPLOYMENT_KEYS)
    _canonical_uuid(_require_str(deployment["commissioning_id"]))
    _require_generation(deployment["state_generation"])
    status = _require_status(deployment["status"])
    if status == "revoked":
        _reject("state-status")
    issued_at = _parse_datetime(_require_str(deployment["issued_at"]))
    expires_at = _parse_datetime(_require_str(deployment["expires_at"]))
    now = datetime.now(UTC)
    if (
        not timedelta(0) < expires_at - issued_at <= timedelta(hours=24)
        or not issued_at <= now < expires_at
    ):
        _reject("state-freshness")

    _require_sha256(deployment["boot_identity_sha256"])
    _require_sha256(deployment["capability_report_sha256"])
    if _require_str(deployment["ptt_input_mode"]) not in PTT_INPUT_MODES:
        _reject("ptt-mode")
    runtime = _runtime(deployment)
    _validate_runtime(runtime)
    ssh_principal = _require_str(deployment["ssh_principal"])
    if (
        not 1 <= len(ssh_principal) <= 32
        or ssh_principal == "root"
        or ssh_principal[0] not in _PRINCIPAL_FIRST_CHARS
        or any(character not in _PRINCIPAL_REST_CHARS for character in ssh_principal[1:])
    ):
        _reject("principal")
    remote_home = _require_command_posix_absolute_path(deployment["remote_home"])
    remote_root = _require_command_posix_absolute_path(deployment["remote_root"])
    dispatcher_path = _require_command_posix_absolute_path(deployment["dispatcher_path"])
    if remote_root != f"{remote_home}/.local/share/tuntun/reachy-a05":
        _reject("remote-root")
    if remote_root != root.as_posix():
        _reject("remote-root")
    if dispatcher_path != f"{remote_root}/bootstrap/{DISPATCHER_BASENAME}":
        _reject("dispatcher-path")
    if _require_str(deployment["dispatcher_protocol_version"]) != DISPATCHER_PROTOCOL_VERSION:
        _reject("dispatcher-protocol")
    dispatcher_sha256 = _require_sha256(deployment["dispatcher_sha256"])
    if not hmac.compare_digest(dispatcher_sha256, current_dispatcher_sha256()):
        _reject("dispatcher-digest")
    _require_sha256(deployment["authorized_key_line_sha256"])

    staged_bundle = _optional_sha256(deployment["staged_bundle_sha256"])
    active_bundle = _optional_sha256(deployment["active_bundle_sha256"])
    if status == "staged":
        valid = staged_bundle is not None and active_bundle is None
    elif status == "active":
        valid = staged_bundle is None and active_bundle is not None
    else:
        valid = staged_bundle is None and active_bundle is None
    if not valid:
        _reject("state-status")


def _validate_runtime(runtime: JsonObject) -> None:
    _require_exact_keys(runtime, RUNTIME_KEYS)
    _require_command_posix_absolute_path(runtime["python_executable"])
    python_version = _require_str(runtime["python_version"])
    parsed_python = _parse_python_version(python_version)
    if parsed_python is None:
        _reject("runtime-python")
    python_abi = _require_str(runtime["python_abi"])
    if python_abi not in PYTHON_ABIS or (parsed_python[0], parsed_python[1], python_abi) not in {
        (3, 11, "cp311"),
        (3, 12, "cp312"),
    }:
        _reject("runtime-abi")
    if _require_str(runtime["selected_wheel_tag"]) != "py3-none-any":
        _reject("runtime-wheel")
    _require_sha256(runtime["target_tag_set_sha256"])
    _require_version_token(runtime["sdk_version"])
    _require_sha256(runtime["sdk_artifact_sha256"])
    _require_version_token(runtime["daemon_version"])
    _require_sha256(runtime["daemon_artifact_sha256"])
    _require_sha256(runtime["runtime_inventory_sha256"])


def _deployment(state: JsonObject) -> JsonObject:
    return _require_object(state["deployment"])


def _runtime(deployment: JsonObject) -> JsonObject:
    return _require_object(deployment["runtime"])


def _state_with_deployment(state: JsonObject, updates: Mapping[str, JsonValue]) -> JsonObject:
    deployment = dict(_deployment(state))
    deployment.update(updates)
    return {"schema_version": REMOTE_STATE_SCHEMA_VERSION, "deployment": deployment}


def _parse_json_object(raw: bytes, *, max_bytes: int) -> JsonObject:
    if type(raw) is not bytes or not 1 <= len(raw) <= max_bytes:
        _reject("json-size")
    try:
        decoded = raw.decode("utf-8")
        parsed = cast(
            object,
            json.loads(
                decoded,
                object_pairs_hook=_object_no_duplicates,
                parse_float=_reject_json_float,
                parse_int=_parse_json_int,
                parse_constant=_reject_json_constant,
            ),
        )
    except (RecursionError, TypeError, UnicodeDecodeError, ValueError):
        _reject("json")
    value = _validate_json_tree(parsed)
    if not isinstance(value, dict):
        _reject("json-object")
    result = value
    if _canonical_bytes(result) != raw:
        _reject("json-canonical")
    return result


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            _reject("json-duplicate")
        result[key] = _validate_json_tree(value)
    return result


def _validate_json_tree(value: object) -> JsonValue:
    if value is None or type(value) in {bool, int, str}:
        if type(value) is int and not -(MAX_JSON_INT) <= value <= MAX_JSON_INT:
            _reject("json-int")
        return cast(JsonValue, value)
    if isinstance(value, list):
        return [_validate_json_tree(item) for item in value]
    if isinstance(value, dict):
        result: JsonObject = {}
        for key, item in value.items():
            if type(key) is not str:
                _reject("json-key")
            result[key] = _validate_json_tree(item)
        return result
    _reject("json-type")


def _parse_json_int(value: str) -> int:
    if len(value) > 16:
        raise ValueError("JSON integer is out of range")
    parsed = int(value)
    if not -(MAX_JSON_INT) <= parsed <= MAX_JSON_INT:
        raise ValueError("JSON integer is out of range")
    return parsed


def _reject_json_float(_value: str) -> NoReturn:
    raise ValueError("JSON floats are not accepted")


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("JSON constants are not accepted")


def _canonical_bytes(value: JsonValue) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _read_exact(stdin: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stdin.read(remaining)
        if chunk == b"":
            _reject("eof")
        if type(chunk) is not bytes:
            _reject("stdin")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _require_stream_eof(stream: BinaryIO) -> None:
    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError):
        extra = stream.read(1)
        if type(extra) is not bytes or extra != b"":
            _reject("frame-extra")
        return
    try:
        readable, _, _ = select.select([descriptor], [], [], STREAM_EOF_SECONDS)
        if not readable:
            _reject("frame-eof")
        extra = os.read(descriptor, 1)
    except DispatcherRejected:
        raise
    except (OSError, ValueError):
        _reject("frame-eof")
    if extra != b"":
        _reject("frame-extra")


def _read_regular_file_at(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int,
    expected_mode: int,
    allow_empty: bool,
) -> bytes:
    if "/" in name or name in {"", ".", ".."}:
        _reject("path")
    fd = -1
    try:
        fd = os.open(
            name,
            os.O_RDONLY | _required_os_flag(_O_CLOEXEC) | _required_os_flag(_O_NOFOLLOW),
            dir_fd=directory_fd,
        )
        info = os.fstat(fd)
        _require_owner_regular(
            info,
            expected_mode=expected_mode,
            max_bytes=max_bytes,
            allow_empty=allow_empty,
        )
        raw = _read_fd_bounded(fd, max_bytes=max_bytes, allow_empty=allow_empty)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _FileIdentity.from_stat(named) != _FileIdentity.from_stat(info):
            _reject("file-race")
        return raw
    except DispatcherRejected:
        raise
    except OSError:
        _reject("file-read")
    finally:
        with contextlib.suppress(OSError):
            if fd >= 0:
                os.close(fd)


def _read_regular_file_path(
    path: Path,
    *,
    max_bytes: int,
    expected_mode: int,
    allow_empty: bool,
) -> bytes:
    parent_fd = -1
    try:
        parent_fd = _open_owner_directory_path(path.parent)
        return _read_regular_file_at(
            parent_fd,
            path.name,
            max_bytes=max_bytes,
            expected_mode=expected_mode,
            allow_empty=allow_empty,
        )
    except DispatcherRejected:
        raise
    except OSError:
        _reject("file-read")
    finally:
        with contextlib.suppress(OSError):
            if parent_fd >= 0:
                os.close(parent_fd)


def _read_fd_bounded(fd: int, *, max_bytes: int, allow_empty: bool) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(READ_CHUNK_BYTES, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            _reject("file-size")
    if total == 0 and not allow_empty:
        _reject("file-empty")
    return b"".join(chunks)


def _write_all_fd(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            raise OSError("short dispatcher write")
        offset += written


def _resolve_remote_root(remote_root: Path | None) -> Path:
    if remote_root is not None:
        return _absolute_lexical_path(remote_root)
    home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    return _absolute_lexical_path(home / ".local" / "share" / "tuntun" / "reachy-a05")


def _require_process_identity(deployment: JsonObject, remote_root: Path) -> None:
    effective_uid = os.geteuid()
    if effective_uid == 0:
        _reject("process-identity")
    try:
        account = pwd.getpwuid(effective_uid)
    except (KeyError, OSError):
        _reject("process-identity")
    principal = _require_str(deployment["ssh_principal"])
    remote_home = _require_command_posix_absolute_path(deployment["remote_home"])
    if (
        type(account.pw_name) is not str
        or type(account.pw_dir) is not str
        or account.pw_name != principal
        or account.pw_dir != remote_home
        or remote_root != Path(remote_home) / ".local" / "share" / "tuntun" / "reachy-a05"
    ):
        _reject("process-identity")


def _absolute_lexical_path(path: Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        _reject("path")
    return candidate


def _relative_path_parts(path: str) -> tuple[str, ...]:
    if (
        type(path) is not str
        or not path
        or not path.isascii()
        or len(path) > MAX_ARTIFACT_PATH_BYTES
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or "//" in path
    ):
        _reject("path")
    parts = tuple(path.split("/"))
    if len(parts) > MAX_ARTIFACT_PATH_DEPTH or any(
        part in {"", ".", ".."}
        or len(part) > 255
        or any(character not in _PORTABLE_PATH_CHARS for character in part)
        for part in parts
    ):
        _reject("path")
    return parts


def _open_owner_directory_path(path: Path) -> int:
    fd = -1
    try:
        fd = _open_directory_no_follow_ancestry(path)
        _require_owner_directory_stat(os.fstat(fd))
        return fd
    except DispatcherRejected:
        with contextlib.suppress(OSError):
            if fd >= 0:
                os.close(fd)
        raise
    except OSError:
        with contextlib.suppress(OSError):
            if fd >= 0:
                os.close(fd)
        _reject("directory")


def _open_optional_owner_directory_at(parent_fd: int, name: str) -> int:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        _reject("directory-name")
    fd = -1
    try:
        fd = os.open(
            name,
            os.O_RDONLY
            | _required_os_flag(_O_CLOEXEC)
            | _required_os_flag(_O_DIRECTORY)
            | _required_os_flag(_O_NOFOLLOW),
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return -1
    except OSError:
        _reject("directory")
    try:
        opened = os.fstat(fd)
        _require_owner_directory_stat(opened)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _FileIdentity.from_stat(named) != _FileIdentity.from_stat(opened):
            _reject("directory-race")
        return fd
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


def _entry_exists_at(parent_fd: int, name: str) -> bool:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        _reject("path")
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        _reject("path")
    return True


def _revalidate_owner_directory_at(parent_fd: int, name: str, directory_fd: int) -> None:
    try:
        opened = os.fstat(directory_fd)
        _require_owner_directory_stat(opened)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except DispatcherRejected:
        raise
    except OSError:
        _reject("directory-race")
    if _FileIdentity.from_stat(named) != _FileIdentity.from_stat(opened):
        _reject("directory-race")


def _revalidate_owner_directory_path(
    path: Path,
    directory_fd: int,
    expected_identity: _FileIdentity,
) -> None:
    try:
        opened = os.fstat(directory_fd)
        _require_owner_directory_stat(opened)
        named = os.stat(path, follow_symlinks=False)
    except DispatcherRejected:
        raise
    except OSError:
        _reject("directory-race")
    if (
        _FileIdentity.from_stat(opened) != expected_identity
        or _FileIdentity.from_stat(named) != expected_identity
    ):
        _reject("directory-race")


def _open_directory_no_follow_ancestry(path: Path) -> int:
    parts = path.parts
    if not parts or parts[0] != "/":
        _reject("path")
    fd = os.open(
        "/",
        os.O_RDONLY | _required_os_flag(_O_CLOEXEC) | _required_os_flag(_O_DIRECTORY),
    )
    try:
        for part in parts[1:]:
            next_fd = os.open(
                part,
                os.O_RDONLY
                | _required_os_flag(_O_CLOEXEC)
                | _required_os_flag(_O_DIRECTORY)
                | _required_os_flag(_O_NOFOLLOW),
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise
    return fd


def _require_owner_directory_path(path: Path) -> None:
    fd = -1
    try:
        fd = _open_owner_directory_path(path)
    except DispatcherRejected:
        raise
    except OSError:
        _reject("directory")
    finally:
        with contextlib.suppress(OSError):
            if fd >= 0:
                os.close(fd)


def _ensure_owner_directory_path(path: Path) -> None:
    parent_fd = -1
    directory_fd = -1
    try:
        parent_fd = _open_owner_directory_path(path.parent)
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        directory_fd = os.open(
            path.name,
            os.O_RDONLY
            | _required_os_flag(_O_CLOEXEC)
            | _required_os_flag(_O_DIRECTORY)
            | _required_os_flag(_O_NOFOLLOW),
            dir_fd=parent_fd,
        )
        info = os.fstat(directory_fd)
        _require_owner_directory_stat(info)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _FileIdentity.from_stat(named) != _FileIdentity.from_stat(info):
            _reject("directory-race")
    except DispatcherRejected:
        raise
    except OSError:
        _reject("directory")
    finally:
        for descriptor in (directory_fd, parent_fd):
            with contextlib.suppress(OSError):
                if descriptor >= 0:
                    os.close(descriptor)


def _require_owner_directory_stat(info: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _reject("directory")


def _require_owner_regular(
    info: os.stat_result,
    *,
    expected_mode: int | None,
    max_bytes: int,
    allow_empty: bool,
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_size > max_bytes
        or (info.st_size == 0 and not allow_empty)
    ):
        _reject("regular")
    if expected_mode is not None and stat.S_IMODE(info.st_mode) != expected_mode:
        _reject("mode")


def _validate_generation_file(path: Path, *, executable: bool) -> None:
    parent_fd = -1
    try:
        parent_fd = _open_owner_directory_path(path.parent)
        info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    except DispatcherRejected:
        raise
    except OSError:
        _reject("generation-file")
    finally:
        with contextlib.suppress(OSError):
            if parent_fd >= 0:
                os.close(parent_fd)
    _require_owner_regular(
        info,
        expected_mode=0o700 if executable else 0o600,
        max_bytes=MAX_ARTIFACT_BYTES,
        allow_empty=True,
    )


def _open_validated_executable_at(
    generation_fd: int,
    relative: str,
    expected_sha256: str,
) -> tuple[int, _FileIdentity]:
    parts = _relative_path_parts(relative)
    parent_fd = -1
    executable_fd = -1
    try:
        parent_fd = os.dup(generation_fd)
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY
                | _required_os_flag(_O_CLOEXEC)
                | _required_os_flag(_O_DIRECTORY)
                | _required_os_flag(_O_NOFOLLOW),
                dir_fd=parent_fd,
            )
            try:
                _revalidate_owner_directory_at(parent_fd, part, next_fd)
            except BaseException:
                os.close(next_fd)
                raise
            os.close(parent_fd)
            parent_fd = next_fd
        executable_fd = os.open(
            parts[-1],
            os.O_RDONLY | _required_os_flag(_O_CLOEXEC) | _required_os_flag(_O_NOFOLLOW),
            dir_fd=parent_fd,
        )
        opened = os.fstat(executable_fd)
        _require_owner_regular(
            opened,
            expected_mode=0o700,
            max_bytes=MAX_ARTIFACT_BYTES,
            allow_empty=True,
        )
        identity = _FileIdentity.from_stat(opened)
        raw = _read_fd_bounded(
            executable_fd,
            max_bytes=MAX_ARTIFACT_BYTES,
            allow_empty=True,
        )
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
            _reject("entrypoint-digest")
        if os.lseek(executable_fd, 0, os.SEEK_SET) != 0:
            _reject("entrypoint-offset")
        named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            _FileIdentity.from_stat(named) != identity
            or _FileIdentity.from_stat(os.fstat(executable_fd)) != identity
        ):
            _reject("entrypoint-race")
        result = executable_fd
        executable_fd = -1
        return result, identity
    except DispatcherRejected:
        raise
    except OSError:
        _reject("entrypoint-open")
    finally:
        for descriptor in (executable_fd, parent_fd):
            with contextlib.suppress(OSError):
                if descriptor >= 0:
                    os.close(descriptor)


def _read_generation_member_at(
    generation_fd: int,
    relative: str,
    *,
    expected_mode: int,
    allow_empty: bool,
) -> bytes:
    parts = _relative_path_parts(relative)
    parent_fd = -1
    try:
        parent_fd = os.dup(generation_fd)
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY
                | _required_os_flag(_O_CLOEXEC)
                | _required_os_flag(_O_DIRECTORY)
                | _required_os_flag(_O_NOFOLLOW),
                dir_fd=parent_fd,
            )
            try:
                _revalidate_owner_directory_at(parent_fd, part, next_fd)
            except BaseException:
                os.close(next_fd)
                raise
            os.close(parent_fd)
            parent_fd = next_fd
        return _read_regular_file_at(
            parent_fd,
            parts[-1],
            max_bytes=MAX_ARTIFACT_BYTES,
            expected_mode=expected_mode,
            allow_empty=allow_empty,
        )
    except DispatcherRejected:
        raise
    except OSError:
        _reject("generation-member")
    finally:
        with contextlib.suppress(OSError):
            if parent_fd >= 0:
                os.close(parent_fd)


def _import_member_parts(path: str) -> tuple[str, ...]:
    if (
        type(path) is not str
        or not path
        or not path.isascii()
        or len(path) > 1_024
        or path.startswith("/")
        or path.endswith("/")
        or "\\" in path
        or "\x00" in path
        or "//" in path
    ):
        _reject("import-path")
    parts = tuple(path.split("/"))
    if len(parts) > 32 or any(
        part in {"", ".", ".."}
        or len(part) > 255
        or any(character not in _PORTABLE_PATH_CHARS for character in part)
        for part in parts
    ):
        _reject("import-path")
    return parts


def _normalized_import_member(path: str) -> str:
    parts = _import_member_parts(path)
    if "site-packages" in parts:
        marker = len(parts) - 1 - tuple(reversed(parts)).index("site-packages")
        parts = parts[marker + 1 :]
        if not parts:
            _reject("import-path")
    return "/".join(parts)


def _capture_wheel_entries(raw: bytes) -> tuple[tuple[str, bytes], ...]:
    entries: list[tuple[str, bytes]] = []
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw), mode="r") as wheel:
            infos = wheel.infolist()
            if not 1 <= len(infos) <= MAX_IMPORT_SNAPSHOT_ENTRIES:
                _reject("wheel-count")
            seen: set[str] = set()
            for info in infos:
                if info.is_dir():
                    continue
                path = _normalized_import_member(info.filename)
                if path in seen or info.flag_bits & 0x1:
                    _reject("wheel-entry")
                seen.add(path)
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    _reject("wheel-compression")
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_IFMT(unix_mode) not in {0, stat.S_IFREG}:
                    _reject("wheel-entry")
                if not 0 <= info.file_size <= MAX_ARTIFACT_BYTES:
                    _reject("wheel-size")
                total += info.file_size
                if total > MAX_TOTAL_ARTIFACT_BYTES:
                    _reject("wheel-total")
                with wheel.open(info, mode="r") as member:
                    content = member.read(info.file_size + 1)
                    if len(content) != info.file_size or member.read(1) != b"":
                        _reject("wheel-size")
                entries.append((path, content))
    except DispatcherRejected:
        raise
    except (
        EOFError,
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        _reject("wheel-read")
    return tuple(entries)


def _capture_import_snapshot_entries(
    generation_fd: int,
    manifest: JsonObject,
    *,
    entrypoint_path: str,
    entrypoint_module: str,
) -> tuple[tuple[str, bytes], ...]:
    captured: dict[str, bytes] = {}
    total = 0

    def add(path: str, raw: bytes) -> None:
        nonlocal total
        normalized = _normalized_import_member(path)
        if normalized in captured:
            _reject("import-duplicate")
        total += len(raw)
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            _reject("import-total")
        captured[normalized] = raw
        if len(captured) > MAX_IMPORT_SNAPSHOT_ENTRIES:
            _reject("import-count")

    for record in _require_artifact_records(manifest["artifacts"]):
        path = _require_str(record["path"])
        executable = _require_bool(record["executable"])
        raw = _read_generation_member_at(
            generation_fd,
            path,
            expected_mode=0o700 if executable else 0o600,
            allow_empty=True,
        )
        size = _require_int(record["size"], minimum=0, maximum=MAX_ARTIFACT_BYTES)
        expected_sha256 = _require_sha256(record["sha256"])
        if len(raw) != size or not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), expected_sha256
        ):
            _reject("import-digest")
        if path == entrypoint_path:
            continue
        if path.endswith(".whl"):
            for wheel_path, wheel_raw in _capture_wheel_entries(raw):
                add(wheel_path, wheel_raw)
        else:
            add(path, raw)

    module_path = entrypoint_module.replace(".", "/")
    if f"{module_path}.py" not in captured and f"{module_path}/__init__.py" not in captured:
        _reject("import-module")
    module_parts = entrypoint_module.split(".")
    for length in range(1, len(module_parts)):
        package_init = f"{'/'.join(module_parts[:length])}/__init__.py"
        if package_init not in captured:
            _reject("import-package")
    return tuple(sorted(captured.items()))


def _seal_import_snapshot(entries: tuple[tuple[str, bytes], ...]) -> int:
    if sys.platform != "linux" or not hasattr(os, "memfd_create"):
        _reject("import-snapshot-platform")
    allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
    close_on_exec = getattr(os, "MFD_CLOEXEC", None)
    if type(allow_sealing) is not int or type(close_on_exec) is not int:
        _reject("import-snapshot-platform")
    snapshot_fd = -1
    try:
        snapshot_fd = os.memfd_create(
            "tuntun-a05-imports",
            flags=allow_sealing | close_on_exec,
        )
        with os.fdopen(os.dup(snapshot_fd), "w+b") as stream:
            with zipfile.ZipFile(
                stream,
                mode="w",
                compression=zipfile.ZIP_STORED,
                allowZip64=False,
            ) as snapshot:
                for path, raw in entries:
                    info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = (stat.S_IFREG | 0o400) << 16
                    snapshot.writestr(info, raw)
            stream.flush()
            os.fsync(stream.fileno())
        snapshot_size = os.fstat(snapshot_fd).st_size
        if not 1 <= snapshot_size <= MAX_TOTAL_ARTIFACT_BYTES + 1_048_576:
            _reject("import-snapshot-size")
        required_seals = (
            _LINUX_F_SEAL_SEAL | _LINUX_F_SEAL_SHRINK | _LINUX_F_SEAL_GROW | _LINUX_F_SEAL_WRITE
        )
        fcntl.fcntl(snapshot_fd, _LINUX_F_ADD_SEALS, required_seals)
        actual_seals = fcntl.fcntl(snapshot_fd, _LINUX_F_GET_SEALS)
        if type(actual_seals) is not int or actual_seals & required_seals != required_seals:
            _reject("import-snapshot-seal")
        if os.lseek(snapshot_fd, 0, os.SEEK_SET) != 0:
            _reject("import-snapshot-offset")
        result = snapshot_fd
        snapshot_fd = -1
        return result
    except DispatcherRejected:
        raise
    except (OSError, ValueError, zipfile.LargeZipFile):
        _reject("import-snapshot")
    finally:
        with contextlib.suppress(OSError):
            if snapshot_fd >= 0:
                os.close(snapshot_fd)


def _build_sealed_import_snapshot(
    generation_fd: int,
    manifest: JsonObject,
    *,
    entrypoint_path: str,
    entrypoint_module: str,
) -> int:
    entries = _capture_import_snapshot_entries(
        generation_fd,
        manifest,
        entrypoint_path=entrypoint_path,
        entrypoint_module=entrypoint_module,
    )
    return _seal_import_snapshot(entries)


def _exists_no_follow(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        _reject("path")
    return True


def _cleanup_empty_directory(path: Path) -> None:
    parent_fd = -1
    try:
        parent_fd = _open_owner_directory_path(path.parent)
        os.rmdir(path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except (DispatcherRejected, OSError):
        pass
    finally:
        with contextlib.suppress(OSError):
            if parent_fd >= 0:
                os.close(parent_fd)


def _fsync_directory(path: Path) -> None:
    fd = -1
    try:
        fd = _open_owner_directory_path(path)
        os.fsync(fd)
    except DispatcherRejected:
        raise
    except OSError:
        _reject("fsync")
    finally:
        with contextlib.suppress(OSError):
            if fd >= 0:
                os.close(fd)


def _required_os_flag(flag: int) -> int:
    if flag == 0:
        _reject("os-flag")
    return flag


def _require_empty_original_command(environ: Mapping[str, str]) -> None:
    if environ.get("SSH_ORIGINAL_COMMAND", "") != "":
        _reject("original-command")


def _require_exact_keys(value: Mapping[str, object], keys: frozenset[str]) -> None:
    if set(value.keys()) != set(keys):
        _reject("keys")


def _require_object(value: JsonValue) -> JsonObject:
    if not isinstance(value, dict):
        _reject("object")
    return value


def _require_list(value: JsonValue) -> list[JsonValue]:
    if not isinstance(value, list):
        _reject("list")
    return value


def _require_str(value: JsonValue) -> str:
    if type(value) is not str:
        _reject("str")
    return value


def _require_bool(value: JsonValue) -> bool:
    if type(value) is not bool:
        _reject("bool")
    return value


def _require_int(value: JsonValue, *, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        _reject("int")
    if not minimum <= value <= maximum:
        _reject("int-bound")
    return value


def _require_generation(value: JsonValue) -> int:
    return _require_int(value, minimum=1, maximum=MAX_JSON_INT)


def _require_status(value: JsonValue) -> str:
    status_value = _require_str(value)
    if status_value not in STATUSES:
        _reject("status")
    return status_value


def _require_sha256(value: JsonValue) -> str:
    text = _require_str(value)
    if not _is_sha256(text):
        _reject("sha256")
    return text


def _optional_sha256(value: JsonValue) -> str | None:
    if value is None:
        return None
    return _require_sha256(value)


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in _SHA256_HEX for character in value)


def _canonical_uuid(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError:
        _reject("uuid")
    if str(parsed) != value:
        _reject("uuid")
    return value


def _parse_datetime(value: str) -> datetime:
    if len(value) != 27 or not value.endswith("Z"):
        _reject("datetime")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        _reject("datetime")
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        _reject("datetime")
    return parsed


def _require_command_posix_absolute_path(value: JsonValue) -> str:
    path = _require_str(value)
    if not 2 <= len(path) <= 512 or not path.startswith("/") or path.endswith("/") or "//" in path:
        _reject("posix-path")
    if any(
        part in {"", ".", ".."} or any(character not in _PORTABLE_PATH_CHARS for character in part)
        for part in path.split("/")[1:]
    ):
        _reject("posix-path")
    return path


def _require_version_token(value: JsonValue) -> str:
    token = _require_str(value)
    if (
        not 1 <= len(token) <= 64
        or token[0] not in _VERSION_FIRST_CHARS
        or any(character not in _VERSION_REST_CHARS for character in token[1:])
        or "xn--" in token.casefold()
    ):
        _reject("version-token")
    return token


def _parse_python_version(value: str) -> tuple[int, int, int] | None:
    parts = value.split(".")
    if len(parts) != 3 or any(
        not 1 <= len(part) <= 3
        or any(character not in _ASCII_DIGITS for character in part)
        or (len(part) > 1 and part.startswith("0"))
        for part in parts
    ):
        return None
    return cast(tuple[int, int, int], tuple(int(part) for part in parts))


def _validate_exec_argv(argv: tuple[str, ...]) -> None:
    if not argv:
        _reject("argv")
    for item in argv:
        if (
            type(item) is not str
            or not item
            or "\x00" in item
            or "\n" in item
            or "\r" in item
            or item in FORBIDDEN_ARGV_ITEMS
        ):
            _reject("argv")


def _execve_supports_fd() -> bool:
    return os.execve in os.supports_fd


def _closed_exec_environment(
    *,
    import_snapshot_fd: int,
) -> dict[str, str]:
    try:
        account = pwd.getpwuid(os.geteuid())
    except (KeyError, OSError):
        _reject("exec-identity")
    if (
        type(account.pw_name) is not str
        or not account.pw_name
        or "\x00" in account.pw_name
        or "\n" in account.pw_name
        or type(account.pw_dir) is not str
        or not account.pw_dir.startswith("/")
        or "\x00" in account.pw_dir
        or "\n" in account.pw_dir
    ):
        _reject("exec-identity")
    if type(import_snapshot_fd) is not int or import_snapshot_fd < 0:
        _reject("exec-imports")
    return {
        "HOME": account.pw_dir,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": account.pw_name,
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": f"/proc/self/fd/{import_snapshot_fd}",
        "PYTHONSAFEPATH": "1",
        "PYTHONUTF8": "1",
        "USER": account.pw_name,
    }


def _close_handoff(handoff: _ExecutableHandoff) -> None:
    for descriptor in (handoff.executable_fd, handoff.generation_fd):
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _exec_handoff(handoff: _ExecutableHandoff) -> NoReturn:
    _validate_exec_argv(handoff.argv)
    previous_cwd_fd = -1
    import_snapshot_fd = -1
    changed_directory = False
    try:
        _revalidate_owner_directory_path(
            handoff.generation_path,
            handoff.generation_fd,
            handoff.generation_identity,
        )
        opened = os.fstat(handoff.executable_fd)
        if _FileIdentity.from_stat(opened) != handoff.executable_identity:
            _reject("entrypoint-race")
        if os.lseek(handoff.executable_fd, 0, os.SEEK_SET) != 0:
            _reject("entrypoint-offset")
        raw = _read_fd_bounded(
            handoff.executable_fd,
            max_bytes=MAX_ARTIFACT_BYTES,
            allow_empty=True,
        )
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), handoff.executable_sha256):
            _reject("entrypoint-digest")
        if os.lseek(handoff.executable_fd, 0, os.SEEK_SET) != 0:
            _reject("entrypoint-offset")
        if not _execve_supports_fd():
            _reject("exec-fd")
        previous_cwd_fd = os.open(
            ".",
            os.O_RDONLY | _required_os_flag(_O_CLOEXEC) | _required_os_flag(_O_DIRECTORY),
        )
        os.fchdir(handoff.generation_fd)
        changed_directory = True
        if _FileIdentity.from_stat(os.fstat(handoff.generation_fd)) != handoff.generation_identity:
            _reject("entrypoint-race")
        final_manifest = _validate_bundle_directory(handoff.generation_path)
        if not hmac.compare_digest(_canonical_bytes(final_manifest), handoff.manifest_bytes):
            _reject("entrypoint-manifest")
        _revalidate_owner_directory_path(
            handoff.generation_path,
            handoff.generation_fd,
            handoff.generation_identity,
        )
        entrypoint = _entrypoint_from_manifest(final_manifest)
        if (
            entrypoint[2] != handoff.entrypoint_module
            or handoff.argv[0] != str(handoff.generation_path / entrypoint[0])
            or handoff.argv[1:3] != entrypoint[1:]
        ):
            _reject("entrypoint-binding")
        import_snapshot_fd = _build_sealed_import_snapshot(
            handoff.generation_fd,
            final_manifest,
            entrypoint_path=entrypoint[0],
            entrypoint_module=entrypoint[2],
        )
        execution_environment = _closed_exec_environment(
            import_snapshot_fd=import_snapshot_fd,
        )
        execution_argv = (f"/proc/self/fd/{handoff.executable_fd}", *handoff.argv[1:])
        _validate_exec_argv(execution_argv)
        os.set_inheritable(handoff.executable_fd, True)
        os.set_inheritable(import_snapshot_fd, True)
        os.chdir("/")
        os.execve(handoff.executable_fd, execution_argv, execution_environment)
    except DispatcherRejected:
        raise
    except OSError:
        _reject("exec")
    finally:
        if changed_directory and previous_cwd_fd >= 0:
            with contextlib.suppress(OSError):
                os.fchdir(previous_cwd_fd)
        with contextlib.suppress(OSError):
            if previous_cwd_fd >= 0:
                os.close(previous_cwd_fd)
        with contextlib.suppress(OSError):
            if import_snapshot_fd >= 0:
                os.close(import_snapshot_fd)
        _close_handoff(handoff)


def _reject(code: str = "rejected") -> NoReturn:
    raise DispatcherRejected(code)


if __name__ == "__main__":
    raise SystemExit(main())
