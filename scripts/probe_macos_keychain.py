from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.metadata
import json
import os
import platform
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import RFC_4122, UUID, uuid4

from tuntun_core.adapters.keychain.macos import MacOSKeychainSecretProvider
from tuntun_core.adapters.keychain.provider import SecretProvider

PROBE_ENVIRONMENT_ACK = "TUNTUN_ALLOW_KEYCHAIN_PROBE"
PROBE_SERVICE = "tuntun.probe.keychain"
PHASE1_HOST_PROBE_SCHEMA_ID = "https://tuntun.local/schemas/evidence/phase1-host-probe.schema.json"
PHASE1_HOST_PROBE_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "docs/evidence/phase1-host-probe.schema.json"
)
PHASE1_HOST_PROBE_RECEIPT_ID = "phase1.macos-keychain.host-probe.v1"
PHASE1_HOST_PROBE_EVIDENCE_USE = "diagnostic_only"
PHASE1_HOST_PROBE_COMPLETION_SCHEMA_ID = (
    "https://tuntun.local/schemas/evidence/phase1-host-probe-completion.schema.json"
)
PHASE1_HOST_PROBE_COMPLETION_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "docs/evidence/phase1-host-probe-completion.schema.json"
)
PHASE1_HOST_PROBE_COMPLETION_ID = "phase1.macos-keychain.host-probe-completion.v1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SYSTEM_GIT = "/usr/bin/git"
SYSTEM_SYSCTL = "/usr/sbin/sysctl"
SYSTEM_SW_VERS = "/usr/bin/sw_vers"
MAX_SOURCE_COMMAND_BYTES = 8 * 1024 * 1024
MAX_SOURCE_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_SOURCE_ENTRIES = 100_000
MAX_SOURCE_REPOSITORIES = 128
SOURCE_COMMAND_TIMEOUT_SECONDS = 10.0

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_SHORT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9,._-]{0,63}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_BACKEND_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,255}$")


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    commit: str
    probe_script_sha256: str
    repository_state_sha256: str


@dataclass(slots=True)
class ReceiptClaim:
    path: Path
    descriptor: int
    device: int
    inode: int
    payload: bytes
    run_id: str
    attempt_id: str
    completion_binding_sha256: str


def _keychain_probe_error(message: str, *, cleanup_verified: bool) -> RuntimeError:
    error = RuntimeError(message)
    error.cleanup_verified = cleanup_verified  # type: ignore[attr-defined]
    return error


def _receipt_error() -> RuntimeError:
    return RuntimeError("invalid host probe receipt")


def _exact_mapping(value: object, keys: set[str]) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise _receipt_error()
    return value


def _safe_string(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise _receipt_error()
    return value


def _safe_run_id(value: object) -> str:
    if type(value) is not str:
        raise _receipt_error()
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError):
        raise _receipt_error() from None
    if parsed.version != 4 or parsed.variant != RFC_4122 or str(parsed) != value:
        raise _receipt_error()
    return value


def _safe_recorded_at_utc(value: object) -> str:
    if type(value) is not str:
        raise _receipt_error()
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise _receipt_error() from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise _receipt_error()
    return value


def _validate_artifact_digests(value: object) -> Mapping[str, object]:
    allowed = {
        "candidate_artifact_sha256",
        "native_lock_sha256",
        "model_manifest_sha256",
    }
    if type(value) is not dict or not set(value) <= allowed:
        raise _receipt_error()
    for digest in value.values():
        _safe_string(digest, _DIGEST_RE)
    return value


def validate_phase1_host_probe_receipt(
    receipt: object,
) -> None:
    root = _exact_mapping(
        receipt,
        {
            "$schema",
            "receipt_id",
            "evidence_use",
            "run_id",
            "attempt_id",
            "recorded_at_utc",
            "status",
            "cleanup_verified",
            "host",
            "runtime",
            "source",
            "artifact_digests",
            "owner_approval_commitment_sha256",
            "completion_binding_sha256",
        },
    )
    if root["$schema"] != PHASE1_HOST_PROBE_SCHEMA_ID:
        raise _receipt_error()
    if root["receipt_id"] != PHASE1_HOST_PROBE_RECEIPT_ID:
        raise _receipt_error()
    if root["evidence_use"] != PHASE1_HOST_PROBE_EVIDENCE_USE:
        raise _receipt_error()
    _safe_run_id(root["run_id"])
    _safe_run_id(root["attempt_id"])
    _safe_recorded_at_utc(root["recorded_at_utc"])
    if root["status"] not in {"pass", "fail"}:
        raise _receipt_error()
    if type(root["cleanup_verified"]) is not bool:
        raise _receipt_error()
    if root["status"] == "pass" and root["cleanup_verified"] is not True:
        raise _receipt_error()

    host = _exact_mapping(
        root["host"],
        {"system", "machine", "model_class", "os_product_version", "os_build"},
    )
    if host["system"] != "Darwin" or host["machine"] != "arm64":
        raise _receipt_error()
    _safe_string(host["model_class"], _SAFE_SHORT_RE)
    _safe_string(host["os_product_version"], _SAFE_VERSION_RE)
    _safe_string(host["os_build"], _SAFE_VERSION_RE)

    runtime = _exact_mapping(
        root["runtime"],
        {"python_version", "keyring_version", "keyring_backend_class"},
    )
    _safe_string(runtime["python_version"], _SAFE_VERSION_RE)
    _safe_string(runtime["keyring_version"], _SAFE_VERSION_RE)
    _safe_string(runtime["keyring_backend_class"], _SAFE_BACKEND_RE)

    source = _exact_mapping(root["source"], {"commit", "probe_script_sha256"})
    _safe_string(source["commit"], _COMMIT_RE)
    _safe_string(source["probe_script_sha256"], _DIGEST_RE)
    _validate_artifact_digests(root["artifact_digests"])
    _safe_string(root["owner_approval_commitment_sha256"], _DIGEST_RE)
    _safe_string(root["completion_binding_sha256"], _DIGEST_RE)


def _canonical_json_sha256(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_receipt_sha256(receipt: Mapping[str, object]) -> str:
    validate_phase1_host_probe_receipt(receipt)
    return _canonical_json_sha256(receipt)


def _validate_phase1_host_probe_completion(completion: object) -> Mapping[str, object]:
    root = _exact_mapping(
        completion,
        {
            "$schema",
            "completion_id",
            "run_id",
            "attempt_id",
            "receipt_sha256",
            "completion_binding_sha256",
            "state",
        },
    )
    if root["$schema"] != PHASE1_HOST_PROBE_COMPLETION_SCHEMA_ID:
        raise _receipt_error()
    if root["completion_id"] != PHASE1_HOST_PROBE_COMPLETION_ID:
        raise _receipt_error()
    if root["state"] != "complete":
        raise _receipt_error()
    _safe_run_id(root["run_id"])
    _safe_run_id(root["attempt_id"])
    _safe_string(root["receipt_sha256"], _DIGEST_RE)
    _safe_string(root["completion_binding_sha256"], _DIGEST_RE)
    return root


def verify_phase1_host_probe_receipt(
    receipt: object,
    completion: object,
    *,
    expected_run_id: str,
    expected_attempt_id: str,
    expected_owner_approval_commitment_sha256: str,
    expected_source_commit: str,
    expected_probe_script_sha256: str,
) -> None:
    validate_phase1_host_probe_receipt(receipt)
    if type(receipt) is not dict:
        raise _receipt_error()
    root = receipt
    completed = _validate_phase1_host_probe_completion(completion)
    source = _exact_mapping(root["source"], {"commit", "probe_script_sha256"})
    expected = (
        _safe_run_id(expected_run_id),
        _safe_run_id(expected_attempt_id),
        _safe_string(expected_owner_approval_commitment_sha256, _DIGEST_RE),
        _safe_string(expected_source_commit, _COMMIT_RE),
        _safe_string(expected_probe_script_sha256, _DIGEST_RE),
    )
    actual = (
        _safe_run_id(root["run_id"]),
        _safe_run_id(root["attempt_id"]),
        _safe_string(root["owner_approval_commitment_sha256"], _DIGEST_RE),
        _safe_string(source["commit"], _COMMIT_RE),
        _safe_string(source["probe_script_sha256"], _DIGEST_RE),
    )
    if any(
        not hmac.compare_digest(actual_value, expected_value)
        for actual_value, expected_value in zip(actual, expected, strict=True)
    ):
        raise RuntimeError("host probe receipt binding mismatch")
    if root["status"] != "pass" or root["cleanup_verified"] is not True:
        raise RuntimeError("host probe receipt did not pass")
    completion_expected = (
        _safe_run_id(root["run_id"]),
        _safe_run_id(root["attempt_id"]),
        _canonical_receipt_sha256(root),
        _safe_string(root["completion_binding_sha256"], _DIGEST_RE),
    )
    completion_actual = (
        _safe_run_id(completed["run_id"]),
        _safe_run_id(completed["attempt_id"]),
        _safe_string(completed["receipt_sha256"], _DIGEST_RE),
        _safe_string(completed["completion_binding_sha256"], _DIGEST_RE),
    )
    if any(
        not hmac.compare_digest(actual_value, expected_value)
        for actual_value, expected_value in zip(
            completion_actual,
            completion_expected,
            strict=True,
        )
    ):
        raise RuntimeError("host probe receipt completion mismatch")


def build_phase1_host_probe_receipt(
    *,
    status: str,
    cleanup_verified: bool,
    run_id: str,
    attempt_id: str,
    completion_binding_sha256: str,
    owner_approval_commitment_sha256: str,
    recorded_at_utc: str,
    system: str,
    machine: str,
    model_class: str,
    os_product_version: str,
    os_build: str,
    python_version: str,
    keyring_version: str,
    keyring_backend_class: str,
    source_commit: str,
    probe_script_sha256: str,
) -> dict[str, object]:
    receipt: dict[str, object] = {
        "$schema": PHASE1_HOST_PROBE_SCHEMA_ID,
        "receipt_id": PHASE1_HOST_PROBE_RECEIPT_ID,
        "evidence_use": PHASE1_HOST_PROBE_EVIDENCE_USE,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "recorded_at_utc": recorded_at_utc,
        "status": status,
        "cleanup_verified": cleanup_verified,
        "host": {
            "system": system,
            "machine": machine,
            "model_class": model_class,
            "os_product_version": os_product_version,
            "os_build": os_build,
        },
        "runtime": {
            "python_version": python_version,
            "keyring_version": keyring_version,
            "keyring_backend_class": keyring_backend_class,
        },
        "source": {
            "commit": source_commit,
            "probe_script_sha256": probe_script_sha256,
        },
        "artifact_digests": {},
        "owner_approval_commitment_sha256": owner_approval_commitment_sha256,
        "completion_binding_sha256": completion_binding_sha256,
    }
    validate_phase1_host_probe_receipt(receipt)
    return receipt


def _run_content_safe_command_bytes(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    allow_empty: bool = False,
) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
            },
        )
        if process.stdout is None:
            raise RuntimeError
        captured = bytearray()
        deadline = time.monotonic() + SOURCE_COMMAND_TIMEOUT_SECONDS
        with selectors.DefaultSelector() as selector:
            stdout_descriptor = process.stdout.fileno()
            os.set_blocking(stdout_descriptor, False)
            selector.register(stdout_descriptor, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                events = selector.select(remaining)
                if not events:
                    raise TimeoutError
                for key, _ in events:
                    chunk = os.read(key.fd, 16_384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured.extend(chunk)
                    if len(captured) > MAX_SOURCE_COMMAND_BYTES:
                        raise RuntimeError
        returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if returncode != 0 or (not captured and not allow_empty):
            raise RuntimeError
        return bytes(captured)
    except BaseException:
        if process is not None:
            with suppress(BaseException):
                process.kill()
            with suppress(BaseException):
                process.wait(timeout=1)
        raise RuntimeError("content-safe host metadata unavailable") from None


def _run_content_safe_command(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    allow_empty: bool = False,
) -> str:
    try:
        return (
            _run_content_safe_command_bytes(
                arguments,
                cwd=cwd,
                allow_empty=allow_empty,
            )
            .decode("utf-8", errors="strict")
            .strip()
        )
    except (RuntimeError, UnicodeError):
        raise RuntimeError("content-safe host metadata unavailable") from None


def _git_arguments(repository: Path, *arguments: str) -> tuple[str, ...]:
    return (
        SYSTEM_GIT,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "diff.ignoreSubmodules=none",
        "-C",
        str(repository),
        *arguments,
    )


def _nul_records(value: bytes) -> tuple[bytes, ...]:
    if not value:
        return ()
    if not value.endswith(b"\0"):
        raise RuntimeError("content-safe source metadata unavailable")
    records = tuple(value[:-1].split(b"\0"))
    if not records or any(not item for item in records):
        raise RuntimeError("content-safe source metadata unavailable")
    return records


def _default_index_records(value: bytes) -> tuple[bytes, ...]:
    records = _nul_records(value)
    if any(not item.startswith(b"H ") or len(item) <= 2 for item in records):
        raise RuntimeError("content-safe source metadata unavailable")
    return records


def _stage_records(value: bytes) -> tuple[tuple[bytes, bytes, bytes], ...]:
    parsed: list[tuple[bytes, bytes, bytes]] = []
    for record in _nul_records(value):
        header, separator, path = record.partition(b"\t")
        fields = header.split(b" ")
        if (
            separator != b"\t"
            or not path
            or len(fields) != 3
            or re.fullmatch(rb"[0-7]{6}", fields[0]) is None
            or re.fullmatch(rb"[0-9a-f]{40}", fields[1]) is None
            or fields[2] != b"0"
        ):
            raise RuntimeError("content-safe source metadata unavailable")
        parsed.append((fields[0], fields[1], path))
    return tuple(parsed)


def _hash_source_component(hasher: object, value: bytes) -> None:
    if not isinstance(hasher, type(hashlib.sha256())):
        raise RuntimeError("content-safe source metadata unavailable")
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _read_bounded_stable_regular_file(path: Path, *, max_bytes: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            raise RuntimeError
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named_after = path.lstat()

        def stable(row: os.stat_result) -> tuple[int, int, int, int, int]:
            return (
                row.st_dev,
                row.st_ino,
                row.st_size,
                row.st_mtime_ns,
                row.st_ctime_ns,
            )

        if (
            total != before.st_size
            or stable(before) != stable(after)
            or stable(after) != stable(named_after)
        ):
            raise RuntimeError
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _capture_source_snapshot() -> SourceSnapshot:
    try:
        source_root = REPOSITORY_ROOT.resolve(strict=True)
        script_path = source_root / "scripts" / "probe_macos_keychain.py"
        script_bytes = _read_bounded_stable_regular_file(
            script_path,
            max_bytes=MAX_SOURCE_COMMAND_BYTES,
        )
        script_digest = hashlib.sha256(script_bytes).hexdigest()
        state = hashlib.sha256()
        total_bytes = len(script_bytes)
        total_entries = 0
        repository_count = 0
        root_commit: str | None = None
        visited: set[Path] = set()

        def command(repository: Path, *arguments: str, allow_empty: bool = False) -> bytes:
            nonlocal total_bytes
            value = _run_content_safe_command_bytes(
                _git_arguments(repository, *arguments),
                cwd=repository,
                allow_empty=allow_empty,
            )
            total_bytes += len(value)
            if total_bytes > MAX_SOURCE_SNAPSHOT_BYTES:
                raise RuntimeError
            return value

        def visit(
            repository: Path,
            relative: bytes,
            expected_commit: bytes | None,
        ) -> None:
            nonlocal repository_count, root_commit, total_entries
            repository = repository.resolve(strict=True)
            if repository in visited or not repository.is_relative_to(source_root):
                raise RuntimeError
            visited.add(repository)
            repository_count += 1
            if repository_count > MAX_SOURCE_REPOSITORIES:
                raise RuntimeError

            top = command(repository, "rev-parse", "--show-toplevel")
            try:
                reported = Path(top.decode("utf-8", errors="strict").strip()).resolve(strict=True)
            except (OSError, UnicodeError):
                raise RuntimeError from None
            if reported != repository:
                raise RuntimeError

            head_bytes = command(repository, "rev-parse", "--verify", "HEAD").strip()
            if re.fullmatch(rb"[0-9a-f]{40}", head_bytes) is None:
                raise RuntimeError
            if expected_commit is not None and not hmac.compare_digest(
                head_bytes,
                expected_commit,
            ):
                raise RuntimeError
            if root_commit is None:
                root_commit = head_bytes.decode("ascii")

            version_tags = command(repository, "ls-files", "-v", "-z", allow_empty=True)
            fsmonitor_tags = command(repository, "ls-files", "-f", "-z", allow_empty=True)
            version_records = _default_index_records(version_tags)
            fsmonitor_records = _default_index_records(fsmonitor_tags)
            if version_records != fsmonitor_records:
                raise RuntimeError
            staged = command(repository, "ls-files", "--stage", "-z", allow_empty=True)
            parsed_staged = _stage_records(staged)
            total_entries += len(parsed_staged)
            if total_entries > MAX_SOURCE_ENTRIES or len(parsed_staged) != len(version_records):
                raise RuntimeError

            dirty = command(
                repository,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
                allow_empty=True,
            )
            if dirty:
                raise RuntimeError

            for component in (relative, head_bytes, version_tags, fsmonitor_tags, staged):
                _hash_source_component(state, component)

            for mode, object_id, path_bytes in parsed_staged:
                if mode != b"160000":
                    continue
                path_text = os.fsdecode(path_bytes)
                path = Path(path_text)
                if path.is_absolute() or ".." in path.parts or "." in path.parts:
                    raise RuntimeError
                child = (repository / path).resolve(strict=True)
                if not child.is_relative_to(repository):
                    raise RuntimeError
                child_relative = (
                    child.relative_to(source_root)
                    .as_posix()
                    .encode(
                        "utf-8",
                        errors="strict",
                    )
                )
                visit(child, child_relative, object_id)

        visit(source_root, b".", None)
        if root_commit is None:
            raise RuntimeError
        return SourceSnapshot(
            commit=root_commit,
            probe_script_sha256=script_digest,
            repository_state_sha256=state.hexdigest(),
        )
    except BaseException:
        raise RuntimeError("content-safe source metadata unavailable") from None


def _current_probe_script_sha256() -> str:
    return hashlib.sha256(
        _read_bounded_stable_regular_file(
            REPOSITORY_ROOT / "scripts" / "probe_macos_keychain.py",
            max_bytes=MAX_SOURCE_COMMAND_BYTES,
        )
    ).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _capture_content_safe_host_context(provider: SecretProvider) -> dict[str, object]:
    backend = getattr(provider, "_backend", None)
    backend_type = type(backend) if backend is not None else type(provider)
    try:
        keyring_version = importlib.metadata.version("keyring")
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError("content-safe host metadata unavailable") from None
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "model_class": _run_content_safe_command((SYSTEM_SYSCTL, "-n", "hw.model")),
        "os_product_version": _run_content_safe_command((SYSTEM_SW_VERS, "-productVersion")),
        "os_build": _run_content_safe_command((SYSTEM_SW_VERS, "-buildVersion")),
        "python_version": platform.python_version(),
        "keyring_version": keyring_version,
        "keyring_backend_class": f"{backend_type.__module__}.{backend_type.__qualname__}",
    }


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short host probe receipt write")
        offset += written


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _completion_stage_operation(stage: str, *arguments: object) -> None:
    if stage == "write":
        descriptor, value = arguments
        if type(descriptor) is not int or type(value) is not bytes:
            raise RuntimeError("host probe completion publication failed")
        _write_all(descriptor, value)
        return
    if stage == "file_fsync":
        descriptor = arguments[0]
        if type(descriptor) is not int:
            raise RuntimeError("host probe completion publication failed")
        os.fsync(descriptor)
        return
    if stage == "link":
        source, destination = arguments
        if not isinstance(source, Path) or not isinstance(destination, Path):
            raise RuntimeError("host probe completion publication failed")
        os.link(source, destination, follow_symlinks=False)
        return
    if stage == "directory_fsync":
        path = arguments[0]
        if not isinstance(path, Path):
            raise RuntimeError("host probe completion publication failed")
        _fsync_directory(path)
        return
    raise RuntimeError("host probe completion publication failed")


def _publish_new_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    descriptor: int | None = None
    published = False
    try:
        rendered = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        _completion_stage_operation("write", descriptor, rendered)
        _completion_stage_operation("file_fsync", descriptor)
        os.close(descriptor)
        descriptor = None
        _completion_stage_operation("link", temporary, path)
        published = True
        _completion_stage_operation("directory_fsync", path.parent)
    except BaseException:
        if published:
            with suppress(BaseException):
                path.unlink()
                _fsync_directory(path.parent)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink()


def phase1_host_probe_completion_path(receipt_path: Path) -> Path:
    return receipt_path.with_name(f"{receipt_path.name}.complete")


def _new_completion_binding_sha256() -> str:
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()


def _claim_payload(
    *,
    run_id: str,
    attempt_id: str,
    owner_approval_commitment_sha256: str,
    completion_binding_sha256: str,
) -> dict[str, object]:
    return {
        "$schema": "https://tuntun.local/schemas/evidence/phase1-host-probe-claim.v1",
        "claim_id": "phase1.macos-keychain.host-probe-claim.v1",
        "state": "claimed_incomplete",
        "run_id": _safe_run_id(run_id),
        "attempt_id": _safe_run_id(attempt_id),
        "owner_approval_commitment_sha256": _safe_string(
            owner_approval_commitment_sha256,
            _DIGEST_RE,
        ),
        "completion_binding_sha256": _safe_string(
            completion_binding_sha256,
            _DIGEST_RE,
        ),
    }


def _render_json(payload: Mapping[str, object]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _require_path_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise RuntimeError("host probe receipt destination unavailable") from None
    raise RuntimeError("host probe receipt destination already exists")


def _claim_receipt_destination(
    path: Path,
    *,
    run_id: str,
    attempt_id: str,
    owner_approval_commitment_sha256: str,
) -> ReceiptClaim:
    path.parent.mkdir(parents=True, exist_ok=True)
    completion_path = phase1_host_probe_completion_path(path)
    completion_binding_sha256 = _new_completion_binding_sha256()
    payload = _render_json(
        _claim_payload(
            run_id=run_id,
            attempt_id=attempt_id,
            owner_approval_commitment_sha256=owner_approval_commitment_sha256,
            completion_binding_sha256=completion_binding_sha256,
        )
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        _fsync_directory(path.parent)
        _require_path_absent(completion_path)
        claim = ReceiptClaim(
            path=path,
            descriptor=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            payload=payload,
            run_id=run_id,
            attempt_id=attempt_id,
            completion_binding_sha256=completion_binding_sha256,
        )
        descriptor = None
        return claim
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _claim_path_is_current(claim: ReceiptClaim) -> bool:
    try:
        metadata = claim.path.lstat()
    except OSError:
        return False
    return (
        metadata.st_dev == claim.device
        and metadata.st_ino == claim.inode
        and not claim.path.is_symlink()
    )


def _restore_fail_closed_claim(claim: ReceiptClaim) -> None:
    if _claim_path_is_current(claim):
        os.ftruncate(claim.descriptor, 0)
        os.lseek(claim.descriptor, 0, os.SEEK_SET)
        _write_all(claim.descriptor, claim.payload)
        os.fsync(claim.descriptor)
        return
    replacement = claim.path.parent / f".{claim.path.name}.{uuid4().hex}.claim"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            replacement,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, claim.payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(replacement, claim.path)
        _fsync_directory(claim.path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            replacement.unlink()


def _receipt_stage_operation(stage: str, *arguments: object) -> None:
    if stage == "truncate":
        descriptor = arguments[0]
        if type(descriptor) is not int:
            raise RuntimeError("host probe receipt publication failed")
        os.ftruncate(descriptor, 0)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return
    if stage == "write":
        descriptor, value = arguments
        if type(descriptor) is not int or type(value) is not bytes:
            raise RuntimeError("host probe receipt publication failed")
        _write_all(descriptor, value)
        return
    if stage == "file_fsync":
        descriptor = arguments[0]
        if type(descriptor) is not int:
            raise RuntimeError("host probe receipt publication failed")
        os.fsync(descriptor)
        return
    if stage == "path_recheck":
        claim = arguments[0]
        if not isinstance(claim, ReceiptClaim) or not _claim_path_is_current(claim):
            raise RuntimeError("host probe receipt claim changed")
        return
    if stage == "directory_fsync":
        path = arguments[0]
        if not isinstance(path, Path):
            raise RuntimeError("host probe receipt publication failed")
        _fsync_directory(path)
        return
    raise RuntimeError("host probe receipt publication failed")


def _stage_claimed_receipt(
    claim: ReceiptClaim,
    receipt: Mapping[str, object],
) -> None:
    rendered = _render_json(receipt)
    try:
        _receipt_stage_operation("path_recheck", claim)
        _receipt_stage_operation("truncate", claim.descriptor)
        _receipt_stage_operation("write", claim.descriptor, rendered)
        _receipt_stage_operation("file_fsync", claim.descriptor)
        _receipt_stage_operation("path_recheck", claim)
        _receipt_stage_operation("directory_fsync", claim.path.parent)
    except BaseException:
        with suppress(BaseException):
            _restore_fail_closed_claim(claim)
        raise


def _completion_record(receipt: Mapping[str, object]) -> dict[str, object]:
    validate_phase1_host_probe_receipt(receipt)
    return {
        "$schema": PHASE1_HOST_PROBE_COMPLETION_SCHEMA_ID,
        "completion_id": PHASE1_HOST_PROBE_COMPLETION_ID,
        "run_id": receipt["run_id"],
        "attempt_id": receipt["attempt_id"],
        "receipt_sha256": _canonical_receipt_sha256(receipt),
        "completion_binding_sha256": receipt["completion_binding_sha256"],
        "state": "complete",
    }


def _publish_completion_record(
    receipt_path: Path,
    receipt: Mapping[str, object],
) -> None:
    completion = _completion_record(receipt)
    _validate_phase1_host_probe_completion(completion)
    _publish_new_json(phase1_host_probe_completion_path(receipt_path), completion)


def _build_phase1_host_probe_receipt_from_context(
    *,
    status: str,
    cleanup_verified: bool,
    run_id: str,
    attempt_id: str,
    completion_binding_sha256: str,
    owner_approval_commitment_sha256: str,
    host_context: Mapping[str, object],
) -> dict[str, object]:
    expected_context_keys = {
        "system",
        "machine",
        "model_class",
        "os_product_version",
        "os_build",
        "python_version",
        "keyring_version",
        "keyring_backend_class",
        "source_commit",
        "probe_script_sha256",
    }
    if set(host_context) != expected_context_keys:
        raise RuntimeError("content-safe host metadata unavailable")

    def context_string(key: str) -> str:
        value = host_context[key]
        if type(value) is not str:
            raise RuntimeError("content-safe host metadata unavailable")
        return value

    receipt = build_phase1_host_probe_receipt(
        status=status,
        cleanup_verified=cleanup_verified,
        run_id=run_id,
        attempt_id=attempt_id,
        completion_binding_sha256=completion_binding_sha256,
        owner_approval_commitment_sha256=owner_approval_commitment_sha256,
        recorded_at_utc=_utc_now(),
        system=context_string("system"),
        machine=context_string("machine"),
        model_class=context_string("model_class"),
        os_product_version=context_string("os_product_version"),
        os_build=context_string("os_build"),
        python_version=context_string("python_version"),
        keyring_version=context_string("keyring_version"),
        keyring_backend_class=context_string("keyring_backend_class"),
        source_commit=context_string("source_commit"),
        probe_script_sha256=context_string("probe_script_sha256"),
    )
    return receipt


def probe_keychain_round_trip(
    provider: SecretProvider,
    service: str,
    account: str,
    value: bytes,
) -> None:
    try:
        occupied = provider.exists(service, account)
    except BaseException:
        raise _keychain_probe_error(
            "Keychain probe preflight failed",
            cleanup_verified=False,
        ) from None
    if type(occupied) is not bool:
        raise _keychain_probe_error(
            "Keychain probe preflight failed", cleanup_verified=False
        ) from None
    if occupied is True:
        raise _keychain_probe_error("Keychain probe slot already exists", cleanup_verified=False)

    operation_failure: str | None = None
    try:
        try:
            provider.set(service, account, value)
            readback = provider.get(service, account)
            if not hmac.compare_digest(readback, value):
                operation_failure = "Keychain probe readback mismatch"
        except BaseException:
            operation_failure = "Keychain probe operation failed"
    finally:
        delete_failed = False
        try:
            provider.delete(service, account)
        except BaseException:
            delete_failed = True
        finally:
            try:
                present = provider.exists(service, account)
            except BaseException:
                raise _keychain_probe_error(
                    "Keychain probe cleanup could not be verified",
                    cleanup_verified=False,
                ) from None
            if type(present) is not bool:
                raise _keychain_probe_error(
                    "Keychain probe cleanup could not be verified",
                    cleanup_verified=False,
                ) from None
            if present is True or delete_failed:
                raise _keychain_probe_error(
                    "Keychain probe cleanup failed",
                    cleanup_verified=False,
                ) from None
    if operation_failure is not None:
        raise _keychain_probe_error(operation_failure, cleanup_verified=True) from None


def _source_snapshots_match(first: SourceSnapshot, second: SourceSnapshot) -> bool:
    return all(
        hmac.compare_digest(left, right)
        for left, right in (
            (first.commit, second.commit),
            (first.probe_script_sha256, second.probe_script_sha256),
            (first.repository_state_sha256, second.repository_state_sha256),
        )
    )


def _emit_probe_result(*, passed: bool) -> None:
    with suppress(OSError):
        print(
            "macOS Keychain probe: PASS" if passed else "macOS Keychain probe: FAIL",
            file=None if passed else sys.stderr,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--acknowledge-keychain-write", action="store_true")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--attempt-id")
    parser.add_argument("--owner-approval-commitment-sha256")
    arguments = parser.parse_args(argv)
    if not arguments.acknowledge_keychain_write or os.environ.get(PROBE_ENVIRONMENT_ACK) != "1":
        raise RuntimeError("Keychain probe requires explicit dual acknowledgement")

    receipt_arguments = (
        arguments.receipt,
        arguments.run_id,
        arguments.attempt_id,
        arguments.owner_approval_commitment_sha256,
    )
    if any(value is not None for value in receipt_arguments) and not all(
        value is not None for value in receipt_arguments
    ):
        raise RuntimeError("Keychain probe receipt requires every evidence binding")

    run_id: str | None = None
    attempt_id: str | None = None
    owner_approval_commitment_sha256: str | None = None
    if arguments.receipt is not None:
        run_id = _safe_run_id(arguments.run_id)
        attempt_id = _safe_run_id(arguments.attempt_id)
        owner_approval_commitment_sha256 = _safe_string(
            arguments.owner_approval_commitment_sha256,
            _DIGEST_RE,
        )

    claim: ReceiptClaim | None = None
    host_context: dict[str, object] | None = None
    initial_snapshot: SourceSnapshot | None = None
    final_snapshot: SourceSnapshot | None = None
    failure: BaseException | None = None
    cleanup_verified = False
    try:
        if arguments.receipt is not None:
            if run_id is None or attempt_id is None or owner_approval_commitment_sha256 is None:
                raise RuntimeError("Keychain probe receipt binding unavailable")
            claim = _claim_receipt_destination(
                arguments.receipt,
                run_id=run_id,
                attempt_id=attempt_id,
                owner_approval_commitment_sha256=owner_approval_commitment_sha256,
            )
            initial_snapshot = _capture_source_snapshot()
        provider = MacOSKeychainSecretProvider()
        if arguments.receipt is not None:
            host_context = dict(_capture_content_safe_host_context(provider))
        account = f"round-trip-{uuid4()}"
        value = secrets.token_bytes(32)
        try:
            probe_keychain_round_trip(
                provider,
                PROBE_SERVICE,
                account,
                value,
            )
            cleanup_verified = True
        except BaseException as error:
            failure = error
            if isinstance(error, RuntimeError):
                cleanup_verified = getattr(error, "cleanup_verified", False)
        finally:
            if arguments.receipt is not None:
                final_snapshot = _capture_source_snapshot()
    except BaseException as error:
        failure = error
        if isinstance(error, RuntimeError):
            cleanup_verified = getattr(error, "cleanup_verified", False)

    receipt_completed = False
    if (
        arguments.receipt is not None
        and claim is not None
        and host_context is not None
        and initial_snapshot is not None
        and final_snapshot is not None
    ):
        try:
            if (
                run_id is None
                or attempt_id is None
                or owner_approval_commitment_sha256 is None
                or not _source_snapshots_match(initial_snapshot, final_snapshot)
            ):
                raise RuntimeError("Keychain probe receipt binding unavailable")
            host_context["source_commit"] = final_snapshot.commit
            host_context["probe_script_sha256"] = final_snapshot.probe_script_sha256
            receipt = _build_phase1_host_probe_receipt_from_context(
                status="pass" if failure is None else "fail",
                cleanup_verified=cleanup_verified,
                run_id=claim.run_id,
                attempt_id=claim.attempt_id,
                completion_binding_sha256=claim.completion_binding_sha256,
                owner_approval_commitment_sha256=owner_approval_commitment_sha256,
                host_context=host_context,
            )
            _stage_claimed_receipt(claim, receipt)
            _publish_completion_record(arguments.receipt, receipt)
            receipt_completed = True
        except BaseException as error:
            failure = error
            with suppress(BaseException):
                _restore_fail_closed_claim(claim)

    if claim is not None:
        with suppress(OSError):
            os.close(claim.descriptor)

    if failure is not None:
        _emit_probe_result(passed=False)
        return 1
    if arguments.receipt is not None and not receipt_completed:
        _emit_probe_result(passed=False)
        return 1
    _emit_probe_result(passed=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
