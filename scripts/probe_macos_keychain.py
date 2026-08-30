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
from typing import Never
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
MAX_EVIDENCE_ARTIFACT_BYTES = 256 * 1024
MAX_EVIDENCE_PAIR_BYTES = 512 * 1024
EVIDENCE_READ_TIMEOUT_SECONDS = 2.0
_GIT_DESCRIPTOR_EXEC_SOURCE = (
    "import os,sys\n"
    "descriptor=int(sys.argv[1],10)\n"
    "os.fchdir(descriptor)\n"
    "os.execve('/usr/bin/git',('/usr/bin/git',*sys.argv[2:]),dict(os.environ))\n"
)

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
class DirectoryIdentity:
    path: Path
    descriptor: int
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class TrackedObject:
    content: bytes
    device: int
    inode: int
    mode: int


@dataclass(slots=True)
class EvidenceArtifact:
    path: Path
    descriptor: int
    device: int
    inode: int


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


class _ProbeCliError(Exception):
    """An intentionally content-free command-line failure."""


class _ContentFreeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise _ProbeCliError

    def exit(self, status: int = 0, message: str | None = None) -> Never:
        del message
        raise _ProbeCliError


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


def _verify_phase1_host_probe_values(
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


def _evidence_metadata_is_exact(
    opened: os.stat_result,
    named: os.stat_result,
    *,
    device: int,
    inode: int,
) -> bool:
    return (
        stat.S_ISREG(opened.st_mode)
        and stat.S_ISREG(named.st_mode)
        and (opened.st_dev, opened.st_ino) == (device, inode)
        and (named.st_dev, named.st_ino) == (device, inode)
        and opened.st_uid == os.geteuid()
        and named.st_uid == os.geteuid()
        and stat.S_IMODE(opened.st_mode) == 0o600
        and stat.S_IMODE(named.st_mode) == 0o600
        and opened.st_nlink == 1
        and named.st_nlink == 1
        and opened.st_size <= MAX_EVIDENCE_ARTIFACT_BYTES
        and named.st_size <= MAX_EVIDENCE_ARTIFACT_BYTES
    )


def _publication_path_is_current(
    path: Path,
    descriptor: int,
    *,
    device: int,
    inode: int,
    expected_links: int,
) -> bool:
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(opened.st_mode)
        and stat.S_ISREG(named.st_mode)
        and (opened.st_dev, opened.st_ino) == (device, inode)
        and (named.st_dev, named.st_ino) == (device, inode)
        and opened.st_uid == os.geteuid()
        and named.st_uid == os.geteuid()
        and stat.S_IMODE(opened.st_mode) == 0o600
        and stat.S_IMODE(named.st_mode) == 0o600
        and opened.st_nlink == expected_links
        and named.st_nlink == expected_links
        and opened.st_size <= MAX_EVIDENCE_ARTIFACT_BYTES
        and named.st_size <= MAX_EVIDENCE_ARTIFACT_BYTES
    )


def _unlink_if_owned(
    path: Path,
    descriptor: int,
    *,
    device: int,
    inode: int,
) -> bool:
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or (opened.st_dev, opened.st_ino) != (device, inode)
            or (named.st_dev, named.st_ino) != (device, inode)
            or opened.st_uid != os.geteuid()
            or named.st_uid != os.geteuid()
        ):
            return False
        path.unlink()
        return True
    except OSError:
        return False


def _evidence_artifact_is_current(artifact: EvidenceArtifact) -> bool:
    try:
        opened = os.fstat(artifact.descriptor)
        named = artifact.path.lstat()
    except OSError:
        return False
    return _evidence_metadata_is_exact(
        opened,
        named,
        device=artifact.device,
        inode=artifact.inode,
    )


def _open_evidence_artifact(path: Path) -> EvidenceArtifact:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        artifact = EvidenceArtifact(
            path=path,
            descriptor=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        if not _evidence_artifact_is_current(artifact):
            raise RuntimeError
        descriptor = None
        return artifact
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise _receipt_error() from None


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _read_evidence_json(
    artifact: EvidenceArtifact,
    *,
    remaining_bytes: int,
    deadline: float,
) -> tuple[object, int]:
    try:
        if not _evidence_artifact_is_current(artifact):
            raise RuntimeError
        before = os.fstat(artifact.descriptor)
        if before.st_size > remaining_bytes:
            raise RuntimeError
        os.lseek(artifact.descriptor, 0, os.SEEK_SET)
        captured = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError
            chunk = os.read(
                artifact.descriptor,
                min(65_536, remaining_bytes + 1 - len(captured)),
            )
            if not chunk:
                break
            captured.extend(chunk)
            if len(captured) > remaining_bytes:
                raise RuntimeError
        after = os.fstat(artifact.descriptor)
        if (
            len(captured) != before.st_size
            or _stable_file_metadata(before) != _stable_file_metadata(after)
            or not _evidence_artifact_is_current(artifact)
        ):
            raise RuntimeError
        parsed = json.loads(
            captured.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_pairs,
        )
        if not _evidence_artifact_is_current(artifact):
            raise RuntimeError
        return parsed, len(captured)
    except BaseException:
        raise _receipt_error() from None


def _require_exact_evidence_path(path: Path) -> None:
    artifact = _open_evidence_artifact(path)
    try:
        if not _evidence_artifact_is_current(artifact):
            raise _receipt_error()
    finally:
        os.close(artifact.descriptor)


def verify_phase1_host_probe_receipt(
    receipt_path: Path,
    completion_path: Path,
    *,
    expected_run_id: str,
    expected_attempt_id: str,
    expected_owner_approval_commitment_sha256: str,
    expected_source_commit: str,
    expected_probe_script_sha256: str,
) -> None:
    if (
        not isinstance(receipt_path, Path)
        or not isinstance(completion_path, Path)
        or completion_path != phase1_host_probe_completion_path(receipt_path)
    ):
        raise _receipt_error()
    receipt_artifact: EvidenceArtifact | None = None
    completion_artifact: EvidenceArtifact | None = None
    try:
        deadline = time.monotonic() + EVIDENCE_READ_TIMEOUT_SECONDS
        receipt_artifact = _open_evidence_artifact(receipt_path)
        completion_artifact = _open_evidence_artifact(completion_path)
        receipt, receipt_size = _read_evidence_json(
            receipt_artifact,
            remaining_bytes=MAX_EVIDENCE_PAIR_BYTES,
            deadline=deadline,
        )
        completion, _ = _read_evidence_json(
            completion_artifact,
            remaining_bytes=MAX_EVIDENCE_PAIR_BYTES - receipt_size,
            deadline=deadline,
        )
        _verify_phase1_host_probe_values(
            receipt,
            completion,
            expected_run_id=expected_run_id,
            expected_attempt_id=expected_attempt_id,
            expected_owner_approval_commitment_sha256=(expected_owner_approval_commitment_sha256),
            expected_source_commit=expected_source_commit,
            expected_probe_script_sha256=expected_probe_script_sha256,
        )
        if not _evidence_artifact_is_current(receipt_artifact) or not _evidence_artifact_is_current(
            completion_artifact
        ):
            raise _receipt_error()
    finally:
        if completion_artifact is not None:
            os.close(completion_artifact.descriptor)
        if receipt_artifact is not None:
            os.close(receipt_artifact.descriptor)


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
    cwd_descriptor: int | None = None,
    allow_empty: bool = False,
    deadline: float | None = None,
) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    try:
        if cwd is not None and cwd_descriptor is not None:
            raise RuntimeError

        selected_arguments = tuple(arguments)
        pass_fds: tuple[int, ...] = ()
        if cwd_descriptor is not None:
            if not selected_arguments or selected_arguments[0] != SYSTEM_GIT:
                raise RuntimeError
            interpreter = Path(sys.executable).resolve(strict=True)
            if not interpreter.is_absolute():
                raise RuntimeError
            selected_arguments = (
                str(interpreter),
                "-I",
                "-S",
                "-c",
                _GIT_DESCRIPTOR_EXEC_SOURCE,
                str(cwd_descriptor),
                *selected_arguments[1:],
            )
            pass_fds = (cwd_descriptor,)

        process = subprocess.Popen(
            selected_arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd if cwd_descriptor is None else None,
            pass_fds=pass_fds,
            close_fds=True,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
        if process.stdout is None:
            raise RuntimeError
        captured = bytearray()
        selected_deadline = (
            time.monotonic() + SOURCE_COMMAND_TIMEOUT_SECONDS if deadline is None else deadline
        )
        with selectors.DefaultSelector() as selector:
            stdout_descriptor = process.stdout.fileno()
            os.set_blocking(stdout_descriptor, False)
            selector.register(stdout_descriptor, selectors.EVENT_READ)
            while selector.get_map():
                remaining = selected_deadline - time.monotonic()
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
        returncode = process.wait(timeout=max(0.001, selected_deadline - time.monotonic()))
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


def _git_arguments(*arguments: str) -> tuple[str, ...]:
    return (
        SYSTEM_GIT,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.trustctime=true",
        "-c",
        "core.checkStat=default",
        "-c",
        "core.symlinks=true",
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
        "-c",
        "diff.ignoreSubmodules=none",
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


def _relative_path_components(value: bytes) -> tuple[bytes, ...]:
    if not value or value.startswith(b"/"):
        raise RuntimeError("content-safe source metadata unavailable")
    components = tuple(value.split(b"/"))
    if any(component in {b"", b".", b".."} for component in components):
        raise RuntimeError("content-safe source metadata unavailable")
    return components


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _stable_file_metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_directory_identity(path: Path) -> DirectoryIdentity:
    absolute = path.absolute()
    descriptor = os.open(
        absolute,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        named = absolute.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or not _same_file_identity(opened, named)
        ):
            raise RuntimeError
        return DirectoryIdentity(
            path=absolute,
            descriptor=descriptor,
            device=opened.st_dev,
            inode=opened.st_ino,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _directory_identity_is_current(identity: DirectoryIdentity) -> bool:
    try:
        opened = os.fstat(identity.descriptor)
        named = identity.path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(opened.st_mode)
        and stat.S_ISDIR(named.st_mode)
        and (opened.st_dev, opened.st_ino) == (identity.device, identity.inode)
        and _same_file_identity(opened, named)
    )


def _open_child_directory_identity(
    repository: DirectoryIdentity,
    path_bytes: bytes,
) -> DirectoryIdentity:
    components = _relative_path_components(path_bytes)
    descriptors, links, name = _open_parent_chain(repository.descriptor, components)
    child_descriptor: int | None = None
    try:
        if not _directory_identity_is_current(repository) or not _path_chain_is_current(
            descriptors,
            links,
        ):
            raise RuntimeError
        child_descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptors[-1],
        )
        opened = os.fstat(child_descriptor)
        named = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or not _same_file_identity(opened, named)
            or not _directory_identity_is_current(repository)
            or not _path_chain_is_current(descriptors, links)
        ):
            raise RuntimeError
        child_path = repository.path.joinpath(*(os.fsdecode(item) for item in components))
        identity = DirectoryIdentity(
            path=child_path,
            descriptor=child_descriptor,
            device=opened.st_dev,
            inode=opened.st_ino,
        )
        child_descriptor = None
        if not _directory_identity_is_current(identity):
            raise RuntimeError
        return identity
    finally:
        if child_descriptor is not None:
            os.close(child_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _open_parent_chain(
    root_descriptor: int,
    components: tuple[bytes, ...],
) -> tuple[list[int], list[tuple[int, bytes, int, int]], bytes]:
    descriptors = [os.dup(root_descriptor)]
    links: list[tuple[int, bytes, int, int]] = []
    try:
        for component in components[:-1]:
            parent = descriptors[-1]
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent,
            )
            opened = os.fstat(child)
            named = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(named.st_mode)
                or not _same_file_identity(opened, named)
            ):
                os.close(child)
                raise RuntimeError
            descriptors.append(child)
            links.append((parent, component, opened.st_dev, opened.st_ino))
        return descriptors, links, components[-1]
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _path_chain_is_current(
    descriptors: Sequence[int],
    links: Sequence[tuple[int, bytes, int, int]],
) -> bool:
    if len(descriptors) != len(links) + 1:
        return False
    try:
        for index, (parent, component, device, inode) in enumerate(links, start=1):
            opened = os.fstat(descriptors[index])
            named = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(named.st_mode)
                or (opened.st_dev, opened.st_ino) != (device, inode)
                or not _same_file_identity(opened, named)
            ):
                return False
    except OSError:
        return False
    return True


def _read_tracked_regular_file(
    repository: DirectoryIdentity,
    path_bytes: bytes,
    *,
    expected_executable: bool,
    max_bytes: int,
    deadline: float,
) -> TrackedObject:
    components = _relative_path_components(path_bytes)
    descriptors, links, name = _open_parent_chain(repository.descriptor, components)
    file_descriptor: int | None = None
    try:
        if not _directory_identity_is_current(repository) or not _path_chain_is_current(
            descriptors,
            links,
        ):
            raise RuntimeError
        file_descriptor = os.open(
            name,
            os.O_RDONLY
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptors[-1],
        )
        before = os.fstat(file_descriptor)
        named = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or not _same_file_identity(before, named)
            or before.st_nlink != 1
            or before.st_size > max_bytes
            or bool(before.st_mode & 0o111) is not expected_executable
        ):
            raise RuntimeError
        captured = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError
            chunk = os.read(file_descriptor, min(65_536, max_bytes + 1 - len(captured)))
            if not chunk:
                break
            captured.extend(chunk)
            if len(captured) > max_bytes:
                raise RuntimeError
        after = os.fstat(file_descriptor)
        named_after = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
        if (
            len(captured) != before.st_size
            or _stable_file_metadata(before) != _stable_file_metadata(after)
            or _stable_file_metadata(after) != _stable_file_metadata(named_after)
            or not _directory_identity_is_current(repository)
            or not _path_chain_is_current(descriptors, links)
        ):
            raise RuntimeError
        return TrackedObject(
            content=bytes(captured),
            device=after.st_dev,
            inode=after.st_ino,
            mode=after.st_mode,
        )
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_tracked_symlink(
    repository: DirectoryIdentity,
    path_bytes: bytes,
    *,
    max_bytes: int,
    deadline: float,
) -> TrackedObject:
    if time.monotonic() >= deadline or not hasattr(os, "O_SYMLINK"):
        raise RuntimeError
    components = _relative_path_components(path_bytes)
    descriptors, links, name = _open_parent_chain(repository.descriptor, components)
    link_descriptor: int | None = None
    try:
        if not _directory_identity_is_current(repository) or not _path_chain_is_current(
            descriptors,
            links,
        ):
            raise RuntimeError
        link_descriptor = os.open(
            name,
            os.O_RDONLY
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_SYMLINK", 0),
            dir_fd=descriptors[-1],
        )
        before = os.fstat(link_descriptor)
        named = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
        target = os.readlink(name, dir_fd=descriptors[-1])
        if type(target) is not bytes:
            raise RuntimeError
        after = os.fstat(link_descriptor)
        named_after = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
        if (
            not stat.S_ISLNK(before.st_mode)
            or not stat.S_ISLNK(named.st_mode)
            or before.st_nlink != 1
            or len(target) > max_bytes
            or _stable_file_metadata(before) != _stable_file_metadata(after)
            or _stable_file_metadata(after) != _stable_file_metadata(named_after)
            or not _directory_identity_is_current(repository)
            or not _path_chain_is_current(descriptors, links)
            or time.monotonic() >= deadline
        ):
            raise RuntimeError
        return TrackedObject(
            content=target,
            device=after.st_dev,
            inode=after.st_ino,
            mode=after.st_mode,
        )
    finally:
        if link_descriptor is not None:
            os.close(link_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _git_blob_oid(value: bytes) -> bytes:
    header = b"blob " + str(len(value)).encode("ascii") + b"\0"
    return hashlib.sha1(header + value).hexdigest().encode("ascii")


def _local_source_config_is_safe(value: bytes) -> bool:
    for name in _nul_records(value):
        lowered = name.lower()
        if lowered.startswith(b"filter.") or lowered == b"core.attributesfile":
            return False
    return True


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
    source_root: DirectoryIdentity | None = None
    try:
        deadline = time.monotonic() + SOURCE_COMMAND_TIMEOUT_SECONDS
        source_root = _open_directory_identity(REPOSITORY_ROOT)
        state = hashlib.sha256()
        total_bytes = 0
        total_entries = 0
        repository_count = 0
        root_commit: str | None = None
        script_digest: str | None = None
        visited: set[tuple[int, int]] = set()

        def add_bytes(value: bytes) -> None:
            nonlocal total_bytes
            total_bytes += len(value)
            if total_bytes > MAX_SOURCE_SNAPSHOT_BYTES or time.monotonic() >= deadline:
                raise RuntimeError

        def command(
            repository: DirectoryIdentity,
            *arguments: str,
            allow_empty: bool = False,
        ) -> bytes:
            if not _directory_identity_is_current(repository):
                raise RuntimeError
            value = _run_content_safe_command_bytes(
                _git_arguments(*arguments),
                cwd_descriptor=repository.descriptor,
                allow_empty=allow_empty,
                deadline=deadline,
            )
            add_bytes(value)
            if not _directory_identity_is_current(repository):
                raise RuntimeError
            return value

        def require_no_local_attributes(repository: DirectoryIdentity) -> bytes:
            config_names = command(
                repository,
                "config",
                "--local",
                "--name-only",
                "--list",
                "-z",
                allow_empty=True,
            )
            if not _local_source_config_is_safe(config_names):
                raise RuntimeError
            git_attributes = command(
                repository,
                "rev-parse",
                "--git-path",
                "info/attributes",
            )
            try:
                decoded = git_attributes.decode("utf-8", errors="strict").strip()
            except UnicodeError:
                raise RuntimeError from None
            attributes_path = Path(decoded)
            if not attributes_path.is_absolute():
                attributes_path = repository.path / attributes_path
            try:
                attributes_path.lstat()
            except FileNotFoundError:
                pass
            except OSError:
                raise RuntimeError from None
            else:
                raise RuntimeError
            return config_names

        def visit(
            repository: DirectoryIdentity,
            relative: bytes,
            expected_commit: bytes | None,
        ) -> None:
            nonlocal repository_count, root_commit, script_digest, total_entries
            identity = (repository.device, repository.inode)
            if identity in visited or not repository.path.is_relative_to(source_root.path):
                raise RuntimeError
            visited.add(identity)
            repository_count += 1
            if repository_count > MAX_SOURCE_REPOSITORIES or not _directory_identity_is_current(
                repository
            ):
                raise RuntimeError
            _hash_source_component(state, relative)
            _hash_source_component(state, repository.device.to_bytes(8, "big"))
            _hash_source_component(state, repository.inode.to_bytes(8, "big"))

            config_before = require_no_local_attributes(repository)
            top = command(repository, "rev-parse", "--show-toplevel")
            try:
                reported = Path(top.decode("utf-8", errors="strict").strip()).absolute()
            except UnicodeError:
                raise RuntimeError from None
            if reported != repository.path:
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
            version_paths = tuple(record[2:] for record in version_records)
            staged_paths = tuple(path for _, _, path in parsed_staged)
            if (
                total_entries > MAX_SOURCE_ENTRIES
                or version_paths != staged_paths
                or any(
                    b".gitattributes" in _relative_path_components(path) for path in staged_paths
                )
            ):
                raise RuntimeError

            for component in (head_bytes, version_tags, fsmonitor_tags, staged):
                _hash_source_component(state, component)

            for mode, object_id, path_bytes in parsed_staged:
                if mode in {b"100644", b"100755"}:
                    actual = _read_tracked_regular_file(
                        repository,
                        path_bytes,
                        expected_executable=mode == b"100755",
                        max_bytes=MAX_SOURCE_SNAPSHOT_BYTES - total_bytes,
                        deadline=deadline,
                    )
                elif mode == b"120000":
                    actual = _read_tracked_symlink(
                        repository,
                        path_bytes,
                        max_bytes=MAX_SOURCE_SNAPSHOT_BYTES - total_bytes,
                        deadline=deadline,
                    )
                elif mode == b"160000":
                    child = _open_child_directory_identity(repository, path_bytes)
                    try:
                        child_relative = (
                            child.path.relative_to(source_root.path)
                            .as_posix()
                            .encode("utf-8", errors="strict")
                        )
                        visit(child, child_relative, object_id)
                        if not _directory_identity_is_current(child):
                            raise RuntimeError
                    finally:
                        os.close(child.descriptor)
                    continue
                else:
                    raise RuntimeError

                add_bytes(actual.content)
                if not hmac.compare_digest(_git_blob_oid(actual.content), object_id):
                    raise RuntimeError
                for component in (
                    mode,
                    object_id,
                    path_bytes,
                    actual.device.to_bytes(8, "big"),
                    actual.inode.to_bytes(8, "big"),
                    actual.mode.to_bytes(8, "big"),
                    actual.content,
                ):
                    _hash_source_component(state, component)
                if relative == b"." and path_bytes == b"scripts/probe_macos_keychain.py":
                    if mode not in {b"100644", b"100755"}:
                        raise RuntimeError
                    script_digest = hashlib.sha256(actual.content).hexdigest()

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
            head_after = command(repository, "rev-parse", "--verify", "HEAD").strip()
            version_after = command(repository, "ls-files", "-v", "-z", allow_empty=True)
            fsmonitor_after = command(repository, "ls-files", "-f", "-z", allow_empty=True)
            staged_after = command(
                repository,
                "ls-files",
                "--stage",
                "-z",
                allow_empty=True,
            )
            config_after = require_no_local_attributes(repository)
            if any(
                not hmac.compare_digest(before, after)
                for before, after in (
                    (head_bytes, head_after),
                    (version_tags, version_after),
                    (fsmonitor_tags, fsmonitor_after),
                    (staged, staged_after),
                    (config_before, config_after),
                )
            ) or not _directory_identity_is_current(repository):
                raise RuntimeError

        visit(source_root, b".", None)
        if root_commit is None or script_digest is None:
            raise RuntimeError
        return SourceSnapshot(
            commit=root_commit,
            probe_script_sha256=script_digest,
            repository_state_sha256=state.hexdigest(),
        )
    except BaseException:
        raise RuntimeError("content-safe source metadata unavailable") from None
    finally:
        if source_root is not None:
            os.close(source_root.descriptor)


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


def _publish_new_json(path: Path, payload: Mapping[str, object]) -> EvidenceArtifact:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    descriptor: int | None = None
    published = False
    device: int | None = None
    inode: int | None = None
    try:
        rendered = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(rendered) > MAX_EVIDENCE_ARTIFACT_BYTES:
            raise RuntimeError("host probe completion publication failed")
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
        metadata = os.fstat(descriptor)
        device = metadata.st_dev
        inode = metadata.st_ino
        if not _publication_path_is_current(
            temporary,
            descriptor,
            device=device,
            inode=inode,
            expected_links=1,
        ):
            raise RuntimeError("host probe completion publication failed")
        _completion_stage_operation("write", descriptor, rendered)
        if not _publication_path_is_current(
            temporary,
            descriptor,
            device=device,
            inode=inode,
            expected_links=1,
        ):
            raise RuntimeError("host probe completion publication failed")
        _completion_stage_operation("file_fsync", descriptor)
        if not _publication_path_is_current(
            temporary,
            descriptor,
            device=device,
            inode=inode,
            expected_links=1,
        ):
            raise RuntimeError("host probe completion publication failed")
        _completion_stage_operation("link", temporary, path)
        published = True
        if not _publication_path_is_current(
            temporary,
            descriptor,
            device=device,
            inode=inode,
            expected_links=2,
        ) or not _publication_path_is_current(
            path,
            descriptor,
            device=device,
            inode=inode,
            expected_links=2,
        ):
            raise RuntimeError("host probe completion publication failed")
        temporary.unlink()
        if not _publication_path_is_current(
            path,
            descriptor,
            device=device,
            inode=inode,
            expected_links=1,
        ):
            raise RuntimeError("host probe completion publication failed")
        _completion_stage_operation("directory_fsync", path.parent)
        if not _publication_path_is_current(
            path,
            descriptor,
            device=device,
            inode=inode,
            expected_links=1,
        ):
            raise RuntimeError("host probe completion publication failed")
        artifact = EvidenceArtifact(
            path=path,
            descriptor=descriptor,
            device=device,
            inode=inode,
        )
        descriptor = None
        return artifact
    except BaseException:
        if descriptor is not None and device is not None and inode is not None:
            removed = False
            if published:
                removed = _unlink_if_owned(
                    path,
                    descriptor,
                    device=device,
                    inode=inode,
                )
            _unlink_if_owned(
                temporary,
                descriptor,
                device=device,
                inode=inode,
            )
            if removed:
                with suppress(BaseException):
                    _fsync_directory(path.parent)
        raise
    finally:
        if descriptor is not None:
            if device is not None and inode is not None:
                _unlink_if_owned(
                    temporary,
                    descriptor,
                    device=device,
                    inode=inode,
                )
            os.close(descriptor)


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
        metadata = os.fstat(descriptor)
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
        if not _claim_path_is_current(claim):
            raise RuntimeError("host probe receipt destination unavailable")
        _write_all(descriptor, payload)
        if not _claim_path_is_current(claim):
            raise RuntimeError("host probe receipt destination unavailable")
        os.fsync(descriptor)
        if not _claim_path_is_current(claim):
            raise RuntimeError("host probe receipt destination unavailable")
        _fsync_directory(path.parent)
        if not _claim_path_is_current(claim):
            raise RuntimeError("host probe receipt destination unavailable")
        _require_path_absent(completion_path)
        descriptor = None
        return claim
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _claim_path_is_current(claim: ReceiptClaim) -> bool:
    try:
        opened = os.fstat(claim.descriptor)
        metadata = claim.path.lstat()
    except OSError:
        return False
    return _evidence_metadata_is_exact(
        opened,
        metadata,
        device=claim.device,
        inode=claim.inode,
    )


def _restore_fail_closed_claim(claim: ReceiptClaim) -> None:
    if _claim_path_is_current(claim):
        os.ftruncate(claim.descriptor, 0)
        os.lseek(claim.descriptor, 0, os.SEEK_SET)
        _write_all(claim.descriptor, claim.payload)
        os.fsync(claim.descriptor)
        return
    raise RuntimeError("host probe receipt claim changed")


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
    if len(rendered) > MAX_EVIDENCE_ARTIFACT_BYTES:
        raise RuntimeError("host probe receipt publication failed")
    try:
        for stage, arguments in (
            ("truncate", (claim.descriptor,)),
            ("write", (claim.descriptor, rendered)),
            ("file_fsync", (claim.descriptor,)),
            ("directory_fsync", (claim.path.parent,)),
        ):
            _receipt_stage_operation("path_recheck", claim)
            _receipt_stage_operation(stage, *arguments)
            _receipt_stage_operation("path_recheck", claim)
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
) -> EvidenceArtifact:
    completion = _completion_record(receipt)
    _validate_phase1_host_probe_completion(completion)
    return _publish_new_json(phase1_host_probe_completion_path(receipt_path), completion)


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


def _main(argv: Sequence[str] | None = None) -> int:
    selected_arguments = tuple(sys.argv[1:] if argv is None else argv)
    parser = _ContentFreeArgumentParser(
        prog="probe_macos_keychain",
        allow_abbrev=False,
        add_help=False,
    )
    parser.add_argument("--acknowledge-keychain-write", action="store_true")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--attempt-id")
    parser.add_argument("--owner-approval-commitment-sha256")
    if selected_arguments in {("-h",), ("--help",)}:
        parser.print_help()
        return 0
    arguments = parser.parse_args(selected_arguments)
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
    completion_artifact: EvidenceArtifact | None = None
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
            completion_artifact = _publish_completion_record(arguments.receipt, receipt)
            completion_path = phase1_host_probe_completion_path(arguments.receipt)
            if not _claim_path_is_current(claim) or not _evidence_artifact_is_current(
                completion_artifact
            ):
                raise RuntimeError("host probe completion publication failed")
            if failure is None:
                verify_phase1_host_probe_receipt(
                    arguments.receipt,
                    completion_path,
                    expected_run_id=claim.run_id,
                    expected_attempt_id=claim.attempt_id,
                    expected_owner_approval_commitment_sha256=(owner_approval_commitment_sha256),
                    expected_source_commit=final_snapshot.commit,
                    expected_probe_script_sha256=final_snapshot.probe_script_sha256,
                )
                if not _claim_path_is_current(claim) or not _evidence_artifact_is_current(
                    completion_artifact
                ):
                    raise RuntimeError("host probe completion publication failed")
            receipt_completed = True
        except BaseException as error:
            failure = error
            with suppress(BaseException):
                _restore_fail_closed_claim(claim)

    if claim is not None:
        with suppress(OSError):
            os.close(claim.descriptor)
    if completion_artifact is not None:
        with suppress(OSError):
            os.close(completion_artifact.descriptor)

    if failure is not None:
        _emit_probe_result(passed=False)
        return 1
    if arguments.receipt is not None and not receipt_completed:
        _emit_probe_result(passed=False)
        return 1
    _emit_probe_result(passed=True)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _main(argv)
    except BaseException:
        _emit_probe_result(passed=False)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
