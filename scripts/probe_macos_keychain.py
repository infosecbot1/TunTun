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
import subprocess
import sys
from collections.abc import Mapping, Sequence
from contextlib import suppress
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
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SYSTEM_GIT = "/usr/bin/git"
SYSTEM_SYSCTL = "/usr/sbin/sysctl"
SYSTEM_SW_VERS = "/usr/bin/sw_vers"

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_SHORT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9,._-]{0,63}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_BACKEND_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,255}$")


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
            "recorded_at_utc",
            "status",
            "cleanup_verified",
            "host",
            "runtime",
            "source",
            "artifact_digests",
            "owner_approval_commitment_sha256",
        },
    )
    if root["$schema"] != PHASE1_HOST_PROBE_SCHEMA_ID:
        raise _receipt_error()
    if root["receipt_id"] != PHASE1_HOST_PROBE_RECEIPT_ID:
        raise _receipt_error()
    if root["evidence_use"] != PHASE1_HOST_PROBE_EVIDENCE_USE:
        raise _receipt_error()
    _safe_run_id(root["run_id"])
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


def verify_phase1_host_probe_receipt(
    receipt: object,
    *,
    expected_run_id: str,
    expected_owner_approval_commitment_sha256: str,
    expected_source_commit: str,
    expected_probe_script_sha256: str,
) -> None:
    validate_phase1_host_probe_receipt(receipt)
    if type(receipt) is not dict:
        raise _receipt_error()
    root = receipt
    source = _exact_mapping(root["source"], {"commit", "probe_script_sha256"})
    expected = (
        _safe_run_id(expected_run_id),
        _safe_string(expected_owner_approval_commitment_sha256, _DIGEST_RE),
        _safe_string(expected_source_commit, _COMMIT_RE),
        _safe_string(expected_probe_script_sha256, _DIGEST_RE),
    )
    actual = (
        _safe_run_id(root["run_id"]),
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


def build_phase1_host_probe_receipt(
    *,
    status: str,
    cleanup_verified: bool,
    run_id: str,
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
    }
    validate_phase1_host_probe_receipt(receipt)
    return receipt


def _run_content_safe_command(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    allow_empty: bool = False,
) -> str:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            cwd=cwd,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except Exception:
        raise RuntimeError("content-safe host metadata unavailable") from None
    value = completed.stdout.strip()
    if completed.returncode != 0 or (not value and not allow_empty):
        raise RuntimeError("content-safe host metadata unavailable")
    return value


def _current_source_commit() -> str:
    root = _run_content_safe_command(
        (SYSTEM_GIT, "-C", str(REPOSITORY_ROOT), "rev-parse", "--show-toplevel"),
        cwd=REPOSITORY_ROOT,
    )
    try:
        source_root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError):
        raise RuntimeError("content-safe source metadata unavailable") from None
    if source_root != REPOSITORY_ROOT:
        raise RuntimeError("content-safe source metadata unavailable")
    dirty = _run_content_safe_command(
        (
            SYSTEM_GIT,
            "-C",
            str(REPOSITORY_ROOT),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ),
        cwd=REPOSITORY_ROOT,
        allow_empty=True,
    )
    if dirty:
        raise RuntimeError("content-safe source metadata unavailable")
    submodules = _run_content_safe_command(
        (
            SYSTEM_GIT,
            "-C",
            str(REPOSITORY_ROOT),
            "submodule",
            "status",
            "--recursive",
        ),
        cwd=REPOSITORY_ROOT,
        allow_empty=True,
    )
    for index, line in enumerate(submodules.splitlines()):
        prefix = "" if index == 0 else " "
        if re.fullmatch(rf"{prefix}[0-9a-f]{{40}} .+", line) is None:
            raise RuntimeError("content-safe source metadata unavailable")
    commit = _run_content_safe_command(
        (
            SYSTEM_GIT,
            "-C",
            str(REPOSITORY_ROOT),
            "rev-parse",
            "--verify",
            "HEAD",
        ),
        cwd=REPOSITORY_ROOT,
    )
    if _COMMIT_RE.fullmatch(commit) is None:
        raise RuntimeError("content-safe source metadata unavailable")
    return commit


def _current_probe_script_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


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
        "source_commit": _current_source_commit(),
        "probe_script_sha256": _current_probe_script_sha256(),
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


def _publish_file_exclusively(source: Path, destination: Path) -> None:
    published = False
    try:
        os.link(source, destination, follow_symlinks=False)
        published = True
        _fsync_directory(destination.parent)
    except BaseException:
        if published:
            with suppress(BaseException):
                destination.unlink()
                _fsync_directory(destination.parent)
        raise


def _publish_new_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    descriptor: int | None = None
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
        _write_all(descriptor, rendered)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        _publish_file_exclusively(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink()


def _write_phase1_host_probe_receipt(
    path: Path,
    *,
    status: str,
    cleanup_verified: bool,
    run_id: str,
    owner_approval_commitment_sha256: str,
    host_context: Mapping[str, object],
) -> None:
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
    _publish_new_json(path, receipt)


def _require_receipt_destination_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise RuntimeError("host probe receipt destination unavailable") from None
    raise RuntimeError("host probe receipt destination already exists")


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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--acknowledge-keychain-write", action="store_true")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--owner-approval-commitment-sha256")
    arguments = parser.parse_args(argv)
    if not arguments.acknowledge_keychain_write or os.environ.get(PROBE_ENVIRONMENT_ACK) != "1":
        raise RuntimeError("Keychain probe requires explicit dual acknowledgement")

    receipt_arguments = (
        arguments.receipt,
        arguments.run_id,
        arguments.owner_approval_commitment_sha256,
    )
    if any(value is not None for value in receipt_arguments) and not all(
        value is not None for value in receipt_arguments
    ):
        raise RuntimeError("Keychain probe receipt requires every evidence binding")

    run_id: str | None = None
    owner_approval_commitment_sha256: str | None = None
    if arguments.receipt is not None:
        run_id = _safe_run_id(arguments.run_id)
        owner_approval_commitment_sha256 = _safe_string(
            arguments.owner_approval_commitment_sha256,
            _DIGEST_RE,
        )

    host_context: Mapping[str, object] | None = None
    failure: BaseException | None = None
    status = "fail"
    cleanup_verified = False
    try:
        if arguments.receipt is not None:
            _require_receipt_destination_absent(arguments.receipt)
        provider = MacOSKeychainSecretProvider()
        if arguments.receipt is not None:
            host_context = _capture_content_safe_host_context(provider)
        account = f"round-trip-{uuid4()}"
        value = secrets.token_bytes(32)
        probe_keychain_round_trip(
            provider,
            PROBE_SERVICE,
            account,
            value,
        )
        status = "pass"
        cleanup_verified = True
    except BaseException as error:
        failure = error
        if isinstance(error, RuntimeError):
            cleanup_verified = getattr(error, "cleanup_verified", False)

    if arguments.receipt is not None and host_context is not None:
        try:
            if run_id is None or owner_approval_commitment_sha256 is None:
                raise RuntimeError("Keychain probe receipt binding unavailable")
            _write_phase1_host_probe_receipt(
                arguments.receipt,
                status=status,
                cleanup_verified=cleanup_verified,
                run_id=run_id,
                owner_approval_commitment_sha256=owner_approval_commitment_sha256,
                host_context=host_context,
            )
        except BaseException as error:
            failure = error

    if failure is not None:
        print("macOS Keychain probe: FAIL", file=sys.stderr)
        return 1
    print("macOS Keychain probe: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
