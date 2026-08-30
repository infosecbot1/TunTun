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
from uuid import uuid4

from tuntun_core.adapters.keychain.macos import MacOSKeychainSecretProvider
from tuntun_core.adapters.keychain.provider import SecretProvider

PROBE_ENVIRONMENT_ACK = "TUNTUN_ALLOW_KEYCHAIN_PROBE"
PROBE_SERVICE = "tuntun.probe.keychain"
PHASE1_HOST_PROBE_SCHEMA_ID = "https://tuntun.local/schemas/evidence/phase1-host-probe.schema.json"
PHASE1_HOST_PROBE_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "docs/evidence/phase1-host-probe.schema.json"
)
PHASE1_HOST_PROBE_RECEIPT_ID = "phase1.macos-keychain.host-probe.v1"

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_RECORDED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SAFE_SHORT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9,._-]{0,63}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_BACKEND_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,255}$")
_SAFE_REVIEW_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


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
    *,
    expected_source_commit: str | None = None,
    expected_probe_script_sha256: str | None = None,
) -> None:
    root = _exact_mapping(
        receipt,
        {
            "$schema",
            "receipt_id",
            "recorded_at_utc",
            "status",
            "cleanup_verified",
            "host",
            "runtime",
            "source",
            "artifact_digests",
            "owner_review_ref",
        },
    )
    if root["$schema"] != PHASE1_HOST_PROBE_SCHEMA_ID:
        raise _receipt_error()
    if root["receipt_id"] != PHASE1_HOST_PROBE_RECEIPT_ID:
        raise _receipt_error()
    _safe_string(root["recorded_at_utc"], _RECORDED_AT_RE)
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
    commit = _safe_string(source["commit"], _COMMIT_RE)
    digest = _safe_string(source["probe_script_sha256"], _DIGEST_RE)
    _validate_artifact_digests(root["artifact_digests"])
    _safe_string(root["owner_review_ref"], _SAFE_REVIEW_RE)

    if (
        expected_source_commit is not None
        and commit != expected_source_commit
        or expected_probe_script_sha256 is not None
        and digest != expected_probe_script_sha256
    ):
        raise RuntimeError("host probe receipt source mismatch")


def build_phase1_host_probe_receipt(
    *,
    status: str,
    cleanup_verified: bool,
    owner_review_ref: str,
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
        "owner_review_ref": owner_review_ref,
    }
    validate_phase1_host_probe_receipt(receipt)
    return receipt


def _run_content_safe_command(arguments: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except Exception:
        raise RuntimeError("content-safe host metadata unavailable") from None
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value:
        raise RuntimeError("content-safe host metadata unavailable")
    return value


def _current_source_commit() -> str:
    return _run_content_safe_command(("git", "rev-parse", "HEAD"))


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
        "model_class": _run_content_safe_command(("sysctl", "-n", "hw.model")),
        "os_product_version": _run_content_safe_command(("sw_vers", "-productVersion")),
        "os_build": _run_content_safe_command(("sw_vers", "-buildVersion")),
        "python_version": platform.python_version(),
        "keyring_version": keyring_version,
        "keyring_backend_class": f"{backend_type.__module__}.{backend_type.__qualname__}",
        "source_commit": _current_source_commit(),
        "probe_script_sha256": _current_probe_script_sha256(),
    }


def _atomic_write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _replace_file(temporary, path)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _replace_file(source: Path, destination: Path) -> None:
    os.replace(str(source), str(destination))


def _write_phase1_host_probe_receipt(
    path: Path,
    *,
    status: str,
    cleanup_verified: bool,
    owner_review_ref: str,
    host_context: Mapping[str, object],
) -> None:
    receipt = build_phase1_host_probe_receipt(
        status=status,
        cleanup_verified=cleanup_verified,
        owner_review_ref=owner_review_ref,
        recorded_at_utc=_utc_now(),
        **host_context,
    )
    _atomic_write_json(path, receipt)


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
    parser.add_argument("--owner-review-ref")
    arguments = parser.parse_args(argv)
    if not arguments.acknowledge_keychain_write or os.environ.get(PROBE_ENVIRONMENT_ACK) != "1":
        raise RuntimeError("Keychain probe requires explicit dual acknowledgement")
    if arguments.receipt is not None and not arguments.owner_review_ref:
        raise RuntimeError("Keychain probe receipt requires owner review reference")
    host_context: Mapping[str, object] | None = None
    try:
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
        if arguments.receipt is not None:
            _write_phase1_host_probe_receipt(
                arguments.receipt,
                status="pass",
                cleanup_verified=True,
                owner_review_ref=arguments.owner_review_ref,
                host_context=host_context,
            )
    except BaseException:
        if arguments.receipt is not None and host_context is not None:
            cleanup_verified = False
            error = sys.exc_info()[1]
            if isinstance(error, RuntimeError):
                cleanup_verified = getattr(error, "cleanup_verified", False)
            with suppress(BaseException):
                _write_phase1_host_probe_receipt(
                    arguments.receipt,
                    status="fail",
                    cleanup_verified=cleanup_verified,
                    owner_review_ref=arguments.owner_review_ref,
                    host_context=host_context,
                )
        print("macOS Keychain probe: FAIL", file=sys.stderr)
        return 1
    print("macOS Keychain probe: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
