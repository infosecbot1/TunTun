from __future__ import annotations

import base64
import builtins
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import traceback
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import keyring
import pytest
from tuntun_core.adapters.keychain import macos
from tuntun_core.adapters.keychain.macos import MacOSKeychainSecretProvider
from tuntun_core.adapters.keychain.provider import (
    MAX_SECRET_BYTES,
    REQUIRED_SECRET_LENGTHS,
    REQUIRED_SECRETS,
    SECRET_IDS,
    InMemorySecretProvider,
    validate_production_secrets,
)

from scripts import probe_macos_keychain as probe_script

EXPECTED_SECRET_IDS = {
    "database": ("tuntun.database", "root-v1"),
    "audit": ("tuntun.audit", "hmac-v1"),
    "backup": ("tuntun.backup", "slot-v1"),
    "records": ("tuntun.records", "root-v1"),
    "openai": ("tuntun.provider.openai", "api-v1"),
    "qwen": ("tuntun.provider.qwen", "api-v1"),
    "edge_ca": ("tuntun.edge.ca", "signing-v1"),
    "device_signing": ("tuntun.edge.device", "signing-v1"),
}
HOST_PROBE_RUN_ID = "00000000-0000-4000-8000-000000000901"
OTHER_HOST_PROBE_RUN_ID = "00000000-0000-4000-8000-000000000902"
HOST_PROBE_ATTEMPT_ID = "00000000-0000-4000-8000-000000000911"
OTHER_HOST_PROBE_ATTEMPT_ID = "00000000-0000-4000-8000-000000000912"
OWNER_APPROVAL_COMMITMENT_SHA256 = "c" * 64
COMPLETION_BINDING_SHA256 = "d" * 64


def _safe_host_receipt_context(**overrides: object) -> dict[str, object]:
    context: dict[str, object] = {
        "system": "Darwin",
        "machine": "arm64",
        "model_class": "Mac15,7",
        "os_product_version": "26.6.1",
        "os_build": "25G76",
        "python_version": "3.12.3",
        "keyring_version": "25.7.0",
        "keyring_backend_class": "keyring.backends.macOS.Keyring",
        "source_commit": "f" * 40,
        "probe_script_sha256": "a" * 64,
    }
    context.update(overrides)
    return context


def _safe_host_receipt(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "status": "pass",
        "cleanup_verified": True,
        "run_id": HOST_PROBE_RUN_ID,
        "attempt_id": HOST_PROBE_ATTEMPT_ID,
        "completion_binding_sha256": COMPLETION_BINDING_SHA256,
        "owner_approval_commitment_sha256": OWNER_APPROVAL_COMMITMENT_SHA256,
        "recorded_at_utc": "2026-08-30T00:00:00Z",
        **_safe_host_receipt_context(),
    }
    values.update(overrides)
    return probe_script.build_phase1_host_probe_receipt(**values)  # type: ignore[arg-type]


def _safe_host_completion(
    receipt: dict[str, object] | None = None,
    **overrides: object,
) -> dict[str, object]:
    selected = _safe_host_receipt() if receipt is None else receipt
    values: dict[str, object] = {
        "$schema": probe_script.PHASE1_HOST_PROBE_COMPLETION_SCHEMA_ID,
        "completion_id": probe_script.PHASE1_HOST_PROBE_COMPLETION_ID,
        "run_id": HOST_PROBE_RUN_ID,
        "attempt_id": HOST_PROBE_ATTEMPT_ID,
        "receipt_sha256": probe_script._canonical_receipt_sha256(selected),
        "completion_binding_sha256": COMPLETION_BINDING_SHA256,
        "state": "complete",
    }
    values.update(overrides)
    return values


def _safe_source_snapshot(**overrides: str) -> object:
    values = {
        "commit": "f" * 40,
        "probe_script_sha256": "a" * 64,
        "repository_state_sha256": "b" * 64,
    }
    values.update(overrides)
    return probe_script.SourceSnapshot(**values)


def _receipt_cli_arguments(path: Path) -> list[str]:
    return [
        "--acknowledge-keychain-write",
        "--receipt",
        str(path),
        "--run-id",
        HOST_PROBE_RUN_ID,
        "--attempt-id",
        HOST_PROBE_ATTEMPT_ID,
        "--owner-approval-commitment-sha256",
        OWNER_APPROVAL_COMMITMENT_SHA256,
    ]


def _expected_host_probe_bindings() -> dict[str, str]:
    return {
        "expected_run_id": HOST_PROBE_RUN_ID,
        "expected_attempt_id": HOST_PROBE_ATTEMPT_ID,
        "expected_owner_approval_commitment_sha256": OWNER_APPROVAL_COMMITMENT_SHA256,
        "expected_source_commit": "f" * 40,
        "expected_probe_script_sha256": "a" * 64,
    }


def _write_host_probe_evidence_pair(
    root: Path,
    *,
    receipt: dict[str, object] | None = None,
    completion: dict[str, object] | None = None,
) -> tuple[Path, Path]:
    selected_receipt = _safe_host_receipt() if receipt is None else receipt
    selected_completion = (
        _safe_host_completion(selected_receipt) if completion is None else completion
    )
    receipt_path = root / "receipt.json"
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    receipt_path.write_text(json.dumps(selected_receipt), encoding="utf-8")
    completion_path.write_text(json.dumps(selected_completion), encoding="utf-8")
    receipt_path.chmod(0o600)
    completion_path.chmod(0o600)
    return receipt_path, completion_path


class ProbeControlFlow(BaseException):
    pass


class FakeMacOSBackend:
    priority = 5

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.get_error: Exception | None = None
        self.set_error: Exception | None = None
        self.delete_error: str | None = None
        self.keep_after_delete = False

    def get_password(self, service: str, account: str) -> str | None:
        if self.get_error is not None:
            raise self.get_error
        return self.values.get((service, account))

    def set_password(self, service: str, account: str, value: str) -> None:
        if self.set_error is not None:
            raise self.set_error
        self.values[(service, account)] = value

    def delete_password(self, service: str, account: str) -> None:
        key = (service, account)
        if self.delete_error == "race":
            self.values.pop(key, None)
            raise keyring.errors.PasswordDeleteError("already absent")
        if self.delete_error == "denied":
            raise keyring.errors.PasswordDeleteError("permission denied")
        if self.delete_error == "generic":
            raise keyring.errors.KeyringLocked("locked")
        if not self.keep_after_delete:
            self.values.pop(key, None)


def _mac_provider(
    monkeypatch: pytest.MonkeyPatch,
    backend: FakeMacOSBackend,
) -> MacOSKeychainSecretProvider:
    monkeypatch.setattr(macos.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(macos, "_load_macos_keyring_type", lambda: FakeMacOSBackend)
    monkeypatch.setattr(macos.keyring, "get_keyring", lambda: backend)
    return MacOSKeychainSecretProvider()


def _complete_required_provider() -> InMemorySecretProvider:
    provider = InMemorySecretProvider()
    for service, account in REQUIRED_SECRETS:
        provider.set(service, account, b"r" * REQUIRED_SECRET_LENGTHS[(service, account)])
    return provider


def _format_runtime_error(action: Callable[[], object]) -> str:
    try:
        action()
    except RuntimeError as error:
        return "".join(traceback.format_exception(error))
    raise AssertionError("expected RuntimeError")


def _capture_boundary_error(
    action: Callable[[], object],
) -> tuple[type[BaseException] | None, str]:
    try:
        action()
    except BaseException as error:
        return type(error), "".join(traceback.format_exception(error))
    return None, ""


def test_secret_identifier_map_is_exact_immutable_and_collision_free() -> None:
    assert SECRET_IDS == EXPECTED_SECRET_IDS
    assert len(set(SECRET_IDS.values())) == len(SECRET_IDS)
    assert tuple(REQUIRED_SECRET_LENGTHS) == REQUIRED_SECRETS
    assert set(REQUIRED_SECRET_LENGTHS.values()) == {32}
    with pytest.raises(TypeError):
        SECRET_IDS["database"] = ("changed", "changed")  # type: ignore[index]
    with pytest.raises(TypeError):
        cast(Any, REQUIRED_SECRET_LENGTHS)[SECRET_IDS["database"]] = 64


def test_in_memory_provider_round_trip_delete_and_repr_are_content_free() -> None:
    provider = InMemorySecretProvider()
    sentinel = b"db-secret-sentinel"
    provider.set("tuntun.database", "root-v1", sentinel)
    assert provider.get("tuntun.database", "root-v1") == sentinel
    assert provider.exists("tuntun.database", "root-v1")
    assert sentinel.decode() not in repr(provider)
    provider.delete("tuntun.database", "root-v1")
    provider.delete("tuntun.database", "root-v1")
    assert not provider.exists("tuntun.database", "root-v1")
    with pytest.raises(RuntimeError, match="missing secret"):
        provider.get("tuntun.database", "root-v1")


def test_provider_tracebacks_hide_dynamic_identifiers_and_provider_failures() -> None:
    dynamic_service = "tuntun.private-sentinel"
    dynamic_account = "private-sentinel"
    missing_traceback = _format_runtime_error(
        lambda: InMemorySecretProvider().get(dynamic_service, dynamic_account)
    )

    class FailingProvider:
        def get(self, service: str, account: str) -> bytes:
            raise RuntimeError(f"provider-private-sentinel-{service}-{account}")

        def set(self, service: str, account: str, value: bytes) -> None:
            raise AssertionError("not called")

        def delete(self, service: str, account: str) -> None:
            raise AssertionError("not called")

        def exists(self, service: str, account: str) -> bool:
            raise AssertionError("not called")

    validation_traceback = _format_runtime_error(
        lambda: validate_production_secrets(FailingProvider())
    )
    rendered = missing_traceback + validation_traceback
    assert "private-sentinel" not in rendered
    assert "tuntun.database" not in validation_traceback
    assert "root-v1" not in validation_traceback


@pytest.mark.parametrize(
    "service,account",
    (
        ("", "root-v1"),
        ("Tuntun.database", "root-v1"),
        ("tuntun.database\n", "root-v1"),
        ("tuntun.database", ""),
        ("tuntun.database", "root/v1"),
    ),
)
def test_secret_identifiers_are_bounded_and_canonical(service: str, account: str) -> None:
    with pytest.raises(ValueError, match="invalid secret identifier"):
        InMemorySecretProvider().set(service, account, b"value")


@pytest.mark.parametrize("value", (b"", b"x" * (MAX_SECRET_BYTES + 1), "not-bytes"))
def test_secret_values_are_nonempty_bounded_exact_bytes(value: object) -> None:
    with pytest.raises(ValueError, match="nonempty bounded bytes"):
        InMemorySecretProvider().set(
            "tuntun.database",
            "root-v1",
            value,  # type: ignore[arg-type]
        )


def test_production_validation_requires_every_exact_length_root() -> None:
    provider = _complete_required_provider()
    validate_production_secrets(provider)
    provider.delete(*SECRET_IDS["audit"])
    with pytest.raises(RuntimeError, match="missing or invalid required secret"):
        validate_production_secrets(provider)
    provider.set(*SECRET_IDS["audit"], b"short")
    with pytest.raises(RuntimeError, match="invalid required secret length"):
        validate_production_secrets(provider)


def test_production_validation_rejects_exists_true_get_empty() -> None:
    class EmptyProvider:
        def get(self, service: str, account: str) -> bytes:
            return b""

        def set(self, service: str, account: str, value: bytes) -> None:
            raise AssertionError("not called")

        def delete(self, service: str, account: str) -> None:
            raise AssertionError("not called")

        def exists(self, service: str, account: str) -> bool:
            return True

    with pytest.raises(RuntimeError, match="missing or invalid required secret"):
        validate_production_secrets(EmptyProvider())


def test_macos_provider_rejects_wrong_platform_before_backend_loading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(macos.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        macos,
        "_load_macos_keyring_type",
        lambda: pytest.fail("backend loader must not run"),
    )
    with pytest.raises(RuntimeError, match="must be macOS Keychain"):
        MacOSKeychainSecretProvider()


def test_macos_backend_loader_fails_closed_on_import_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def reject_macos_backend(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if name == "keyring.backends.macOS":
            raise ImportError("synthetic unavailable backend")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", reject_macos_backend)
    with pytest.raises(RuntimeError, match="backend is unavailable"):
        macos._load_macos_keyring_type()


def test_macos_provider_requires_exact_backend_type_and_priority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DerivedBackend(FakeMacOSBackend):
        pass

    monkeypatch.setattr(macos.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(macos, "_load_macos_keyring_type", lambda: FakeMacOSBackend)
    monkeypatch.setattr(macos.keyring, "get_keyring", lambda: DerivedBackend())
    with pytest.raises(RuntimeError, match="must be macOS Keychain"):
        MacOSKeychainSecretProvider()


def test_macos_provider_surfaces_backend_discovery_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(macos.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(macos, "_load_macos_keyring_type", lambda: FakeMacOSBackend)

    def fail_discovery() -> FakeMacOSBackend:
        raise keyring.errors.KeyringLocked("locked")

    monkeypatch.setattr(macos.keyring, "get_keyring", fail_discovery)
    with pytest.raises(RuntimeError, match="backend is unavailable"):
        MacOSKeychainSecretProvider()

    for invalid_priority in (object(), "5", float("nan")):

        class InvalidPriorityBackend(FakeMacOSBackend):
            pass

        InvalidPriorityBackend.priority = cast(Any, invalid_priority)
        monkeypatch.setattr(macos, "_load_macos_keyring_type", lambda: InvalidPriorityBackend)
        monkeypatch.setattr(macos.keyring, "get_keyring", lambda: InvalidPriorityBackend())
        with pytest.raises(RuntimeError, match="backend is unavailable"):
            MacOSKeychainSecretProvider()

    class ZeroPriorityBackend(FakeMacOSBackend):
        priority = 0

    monkeypatch.setattr(macos, "_load_macos_keyring_type", lambda: ZeroPriorityBackend)
    monkeypatch.setattr(macos.keyring, "get_keyring", lambda: ZeroPriorityBackend())
    with pytest.raises(RuntimeError, match="backend is unavailable"):
        MacOSKeychainSecretProvider()


def test_macos_priority_type_check_does_not_hash_hostile_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects: list[str] = []

    class HostileMeta(type):
        def __hash__(cls) -> int:
            effects.append("type-hash")
            raise RuntimeError("private-priority-hash-sentinel")

    class PriorityValue(metaclass=HostileMeta):
        pass

    class HostilePriorityBackend(FakeMacOSBackend):
        priority = PriorityValue()

    monkeypatch.setattr(macos.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        macos,
        "_load_macos_keyring_type",
        lambda: HostilePriorityBackend,
    )
    monkeypatch.setattr(macos.keyring, "get_keyring", HostilePriorityBackend)
    rendered = _format_runtime_error(MacOSKeychainSecretProvider)
    assert "private-priority-hash-sentinel" not in rendered
    assert effects == []


@pytest.mark.parametrize("seam", ("bind", "constructor"))
@pytest.mark.parametrize("comparison", ("eq", "ne"))
@pytest.mark.parametrize("raises", (False, True), ids=("recording", "raising"))
def test_macos_platform_checks_reject_non_strings_without_comparison_hooks(
    monkeypatch: pytest.MonkeyPatch,
    seam: str,
    comparison: str,
    raises: bool,
) -> None:
    comparisons: list[str] = []
    backend_loads: list[str] = []

    if comparison == "eq":

        class SystemNameSpy:
            def __eq__(self, other: object) -> bool:
                del other
                comparisons.append("eq")
                if raises:
                    raise RuntimeError("private-platform-eq-sentinel")
                return True

    else:

        class SystemNameSpy:
            def __ne__(self, other: object) -> bool:
                del other
                comparisons.append("ne")
                if raises:
                    raise RuntimeError("private-platform-ne-sentinel")
                return False

    system_name = SystemNameSpy()
    backend = FakeMacOSBackend()
    if seam == "bind":
        action = lambda: macos._bind_macos_backend(  # noqa: E731
            cast(Any, system_name),
            cast(Any, backend),
            cast(Any, FakeMacOSBackend),
        )
    else:
        monkeypatch.setattr(macos.platform, "system", lambda: cast(Any, system_name))

        def load_backend() -> Any:
            backend_loads.append("loaded")
            return FakeMacOSBackend

        monkeypatch.setattr(macos, "_load_macos_keyring_type", load_backend)
        monkeypatch.setattr(macos.keyring, "get_keyring", lambda: backend)
        action = MacOSKeychainSecretProvider

    error_type, rendered = _capture_boundary_error(action)
    assert error_type is RuntimeError
    assert "production secret backend must be macOS Keychain" in rendered
    assert "private-platform" not in rendered
    assert comparisons == []
    assert backend_loads == []


def test_macos_provider_binds_validated_backend_and_round_trips_base64(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeMacOSBackend()
    provider = _mac_provider(monkeypatch, backend)
    other_backend = FakeMacOSBackend()
    monkeypatch.setattr(macos.keyring, "get_keyring", lambda: other_backend)
    sentinel = b"mac-keychain-secret-sentinel"
    provider.set("tuntun.database", "root-v1", sentinel)
    stored = backend.values[("tuntun.database", "root-v1")]
    assert sentinel.decode() not in stored
    assert provider.get("tuntun.database", "root-v1") == sentinel
    assert provider.exists("tuntun.database", "root-v1")
    assert not other_backend.values
    assert sentinel.decode() not in repr(provider)


@pytest.mark.parametrize(
    "encoded",
    (
        "",
        "%%%",
        "YWJjZA==\n",
        "Zh==",
        "A" * (macos.MAX_ENCODED_SECRET_CHARS + 1),
        base64.b64encode(b"x" * (MAX_SECRET_BYTES + 1)).decode("ascii"),
    ),
)
def test_macos_provider_rejects_empty_or_corrupt_stored_values(
    monkeypatch: pytest.MonkeyPatch,
    encoded: str,
) -> None:
    backend = FakeMacOSBackend()
    backend.values[("tuntun.database", "root-v1")] = encoded
    provider = _mac_provider(monkeypatch, backend)
    with pytest.raises(RuntimeError, match="invalid stored secret"):
        provider.get("tuntun.database", "root-v1")
    with pytest.raises(RuntimeError, match="invalid stored secret"):
        provider.exists("tuntun.database", "root-v1")


def test_macos_provider_rejects_non_string_stored_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeMacOSBackend()
    cast(Any, backend.values)[("tuntun.database", "root-v1")] = b"not-text"
    provider = _mac_provider(monkeypatch, backend)
    with pytest.raises(RuntimeError, match="invalid stored secret"):
        provider.get("tuntun.database", "root-v1")


def test_macos_provider_missing_and_backend_read_failures_are_content_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeMacOSBackend()
    provider = _mac_provider(monkeypatch, backend)
    assert not provider.exists("tuntun.database", "root-v1")
    with pytest.raises(RuntimeError, match="missing secret"):
        provider.get("tuntun.database", "root-v1")
    backend.get_error = keyring.errors.KeyringLocked("locked")
    with pytest.raises(RuntimeError, match="secret read failed") as raised:
        provider.get("tuntun.database", "root-v1")
    assert "secret-sentinel" not in str(raised.value)


def test_macos_boundary_tracebacks_hide_backend_text_and_dynamic_identifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "private-backend-sentinel"
    dynamic_service = "tuntun.private-sentinel"
    dynamic_account = "private-sentinel"

    monkeypatch.setattr(macos.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(macos, "_load_macos_keyring_type", lambda: FakeMacOSBackend)

    def fail_discovery() -> FakeMacOSBackend:
        raise RuntimeError(sentinel)

    monkeypatch.setattr(macos.keyring, "get_keyring", fail_discovery)
    rendered = _format_runtime_error(MacOSKeychainSecretProvider)

    backend = FakeMacOSBackend()
    provider = _mac_provider(monkeypatch, backend)
    backend.get_error = RuntimeError(sentinel)
    rendered += _format_runtime_error(lambda: provider.get(dynamic_service, dynamic_account))

    backend.get_error = None
    backend.set_error = RuntimeError(sentinel)
    rendered += _format_runtime_error(
        lambda: provider.set(dynamic_service, dynamic_account, b"value")
    )

    backend.set_error = None
    provider.set(dynamic_service, dynamic_account, b"value")

    def fail_delete(service: str, account: str) -> None:
        raise RuntimeError(f"{sentinel}-{service}-{account}")

    monkeypatch.setattr(backend, "delete_password", fail_delete)
    rendered += _format_runtime_error(lambda: provider.delete(dynamic_service, dynamic_account))

    assert sentinel not in rendered
    assert dynamic_service not in rendered
    assert dynamic_account not in rendered


def test_macos_provider_rejects_empty_set_before_backend_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeMacOSBackend()
    provider = _mac_provider(monkeypatch, backend)
    with pytest.raises(ValueError, match="nonempty bounded bytes"):
        provider.set("tuntun.database", "root-v1", b"")
    assert not backend.values


def test_macos_provider_surfaces_write_failure_and_readback_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeMacOSBackend()
    provider = _mac_provider(monkeypatch, backend)
    backend.set_error = keyring.errors.KeyringLocked("locked")
    with pytest.raises(RuntimeError, match="secret write failed"):
        provider.set("tuntun.database", "root-v1", b"value")

    backend.set_error = None

    def corrupt_write(service: str, account: str, value: str) -> None:
        del value
        backend.values[(service, account)] = "ZGlmZmVyZW50"

    monkeypatch.setattr(backend, "set_password", corrupt_write)
    with pytest.raises(RuntimeError, match="write verification failed"):
        provider.set("tuntun.database", "root-v1", b"value")


def test_macos_provider_delete_is_idempotent_and_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeMacOSBackend()
    provider = _mac_provider(monkeypatch, backend)
    provider.delete("tuntun.database", "root-v1")
    provider.set("tuntun.database", "root-v1", b"value")
    provider.delete("tuntun.database", "root-v1")
    assert not provider.exists("tuntun.database", "root-v1")


def test_macos_provider_accepts_only_proven_concurrent_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeMacOSBackend()
    provider = _mac_provider(monkeypatch, backend)
    provider.set("tuntun.database", "root-v1", b"value")
    backend.delete_error = "race"
    provider.delete("tuntun.database", "root-v1")
    assert not provider.exists("tuntun.database", "root-v1")


def test_macos_provider_surfaces_denied_or_unverified_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeMacOSBackend()
    provider = _mac_provider(monkeypatch, backend)
    provider.set("tuntun.database", "root-v1", b"value")
    backend.delete_error = "denied"
    with pytest.raises(RuntimeError, match="secret deletion failed"):
        provider.delete("tuntun.database", "root-v1")
    assert provider.exists("tuntun.database", "root-v1")
    backend.delete_error = None
    backend.keep_after_delete = True
    with pytest.raises(RuntimeError, match="deletion verification failed"):
        provider.delete("tuntun.database", "root-v1")


def test_macos_provider_surfaces_generic_and_unverifiable_delete_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeMacOSBackend()
    provider = _mac_provider(monkeypatch, backend)
    provider.set("tuntun.database", "root-v1", b"value")
    backend.delete_error = "generic"
    with pytest.raises(RuntimeError, match="secret deletion failed"):
        provider.delete("tuntun.database", "root-v1")

    class VerificationReadFailureBackend(FakeMacOSBackend):
        def delete_password(self, service: str, account: str) -> None:
            self.get_error = keyring.errors.KeyringLocked("locked")
            raise keyring.errors.PasswordDeleteError("permission denied")

    read_failure_backend = VerificationReadFailureBackend()
    monkeypatch.setattr(
        macos,
        "_load_macos_keyring_type",
        lambda: VerificationReadFailureBackend,
    )
    monkeypatch.setattr(macos.keyring, "get_keyring", lambda: read_failure_backend)
    read_failure_provider = MacOSKeychainSecretProvider()
    read_failure_provider.set("tuntun.database", "root-v1", b"value")
    with pytest.raises(RuntimeError, match="deletion could not be verified"):
        read_failure_provider.delete("tuntun.database", "root-v1")


def test_target_probe_round_trip_cleans_up_and_collision_preserves_existing() -> None:
    provider = InMemorySecretProvider()
    probe_script.probe_keychain_round_trip(provider, "tuntun.probe", "slot-v1", b"probe")
    assert not provider.exists("tuntun.probe", "slot-v1")
    provider.set("tuntun.probe", "slot-v1", b"existing")
    with pytest.raises(RuntimeError, match="slot already exists"):
        probe_script.probe_keychain_round_trip(
            provider,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    assert provider.get("tuntun.probe", "slot-v1") == b"existing"


def test_target_probe_cleans_up_a_partially_failed_write() -> None:
    class PartialFailureProvider(InMemorySecretProvider):
        def set(self, service: str, account: str, value: bytes) -> None:
            super().set(service, account, value)
            raise RuntimeError("synthetic post-write failure")

    provider = PartialFailureProvider()
    rendered = _format_runtime_error(
        lambda: probe_script.probe_keychain_round_trip(
            provider,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert "Keychain probe operation failed" in rendered
    assert "synthetic post-write failure" not in rendered
    assert not provider.exists("tuntun.probe", "slot-v1")


def test_target_probe_partial_write_and_ineffective_delete_reports_cleanup_failure() -> None:
    class PartialWriteNoDeleteProvider(InMemorySecretProvider):
        def set(self, service: str, account: str, value: bytes) -> None:
            super().set(service, account, value)
            raise RuntimeError("private-partial-write-sentinel")

        def delete(self, service: str, account: str) -> None:
            return None

    provider = PartialWriteNoDeleteProvider()
    rendered = _format_runtime_error(
        lambda: probe_script.probe_keychain_round_trip(
            provider,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert "Keychain probe cleanup failed" in rendered
    assert "private-partial-write-sentinel" not in rendered
    assert provider.exists("tuntun.probe", "slot-v1")


def test_target_probe_verifies_absence_after_delete_and_verification_exceptions() -> None:
    class DeleteFailureProvider(InMemorySecretProvider):
        def delete(self, service: str, account: str) -> None:
            super().delete(service, account)
            raise RuntimeError("private-delete-sentinel")

    delete_failure = DeleteFailureProvider()
    rendered = _format_runtime_error(
        lambda: probe_script.probe_keychain_round_trip(
            delete_failure,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert "Keychain probe cleanup failed" in rendered
    assert "private-delete-sentinel" not in rendered
    assert not delete_failure.exists("tuntun.probe", "slot-v1")

    class VerificationFailureProvider(InMemorySecretProvider):
        def __init__(self) -> None:
            super().__init__()
            self.exists_calls = 0

        def set(self, service: str, account: str, value: bytes) -> None:
            super().set(service, account, value)
            raise RuntimeError("private-partial-verification-sentinel")

        def exists(self, service: str, account: str) -> bool:
            self.exists_calls += 1
            if self.exists_calls > 1:
                raise RuntimeError("private-verification-sentinel")
            return super().exists(service, account)

    verification_failure = VerificationFailureProvider()
    rendered = _format_runtime_error(
        lambda: probe_script.probe_keychain_round_trip(
            verification_failure,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert "Keychain probe cleanup could not be verified" in rendered
    assert "private-verification-sentinel" not in rendered
    assert "private-partial-verification-sentinel" not in rendered
    assert verification_failure.exists_calls == 2
    assert not InMemorySecretProvider.exists(
        verification_failure,
        "tuntun.probe",
        "slot-v1",
    )


@pytest.mark.parametrize("error_type", (KeyboardInterrupt, SystemExit, ProbeControlFlow))
def test_target_probe_base_exception_after_partial_write_still_cleans_up(
    error_type: type[BaseException],
) -> None:
    class PartialControlFlowProvider(InMemorySecretProvider):
        def __init__(self) -> None:
            super().__init__()
            self.delete_calls = 0
            self.exists_calls = 0

        def exists(self, service: str, account: str) -> bool:
            self.exists_calls += 1
            return super().exists(service, account)

        def set(self, service: str, account: str, value: bytes) -> None:
            super().set(service, account, value)
            raise error_type("private-control-flow-sentinel")

        def delete(self, service: str, account: str) -> None:
            self.delete_calls += 1
            super().delete(service, account)

    provider = PartialControlFlowProvider()
    captured_type, rendered = _capture_boundary_error(
        lambda: probe_script.probe_keychain_round_trip(
            provider,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert captured_type is RuntimeError
    assert "Keychain probe operation failed" in rendered
    assert "private-control-flow-sentinel" not in rendered
    assert provider.delete_calls == 1
    assert provider.exists_calls == 2
    assert not InMemorySecretProvider.exists(provider, "tuntun.probe", "slot-v1")


@pytest.mark.parametrize("error_type", (KeyboardInterrupt, SystemExit, ProbeControlFlow))
def test_target_probe_preflight_translates_every_base_exception_without_cleanup(
    error_type: type[BaseException],
) -> None:
    class PreflightControlFlowProvider(InMemorySecretProvider):
        def __init__(self) -> None:
            super().__init__()
            self.delete_calls = 0

        def exists(self, service: str, account: str) -> bool:
            del service, account
            raise error_type("private-preflight-control-flow-sentinel")

        def delete(self, service: str, account: str) -> None:
            del service, account
            self.delete_calls += 1

    provider = PreflightControlFlowProvider()
    captured_type, rendered = _capture_boundary_error(
        lambda: probe_script.probe_keychain_round_trip(
            provider,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert captured_type is RuntimeError
    assert "Keychain probe preflight failed" in rendered
    assert "private-preflight-control-flow-sentinel" not in rendered
    assert provider.delete_calls == 0


@pytest.mark.parametrize("stage", ("get", "compare"))
def test_target_probe_translates_get_and_compare_base_exceptions_after_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    class OperationControlFlowProvider(InMemorySecretProvider):
        def __init__(self) -> None:
            super().__init__()
            self.delete_calls = 0
            self.exists_calls = 0

        def exists(self, service: str, account: str) -> bool:
            self.exists_calls += 1
            return super().exists(service, account)

        def get(self, service: str, account: str) -> bytes:
            if stage == "get":
                raise ProbeControlFlow("private-get-control-flow-sentinel")
            return super().get(service, account)

        def delete(self, service: str, account: str) -> None:
            self.delete_calls += 1
            super().delete(service, account)

    if stage == "compare":

        def interrupt_compare(left: object, right: object) -> bool:
            del left, right
            raise KeyboardInterrupt("private-compare-control-flow-sentinel")

        monkeypatch.setattr(probe_script.hmac, "compare_digest", interrupt_compare)
    provider = OperationControlFlowProvider()
    captured_type, rendered = _capture_boundary_error(
        lambda: probe_script.probe_keychain_round_trip(
            provider,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert captured_type is RuntimeError
    assert "Keychain probe operation failed" in rendered
    assert "private-" not in rendered
    assert provider.delete_calls == 1
    assert provider.exists_calls == 2
    assert not InMemorySecretProvider.exists(provider, "tuntun.probe", "slot-v1")


def test_target_probe_base_exception_delete_still_verifies_and_cleanup_takes_precedence() -> None:
    class RemovedThenInterruptedProvider(InMemorySecretProvider):
        def __init__(self) -> None:
            super().__init__()
            self.exists_calls = 0

        def exists(self, service: str, account: str) -> bool:
            self.exists_calls += 1
            return super().exists(service, account)

        def delete(self, service: str, account: str) -> None:
            super().delete(service, account)
            raise KeyboardInterrupt("private-delete-control-flow-sentinel")

    removed = RemovedThenInterruptedProvider()
    captured_type, rendered = _capture_boundary_error(
        lambda: probe_script.probe_keychain_round_trip(
            removed,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert captured_type is RuntimeError
    assert "Keychain probe cleanup failed" in rendered
    assert "private-delete-control-flow-sentinel" not in rendered
    assert removed.exists_calls == 2
    assert not InMemorySecretProvider.exists(removed, "tuntun.probe", "slot-v1")

    class StillPresentProvider(InMemorySecretProvider):
        def delete(self, service: str, account: str) -> None:
            raise KeyboardInterrupt("private-still-present-sentinel")

    present = StillPresentProvider()
    rendered = _format_runtime_error(
        lambda: probe_script.probe_keychain_round_trip(
            present,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert "Keychain probe cleanup failed" in rendered
    assert "private-still-present-sentinel" not in rendered
    assert InMemorySecretProvider.exists(present, "tuntun.probe", "slot-v1")


def test_target_probe_base_exception_final_verification_is_fixed_and_content_free() -> None:
    class VerificationInterruptedProvider(InMemorySecretProvider):
        def __init__(self) -> None:
            super().__init__()
            self.exists_calls = 0

        def exists(self, service: str, account: str) -> bool:
            self.exists_calls += 1
            if self.exists_calls > 1:
                raise KeyboardInterrupt("private-final-verification-sentinel")
            return super().exists(service, account)

    provider = VerificationInterruptedProvider()
    rendered = _format_runtime_error(
        lambda: probe_script.probe_keychain_round_trip(
            provider,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert "Keychain probe cleanup could not be verified" in rendered
    assert "private-final-verification-sentinel" not in rendered
    assert provider.exists_calls == 2
    assert not InMemorySecretProvider.exists(provider, "tuntun.probe", "slot-v1")


def test_target_probe_exists_requires_exact_bool_without_truthiness() -> None:
    effects: list[str] = []

    class TruthinessTrap:
        def __bool__(self) -> bool:
            effects.append("truthiness")
            raise RuntimeError("private-truthiness-sentinel")

    class PreflightTrapProvider(InMemorySecretProvider):
        def exists(self, service: str, account: str) -> Any:
            return TruthinessTrap()

        def delete(self, service: str, account: str) -> None:
            raise AssertionError("collision cleanup must not run")

    preflight = PreflightTrapProvider()
    rendered = _format_runtime_error(
        lambda: probe_script.probe_keychain_round_trip(
            preflight,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert "Keychain probe preflight failed" in rendered

    class FinalTrapProvider(InMemorySecretProvider):
        def __init__(self) -> None:
            super().__init__()
            self.exists_calls = 0

        def exists(self, service: str, account: str) -> Any:
            self.exists_calls += 1
            if self.exists_calls > 1:
                return TruthinessTrap()
            return False

    final = FinalTrapProvider()
    rendered += _format_runtime_error(
        lambda: probe_script.probe_keychain_round_trip(
            final,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    )
    assert "Keychain probe cleanup could not be verified" in rendered
    assert "private-truthiness-sentinel" not in rendered
    assert effects == []
    assert not InMemorySecretProvider.exists(final, "tuntun.probe", "slot-v1")


def test_target_probe_fails_closed_on_mismatch_or_unverified_cleanup() -> None:
    class MismatchProvider(InMemorySecretProvider):
        def get(self, service: str, account: str) -> bytes:
            super().get(service, account)
            return b"different"

    mismatch = MismatchProvider()
    with pytest.raises(RuntimeError, match="readback mismatch"):
        probe_script.probe_keychain_round_trip(
            mismatch,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    assert not mismatch.exists("tuntun.probe", "slot-v1")

    class FailedCleanupProvider(InMemorySecretProvider):
        def delete(self, service: str, account: str) -> None:
            return None

    failed_cleanup = FailedCleanupProvider()
    with pytest.raises(RuntimeError, match="cleanup failed"):
        probe_script.probe_keychain_round_trip(
            failed_cleanup,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )


@pytest.mark.parametrize(
    "arguments,environment_ack",
    ((["--acknowledge-keychain-write"], None), ([], "1")),
)
def test_target_probe_requires_both_acknowledgements_before_side_effects(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    environment_ack: str | None,
) -> None:
    if environment_ack is None:
        monkeypatch.delenv(probe_script.PROBE_ENVIRONMENT_ACK, raising=False)
    else:
        monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, environment_ack)
    side_effects: list[str] = []
    monkeypatch.setattr(
        probe_script,
        "MacOSKeychainSecretProvider",
        lambda: side_effects.append("provider"),
    )
    monkeypatch.setattr(
        probe_script.secrets,
        "token_bytes",
        lambda size: side_effects.append(f"bytes:{size}"),
    )
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: side_effects.append("uuid"),
    )

    assert probe_script.main(arguments) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "macOS Keychain probe: FAIL\n"
    assert side_effects == []


@pytest.mark.parametrize(
    "arguments",
    (
        ["--acknowledge-keychain-write", "--receipt", "unused.json"],
        ["--acknowledge-keychain-write", "--run-id", HOST_PROBE_RUN_ID],
        ["--acknowledge-keychain-write", "--attempt-id", HOST_PROBE_ATTEMPT_ID],
        [
            "--acknowledge-keychain-write",
            "--receipt",
            "unused.json",
            "--run-id",
            "not-a-uuid",
            "--attempt-id",
            HOST_PROBE_ATTEMPT_ID,
            "--owner-approval-commitment-sha256",
            OWNER_APPROVAL_COMMITMENT_SHA256,
        ],
        [
            "--acknowledge-keychain-write",
            "--receipt",
            "unused.json",
            "--run-id",
            HOST_PROBE_RUN_ID,
            "--attempt-id",
            HOST_PROBE_ATTEMPT_ID,
            "--owner-approval-commitment-sha256",
            "not-a-digest",
        ],
        [
            "--acknowledge-keychain-write",
            "--receipt",
            "unused.json",
            "--run-id",
            HOST_PROBE_RUN_ID,
            "--attempt-id",
            "not-an-attempt-id",
            "--owner-approval-commitment-sha256",
            OWNER_APPROVAL_COMMITMENT_SHA256,
        ],
    ),
)
def test_target_probe_requires_closed_receipt_bindings_before_side_effects(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    side_effects: list[str] = []
    monkeypatch.setattr(
        probe_script,
        "MacOSKeychainSecretProvider",
        lambda: side_effects.append("provider"),
    )
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: side_effects.append("uuid"),
    )

    assert probe_script.main(arguments) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "macOS Keychain probe: FAIL\n"
    assert side_effects == []


@pytest.mark.parametrize(
    "arguments,environment_ack",
    (
        (["--private-argument-sentinel"], None),
        (["--help", "--private-argument-sentinel"], None),
        (["--private-argument-sentinel", "--help"], None),
        (["-h", "private-positional-sentinel"], None),
        (
            [
                "--acknowledge-keychain-write",
                "--receipt",
                "/private-path-sentinel/receipt.json",
            ],
            "1",
        ),
        (
            [
                "--acknowledge-keychain-write",
                "--receipt",
                "/private-path-sentinel/receipt.json",
                "--run-id",
                "private-run-id-sentinel",
                "--attempt-id",
                HOST_PROBE_ATTEMPT_ID,
                "--owner-approval-commitment-sha256",
                OWNER_APPROVAL_COMMITMENT_SHA256,
            ],
            "1",
        ),
        (["--acknowledge-keychain-write"], None),
    ),
)
def test_target_probe_real_cli_invalid_invocations_are_content_free(
    arguments: list[str],
    environment_ack: str | None,
) -> None:
    environment = dict(os.environ)
    environment["PRIVATE_ENV_SENTINEL"] = "private-environment-value-sentinel"
    if environment_ack is None:
        environment.pop(probe_script.PROBE_ENVIRONMENT_ACK, None)
    else:
        environment[probe_script.PROBE_ENVIRONMENT_ACK] = environment_ack

    completed = subprocess.run(
        (sys.executable, str(Path(probe_script.__file__).resolve()), *arguments),
        cwd=probe_script.REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == "macOS Keychain probe: FAIL\n"
    combined = completed.stdout + completed.stderr
    for forbidden in (
        "private-argument-sentinel",
        "private-path-sentinel",
        "private-run-id-sentinel",
        "private-environment-value-sentinel",
        "Traceback",
        str(probe_script.REPOSITORY_ROOT),
    ):
        assert forbidden not in combined


def test_target_probe_real_cli_help_is_fixed_and_bounded() -> None:
    completed = subprocess.run(
        (sys.executable, str(Path(probe_script.__file__).resolve()), "--help"),
        cwd=probe_script.REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout.startswith("usage: probe_macos_keychain ")
    assert len(completed.stdout.encode("utf-8")) <= 2048
    assert str(probe_script.REPOSITORY_ROOT) not in completed.stdout


def test_target_probe_cli_emits_no_secret_or_identifier(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    provider = InMemorySecretProvider()
    sentinel = b"target-probe-secret-sentinel-32b"
    assert len(sentinel) == 32
    captured: dict[str, object] = {}
    real_probe = probe_script.probe_keychain_round_trip

    def capture_probe(
        selected_provider: InMemorySecretProvider,
        service: str,
        account: str,
        value: bytes,
    ) -> None:
        captured.update(
            provider=selected_provider,
            service=service,
            account=account,
            value=value,
        )
        real_probe(selected_provider, service, account, value)

    def token_bytes(size: int) -> bytes:
        assert size == 32
        return sentinel

    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", lambda: provider)
    monkeypatch.setattr(probe_script, "probe_keychain_round_trip", capture_probe)
    monkeypatch.setattr(probe_script.secrets, "token_bytes", token_bytes)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )
    assert probe_script.main(["--acknowledge-keychain-write"]) == 0
    output = capsys.readouterr().out
    assert output == "macOS Keychain probe: PASS\n"
    assert captured == {
        "provider": provider,
        "service": "tuntun.probe.keychain",
        "account": "round-trip-00000000-0000-4000-8000-000000000801",
        "value": sentinel,
    }
    assert sentinel.decode() not in output
    assert "00000000" not in output


def test_target_probe_cli_failure_is_content_free_and_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class PartialFailureProvider(InMemorySecretProvider):
        def set(self, service: str, account: str, value: bytes) -> None:
            super().set(service, account, value)
            raise RuntimeError(f"private-{account}-{value.decode()}-sentinel")

    provider = PartialFailureProvider()
    sentinel = b"target-probe-secret-sentinel-32b"
    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", lambda: provider)
    monkeypatch.setattr(probe_script.secrets, "token_bytes", lambda size: sentinel)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )
    assert probe_script.main(["--acknowledge-keychain-write"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "macOS Keychain probe: FAIL\n"
    assert sentinel.decode() not in output.err
    assert "00000000" not in output.err
    assert not provider.exists(
        "tuntun.probe.keychain",
        "round-trip-00000000-0000-4000-8000-000000000801",
    )


@pytest.mark.parametrize("stage", ("operation", "delete"))
def test_target_probe_cli_system_exit_zero_fails_and_proves_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stage: str,
) -> None:
    class SystemExitProvider(InMemorySecretProvider):
        def __init__(self) -> None:
            super().__init__()
            self.delete_calls = 0
            self.exists_calls = 0

        def exists(self, service: str, account: str) -> bool:
            self.exists_calls += 1
            return super().exists(service, account)

        def set(self, service: str, account: str, value: bytes) -> None:
            super().set(service, account, value)
            if stage == "operation":
                raise SystemExit(0)

        def delete(self, service: str, account: str) -> None:
            self.delete_calls += 1
            super().delete(service, account)
            if stage == "delete":
                raise SystemExit(0)

    provider = SystemExitProvider()
    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", lambda: provider)
    monkeypatch.setattr(probe_script.secrets, "token_bytes", lambda size: b"p" * size)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )
    try:
        result: int | BaseException = probe_script.main(["--acknowledge-keychain-write"])
    except BaseException as error:
        result = error
    assert result == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "macOS Keychain probe: FAIL\n"
    assert provider.delete_calls == 1
    assert provider.exists_calls == 2
    assert not InMemorySecretProvider.exists(
        provider,
        "tuntun.probe.keychain",
        "round-trip-00000000-0000-4000-8000-000000000801",
    )


@pytest.mark.parametrize(
    "stage,error",
    (
        ("provider", KeyboardInterrupt("private-provider-boundary-sentinel")),
        ("uuid", ProbeControlFlow("private-uuid-boundary-sentinel")),
        ("randomness", SystemExit(0)),
        ("probe", ProbeControlFlow("private-probe-boundary-sentinel")),
    ),
)
def test_target_probe_cli_translates_every_boundary_base_exception(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stage: str,
    error: BaseException,
) -> None:
    provider = InMemorySecretProvider()

    def raise_boundary_error(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        raise error

    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", lambda: provider)
    monkeypatch.setattr(probe_script.secrets, "token_bytes", lambda size: b"p" * size)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )
    if stage == "provider":
        monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", raise_boundary_error)
    elif stage == "uuid":
        monkeypatch.setattr(probe_script, "uuid4", raise_boundary_error)
    elif stage == "randomness":
        monkeypatch.setattr(probe_script.secrets, "token_bytes", raise_boundary_error)
    else:
        monkeypatch.setattr(probe_script, "probe_keychain_round_trip", raise_boundary_error)

    try:
        result: int | BaseException = probe_script.main(["--acknowledge-keychain-write"])
    except BaseException as caught:
        result = caught
    assert result == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "macOS Keychain probe: FAIL\n"


def test_phase1_host_probe_receipt_schema_is_closed_and_content_safe() -> None:
    schema = json.loads(probe_script.PHASE1_HOST_PROBE_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$id"] == probe_script.PHASE1_HOST_PROBE_SCHEMA_ID
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
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
    }
    for nested in ("host", "runtime", "source", "artifact_digests"):
        assert schema["properties"][nested]["additionalProperties"] is False
    assert schema["properties"]["evidence_use"] == {"const": "diagnostic_only"}
    assert schema["properties"]["recorded_at_utc"] == {
        "type": "string",
        "format": "date-time",
        "pattern": (
            r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])"
            r"T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$"
        ),
    }
    assert schema["allOf"] == [
        {
            "if": {
                "properties": {"status": {"const": "pass"}},
                "required": ["status"],
            },
            "then": {
                "properties": {"cleanup_verified": {"const": True}},
                "required": ["cleanup_verified"],
            },
        }
    ]
    rendered = json.dumps(schema, sort_keys=True)
    for forbidden in (
        "username",
        "hostname",
        "serial",
        "hardware_uuid",
        "provisioning_udid",
        "account",
        "secret",
        "environment",
        "keychain_path",
        "owner_review_ref",
        "target_id",
        "host_id",
        "public_key",
    ):
        assert forbidden not in rendered


def test_phase1_host_probe_completion_schema_is_closed_and_content_safe() -> None:
    schema = json.loads(
        probe_script.PHASE1_HOST_PROBE_COMPLETION_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    assert schema == {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": probe_script.PHASE1_HOST_PROBE_COMPLETION_SCHEMA_ID,
        "type": "object",
        "additionalProperties": False,
        "required": [
            "$schema",
            "completion_id",
            "run_id",
            "attempt_id",
            "receipt_sha256",
            "completion_binding_sha256",
            "state",
        ],
        "properties": {
            "$schema": {"const": probe_script.PHASE1_HOST_PROBE_COMPLETION_SCHEMA_ID},
            "completion_id": {"const": probe_script.PHASE1_HOST_PROBE_COMPLETION_ID},
            "run_id": {
                "type": "string",
                "pattern": (
                    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                ),
            },
            "attempt_id": {
                "type": "string",
                "pattern": (
                    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                ),
            },
            "receipt_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "completion_binding_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "state": {"const": "complete"},
        },
    }
    rendered = json.dumps(schema, sort_keys=True)
    for forbidden in (
        "username",
        "hostname",
        "serial",
        "account",
        "secret",
        "environment",
        "keychain_path",
        "target_id",
        "public_key",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    "timestamp,accepted",
    (
        ("2024-02-29T23:59:59Z", True),
        ("2023-02-29T00:00:00Z", False),
        ("2026-04-31T00:00:00Z", False),
        ("2026-13-01T00:00:00Z", False),
        ("2026-08-30T24:00:00Z", False),
        ("2026-08-30T23:59:60Z", False),
        ("2026-08-30T00:00:00+00:00", False),
    ),
)
def test_phase1_host_probe_schema_and_runtime_agree_on_canonical_rfc3339_datetime(
    timestamp: str,
    accepted: bool,
) -> None:
    schema = json.loads(probe_script.PHASE1_HOST_PROBE_SCHEMA_PATH.read_text(encoding="utf-8"))
    timestamp_schema = schema["properties"]["recorded_at_utc"]
    schema_accepts = (
        timestamp_schema.get("format") == "date-time"
        and re.fullmatch(timestamp_schema["pattern"], timestamp) is not None
    )
    if schema_accepts:
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            schema_accepts = False

    try:
        _safe_host_receipt(recorded_at_utc=timestamp)
    except RuntimeError:
        runtime_accepts = False
    else:
        runtime_accepts = True

    assert schema_accepts is accepted
    assert runtime_accepts is accepted


def test_phase1_host_probe_receipt_is_diagnostic_and_bound_to_trusted_expectations(
    tmp_path: Path,
) -> None:
    receipt = _safe_host_receipt()
    probe_script.validate_phase1_host_probe_receipt(receipt)
    receipt_path, completion_path = _write_host_probe_evidence_pair(
        tmp_path,
        receipt=receipt,
    )
    probe_script.verify_phase1_host_probe_receipt(
        receipt_path,
        completion_path,
        **_expected_host_probe_bindings(),
    )

    assert receipt == {
        "$schema": probe_script.PHASE1_HOST_PROBE_SCHEMA_ID,
        "receipt_id": "phase1.macos-keychain.host-probe.v1",
        "evidence_use": "diagnostic_only",
        "run_id": HOST_PROBE_RUN_ID,
        "attempt_id": HOST_PROBE_ATTEMPT_ID,
        "recorded_at_utc": "2026-08-30T00:00:00Z",
        "status": "pass",
        "cleanup_verified": True,
        "host": {
            "system": "Darwin",
            "machine": "arm64",
            "model_class": "Mac15,7",
            "os_product_version": "26.6.1",
            "os_build": "25G76",
        },
        "runtime": {
            "python_version": "3.12.3",
            "keyring_version": "25.7.0",
            "keyring_backend_class": "keyring.backends.macOS.Keyring",
        },
        "source": {
            "commit": "f" * 40,
            "probe_script_sha256": "a" * 64,
        },
        "artifact_digests": {},
        "owner_approval_commitment_sha256": OWNER_APPROVAL_COMMITMENT_SHA256,
        "completion_binding_sha256": COMPLETION_BINDING_SHA256,
    }
    rendered = json.dumps(receipt, sort_keys=True)
    for forbidden in (
        "private-user-sentinel",
        "private-host-sentinel",
        "private-serial-sentinel",
        "round-trip-00000000-0000-4000-8000-000000000801",
        "target-probe-secret-sentinel-32b",
        "/Users/private-user-sentinel",
        "login.keychain",
        "private-owner@example.invalid",
    ):
        assert forbidden not in rendered


def test_phase1_host_probe_acceptance_loads_exact_paths_not_parsed_objects(
    tmp_path: Path,
) -> None:
    receipt = _safe_host_receipt()
    completion = _safe_host_completion(receipt)
    receipt_path, completion_path = _write_host_probe_evidence_pair(
        tmp_path,
        receipt=receipt,
        completion=completion,
    )

    probe_script.verify_phase1_host_probe_receipt(
        receipt_path,
        completion_path,
        **_expected_host_probe_bindings(),
    )
    with pytest.raises((TypeError, RuntimeError)):
        probe_script.verify_phase1_host_probe_receipt(
            receipt,
            completion,
            **_expected_host_probe_bindings(),
        )


@pytest.mark.parametrize("artifact", ("receipt", "completion"))
def test_phase1_host_probe_acceptance_rejects_duplicate_json_keys(
    tmp_path: Path,
    artifact: str,
) -> None:
    receipt_path, completion_path = _write_host_probe_evidence_pair(tmp_path)
    selected = receipt_path if artifact == "receipt" else completion_path
    rendered = selected.read_text(encoding="utf-8")
    duplicate = '"status":"pass"' if artifact == "receipt" else '"state":"complete"'
    rendered = rendered.replace("{", "{" + duplicate + ",", 1)
    selected.write_text(rendered, encoding="utf-8")
    selected.chmod(0o600)

    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


@pytest.mark.parametrize("artifact", ("receipt", "completion"))
def test_phase1_host_probe_acceptance_rejects_oversized_artifacts(
    tmp_path: Path,
    artifact: str,
) -> None:
    receipt_path, completion_path = _write_host_probe_evidence_pair(tmp_path)
    selected = receipt_path if artifact == "receipt" else completion_path
    selected.write_bytes(b"{" + b"x" * probe_script.MAX_EVIDENCE_ARTIFACT_BYTES)
    selected.chmod(0o600)

    with pytest.raises(RuntimeError, match="invalid host probe receipt") as caught:
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )
    assert str(selected) not in str(caught.value)


@pytest.mark.parametrize("artifact", ("receipt", "completion"))
@pytest.mark.parametrize("mutation", ("mode", "hardlink", "owner", "type"))
def test_phase1_host_probe_acceptance_rejects_unsafe_artifact_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    artifact: str,
    mutation: str,
) -> None:
    receipt_path, completion_path = _write_host_probe_evidence_pair(tmp_path)
    selected = receipt_path if artifact == "receipt" else completion_path
    if mutation == "mode":
        selected.chmod(0o640)
    elif mutation == "hardlink":
        os.link(selected, tmp_path / f"private-{artifact}-hardlink")
    elif mutation == "owner":
        actual_euid = os.geteuid()
        monkeypatch.setattr(probe_script.os, "geteuid", lambda: actual_euid + 1)
    else:
        selected.unlink()
        selected.mkdir()

    with pytest.raises(RuntimeError, match="invalid host probe receipt") as caught:
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )
    assert "private-" not in str(caught.value)


@pytest.mark.parametrize("artifact", ("receipt", "completion"))
def test_phase1_host_probe_acceptance_holds_both_descriptors_against_path_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    artifact: str,
) -> None:
    receipt_path, completion_path = _write_host_probe_evidence_pair(tmp_path)
    selected = receipt_path if artifact == "receipt" else completion_path
    replacement = tmp_path / f"private-{artifact}-replacement"
    replacement.write_bytes(selected.read_bytes())
    replacement.chmod(0o600)
    real_validate = probe_script.validate_phase1_host_probe_receipt
    swapped = False

    def swap_during_validation(value: object) -> None:
        nonlocal swapped
        if not swapped:
            selected.unlink()
            replacement.rename(selected)
            swapped = True
        real_validate(value)

    monkeypatch.setattr(
        probe_script,
        "validate_phase1_host_probe_receipt",
        swap_during_validation,
    )

    with pytest.raises(RuntimeError, match="invalid host probe receipt") as caught:
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )
    assert swapped is True
    assert "private-" not in str(caught.value)


def test_phase1_host_probe_receipt_rejects_malformed_or_impossible_evidence(
    tmp_path: Path,
) -> None:
    for overrides in (
        {"system": "Linux"},
        {"machine": "x86_64"},
        {"keyring_version": ""},
        {"keyring_backend_class": ""},
        {"source_commit": "not-a-commit"},
        {"probe_script_sha256": "not-a-digest"},
        {"run_id": "not-a-run-id"},
        {"attempt_id": "not-an-attempt-id"},
        {"owner_approval_commitment_sha256": "private-owner@example.invalid"},
        {"completion_binding_sha256": "not-a-digest"},
        {"recorded_at_utc": "2026-99-99T99:99:99Z"},
    ):
        with pytest.raises(RuntimeError, match="invalid host probe receipt"):
            _safe_host_receipt(**overrides)
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        _safe_host_receipt(cleanup_verified=False)

    receipt = _safe_host_receipt()
    extra = json.loads(json.dumps(receipt))
    extra["username"] = "private-user-sentinel"
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.validate_phase1_host_probe_receipt(extra)

    fail_without_cleanup = json.loads(json.dumps(receipt))
    fail_without_cleanup["status"] = "fail"
    fail_without_cleanup["cleanup_verified"] = False
    probe_script.validate_phase1_host_probe_receipt(fail_without_cleanup)
    receipt_path, completion_path = _write_host_probe_evidence_pair(
        tmp_path,
        receipt=fail_without_cleanup,
    )
    with pytest.raises(RuntimeError, match="host probe receipt did not pass"):
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


@pytest.mark.parametrize(
    "changed",
    (
        {"expected_run_id": OTHER_HOST_PROBE_RUN_ID},
        {"expected_attempt_id": OTHER_HOST_PROBE_ATTEMPT_ID},
        {"expected_owner_approval_commitment_sha256": "d" * 64},
        {"expected_source_commit": "e" * 40},
        {"expected_probe_script_sha256": "b" * 64},
    ),
)
def test_phase1_host_probe_verifier_requires_every_trusted_binding(
    changed: dict[str, str],
    tmp_path: Path,
) -> None:
    expected = _expected_host_probe_bindings()
    expected.update(changed)
    receipt_path, completion_path = _write_host_probe_evidence_pair(tmp_path)
    with pytest.raises(RuntimeError, match="host probe receipt binding mismatch"):
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **expected,
        )


def _git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        (probe_script.SYSTEM_GIT, "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
    )


def _committed_probe_repository(root: Path) -> Path:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Host Probe Tests")
    _git(root, "config", "user.email", "host-probe@example.invalid")
    script = root / "scripts" / "probe_macos_keychain.py"
    script.parent.mkdir()
    script.write_text("print('content-safe')\n", encoding="utf-8")
    (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "fixture")
    return root


@pytest.mark.parametrize(
    "flag_arguments",
    (
        ("--assume-unchanged", "tracked.txt"),
        ("--skip-worktree", "tracked.txt"),
    ),
)
def test_source_snapshot_rejects_every_nondefault_root_index_flag_without_path_leak(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    flag_arguments: tuple[str, str],
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-source-sentinel")
    _git(repository, "update-index", *flag_arguments)
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-source-sentinel" not in str(caught.value)
    assert "tracked.txt" not in str(caught.value)


@pytest.mark.parametrize("tag", (b"h", b"S", b"s", b"M", b"R", b"C", b"K"))
def test_source_snapshot_index_inventory_rejects_every_nondefault_tag(tag: bytes) -> None:
    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable"):
        probe_script._default_index_records(tag + b" private-path-sentinel\0")


@pytest.mark.parametrize("flag", ("--assume-unchanged", "--skip-worktree"))
def test_source_snapshot_rejects_nondefault_index_flags_in_initialized_submodule(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    flag: str,
) -> None:
    submodule = _committed_probe_repository(tmp_path / "private-submodule-origin")
    repository = _committed_probe_repository(tmp_path / "private-source-root")
    _git(
        repository,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        str(submodule),
        "vendor/private-submodule-sentinel",
    )
    _git(repository, "commit", "-qam", "add submodule")
    initialized = repository / "vendor" / "private-submodule-sentinel"
    _git(initialized, "update-index", flag, "tracked.txt")
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-submodule-sentinel" not in str(caught.value)
    assert "tracked.txt" not in str(caught.value)


def test_source_snapshot_recursively_rejects_nondefault_index_flag_in_nested_submodule(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    leaf = _committed_probe_repository(tmp_path / "private-leaf-origin")
    middle = _committed_probe_repository(tmp_path / "private-middle-origin")
    _git(
        middle,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        str(leaf),
        "deps/private-leaf-sentinel",
    )
    _git(middle, "commit", "-qam", "add leaf")
    repository = _committed_probe_repository(tmp_path / "private-source-root")
    _git(
        repository,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        str(middle),
        "vendor/private-middle-sentinel",
    )
    _git(repository, "commit", "-qam", "add middle")
    _git(
        repository,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "update",
        "--init",
        "--recursive",
    )
    nested = repository / "vendor/private-middle-sentinel/deps/private-leaf-sentinel"
    _git(nested, "update-index", "--assume-unchanged", "tracked.txt")
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-middle-sentinel" not in str(caught.value)
    assert "private-leaf-sentinel" not in str(caught.value)
    assert "tracked.txt" not in str(caught.value)


def test_source_snapshot_is_bounded_and_ignores_caller_working_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _committed_probe_repository(tmp_path / "source")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda self: pytest.fail("source proof must use a bounded stable descriptor read"),
    )

    snapshot = probe_script._capture_source_snapshot()

    assert snapshot.commit == _git(repository, "rev-parse", "HEAD").stdout.decode().strip()
    assert snapshot.probe_script_sha256 == hashlib.sha256(b"print('content-safe')\n").hexdigest()
    assert len(snapshot.repository_state_sha256) == 64


def test_source_snapshot_hashes_bytes_despite_restored_git_stat_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-stat-source")
    tracked = repository / "tracked.txt"
    stable_time_ns = 1_600_000_000_000_000_000
    os.utime(tracked, ns=(stable_time_ns, stable_time_ns))
    _git(repository, "config", "core.trustctime", "false")
    _git(repository, "config", "core.checkStat", "minimal")
    _git(repository, "update-index", "--refresh")
    original = tracked.stat()
    tracked.write_bytes(b"mutated\n")
    os.utime(tracked, ns=(original.st_atime_ns, original.st_mtime_ns))
    assert _git(repository, "status", "--porcelain=v1").stdout == b""
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-stat-source" not in str(caught.value)
    assert "tracked.txt" not in str(caught.value)


def test_source_snapshot_checks_executable_mode_when_git_filemode_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-mode-source")
    tracked = repository / "tracked.txt"
    _git(repository, "config", "core.fileMode", "false")
    tracked.chmod(0o755)
    assert _git(repository, "status", "--porcelain=v1").stdout == b""
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-mode-source" not in str(caught.value)
    assert "tracked.txt" not in str(caught.value)


@pytest.mark.parametrize(
    "mutation",
    ("filter_config", "info_attributes", "tracked_attributes"),
)
def test_source_snapshot_rejects_local_filters_and_attributes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-filter-source")
    if mutation == "filter_config":
        _git(repository, "config", "filter.private.clean", "cat")
        _git(repository, "config", "filter.private.smudge", "cat")
    elif mutation == "info_attributes":
        attributes = repository / ".git" / "info" / "attributes"
        attributes.write_text("*.txt filter=private\n", encoding="utf-8")
    else:
        (repository / ".gitattributes").write_text(
            "*.txt filter=private\n",
            encoding="utf-8",
        )
        _git(repository, "add", ".gitattributes")
        _git(repository, "commit", "-qm", "add attributes")
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-filter-source" not in str(caught.value)
    assert "filter.private" not in str(caught.value)


def test_source_snapshot_rejects_symlinked_repository_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-real-source")
    linked_root = tmp_path / "private-linked-source"
    linked_root.symlink_to(repository, target_is_directory=True)
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", linked_root)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-real-source" not in str(caught.value)
    assert "private-linked-source" not in str(caught.value)


def test_source_snapshot_rejects_hardlinked_tracked_file_even_when_bytes_match(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-hardlink-source")
    tracked = repository / "tracked.txt"
    alternate = tmp_path / "private-hardlink-target"
    alternate.write_bytes(tracked.read_bytes())
    tracked.unlink()
    os.link(alternate, tracked)
    assert _git(repository, "status", "--porcelain=v1").stdout == b""
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-hardlink-source" not in str(caught.value)
    assert "private-hardlink-target" not in str(caught.value)


def test_source_snapshot_hashes_symlink_target_despite_restored_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-symlink-source")
    tracked_link = repository / "tracked-link"
    tracked_link.symlink_to("target-one")
    _git(repository, "add", "tracked-link")
    _git(repository, "commit", "-qm", "add symlink")
    stable_time_ns = 1_600_000_000_000_000_000
    os.utime(
        tracked_link,
        ns=(stable_time_ns, stable_time_ns),
        follow_symlinks=False,
    )
    _git(repository, "config", "core.trustctime", "false")
    _git(repository, "config", "core.checkStat", "minimal")
    _git(repository, "update-index", "--refresh")
    original = tracked_link.lstat()
    tracked_link.unlink()
    tracked_link.symlink_to("target-two")
    os.utime(
        tracked_link,
        ns=(original.st_atime_ns, original.st_mtime_ns),
        follow_symlinks=False,
    )
    assert _git(repository, "status", "--porcelain=v1").stdout == b""
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-symlink-source" not in str(caught.value)
    assert "tracked-link" not in str(caught.value)


def test_source_snapshot_rejects_submodule_root_swap_during_verification(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    origin = _committed_probe_repository(tmp_path / "private-submodule-origin")
    repository = _committed_probe_repository(tmp_path / "private-submodule-parent")
    _git(
        repository,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        str(origin),
        "vendor/private-submodule-path",
    )
    _git(repository, "commit", "-qam", "add submodule")
    child = repository / "vendor" / "private-submodule-path"
    replacement = tmp_path / "private-submodule-replacement"
    subprocess.run(
        (
            probe_script.SYSTEM_GIT,
            "-c",
            "protocol.file.allow=always",
            "clone",
            "-q",
            str(origin),
            str(replacement),
        ),
        check=True,
        capture_output=True,
    )
    retired = tmp_path / "private-submodule-retired"
    real_command = probe_script._run_content_safe_command_bytes
    swapped = False

    def swap_before_child_command(
        arguments: tuple[str, ...],
        **keywords: object,
    ) -> bytes:
        nonlocal swapped
        cwd_descriptor = keywords.get("cwd_descriptor")
        descriptor_matches_child = isinstance(cwd_descriptor, int) and (
            os.fstat(cwd_descriptor).st_dev,
            os.fstat(cwd_descriptor).st_ino,
        ) == (child.lstat().st_dev, child.lstat().st_ino)
        if not swapped and descriptor_matches_child:
            child.rename(retired)
            replacement.rename(child)
            swapped = True
        return real_command(arguments, **keywords)  # type: ignore[arg-type]

    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(
        probe_script,
        "_run_content_safe_command_bytes",
        swap_before_child_command,
    )

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert swapped is True
    assert "private-submodule" not in str(caught.value)
    shutil.rmtree(retired)


def test_source_snapshot_git_commands_remain_bound_to_retained_root_during_aba_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-source-root")
    original_commit = _git(repository, "rev-parse", "HEAD").stdout.decode().strip()
    replacement = tmp_path / "private-source-replacement"
    subprocess.run(
        (probe_script.SYSTEM_GIT, "clone", "-q", str(repository), str(replacement)),
        check=True,
        capture_output=True,
    )
    _git(replacement, "config", "user.name", "Host Probe Tests")
    _git(replacement, "config", "user.email", "host-probe@example.invalid")
    _git(replacement, "commit", "--allow-empty", "-qm", "alternate equivalent source")
    replacement_commit = _git(replacement, "rev-parse", "HEAD").stdout.decode().strip()
    assert replacement_commit != original_commit
    retired = tmp_path / "private-source-retired"
    real_command = probe_script._run_content_safe_command_bytes
    swaps = 0

    def aba_swap_around_git_command(
        arguments: tuple[str, ...],
        **keywords: object,
    ) -> bytes:
        nonlocal swaps
        repository.rename(retired)
        replacement.rename(repository)
        swaps += 1
        try:
            return real_command(arguments, **keywords)  # type: ignore[arg-type]
        finally:
            repository.rename(replacement)
            retired.rename(repository)

    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(
        probe_script,
        "_run_content_safe_command_bytes",
        aba_swap_around_git_command,
    )

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert swaps > 0
    assert "private-source" not in str(caught.value)


def test_source_snapshot_git_processes_use_isolated_descriptor_exec_helper(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _committed_probe_repository(tmp_path / "repository")
    real_popen = probe_script.subprocess.Popen
    launches: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def observe_launch(
        arguments: tuple[str, ...],
        **keywords: object,
    ) -> subprocess.Popen[bytes]:
        launches.append((arguments, keywords))
        return real_popen(arguments, **keywords)  # type: ignore[arg-type]

    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(probe_script.subprocess, "Popen", observe_launch)

    probe_script._capture_source_snapshot()

    assert launches
    for arguments, keywords in launches:
        assert arguments[:5] == (
            str(Path(sys.executable).resolve(strict=True)),
            "-I",
            "-S",
            "-c",
            probe_script._GIT_DESCRIPTOR_EXEC_SOURCE,
        )
        assert arguments[5].isdigit()
        assert keywords["cwd"] is None
        assert keywords["pass_fds"] == (int(arguments[5]),)
        assert keywords["close_fds"] is True
        assert "preexec_fn" not in keywords
        assert "shell" not in keywords
        assert keywords["env"] == {
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
        }


def test_source_snapshot_rejects_dirty_index_hidden_by_git_replacement_ref(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-replacement-ref")
    tracked = repository / "tracked.txt"
    tracked.write_text("changed but replacement-hidden\n")
    _git(repository, "add", "tracked.txt")
    tree = _git(repository, "write-tree").stdout.decode().strip()
    replacement_commit = _git(repository, "commit-tree", tree, "-m", "replacement").stdout
    original_commit = _git(repository, "rev-parse", "HEAD").stdout
    _git(
        repository,
        "replace",
        original_commit.decode().strip(),
        replacement_commit.decode().strip(),
    )
    assert _git(repository, "status", "--porcelain=v1").stdout == b""
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)

    with pytest.raises(RuntimeError, match="content-safe source metadata unavailable") as caught:
        probe_script._capture_source_snapshot()
    assert "private-replacement-ref" not in str(caught.value)


def test_target_probe_cli_writes_atomic_pass_receipt_without_extra_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    provider = InMemorySecretProvider()
    receipt_path = tmp_path / "receipt.json"
    snapshots = iter((_safe_source_snapshot(), _safe_source_snapshot()))

    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", lambda: provider)
    monkeypatch.setattr(
        probe_script,
        "_capture_content_safe_host_context",
        lambda selected_provider: _safe_host_receipt_context(),
    )
    monkeypatch.setattr(probe_script, "_capture_source_snapshot", lambda: next(snapshots))
    monkeypatch.setattr(
        probe_script,
        "_new_completion_binding_sha256",
        lambda: COMPLETION_BINDING_SHA256,
    )
    monkeypatch.setattr(probe_script, "_utc_now", lambda: "2026-08-30T00:00:00Z")
    monkeypatch.setattr(probe_script.secrets, "token_bytes", lambda size: b"p" * size)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )
    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 0
    output = capsys.readouterr()
    assert output.out == "macOS Keychain probe: PASS\n"
    assert output.err == ""
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    probe_script.validate_phase1_host_probe_receipt(receipt)
    probe_script.verify_phase1_host_probe_receipt(
        receipt_path,
        completion_path,
        **_expected_host_probe_bindings(),
    )
    assert receipt["status"] == "pass"
    assert receipt["cleanup_verified"] is True
    assert receipt_path.stat().st_mode & 0o777 == 0o600
    assert completion_path.stat().st_mode & 0o777 == 0o600
    assert tuple(tmp_path.glob(".receipt.json.*.tmp")) == ()
    rendered = json.dumps(receipt, sort_keys=True)
    assert "round-trip-00000000-0000-4000-8000-000000000801" not in rendered
    assert "pppp" not in rendered


def test_target_probe_cli_writes_fail_receipt_when_cleanup_is_not_verified(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FailedCleanupProvider(InMemorySecretProvider):
        def delete(self, service: str, account: str) -> None:
            return None

    provider = FailedCleanupProvider()
    receipt_path = tmp_path / "cleanup-failure.json"
    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", lambda: provider)
    monkeypatch.setattr(
        probe_script,
        "_capture_content_safe_host_context",
        lambda selected_provider: _safe_host_receipt_context(),
    )
    snapshots = iter((_safe_source_snapshot(), _safe_source_snapshot()))
    monkeypatch.setattr(probe_script, "_capture_source_snapshot", lambda: next(snapshots))
    monkeypatch.setattr(
        probe_script,
        "_new_completion_binding_sha256",
        lambda: COMPLETION_BINDING_SHA256,
    )
    monkeypatch.setattr(probe_script, "_utc_now", lambda: "2026-08-30T00:00:00Z")
    monkeypatch.setattr(probe_script.secrets, "token_bytes", lambda size: b"q" * size)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "macOS Keychain probe: FAIL\n"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    probe_script.validate_phase1_host_probe_receipt(receipt)
    assert receipt["status"] == "fail"
    assert receipt["cleanup_verified"] is False
    rendered = json.dumps(receipt, sort_keys=True)
    assert "round-trip-00000000-0000-4000-8000-000000000801" not in rendered
    assert "qqqq" not in rendered
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    with pytest.raises(RuntimeError, match="host probe receipt did not pass"):
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


def test_target_probe_cli_rejects_preexisting_receipt_before_keychain_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt_path = tmp_path / "receipt.json"
    old_receipt = _safe_host_receipt(run_id=OTHER_HOST_PROBE_RUN_ID)
    original = json.dumps(old_receipt, sort_keys=True).encode()
    receipt_path.write_bytes(original)
    receipt_path.chmod(0o600)
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    completion_path.write_text(
        json.dumps(_safe_host_completion(old_receipt)),
        encoding="utf-8",
    )
    completion_path.chmod(0o600)
    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(
        probe_script,
        "MacOSKeychainSecretProvider",
        lambda: pytest.fail("Keychain must not be opened for an occupied receipt path"),
    )

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "macOS Keychain probe: FAIL\n"
    assert receipt_path.read_bytes() == original
    with pytest.raises(RuntimeError, match="host probe receipt binding mismatch"):
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


def _configure_receipt_probe(
    monkeypatch: pytest.MonkeyPatch,
    provider: InMemorySecretProvider,
    snapshots: tuple[object, object],
) -> None:
    selected = iter(snapshots)
    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", lambda: provider)
    monkeypatch.setattr(
        probe_script,
        "_capture_content_safe_host_context",
        lambda selected_provider: _safe_host_receipt_context(),
    )
    monkeypatch.setattr(probe_script, "_capture_source_snapshot", lambda: next(selected))
    monkeypatch.setattr(
        probe_script,
        "_new_completion_binding_sha256",
        lambda: COMPLETION_BINDING_SHA256,
    )
    monkeypatch.setattr(probe_script, "_utc_now", lambda: "2026-08-30T00:00:00Z")
    monkeypatch.setattr(probe_script.secrets, "token_bytes", lambda size: b"r" * size)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )


@pytest.mark.parametrize(
    "mutation",
    (
        {"repository_state_sha256": "e" * 64},
        {"commit": "e" * 40},
        {"probe_script_sha256": "e" * 64},
        {"repository_state_sha256": "9" * 64},
    ),
    ids=("dirty", "head", "probe_script", "submodule"),
)
def test_source_is_resnapshotted_after_keychain_cleanup_and_concurrent_change_blocks_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: dict[str, str],
) -> None:
    provider = InMemorySecretProvider()
    initial = _safe_source_snapshot()
    changed = _safe_source_snapshot(**mutation)
    receipt_path = tmp_path / "receipt.json"
    calls = 0

    def resnapshot() -> object:
        nonlocal calls
        calls += 1
        if calls == 2:
            assert not provider.exists(
                probe_script.PROBE_SERVICE,
                "round-trip-00000000-0000-4000-8000-000000000801",
            )
            return changed
        return initial

    _configure_receipt_probe(monkeypatch, provider, (initial, changed))
    monkeypatch.setattr(probe_script, "_capture_source_snapshot", resnapshot)

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert calls == 2
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.validate_phase1_host_probe_receipt(
            json.loads(receipt_path.read_text(encoding="utf-8"))
        )
    assert not probe_script.phase1_host_probe_completion_path(receipt_path).exists()


@pytest.mark.parametrize("mutation", ("dirty", "head", "probe_script", "submodule"))
def test_real_concurrent_source_mutation_after_cleanup_blocks_receipt_without_path_leak(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    repository = _committed_probe_repository(tmp_path / "private-source-root")
    initialized_submodule: Path | None = None
    if mutation == "submodule":
        origin = _committed_probe_repository(tmp_path / "private-submodule-origin")
        _git(
            repository,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(origin),
            "vendor/private-submodule-sentinel",
        )
        _git(repository, "commit", "-qam", "add submodule")
        initialized_submodule = repository / "vendor" / "private-submodule-sentinel"

    provider = InMemorySecretProvider()
    receipt_path = tmp_path / "receipt.json"
    real_probe = probe_script.probe_keychain_round_trip

    def mutate_after_cleanup(
        selected_provider: InMemorySecretProvider,
        service: str,
        account: str,
        value: bytes,
    ) -> None:
        real_probe(selected_provider, service, account, value)
        assert not selected_provider.exists(service, account)
        if mutation == "dirty":
            (repository / "private-untracked-sentinel").write_text("changed\n")
        elif mutation == "head":
            (repository / "tracked.txt").write_text("new committed source\n")
            _git(repository, "add", "tracked.txt")
            _git(repository, "commit", "-qm", "concurrent source commit")
        elif mutation == "probe_script":
            (repository / "scripts" / "probe_macos_keychain.py").write_text(
                "print('concurrent script mutation')\n"
            )
        else:
            assert initialized_submodule is not None
            (initialized_submodule / "tracked.txt").write_text("submodule changed\n")

    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", lambda: provider)
    monkeypatch.setattr(
        probe_script,
        "_capture_content_safe_host_context",
        lambda selected_provider: _safe_host_receipt_context(),
    )
    monkeypatch.setattr(probe_script, "probe_keychain_round_trip", mutate_after_cleanup)
    monkeypatch.setattr(
        probe_script,
        "_new_completion_binding_sha256",
        lambda: COMPLETION_BINDING_SHA256,
    )
    monkeypatch.setattr(probe_script.secrets, "token_bytes", lambda size: b"r" * size)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "macOS Keychain probe: FAIL\n"
    with pytest.raises(RuntimeError, match="invalid host probe receipt") as caught:
        probe_script.validate_phase1_host_probe_receipt(
            json.loads(receipt_path.read_text(encoding="utf-8"))
        )
    assert "private-source-root" not in str(caught.value)
    assert "private-submodule-sentinel" not in str(caught.value)
    assert not probe_script.phase1_host_probe_completion_path(receipt_path).exists()


def test_competing_matching_pass_cannot_replace_winning_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    real_stage = probe_script._stage_claimed_receipt
    competing_bytes: bytes | None = None

    def insert_competing_pass(claim: object, receipt: dict[str, object]) -> None:
        nonlocal competing_bytes
        competing_bytes = json.dumps(receipt).encode("utf-8")
        receipt_path.unlink()
        receipt_path.write_bytes(competing_bytes)
        receipt_path.chmod(0o600)
        real_stage(claim, receipt)

    monkeypatch.setattr(probe_script, "_stage_claimed_receipt", insert_competing_pass)

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert competing_bytes is not None
    assert receipt_path.read_bytes() == competing_bytes
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    assert not completion_path.exists()
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


def test_competing_completion_is_not_unlinked_when_exclusive_publication_loses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    real_completion_operation = probe_script._completion_stage_operation
    competing_completion = b'{"state":"foreign"}\n'

    def lose_exclusive_link(stage: str, *arguments: object) -> None:
        if stage == "link":
            completion_path.write_bytes(competing_completion)
        real_completion_operation(stage, *arguments)

    monkeypatch.setattr(
        probe_script,
        "_completion_stage_operation",
        lose_exclusive_link,
    )

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert completion_path.read_bytes() == competing_completion
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.validate_phase1_host_probe_receipt(
            json.loads(receipt_path.read_text(encoding="utf-8"))
        )


def test_matching_completion_swap_before_final_acceptance_cannot_win_invocation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    real_verify = probe_script.verify_phase1_host_probe_receipt
    foreign_completion: bytes | None = None

    def swap_matching_completion_before_acceptance(*args: object, **kwargs: object) -> None:
        nonlocal foreign_completion
        foreign_completion = completion_path.read_bytes()
        completion_path.unlink()
        completion_path.write_bytes(foreign_completion)
        completion_path.chmod(0o600)
        real_verify(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        probe_script,
        "verify_phase1_host_probe_receipt",
        swap_matching_completion_before_acceptance,
    )

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert foreign_completion is not None
    assert completion_path.read_bytes() == foreign_completion
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        real_verify(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


def test_matching_receipt_swap_before_final_acceptance_retires_owned_completion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    real_verify = probe_script.verify_phase1_host_probe_receipt
    foreign_receipt: bytes | None = None

    def swap_matching_receipt_before_acceptance(*args: object, **kwargs: object) -> None:
        nonlocal foreign_receipt
        foreign_receipt = receipt_path.read_bytes()
        receipt_path.unlink()
        receipt_path.write_bytes(foreign_receipt)
        receipt_path.chmod(0o600)
        real_verify(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        probe_script,
        "verify_phase1_host_probe_receipt",
        swap_matching_receipt_before_acceptance,
    )

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert foreign_receipt is not None
    assert receipt_path.read_bytes() == foreign_receipt
    assert not completion_path.exists()
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        real_verify(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


def test_matching_pair_swap_before_final_acceptance_cannot_leave_accepted_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    real_verify = probe_script.verify_phase1_host_probe_receipt
    foreign_receipt: bytes | None = None
    foreign_completion: bytes | None = None

    def swap_matching_pair_before_acceptance(*args: object, **kwargs: object) -> None:
        nonlocal foreign_receipt, foreign_completion
        foreign_receipt = receipt_path.read_bytes()
        foreign_completion = completion_path.read_bytes()
        receipt_path.unlink()
        completion_path.unlink()
        receipt_path.write_bytes(foreign_receipt)
        completion_path.write_bytes(foreign_completion)
        receipt_path.chmod(0o600)
        completion_path.chmod(0o600)
        real_verify(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        probe_script,
        "verify_phase1_host_probe_receipt",
        swap_matching_pair_before_acceptance,
    )

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert foreign_receipt is not None
    assert foreign_completion is not None
    assert receipt_path.read_bytes() == foreign_receipt
    assert completion_path.read_bytes() == b""
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        real_verify(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


def test_matching_pair_swap_with_completion_truncate_failure_still_rejects_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    real_verify = probe_script.verify_phase1_host_probe_receipt
    real_ftruncate = probe_script.os.ftruncate
    swapped = False

    def swap_matching_pair_before_acceptance(*args: object, **kwargs: object) -> None:
        nonlocal swapped
        receipt = receipt_path.read_bytes()
        completion = completion_path.read_bytes()
        receipt_path.unlink()
        completion_path.unlink()
        receipt_path.write_bytes(receipt)
        completion_path.write_bytes(completion)
        receipt_path.chmod(0o600)
        completion_path.chmod(0o600)
        swapped = True
        real_verify(*args, **kwargs)  # type: ignore[arg-type]

    def fail_completion_truncate(descriptor: int, length: int) -> None:
        if swapped:
            raise OSError
        real_ftruncate(descriptor, length)

    monkeypatch.setattr(
        probe_script,
        "verify_phase1_host_probe_receipt",
        swap_matching_pair_before_acceptance,
    )
    monkeypatch.setattr(probe_script.os, "ftruncate", fail_completion_truncate)

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        real_verify(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


@pytest.mark.parametrize(
    "stage",
    ("truncate", "write", "file_fsync", "directory_fsync"),
)
def test_receipt_metadata_is_revalidated_at_every_publication_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stage: str,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    real_operation = probe_script._receipt_stage_operation
    mutated = False

    def mutate_mode_after_stage(selected: str, *arguments: object) -> None:
        nonlocal mutated
        real_operation(selected, *arguments)
        if selected == stage and not mutated:
            receipt_path.chmod(0o640)
            mutated = True

    monkeypatch.setattr(
        probe_script,
        "_receipt_stage_operation",
        mutate_mode_after_stage,
    )

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert mutated is True
    assert not probe_script.phase1_host_probe_completion_path(receipt_path).exists()


@pytest.mark.parametrize("mutation", ("mode", "hardlink"))
def test_completion_commit_revalidates_exact_artifact_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    real_operation = probe_script._completion_stage_operation
    mutated = False

    def mutate_after_commit(stage: str, *arguments: object) -> None:
        nonlocal mutated
        real_operation(stage, *arguments)
        if stage == "directory_fsync" and not mutated:
            if mutation == "mode":
                completion_path.chmod(0o640)
            else:
                os.link(completion_path, tmp_path / "private-completion-hardlink")
            mutated = True

    monkeypatch.setattr(
        probe_script,
        "_completion_stage_operation",
        mutate_after_commit,
    )

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert mutated is True
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.verify_phase1_host_probe_receipt(
            receipt_path,
            completion_path,
            **_expected_host_probe_bindings(),
        )


def test_receipt_claim_rejects_euid_mismatch_before_keychain_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    provider_opened = False
    actual_euid = os.geteuid()
    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script.os, "geteuid", lambda: actual_euid + 1)
    monkeypatch.setattr(
        probe_script,
        "_capture_source_snapshot",
        lambda: _safe_source_snapshot(),
    )

    def open_provider() -> InMemorySecretProvider:
        nonlocal provider_opened
        provider_opened = True
        return InMemorySecretProvider()

    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", open_provider)

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert provider_opened is False


@pytest.mark.parametrize(
    "operation",
    (
        "truncate",
        "write",
        "file_fsync",
        "path_recheck",
        "directory_fsync",
        "completion",
        "completion_write",
        "completion_file_fsync",
        "completion_link",
        "completion_directory_fsync",
    ),
)
def test_interruption_at_each_publication_stage_leaves_fail_closed_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operation: str,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    if operation == "completion":
        monkeypatch.setattr(
            probe_script,
            "_publish_completion_record",
            lambda *args: (_ for _ in ()).throw(ProbeControlFlow()),
        )
    elif operation.startswith("completion_"):
        real_completion_operation = probe_script._completion_stage_operation
        selected_operation = operation.removeprefix("completion_")
        monkeypatch.setattr(
            probe_script,
            "_completion_stage_operation",
            lambda selected, *args: (
                (_ for _ in ()).throw(ProbeControlFlow())
                if selected == selected_operation
                else real_completion_operation(selected, *args)
            ),
        )
    else:
        real_stage = probe_script._stage_claimed_receipt
        real_operation = probe_script._receipt_stage_operation

        def interrupted_stage(claim: object, receipt: dict[str, object]) -> None:
            monkeypatch.setattr(
                probe_script,
                "_receipt_stage_operation",
                lambda selected, *args: (
                    (_ for _ in ()).throw(ProbeControlFlow())
                    if selected == operation
                    else real_operation(selected, *args)
                ),
            )
            real_stage(claim, receipt)

        monkeypatch.setattr(probe_script, "_stage_claimed_receipt", interrupted_stage)

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.validate_phase1_host_probe_receipt(
            json.loads(receipt_path.read_text(encoding="utf-8"))
        )
    assert not probe_script.phase1_host_probe_completion_path(receipt_path).exists()


def test_failed_attempt_claim_blocks_same_run_retry_before_keychain_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    monkeypatch.setattr(
        probe_script,
        "_publish_completion_record",
        lambda *args: (_ for _ in ()).throw(OSError("synthetic publication failure")),
    )
    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    claimed = receipt_path.read_bytes()

    monkeypatch.setattr(
        probe_script,
        "MacOSKeychainSecretProvider",
        lambda: pytest.fail("same-run retry must stop at the occupied claim"),
    )
    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    assert receipt_path.read_bytes() == claimed


def test_completion_binding_rejects_missing_forged_or_mismatched_completion(
    tmp_path: Path,
) -> None:
    receipt = _safe_host_receipt()
    expected = _expected_host_probe_bindings()
    for index, completion in enumerate(
        (
            None,
            _safe_host_completion(receipt, receipt_sha256="e" * 64),
            _safe_host_completion(receipt, attempt_id=OTHER_HOST_PROBE_ATTEMPT_ID),
            _safe_host_completion(receipt, completion_binding_sha256="e" * 64),
            {**_safe_host_completion(receipt), "extra": "not-closed"},
        )
    ):
        root = tmp_path / str(index)
        root.mkdir()
        receipt_path = root / "receipt.json"
        completion_path = probe_script.phase1_host_probe_completion_path(receipt_path)
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        receipt_path.chmod(0o600)
        if completion is not None:
            completion_path.write_text(json.dumps(completion), encoding="utf-8")
            completion_path.chmod(0o600)
        with pytest.raises(RuntimeError):
            probe_script.verify_phase1_host_probe_receipt(
                receipt_path,
                completion_path,
                **expected,
            )


def test_completion_publication_fsync_rollback_failure_still_cannot_accept_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    provider = InMemorySecretProvider()
    _configure_receipt_probe(
        monkeypatch,
        provider,
        (_safe_source_snapshot(), _safe_source_snapshot()),
    )
    calls = 0
    real_fsync_directory = probe_script._fsync_directory

    def fail_completion_fsync(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls >= 3:
            raise OSError("synthetic completion directory fsync failure")
        real_fsync_directory(path)

    monkeypatch.setattr(probe_script, "_fsync_directory", fail_completion_fsync)

    assert probe_script.main(_receipt_cli_arguments(receipt_path)) == 1
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.validate_phase1_host_probe_receipt(
            json.loads(receipt_path.read_text(encoding="utf-8"))
        )
    assert not probe_script.phase1_host_probe_completion_path(receipt_path).exists()
