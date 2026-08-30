from __future__ import annotations

import base64
import builtins
import json
import traceback
from collections.abc import Callable
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
    arguments: list[str],
    environment_ack: str | None,
) -> None:
    if environment_ack is None:
        monkeypatch.delenv(probe_script.PROBE_ENVIRONMENT_ACK, raising=False)
    else:
        monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, environment_ack)
    monkeypatch.setattr(
        probe_script,
        "MacOSKeychainSecretProvider",
        lambda: pytest.fail("provider must not be constructed"),
    )
    monkeypatch.setattr(
        probe_script.secrets,
        "token_bytes",
        lambda size: pytest.fail(f"must not generate {size} bytes"),
    )
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: pytest.fail("must not generate a UUID"),
    )
    with pytest.raises(RuntimeError, match="dual acknowledgement"):
        probe_script.main(arguments)


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
        "recorded_at_utc",
        "status",
        "cleanup_verified",
        "host",
        "runtime",
        "source",
        "artifact_digests",
        "owner_review_ref",
    }
    for nested in ("host", "runtime", "source", "artifact_digests"):
        assert schema["properties"][nested]["additionalProperties"] is False
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
    ):
        assert forbidden not in rendered


def test_phase1_host_probe_receipt_is_bound_to_safe_darwin_arm64_metadata() -> None:
    receipt = probe_script.build_phase1_host_probe_receipt(
        status="pass",
        cleanup_verified=True,
        owner_review_ref="owner-approved-baseline-selection",
        recorded_at_utc="2026-08-30T00:00:00Z",
        **_safe_host_receipt_context(),
    )
    probe_script.validate_phase1_host_probe_receipt(
        receipt,
        expected_source_commit="f" * 40,
        expected_probe_script_sha256="a" * 64,
    )

    assert receipt == {
        "$schema": probe_script.PHASE1_HOST_PROBE_SCHEMA_ID,
        "receipt_id": "phase1.macos-keychain.host-probe.v1",
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
        "owner_review_ref": "owner-approved-baseline-selection",
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
    ):
        assert forbidden not in rendered


def test_phase1_host_probe_receipt_rejects_wrong_or_stale_evidence() -> None:
    receipt = probe_script.build_phase1_host_probe_receipt(
        status="pass",
        cleanup_verified=True,
        owner_review_ref="owner-approved-baseline-selection",
        recorded_at_utc="2026-08-30T00:00:00Z",
        **_safe_host_receipt_context(),
    )

    for overrides in (
        {"system": "Linux"},
        {"machine": "x86_64"},
        {"keyring_version": ""},
        {"keyring_backend_class": ""},
        {"source_commit": "not-a-commit"},
        {"probe_script_sha256": "not-a-digest"},
    ):
        with pytest.raises(RuntimeError, match="invalid host probe receipt"):
            probe_script.build_phase1_host_probe_receipt(
                status="pass",
                cleanup_verified=True,
                owner_review_ref="owner-approved-baseline-selection",
                recorded_at_utc="2026-08-30T00:00:00Z",
                **_safe_host_receipt_context(**overrides),
            )
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.build_phase1_host_probe_receipt(
            status="pass",
            cleanup_verified=False,
            owner_review_ref="owner-approved-baseline-selection",
            recorded_at_utc="2026-08-30T00:00:00Z",
            **_safe_host_receipt_context(),
        )

    extra = json.loads(json.dumps(receipt))
    extra["username"] = "private-user-sentinel"
    with pytest.raises(RuntimeError, match="invalid host probe receipt"):
        probe_script.validate_phase1_host_probe_receipt(extra)

    changed_commit = json.loads(json.dumps(receipt))
    changed_commit["source"]["commit"] = "e" * 40
    with pytest.raises(RuntimeError, match="host probe receipt source mismatch"):
        probe_script.validate_phase1_host_probe_receipt(
            changed_commit,
            expected_source_commit="f" * 40,
            expected_probe_script_sha256="a" * 64,
        )

    changed_script = json.loads(json.dumps(receipt))
    changed_script["source"]["probe_script_sha256"] = "b" * 64
    with pytest.raises(RuntimeError, match="host probe receipt source mismatch"):
        probe_script.validate_phase1_host_probe_receipt(
            changed_script,
            expected_source_commit="f" * 40,
            expected_probe_script_sha256="a" * 64,
        )


def test_target_probe_cli_writes_atomic_pass_receipt_without_extra_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    provider = InMemorySecretProvider()
    receipt_path = tmp_path / "receipt.json"
    replace_calls: list[tuple[Path, Path, bool]] = []
    real_replace = probe_script._replace_file

    def capture_replace(source_path: Path, destination_path: Path) -> None:
        replace_calls.append((source_path, destination_path, source_path.exists()))
        real_replace(source_path, destination_path)

    monkeypatch.setenv(probe_script.PROBE_ENVIRONMENT_ACK, "1")
    monkeypatch.setattr(probe_script, "MacOSKeychainSecretProvider", lambda: provider)
    monkeypatch.setattr(
        probe_script,
        "_capture_content_safe_host_context",
        lambda selected_provider: _safe_host_receipt_context(),
    )
    monkeypatch.setattr(probe_script, "_utc_now", lambda: "2026-08-30T00:00:00Z")
    monkeypatch.setattr(probe_script.secrets, "token_bytes", lambda size: b"p" * size)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )
    monkeypatch.setattr(probe_script, "_replace_file", capture_replace)

    assert (
        probe_script.main(
            [
                "--acknowledge-keychain-write",
                "--receipt",
                str(receipt_path),
                "--owner-review-ref",
                "owner-approved-baseline-selection",
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.out == "macOS Keychain probe: PASS\n"
    assert output.err == ""
    assert len(replace_calls) == 1
    assert replace_calls[0][0].name.startswith(".receipt.json.")
    assert replace_calls[0][1] == receipt_path
    assert replace_calls[0][2] is True

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    probe_script.validate_phase1_host_probe_receipt(receipt)
    assert receipt["status"] == "pass"
    assert receipt["cleanup_verified"] is True
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
    monkeypatch.setattr(probe_script, "_utc_now", lambda: "2026-08-30T00:00:00Z")
    monkeypatch.setattr(probe_script.secrets, "token_bytes", lambda size: b"q" * size)
    monkeypatch.setattr(
        probe_script,
        "uuid4",
        lambda: UUID("00000000-0000-4000-8000-000000000801"),
    )

    assert (
        probe_script.main(
            [
                "--acknowledge-keychain-write",
                "--receipt",
                str(receipt_path),
                "--owner-review-ref",
                "owner-approved-baseline-selection",
            ]
        )
        == 1
    )
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
