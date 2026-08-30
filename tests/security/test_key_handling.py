from __future__ import annotations

import base64
import builtins
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
    with pytest.raises(RuntimeError, match="synthetic post-write failure"):
        probe_script.probe_keychain_round_trip(
            provider,
            "tuntun.probe",
            "slot-v1",
            b"probe",
        )
    assert not provider.exists("tuntun.probe", "slot-v1")


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
