from __future__ import annotations

import os
import re
import traceback
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError
from tuntun_core.config import loader, secure_paths
from tuntun_core.config.loader import load_settings, read_bounded_strict_yaml
from tuntun_core.config.settings import Settings

PROJECT_ROOT = Path(__file__).parents[3]
DESCRIPTOR_CLEANUP_NOTE = "additional descriptor cleanup failure"


def _write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def _audit_config_descriptors(monkeypatch: pytest.MonkeyPatch, audit) -> None:
    original_root = secure_paths._open_root
    original_directory_open = secure_paths._open_directory_at
    original_file_open = loader._open_regular_at

    def recording_root() -> int:
        return audit.acquire(original_root(), "root")

    def recording_directory_open(name: str, parent_fd: int) -> int:
        descriptor = original_directory_open(name, parent_fd)
        metadata = os.fstat(descriptor)
        return audit.acquire(
            descriptor,
            f"directory:{name}:{metadata.st_dev}:{metadata.st_ino}",
        )

    def recording_file_open(name: str, parent_fd: int) -> int:
        descriptor = original_file_open(name, parent_fd)
        metadata = os.fstat(descriptor)
        return audit.acquire(
            descriptor,
            f"config-file:{name}:{metadata.st_dev}:{metadata.st_ino}",
        )

    monkeypatch.setattr(secure_paths, "_open_root", recording_root)
    monkeypatch.setattr(secure_paths, "_open_directory_at", recording_directory_open)
    monkeypatch.setattr(secure_paths, "_close_fd", audit.close)
    monkeypatch.setattr(loader, "_open_regular_at", recording_file_open)
    monkeypatch.setattr(loader, "_close_fd", audit.close)


def test_defaults_are_locked() -> None:
    settings = load_settings(None, {})

    assert settings.household.timezone == "Asia/Singapore"
    assert settings.conversation.active_limit == 1
    assert settings.network.admin_host == "127.0.0.1"
    assert settings.network.admin_port == 8787
    assert settings.network.admin_lan_port == 8443
    assert settings.network.edge_gateway_port == 7443
    assert settings.providers.primary_model == "gpt-5.6-sol"
    assert settings.providers.qwen_enabled is False
    assert (
        settings.providers.connect_timeout_ms,
        settings.providers.write_timeout_ms,
        settings.providers.read_timeout_ms,
        settings.providers.pool_timeout_ms,
        settings.providers.max_attempts,
    ) == (5_000, 30_000, 120_000, 5_000, 2)
    assert (
        settings.identity.child_reenrollment_reminder_days,
        settings.identity.child_biometric_hard_expiry_days,
    ) == (180, 365)
    assert (
        settings.admin.session_idle_seconds,
        settings.admin.session_absolute_seconds,
        settings.admin.json_body_max_bytes,
    ) == (900, 28_800, 1_048_576)
    assert (
        settings.admin.read_requests_per_minute,
        settings.admin.mutation_requests_per_minute,
        settings.admin.auth_requests_per_minute,
        settings.admin.trust_proxy_headers,
    ) == (120, 30, 10, False)
    assert (
        settings.observability.telemetry_enabled,
        settings.observability.cloud_tracing_enabled,
        settings.observability.provider_body_logging,
    ) == (False, False, False)
    assert settings.budget.soft_limit_micros_sgd == 100_000_000
    assert settings.budget.hard_limit_micros_sgd == 150_000_000


def test_settings_and_nested_models_are_frozen() -> None:
    settings = load_settings(None, {})

    with pytest.raises(ValidationError):
        settings.network.admin_port = 9999


@pytest.mark.parametrize(
    "raw",
    (
        "network:\n  admin_host: 0.0.0.0\n",
        "unknown: true\n",
        "network:\n  unknown: true\n",
        "[1, 2]\n",
        "memory: 5\n",
    ),
)
def test_invalid_settings_documents_fail(tmp_path: Path, raw: str) -> None:
    config = tmp_path / "invalid.yaml"
    _write_private(config, raw)

    with pytest.raises((ValidationError, ValueError)):
        load_settings(config, {})


def test_yaml_syntax_failure_is_content_free() -> None:
    marker = "private-config-value-marker"
    raw = f"network: [{marker}\n".encode()

    with pytest.raises(ValueError) as rejected:
        loader.parse_bounded_strict_yaml(raw, max_bytes=len(raw))

    rendered = "".join(traceback.format_exception(rejected.value))
    assert rejected.value.args == ("invalid configuration",)
    assert rejected.value.__cause__ is None
    assert rejected.value.__suppress_context__ is True
    assert marker not in rendered


def test_environment_overrides_yaml_but_unspecified_yaml_survives(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config.yaml"
    _write_private(
        config,
        "providers:\n  primary_model: configured-model\nmemory:\n  max_items_per_turn: 5\n",
    )

    settings = load_settings(
        config,
        {"TUNTUN_PROVIDERS__PRIMARY_MODEL": "environment-model"},
    )

    assert settings.providers.primary_model == "environment-model"
    assert settings.memory.max_items_per_turn == 5


def test_environment_cannot_hide_invalid_yaml(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    _write_private(config, "network:\n  admin_port: 0\n")

    with pytest.raises(ValidationError):
        load_settings(
            config,
            {"TUNTUN_NETWORK__ADMIN_PORT": "8787"},
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate_key",
        "yaml_alias",
        "explicit_tag",
        "overdeep",
        "too_many_events",
        "oversized_file",
        "invalid_utf8",
        "multiple_documents",
        "symlink",
        "hardlink",
        "ancestor_symlink",
        "fifo",
        "group_writable",
        "group_readable",
        "world_readable",
        "wrong_owner",
        "same_inode_content_change",
        "changed_during_read",
        "parent_changed_during_read",
    ),
)
def test_settings_file_is_bounded_duplicate_free_nofollow_and_stable(
    strict_settings_case,
    mutation: str,
) -> None:
    strict_settings_case.mutate(mutation)

    with pytest.raises((PermissionError, ValueError)):
        load_settings(strict_settings_case.path, {})


@pytest.mark.parametrize(
    "raw",
    (
        "[1,2]",
        "{x: 1}",
        "&x value",
        "!custom value",
        "x" * 1_025,
        "0",
    ),
)
def test_environment_override_is_one_bounded_strict_scalar(raw: str) -> None:
    with pytest.raises((ValidationError, ValueError)):
        load_settings(
            None,
            {"TUNTUN_OBSERVABILITY__TELEMETRY_ENABLED": raw},
        )


@pytest.mark.parametrize(
    "name",
    (
        "TUNTUN_network__ADMIN_PORT",
        "TUNTUN_NETWORK_ADMIN_PORT",
        "TUNTUN_NETWORK__ADMIN__PORT",
    ),
)
def test_environment_override_name_must_be_canonical(name: str) -> None:
    with pytest.raises(ValueError, match="invalid TUNTUN override"):
        load_settings(None, {name: "8787"})


@pytest.mark.parametrize(
    "payload",
    (
        {"network": {"admin_port": 0}},
        {"network": {"admin_lan_port": 8_444}},
        {"network": {"edge_gateway_port": 65_536}},
        {"network": {"admin_port": 8_443}},
        {"conversation": {"active_limit": 2}},
        {
            "conversation": {
                "follow_up_window_seconds": 61,
                "idle_close_seconds": 60,
            }
        },
        {
            "conversation": {
                "idle_close_seconds": 1_801,
                "absolute_session_limit_minutes": 30,
            }
        },
        {"privacy": {"audit_default_view_days": 0}},
        {"providers": {"primary_model": "bad model"}},
        {"providers": {"context_max_tokens": 0}},
        {"providers": {"read_timeout_ms": 120_001}},
        {"providers": {"max_attempts": 3}},
        {
            "identity": {
                "child_reenrollment_reminder_days": 365,
                "child_biometric_hard_expiry_days": 180,
            }
        },
        {
            "admin": {
                "session_idle_seconds": 901,
                "session_absolute_seconds": 900,
            }
        },
        {"admin": {"json_body_max_bytes": 0}},
        {"admin": {"read_requests_per_minute": 0}},
        {"admin": {"trust_proxy_headers": True}},
        {"admin": {"trust_proxy_headers": 0}},
        {"observability": {"telemetry_enabled": True}},
        {"observability": {"telemetry_enabled": 0}},
        {"observability": {"cloud_tracing_enabled": True}},
        {"observability": {"provider_body_logging": True}},
        {
            "budget": {
                "soft_limit_micros_sgd": -1,
                "hard_limit_micros_sgd": 1,
            }
        },
        {
            "budget": {
                "soft_limit_micros_sgd": 2,
                "hard_limit_micros_sgd": 1,
            }
        },
        {"household": {"timezone": ""}},
        {"household": {"timezone": "Not/A_Timezone"}},
        {"identity": {"passive_discovery_enabled": False}},
        {"identity": {"unknown_candidate_retention_days": 1}},
    ),
)
def test_invalid_operational_settings_fail_closed(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate(payload)


def test_checked_in_yaml_example_exactly_spells_out_defaults() -> None:
    raw = read_bounded_strict_yaml(
        PROJECT_ROOT / "config/tuntun.example.yaml",
        require_private=False,
    )

    assert raw == Settings().model_dump(mode="python")


def _supported_override_names() -> list[str]:
    names: list[str] = []
    for section_name, section_field in Settings.model_fields.items():
        section_type = section_field.annotation
        assert isinstance(section_type, type)
        assert issubclass(section_type, BaseModel)
        for field_name in section_type.model_fields:
            names.append(f"TUNTUN_{section_name.upper()}__{field_name.upper()}")
    return sorted(names)


def test_env_example_contains_every_name_once_and_no_values() -> None:
    lines = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    expected = [f"# {name}" for name in _supported_override_names()]

    assert lines == expected
    assert len(lines) == len(set(lines))
    assert all(re.fullmatch(r"# TUNTUN_[A-Z0-9_]+__[A-Z0-9_]+", line) for line in lines)
    assert all("=" not in line for line in lines)


def test_settings_file_descriptor_closes_when_parsing_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    config = tmp_path / "config.yaml"
    _write_private(config, "{}\n")

    def failing_parse(
        raw: bytes,
        *,
        max_bytes: int,
        max_events: int = 16_384,
        max_depth: int = 32,
    ) -> loader.YamlValue:
        raise ValueError("injected parser failure")

    _audit_config_descriptors(monkeypatch, descriptor_audit)
    monkeypatch.setattr(loader, "parse_bounded_strict_yaml", failing_parse)

    with pytest.raises(ValueError, match="injected parser failure"):
        load_settings(config, {})

    descriptor_audit.assert_all_closed_once()


def test_settings_success_closes_every_owned_descriptor_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    config = tmp_path / "config.yaml"
    _write_private(config, "memory:\n  max_items_per_turn: 5\n")
    _audit_config_descriptors(monkeypatch, descriptor_audit)

    settings = load_settings(config, {})

    assert settings.memory.max_items_per_turn == 5
    descriptor_audit.assert_all_closed_once()


def test_settings_cleanup_failure_after_success_is_fixed_and_one_shot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    config = tmp_path / "config.yaml"
    _write_private(config, "{}\n")
    descriptor_audit.fail_label = "config-file"
    _audit_config_descriptors(monkeypatch, descriptor_audit)

    with pytest.raises(PermissionError) as rejected:
        load_settings(config, {})

    assert rejected.value.args == ("unsafe configuration file",)
    assert rejected.value.__cause__ is None
    assert rejected.value.__suppress_context__ is True
    descriptor_audit.assert_all_closed_once()


@pytest.mark.parametrize("failure_point", ("open", "stat", "read"))
def test_settings_os_failures_are_content_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
    failure_point: str,
) -> None:
    marker = "private-settings-marker"
    config = tmp_path / f"{marker}.yaml"
    if failure_point != "open":
        _write_private(config, "{}\n")
    _audit_config_descriptors(monkeypatch, descriptor_audit)

    if failure_point == "stat":
        original_stat = loader._stat_regular_at

        def failing_stat(name: str, parent_fd: int) -> os.stat_result:
            if name == config.name:
                raise OSError(marker)
            return original_stat(name, parent_fd)

        monkeypatch.setattr(loader, "_stat_regular_at", failing_stat)
    elif failure_point == "read":

        def failing_read(descriptor: int, size: int) -> bytes:
            del descriptor, size
            raise OSError(marker)

        monkeypatch.setattr(loader.os, "read", failing_read)

    with pytest.raises(PermissionError) as rejected:
        load_settings(config, {})

    rendered = "".join(traceback.format_exception(rejected.value))
    assert rejected.value.args == ("unsafe configuration file",)
    assert rejected.value.__cause__ is None
    assert rejected.value.__suppress_context__ is True
    assert marker not in rendered
    descriptor_audit.assert_all_closed_once()


def test_settings_owner_construction_failure_closes_raw_descriptor_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    config = tmp_path / "constructor-settings.yaml"
    _write_private(config, "{}\n")
    file_label = f"config-file:{config.name}:"
    descriptor_audit.fail_label = file_label
    original_owner = secure_paths._OwnedDescriptor

    def reject_file_owner(descriptor: int | None):
        if descriptor is not None and file_label in descriptor_audit.active[descriptor]:
            raise RuntimeError("primary settings owner construction failure")
        return original_owner(descriptor)

    _audit_config_descriptors(monkeypatch, descriptor_audit)
    monkeypatch.setattr(secure_paths, "_OwnedDescriptor", reject_file_owner)

    with pytest.raises(
        RuntimeError, match="primary settings owner construction failure"
    ) as primary:
        load_settings(config, {})

    assert primary.value.__notes__ == [DESCRIPTOR_CLEANUP_NOTE]
    descriptor_audit.assert_all_closed_once()


def test_settings_read_preserves_primary_when_file_cleanup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_audit,
) -> None:
    config = tmp_path / "config.yaml"
    _write_private(config, "{}\n")
    descriptor_audit.fail_label = "config-file"
    _audit_config_descriptors(monkeypatch, descriptor_audit)

    def fail_read(descriptor: int, size: int) -> bytes:
        del descriptor, size
        raise RuntimeError("primary configuration read failure")

    monkeypatch.setattr(loader.os, "read", fail_read)

    with pytest.raises(RuntimeError, match="primary configuration read failure") as primary:
        load_settings(config, {})

    assert primary.value.__notes__ == [DESCRIPTOR_CLEANUP_NOTE]
    assert "sensitive" not in primary.value.__notes__[0]
    descriptor_audit.assert_all_closed_once()


@pytest.mark.parametrize("reject_on_inspection", (1, 2, None))
def test_settings_file_acl_inspection_brackets_the_stable_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reject_on_inspection: int | None,
) -> None:
    config = tmp_path / "config.yaml"
    _write_private(config, "memory:\n  max_items_per_turn: 5\n")
    identity = (config.stat().st_dev, config.stat().st_ino)
    original_read = loader.os.read
    read_started = False
    inspection_states: list[bool] = []

    def recording_read(descriptor: int, size: int) -> bytes:
        nonlocal read_started
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == identity:
            read_started = True
        return original_read(descriptor, size)

    def has_unsafe_acl(descriptor: int) -> bool:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != identity:
            return False
        inspection_states.append(read_started)
        return reject_on_inspection == len(inspection_states)

    monkeypatch.setattr(loader.os, "read", recording_read)
    monkeypatch.setattr(secure_paths, "_descriptor_has_unsafe_acl", has_unsafe_acl)

    if reject_on_inspection is None:
        settings = load_settings(config, {})
        assert settings.memory.max_items_per_turn == 5
        assert inspection_states == [False, True]
    else:
        with pytest.raises(PermissionError) as rejected:
            load_settings(config, {})
        assert rejected.value.args == ("unsafe configuration file",)
        assert inspection_states == [False, True][:reject_on_inspection]


def test_settings_unsafe_acl_inspection_failure_is_content_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "config.yaml"
    _write_private(config, "{}\n")
    identity = (config.stat().st_dev, config.stat().st_ino)

    def fail_inspection(descriptor: int) -> bool:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == identity:
            raise OSError("sensitive native ACL diagnostic")
        return False

    monkeypatch.setattr(secure_paths, "_descriptor_has_unsafe_acl", fail_inspection)
    with pytest.raises(PermissionError) as rejected:
        load_settings(config, {})

    assert rejected.value.args == ("unsafe configuration file",)
    assert "sensitive" not in str(rejected.value)
    assert rejected.value.__cause__ is None
    assert rejected.value.__suppress_context__ is True


def test_native_granting_settings_acl_is_rejected_without_mutating_raw_acl(
    tmp_path: Path,
    native_unsafe_acl_installer,
) -> None:
    config = tmp_path / "config.yaml"
    _write_private(config, "{}\n")
    lease = native_unsafe_acl_installer(config, "access")

    with pytest.raises(PermissionError, match="unsafe configuration file"):
        load_settings(config, {})

    lease.assert_installed_unchanged()
