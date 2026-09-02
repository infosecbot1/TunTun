from __future__ import annotations

import builtins
import hashlib
import inspect
import os
import socket
import subprocess
from pathlib import Path
from typing import Any, Protocol

import pytest
import tuntun_core.services.reachy.operator as operator_module
from tuntun_contracts.base import canonical_bytes
from tuntun_contracts.reachy_operator import ReachyAcceptedCapabilityV1, ReachyOperatorStateV1
from tuntun_core.cli.main import app
from tuntun_core.services.reachy.operator import (
    MAX_OPERATOR_JSON_DEPTH,
    MAX_OPERATOR_STATE_BYTES,
    OPERATOR_STATE_PATH,
    ReachyOperatorReader,
    ReachyOperatorStateUnavailable,
)
from typer.testing import CliRunner


class _ReadableOperatorState(Protocol):
    def compatibility_field(self, field: str) -> str: ...

    def commissioned_numeric_ssh_target(self) -> str: ...


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _accepted_capability(*, username: str = "tuntunops") -> ReachyAcceptedCapabilityV1:
    return ReachyAcceptedCapabilityV1(
        capability_report_sha256=_digest("capability-report"),
        acceptance_receipt_sha256=_digest("acceptance-receipt"),
        sdk_version="1.2.3",
        daemon_version="4.5.6",
        ssh_username=username,
        python_executable="/venvs/apps_venv/bin/python3",
        python_version="3.12",
        python_abi="cp312",
        selected_wheel_tag="py3-none-any",
        target_tag_set_sha256=_digest("target-tags"),
        runtime_inventory_sha256=_digest("runtime-inventory"),
    )


def _operator_state(*, accepted: bool = True) -> ReachyOperatorStateV1:
    return ReachyOperatorStateV1(
        schema_version="tuntun.reachy-operator-state.v1",
        commissioning_generation=7,
        commissioning_state_sha256=_digest("commissioning-state-generation-7"),
        ssh_username="tuntunops",
        reachy_ipv4="192.168.50.20",
        core_ipv4="192.168.50.10",
        pinned_ssh_host_key_sha256=_digest("ssh-host-key"),
        dhcp_receipt_sha256=_digest("dhcp-receipt"),
        accepted_capability=_accepted_capability() if accepted else None,
    )


def _operator_fixture_path(tmp_path: Path) -> Path:
    path = tmp_path / "system" / "tuntun" / "reachy" / "operator-state.json"
    path.parent.mkdir(parents=True)
    (tmp_path / "system").chmod(0o755)
    (tmp_path / "system" / "tuntun").chmod(0o700)
    path.parent.chmod(0o700)
    return path


def _write_operator_state(
    path: Path,
    state: ReachyOperatorStateV1,
    *,
    mode: int = 0o600,
) -> None:
    path.write_bytes(canonical_bytes(state))
    path.chmod(mode)


def _reader_for_test_path(path: Path, tmp_path: Path) -> ReachyOperatorReader:
    return ReachyOperatorReader(
        operator_module._PathPolicy(
            state_path=path,
            trusted_root=tmp_path,
            system_component_count=1,
            trusted_root_owner_uid=os.geteuid(),
            system_owner_uid=os.geteuid(),
            app_owner_uid=os.geteuid(),
        )
    )


def _use_fixed_reader(
    monkeypatch: pytest.MonkeyPatch,
    reader: _ReadableOperatorState,
) -> None:
    def factory(cls: type[ReachyOperatorReader]) -> _ReadableOperatorState:
        del cls
        return reader

    monkeypatch.setattr(ReachyOperatorReader, "from_fixed_owner_file", classmethod(factory))


def test_fixed_reader_factory_is_not_configurable() -> None:
    assert Path("/private/var/lib/tuntun/reachy/operator-state.json") == OPERATOR_STATE_PATH
    assert inspect.signature(ReachyOperatorReader.from_fixed_owner_file).parameters == {}


def test_reader_returns_only_accepted_current_projection_values(tmp_path: Path) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state())

    reader = _reader_for_test_path(path, tmp_path)

    assert reader.compatibility_field("sdk") == "1.2.3"
    assert reader.compatibility_field("daemon") == "4.5.6"
    assert reader.compatibility_field("python-version") == "3.12"
    assert reader.compatibility_field("python-abi") == "cp312"
    assert reader.compatibility_field("wheel-platform") == "py3-none-any"
    assert reader.compatibility_field("selected-wheel-tag") == "py3-none-any"
    assert reader.compatibility_field("python-executable") == "/venvs/apps_venv/bin/python3"
    assert reader.commissioned_numeric_ssh_target() == "tuntunops@192.168.50.20"


def test_reader_rejects_cleared_operator_projection_as_not_current_active(
    tmp_path: Path,
) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state(accepted=False))

    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")


@pytest.mark.parametrize("mode", (0o640, 0o660, 0o666))
def test_reader_rejects_operator_state_without_exact_owner_mode(
    tmp_path: Path,
    mode: int,
) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state(), mode=mode)

    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).commissioned_numeric_ssh_target()


def test_reader_rejects_hardlinked_operator_state(tmp_path: Path) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state())
    os.link(path, path.with_name("operator-state-copy.json"))

    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")


def test_reader_rejects_symlink_operator_state_without_following(tmp_path: Path) -> None:
    path = _operator_fixture_path(tmp_path)
    real = path.with_name("real-operator-state.json")
    _write_operator_state(real, _operator_state())
    path.symlink_to(real)

    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")


def test_reader_rejects_named_inode_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _operator_fixture_path(tmp_path)
    replacement = path.with_name("replacement-operator-state.json")
    _write_operator_state(path, _operator_state())
    _write_operator_state(replacement, _operator_state())
    real_stat = os.stat
    file_stat_count = 0

    def replace_name_before_final_stat(path_arg: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal file_stat_count
        if (
            path_arg == "operator-state.json"
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            file_stat_count += 1
            if file_stat_count == 2:
                replacement.replace(path)
        return real_stat(path_arg, *args, **kwargs)

    monkeypatch.setattr(os, "stat", replace_name_before_final_stat)

    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")

    assert file_stat_count >= 2


def test_reader_rejects_short_read_before_snapshot_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state())
    real_read = os.read
    shortened = False

    def short_read(fd: int, byte_count: int) -> bytes:
        nonlocal shortened
        if not shortened and byte_count > 1:
            shortened = True
            return b""
        return real_read(fd, byte_count)

    monkeypatch.setattr(os, "read", short_read)

    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")

    assert shortened is True


def test_reader_rejects_growth_after_snapshot_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state())
    real_read = os.read
    grew = False

    def grow_after_content_read(fd: int, byte_count: int) -> bytes:
        nonlocal grew
        chunk = real_read(fd, byte_count)
        if chunk and byte_count > 1 and not grew:
            with path.open("ab") as handle:
                handle.write(b"x")
            grew = True
        return chunk

    monkeypatch.setattr(os, "read", grow_after_content_read)

    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")

    assert grew is True


def test_reader_rejects_unsafe_app_and_system_directories(tmp_path: Path) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state())
    path.parent.chmod(0o755)
    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")

    path.parent.chmod(0o700)
    (tmp_path / "system").chmod(0o777)
    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")


def test_reader_rejects_oversized_noncanonical_and_hostile_json(tmp_path: Path) -> None:
    path = _operator_fixture_path(tmp_path)

    path.write_bytes(b"{" + (b'"x":0,' * 6000) + b'"z":0}')
    path.chmod(0o600)
    assert path.stat().st_size > MAX_OPERATOR_STATE_BYTES
    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")

    path.write_bytes(_operator_state().model_dump_json(indent=2).encode("utf-8"))
    path.chmod(0o600)
    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")

    path.write_bytes((b"[" * (MAX_OPERATOR_JSON_DEPTH + 1)) + b"0" + (b"]" * 5))
    path.chmod(0o600)
    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")


def test_reader_rejects_duplicate_json_key(tmp_path: Path) -> None:
    path = _operator_fixture_path(tmp_path)
    raw = canonical_bytes(_operator_state())
    duplicate = raw.replace(
        b'{"accepted_capability":',
        b'{"schema_version":"tuntun.reachy-operator-state.v1","accepted_capability":',
        1,
    )
    assert duplicate.count(b'"schema_version"') == 2
    path.write_bytes(duplicate)
    path.chmod(0o600)

    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")


def test_reader_has_no_dns_socket_subprocess_or_write_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state())

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("forbidden side effect")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "write", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)

    reader = _reader_for_test_path(path, tmp_path)

    assert reader.commissioned_numeric_ssh_target() == "tuntunops@192.168.50.20"


@pytest.mark.parametrize("flag_name", ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"))
def test_reader_fails_closed_when_required_open_flag_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flag_name: str,
) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state())
    monkeypatch.setattr(os, flag_name, 0)

    with pytest.raises(ReachyOperatorStateUnavailable, match="unsafe Reachy operator state"):
        _reader_for_test_path(path, tmp_path).compatibility_field("sdk")


def test_tuntunctl_reachy_cli_prints_exact_values_and_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state())
    reader = _reader_for_test_path(path, tmp_path)

    _use_fixed_reader(monkeypatch, reader)

    runner = CliRunner()
    expected_fields = {
        "sdk": "1.2.3\n",
        "daemon": "4.5.6\n",
        "python-version": "3.12\n",
        "python-abi": "cp312\n",
        "wheel-platform": "py3-none-any\n",
        "selected-wheel-tag": "py3-none-any\n",
        "python-executable": "/venvs/apps_venv/bin/python3\n",
    }
    for field, expected in expected_fields.items():
        result = runner.invoke(app, ["reachy", "compatibility", "--field", field])
        assert result.exit_code == 0
        assert result.stdout == expected
        assert result.stderr == ""

    target = runner.invoke(
        app,
        ["reachy", "commissioned-ssh-target", "--numeric", "--plain"],
    )
    assert target.exit_code == 0
    assert target.stdout == "tuntunops@192.168.50.20\n"
    assert target.stderr == ""


def test_tuntunctl_reachy_cli_keeps_usage_errors_at_exit_2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExplodingReader:
        def compatibility_field(self, field: str) -> str:
            raise AssertionError(f"reader should not run for {field}")

        def commissioned_numeric_ssh_target(self) -> str:
            raise AssertionError("reader should not run for usage errors")

    _use_fixed_reader(monkeypatch, ExplodingReader())
    runner = CliRunner()

    for arguments in (
        ["reachy", "compatibility"],
        ["reachy", "compatibility", "--field", "target-tag-set-sha256"],
        ["reachy", "compatibility", "--field", "sdk", "extra"],
        ["reachy", "commissioned-ssh-target", "--numeric"],
        ["reachy", "commissioned-ssh-target", "--plain"],
        ["reachy", "commissioned-ssh-target", "--numeric", "--plain", "extra"],
    ):
        result = runner.invoke(app, arguments)
        assert result.exit_code == 2, arguments
        assert result.stdout == ""


def test_tuntunctl_reachy_cli_maps_operational_failures_to_exit_70(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingReader:
        def compatibility_field(self, field: str) -> str:
            del field
            raise ReachyOperatorStateUnavailable("unsafe Reachy operator state")

        def commissioned_numeric_ssh_target(self) -> str:
            raise ReachyOperatorStateUnavailable("unsafe Reachy operator state")

    _use_fixed_reader(monkeypatch, FailingReader())
    runner = CliRunner()

    compatibility = runner.invoke(app, ["reachy", "compatibility", "--field", "sdk"])
    assert compatibility.exit_code == 70
    assert compatibility.stdout == ""
    assert compatibility.stderr == "Reachy qualified state unavailable\n"

    target = runner.invoke(
        app,
        ["reachy", "commissioned-ssh-target", "--numeric", "--plain"],
    )
    assert target.exit_code == 70
    assert target.stdout == ""
    assert target.stderr == "Reachy qualified state unavailable\n"


@pytest.mark.parametrize("flag_name", ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"))
def test_tuntunctl_reachy_cli_maps_missing_required_open_flag_to_exit_70(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flag_name: str,
) -> None:
    path = _operator_fixture_path(tmp_path)
    _write_operator_state(path, _operator_state())
    _use_fixed_reader(monkeypatch, _reader_for_test_path(path, tmp_path))
    monkeypatch.setattr(os, flag_name, 0)

    result = CliRunner().invoke(app, ["reachy", "compatibility", "--field", "sdk"])

    assert result.exit_code == 70
    assert result.stdout == ""
    assert result.stderr == "Reachy qualified state unavailable\n"
