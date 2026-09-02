from __future__ import annotations

import inspect
import io

import pytest
from typer.main import get_command


def test_edge_cli_keeps_importable_typer_app_and_single_dispatcher() -> None:
    from tuntun_edge.cli.main import app, main

    command = get_command(app)

    assert app.info.no_args_is_help is True
    assert app._add_completion is False
    assert inspect.signature(main).parameters["argv"].default is None
    assert inspect.signature(main).return_annotation == "int"
    assert command.params == []
    assert list(command.commands) == ["ptt", "reachy"]  # type: ignore[attr-defined]
    assert command.commands["ptt"].params == []  # type: ignore[attr-defined]
    reachy = command.commands["reachy"]  # type: ignore[attr-defined]
    assert list(reachy.commands) == ["commission", "recommission"]
    assert reachy.commands["commission"].params == []
    assert reachy.commands["recommission"].params == []


def test_edge_dispatcher_preserves_ptt_placeholder_behavior(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tuntun_edge.cli.main import main

    assert main(["ptt"]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "reachy-ptt-unavailable\n"


@pytest.mark.parametrize(
    "arguments",
    (
        ["pt"],
        ["reach"],
        ["reachy"],
        ["reachy", "comm"],
        ["reachy", "commission", "extra"],
        ["reachy", "commission", "--username", "tuntunops"],
        ["reachy", "commission", "--one-time-code", "123456"],
        ["reachy", "commission", "--proof", "abc"],
        ["reachy", "commission", "--private-key", "/tmp/key"],
        ["reachy", "recommission", "--otp", "123456"],
        ["reachy", "revoke"],
    ),
)
def test_edge_dispatcher_maps_closed_surface_usage_errors_to_65(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tuntun_edge.cli.main import main

    assert main(arguments) == 65

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Usage:" in captured.err or "No such command" in captured.err
    for secret_surface in ("123456", "tuntunops", "/tmp/key", "abc"):
        assert secret_surface not in captured.err


@pytest.mark.parametrize("ssh_indicator", ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"))
def test_reachy_commission_rejects_remote_invocation_before_prompt_or_composition(
    monkeypatch: pytest.MonkeyPatch,
    ssh_indicator: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tuntun_edge.cli import reachy_commission
    from tuntun_edge.cli.main import main

    observed: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        observed.append("side-effect")
        raise AssertionError("preflight must run first")

    monkeypatch.setenv(ssh_indicator, "remote")
    monkeypatch.setattr(reachy_commission, "prompt_one_time_code", forbidden)
    monkeypatch.setattr(reachy_commission, "build_production_commissioning", forbidden)

    assert main(["reachy", "commission"]) == 70

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Reachy local ceremony unavailable\n"
    assert observed == []


def test_reachy_commission_rejects_non_tty_before_prompt_or_composition(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tuntun_edge.cli import reachy_commission
    from tuntun_edge.cli.main import main

    observed: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        observed.append("side-effect")
        raise AssertionError("preflight must run first")

    monkeypatch.setattr(reachy_commission, "STDIN", io.StringIO(""))
    monkeypatch.setattr(reachy_commission, "STDERR", io.StringIO(""))
    monkeypatch.setattr(reachy_commission, "prompt_one_time_code", forbidden)
    monkeypatch.setattr(reachy_commission, "build_production_commissioning", forbidden)

    assert main(["reachy", "commission"]) == 70

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Reachy local ceremony unavailable\n"
    assert observed == []


@pytest.mark.parametrize("operation", ("commission", "recommission"))
def test_reachy_commission_maps_operational_failures_to_generic_70(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tuntun_edge.cli import reachy_commission
    from tuntun_edge.cli.main import main

    class _Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    class ExplodingComposition:
        def commission(self, one_time_code: str) -> None:
            assert one_time_code == "123456"
            raise RuntimeError("leaked principal tuntunops /etc/tuntun/reachy/commissioning.json")

        def recommission(self, one_time_code: str) -> None:
            assert one_time_code == "123456"
            raise RuntimeError("leaked proof digest abc123 and private key path")

    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.setattr(reachy_commission, "STDIN", _Tty())
    monkeypatch.setattr(reachy_commission, "STDERR", _Tty())
    monkeypatch.setattr(reachy_commission, "prompt_one_time_code", lambda: "123456")
    monkeypatch.setattr(
        reachy_commission,
        "build_production_commissioning",
        lambda: ExplodingComposition(),
    )

    assert main(["reachy", operation]) == 70

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Reachy local ceremony unavailable\n"
    assert "tuntunops" not in captured.err
    assert "/etc/tuntun/reachy" not in captured.err
    assert "abc123" not in captured.err
    assert "private key" not in captured.err


def test_commissioning_command_module_exposes_no_secret_parameter_names() -> None:
    from tuntun_edge.cli import reachy_commission

    secret_words = {"otp", "one_time_code", "username", "proof", "private_key"}
    for command in (reachy_commission.commission, reachy_commission.recommission):
        assert not secret_words & set(inspect.signature(command).parameters)
    assert inspect.signature(reachy_commission.prompt_one_time_code).parameters == {}
    assert inspect.signature(reachy_commission.build_production_commissioning).parameters == {}


def test_dispatcher_accepts_no_environment_override_for_paths_or_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tuntun_edge.cli import reachy_commission
    from tuntun_edge.cli.main import main

    class _Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    class RecordingComposition:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def recommission(self, one_time_code: str) -> None:
            self.calls.append(one_time_code)

    composition = RecordingComposition()
    for name in (
        "TUNTUN_REACHY_COMMISSIONING",
        "TUNTUN_REACHY_ONE_TIME_CODE",
        "TUNTUN_REACHY_USERNAME",
        "TUNTUN_REACHY_PROOF",
        "TUNTUN_REACHY_PRIVATE_KEY",
    ):
        monkeypatch.setenv(name, "must-not-be-read")
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.setattr(reachy_commission, "STDIN", _Tty())
    monkeypatch.setattr(reachy_commission, "STDERR", _Tty())
    monkeypatch.setattr(reachy_commission, "prompt_one_time_code", lambda: "654321")
    monkeypatch.setattr(reachy_commission, "build_production_commissioning", lambda: composition)

    assert main(["reachy", "recommission"]) == 0

    assert composition.calls == ["654321"]
