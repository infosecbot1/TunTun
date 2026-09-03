from tuntun_core.cli.main import app
from typer.testing import CliRunner


def test_version_command_exercises_the_bootstrap_cli() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout == "0.1.0.dev0\n"


def test_talk_fake_simulated_cli_runs_content_free_loop() -> None:
    result = CliRunner().invoke(app, ["talk", "--mode", "fake", "--transport", "simulated"])

    assert result.exit_code == 0
    assert result.stdout == "turns=1\noutcome=completed\n"
    assert "PRIVATE" not in result.stdout
    assert result.stderr == ""


def test_talk_unsupported_cell_fails_before_effectful_adapters() -> None:
    result = CliRunner().invoke(app, ["talk", "--mode", "live-cloud", "--transport", "simulated"])

    assert result.exit_code == 65
    assert result.stdout == ""
    assert result.stderr == "unsupported-talk-mode\n"
