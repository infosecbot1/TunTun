from tuntun_core.cli.main import app
from typer.testing import CliRunner


def test_version_command_exercises_the_bootstrap_cli() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout == "0.1.0.dev0\n"
