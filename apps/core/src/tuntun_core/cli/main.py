import typer
from tuntun_core.cli.commands.models import models_app
from tuntun_core.cli.commands.simulate import simulate

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Manage local Tuntun development commands."""


@app.command()
def version() -> None:
    """Print the application version without reading configuration or secrets."""
    typer.echo("0.1.0.dev0")


app.command("simulate")(simulate)
app.add_typer(models_app, name="models")
