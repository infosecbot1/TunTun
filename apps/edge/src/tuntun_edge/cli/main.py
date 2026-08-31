import typer

from tuntun_edge.cli.ptt import ptt

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.callback()
def main() -> None:
    """Run the commissioned robot-local Edge process."""


app.command("ptt")(ptt)
