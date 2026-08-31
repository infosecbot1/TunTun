import typer


def ptt() -> None:
    """Fail closed until the commissioned Reachy adapter is available."""
    typer.echo("reachy-ptt-unavailable", err=True)
    raise typer.Exit(code=1)
