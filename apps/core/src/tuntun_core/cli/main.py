import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def version() -> None:
    """Print the application version without reading configuration or secrets."""
    typer.echo("0.1.0.dev0")
