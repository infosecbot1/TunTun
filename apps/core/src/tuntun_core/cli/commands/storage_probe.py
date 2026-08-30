from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from tuntun_core.adapters.keychain.macos import MacOSKeychainSecretProvider
from tuntun_core.adapters.sqlcipher.probe import probe_storage

storage_app = typer.Typer(no_args_is_help=True, help="Inspect encrypted local storage.")
_MISSING_DATABASE_KEY_MESSAGE = "storage probe: database key unavailable"


def _read_database_key() -> bytes:
    try:
        return MacOSKeychainSecretProvider().get("tuntun.database", "root-v1")
    except RuntimeError as error:
        if type(error) is not RuntimeError or error.args != ("missing secret",):
            raise
        typer.echo(_MISSING_DATABASE_KEY_MESSAGE, err=True)
        raise typer.Exit(code=1) from None


@storage_app.command("probe")
def storage_probe(
    path: Annotated[Path, typer.Option("--path", help="Database path to probe.")],
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Emit sanitized machine-readable probe metadata.",
        ),
    ] = False,
) -> None:
    """Verify SQLCipher compatibility without exposing the path or key."""
    key = _read_database_key()
    result = probe_storage(path, key).as_dict()
    typer.echo(json.dumps(result, sort_keys=True, indent=None if json_output else 2))
