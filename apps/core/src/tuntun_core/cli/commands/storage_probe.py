from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from tuntun_core.adapters.keychain.macos import MacOSKeychainSecretProvider
from tuntun_core.adapters.sqlcipher.probe import probe_storage

storage_app = typer.Typer(no_args_is_help=True, help="Inspect encrypted local storage.")


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
    key = MacOSKeychainSecretProvider().get("tuntun.database", "root-v1")
    result = probe_storage(path, key).as_dict()
    typer.echo(json.dumps(result, sort_keys=True, indent=None if json_output else 2))
