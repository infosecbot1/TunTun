from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Annotated

import typer
from tuntun_core.services.reachy.operator import (
    ReachyOperatorReader,
    ReachyOperatorStateUnavailable,
)

reachy_app = typer.Typer(
    no_args_is_help=True,
    help="Inspect the accepted local Reachy operator projection.",
)
_OPERATIONAL_ERROR_MESSAGE = "Reachy qualified state unavailable"


class CompatibilityField(StrEnum):
    SDK = "sdk"
    DAEMON = "daemon"
    PYTHON_VERSION = "python-version"
    PYTHON_ABI = "python-abi"
    WHEEL_PLATFORM = "wheel-platform"
    SELECTED_WHEEL_TAG = "selected-wheel-tag"
    PYTHON_EXECUTABLE = "python-executable"


def _emit_value(operation: Callable[[], str]) -> None:
    try:
        typer.echo(operation())
    except ReachyOperatorStateUnavailable:
        typer.echo(_OPERATIONAL_ERROR_MESSAGE, err=True)
        raise typer.Exit(code=70) from None


@reachy_app.command("compatibility")
def compatibility(
    field: Annotated[
        CompatibilityField,
        typer.Option(
            "--field",
            case_sensitive=True,
            help="Closed Reachy compatibility field to print.",
        ),
    ],
) -> None:
    """Print one accepted Reachy compatibility value."""
    reader = ReachyOperatorReader.from_fixed_owner_file()
    _emit_value(lambda: reader.compatibility_field(field.value))


@reachy_app.command("commissioned-ssh-target")
def commissioned_ssh_target(
    numeric: Annotated[
        bool,
        typer.Option("--numeric", help="Require a numeric RFC1918 Reachy address."),
    ] = False,
    plain: Annotated[
        bool,
        typer.Option("--plain", help="Emit only the ssh target and trailing newline."),
    ] = False,
) -> None:
    """Print the accepted numeric Reachy SSH target."""
    if not numeric or not plain:
        raise typer.BadParameter("--numeric and --plain are required")
    reader = ReachyOperatorReader.from_fixed_owner_file()
    _emit_value(reader.commissioned_numeric_ssh_target)
