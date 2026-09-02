from __future__ import annotations

import getpass
import os
import sys
from typing import Literal

import typer

from tuntun_edge.bootstrap.commissioning import build_production_commissioning

STDIN = sys.stdin
STDERR = sys.stderr
_REMOTE_ENV_NAMES = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
_GENERIC_ERROR = "Reachy local ceremony unavailable"

reachy_app = typer.Typer(no_args_is_help=True, add_completion=False)


class ReachyLocalConsoleUnavailable(PermissionError):
    """The Edge CLI was not invoked from the local owner console."""


def require_local_console() -> None:
    if any(os.environ.get(name) for name in _REMOTE_ENV_NAMES):
        raise ReachyLocalConsoleUnavailable(_GENERIC_ERROR)
    if not STDIN.isatty() or not STDERR.isatty():
        raise ReachyLocalConsoleUnavailable(_GENERIC_ERROR)


def prompt_one_time_code() -> str:
    return getpass.getpass("Reachy physical one-time code: ", stream=STDERR)


@reachy_app.command("commission")
def commission() -> None:
    _run_local_ceremony("commission")


@reachy_app.command("recommission")
def recommission() -> None:
    _run_local_ceremony("recommission")


def _run_local_ceremony(operation: Literal["commission", "recommission"]) -> None:
    one_time_code: str | None = None
    try:
        require_local_console()
        one_time_code = prompt_one_time_code()
        composition = build_production_commissioning()
        if operation == "commission":
            composition.commission(one_time_code)
        else:
            composition.recommission(one_time_code)
    except Exception as error:
        typer.echo(_GENERIC_ERROR, err=True)
        raise typer.Exit(70) from error
    finally:
        one_time_code = None
