from __future__ import annotations

import sys
from typing import Annotated

import typer

from tuntun_edge.cli.managed import managed
from tuntun_edge.cli.ptt import ptt
from tuntun_edge.cli.reachy_commission import reachy_app
from tuntun_edge.poc.simulator import main as simulator_main

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.callback()
def _callback() -> None:
    """Run the commissioned robot-local Edge process."""


app.command("ptt")(ptt)
app.command("managed")(managed)
app.add_typer(reachy_app, name="reachy")


@app.command("simulate-ptt")
def simulate_ptt(
    turn_id: Annotated[
        str | None,
        typer.Option("--turn-id", help="Turn UUID shared with the Core fake supervisor."),
    ] = None,
    input_mode: Annotated[
        str,
        typer.Option("--input-mode", help="SDK-free simulated input owner."),
    ] = "core_terminal_toggle",
    capture_hex: Annotated[
        str,
        typer.Option("--capture-hex", help="Hex-encoded transport PCM for the fake turn."),
    ] = "0100020003000400",
) -> None:
    """Run the SDK-free binary PTT simulator over stdin/stdout."""

    from tuntun_contracts.poc.framing import PttInputMode

    try:
        mode = PttInputMode(input_mode)
    except ValueError:
        sys.stderr.write("simulate-ptt-rejected\n")
        raise typer.Exit(code=70) from None
    raise typer.Exit(code=simulator_main(turn_id=turn_id, input_mode=mode, capture_hex=capture_hex))


def main(argv: list[str] | None = None) -> int:
    command = typer.main.get_command(app)
    args = None if argv is None else list(argv)
    if args in ([], ["reachy"]):
        sys.stderr.write("Usage: tuntun-edge COMMAND [ARGS]...\n")
        return 65
    try:
        result = command.main(args=args, prog_name="tuntun-edge", standalone_mode=False)
    except typer.Exit as error:
        return int(error.exit_code)
    except Exception as error:
        if _is_click_exception(error, "NoArgsIsHelpError"):
            _show_click_error(error)
            return 65
        if _is_click_exception(error, "UsageError"):
            _show_click_error(error)
            return 65
        if _is_click_exception(error, "ClickException"):
            _show_click_error(error)
            return int(getattr(error, "exit_code", 1))
        raise
    if isinstance(result, int):
        return result
    return 0


def _is_click_exception(error: Exception, class_name: str) -> bool:
    return any(base.__name__ == class_name for base in type(error).mro())


def _show_click_error(error: Exception) -> None:
    show = getattr(error, "show", None)
    if callable(show):
        show(file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
