from __future__ import annotations

import sys

import typer

from tuntun_edge.cli.managed import managed
from tuntun_edge.cli.ptt import ptt
from tuntun_edge.cli.reachy_commission import reachy_app

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.callback()
def _callback() -> None:
    """Run the commissioned robot-local Edge process."""


app.command("ptt")(ptt)
app.command("managed")(managed)
app.add_typer(reachy_app, name="reachy")


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
