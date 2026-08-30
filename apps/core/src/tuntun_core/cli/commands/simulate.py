from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated

import typer

_SIMULATE_CHILD_CODE = """
from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from tuntun_testing.network_guard import install_network_guard

    install_network_guard()
    from tuntun_testing.scenario import ScenarioRunner
    from tuntun_testing.scenario_io import read_scenario_input

    repository_root = Path(os.environ["TUNTUN_SIMULATION_ROOT"])
    scenario = Path(os.environ["TUNTUN_SIMULATION_SCENARIO"])
    result = ScenarioRunner().run(read_scenario_input(scenario, trusted_root=repository_root))
    if os.environ.get("TUNTUN_SIMULATION_JSON") == "1":
        sys.stdout.buffer.write(result.canonical_json() + b"\\n")
    else:
        print("simulation: PASS")
except ImportError:
    print("simulation-extra-required", file=sys.stderr)
    raise SystemExit(2)
except BaseException:
    print("simulation-invalid-input", file=sys.stderr)
    raise SystemExit(2)
"""


def simulate(
    scenario: Annotated[Path, typer.Option("--scenario")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run one synthetic repository scenario with the optional simulation extra."""
    if importlib.util.find_spec("tuntun_testing") is None:
        typer.echo("simulation-extra-required", err=True)
        raise typer.Exit(2) from None
    repository_root = Path(__file__).absolute().parents[6]
    environment = os.environ.copy()
    environment.update(
        {
            "TUNTUN_SIMULATION_JSON": "1" if json_output else "0",
            "TUNTUN_SIMULATION_ROOT": str(repository_root),
            "TUNTUN_SIMULATION_SCENARIO": str(scenario),
        }
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", _SIMULATE_CHILD_CODE],
            cwd=repository_root,
            env=environment,
            capture_output=True,
            check=False,
            close_fds=True,
            timeout=120,
        )
    except BaseException:
        typer.echo("simulation-invalid-input", err=True)
        raise typer.Exit(2) from None
    if result.returncode == 0 and result.stderr == b"":
        typer.echo(result.stdout.decode("utf-8"), nl=False)
        return
    if result.stderr == b"simulation-extra-required\n":
        typer.echo("simulation-extra-required", err=True)
        raise typer.Exit(2) from None
    typer.echo("simulation-invalid-input", err=True)
    raise typer.Exit(2) from None
