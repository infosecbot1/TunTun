from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer


def simulate(
    scenario: Annotated[Path, typer.Option("--scenario")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run one synthetic repository scenario with the optional simulation extra."""
    try:
        from tuntun_testing.network_guard import install_network_guard

        install_network_guard()
        from tuntun_testing.scenario import ScenarioRunner
        from tuntun_testing.scenario_io import read_scenario_input
    except ImportError:
        typer.echo("simulation-extra-required", err=True)
        raise typer.Exit(2) from None
    try:
        repository_root = Path(__file__).absolute().parents[6]
        value = read_scenario_input(scenario, trusted_root=repository_root)
        result = ScenarioRunner().run(value)
    except Exception:
        typer.echo("simulation-invalid-input", err=True)
        raise typer.Exit(2) from None
    if json_output:
        typer.echo(result.canonical_json().decode("utf-8"))
    else:
        typer.echo("simulation: PASS")
