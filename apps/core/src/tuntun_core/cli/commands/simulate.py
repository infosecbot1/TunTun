from __future__ import annotations

import importlib.util
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Annotated, Any, Never
from uuid import UUID

import typer

_SIMULATION_TIMEOUT_SECONDS = 120.0
_MAX_SIMULATION_OUTPUT_BYTES = 65_536
_SIMULATION_OUTPUT_LIMIT_ENV = "TUNTUN_SIMULATION_OUTPUT_LIMIT"
_SCENARIO_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SIMULATE_BOOTSTRAP = """
from __future__ import annotations

import os
import resource
import site

limit = int(os.environ.pop("TUNTUN_SIMULATION_OUTPUT_LIMIT"))
_soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
bounded = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
resource.setrlimit(resource.RLIMIT_FSIZE, (bounded, bounded))
site.main()
"""
_SIMULATE_CHILD_CODE = """
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


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-json-key")
        result[key] = value
    return result


def _reject_json_number(_value: str) -> Never:
    raise ValueError("invalid-json-number")


def _canonical_json_object(raw: bytes) -> dict[str, Any]:
    if not 2 <= len(raw) <= _MAX_SIMULATION_OUTPUT_BYTES or not raw.endswith(b"\n"):
        raise ValueError("invalid-child-output")
    payload = raw[:-1]
    value = json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_unique_json_object,
        parse_float=_reject_json_number,
        parse_constant=_reject_json_number,
    )
    if type(value) is not dict:
        raise ValueError("invalid-child-output")
    canonical = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if canonical != payload:
        raise ValueError("invalid-child-output")
    return value


def _valid_text(value: Any, *, maximum: int, prefix: str | None = None) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and len(value.encode("utf-8")) <= maximum * 4
        and value == unicodedata.normalize("NFC", value)
        and value.isprintable()
        and (prefix is None or value.startswith(prefix))
    )


def _valid_uuid(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _valid_usage(value: Any) -> bool:
    keys = {
        "input_audio_bytes",
        "output_audio_bytes",
        "response_characters",
        "transcript_characters",
    }
    return (
        type(value) is dict
        and set(value) == keys
        and all(type(value[key]) is int and 0 <= value[key] <= 1_000_000 for key in keys)
    )


def _validated_simulation_output(raw: bytes, *, json_output: bool) -> bytes:
    if not json_output:
        if raw != b"simulation: PASS\n":
            raise ValueError("invalid-child-output")
        return raw
    value = _canonical_json_object(raw)
    keys = {
        "audit_receipt_ids",
        "events",
        "identity",
        "language",
        "outcome",
        "response",
        "scenario",
        "schema_version",
        "transcript",
        "turn_id",
        "turn_index",
        "usage",
    }
    audit_ids = value.get("audit_receipt_ids")
    events = value.get("events")
    scenario = value.get("scenario")
    if (
        set(value) != keys
        or value["schema_version"] != "scenario_result.v1"
        or type(scenario) is not str
        or _SCENARIO_NAME_PATTERN.fullmatch(scenario) is None
        or value["identity"] != "guest"
        or value["language"] not in {"en", "hi", "hinglish"}
        or value["outcome"] != "completed"
        or not _valid_text(value["transcript"], maximum=256, prefix="synthetic-")
        or not _valid_text(value["response"], maximum=256, prefix="synthetic-")
        or type(value["turn_index"]) is not int
        or not 0 <= value["turn_index"] < 10_000
        or not _valid_uuid(value["turn_id"])
        or type(audit_ids) is not list
        or not 1 <= len(audit_ids) <= 16
        or not all(_valid_uuid(item) for item in audit_ids)
        or type(events) is not list
        or not 1 <= len(events) <= 64
        or not all(type(item) is str and _EVENT_PATTERN.fullmatch(item) for item in events)
        or not _valid_usage(value["usage"])
    ):
        raise ValueError("invalid-child-output")
    return raw


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        process.kill()
    try:
        process.wait(timeout=5)
    except BaseException:
        process.kill()
        process.wait()


def _run_simulation_child(
    *,
    repository_root: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    environment[_SIMULATION_OUTPUT_LIMIT_ENV] = str(_MAX_SIMULATION_OUTPUT_BYTES)
    with (
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        process = subprocess.Popen(
            [sys.executable, "-S", "-c", _SIMULATE_BOOTSTRAP + _SIMULATE_CHILD_CODE],
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=repository_root,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
        try:
            process.wait(timeout=_SIMULATION_TIMEOUT_SECONDS)
        except BaseException:
            _terminate_process_group(process)
            raise
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(_MAX_SIMULATION_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(_MAX_SIMULATION_OUTPUT_BYTES + 1)
    if len(stdout) > _MAX_SIMULATION_OUTPUT_BYTES or len(stderr) > _MAX_SIMULATION_OUTPUT_BYTES:
        raise ValueError("child-output-limit-exceeded")
    return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)


def simulate(
    scenario: Annotated[Path, typer.Option("--scenario")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run one synthetic repository scenario with the optional simulation extra."""
    try:
        simulation_available = importlib.util.find_spec("tuntun_testing") is not None
    except BaseException:
        typer.echo("simulation-invalid-input", err=True)
        raise typer.Exit(2) from None
    if not simulation_available:
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
        result = _run_simulation_child(
            repository_root=repository_root,
            environment=environment,
        )
        if result.returncode == 0 and result.stderr == b"":
            output = _validated_simulation_output(result.stdout, json_output=json_output)
        else:
            output = None
    except BaseException:
        typer.echo("simulation-invalid-input", err=True)
        raise typer.Exit(2) from None
    if output is not None:
        typer.echo(output.decode("utf-8"), nl=False)
        return
    if (
        result.returncode == 2
        and result.stdout == b""
        and result.stderr == b"simulation-extra-required\n"
    ):
        typer.echo("simulation-extra-required", err=True)
        raise typer.Exit(2) from None
    typer.echo("simulation-invalid-input", err=True)
    raise typer.Exit(2) from None
