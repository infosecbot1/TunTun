from __future__ import annotations

import argparse
import asyncio
import gc
import inspect
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Never

MIN_TURNS = 1
MAX_TURNS = 10_000
MAX_TOTAL_TURNS = 10_000
_CHILD_ENV = "TUNTUN_SCENARIO_CHILD"
_CHILD_ARGUMENT = "--tuntun-scenario-child"
_CHILD_OUTPUT_LIMIT_ENV = "TUNTUN_SCENARIO_OUTPUT_LIMIT"
_CHILD_TIMEOUT_SECONDS = 120.0
_MAX_CHILD_OUTPUT_BYTES = 65_536
_MAX_CHILD_CONFIGURATION_BYTES = 1_048_576
_SCENARIO_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CHILD_BOOTSTRAP = """
from __future__ import annotations

import os
import resource
import runpy
import site
import sys

limit = int(os.environ.pop("TUNTUN_SCENARIO_OUTPUT_LIMIT"))
_soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
bounded = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
resource.setrlimit(resource.RLIMIT_FSIZE, (bounded, bounded))
site.main()
script, token = sys.argv[1:]
sys.argv = [script, "--tuntun-scenario-child", token]
runpy.run_path(script, run_name="__main__")
"""


class _InputFailure(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise _InputFailure("invalid-input")


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = _Parser(prog="run_scenarios.py", add_help=True)
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--turns", type=int, required=True)
    parser.add_argument("--assert-resource-bounds", action="store_true")
    parser.add_argument("--json", action="store_true")
    values = parser.parse_args(argv)
    if not MIN_TURNS <= values.turns <= MAX_TURNS:
        raise _InputFailure("invalid-input")
    return values


def _fd_count() -> int:
    directory = next((path for path in ("/proc/self/fd", "/dev/fd") if os.path.isdir(path)), None)
    if directory is None:
        raise RuntimeError("fd-measurement-unavailable")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        entries = tuple(name for name in os.listdir(descriptor) if name.isdecimal())
        return len(entries) - (1 if str(descriptor) in entries else 0)
    finally:
        os.close(descriptor)


def _pending_task_count() -> int:
    current = asyncio.current_task()
    return sum(1 for task in asyncio.all_tasks() if task is not current and not task.done())


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
    if not 2 <= len(raw) <= _MAX_CHILD_OUTPUT_BYTES or not raw.endswith(b"\n"):
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


def _valid_b2(value: Any) -> bool:
    keys = {
        "duplicate_effect_count",
        "peak_rss_growth_bytes",
        "privacy_block_p95_ms",
        "private_sentinel_count",
        "status",
        "terminal_rss_growth_bytes",
        "warmup_turns",
    }
    if type(value) is not dict or set(value) != keys:
        return False
    metrics = tuple(value[key] for key in keys - {"status"})
    if value["status"] == "not_measured":
        return all(item is None for item in metrics)
    return (
        value["status"] == "pass"
        and value["warmup_turns"] == 50
        and all(type(item) is int and item >= 0 for item in metrics)
    )


def _valid_foundation_resources(value: Any, *, measured: bool) -> bool:
    keys = {
        "fd_after",
        "fd_baseline",
        "fd_delta",
        "pending_tasks_after",
        "pending_tasks_baseline",
        "pending_tasks_delta",
        "status",
    }
    if type(value) is not dict or set(value) != keys:
        return False
    metrics = tuple(value[key] for key in keys - {"status"})
    if not measured:
        return value["status"] == "not_measured" and all(item is None for item in metrics)
    return (
        value["status"] == "pass"
        and all(type(item) is int and item >= 0 for item in metrics)
        and value["fd_delta"] == 0
        and value["pending_tasks_delta"] == 0
        and value["fd_after"] == value["fd_baseline"]
        and value["pending_tasks_after"] == value["pending_tasks_baseline"]
    )


def _valid_scenario_records(value: Any, *, turns: int) -> bool:
    if type(value) is not list or not 1 <= len(value) <= 32:
        return False
    names: list[str] = []
    for item in value:
        if type(item) is not dict or set(item) != {"name", "result_chain_sha256", "turns"}:
            return False
        name = item["name"]
        digest = item["result_chain_sha256"]
        if (
            type(name) is not str
            or _SCENARIO_NAME_PATTERN.fullmatch(name) is None
            or type(digest) is not str
            or _DIGEST_PATTERN.fullmatch(digest) is None
            or type(item["turns"]) is not int
            or item["turns"] != turns
        ):
            return False
        names.append(name)
    return len(names) == len(set(names))


def _validated_gate_output(raw: bytes, argv: Sequence[str]) -> bytes:
    values = _arguments(argv)
    if not values.json:
        if raw != b"scenario-gate: PASS\n":
            raise ValueError("invalid-child-output")
        return raw
    value = _canonical_json_object(raw)
    if (
        set(value) != {"b2", "foundation_resources", "scenarios", "schema_version", "status"}
        or value["schema_version"] != "scenario_gate.v1"
        or value["status"] != "pass"
        or not _valid_b2(value["b2"])
        or not _valid_foundation_resources(
            value["foundation_resources"],
            measured=values.assert_resource_bounds,
        )
        or not _valid_scenario_records(value["scenarios"], turns=values.turns)
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


def _run_bounded_process(
    command: Sequence[str],
    *,
    payload: bytes,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    with (
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=cwd,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
        try:
            process.communicate(input=payload, timeout=_CHILD_TIMEOUT_SECONDS)
        except BaseException:
            _terminate_process_group(process)
            raise
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(_MAX_CHILD_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(_MAX_CHILD_OUTPUT_BYTES + 1)
    if len(stdout) > _MAX_CHILD_OUTPUT_BYTES or len(stderr) > _MAX_CHILD_OUTPUT_BYTES:
        raise ValueError("child-output-limit-exceeded")
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


async def _execute(
    inputs: tuple[Any, ...],
    turns: int,
    assert_resource_bounds: bool,
    turn_observer: Callable[[int], object] | None,
) -> tuple[tuple[Any, ...], Any]:
    from tuntun_testing.scenario import (
        FoundationResourceEvidence,
        ScenarioGateRecord,
        ScenarioRunner,
        result_chain,
    )

    await asyncio.sleep(0)
    gc.collect()
    fd_baseline = _fd_count() if assert_resource_bounds else None
    task_baseline = _pending_task_count() if assert_resource_bounds else None
    for value in inputs:
        await ScenarioRunner().run_async(value, turn_index=0)
    await asyncio.sleep(0)
    gc.collect()
    if assert_resource_bounds:
        if fd_baseline is None or task_baseline is None:
            raise AssertionError("resource-measurement-missing")
        if _fd_count() != fd_baseline or _pending_task_count() != task_baseline:
            raise AssertionError("resource-bound-failed")
    records: list[Any] = []
    global_turn = 0
    for value in inputs:
        results = []
        for turn_index in range(turns):
            results.append(await ScenarioRunner().run_async(value, turn_index=turn_index))
            if turn_observer is not None:
                observed = turn_observer(global_turn)
                if inspect.isawaitable(observed):
                    await observed
            global_turn += 1
        records.append(
            ScenarioGateRecord(
                name=results[0].scenario,
                turns=turns,
                result_chain_sha256=result_chain(tuple(results)),
            )
        )
    await asyncio.sleep(0)
    gc.collect()
    if assert_resource_bounds:
        fd_after = _fd_count()
        task_after = _pending_task_count()
        if fd_baseline is None or task_baseline is None:
            raise AssertionError("resource-measurement-missing")
        evidence = FoundationResourceEvidence(
            status="pass",
            fd_baseline=fd_baseline,
            fd_after=fd_after,
            fd_delta=fd_after - fd_baseline,
            pending_tasks_baseline=task_baseline,
            pending_tasks_after=task_after,
            pending_tasks_delta=task_after - task_baseline,
        )
        if evidence.fd_delta != 0 or evidence.pending_tasks_delta != 0:
            raise AssertionError("resource-bound-failed")
    else:
        evidence = FoundationResourceEvidence.not_measured()
    return tuple(records), evidence


def _run_gate_in_process(
    argv: Sequence[str],
    *,
    _after_guard: Callable[[], object] | None = None,
    _turn_observer: Callable[[int], object] | None = None,
    _repository_root: Path | None = None,
) -> int:
    try:
        values = _arguments(argv)
    except _InputFailure:
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    try:
        from tuntun_testing.network_guard import install_network_guard

        install_network_guard()
        if _after_guard is not None:
            guarded_result = _after_guard()
            if inspect.isawaitable(guarded_result):
                raise AssertionError("invalid-guard-hook")
        from tuntun_testing.scenario import ScenarioGateDocument, ScenarioSchemaError
        from tuntun_testing.scenario_io import (
            ScenarioInputError,
            load_scenario_inputs,
        )
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    try:
        repository_root = (
            Path(__file__).absolute().parent.parent
            if _repository_root is None
            else _repository_root
        )
        default_directory = Path("tests/fixtures/scenarios")
        inputs = load_scenario_inputs(
            (Path(item) for item in values.scenario),
            trusted_root=repository_root,
            default_directory=default_directory,
        )
        if len(inputs) * values.turns > MAX_TOTAL_TURNS:
            raise _InputFailure("invalid-input")
        records, evidence = asyncio.run(
            _execute(
                inputs,
                values.turns,
                values.assert_resource_bounds,
                _turn_observer,
            )
        )
        document = ScenarioGateDocument(scenarios=records, foundation_resources=evidence)
        if values.json:
            sys.stdout.buffer.write(document.canonical_json() + b"\n")
        else:
            print("scenario-gate: PASS")
        return 0
    except (_InputFailure, ScenarioInputError, ScenarioSchemaError):
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1


def _run_gate_child(argv: Sequence[str], repository_root: Path) -> int:
    try:
        token = secrets.token_hex(32)
        payload = json.dumps(
            {
                "argv": list(argv),
                "repository_root": str(repository_root),
                "token": token,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        environment = os.environ.copy()
        environment[_CHILD_ENV] = token
        environment[_CHILD_OUTPUT_LIMIT_ENV] = str(_MAX_CHILD_OUTPUT_BYTES)
        result = _run_bounded_process(
            (
                sys.executable,
                "-S",
                "-c",
                _CHILD_BOOTSTRAP,
                str(Path(__file__).absolute()),
                token,
            ),
            payload=payload,
            cwd=repository_root,
            environment=environment,
        )
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    if result.returncode == 0 and result.stderr == b"":
        try:
            sys.stdout.buffer.write(_validated_gate_output(result.stdout, argv))
            return 0
        except BaseException:
            print("scenario-gate: failed", file=sys.stderr)
            return 1
    if (
        result.returncode == 2
        and result.stdout == b""
        and result.stderr == b"scenario-gate: invalid-input\n"
    ):
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    print("scenario-gate: failed", file=sys.stderr)
    return 1


def _child_main_from_stdin(expected_token: str) -> int:
    try:
        raw = sys.stdin.buffer.read(_MAX_CHILD_CONFIGURATION_BYTES + 1)
        if len(raw) > _MAX_CHILD_CONFIGURATION_BYTES:
            raise ValueError("invalid-child-configuration")
        configuration = json.loads(raw)
        argv = configuration["argv"]
        repository_root = Path(configuration["repository_root"])
        token = configuration["token"]
        if (
            type(configuration) is not dict
            or set(configuration) != {"argv", "repository_root", "token"}
            or type(argv) is not list
            or not all(type(item) is str for item in argv)
            or not repository_root.is_absolute()
            or type(token) is not str
            or token != expected_token
            or os.environ.pop(_CHILD_ENV, None) != expected_token
        ):
            raise ValueError("invalid-child-configuration")
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    return _run_gate_in_process(argv, _repository_root=repository_root)


def main(
    argv: Sequence[str] | None = None,
    *,
    _after_guard: Callable[[], object] | None = None,
    _turn_observer: Callable[[int], object] | None = None,
    _repository_root: Path | None = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if (
        argv is None
        and len(arguments) == 2
        and arguments[0] == _CHILD_ARGUMENT
        and len(arguments[1]) == 64
        and os.environ.get(_CHILD_ENV) == arguments[1]
    ):
        return _child_main_from_stdin(arguments[1])
    if _after_guard is not None or _turn_observer is not None:
        return _run_gate_in_process(
            arguments,
            _after_guard=_after_guard,
            _turn_observer=_turn_observer,
            _repository_root=_repository_root,
        )
    try:
        _arguments(arguments)
    except _InputFailure:
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    repository_root = (
        Path(__file__).absolute().parent.parent if _repository_root is None else _repository_root
    )
    return _run_gate_child(arguments, repository_root)


if __name__ == "__main__":
    raise SystemExit(main())
