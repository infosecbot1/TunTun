from __future__ import annotations

import argparse
import asyncio
import gc
import inspect
import json
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Never

MIN_TURNS = 1
MAX_TURNS = 10_000
MAX_TOTAL_TURNS = 10_000
_CHILD_ENV = "TUNTUN_SCENARIO_CHILD"


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
    payload = json.dumps(
        {
            "argv": list(argv),
            "repository_root": str(repository_root),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    environment = os.environ.copy()
    environment[_CHILD_ENV] = "1"
    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).absolute())],
            input=payload,
            cwd=repository_root,
            env=environment,
            capture_output=True,
            check=False,
            close_fds=True,
        )
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    if result.returncode == 0 and result.stderr == b"":
        sys.stdout.buffer.write(result.stdout)
        return 0
    if result.returncode == 2:
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    print("scenario-gate: failed", file=sys.stderr)
    return 1


def _child_main_from_stdin() -> int:
    try:
        raw = sys.stdin.buffer.read(1_048_576)
        configuration = json.loads(raw)
        argv = configuration["argv"]
        repository_root = Path(configuration["repository_root"])
        if (
            type(argv) is not list
            or not all(type(item) is str for item in argv)
            or not repository_root.is_absolute()
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
    if os.environ.get(_CHILD_ENV) == "1":
        return _child_main_from_stdin()
    arguments = list(sys.argv[1:] if argv is None else argv)
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
