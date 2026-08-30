from __future__ import annotations

import asyncio
import base64
import fcntl
import importlib
import importlib.util
import io
import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Sequence
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_testing import scenario_io
from tuntun_testing.scenario_io import (
    ScenarioInput,
    ScenarioInputError,
    load_scenario_inputs,
    read_scenario_input,
)

ROOT = Path(__file__).absolute().parents[3]
SCRIPT = ROOT / "scripts/run_scenarios.py"
PYTHON_PATH = os.pathsep.join(
    str(ROOT / path) for path in ("packages/testing/src", "packages/contracts/src", "apps/core/src")
)
CUSTOM_ROOT_CODE = (
    "import sys; from pathlib import Path; "
    "from scripts.run_scenarios import main; "
    "raise SystemExit(main(sys.argv[2:], _repository_root=Path(sys.argv[1])))"
)


def _environment(seed: str = "1", timezone: str = "UTC") -> dict[str, str]:
    environment = os.environ.copy()
    environment.update({"PYTHONHASHSEED": seed, "PYTHONPATH": PYTHON_PATH, "TZ": timezone})
    return environment


def _run(
    *arguments: str,
    seed: str = "1",
    timezone: str = "UTC",
    timeout: float = 120,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=ROOT,
        env=_environment(seed, timezone),
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _run_at(
    root: Path,
    *arguments: str,
    code: str = CUSTOM_ROOT_CODE,
    timeout: float = 20,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-c", code, str(root), *arguments],
        cwd=ROOT,
        env=_environment(),
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _yaml(name: str = "case") -> bytes:
    return (
        'schema_version: "1.0"\n'
        f"name: {name}\n"
        "identity: guest\n"
        "transcript: synthetic-namaste\n"
        "response: synthetic-welcome\n"
        "language: hinglish\n"
        "outcome: completed\n"
    ).encode()


def _canonical_line(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


def _gate_document(names: list[str], *, turns: int = 1) -> dict[str, object]:
    return {
        "b2": {
            "duplicate_effect_count": None,
            "peak_rss_growth_bytes": None,
            "privacy_block_p95_ms": None,
            "private_sentinel_count": None,
            "status": "not_measured",
            "terminal_rss_growth_bytes": None,
            "warmup_turns": None,
        },
        "foundation_resources": {
            "fd_after": None,
            "fd_baseline": None,
            "fd_delta": None,
            "pending_tasks_after": None,
            "pending_tasks_baseline": None,
            "pending_tasks_delta": None,
            "status": "not_measured",
        },
        "scenarios": [
            {"name": name, "result_chain_sha256": "0" * 64, "turns": turns}
            for name in names
        ],
        "schema_version": "scenario_gate.v1",
        "status": "pass",
    }


def _gate_child_bytes(configuration: dict[str, object], names: list[str]) -> bytes:
    document = _gate_document(names)
    invocation = configuration.get("invocation")
    if type(invocation) is not dict:
        return _canonical_line(document)
    return _canonical_line(
        {
            "document": document,
            "input_references": invocation["inputs"],
            "invocation_commitment": configuration["invocation_commitment"],
            "nonce": configuration["nonce"],
            "schema_version": "scenario_supervisor_envelope.v1",
        }
    )


def _load_runner_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_tuntun_task9_run_scenarios", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("runner-load-failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_json_is_canonical_and_process_deterministic() -> None:
    arguments = ("--turns", "2", "--assert-resource-bounds", "--json")
    first = _run(*arguments, seed="1", timezone="UTC")
    second = _run(*arguments, seed="98765", timezone="Asia/Singapore")
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == b""
    decoded = json.loads(first.stdout)
    assert set(decoded) == {
        "b2",
        "foundation_resources",
        "scenarios",
        "schema_version",
        "status",
    }
    assert decoded["schema_version"] == "scenario_gate.v1"
    assert decoded["status"] == "pass"
    assert decoded["b2"] == {
        "duplicate_effect_count": None,
        "peak_rss_growth_bytes": None,
        "privacy_block_p95_ms": None,
        "private_sentinel_count": None,
        "status": "not_measured",
        "terminal_rss_growth_bytes": None,
        "warmup_turns": None,
    }
    resources = decoded["foundation_resources"]
    assert set(resources) == {
        "fd_after",
        "fd_baseline",
        "fd_delta",
        "pending_tasks_after",
        "pending_tasks_baseline",
        "pending_tasks_delta",
        "status",
    }
    assert resources["status"] == "pass"
    assert resources["fd_delta"] == 0
    assert resources["pending_tasks_delta"] == 0
    assert len(decoded["scenarios"]) == 1
    assert set(decoded["scenarios"][0]) == {
        "name",
        "result_chain_sha256",
        "turns",
    }
    assert decoded["scenarios"][0] == {
        "name": "guest-hinglish",
        "result_chain_sha256": ("59477a0065a6700cbc68456ad3dcb7b33a7172403a16ea35b261940d8d7c9e40"),
        "turns": 2,
    }
    assert b"synthetic-" not in first.stdout
    assert b"transcript" not in first.stdout
    assert b"response" not in first.stdout
    assert canonical_mapping_bytes(decoded) + b"\n" == first.stdout


def test_supervisor_accepts_records_in_normalized_path_order(tmp_path: Path) -> None:
    first = tmp_path / "a" / "z-case.yaml"
    second = tmp_path / "b" / "a-case.yaml"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(_yaml("z-case"))
    second.write_bytes(_yaml("a-case"))

    result = _run_at(
        tmp_path,
        "--scenario",
        "a/z-case.yaml",
        "--scenario",
        "b/a-case.yaml",
        "--turns",
        "1",
        "--json",
    )

    assert result.returncode == 0
    assert result.stderr == b""
    assert [record["name"] for record in json.loads(result.stdout)["scenarios"]] == [
        "z-case",
        "a-case",
    ]


def test_core_simulate_command_runs_with_the_optional_workspace_package() -> None:
    code = """
import json
from typer.testing import CliRunner
from tuntun_core.cli.main import app
result = CliRunner().invoke(
    app,
    ["simulate", "--scenario", "tests/fixtures/scenarios/guest-hinglish.yaml", "--json"],
)
assert result.exit_code == 0, result.stderr
assert json.loads(result.stdout)["schema_version"] == "scenario_result.v1"
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=_environment(),
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0
    assert result.stdout == result.stderr == b""


def test_core_simulate_runs_in_child_without_mutating_parent_network_state() -> None:
    from typer.testing import CliRunner

    app = importlib.import_module("tuntun_core.cli.main").app
    original_socket = socket.socket
    original_getaddrinfo = socket.getaddrinfo
    result = CliRunner().invoke(
        app,
        ["simulate", "--scenario", "tests/fixtures/scenarios/guest-hinglish.yaml", "--json"],
    )
    assert result.exit_code == 0, result.stderr
    assert json.loads(result.stdout)["schema_version"] == "scenario_result.v1"
    assert socket.socket is original_socket
    assert socket.getaddrinfo is original_getaddrinfo
    probe = socket.socket()
    probe.close()
    assert socket.getaddrinfo("localhost", 0)


@pytest.mark.parametrize(
    "child_code",
    [
        "pass",
        "import os; os.write(1, b'not-json\\n')",
        "import os; os.write(1, b'\\xffprivate-output-sentinel\\n')",
    ],
)
def test_core_simulate_rejects_malformed_child_success_content_free(
    monkeypatch: pytest.MonkeyPatch,
    child_code: str,
) -> None:
    from typer.testing import CliRunner

    module = importlib.import_module("tuntun_core.cli.commands.simulate")
    app = importlib.import_module("tuntun_core.cli.main").app
    monkeypatch.setattr(module, "_SIMULATE_CHILD_CODE", child_code)

    result = CliRunner().invoke(
        app,
        ["simulate", "--scenario", "tests/fixtures/scenarios/guest-hinglish.yaml", "--json"],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr == "simulation-invalid-input\n"
    assert b"private-output-sentinel" not in result.stdout_bytes + result.stderr_bytes


def test_core_simulate_requires_exact_schema_and_canonical_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from typer.testing import CliRunner

    module = importlib.import_module("tuntun_core.cli.commands.simulate")
    app = importlib.import_module("tuntun_core.cli.main").app
    arguments = [
        "simulate",
        "--scenario",
        "tests/fixtures/scenarios/guest-hinglish.yaml",
        "--json",
    ]
    valid = CliRunner().invoke(app, arguments)
    assert valid.exit_code == 0
    document = json.loads(valid.stdout)
    wrong_schema = dict(document)
    wrong_schema["schema_version"] = "scenario_result.v2"
    payloads = (
        canonical_mapping_bytes(wrong_schema) + b"\n",
        json.dumps(document, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8") + b"\n",
    )

    for payload in payloads:
        monkeypatch.setattr(
            module,
            "_SIMULATE_CHILD_CODE",
            f"import os; os.write(1, bytes.fromhex('{payload.hex()}'))",
        )
        result = CliRunner().invoke(app, arguments)

        assert result.exit_code == 2
        assert result.stdout == ""
        assert result.stderr == "simulation-invalid-input\n"


def test_core_simulate_rejects_bound_envelope_with_substituted_scenario(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from typer.testing import CliRunner

    module = importlib.import_module("tuntun_core.cli.commands.simulate")
    app = importlib.import_module("tuntun_core.cli.main").app
    arguments = [
        "simulate",
        "--scenario",
        "tests/fixtures/scenarios/guest-hinglish.yaml",
        "--json",
    ]
    valid = CliRunner().invoke(app, arguments)
    assert valid.exit_code == 0
    document = json.loads(valid.stdout)
    document["scenario"] = "substituted"
    public_line = _canonical_line(document)
    monkeypatch.setattr(
        module,
        "_SIMULATE_CHILD_CODE",
        f"""
import json
import os
import signal
import sys

raw = sys.stdin.buffer.readline()
if not raw:
    os.write(1, bytes.fromhex("{public_line.hex()}"))
else:
    configuration = json.loads(raw)
    envelope = {{
        "document": {document!r},
        "input_reference": configuration["invocation"]["input"],
        "invocation_commitment": configuration["invocation_commitment"],
        "nonce": configuration["nonce"],
        "schema_version": "simulation_supervisor_envelope.v1",
    }}
    sys.stdout.write(json.dumps(envelope, separators=(",", ":"), sort_keys=True) + "\\n")
    sys.stdout.flush()
    signal.pause()
""",
    )

    result = CliRunner().invoke(app, arguments)

    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr == "simulation-invalid-input\n"


def test_core_simulate_rejects_forged_plain_text_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from typer.testing import CliRunner

    module = importlib.import_module("tuntun_core.cli.commands.simulate")
    app = importlib.import_module("tuntun_core.cli.main").app
    monkeypatch.setattr(module, "_SIMULATE_CHILD_CODE", "print('simulation: PASS')")

    result = CliRunner().invoke(
        app,
        ["simulate", "--scenario", "tests/fixtures/scenarios/guest-hinglish.yaml"],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr == "simulation-invalid-input\n"


def test_core_simulate_runtime_deadline_is_bounded_and_content_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from typer.testing import CliRunner

    module = importlib.import_module("tuntun_core.cli.commands.simulate")
    app = importlib.import_module("tuntun_core.cli.main").app
    monkeypatch.setattr(module, "_SIMULATE_CHILD_CODE", "import time; time.sleep(2)")
    monkeypatch.setattr(module, "_SIMULATION_TIMEOUT_SECONDS", 0.05, raising=False)

    started = time.monotonic()
    result = CliRunner().invoke(
        app,
        ["simulate", "--scenario", "tests/fixtures/scenarios/guest-hinglish.yaml", "--json"],
    )
    elapsed = time.monotonic() - started

    assert elapsed < 1.0
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr == "simulation-invalid-input\n"


@pytest.mark.parametrize(
    ("code", "sentinel"),
    [
        (
            "after=lambda: (_ for _ in ()).throw(SystemExit('private-after-guard-sentinel')); "
            "raise SystemExit(main(sys.argv[2:], _repository_root=Path(sys.argv[1]), "
            "_after_guard=after))",
            b"private-after-guard-sentinel",
        ),
        (
            "observer=lambda _: (_ for _ in ()).throw(SystemExit('private-execution-sentinel')); "
            "raise SystemExit(main(sys.argv[2:], _repository_root=Path(sys.argv[1]), "
            "_turn_observer=observer))",
            b"private-execution-sentinel",
        ),
    ],
)
def test_private_main_seams_suppress_baseexception_messages(
    code: str,
    sentinel: bytes,
) -> None:
    result = _run_at(
        ROOT,
        "--turns",
        "1",
        "--json",
        code=(
            f"import sys; from pathlib import Path; from scripts.run_scenarios import main; {code}"
        ),
    )
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"scenario-gate: failed\n"
    assert sentinel not in result.stdout + result.stderr


def test_resource_gate_counts_fd_leaks_from_warmup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_testing.scenario as scenario_module

    runner = _load_runner_module()
    original_runner = scenario_module.ScenarioRunner
    held_descriptors: list[int] = []
    call_count = 0

    class LeakyRunner:
        async def run_async(self, value: ScenarioInput, *, turn_index: int = 0) -> object:
            nonlocal call_count
            if call_count == 0:
                held_descriptors.append(os.open("/dev/null", os.O_RDONLY))
            call_count += 1
            return await original_runner().run_async(value, turn_index=turn_index)

    monkeypatch.setattr(scenario_module, "ScenarioRunner", LeakyRunner)
    value = read_scenario_input(
        Path("tests/fixtures/scenarios/guest-hinglish.yaml"),
        trusted_root=ROOT,
    )
    try:
        with pytest.raises(AssertionError, match="resource-bound-failed"):
            asyncio.run(runner._execute((value,), 1, True, None))
    finally:
        for descriptor in held_descriptors:
            os.close(descriptor)


def test_resource_gate_counts_task_leaks_from_warmup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_testing.scenario as scenario_module

    runner = _load_runner_module()
    original_runner = scenario_module.ScenarioRunner
    held_tasks: list[asyncio.Task[object]] = []
    call_count = 0

    class LeakyRunner:
        async def run_async(self, value: ScenarioInput, *, turn_index: int = 0) -> object:
            nonlocal call_count
            if call_count == 0:
                held_tasks.append(asyncio.create_task(asyncio.Event().wait()))
            call_count += 1
            return await original_runner().run_async(value, turn_index=turn_index)

    async def run_case() -> None:
        value = read_scenario_input(
            Path("tests/fixtures/scenarios/guest-hinglish.yaml"),
            trusted_root=ROOT,
        )
        try:
            with pytest.raises(AssertionError, match="resource-bound-failed"):
                await runner._execute((value,), 1, True, None)
        finally:
            for task in held_tasks:
                task.cancel()
            await asyncio.gather(*held_tasks, return_exceptions=True)

    monkeypatch.setattr(scenario_module, "ScenarioRunner", LeakyRunner)
    asyncio.run(run_case())


def test_resource_gate_checks_fd_bounds_immediately_after_warmup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_testing.scenario as scenario_module

    runner = _load_runner_module()
    original_runner = scenario_module.ScenarioRunner
    held_descriptors: list[int] = []
    call_count = 0

    class WarmupCleanupRunner:
        async def run_async(self, value: ScenarioInput, *, turn_index: int = 0) -> object:
            nonlocal call_count
            if call_count == 0:
                held_descriptors.append(os.open("/dev/null", os.O_RDONLY))
            elif call_count == 1:
                os.close(held_descriptors.pop())
            call_count += 1
            return await original_runner().run_async(value, turn_index=turn_index)

    monkeypatch.setattr(scenario_module, "ScenarioRunner", WarmupCleanupRunner)
    value = read_scenario_input(
        Path("tests/fixtures/scenarios/guest-hinglish.yaml"),
        trusted_root=ROOT,
    )
    try:
        with pytest.raises(AssertionError, match="resource-bound-failed"):
            asyncio.run(runner._execute((value,), 1, True, None))
        assert call_count == 1
    finally:
        for descriptor in held_descriptors:
            os.close(descriptor)


def test_resource_gate_checks_task_bounds_immediately_after_warmup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_testing.scenario as scenario_module

    runner = _load_runner_module()
    original_runner = scenario_module.ScenarioRunner
    held_tasks: list[asyncio.Task[object]] = []
    call_count = 0

    class WarmupCleanupRunner:
        async def run_async(self, value: ScenarioInput, *, turn_index: int = 0) -> object:
            nonlocal call_count
            if call_count == 0:
                held_tasks.append(asyncio.create_task(asyncio.Event().wait()))
            elif call_count == 1:
                held_tasks[0].cancel()
                await asyncio.gather(*held_tasks, return_exceptions=True)
                held_tasks.clear()
            call_count += 1
            return await original_runner().run_async(value, turn_index=turn_index)

    async def run_case() -> None:
        value = read_scenario_input(
            Path("tests/fixtures/scenarios/guest-hinglish.yaml"),
            trusted_root=ROOT,
        )
        try:
            with pytest.raises(AssertionError, match="resource-bound-failed"):
                await runner._execute((value,), 1, True, None)
            assert call_count == 1
        finally:
            for task in held_tasks:
                task.cancel()
            await asyncio.gather(*held_tasks, return_exceptions=True)

    monkeypatch.setattr(scenario_module, "ScenarioRunner", WarmupCleanupRunner)
    asyncio.run(run_case())


def test_ambient_child_marker_does_not_skip_the_supervisor() -> None:
    environment = _environment()
    environment["TUNTUN_SCENARIO_CHILD"] = "1"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--turns", "1", "--json"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0
    assert result.stderr == b""
    assert json.loads(result.stdout)["schema_version"] == "scenario_gate.v1"


def test_child_argument_without_matching_environment_is_normal_invalid_input() -> None:
    environment = _environment()
    environment["TUNTUN_SCENARIO_CHILD"] = "b" * 64
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--tuntun-scenario-child", "a" * 64],
        cwd=ROOT,
        env=environment,
        input=b"malformed-child-configuration",
        capture_output=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr == b"scenario-gate: invalid-input\n"


@pytest.mark.parametrize("mutation", ["omission", "substitution", "reordering"])
def test_scenario_supervisor_binds_records_to_exact_requested_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    (tmp_path / "first.yaml").write_bytes(_yaml("first"))
    (tmp_path / "second.yaml").write_bytes(_yaml("second"))
    runner = _load_runner_module()

    def fake_process(
        command: Sequence[str],
        *,
        payload: bytes,
        cwd: Path,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment
        configuration = json.loads(payload)
        names = ["first", "second"]
        if mutation == "omission":
            names = names[:1]
        elif mutation == "substitution":
            names[0] = "substituted"
        else:
            names.reverse()
        return subprocess.CompletedProcess(command, 0, _gate_child_bytes(configuration, names), b"")

    monkeypatch.setattr(runner, "_run_bounded_process", fake_process)
    result = runner._run_gate_child(
        (
            "--scenario",
            "first.yaml",
            "--scenario",
            "second.yaml",
            "--turns",
            "1",
            "--json",
        ),
        tmp_path,
    )
    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ""
    assert captured.err == "scenario-gate: failed\n"


def test_scenario_supervisor_rejects_replayed_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "case.yaml").write_bytes(_yaml("case"))
    runner = _load_runner_module()
    saved: list[bytes] = []

    def replaying_process(
        command: Sequence[str],
        *,
        payload: bytes,
        cwd: Path,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment
        if not saved:
            saved.append(_gate_child_bytes(json.loads(payload), ["case"]))
        return subprocess.CompletedProcess(command, 0, saved[0], b"")

    monkeypatch.setattr(runner, "_run_bounded_process", replaying_process)
    arguments = ("--scenario", "case.yaml", "--turns", "1", "--json")

    first = runner._run_gate_child(arguments, tmp_path)
    first_output = capsys.readouterr()
    second = runner._run_gate_child(arguments, tmp_path)
    second_output = capsys.readouterr()

    assert first == 0
    assert json.loads(first_output.out)["schema_version"] == "scenario_gate.v1"
    assert first_output.err == ""
    assert second == 1
    assert second_output.out == ""
    assert second_output.err == "scenario-gate: failed\n"


def test_scenario_supervisor_rejects_forged_plain_text_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "case.yaml").write_bytes(_yaml("case"))
    runner = _load_runner_module()
    monkeypatch.setattr(
        runner,
        "_run_bounded_process",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            0,
            b"scenario-gate: PASS\n",
            b"",
        ),
    )

    result = runner._run_gate_child(("--scenario", "case.yaml", "--turns", "1"), tmp_path)
    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ""
    assert captured.err == "scenario-gate: failed\n"


def test_maximum_declared_scenario_set_fits_bounded_child_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = _load_runner_module()
    for index in range(32):
        name = f"case-{index:02d}"
        prefix = _yaml(name)
        raw = prefix + b"#" + (b"x" * (65_536 - len(prefix) - 2)) + b"\n"
        assert len(raw) == 65_536
        (tmp_path / f"{name}.yaml").write_bytes(raw)
    captured_payloads: list[bytes] = []

    def fake_process(
        command: Sequence[str],
        *,
        payload: bytes,
        cwd: Path,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd
        assert environment == {}
        captured_payloads.append(payload)
        return subprocess.CompletedProcess(command, 1, b"", b"")

    monkeypatch.setattr(runner, "_run_bounded_process", fake_process)
    arguments = [
        item
        for index in range(32)
        for item in ("--scenario", f"case-{index:02d}.yaml")
    ]
    result = runner._run_gate_child((*arguments, "--turns", "1", "--json"), tmp_path)
    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ""
    assert captured.err == "scenario-gate: failed\n"
    assert len(captured_payloads) == 1
    assert 1_048_576 < len(captured_payloads[0]) <= runner._MAX_CHILD_CONFIGURATION_BYTES


@pytest.mark.parametrize(
    "mutation",
    ["nonce-type", "commitment-type", "path-escape", "digest-type", "raw-type"],
)
def test_gate_child_configuration_validates_exact_field_types_and_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    runner = _load_runner_module()
    (tmp_path / "case.yaml").write_bytes(_yaml("case"))
    prepared = runner._prepare_gate_invocation(
        ("--scenario", "case.yaml", "--turns", "1", "--json"),
        tmp_path,
    )
    nonce = "a" * 64
    configuration: dict[str, Any] = {
        "inputs": [
            {
                **prepared.input_references[0],
                "raw_b64": base64.b64encode(prepared.inputs[0].raw).decode("ascii"),
            }
        ],
        "invocation": prepared.invocation,
        "invocation_commitment": prepared.invocation_commitment,
        "nonce": nonce,
        "schema_version": "scenario_child_config.v1",
    }
    if mutation == "nonce-type":
        configuration["nonce"] = 7
    elif mutation == "commitment-type":
        configuration["invocation_commitment"] = [prepared.invocation_commitment]
    elif mutation == "path-escape":
        reference = configuration["invocation"]["inputs"][0]
        reference["path"] = "../case.yaml"
        configuration["inputs"][0]["path"] = "../case.yaml"
        configuration["invocation_commitment"] = sha256(
            runner._canonical_bytes(configuration["invocation"])
        ).hexdigest()
    elif mutation == "digest-type":
        configuration["invocation"]["inputs"][0]["content_sha256"] = 7
        configuration["inputs"][0]["content_sha256"] = 7
        configuration["invocation_commitment"] = sha256(
            runner._canonical_bytes(configuration["invocation"])
        ).hexdigest()
    else:
        configuration["inputs"][0]["raw_b64"] = 7
    stream = io.TextIOWrapper(io.BytesIO(_canonical_line(configuration)))
    monkeypatch.setattr(runner.sys, "stdin", stream)

    assert runner._child_main_from_stdin(nonce) == 1


@pytest.mark.parametrize(
    "mutation",
    ["nonce-type", "commitment-type", "path-escape", "digest-type", "raw-type"],
)
def test_simulation_child_configuration_validates_exact_field_types_and_bounds(
    mutation: str,
) -> None:
    module = importlib.import_module("tuntun_core.cli.commands.simulate")
    scenario = Path("tests/fixtures/scenarios/guest-hinglish.yaml")
    prepared = module._prepare_simulation_invocation(
        scenario,
        json_output=True,
        repository_root=ROOT,
    )
    nonce = "a" * 64
    configuration: dict[str, Any] = {
        "input": {
            **prepared.input_reference,
            "raw_b64": base64.b64encode(prepared.raw).decode("ascii"),
        },
        "invocation": prepared.invocation,
        "invocation_commitment": prepared.invocation_commitment,
        "nonce": nonce,
        "schema_version": "simulation_child_config.v1",
    }
    if mutation == "nonce-type":
        configuration["nonce"] = 7
    elif mutation == "commitment-type":
        configuration["invocation_commitment"] = [prepared.invocation_commitment]
    elif mutation == "path-escape":
        reference = configuration["invocation"]["input"]
        reference["path"] = "../guest-hinglish.yaml"
        configuration["input"]["path"] = "../guest-hinglish.yaml"
        configuration["invocation_commitment"] = sha256(
            module._canonical_bytes(configuration["invocation"])
        ).hexdigest()
    elif mutation == "digest-type":
        configuration["invocation"]["input"]["content_sha256"] = 7
        configuration["input"]["content_sha256"] = 7
        configuration["invocation_commitment"] = sha256(
            module._canonical_bytes(configuration["invocation"])
        ).hexdigest()
    else:
        configuration["input"]["raw_b64"] = 7

    if mutation == "nonce-type":
        with pytest.raises(ValueError, match="invalid-child-configuration"):
            module._run_simulation_child(
                repository_root=ROOT,
                configuration=module._canonical_bytes(configuration),
            )
        return
    result = module._run_simulation_child(
        repository_root=ROOT,
        configuration=module._canonical_bytes(configuration),
    )

    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"simulation-invalid-input\n"


@pytest.mark.parametrize("target", ["runner", "simulate"])
def test_success_path_terminates_descendants_holding_flock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    lock_path = tmp_path / f"{target}.lock"
    pid_path = tmp_path / f"{target}.pid"
    child_code = f"""
import fcntl
import os
import time
from pathlib import Path

pid = os.fork()
if pid == 0:
    handle = open({str(lock_path)!r}, "w")
    fcntl.flock(handle, fcntl.LOCK_EX)
    Path({str(pid_path)!r}).write_text(str(os.getpid()), encoding="utf-8")
    time.sleep(30)
    os._exit(0)
while not Path({str(pid_path)!r}).exists():
    time.sleep(0.01)
os.write(1, b"complete\\n")
"""
    runner = _load_runner_module()
    module = importlib.import_module("tuntun_core.cli.commands.simulate")
    try:
        if target == "runner":
            runner._run_bounded_process(
                (sys.executable, "-I", "-S", "-c", child_code),
                payload=b"{}",
                cwd=ROOT,
                environment={},
            )
        else:
            monkeypatch.setattr(module, "_SIMULATE_CHILD_CODE", child_code)
            parameters = importlib.import_module("inspect").signature(
                module._run_simulation_child
            ).parameters
            kwargs: dict[str, object] = {"repository_root": ROOT}
            if "configuration" in parameters:
                kwargs["configuration"] = _canonical_line({"nonce": "a" * 64})[:-1]
            else:
                kwargs["environment"] = {}
            module._run_simulation_child(**kwargs)

        with lock_path.open("a") as probe:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(probe, fcntl.LOCK_UN)
    finally:
        if pid_path.exists():
            with suppress(ProcessLookupError):
                os.kill(int(pid_path.read_text(encoding="utf-8")), signal.SIGKILL)


@pytest.mark.parametrize(
    "startup_code",
    [
        "print('unexpected-startup-output')",
        "import os; os.write(1, b'\\xffprivate-output-sentinel\\n')",
        "import os; os.write(1, b'x' * 70000)",
    ],
)
def test_scenario_supervisor_rejects_malformed_or_oversized_child_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    startup_code: str,
) -> None:
    runner = _load_runner_module()
    monkeypatch.setattr(runner, "_CHILD_BOOTSTRAP", startup_code)
    result = runner._run_gate_child(("--turns", "1", "--json"), ROOT)
    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ""
    assert captured.err == "scenario-gate: failed\n"
    assert "private-output-sentinel" not in captured.out + captured.err


def test_scenario_supervisor_requires_exact_schema_and_canonical_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    valid = _run("--turns", "1", "--json")
    assert valid.returncode == 0
    document = json.loads(valid.stdout)
    wrong_schema = dict(document)
    wrong_schema["schema_version"] = "scenario_gate.v2"
    runner = _load_runner_module()
    responses = ((wrong_schema, True), (document, False))

    for child_document, canonical in responses:
        def fake_process(
            command: Sequence[str],
            *,
            payload: bytes,
            cwd: Path,
            environment: dict[str, str],
            _child_document: object = child_document,
            _canonical: bool = canonical,
        ) -> subprocess.CompletedProcess[bytes]:
            del cwd, environment
            configuration = json.loads(payload)
            envelope = {
                "document": _child_document,
                "input_references": configuration["invocation"]["inputs"],
                "invocation_commitment": configuration["invocation_commitment"],
                "nonce": configuration["nonce"],
                "schema_version": "scenario_supervisor_envelope.v1",
            }
            output = (
                _canonical_line(envelope)
                if _canonical
                else json.dumps(envelope, indent=1, sort_keys=True).encode("utf-8") + b"\n"
            )
            return subprocess.CompletedProcess(command, 0, output, b"")

        monkeypatch.setattr(runner, "_run_bounded_process", fake_process)
        result = runner._run_gate_child(("--turns", "1", "--json"), ROOT)
        captured = capsys.readouterr()

        assert result == 1
        assert captured.out == ""
        assert captured.err == "scenario-gate: failed\n"


def test_scenario_supervisor_runtime_deadline_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = _load_runner_module()
    monkeypatch.setattr(runner, "_CHILD_BOOTSTRAP", "import time; time.sleep(2)")
    monkeypatch.setattr(runner, "_CHILD_TIMEOUT_SECONDS", 0.05, raising=False)

    started = time.monotonic()
    result = runner._run_gate_child(("--turns", "1", "--json"), ROOT)
    elapsed = time.monotonic() - started
    captured = capsys.readouterr()

    assert elapsed < 1.0
    assert result == 1
    assert captured.out == ""
    assert captured.err == "scenario-gate: failed\n"


@pytest.mark.parametrize(
    ("turns", "expected"),
    [("0", 2), ("1", 0), ("10000", 0), ("10001", 2)],
)
def test_turn_bounds_are_executed_or_rejected(turns: str, expected: int) -> None:
    result = _run("--turns", turns, "--json", timeout=180)
    assert result.returncode == expected
    if expected == 0:
        assert json.loads(result.stdout)["scenarios"][0]["turns"] == int(turns)
    else:
        assert result.stdout == b""
        assert result.stderr == b"scenario-gate: invalid-input\n"


def test_aggregate_turn_cap_accepts_10000_and_rejects_10002(tmp_path: Path) -> None:
    (tmp_path / "first.yaml").write_bytes(_yaml("first"))
    (tmp_path / "second.yaml").write_bytes(_yaml("second"))
    arguments = (
        "--scenario",
        "first.yaml",
        "--scenario",
        "second.yaml",
        "--turns",
    )
    accepted = _run_at(tmp_path, *arguments, "5000", "--json", timeout=180)
    assert accepted.returncode == 0
    assert [item["turns"] for item in json.loads(accepted.stdout)["scenarios"]] == [
        5000,
        5000,
    ]
    rejected = _run_at(tmp_path, *arguments, "5001", "--json")
    assert rejected.returncode == 2
    assert rejected.stdout == b""
    assert rejected.stderr == b"scenario-gate: invalid-input\n"


def test_descriptor_reader_rejects_escape_links_fifo_duplicates_and_hardlinks(
    tmp_path: Path,
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    scenario = trusted / "case.yaml"
    scenario.write_bytes(_yaml())
    outside = tmp_path / "outside.yaml"
    outside.write_bytes(_yaml("outside"))
    terminal_target = trusted / "terminal-target.data"
    terminal_target.write_bytes(_yaml("terminal"))
    terminal_link = trusted / "terminal.yaml"
    terminal_link.symlink_to(terminal_target)
    real_directory = trusted / "real"
    real_directory.mkdir()
    (real_directory / "nested.yaml").write_bytes(_yaml("nested"))
    parent_link = trusted / "linked"
    parent_link.symlink_to(real_directory, target_is_directory=True)
    fifo = trusted / "fifo.yaml"
    os.mkfifo(fifo)
    duplicate = _run_at(
        trusted,
        "--scenario",
        "case.yaml",
        "--scenario",
        str(scenario),
        "--turns",
        "1",
        "--json",
    )
    assert duplicate.returncode == 2
    hardlink = trusted / "hardlink.yaml"
    os.link(scenario, hardlink)
    candidates = (
        "../outside.yaml",
        "terminal.yaml",
        "linked/nested.yaml",
        "fifo.yaml",
        "case.yaml",
        "hardlink.yaml",
    )
    for candidate in candidates:
        result = _run_at(trusted, "--scenario", candidate, "--turns", "1", "--json")
        assert result.returncode == 2
        assert result.stdout == b""
        assert result.stderr == b"scenario-gate: invalid-input\n"


def test_size_encoding_and_yaml_ambiguity_are_bounded(tmp_path: Path) -> None:
    alias = _yaml("alias").replace(
        b"transcript: synthetic-namaste\nresponse: synthetic-welcome\n",
        b"transcript: &text synthetic-namaste\nresponse: *text\n",
    )
    cases = {
        "malformed.yaml": b"schema_version: [\n",
        "nonutf8.yaml": b"\xff",
        "alias.yaml": alias,
        "tag.yaml": _yaml("tag").replace(b'"1.0"', b"!!str '1.0'"),
        "directive.yaml": b"%YAML 1.2\n---\n" + _yaml("directive"),
        "duplicate.yaml": _yaml("duplicate").replace(
            b"name: duplicate\n",
            b"name: duplicate\nname: duplicate\n",
        ),
        "surrogate.yaml": _yaml("surrogate").replace(b"synthetic-namaste", b'"synthetic-\\uD800"'),
        "integer.yaml": _yaml("integer").replace(b"synthetic-namaste", b"9" * 5_000),
        "timestamp.yaml": _yaml("timestamp").replace(b"synthetic-namaste", b"2026-99-99"),
        "version.yaml": _yaml("version").replace(b'"1.0"', b'"2.0"'),
        "oversized.yaml": b"#" * 65_537,
    }
    for name, raw in cases.items():
        (tmp_path / name).write_bytes(raw)
        result = _run_at(tmp_path, "--scenario", name, "--turns", "1", "--json")
        assert result.returncode == 2
        assert result.stdout == b""
        assert b"synthetic-" not in result.stderr
    exact = _yaml("exact")
    exact += b"#" + b"x" * (65_536 - len(exact) - 2) + b"\n"
    assert len(exact) == 65_536
    (tmp_path / "exact.yaml").write_bytes(exact)
    accepted = _run_at(tmp_path, "--scenario", "exact.yaml", "--turns", "1", "--json")
    assert accepted.returncode == 0
    with pytest.raises(ScenarioInputError, match="invalid-scenario-input"):
        read_scenario_input(Path("oversized.yaml"), trusted_root=tmp_path)


@pytest.mark.parametrize("mutation", ["grow", "truncate"])
def test_descriptor_reader_rejects_file_growth_or_truncation_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    scenario = tmp_path / "case.yaml"
    original = _yaml()
    scenario.write_bytes(original)
    original_read = os.read
    mutated = False

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        if not mutated:
            mutated = True
            if mutation == "grow":
                with scenario.open("ab") as handle:
                    handle.write(b"# growth\n")
            else:
                scenario.write_bytes(original[: max(1, len(original) // 2)])
        return original_read(descriptor, size)

    monkeypatch.setattr(os, "read", mutating_read)
    with pytest.raises(ScenarioInputError, match="invalid-scenario-input"):
        read_scenario_input(Path("case.yaml"), trusted_root=tmp_path)


def test_default_inventory_rejects_mutation_during_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "scenarios"
    directory.mkdir()
    (directory / "case.yaml").write_bytes(_yaml())
    original_snapshot = scenario_io._directory_snapshot
    calls = 0

    def changing_snapshot(descriptor: int) -> scenario_io._DirectorySnapshot:
        nonlocal calls
        snapshot = original_snapshot(descriptor)
        calls += 1
        if calls == 1:
            (directory / "added.yaml").write_bytes(_yaml("added"))
        return snapshot

    monkeypatch.setattr(scenario_io, "_directory_snapshot", changing_snapshot)
    with pytest.raises(ScenarioInputError, match="invalid-scenario-input"):
        load_scenario_inputs(
            (),
            trusted_root=tmp_path,
            default_directory=Path("scenarios"),
        )


def test_default_inventory_rejects_same_name_directory_replacement_mid_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "scenarios"
    directory.mkdir()
    for name in ("first", "second"):
        (directory / f"{name}.yaml").write_bytes(_yaml(name))
    moved = tmp_path / "original-scenarios"
    original_reader = scenario_io._read_scenario_child
    calls = 0

    def replacing_reader(
        parent_descriptor: int,
        name: str,
        normalized_name: str,
        *,
        max_bytes: int,
        expected_identity: tuple[int, int, int, int, int, int] | None = None,
    ) -> ScenarioInput:
        nonlocal calls
        result = original_reader(
            parent_descriptor,
            name,
            normalized_name,
            max_bytes=max_bytes,
            expected_identity=expected_identity,
        )
        calls += 1
        if calls == 1:
            directory.rename(moved)
            directory.mkdir()
            for replacement_name in ("first", "second"):
                replacement = _yaml(replacement_name).replace(
                    b"synthetic-namaste",
                    b"synthetic-replacement",
                )
                (directory / f"{replacement_name}.yaml").write_bytes(replacement)
        return result

    monkeypatch.setattr(scenario_io, "_read_scenario_child", replacing_reader)
    with pytest.raises(ScenarioInputError, match="invalid-scenario-input"):
        load_scenario_inputs(
            (),
            trusted_root=tmp_path,
            default_directory=Path("scenarios"),
        )


@pytest.mark.parametrize(
    "directory",
    [Path("missing"), Path(os.fsdecode(b"invalid-\xff"))],
)
def test_default_inventory_normalizes_path_and_open_errors(
    tmp_path: Path,
    directory: Path,
) -> None:
    with pytest.raises(ScenarioInputError, match="invalid-scenario-input"):
        load_scenario_inputs(
            (),
            trusted_root=tmp_path,
            default_directory=directory,
        )


def test_scenario_count_cap_accepts_32_and_rejects_33(tmp_path: Path) -> None:
    directory = tmp_path / "scenarios"
    directory.mkdir()
    paths: list[Path] = []
    for index in range(32):
        relative = Path("scenarios") / f"case-{index:02}.yaml"
        (tmp_path / relative).write_bytes(_yaml(f"case-{index:02}"))
        paths.append(relative)
    assert (
        len(
            load_scenario_inputs(
                paths,
                trusted_root=tmp_path,
                default_directory=Path("scenarios"),
            )
        )
        == len(
            load_scenario_inputs(
                (),
                trusted_root=tmp_path,
                default_directory=Path("scenarios"),
            )
        )
        == 32
    )
    extra = Path("scenarios/case-32.yaml")
    (tmp_path / extra).write_bytes(_yaml("case-32"))
    with pytest.raises(ScenarioInputError, match="invalid-scenario-input"):
        load_scenario_inputs(
            (*paths, extra),
            trusted_root=tmp_path,
            default_directory=Path("scenarios"),
        )
    with pytest.raises(ScenarioInputError, match="invalid-scenario-input"):
        load_scenario_inputs(
            (),
            trusted_root=tmp_path,
            default_directory=Path("scenarios"),
        )


def test_surrogateescaped_filename_is_invalid_input_not_an_assertion(tmp_path: Path) -> None:
    invalid_name = os.fsdecode(b"invalid-\xff.yaml")
    result = _run_at(
        tmp_path,
        "--scenario",
        invalid_name,
        "--turns",
        "1",
        "--json",
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr == b"scenario-gate: invalid-input\n"


def test_loader_rejects_casefold_logical_collision_on_every_platform(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = iter(
        (
            ScenarioInput("a/case.yaml", _yaml(), 1, 1),
            ScenarioInput("A/CASE.yaml", _yaml(), 1, 2),
        )
    )

    def scripted_reader(path: Path, *, trusted_root: Path) -> ScenarioInput:
        assert path in {Path("first.yaml"), Path("second.yaml")}
        assert trusted_root == tmp_path
        return next(values)

    monkeypatch.setattr(scenario_io, "read_scenario_input", scripted_reader)
    with pytest.raises(ScenarioInputError, match="invalid-scenario-input"):
        load_scenario_inputs(
            (Path("first.yaml"), Path("second.yaml")),
            trusted_root=tmp_path,
            default_directory=Path("unused"),
        )


def test_loader_rejects_duplicate_logical_scenario_names(tmp_path: Path) -> None:
    paths = (Path("a/case.yaml"), Path("b/case.yaml"))
    for path in paths:
        target = tmp_path / path
        target.parent.mkdir()
        target.write_bytes(_yaml())
    with pytest.raises(ScenarioInputError, match="invalid-scenario-input"):
        load_scenario_inputs(
            paths,
            trusted_root=tmp_path,
            default_directory=Path("unused"),
        )


@pytest.mark.parametrize(
    "hook",
    [
        "import socket; after=lambda: socket.socket()",
        "import socket; after=lambda: socket.getaddrinfo('example.invalid', 443)",
    ],
)
def test_network_and_dns_are_denied_after_guard(tmp_path: Path, hook: str) -> None:
    scenario = tmp_path / "case.yaml"
    scenario.write_bytes(_yaml())
    code = (
        f"{hook}; import sys; from pathlib import Path; "
        "from scripts.run_scenarios import main; "
        "raise SystemExit(main(sys.argv[2:], _repository_root=Path(sys.argv[1]), "
        "_after_guard=after))"
    )
    result = _run_at(
        tmp_path,
        "--scenario",
        "case.yaml",
        "--turns",
        "1",
        "--json",
        code=code,
    )
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"scenario-gate: failed\n"


@pytest.mark.parametrize(
    "observer",
    [
        "held=[]; observer=lambda _: held.append(os.open('/dev/null', os.O_RDONLY))",
        "held=[]; observer=lambda _: held.append(asyncio.create_task(asyncio.Event().wait()))",
    ],
)
def test_resource_gate_detects_fd_or_task_leaks(tmp_path: Path, observer: str) -> None:
    (tmp_path / "case.yaml").write_bytes(_yaml())
    code = (
        f"import asyncio, os, sys; {observer}; from pathlib import Path; "
        "from scripts.run_scenarios import main; "
        "raise SystemExit(main(sys.argv[2:], _repository_root=Path(sys.argv[1]), "
        "_turn_observer=observer))"
    )
    result = _run_at(
        tmp_path,
        "--scenario",
        "case.yaml",
        "--turns",
        "1",
        "--assert-resource-bounds",
        "--json",
        code=code,
    )
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"scenario-gate: failed\n"


def test_invalid_private_content_is_never_echoed(tmp_path: Path) -> None:
    sentinel = b"synthetic-private-sentinel-9381"
    valid = _yaml("private-valid").replace(b"synthetic-namaste", sentinel)
    (tmp_path / "private-valid.yaml").write_bytes(valid)
    accepted = _run_at(
        tmp_path,
        "--scenario",
        "private-valid.yaml",
        "--turns",
        "1",
        "--json",
    )
    assert accepted.returncode == 0
    assert sentinel not in accepted.stdout + accepted.stderr
    (tmp_path / "private-invalid.yaml").write_bytes(b"invalid: " + sentinel + b"\n")
    rejected = _run_at(
        tmp_path,
        "--scenario",
        "private-invalid.yaml",
        "--turns",
        "1",
        "--json",
    )
    assert rejected.returncode == 2
    assert sentinel not in rejected.stdout + rejected.stderr
