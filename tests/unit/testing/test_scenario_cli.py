from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

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


def _load_runner_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_tuntun_task9_run_scenarios", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("runner-load-failed")
    module = importlib.util.module_from_spec(spec)
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


@pytest.mark.parametrize(
    "startup_code",
    [
        "print('unexpected-startup-output')",
        "import os; os.write(1, b'\\xffprivate-output-sentinel\\n')",
        "import os; os.write(1, b'x' * 70000)",
    ],
)
def test_scenario_supervisor_rejects_malformed_or_oversized_child_output(
    tmp_path: Path,
    startup_code: str,
) -> None:
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "sitecustomize.py").write_text(
        (f"import os\nif os.environ.get('TUNTUN_SCENARIO_CHILD'):\n    {startup_code}\n"),
        encoding="utf-8",
    )
    environment = _environment()
    environment["PYTHONPATH"] = os.pathsep.join((str(shadow), PYTHON_PATH))

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--turns", "1", "--json"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"scenario-gate: failed\n"
    assert b"private-output-sentinel" not in result.stdout + result.stderr


def test_scenario_supervisor_requires_exact_schema_and_canonical_json(tmp_path: Path) -> None:
    valid = _run("--turns", "1", "--json")
    assert valid.returncode == 0
    document = json.loads(valid.stdout)
    wrong_schema = dict(document)
    wrong_schema["schema_version"] = "scenario_gate.v2"
    payloads = (
        canonical_mapping_bytes(wrong_schema) + b"\n",
        json.dumps(document, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8") + b"\n",
    )

    for index, payload in enumerate(payloads):
        shadow = tmp_path / f"shadow-{index}"
        shadow.mkdir()
        (shadow / "sitecustomize.py").write_text(
            (
                "import os\n"
                "if os.environ.get('TUNTUN_SCENARIO_CHILD'):\n"
                f"    os.write(1, bytes.fromhex('{payload.hex()}'))\n"
                "    os._exit(0)\n"
            ),
            encoding="utf-8",
        )
        environment = _environment()
        environment["PYTHONPATH"] = os.pathsep.join((str(shadow), PYTHON_PATH))

        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--turns", "1", "--json"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            check=False,
            timeout=20,
        )

        assert result.returncode == 1
        assert result.stdout == b""
        assert result.stderr == b"scenario-gate: failed\n"


def test_scenario_supervisor_runtime_deadline_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "sitecustomize.py").write_text(
        "import os, time\nif os.environ.get('TUNTUN_SCENARIO_CHILD'):\n    time.sleep(2)\n",
        encoding="utf-8",
    )
    runner = _load_runner_module()
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join((str(shadow), PYTHON_PATH)))
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
