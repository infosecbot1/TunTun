from __future__ import annotations

import ast
import os
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).absolute().parents[2]
SCRIPT = ROOT / "scripts/run_scenarios.py"
PYTHON_PATH = os.pathsep.join(
    str(ROOT / path) for path in ("packages/testing/src", "packages/contracts/src", "apps/core/src")
)


def _python(code: str) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = PYTHON_PATH
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=20,
    )


def test_guard_import_is_stdlib_only_and_allows_asyncio_local_wakeup() -> None:
    code = """
import asyncio
import _socket
import socket
import sys
original_dns = socket.getaddrinfo
original_socket = socket.socket
original_socket_type = socket.SocketType
original_c_socket = _socket.socket
assert "yaml" not in sys.modules
assert "tuntun_contracts" not in sys.modules
assert "tuntun_core" not in sys.modules
from tuntun_testing.network_guard import NetworkDeniedError, install_network_guard
assert "yaml" not in sys.modules
assert "tuntun_contracts" not in sys.modules
assert "tuntun_core" not in sys.modules
install_network_guard()
for call in (
    lambda: socket.socket(),
    lambda: socket.getaddrinfo("example.invalid", 443),
    lambda: original_socket(),
    lambda: original_socket_type(),
    lambda: original_c_socket(),
    lambda: original_dns("example.invalid", 443),
):
    try:
        call()
    except NetworkDeniedError:
        pass
    else:
        raise AssertionError("network guard bypass")
asyncio.run(asyncio.sleep(0))
left, right = socket.socketpair()
left.close()
right.close()
"""
    result = _python(code)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout == result.stderr == b""


def test_testing_is_an_optional_core_extra_and_imports_are_lazy() -> None:
    core = tomllib.loads((ROOT / "apps/core/pyproject.toml").read_text(encoding="utf-8"))
    testing = tomllib.loads((ROOT / "packages/testing/pyproject.toml").read_text(encoding="utf-8"))
    assert "tuntun-testing" not in core["project"]["dependencies"]
    assert core["project"]["optional-dependencies"]["simulation"] == ["tuntun-testing"]
    assert core["tool"]["uv"]["sources"]["tuntun-testing"] == {"workspace": True}
    assert testing["project"]["dependencies"] == ["PyYAML>=6.0,<7", "tuntun-contracts"]
    for relative in (
        "apps/core/src/tuntun_core/cli/main.py",
        "apps/core/src/tuntun_core/cli/commands/simulate.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        assert all("tuntun_testing" not in ast.unparse(node) for node in imports)


def test_guard_is_active_before_a_failing_yaml_import_and_error_is_content_free(
    tmp_path: Path,
) -> None:
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    marker = tmp_path / "guard-state.txt"
    (shadow / "yaml.py").write_text(
        """
import os
import socket
from pathlib import Path
try:
    socket.socket()
except Exception:
    Path(os.environ["TUNTUN_GUARD_MARKER"]).write_text("guarded", encoding="utf-8")
else:
    Path(os.environ["TUNTUN_GUARD_MARKER"]).write_text("unguarded", encoding="utf-8")
raise RuntimeError("private-import-sentinel")
""",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": os.pathsep.join((str(shadow), PYTHON_PATH)),
            "TUNTUN_GUARD_MARKER": str(marker),
        }
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--turns", "1", "--json"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert marker.read_text(encoding="utf-8") == "guarded"
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"scenario-gate: failed\n"
    assert b"traceback" not in result.stderr.lower()
    assert b"private-import-sentinel" not in result.stdout + result.stderr


def test_synthetic_fixture_policy_names_every_data_boundary() -> None:
    policy = (ROOT / "tests/fixtures/synthetic/README.md").read_text(encoding="utf-8")
    assert "canonical UUID encoded as 16 bytes" in policy
    assert "never contain" in policy
    scenario = (ROOT / "tests/fixtures/scenarios/guest-hinglish.yaml").read_text(encoding="utf-8")
    assert "synthetic-" in scenario
    assert "password" not in scenario.casefold()
