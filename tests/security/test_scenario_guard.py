from __future__ import annotations

import ast
import json
import os
import shutil
import socket
import subprocess
import sys
import sysconfig
import tomllib
from collections.abc import Mapping
from pathlib import Path

import pytest

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


def _descriptor_count() -> int:
    directory = next((path for path in ("/proc/self/fd", "/dev/fd") if os.path.isdir(path)), None)
    if directory is None:
        pytest.skip("descriptor inventory unavailable")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        entries = tuple(name for name in os.listdir(descriptor) if name.isdecimal())
        return len(entries) - (1 if str(descriptor) in entries else 0)
    finally:
        os.close(descriptor)


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


def test_child_cleanup_has_no_unbounded_wait() -> None:
    for relative in (
        "scripts/run_scenarios.py",
        "apps/core/src/tuntun_core/cli/commands/simulate.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        cleanup = [
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in {"_force_process_group_cleanup", "_shutdown_supervised_process"}
        ]
        assert len(cleanup) == 2
        waits = [
            node
            for function in cleanup
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "wait"
        ]
        assert waits
        assert all(
            call.args or any(item.arg == "timeout" for item in call.keywords) for call in waits
        )


@pytest.mark.parametrize("target", ["runner", "simulate"])
def test_child_startup_ignores_sitecustomize_and_executable_pth(
    tmp_path: Path,
    target: str,
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            listener.bind(("127.0.0.1", 0))
        except PermissionError as error:
            pytest.skip(f"loopback sockets unavailable: {error}")
        listener.listen(4)
        listener.settimeout(0.2)
        port = listener.getsockname()[1]
        shadow = tmp_path / "shadow"
        shadow.mkdir()
        site_marker = tmp_path / "sitecustomize-ran"
        pth_marker = tmp_path / "executable-pth-ran"
        activation = (
            "any(len(item) == 64 and all(character in '0123456789abcdef' "
            "for character in item) for item in sys.argv[1:])"
        )
        (shadow / "sitecustomize.py").write_text(
            (
                "import os\n"
                "import socket\n"
                "import sys\n"
                "from pathlib import Path\n"
                f"if {activation}:\n"
                f"    Path({str(site_marker)!r}).write_text('executed', encoding='utf-8')\n"
                f"    socket.create_connection(('127.0.0.1', {port}), timeout=1).close()\n"
            ),
            encoding="utf-8",
        )
        site_packages = Path(sysconfig.get_path("purelib"))
        hook = site_packages / f"_tuntun_task9_{tmp_path.name}_{target}.pth"
        hook.write_text(
            (
                "import os,pathlib,socket,sys; "
                f"active={activation}; "
                f"active and pathlib.Path({str(pth_marker)!r}).write_text('executed'); "
                f"active and socket.create_connection(('127.0.0.1',{port}),timeout=1).close()\n"
            ),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join((str(shadow), PYTHON_PATH))
        try:
            if target == "runner":
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--turns", "1", "--json"],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    check=False,
                    timeout=20,
                )
            else:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        (
                            "from typer.testing import CliRunner; "
                            "from tuntun_core.cli.main import app; "
                            "r=CliRunner().invoke(app,['simulate','--scenario',"
                            "'tests/fixtures/scenarios/guest-hinglish.yaml','--json']); "
                            "raise SystemExit(r.exit_code)"
                        ),
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    check=False,
                    timeout=20,
                )
        finally:
            hook.unlink(missing_ok=True)

        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
        assert not site_marker.exists()
        assert not pth_marker.exists()
        with pytest.raises(TimeoutError):
            listener.accept()
    finally:
        listener.close()


def _run_supervised_target(
    target: str,
    environment: Mapping[str, str],
) -> subprocess.CompletedProcess[bytes]:
    if target == "runner":
        command = [sys.executable, str(SCRIPT), "--turns", "1", "--json"]
    else:
        command = [
            sys.executable,
            "-c",
            (
                "from typer.testing import CliRunner; "
                "from tuntun_core.cli.main import app; "
                "r=CliRunner().invoke(app,['simulate','--scenario',"
                "'tests/fixtures/scenarios/guest-hinglish.yaml','--json']); "
                "raise SystemExit(r.exit_code)"
            ),
        ]
    return subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=20,
    )


@pytest.mark.parametrize("target", ["runner", "simulate"])
def test_parent_does_not_execute_ambient_scenario_io(
    tmp_path: Path,
    target: str,
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            listener.bind(("127.0.0.1", 0))
        except PermissionError as error:
            pytest.skip(f"loopback sockets unavailable: {error}")
        listener.listen(2)
        listener.settimeout(0.2)
        marker = tmp_path / "ambient-scenario-io-ran"
        package = tmp_path / "shadow/tuntun_testing"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "scenario_io.py").write_text(
            (
                "import socket\n"
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
                "socket.create_connection("
                f"('127.0.0.1', {listener.getsockname()[1]}), timeout=1"
                ").close()\n"
            ),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join((str(tmp_path / "shadow"), PYTHON_PATH))

        result = _run_supervised_target(target, environment)

        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
        assert not marker.exists()
        with pytest.raises(TimeoutError):
            listener.accept()
    finally:
        listener.close()


@pytest.mark.parametrize("target", ["runner", "simulate"])
def test_workspace_packages_precede_exact_venv_site_packages(
    tmp_path: Path,
    target: str,
) -> None:
    site_packages = Path(sysconfig.get_path("purelib"))
    hostile_module = site_packages / "tuntun_testing.py"
    marker = tmp_path / "stale-site-package-ran"
    assert not hostile_module.exists()
    hostile_module.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    try:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = PYTHON_PATH
        result = _run_supervised_target(target, environment)
    finally:
        hostile_module.unlink(missing_ok=True)

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert not marker.exists()


def test_supervisor_startup_structure_is_isolated_and_workspace_first() -> None:
    for relative in (
        "scripts/run_scenarios.py",
        "apps/core/src/tuntun_core/cli/commands/simulate.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert '"-I"' in source
        assert '"-S"' in source
        assert "site.main" not in source
        assert "addsitedir" not in source
        assert "os.environ.copy" not in source
        assert "class _WorkspaceFinder:" in source
        assert "sys.meta_path.insert(0, _WorkspaceFinder())" in source
        assert 'sys.path.append(".")' in source
        assert "sys.path.append(site_path)" not in source
        assert "pass_fds=" in source
    runner_tree = ast.parse((ROOT / "scripts/run_scenarios.py").read_text(encoding="utf-8"))
    prepare = next(
        node
        for node in runner_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_prepare_gate_invocation"
    )
    assert "scenario_io" not in ast.unparse(prepare)
    assert "importlib" not in ast.unparse(prepare)


def _runtime_tree(root: Path) -> Path:
    for relative in (
        "packages/testing/src",
        "packages/contracts/src",
        "apps/core/src",
        "scripts",
        f".venv/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages",
        ".venv/bin",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    executable = root / ".venv/bin/python"
    executable.write_bytes(b"synthetic-interpreter")
    executable.chmod(0o700)
    (root / "scripts/run_scenarios.py").write_bytes(b"raise SystemExit(0)\n")
    (root / "packages/testing/src/original.txt").write_text("original", encoding="utf-8")
    return executable


@pytest.mark.parametrize("target", ["runner", "simulate"])
@pytest.mark.parametrize(
    "mutation",
    [
        "root-symlink",
        "site-symlink",
        "root-writable",
        "workspace-writable",
        "site-writable",
        "interpreter-writable",
        "prefix",
    ],
)
def test_runtime_layout_rejects_untrusted_symlink_mode_or_interpreter_prefix(
    tmp_path: Path,
    target: str,
    mutation: str,
) -> None:
    if target == "runner":
        import importlib.util

        spec = importlib.util.spec_from_file_location("_runtime_runner", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        script_relative = "scripts/run_scenarios.py"
    else:
        import importlib

        module = importlib.import_module("tuntun_core.cli.commands.simulate")
        script_relative = None
    root = tmp_path / "runtime"
    root.mkdir()
    executable = _runtime_tree(root)
    selected_root = root
    if mutation == "root-symlink":
        selected_root = tmp_path / "runtime-link"
        selected_root.symlink_to(root, target_is_directory=True)
    elif mutation == "site-symlink":
        site_packages = (
            root
            / ".venv/lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
        site_packages.rmdir()
        outside = tmp_path / "outside-site"
        outside.mkdir()
        site_packages.symlink_to(outside, target_is_directory=True)
    elif mutation == "root-writable":
        root.chmod(0o777)
    elif mutation == "workspace-writable":
        (root / "packages/testing/src").chmod(0o777)
    elif mutation == "site-writable":
        (
            root
            / ".venv/lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        ).chmod(0o777)
    elif mutation == "interpreter-writable":
        executable.chmod(0o777)
    else:
        executable = tmp_path / "outside-python"
        executable.write_bytes(b"synthetic-interpreter")
        executable.chmod(0o700)

    with pytest.raises(ValueError, match="invalid-runtime-path"):
        module._open_runtime_layout(
            selected_root,
            str(executable),
            script_relative=script_relative,
        )


@pytest.mark.parametrize("target", ["runner", "simulate"])
def test_open_runtime_relative_closes_a_descriptor_rejected_by_validation(
    tmp_path: Path,
    target: str,
) -> None:
    if target == "runner":
        import importlib.util

        spec = importlib.util.spec_from_file_location("_runtime_runner_rejected_fd", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    else:
        import importlib

        module = importlib.import_module("tuntun_core.cli.commands.simulate")
    root = tmp_path / "runtime"
    root.mkdir()
    rejected = root / "rejected"
    rejected.mkdir()
    rejected.chmod(0o777)
    root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = _descriptor_count()
        with pytest.raises(ValueError, match="invalid-runtime-path"):
            module._open_runtime_relative(
                root_descriptor,
                "rejected",
                directory=True,
            )
        assert _descriptor_count() == before
    finally:
        os.close(root_descriptor)


@pytest.mark.parametrize("target", ["runner", "simulate"])
def test_runtime_layout_closes_earlier_workspace_descriptor_when_a_later_open_fails(
    tmp_path: Path,
    target: str,
) -> None:
    if target == "runner":
        import importlib.util

        spec = importlib.util.spec_from_file_location("_runtime_runner_partial_layout", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        script_relative = "scripts/run_scenarios.py"
    else:
        import importlib

        module = importlib.import_module("tuntun_core.cli.commands.simulate")
        script_relative = None
    root = tmp_path / "runtime"
    root.mkdir()
    executable = _runtime_tree(root)
    (root / "packages/contracts/src").rmdir()

    before = _descriptor_count()
    with pytest.raises(ValueError, match="invalid-runtime-path"):
        module._open_runtime_layout(
            root,
            str(executable),
            script_relative=script_relative,
        )
    assert _descriptor_count() == before


@pytest.mark.parametrize("target", ["runner", "simulate"])
def test_runtime_layout_descriptors_survive_root_rename_and_replacement(
    tmp_path: Path,
    target: str,
) -> None:
    if target == "runner":
        import importlib.util

        spec = importlib.util.spec_from_file_location("_runtime_runner_rename", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        script_relative = "scripts/run_scenarios.py"
    else:
        import importlib

        module = importlib.import_module("tuntun_core.cli.commands.simulate")
        script_relative = None
    root = tmp_path / "runtime"
    root.mkdir()
    executable = _runtime_tree(root)
    layout = module._open_runtime_layout(
        root,
        str(executable),
        script_relative=script_relative,
    )
    try:
        moved = tmp_path / "moved-runtime"
        root.rename(moved)
        root.mkdir()
        replacement = root / "packages/testing/src"
        replacement.mkdir(parents=True)
        (replacement / "original.txt").write_text("replacement", encoding="utf-8")
        descriptor = layout.workspace_descriptors[0]
        original_fd = os.open("original.txt", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            assert os.read(original_fd, 32) == b"original"
        finally:
            os.close(original_fd)
        assert (replacement / "original.txt").read_text(encoding="utf-8") == "replacement"
    finally:
        module._close_runtime_layout(layout)


@pytest.mark.parametrize("target", ["runner", "simulate"])
def test_descriptor_workspace_loader_handles_package_relative_import_without_lexical_fallback(
    tmp_path: Path,
    target: str,
) -> None:
    if target == "runner":
        import importlib.util

        spec = importlib.util.spec_from_file_location("_runtime_runner_loader", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        script_relative = "scripts/run_scenarios.py"
    else:
        import importlib

        module = importlib.import_module("tuntun_core.cli.commands.simulate")
        script_relative = None
    root = tmp_path / "runtime"
    root.mkdir()
    _runtime_tree(root).unlink()
    (root / ".venv/bin/python").symlink_to(sys.executable)
    package = root / "packages/testing/src/tuntun_testing"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .submodule import VALUE\n",
        encoding="utf-8",
    )
    (package / "submodule.py").write_text("VALUE = 'original'\n", encoding="utf-8")
    script = root / "scripts/run_scenarios.py"
    script.write_text(
        """
import os
import signal

def _child_main_from_stdin(_nonce: str) -> int:
    import tuntun_testing
    assert tuntun_testing.VALUE == "original"
    assert list(tuntun_testing.__spec__.submodule_search_locations) == []
    os.write(1, b"complete\\n")
    while True:
        signal.pause()
""",
        encoding="utf-8",
    )
    layout = module._open_runtime_layout(
        root,
        str(root / ".venv/bin/python"),
        script_relative=script_relative,
    )
    moved = tmp_path / "moved-runtime"
    marker = tmp_path / "replacement-imported"
    try:
        root.rename(moved)
        root.mkdir()
        replacement = root / "packages/testing/src/tuntun_testing"
        replacement.mkdir(parents=True)
        (replacement / "__init__.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('bad')\n"
            "VALUE='replacement'\n",
            encoding="utf-8",
        )
        nonce = "a" * 64
        child_code = """
import os
import signal
import tuntun_testing
assert tuntun_testing.VALUE == "original"
assert list(tuntun_testing.__spec__.submodule_search_locations) == []
os.write(1, b"complete\\n")
while True:
    signal.pause()
"""
        bootstrap = (
            module._CHILD_BOOTSTRAP
            if target == "runner"
            else module._SIMULATE_BOOTSTRAP + child_code
        )
        result = module._run_bounded_process(
            (
                sys.executable,
                "-I",
                "-S",
                "-c",
                bootstrap,
                nonce,
                "65536",
                layout.manifest_b64,
            ),
            payload=b"{}",
            cwd=root,
            environment={},
            supervision_nonce=nonce,
            inherited_descriptors=layout.descriptors,
        )
        assert result.returncode == 0
        assert result.stdout == b"complete\n"
        assert result.stderr == b""
        assert not marker.exists()
    finally:
        module._close_runtime_layout(layout)


@pytest.mark.parametrize("target", ["runner", "simulate"])
def test_site_packages_imports_remain_bound_to_retained_directory_after_replacement(
    tmp_path: Path,
    target: str,
) -> None:
    if target == "runner":
        import importlib.util

        spec = importlib.util.spec_from_file_location("_runtime_runner_site", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        script_relative = "scripts/run_scenarios.py"
    else:
        import importlib

        module = importlib.import_module("tuntun_core.cli.commands.simulate")
        script_relative = None
    root = tmp_path / "runtime"
    root.mkdir()
    _runtime_tree(root).unlink()
    (root / ".venv/bin/python").symlink_to(sys.executable)
    site_packages = (
        root
        / ".venv/lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    (site_packages / "tuntun_site_probe.py").write_text(
        "VALUE = 'original'\n",
        encoding="utf-8",
    )
    script = root / "scripts/run_scenarios.py"
    script.write_text(
        """
import os
import signal

def _child_main_from_stdin(_nonce: str) -> int:
    import tuntun_site_probe
    assert tuntun_site_probe.VALUE == "original"
    os.write(1, b"complete\\n")
    while True:
        signal.pause()
""",
        encoding="utf-8",
    )
    layout = module._open_runtime_layout(
        root,
        str(root / ".venv/bin/python"),
        script_relative=script_relative,
    )
    marker = tmp_path / "replacement-site-imported"
    try:
        attack = f"""
moved_site_path = site_path + ".moved"
os.rename(site_path, moved_site_path)
os.mkdir(site_path, 0o700)
with open(site_path + "/tuntun_site_probe.py", "w", encoding="utf-8") as handle:
    handle.write("from pathlib import Path\\n")
    handle.write("Path({str(marker)!r}).write_text('bad')\\n")
    handle.write("VALUE='replacement'\\n")
"""
        insertion = "sys.meta_path.insert(0, _WorkspaceFinder())"
        base_bootstrap = (
            module._CHILD_BOOTSTRAP if target == "runner" else module._SIMULATE_BOOTSTRAP
        )
        assert base_bootstrap.count(insertion) == 1
        bootstrap = base_bootstrap.replace(insertion, attack + "\n" + insertion)
        if target == "simulate":
            bootstrap += """
import os
import signal
import tuntun_site_probe
assert tuntun_site_probe.VALUE == "original"
os.write(1, b"complete\\n")
while True:
    signal.pause()
"""
        nonce = "a" * 64
        result = module._run_bounded_process(
            (
                sys.executable,
                "-I",
                "-S",
                "-c",
                bootstrap,
                nonce,
                "65536",
                layout.manifest_b64,
            ),
            payload=b"{}",
            cwd=root,
            environment={},
            supervision_nonce=nonce,
            inherited_descriptors=layout.descriptors,
        )
        assert result.returncode == 0
        assert result.stdout == b"complete\n"
        assert result.stderr == b""
        assert not marker.exists()
    finally:
        module._close_runtime_layout(layout)


@pytest.mark.parametrize("target", ["scenario-typecheck", "scenario-check"])
def test_make_scenario_gate_uses_offline_no_sync_isolated_python(
    tmp_path: Path,
    target: str,
) -> None:
    real_uv = shutil.which("uv")
    assert real_uv is not None
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    marker = tmp_path / "sitecustomize-ran"
    (shadow / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uv_log = tmp_path / "uv-args"
    uv_wrapper = fake_bin / "uv"
    uv_wrapper.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$TUNTUN_UV_ARGS"\nexec "$TUNTUN_REAL_UV" "$@"\n',
        encoding="utf-8",
    )
    uv_wrapper.chmod(0o700)
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": os.pathsep.join((str(fake_bin), environment["PATH"])),
            "PYTHONPATH": str(shadow),
            "TUNTUN_REAL_UV": real_uv,
            "TUNTUN_UV_ARGS": str(uv_log),
            "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
        }
    )

    result = subprocess.run(
        ["make", target],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert not marker.exists()
    arguments = uv_log.read_text(encoding="utf-8").splitlines()
    assert arguments[:3] == ["run", "--offline", "--no-sync"]
    assert "-I" in arguments and "-S" in arguments


def test_isolated_module_retains_validated_site_root_through_package_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib.util

    launcher = ROOT / "scripts/run_isolated_module.py"
    spec = importlib.util.spec_from_file_location("_isolated_module_retained_site", launcher)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    repository = tmp_path / "repository"
    fake_launcher = repository / "scripts/run_isolated_module.py"
    fake_launcher.parent.mkdir(parents=True)
    fake_launcher.write_text("# synthetic launcher location\n", encoding="utf-8")
    executable = repository / ".venv/bin/python"
    executable.parent.mkdir(parents=True)
    executable.symlink_to(sys.executable)
    site_packages = (
        repository
        / ".venv/lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    package = site_packages / "mypy"
    package.mkdir(parents=True)
    marker = tmp_path / "loaded-package"
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "submodule.py").write_text("VALUE = 'original'\n", encoding="utf-8")
    (package / "main.py").write_text(
        "def get_search_dirs(_python_executable):\n    return ([], [])\n",
        encoding="utf-8",
    )
    (package / "modulefinder.py").write_text(
        "def get_search_dirs(_python_executable):\n    return ([], [])\n",
        encoding="utf-8",
    )
    (package / "__main__.py").write_text(
        "from pathlib import Path\n"
        "from .submodule import VALUE\n"
        "def console_entry():\n"
        f"    Path({str(marker)!r}).write_text(VALUE, encoding='utf-8')\n",
        encoding="utf-8",
    )
    safe_path = [item for item in sys.path if "site-packages" not in item and str(ROOT) not in item]
    monkeypatch.setattr(module, "__file__", str(fake_launcher))
    monkeypatch.setattr(module.sys, "executable", str(executable))
    monkeypatch.setattr(module.sys, "argv", [str(fake_launcher), "mypy"])
    monkeypatch.setattr(module.sys, "path", safe_path)
    real_import_module = module.importlib.import_module
    moved_site = site_packages.with_name("site-packages.original")
    replaced = False

    def replace_then_import(name: str, package_name: str | None = None) -> object:
        nonlocal replaced
        if name == "mypy.__main__" and not replaced:
            replaced = True
            site_packages.rename(moved_site)
            replacement = site_packages / "mypy"
            replacement.mkdir(parents=True)
            (replacement / "__init__.py").write_text("", encoding="utf-8")
            (replacement / "__main__.py").write_text(
                "from pathlib import Path\n"
                "def console_entry():\n"
                f"    Path({str(marker)!r}).write_text('replacement', encoding='utf-8')\n",
                encoding="utf-8",
            )
        return real_import_module(name, package_name)

    monkeypatch.setattr(module.importlib, "import_module", replace_then_import)
    saved_modules = {
        name: value
        for name, value in tuple(sys.modules.items())
        if name == "mypy" or name.startswith("mypy.")
    }
    for name in saved_modules:
        sys.modules.pop(name)
    try:
        assert module.main() == 0
        assert marker.read_text(encoding="utf-8") == "original"
    finally:
        for name in tuple(sys.modules):
            if name == "mypy" or name.startswith("mypy."):
                sys.modules.pop(name)
        sys.modules.update(saved_modules)


def test_installed_tuntunctl_discloses_trusted_python_startup_boundary(
    tmp_path: Path,
) -> None:
    executable = ROOT / ".venv/bin/tuntunctl"
    assert executable.is_file()
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    marker = tmp_path / "sitecustomize-ran"
    (shadow / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(shadow)

    result = subprocess.run(
        [str(executable), "simulate", "--help"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert marker.exists()
    assert b"trusted Python environment" in b" ".join(result.stdout.split())


def test_core_wheel_smoke_uses_private_cache_and_highest_current_ranges(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "calls.jsonl"
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        '''#!/usr/bin/env python3
import json
import os
import stat
import sys
from pathlib import Path

record = {
    "argv": sys.argv[1:],
    "cache": os.environ.get("UV_CACHE_DIR"),
    "pythonpath": os.environ.get("PYTHONPATH"),
    "tool": "uv",
}
with Path(os.environ["TUNTUN_UV_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True) + "\\n")

if sys.argv[1] == "build":
    output = Path(sys.argv[sys.argv.index("--out-dir") + 1])
    output.mkdir(parents=True, exist_ok=True)
    (output / "tuntun_core-0.1.0.dev0-py3-none-any.whl").write_bytes(b"synthetic-wheel")
elif sys.argv[1] == "venv":
    executable = Path(sys.argv[-1]) / "bin" / "python"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_text(
        """#!/usr/bin/env python3
import json
import os
from pathlib import Path
record = {
    "argv": [],
    "cache": os.environ.get("UV_CACHE_DIR"),
    "pythonpath": os.environ.get("PYTHONPATH"),
    "tool": "python",
}
with Path(os.environ["TUNTUN_UV_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True) + "\\\\n")
""",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
''',
        encoding="utf-8",
    )
    fake_uv.chmod(fake_uv.stat().st_mode | 0o100)
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    ambient_cache = tmp_path / "ambient-cache"
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": os.pathsep.join((str(fake_bin), environment["PATH"])),
            "TMPDIR": str(temp_root),
            "TUNTUN_UV_LOG": str(log),
            "UV_CACHE_DIR": str(ambient_cache),
        }
    )

    result = subprocess.run(
        ["make", "core-wheel-smoke"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    records = tuple(json.loads(line) for line in log.read_text(encoding="utf-8").splitlines())
    assert [record["tool"] for record in records] == ["uv", "uv", "uv", "python"]
    caches = {record["cache"] for record in records}
    assert len(caches) == 1
    cache = next(iter(caches))
    assert cache != str(ambient_cache)
    assert cache.startswith(str(temp_root / "tuntun-core-wheel."))
    assert cache.endswith("/uv-cache")
    pip_install = records[2]["argv"]
    assert pip_install[:2] == ["pip", "install"]
    assert pip_install[pip_install.index("--resolution") + 1] == "highest"
    assert records[3]["pythonpath"] is None
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "current dependency ranges" in makefile
    assert "dependency_intent=" not in makefile


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
    assert not marker.exists()
    assert result.returncode == 0
    assert json.loads(result.stdout)["schema_version"] == "scenario_gate.v1"
    assert result.stderr == b""
    assert b"traceback" not in result.stderr.lower()
    assert b"private-import-sentinel" not in result.stdout + result.stderr


def test_guard_import_baseexception_is_content_free(tmp_path: Path) -> None:
    shadow = tmp_path / "shadow"
    package = shadow / "tuntun_testing"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "network_guard.py").write_text(
        'raise SystemExit("private-guard-sentinel")\n',
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join((str(shadow), PYTHON_PATH))
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--turns", "1", "--json"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["schema_version"] == "scenario_gate.v1"
    assert result.stderr == b""
    assert b"private-guard-sentinel" not in result.stdout + result.stderr


def test_yaml_import_baseexception_is_content_free(tmp_path: Path) -> None:
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
raise SystemExit("private-import-sentinel")
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
    assert not marker.exists()
    assert result.returncode == 0
    assert json.loads(result.stdout)["schema_version"] == "scenario_gate.v1"
    assert result.stderr == b""
    assert b"private-import-sentinel" not in result.stdout + result.stderr


def test_child_execution_does_not_inherit_connected_inet_descriptors(tmp_path: Path) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            listener.bind(("127.0.0.1", 0))
        except PermissionError as error:
            pytest.skip(f"loopback sockets unavailable: {error}")
        listener.listen(1)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect(listener.getsockname())
            server, _address = listener.accept()
            try:
                client.set_inheritable(True)
                server.settimeout(2)
                shadow = tmp_path / "shadow"
                shadow.mkdir()
                (shadow / "yaml.py").write_text(
                    """
import os
try:
    os.write(int(os.environ["TUNTUN_INHERITED_FD"]), b"private-inherited-sentinel")
except OSError:
    pass
raise RuntimeError("private-import-sentinel")
""",
                    encoding="utf-8",
                )
                environment = os.environ.copy()
                environment.update(
                    {
                        "PYTHONPATH": os.pathsep.join((str(shadow), PYTHON_PATH)),
                        "TUNTUN_INHERITED_FD": str(client.fileno()),
                    }
                )
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--turns", "1", "--json"],
                    cwd=ROOT,
                    env=environment,
                    pass_fds=(client.fileno(),),
                    capture_output=True,
                    check=False,
                    timeout=20,
                )
                try:
                    received = server.recv(4096)
                except TimeoutError:
                    received = b""
                assert result.returncode == 0
                assert json.loads(result.stdout)["schema_version"] == "scenario_gate.v1"
                assert result.stderr == b""
                assert b"private-import-sentinel" not in result.stdout + result.stderr
                assert received == b""
            finally:
                server.close()
        finally:
            client.close()
    finally:
        listener.close()


def test_synthetic_fixture_policy_names_every_data_boundary() -> None:
    policy = (ROOT / "tests/fixtures/synthetic/README.md").read_text(encoding="utf-8")
    assert "canonical UUID encoded as 16 bytes" in policy
    assert "never contain" in policy
    scenario = (ROOT / "tests/fixtures/scenarios/guest-hinglish.yaml").read_text(encoding="utf-8")
    assert "synthetic-" in scenario
    assert "password" not in scenario.casefold()
