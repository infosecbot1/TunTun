from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib
import inspect
import os
import pathlib
import socket
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest
from packaging.requirements import Requirement
from packaging.tags import Tag
from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_edge.reachy.probe import LocalRuntimeCompatibility

probe_module = importlib.import_module("tuntun_edge.reachy.probe")

_FUTURE_DEADLINE = 1_000_000_000_000.0


def _probe_attr(name: str) -> Any:
    value = getattr(probe_module, name, None)
    assert value is not None, f"{name} is missing"
    return value


def _tag_digest(tags: Iterable[Tag | str]) -> str:
    return hashlib.sha256(
        canonical_mapping_bytes({"sys_tags": tuple(str(tag) for tag in tags)})
    ).hexdigest()


def _runtime_inventory_digest(
    *,
    python: str = "3.12.9",
    sdk: str = "9.8.7",
    websockets: str = "15.0.1",
) -> str:
    return hashlib.sha256(
        canonical_mapping_bytes(
            {
                "runtime_packages": (
                    {"name": "python", "version": python},
                    {"name": "reachy-mini", "version": sdk},
                    {"name": "websockets", "version": websockets},
                )
            }
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class _FakeMetadata:
    versions: dict[str, str]
    requirements: dict[str, tuple[Requirement, ...]]
    calls: list[str]

    def version(self, distribution_name: str, *, deadline: float) -> str:
        self.calls.append(f"version:{distribution_name}:{deadline}")
        return self.versions[distribution_name]

    def requires(self, distribution_name: str, *, deadline: float) -> tuple[Requirement, ...]:
        self.calls.append(f"requires:{distribution_name}:{deadline}")
        return self.requirements.get(distribution_name, ())


@dataclass(frozen=True, slots=True)
class _FakeImporter:
    missing: frozenset[str] = frozenset()
    calls: list[str] | None = None

    def import_module(self, module_name: str, *, deadline: float) -> object:
        if self.calls is not None:
            self.calls.append(f"import:{module_name}:{deadline}")
        if module_name in self.missing:
            raise ImportError(module_name)
        return object()


@dataclass(frozen=True, slots=True)
class _FakeDaemonReader:
    version_value: str
    calls: list[str]

    def read_version(self, *, deadline: float, max_bytes: int) -> str:
        self.calls.append(f"daemon:{deadline}:{max_bytes}")
        return self.version_value


@dataclass(frozen=True, slots=True)
class _ProbeCase:
    daemon_reader: _FakeDaemonReader
    metadata: _FakeMetadata
    importer: _FakeImporter
    tags: tuple[Tag, ...]
    observed_runtime: Any


def _make_probe_case(
    *,
    daemon: str = "1.2.3",
    sdk: str = "9.8.7",
    websockets: str = "15.0.1",
    packaging: str | None = "26.3",
    tags: tuple[Tag, ...] | None = None,
    importer: _FakeImporter | None = None,
    sdk_requirements: tuple[Requirement, ...] = (Requirement("websockets>=12,<16"),),
    python_executable: str = "/venvs/apps_venv/bin/python3",
    python_version: str = "3.12",
    implementation_cache_tag: str = "cpython-312",
    python_package_version: str = "3.12.9",
) -> _ProbeCase:
    selected_tags = tags or (
        Tag("cp312", "cp312", "manylinux_2_31_aarch64"),
        Tag("py3", "none", "any"),
    )
    daemon_calls: list[str] = []
    metadata_calls: list[str] = []
    import_calls: list[str] = []
    versions = {"reachy-mini": sdk, "websockets": websockets}
    if packaging is not None:
        versions["packaging"] = packaging
    return _ProbeCase(
        daemon_reader=_FakeDaemonReader(daemon, daemon_calls),
        metadata=_FakeMetadata(
            versions,
            {"reachy-mini": sdk_requirements},
            metadata_calls,
        ),
        importer=importer or _FakeImporter(calls=import_calls),
        tags=selected_tags,
        observed_runtime=_probe_attr("_ObservedPythonRuntime")(
            executable=python_executable,
            version=python_version,
            implementation_cache_tag=implementation_cache_tag,
            package_version=python_package_version,
        ),
    )


def _run_private_probe(case: _ProbeCase, *, timeout_seconds: int = 5) -> Any:
    implementation = _probe_attr("_probe_local_runtime_compatibility")
    return implementation(
        timeout_seconds=timeout_seconds,
        network=False,
        daemon_reader=case.daemon_reader,
        metadata=case.metadata,
        importer=case.importer,
        observed_runtime=case.observed_runtime,
        sys_tags=lambda: iter(case.tags),
        monotonic=lambda: 1.0,
    )


def _deny_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("forbidden side effect")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "gethostbyname", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(os, "write", fail)
    monkeypatch.setattr(pathlib.Path, "write_bytes", fail)
    monkeypatch.setattr(pathlib.Path, "write_text", fail)


def test_public_probe_signature_is_fixed_and_result_is_frozen() -> None:
    probe = _probe_attr("probe_local_runtime_compatibility")

    assert dataclasses.is_dataclass(LocalRuntimeCompatibility)
    assert LocalRuntimeCompatibility.__dataclass_params__.frozen is True  # type: ignore[attr-defined]
    assert probe.__kwdefaults__ is None or "network" not in probe.__kwdefaults__

    result = LocalRuntimeCompatibility(
        sdk="9.8.7",
        daemon="1.2.3",
        python_executable="/venvs/apps_venv/bin/python3",
        python_version="3.12",
        python_abi="cp312",
        selected_wheel_tag="py3-none-any",
        target_tag_set_sha256="0" * 64,
        runtime_inventory_sha256="1" * 64,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.sdk = "changed"  # type: ignore[misc]


def test_probe_module_has_no_top_level_packaging_imports() -> None:
    assert probe_module.__file__ is not None
    source_path = pathlib.Path(probe_module.__file__)
    parsed = ast.parse(source_path.read_text())

    top_level_packaging_imports = [
        statement
        for statement in parsed.body
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.module is not None
            and statement.module.split(".", 1)[0] == "packaging"
        )
        or (
            isinstance(statement, ast.Import)
            and any(alias.name.split(".", 1)[0] == "packaging" for alias in statement.names)
        )
    ]

    assert top_level_packaging_imports == []


def test_reachy_package_import_and_cli_startup_do_not_require_probe_packaging() -> None:
    repo_root = pathlib.Path(__file__).resolve().parents[3]
    python_path = os.pathsep.join(
        (
            str(repo_root / "apps" / "edge" / "src"),
            str(repo_root / "packages" / "contracts" / "src"),
            os.environ.get("PYTHONPATH", ""),
        )
    )
    script = """
import importlib.abc
import sys


class BlockPackaging(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "packaging" or fullname.startswith("packaging."):
            raise ModuleNotFoundError("blocked packaging support")
        return None


for name in tuple(sys.modules):
    if name == "packaging" or name.startswith("packaging."):
        del sys.modules[name]
sys.meta_path.insert(0, BlockPackaging())

import tuntun_edge.reachy
import tuntun_edge.cli.main
"""

    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": python_path},
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr


def test_probe_returns_reachy_local_observation_without_operator_state_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _deny_side_effects(monkeypatch)
    case = _make_probe_case()

    result = _run_private_probe(case)

    assert result == LocalRuntimeCompatibility(
        sdk="9.8.7",
        daemon="1.2.3",
        python_executable="/venvs/apps_venv/bin/python3",
        python_version="3.12",
        python_abi="cp312",
        selected_wheel_tag="py3-none-any",
        target_tag_set_sha256=_tag_digest(case.tags),
        runtime_inventory_sha256=_runtime_inventory_digest(sdk="9.8.7"),
    )
    assert case.metadata.calls == [
        "version:packaging:6.0",
        "version:reachy-mini:6.0",
        "version:websockets:6.0",
        "requires:reachy-mini:6.0",
    ]
    assert case.daemon_reader.calls == ["daemon:6.0:256"]


def test_runtime_inventory_digest_stays_task08_compatible_and_imports_are_separate() -> None:
    case = _make_probe_case()
    result = _run_private_probe(case)
    digest_with_imports = hashlib.sha256(
        canonical_mapping_bytes(
            {
                "runtime_packages": (
                    {"name": "python", "version": "3.12.9"},
                    {"name": "reachy-mini", "version": "9.8.7"},
                    {"name": "websockets", "version": "15.0.1"},
                ),
                "imported_modules": _probe_attr("REQUIRED_RUNTIME_IMPORTS"),
            }
        )
    ).hexdigest()

    assert result.runtime_inventory_sha256 == _runtime_inventory_digest(sdk="9.8.7")
    assert result.runtime_inventory_sha256 != digest_with_imports


@pytest.mark.parametrize("packaging_version", (None, "25.9", "27.0"))
def test_probe_rejects_absent_or_wrong_onboard_packaging_support(
    packaging_version: str | None,
) -> None:
    case = _make_probe_case(packaging=packaging_version)

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility") as caught:
        _run_private_probe(case)

    assert str(caught.value) == "unsafe Reachy runtime compatibility"


@pytest.mark.parametrize(
    "module_name",
    (
        "packaging.requirements",
        "packaging.tags",
        "packaging.utils",
        "packaging.version",
    ),
)
@pytest.mark.parametrize("break_mode", ("import-error", "missing-api"))
def test_probe_converts_broken_packaging_imports_or_apis_to_content_free_error(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    break_mode: str,
) -> None:
    real_import_module = probe_module.importlib.import_module

    def import_module(name: str, package: str | None = None) -> object:
        if name == module_name:
            if break_mode == "import-error":
                raise ImportError("secret packaging path")
            return SimpleNamespace()
        return real_import_module(name, package)

    monkeypatch.setattr(probe_module.importlib, "import_module", import_module)
    case = _make_probe_case()

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility") as caught:
        _run_private_probe(case)

    assert str(caught.value) == "unsafe Reachy runtime compatibility"


@pytest.mark.parametrize(
    ("timeout_seconds", "network"),
    ((0, False), (6, False), (True, False), (5, True)),
)
def test_probe_rejects_invalid_arguments_before_observing_runtime(
    timeout_seconds: Any,
    network: Any,
) -> None:
    implementation = _probe_attr("_probe_local_runtime_compatibility")

    with pytest.raises(ValueError, match="unsafe Reachy runtime compatibility"):
        implementation(
            timeout_seconds=timeout_seconds,
            network=network,
            daemon_reader=SimpleNamespace(read_version=lambda **_: pytest.fail("daemon")),
            metadata=SimpleNamespace(
                version=lambda *_args, **_kwargs: pytest.fail("metadata"),
                requires=lambda *_args, **_kwargs: pytest.fail("metadata"),
            ),
            importer=SimpleNamespace(import_module=lambda *_args, **_kwargs: pytest.fail("import")),
            observed_runtime=SimpleNamespace(
                executable="/venvs/apps_venv/bin/python3",
                version="3.12",
                implementation_cache_tag="cpython-312",
                package_version="3.12.9",
            ),
            sys_tags=lambda: pytest.fail("tags"),
            monotonic=lambda: 1.0,
        )


@pytest.mark.parametrize(
    ("python_executable", "python_version", "implementation_cache_tag"),
    (
        ("/usr/bin/python3", "3.12", "cpython-312"),
        ("/venvs/apps_venv/bin/python3", "3.10", "cpython-310"),
        ("/venvs/apps_venv/bin/python3", "3.11", "cpython-312"),
        ("/venvs/apps_venv/bin/python3", "3.12", "cpython-311"),
        ("/venvs/apps_venv/bin/python3", "3.12", "pypy-312"),
    ),
)
def test_probe_rejects_unqualified_local_python_runtime(
    python_executable: str,
    python_version: str,
    implementation_cache_tag: str,
) -> None:
    case = _make_probe_case(
        python_executable=python_executable,
        python_version=python_version,
        implementation_cache_tag=implementation_cache_tag,
    )

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        _run_private_probe(case)


@pytest.mark.parametrize(
    ("websockets", "requirements"),
    (
        ("15.0.0", (Requirement("websockets>=12,<16"),)),
        ("15.0.1", (Requirement("websockets<15"),)),
        ("15.0.1", (Requirement("requests>=2"),)),
    ),
)
def test_probe_rejects_websockets_version_or_sdk_constraint_drift(
    websockets: str,
    requirements: tuple[Requirement, ...],
) -> None:
    case = _make_probe_case(websockets=websockets, sdk_requirements=requirements)

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        _run_private_probe(case)


def test_probe_rejects_missing_closed_runtime_import() -> None:
    missing = frozenset({_probe_attr("REQUIRED_RUNTIME_IMPORTS")[-1]})
    case = _make_probe_case(importer=_FakeImporter(missing=missing, calls=[]))

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        _run_private_probe(case)


@pytest.mark.parametrize(
    "tags",
    (
        (Tag("cp312", "cp312", "manylinux_2_31_aarch64"),),
        (Tag("py3", "none", "any"), Tag("py3", "none", "any")),
    ),
)
def test_probe_rejects_missing_or_duplicate_target_tags(tags: tuple[Tag, ...]) -> None:
    case = _make_probe_case(tags=tags)

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        _run_private_probe(case)


def test_canonical_target_tag_set_rejects_more_than_4096_tags() -> None:
    canonical_target_tag_set_sha256 = _probe_attr("canonical_target_tag_set_sha256")
    tags = ("py3-none-any", *(f"tag-{index}" for index in range(4096)))

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        canonical_target_tag_set_sha256(tags)


@pytest.mark.parametrize("unsafe_tag", ("", "a" * 129, "py3 none any", "py3/none/any"))
def test_canonical_target_tag_set_rejects_unsafe_tag_names(unsafe_tag: str) -> None:
    canonical_target_tag_set_sha256 = _probe_attr("canonical_target_tag_set_sha256")

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        canonical_target_tag_set_sha256(("py3-none-any", unsafe_tag))


def test_probe_preserves_control_flow_base_exceptions() -> None:
    implementation = _probe_attr("_probe_local_runtime_compatibility")

    with pytest.raises(KeyboardInterrupt):
        implementation(
            timeout_seconds=5,
            network=False,
            daemon_reader=SimpleNamespace(read_version=lambda **_: "1.2.3"),
            metadata=SimpleNamespace(
                version=lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt),
                requires=lambda *_args, **_kwargs: (),
            ),
            importer=SimpleNamespace(import_module=lambda **_: object()),
            observed_runtime=SimpleNamespace(
                executable="/venvs/apps_venv/bin/python3",
                version="3.12",
                implementation_cache_tag="cpython-312",
                package_version="3.12.9",
            ),
            sys_tags=lambda: iter((Tag("py3", "none", "any"),)),
            monotonic=lambda: 1.0,
        )


def test_probe_converts_dependency_timeouts_to_content_free_errors() -> None:
    implementation = _probe_attr("_probe_local_runtime_compatibility")

    with pytest.raises(TimeoutError, match="unsafe Reachy runtime compatibility") as caught:
        implementation(
            timeout_seconds=5,
            network=False,
            daemon_reader=SimpleNamespace(read_version=lambda **_: "1.2.3"),
            metadata=SimpleNamespace(
                version=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    TimeoutError("secret path")
                ),
                requires=lambda *_args, **_kwargs: (),
            ),
            importer=SimpleNamespace(import_module=lambda **_: object()),
            observed_runtime=SimpleNamespace(
                executable="/venvs/apps_venv/bin/python3",
                version="3.12",
                implementation_cache_tag="cpython-312",
                package_version="3.12.9",
            ),
            sys_tags=lambda: iter((Tag("py3", "none", "any"),)),
            monotonic=lambda: 1.0,
        )
    assert str(caught.value) == "unsafe Reachy runtime compatibility"


def test_probe_uses_one_monotonic_service_deadline_across_observations() -> None:
    implementation = _probe_attr("_probe_local_runtime_compatibility")
    times = iter((1.0, 1.1, 1.2, 5.9, 6.1))
    daemon_reader = _FakeDaemonReader("1.2.3", [])
    case = _make_probe_case()

    with pytest.raises(TimeoutError, match="unsafe Reachy runtime compatibility"):
        implementation(
            timeout_seconds=5,
            network=False,
            daemon_reader=daemon_reader,
            metadata=case.metadata,
            importer=case.importer,
            observed_runtime=case.observed_runtime,
            sys_tags=lambda: iter(case.tags),
            monotonic=lambda: next(times),
        )
    assert daemon_reader.calls == []


def test_runtime_probe_has_no_operator_state_reader_and_daemon_path_is_fixed() -> None:
    implementation = _probe_attr("_probe_local_runtime_compatibility")
    daemon_reader = _probe_attr("_LoopbackDaemonStatusReader").from_fixed_loopback_daemon_status()

    assert "accepted_reader" not in inspect.signature(implementation).parameters
    assert getattr(probe_module, "_AcceptedReachyRuntimeReader", None) is None
    assert getattr(probe_module, "_OperatorStatePathPolicy", None) is None
    assert daemon_reader.endpoint == "http://127.0.0.1:8000/api/daemon/status"  # noqa: SLF001
    assert getattr(probe_module, "_LocalDaemonVersionReader", None) is None


class _FakeLoopbackSocket:
    def __init__(self, chunks: tuple[bytes | BaseException, ...]) -> None:
        self.chunks = list(chunks)
        self.recv_sizes: list[int] = []
        self.sent: list[bytes] = []
        self.connected: tuple[str, int] | None = None
        self.timeouts: list[float] = []
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def connect(self, endpoint: tuple[str, int]) -> None:
        self.connected = endpoint

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)

    def recv(self, size: int) -> bytes:
        self.recv_sizes.append(size)
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        if len(chunk) <= size:
            return chunk
        self.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def bind(self, _address: object) -> None:
        raise AssertionError("listener creation is forbidden")

    def listen(self, _backlog: int = 0) -> None:
        raise AssertionError("listener creation is forbidden")

    def close(self) -> None:
        self.closed = True


def _daemon_status_response(
    body: bytes,
    *,
    status: bytes = b"200 OK",
    content_type: bytes = b"application/json",
    extra_headers: tuple[tuple[bytes, bytes], ...] = (),
) -> bytes:
    headers = [
        b"HTTP/1.1 " + status,
        b"Content-Type: " + content_type,
        b"Content-Length: " + str(len(body)).encode("ascii"),
    ]
    headers.extend(name + b": " + value for name, value in extra_headers)
    return b"\r\n".join(headers) + b"\r\n\r\n" + body


def _daemon_status_reader(
    fake_socket: _FakeLoopbackSocket,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    path: str = "/api/daemon/status",
) -> tuple[Any, list[tuple[int, int]]]:
    socket_calls: list[tuple[int, int]] = []

    def socket_factory(family: int, socket_type: int) -> _FakeLoopbackSocket:
        socket_calls.append((family, socket_type))
        return fake_socket

    return (
        _probe_attr("_LoopbackDaemonStatusReader")(
            host=host,
            port=port,
            path=path,
            socket_factory=socket_factory,
        ),
        socket_calls,
    )


def test_daemon_status_reader_uses_fixed_loopback_http_and_bounded_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _deny_side_effects(monkeypatch)
    body = b'{"status":"running","version":"2.3.4"}'
    fake_socket = _FakeLoopbackSocket((_daemon_status_response(body),))
    reader, socket_calls = _daemon_status_reader(fake_socket)

    assert reader.read_version(deadline=_FUTURE_DEADLINE, max_bytes=256) == "2.3.4"
    assert socket_calls == [(socket.AF_INET, socket.SOCK_STREAM)]
    assert fake_socket.connected == ("127.0.0.1", 8000)
    assert fake_socket.sent == [
        (
            b"GET /api/daemon/status HTTP/1.1\r\n"
            b"Host: 127.0.0.1:8000\r\n"
            b"Accept: application/json\r\n"
            b"Connection: close\r\n\r\n"
        )
    ]
    assert fake_socket.recv_sizes
    assert max(fake_socket.recv_sizes) <= 4096
    assert fake_socket.closed is True
    assert all(0 < timeout <= 5.0 for timeout in fake_socket.timeouts)


@pytest.mark.parametrize(
    ("host", "port", "path"),
    (
        ("localhost", 8000, "/api/daemon/status"),
        ("0.0.0.0", 8000, "/api/daemon/status"),
        ("127.0.0.2", 8000, "/api/daemon/status"),
        ("127.0.0.1", 8001, "/api/daemon/status"),
        ("127.0.0.1", 8000, "/api/daemon/status/"),
    ),
)
def test_daemon_status_reader_rejects_nonloopback_or_nonfixed_endpoint(
    host: str,
    port: int,
    path: str,
) -> None:
    fake_socket = _FakeLoopbackSocket((_daemon_status_response(b'{"version":"2.3.4"}'),))
    reader, socket_calls = _daemon_status_reader(
        fake_socket,
        host=host,
        port=port,
        path=path,
    )

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        reader.read_version(deadline=_FUTURE_DEADLINE, max_bytes=256)
    assert socket_calls == []
    assert fake_socket.connected is None


@pytest.mark.parametrize(
    "response",
    (
        _daemon_status_response(b'{"version":"2.3.4"}', status=b"302 Found"),
        _daemon_status_response(b'{"version":"2.3.4"}', content_type=b"text/plain"),
        _daemon_status_response(
            b'{"version":"2.3.4"}', extra_headers=((b"content-type", b"application/json"),)
        ),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
        _daemon_status_response(b'{"version":'),
        _daemon_status_response(b'{"version":"2.3.4","version":"2.3.4"}'),
        _daemon_status_response(b'{"version":"2.3.4"}') + b"x",
        _daemon_status_response(b'{"version":"2.3.4-dev"}'),
        _daemon_status_response(b"{}"),
        _daemon_status_response(b'{"version":"' + (b"1" * 260) + b'"}'),
    ),
)
def test_daemon_status_reader_rejects_redirect_non_json_malformed_duplicate_trailing_or_oversize(
    response: bytes,
) -> None:
    fake_socket = _FakeLoopbackSocket((response,))
    reader, _socket_calls = _daemon_status_reader(fake_socket)

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        reader.read_version(deadline=_FUTURE_DEADLINE, max_bytes=256)
    assert fake_socket.closed is True


@pytest.mark.parametrize("transfer_encoding", (b"chunked", b"identity", b"gzip, chunked"))
def test_daemon_status_reader_rejects_any_transfer_encoding_header(
    transfer_encoding: bytes,
) -> None:
    fake_socket = _FakeLoopbackSocket(
        (
            _daemon_status_response(
                b'{"version":"2.3.4"}',
                extra_headers=((b"Transfer-Encoding", transfer_encoding),),
            ),
        )
    )
    reader, _socket_calls = _daemon_status_reader(fake_socket)

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        reader.read_version(deadline=_FUTURE_DEADLINE, max_bytes=256)
    assert fake_socket.closed is True


def test_daemon_status_reader_rejects_slow_drip_under_service_timeout() -> None:
    fake_socket = _FakeLoopbackSocket((b"HTTP/1.1 200 OK\r\n", TimeoutError("timed out")))
    reader, _socket_calls = _daemon_status_reader(fake_socket)

    with pytest.raises(TimeoutError, match="unsafe Reachy runtime compatibility") as caught:
        reader.read_version(deadline=_FUTURE_DEADLINE, max_bytes=256)
    assert str(caught.value) == "unsafe Reachy runtime compatibility"
    assert fake_socket.closed is True


def test_daemon_status_reader_rejects_body_beyond_declared_bound_without_unbounded_reads() -> None:
    fake_socket = _FakeLoopbackSocket((_daemon_status_response(b'{"version":"2.3.4"}' * 40),))
    reader, _socket_calls = _daemon_status_reader(fake_socket)

    with pytest.raises(RuntimeError, match="unsafe Reachy runtime compatibility"):
        reader.read_version(deadline=_FUTURE_DEADLINE, max_bytes=256)
    assert fake_socket.recv_sizes
    assert max(fake_socket.recv_sizes) <= 4096
