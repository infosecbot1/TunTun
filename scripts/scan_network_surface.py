from __future__ import annotations

import ipaddress
import os
import platform
import re
import selectors
import subprocess
import time
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        validate_root,
    )
elif __package__:
    from .assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        validate_root,
    )
else:
    from assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        validate_root,
    )

TOOL = "network-surface"
PROBE_TIMEOUT_SECONDS = 10.0
MAX_PROBE_STREAM_BYTES = 4 * 1024 * 1024
SAFE_ENVIRONMENT = {"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
OWNER = re.compile(r"[a-z][a-z0-9_]{0,63}")


@dataclass(frozen=True)
class SocketRecord:
    protocol: str
    address: str
    port: int
    pid: int
    generation: int


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    executable: str
    service_owner: str
    generation: int


@dataclass(frozen=True)
class ListenerRecord:
    protocol: str
    address: str
    port: int
    pid: int
    executable: str
    service_owner: str


@dataclass(frozen=True)
class InventorySnapshot:
    sockets: tuple[SocketRecord, ...]
    processes: tuple[ProcessRecord, ...]
    generation: int
    complete: bool
    errors: tuple[str, ...] = ()


class ProbeError(RuntimeError):
    pass


def _bounded_command(argv: tuple[str, ...]) -> bytes:
    process = subprocess.Popen(
        argv,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=SAFE_ENVIRONMENT,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    streams: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError("probe-timeout")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output = streams[key.data]
                output.extend(chunk)
                if len(output) > MAX_PROBE_STREAM_BYTES:
                    raise ProbeError(f"probe-{key.data}-limit")
        return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        if return_code != 0:
            raise ProbeError("probe-failed")
        return bytes(streams["stdout"])
    except (OSError, subprocess.SubprocessError) as error:
        raise ProbeError("probe-unavailable") from error
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()


def _split_endpoint(value: str) -> tuple[str, int]:
    if value.startswith("["):
        closing = value.rfind("]:")
        if closing < 0:
            raise ProbeError("socket-row-invalid")
        address, port_text = value[1:closing], value[closing + 2 :]
    else:
        address, separator, port_text = value.rpartition(":")
        if not separator:
            raise ProbeError("socket-row-invalid")
    if port_text == "*" or not port_text.isdecimal():
        raise ProbeError("socket-port-unresolved")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ProbeError("socket-port-invalid")
    return address, port


def _capture_linux(generation: int) -> InventorySnapshot:
    socket_raw = _bounded_command(("ss", "-H", "-lntup"))
    process_raw = _bounded_command(("ps", "-axo", "pid=,comm="))
    try:
        socket_text = socket_raw.decode("utf-8")
        process_text = process_raw.decode("utf-8")
    except UnicodeDecodeError:
        return InventorySnapshot((), (), generation, False, ("probe-invalid-utf8",))
    processes: list[ProcessRecord] = []
    for line in process_text.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or not fields[0].isdecimal():
            return InventorySnapshot((), (), generation, False, ("process-row-invalid",))
        executable = Path(fields[1]).name
        processes.append(ProcessRecord(int(fields[0]), executable, executable, generation))
    sockets: list[SocketRecord] = []
    for line in socket_text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            return InventorySnapshot(
                (), tuple(processes), generation, False, ("socket-row-invalid",)
            )
        protocol = fields[0].lower().removesuffix("6")
        local_index = 4 if protocol == "tcp" else 4
        try:
            address, port = _split_endpoint(fields[local_index])
        except ProbeError as error:
            return InventorySnapshot((), tuple(processes), generation, False, (str(error),))
        pid_match = re.search(r"pid=(\d+)", line)
        if pid_match is None:
            return InventorySnapshot(
                (), tuple(processes), generation, False, ("socket-pid-missing",)
            )
        sockets.append(SocketRecord(protocol, address, port, int(pid_match.group(1)), generation))
    return InventorySnapshot(tuple(sockets), tuple(processes), generation, True)


def _capture_darwin(generation: int) -> InventorySnapshot:
    raw = _bounded_command(("/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP", "-FpcnPT"))
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return InventorySnapshot((), (), generation, False, ("probe-invalid-utf8",))
    sockets: list[SocketRecord] = []
    processes: dict[int, ProcessRecord] = {}
    pid: int | None = None
    executable: str | None = None
    protocol: str | None = None
    for line in lines:
        if not line:
            continue
        field, value = line[0], line[1:]
        if field == "p":
            if not value.isdecimal():
                return InventorySnapshot((), (), generation, False, ("process-row-invalid",))
            pid = int(value)
            executable = None
            protocol = None
        elif field == "c" and pid is not None:
            executable = value
            processes[pid] = ProcessRecord(pid, value, value, generation)
        elif field == "P":
            protocol = value.lower()
        elif field == "n":
            endpoint = value.split("->", 1)[0]
            if pid is None or executable is None or protocol not in {"tcp", "udp"}:
                return InventorySnapshot(
                    (), tuple(processes.values()), generation, False, ("socket-owner-missing",)
                )
            try:
                address, port = _split_endpoint(endpoint)
            except ProbeError as error:
                return InventorySnapshot(
                    (), tuple(processes.values()), generation, False, (str(error),)
                )
            sockets.append(SocketRecord(protocol, address, port, pid, generation))
    return InventorySnapshot(tuple(sockets), tuple(processes.values()), generation, True)


def capture_inventory() -> InventorySnapshot:
    generation = time.monotonic_ns()
    try:
        system = platform.system()
        if system == "Linux":
            return _capture_linux(generation)
        if system == "Darwin":
            return _capture_darwin(generation)
        return InventorySnapshot((), (), generation, False, ("unsupported-platform",))
    except ProbeError as error:
        return InventorySnapshot((), (), generation, False, (str(error),))


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="scan_network_surface.py")
    parser.add_argument("--root", default=".")
    parser.add_argument("--require-listener", action="append", default=[])
    parser.add_argument("--forbid-lan-port", action="append", default=[])
    parser.add_argument(
        "--optional-exact-commissioned-private-lan-port", action="append", default=[]
    )
    parser.add_argument("--forbid-wildcard", action="store_true")
    parser.add_argument("--forbid-ipv6", action="store_true")
    parser.add_argument("--forbid-core-tcp", action="store_true")
    parser.add_argument("--forbid-media-proxy-tcp", action="store_true")
    parser.add_argument("--forbid-camera-ports", action="store_true")
    parser.add_argument("--forbid-camera-public", action="store_true")
    return parser


def _port(value: str) -> int:
    if not value.isdecimal() or (value.startswith("0") and value != "0"):
        raise ValueError("port must be canonical")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("port is out of range")
    return port


def _owner(value: str) -> str:
    if OWNER.fullmatch(value) is None:
        raise ValueError("owner must be canonical")
    return value


def _required(value: str) -> tuple[str, int, str]:
    endpoint, separator, owner = value.partition("=")
    if not separator or "=" in owner:
        raise ValueError("listener must be ADDRESS:PORT=OWNER")
    if endpoint.startswith("["):
        closing = endpoint.rfind("]:")
        if closing < 0:
            raise ValueError("listener address is invalid")
        address, port_text = endpoint[1:closing], endpoint[closing + 2 :]
    else:
        address, colon, port_text = endpoint.rpartition(":")
        if not colon:
            raise ValueError("listener address is invalid")
    try:
        canonical = ipaddress.ip_address(address).compressed
    except ValueError as error:
        raise ValueError("listener address is invalid") from error
    if canonical != address:
        raise ValueError("listener address must be canonical")
    return address, _port(port_text), _owner(owner)


def _commissioned(value: str) -> tuple[int, str]:
    port, separator, owner = value.partition("=")
    if not separator or "=" in owner:
        raise ValueError("commissioned listener must be PORT=OWNER")
    return _port(port), _owner(owner)


def _listeners(snapshot: InventorySnapshot) -> tuple[ListenerRecord, ...]:
    if not snapshot.complete or snapshot.errors:
        raise AssuranceInputError(
            Path("<network>"), "inventory-incomplete", ",".join(snapshot.errors)
        )
    generations_match = all(
        row.generation == snapshot.generation for row in snapshot.sockets
    ) and all(row.generation == snapshot.generation for row in snapshot.processes)
    if not generations_match:
        raise AssuranceInputError(Path("<network>"), "inventory-generation-mismatch")
    processes: dict[int, list[ProcessRecord]] = defaultdict(list)
    for row in snapshot.processes:
        processes[row.pid].append(row)
    listeners = []
    seen: set[tuple[str, str, int, int]] = set()
    for socket in snapshot.sockets:
        owners = processes.get(socket.pid, [])
        if len(owners) != 1:
            raise AssuranceInputError(Path("<network>"), "socket-owner-ambiguous", str(socket.pid))
        identity = (socket.protocol, socket.address, socket.port, socket.pid)
        if identity in seen:
            raise AssuranceInputError(Path("<network>"), "socket-row-duplicate")
        seen.add(identity)
        owner = owners[0]
        listeners.append(
            ListenerRecord(
                socket.protocol,
                socket.address,
                socket.port,
                socket.pid,
                owner.executable,
                owner.service_owner,
            )
        )
    return tuple(listeners)


def _is_wildcard(address: str) -> bool:
    return address in {"0.0.0.0", "::", "*"}


def _is_lan(address: str) -> bool:
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not value.is_loopback and (value.is_private or value.is_link_local)


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        root = validate_root(lexical_path(arguments.root))
        required = tuple(_required(item) for item in arguments.require_listener)
        lan_ports = tuple(_port(item) for item in arguments.forbid_lan_port)
        commissioned = tuple(
            _commissioned(item) for item in arguments.optional_exact_commissioned_private_lan_port
        )
        if (
            len(set(required)) != len(required)
            or len(set(lan_ports)) != len(lan_ports)
            or len(set(commissioned)) != len(commissioned)
        ):
            raise ValueError("network selectors must be unique")
        listeners = _listeners(capture_inventory())
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )

    findings: list[AssuranceFinding] = []
    for address, port, owner in required:
        matches = [item for item in listeners if item.address == address and item.port == port]
        if len(matches) != 1 or matches[0].service_owner != owner:
            findings.append(
                AssuranceFinding(root, "required-listener-mismatch", f"{address}:{port}={owner}")
            )
    for port in lan_ports:
        for listener in listeners:
            if listener.port == port and _is_lan(listener.address):
                findings.append(AssuranceFinding(root, "forbidden-lan-port", str(port)))
    for port, owner in commissioned:
        matches = [item for item in listeners if item.port == port]
        if matches and (
            len(matches) != 1
            or matches[0].service_owner != owner
            or not _is_lan(matches[0].address)
        ):
            findings.append(
                AssuranceFinding(root, "commissioned-listener-mismatch", f"{port}={owner}")
            )
    for listener in listeners:
        identity = f"{listener.address}:{listener.port}={listener.service_owner}"
        if arguments.forbid_wildcard and _is_wildcard(listener.address):
            findings.append(AssuranceFinding(root, "wildcard-listener", identity))
        if arguments.forbid_ipv6 and ":" in listener.address:
            findings.append(AssuranceFinding(root, "ipv6-listener", identity))
        owner = (listener.service_owner + " " + listener.executable).lower()
        if arguments.forbid_core_tcp and listener.protocol == "tcp" and "core" in owner:
            findings.append(AssuranceFinding(root, "core-tcp-listener", identity))
        if (
            arguments.forbid_media_proxy_tcp
            and listener.protocol == "tcp"
            and ("media_proxy" in owner or "media-proxy" in owner)
        ):
            findings.append(AssuranceFinding(root, "media-proxy-tcp-listener", identity))
        if arguments.forbid_camera_ports and listener.port in {554, 8554, 3702}:
            findings.append(AssuranceFinding(root, "camera-port-listener", identity))
        if (
            arguments.forbid_camera_public
            and "camera" in owner
            and not ipaddress.ip_address(listener.address).is_loopback
        ):
            findings.append(AssuranceFinding(root, "camera-public-listener", identity))
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
