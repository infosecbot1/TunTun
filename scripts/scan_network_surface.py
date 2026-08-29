from __future__ import annotations

import ipaddress
import os
import platform
import re
import selectors
import subprocess
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from contextlib import suppress
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
PROCESS_ROW = re.compile(
    r"^\s*(?P<pid>[0-9]+)\s+"
    r"(?P<started>\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+"
    r"(?P<command>\S.*)$"
)
PROCESS_COMMAND = ("ps", "-ww", "-axo", "pid=,lstart=,args=")
SERVICE_OWNERS = ("camera_source", "core", "media_proxy", "owner_ingress", "recorder")
GENERIC_EXECUTABLES = {
    "bash",
    "bun",
    "dash",
    "deno",
    "env",
    "java",
    "node",
    "nodejs",
    "perl",
    "php",
    "ruby",
    "sh",
    "uv",
    "zsh",
}


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
    identity: str = ""
    command: str = ""


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
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    streams: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENVIRONMENT,
        )
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
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
        if process is not None:
            if process.poll() is None:
                process.kill()
            with suppress(subprocess.SubprocessError):
                process.wait(timeout=1.0)


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


def _service_owner(executable: str, command: str) -> str:
    candidates: set[str] = set()
    for raw in (executable, *re.findall(r"[A-Za-z0-9_./-]+", command)):
        token = Path(raw).name.lower().removesuffix(".py").replace("-", "_")
        for owner in SERVICE_OWNERS:
            if token in {owner, f"tuntun_{owner}"} or token.startswith(f"tuntun_{owner}."):
                candidates.add(owner)
    if len(candidates) == 1:
        return next(iter(candidates))
    if candidates:
        return ""
    native = re.sub(r"[^a-z0-9_]+", "_", executable.lower().replace("-", "_")).strip("_")
    generic = native in GENERIC_EXECUTABLES or re.fullmatch(r"python[0-9_]*", native) is not None
    if generic or not native or len(native) > 55:
        return ""
    return f"external_{native}"


def _process_records(raw: bytes, generation: int) -> tuple[ProcessRecord, ...]:
    try:
        process_text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProbeError("probe-invalid-utf8") from error
    processes: list[ProcessRecord] = []
    for line in process_text.splitlines():
        match = PROCESS_ROW.fullmatch(line)
        if match is None:
            raise ProbeError("process-row-invalid")
        pid = int(match.group("pid"))
        command = match.group("command")
        executable = Path(command.split(maxsplit=1)[0]).name
        processes.append(
            ProcessRecord(
                pid,
                executable,
                _service_owner(executable, command),
                generation,
                match.group("started"),
                command,
            )
        )
    if len({row.pid for row in processes}) != len(processes):
        raise ProbeError("process-row-duplicate")
    return tuple(processes)


def _linux_socket_records(raw: bytes, generation: int) -> tuple[SocketRecord, ...]:
    try:
        socket_text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProbeError("probe-invalid-utf8") from error
    sockets: list[SocketRecord] = []
    for line in socket_text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            raise ProbeError("socket-row-invalid")
        protocol = fields[0].lower().removesuffix("6")
        if protocol not in {"tcp", "udp"}:
            raise ProbeError("socket-row-invalid")
        address, port = _split_endpoint(fields[4])
        pid_matches = re.findall(r"\bpid=(\d+)\b", line)
        if not pid_matches:
            raise ProbeError("socket-pid-missing")
        pids = tuple(int(pid) for pid in pid_matches)
        if len(set(pids)) != len(pids):
            raise ProbeError("socket-row-invalid")
        sockets.extend(SocketRecord(protocol, address, port, pid, generation) for pid in pids)
    return tuple(sockets)


def _darwin_socket_records(raw: bytes, generation: int) -> tuple[SocketRecord, ...]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ProbeError("probe-invalid-utf8") from error
    sockets: list[SocketRecord] = []
    pid: int | None = None
    protocol: str | None = None
    endpoint: str | None = None
    listening = False
    record_active = False

    def finish_record() -> None:
        nonlocal protocol, endpoint, listening, record_active
        if not record_active:
            return
        if pid is None or protocol not in {"tcp", "udp"} or endpoint is None:
            raise ProbeError("socket-owner-missing")
        if protocol == "udp" and endpoint == "*:*":
            protocol = None
            endpoint = None
            listening = False
            record_active = False
            return
        if protocol == "tcp" and not listening:
            raise ProbeError("socket-owner-missing")
        address, port = _split_endpoint(endpoint.split("->", 1)[0])
        sockets.append(SocketRecord(protocol, address, port, pid, generation))
        protocol = None
        endpoint = None
        listening = False
        record_active = False

    for line in lines:
        if not line:
            continue
        field, value = line[0], line[1:]
        if field == "p":
            finish_record()
            if not value.isdecimal():
                raise ProbeError("process-row-invalid")
            pid = int(value)
        elif field == "f":
            finish_record()
            record_active = True
        elif field == "P":
            record_active = True
            protocol = value.lower()
        elif field == "T" and value == "ST=LISTEN":
            record_active = True
            listening = True
        elif field == "n":
            record_active = True
            endpoint = value
    finish_record()
    return tuple(sockets)


def _captured_snapshot(
    generation: int,
    socket_command: tuple[str, ...],
    parser: Callable[[bytes, int], tuple[SocketRecord, ...]],
) -> InventorySnapshot:
    try:
        before = _process_records(_bounded_command(PROCESS_COMMAND), generation)
        sockets = parser(_bounded_command(socket_command), generation)
        after = _process_records(_bounded_command(PROCESS_COMMAND), generation)
    except ProbeError as error:
        return InventorySnapshot((), (), generation, False, (str(error),))
    before_by_pid = {row.pid: row for row in before}
    after_by_pid = {row.pid: row for row in after}
    processes: list[ProcessRecord] = []
    for pid in sorted({row.pid for row in sockets}):
        if before_by_pid.get(pid) != after_by_pid.get(pid):
            return InventorySnapshot((), (), generation, False, ("process-inventory-drift",))
        process = after_by_pid.get(pid)
        if process is None:
            return InventorySnapshot((), (), generation, False, ("socket-owner-missing",))
        if not process.service_owner:
            return InventorySnapshot((), (), generation, False, ("service-owner-unresolved",))
        processes.append(process)
    return InventorySnapshot(sockets, tuple(processes), generation, True)


def _capture_linux(generation: int) -> InventorySnapshot:
    return _captured_snapshot(generation, ("ss", "-H", "-lntup"), _linux_socket_records)


def _capture_darwin(generation: int) -> InventorySnapshot:
    return _captured_snapshot(
        generation,
        ("/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-FpnPT"),
        _darwin_socket_records,
    )


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
    grouped: dict[tuple[str, str, int], list[SocketRecord]] = defaultdict(list)
    seen: set[tuple[str, str, int, int]] = set()
    for socket in snapshot.sockets:
        identity = (socket.protocol, socket.address, socket.port, socket.pid)
        if identity in seen:
            raise AssuranceInputError(Path("<network>"), "socket-row-duplicate")
        seen.add(identity)
        grouped[(socket.protocol, socket.address, socket.port)].append(socket)
    listeners = []
    for (protocol, address, port), sockets in grouped.items():
        owner_rows: list[ProcessRecord] = []
        for socket in sockets:
            owners = processes.get(socket.pid, [])
            if len(owners) != 1:
                raise AssuranceInputError(
                    Path("<network>"), "socket-owner-ambiguous", str(socket.pid)
                )
            owner_rows.append(owners[0])
        service_owners = {owner.service_owner for owner in owner_rows if owner.service_owner}
        if len(service_owners) != 1 or len(service_owners) != len(
            {owner.service_owner for owner in owner_rows}
        ):
            raise AssuranceInputError(Path("<network>"), "socket-owner-ambiguous")
        owner = min(owner_rows, key=lambda row: row.pid)
        listeners.append(
            ListenerRecord(
                protocol,
                address,
                port,
                owner.pid,
                owner.executable,
                owner.service_owner,
            )
        )
    return tuple(sorted(listeners, key=lambda row: (row.protocol, row.address, row.port, row.pid)))


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
        owner = listener.service_owner.lower()
        if arguments.forbid_core_tcp and listener.protocol == "tcp" and owner == "core":
            findings.append(AssuranceFinding(root, "core-tcp-listener", identity))
        if (
            arguments.forbid_media_proxy_tcp
            and listener.protocol == "tcp"
            and owner == "media_proxy"
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
