from __future__ import annotations

import getpass
import hashlib
import shlex
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path
from uuid import UUID

import pytest
from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_core.adapters.reachy.ssh_forced import (
    DispatchVerb,
    SshBridgeError,
    SshForcedCommandProcess,
    SshLoopbackContractTarget,
    build_pinned_ssh_argv,
)

OPERATION_ID = UUID("61000000-0000-4000-8000-000000000001")
COMMISSIONING_ID = UUID("60000000-0000-4000-8000-000000000001")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(*argv: str) -> None:
    subprocess.run(argv, check=True, capture_output=True)


def _authorized_key_line(*, public_key: str, dispatcher: Path) -> str:
    forced_command = f"{shlex.quote(sys.executable)} {shlex.quote(str(dispatcher))}"
    assert '"' not in forced_command
    assert "\n" not in forced_command
    return f'restrict,command="{forced_command}" {public_key}\n'


def _write_dispatcher(path: Path) -> None:
    path.write_text(
        """
from __future__ import annotations

import json
import struct
import sys

raw_length = sys.stdin.buffer.read(4)
if len(raw_length) != 4:
    raise SystemExit(65)
length = struct.unpack(">I", raw_length)[0]
body = sys.stdin.buffer.read(length)
request = json.loads(body)
response = {
    "version": 1,
    "operation_id": request["operation_id"],
    "ok": True,
    "state_generation": request["expected_state_generation"],
    "status": "active",
    "payload": {"echo_verb": request["verb"]},
}
payload = json.dumps(response, allow_nan=False, separators=(",", ":"), sort_keys=True).encode()
sys.stdout.buffer.write(struct.pack(">I", len(payload)))
sys.stdout.buffer.write(payload)
sys.stdout.buffer.flush()
""".lstrip(),
        encoding="utf-8",
    )
    path.chmod(0o700)


def _write_hanging_dispatcher(path: Path) -> None:
    path.write_text(
        """
from __future__ import annotations

import signal
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(60)
""".lstrip(),
        encoding="utf-8",
    )
    path.chmod(0o700)


@pytest.fixture
def local_sshd(
    tmp_path: Path,
) -> Generator[tuple[SshLoopbackContractTarget, subprocess.Popen[bytes]], None, None]:
    sshd = shutil.which("sshd")
    ssh_keygen = shutil.which("ssh-keygen")
    if sshd is None or ssh_keygen is None:
        pytest.fail("local OpenSSH sshd and ssh-keygen are required prerequisites")

    port = _free_loopback_port()
    host_key = tmp_path / "ssh_host_ed25519_key"
    client_key = tmp_path / "id_tuntun_contract"
    authorized_keys = tmp_path / "authorized_keys"
    known_hosts = tmp_path / "known_hosts"
    dispatcher = tmp_path / "forced_dispatcher.py"
    config = tmp_path / "sshd_config"
    log_path = tmp_path / "sshd.log"
    _run(ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(host_key))
    _run(ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(client_key))
    _write_dispatcher(dispatcher)
    public_key = client_key.with_suffix(".pub").read_text(encoding="ascii").strip()
    authorized_keys.write_text(_authorized_key_line(public_key=public_key, dispatcher=dispatcher))
    authorized_keys.chmod(0o600)
    host_public = host_key.with_suffix(".pub").read_text(encoding="ascii").strip()
    known_hosts.write_text(f"[127.0.0.1]:{port} {host_public}\n", encoding="ascii")
    known_hosts.chmod(0o600)
    config.write_text(
        f"""
Port {port}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {tmp_path / "sshd.pid"}
AuthorizedKeysFile {authorized_keys}
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
AllowTcpForwarding no
X11Forwarding no
PermitTTY no
PermitUserEnvironment no
StrictModes no
LogLevel ERROR
""".lstrip(),
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sshd, "-D", "-e", "-f", str(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(50):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.1)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    break
            process.poll()
            if process.returncode is not None:
                stderr = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
                pytest.fail(f"temporary sshd exited before accepting connections: {stderr}")
            time.sleep(0.05)
        else:
            process.terminate()
            pytest.fail("temporary sshd did not accept loopback connections")
        target = SshLoopbackContractTarget(
            user=getpass.getuser(),
            port=port,
            identity_file=client_key,
            known_hosts_file=known_hosts,
            commissioning_id=COMMISSIONING_ID,
            state_generation=3,
            file_commitments={
                "identity_file_sha256": _digest(client_key.read_bytes()),
                "known_hosts_file_sha256": _digest(known_hosts.read_bytes()),
            },
        )
        yield target, process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        log_path.write_bytes(process.stderr.read() if process.stderr else b"")


@pytest.fixture
def local_hanging_sshd(
    tmp_path: Path,
) -> Generator[tuple[SshLoopbackContractTarget, subprocess.Popen[bytes]], None, None]:
    sshd = shutil.which("sshd")
    ssh_keygen = shutil.which("ssh-keygen")
    if sshd is None or ssh_keygen is None:
        pytest.fail("local OpenSSH sshd and ssh-keygen are required prerequisites")

    port = _free_loopback_port()
    host_key = tmp_path / "ssh_host_ed25519_key"
    client_key = tmp_path / "id_tuntun_contract"
    authorized_keys = tmp_path / "authorized_keys"
    known_hosts = tmp_path / "known_hosts"
    dispatcher = tmp_path / "forced_dispatcher_hang.py"
    config = tmp_path / "sshd_config"
    log_path = tmp_path / "sshd.log"
    _run(ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(host_key))
    _run(ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(client_key))
    _write_hanging_dispatcher(dispatcher)
    public_key = client_key.with_suffix(".pub").read_text(encoding="ascii").strip()
    authorized_keys.write_text(_authorized_key_line(public_key=public_key, dispatcher=dispatcher))
    authorized_keys.chmod(0o600)
    host_public = host_key.with_suffix(".pub").read_text(encoding="ascii").strip()
    known_hosts.write_text(f"[127.0.0.1]:{port} {host_public}\n", encoding="ascii")
    known_hosts.chmod(0o600)
    config.write_text(
        f"""
Port {port}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {tmp_path / "sshd.pid"}
AuthorizedKeysFile {authorized_keys}
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
AllowTcpForwarding no
X11Forwarding no
PermitTTY no
PermitUserEnvironment no
StrictModes no
LogLevel ERROR
""".lstrip(),
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sshd, "-D", "-e", "-f", str(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(50):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.1)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    break
            process.poll()
            if process.returncode is not None:
                stderr = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
                pytest.fail(f"temporary sshd exited before accepting connections: {stderr}")
            time.sleep(0.05)
        else:
            process.terminate()
            pytest.fail("temporary sshd did not accept loopback connections")
        target = SshLoopbackContractTarget(
            user=getpass.getuser(),
            port=port,
            identity_file=client_key,
            known_hosts_file=known_hosts,
            commissioning_id=COMMISSIONING_ID,
            state_generation=3,
            file_commitments={
                "identity_file_sha256": _digest(client_key.read_bytes()),
                "known_hosts_file_sha256": _digest(known_hosts.read_bytes()),
            },
        )
        yield target, process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        log_path.write_bytes(process.stderr.read() if process.stderr else b"")


def test_authorized_keys_forced_command_quotes_paths_with_spaces(tmp_path: Path) -> None:
    directory = tmp_path / "path with spaces"
    directory.mkdir()
    dispatcher = directory / "forced dispatcher.py"

    line = _authorized_key_line(
        public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEfakefakefakefakefakefakefakefakefakefake",
        dispatcher=dispatcher,
    )

    assert shlex.quote(str(dispatcher)) in line
    assert line.startswith('restrict,command="')
    assert line.endswith("fakefakefakefakefakefakefakefakefakefake\n")


def test_loopback_openssh_argv_is_exactly_pinned_and_has_no_remote_command(
    local_sshd: tuple[SshLoopbackContractTarget, subprocess.Popen[bytes]],
) -> None:
    target, _server = local_sshd
    validated = target.to_validated_target()

    argv = build_pinned_ssh_argv(validated)

    separator_index = argv.index("--")
    assert argv[:7] == ("/usr/bin/ssh", "-4", "-T", "-F", "/dev/null", "-p", str(target.port))
    assert argv[-2:] == ("--", f"{getpass.getuser()}@127.0.0.1")
    assert len(argv) == separator_index + 2
    assert validated.identity_config_option in argv
    assert validated.known_hosts_config_option in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "ProxyCommand=none" in argv
    assert "ProxyJump=none" in argv


@pytest.mark.asyncio
async def test_loopback_openssh_forced_command_uses_stdin_without_remote_command(
    local_sshd: tuple[SshLoopbackContractTarget, subprocess.Popen[bytes]],
) -> None:
    target, _server = local_sshd
    process = await SshForcedCommandProcess.spawn_target_for_loopback_contract(target)

    response = await process.dispatch(
        DispatchVerb.STATUS,
        operation_id=OPERATION_ID,
        expected_generation=3,
        payload={},
    )
    await process.close()

    assert response.payload == {"echo_verb": "status"}


@pytest.mark.asyncio
async def test_loopback_openssh_hanging_forced_command_is_terminated_on_close(
    local_hanging_sshd: tuple[SshLoopbackContractTarget, subprocess.Popen[bytes]],
) -> None:
    target, _server = local_hanging_sshd
    process = await SshForcedCommandProcess.spawn_target_for_loopback_contract(target)

    await process.close()

    assert process.returncode is not None


@pytest.mark.asyncio
async def test_loopback_openssh_fails_closed_on_host_key_mismatch(
    local_sshd: tuple[SshLoopbackContractTarget, subprocess.Popen[bytes]],
    tmp_path: Path,
) -> None:
    target, _server = local_sshd
    wrong_known_hosts = tmp_path / "wrong_known_hosts"
    wrong_known_hosts.write_text("[127.0.0.1]:65535 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==\n")
    wrong_known_hosts.chmod(0o600)
    wrong_target = target.model_copy(
        update={
            "known_hosts_file": wrong_known_hosts,
            "file_commitments": {
                **target.file_commitments,
                "known_hosts_file_sha256": _digest(wrong_known_hosts.read_bytes()),
            },
        }
    )

    process = await SshForcedCommandProcess.spawn_target_for_loopback_contract(wrong_target)
    try:
        with pytest.raises(SshBridgeError):
            await process.dispatch(
                DispatchVerb.STATUS,
                operation_id=OPERATION_ID,
                expected_generation=3,
                payload={},
            )
    finally:
        await process.close()


def test_loopback_contract_request_body_is_the_exact_stdin_dispatch() -> None:
    raw = canonical_mapping_bytes(
        {
            "commissioning_id": str(COMMISSIONING_ID),
            "expected_state_generation": 3,
            "operation_id": str(OPERATION_ID),
            "payload": {},
            "verb": "status",
            "version": 1,
        }
    )

    assert raw == (
        b'{"commissioning_id":"60000000-0000-4000-8000-000000000001",'
        b'"expected_state_generation":3,'
        b'"operation_id":"61000000-0000-4000-8000-000000000001",'
        b'"payload":{},"verb":"status","version":1}'
    )
