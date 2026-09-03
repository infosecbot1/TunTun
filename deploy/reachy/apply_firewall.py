from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import selectors
import socket
import stat
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any, Final, cast
from uuid import UUID

from tuntun_contracts.base import parse_bounded_json_value

MAX_VENDOR_OUTPUT_BYTES: Final = 1_048_576
NFT_COMMAND: Final = "/usr/sbin/nft"
IP_COMMAND: Final = "/usr/sbin/ip"
ENDPOINT_PATH: Final = Path("/etc/tuntun/reachy/core-endpoint.json")
NETWORK_PATH: Final = Path("/etc/tuntun/reachy/network.json")
CAPABILITY_PATH: Final = Path("/var/lib/tuntun/reachy/capabilities.json")
BUILD_COMMIT_PATH: Final = Path(
    "/var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge/firewall/current/BUILD_COMMIT"
)
BOOT_ID_PATH: Final = Path("/proc/sys/kernel/random/boot_id")
RECEIPT_PATH: Final = Path("/run/tuntun/firewall-boot-receipt.json")
DEGRADED_RECEIPT_PATH: Final = Path("/run/tuntun/firewall-degraded-receipt.json")
KEY_ROOT: Final = Path("/var/lib/tuntun/keys")
RECEIPT_KEY_ID: Final = "firewall-receipt-v1"


class FirewallDegradedError(RuntimeError):
    def __init__(self, reason_code: str, emergency_rules_sha256: str) -> None:
        super().__init__(f"firewall_{reason_code}")
        self.reason_code = reason_code
        self.emergency_rules_sha256 = emergency_rules_sha256


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def _run_bounded_command(
    argv: list[str],
    payload: bytes | None,
    timeout: float,
    error_code: str,
) -> bytes:
    if not argv or any(type(argument) is not str or "\x00" in argument for argument in argv):
        raise ValueError("fixed argv required")
    if payload is not None and (
        type(payload) is not bytes or len(payload) > MAX_VENDOR_OUTPUT_BYTES
    ):
        raise RuntimeError(error_code)
    with contextlib.ExitStack() as stack:
        input_stream = None
        if payload is not None:
            input_stream = stack.enter_context(tempfile.TemporaryFile())
            input_stream.write(payload)
            input_stream.seek(0)
        process = subprocess.Popen(
            argv,
            stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env={"LC_ALL": "C"},
        )
        output = bytearray()
        errors = bytearray()
        selector: selectors.BaseSelector | None = None
        deadline = time.monotonic() + timeout
        try:
            selector = selectors.DefaultSelector()
            stdout = process.stdout
            stderr = process.stderr
            if stdout is None or stderr is None:
                raise RuntimeError(error_code)
            for stream, label in ((stdout, "stdout"), (stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(error_code)
                events = selector.select(remaining)
                if not events:
                    raise TimeoutError(error_code)
                for key, _mask in events:
                    stream_fd = cast(Any, key.fileobj).fileno()
                    chunk = os.read(stream_fd, 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = output if key.data == "stdout" else errors
                    target.extend(chunk)
                    if len(target) > MAX_VENDOR_OUTPUT_BYTES:
                        raise RuntimeError(error_code)
            returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if returncode != 0:
                raise RuntimeError(error_code)
            return bytes(output)
        except BaseException:
            with contextlib_suppress_process_lookup():
                process.kill()
            with contextlib_suppress_process_lookup():
                process.wait(timeout=1)
            raise
        finally:
            if selector is not None:
                selector.close()


def _run_nft(arguments: list[str], payload: bytes | None = None) -> bytes:
    return _run_bounded_command(
        [NFT_COMMAND, *arguments],
        payload,
        timeout=10,
        error_code="nft_transaction_failed",
    )


def _run_ip(arguments: list[str]) -> bytes:
    return _run_bounded_command(
        [IP_COMMAND, *arguments],
        None,
        timeout=5,
        error_code="neighbor_binding_command_failed",
    )


def _parse_ip_json(raw: bytes) -> list[dict[str, Any]]:
    value = parse_bounded_json_value(
        raw,
        max_bytes=MAX_VENDOR_OUTPUT_BYTES,
        max_depth=16,
        max_containers=4096,
        max_structure_tokens=16_384,
    )
    if (
        not isinstance(value, list)
        or len(value) > 256
        or any(not isinstance(row, dict) for row in value)
    ):
        raise PermissionError("invalid_iproute2_json")
    return cast(list[dict[str, Any]], value)


def _parse_nft_json(raw: bytes) -> dict[str, Any]:
    value = parse_bounded_json_value(
        raw,
        max_bytes=MAX_VENDOR_OUTPUT_BYTES,
        max_depth=32,
        max_containers=4096,
        max_structure_tokens=16_384,
    )
    if (
        not isinstance(value, dict)
        or set(value) != {"nftables"}
        or not isinstance(value["nftables"], list)
    ):
        raise PermissionError("invalid_nftables_json")
    return cast(dict[str, Any], value)


def canonical_tuntun_table_semantics(document: dict[str, Any]) -> bytes:
    objects: list[dict[str, Any]] = []
    if not isinstance(document, dict) or set(document) != {"nftables"}:
        raise PermissionError("firewall_semantic_mismatch")
    nftables = document["nftables"]
    if not isinstance(nftables, list):
        raise PermissionError("firewall_semantic_mismatch")
    for command in nftables:
        if not isinstance(command, dict) or len(command) != 1:
            raise PermissionError("firewall_semantic_mismatch")
        command_name, body = next(iter(command.items()))
        if command_name == "metainfo":
            if not isinstance(body, dict):
                raise PermissionError("firewall_semantic_mismatch")
            continue
        if command_name == "destroy":
            if not isinstance(body, dict) or set(body) != {"table"}:
                raise PermissionError("firewall_semantic_mismatch")
            _require_tuntun_object("table", body["table"])
            continue
        if command_name == "add":
            if not isinstance(body, dict) or len(body) != 1:
                raise PermissionError("firewall_semantic_mismatch")
            kind, item = next(iter(body.items()))
        elif command_name in {"table", "chain", "rule"}:
            kind = command_name
            item = body
        else:
            raise PermissionError("firewall_semantic_mismatch")
        if kind not in {"table", "chain", "rule"}:
            raise PermissionError("firewall_semantic_mismatch")
        _require_tuntun_object(kind, item)
        objects.append({kind: _without_volatile(item)})
    if not objects or sum(1 for item in objects if "table" in item) != 1:
        raise PermissionError("firewall_semantic_mismatch")
    return json.dumps(objects, sort_keys=True, separators=(",", ":")).encode("utf-8")


def install_emergency_table() -> str:
    from deploy.reachy.render_firewall import build_emergency_ruleset

    emergency = build_emergency_ruleset()
    payload = json.dumps(emergency, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = canonical_tuntun_table_semantics(emergency)
    _run_nft(["--json", "--file", "-"], payload)
    try:
        observed = _parse_nft_json(_run_nft(["--json", "list", "table", "inet", "tuntun"]))
        observed_canonical = canonical_tuntun_table_semantics(observed)
    except BaseException as error:
        raise PermissionError("firewall_emergency_semantic_mismatch") from error
    if observed_canonical != expected:
        raise PermissionError("firewall_emergency_semantic_mismatch")
    return hashlib.sha256(observed_canonical).hexdigest()


def apply_ruleset(ruleset: dict[str, Any]) -> tuple[str, str]:
    payload = json.dumps(ruleset, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = canonical_tuntun_table_semantics(ruleset)
    try:
        _run_nft(["--check", "--json", "--file", "-"], payload)
        _run_nft(["--json", "--file", "-"], payload)
    except BaseException as error:
        emergency_sha256 = install_emergency_table()
        raise FirewallDegradedError("apply_failed", emergency_sha256) from error
    try:
        observed = _parse_nft_json(_run_nft(["--json", "list", "table", "inet", "tuntun"]))
        canonical_observed = canonical_tuntun_table_semantics(observed)
    except BaseException as error:
        emergency_sha256 = install_emergency_table()
        raise FirewallDegradedError("observation_failed", emergency_sha256) from error
    if canonical_observed != expected:
        emergency_sha256 = install_emergency_table()
        raise FirewallDegradedError("semantic_mismatch", emergency_sha256)
    return hashlib.sha256(expected).hexdigest(), hashlib.sha256(canonical_observed).hexdigest()


def install_neighbor_binding(inputs: Any) -> str:
    _require_on_link_route(inputs)
    _run_ip(
        [
            "-4",
            "neigh",
            "replace",
            inputs.endpoint.core_ipv4,
            "lladdr",
            inputs.endpoint.core_link_address.lower(),
            "nud",
            "permanent",
            "dev",
            inputs.network.reachy_ingress_interface,
        ]
    )
    return require_neighbor_binding(inputs)


def require_neighbor_binding(inputs: Any) -> str:
    route = _require_on_link_route(inputs)
    rows = _parse_ip_json(
        _run_ip(
            [
                "-j",
                "-4",
                "neigh",
                "show",
                "to",
                inputs.endpoint.core_ipv4,
                "dev",
                inputs.network.reachy_ingress_interface,
            ]
        )
    )
    document = _neighbor_binding_document(inputs, rows, route)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def read_fixed_owner_file(path: Path, max_bytes: int, *, exact_mode: int | None = 0o600) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise PermissionError("firewall_fixed_input_path")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or (exact_mode is not None and mode != exact_mode)
            or (exact_mode is None and bool(mode & 0o022))
        ):
            raise PermissionError("firewall_fixed_input_permissions")
        payload = _read_at_most(descriptor, max_bytes)
        if not payload:
            raise PermissionError("firewall_fixed_input_size")
        return payload
    finally:
        os.close(descriptor)


def read_candidate_commit() -> str:
    value = read_fixed_owner_file(BUILD_COMMIT_PATH, 65, exact_mode=None).decode("ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", value) is None:
        raise PermissionError("firewall_candidate_commit_invalid")
    return value


def apply_for_current_boot() -> None:
    emergency_sha256 = install_emergency_table()
    signer = None
    boot_id = None
    phase = "preflight"
    try:
        from tuntun_edge.security.key_store import EdgeKeyStore

        from deploy.reachy.boot_gate import (
            FirewallReceiptRepository,
            LocalReceiptSigner,
            issue_current_boot_receipt,
            issue_degraded_firewall_receipt,
        )
        from deploy.reachy.render_firewall import build_nftables_ruleset, restore_firewall_inputs

        boot_id = UUID(read_fixed_owner_file(BOOT_ID_PATH, 64, exact_mode=None).decode().strip())
        signer = LocalReceiptSigner(RECEIPT_KEY_ID, EdgeKeyStore(KEY_ROOT).read(RECEIPT_KEY_ID))
        endpoint = read_fixed_owner_file(ENDPOINT_PATH, 65_536)
        network = read_fixed_owner_file(NETWORK_PATH, 65_536)
        capabilities = read_fixed_owner_file(CAPABILITY_PATH, 65_536)
        inputs = restore_firewall_inputs(
            endpoint,
            network,
            capabilities,
            available_interfaces={name for _, name in socket.if_nameindex()},
        )
        candidate_commit = read_candidate_commit()
        phase = "neighbor_binding"
        neighbor_sha256 = install_neighbor_binding(inputs)
        ruleset = build_nftables_ruleset(inputs)
        phase = "apply"
        apply_ruleset(ruleset)
        phase = "observation"
        observed = _parse_nft_json(_run_nft(["--json", "list", "table", "inet", "tuntun"]))
        phase = "attestation"
        issue_current_boot_receipt(
            inputs=inputs,
            ruleset=ruleset,
            observed_table=observed,
            neighbor_binding_sha256=neighbor_sha256,
            boot_id=boot_id,
            candidate_commit=candidate_commit,
            clock=SystemClock(),
            signer=signer,
            repository=FirewallReceiptRepository(RECEIPT_PATH),
        )
        DEGRADED_RECEIPT_PATH.unlink(missing_ok=True)
    except BaseException as error:
        try:
            emergency_sha256 = install_emergency_table()
        except BaseException as emergency_error:
            raise BaseExceptionGroup(
                "firewall emergency retention could not be re-observed",
                [error, emergency_error],
            ) from emergency_error
        reason = (
            error.reason_code
            if isinstance(error, FirewallDegradedError)
            else {
                "preflight": "preflight_failed",
                "neighbor_binding": "neighbor_binding_failed",
                "apply": "apply_failed",
                "observation": "observation_failed",
                "attestation": "attestation_failed",
            }[phase]
        )
        if signer is not None and boot_id is not None:
            from deploy.reachy.boot_gate import (
                FirewallReceiptRepository,
                issue_degraded_firewall_receipt,
            )

            issue_degraded_firewall_receipt(
                reason_code=reason,
                emergency_rules_sha256=emergency_sha256,
                boot_id=boot_id,
                clock=SystemClock(),
                signer=signer,
                repository=FirewallReceiptRepository(DEGRADED_RECEIPT_PATH),
            )
        raise RuntimeError(f"firewall_{reason}") from error


def check_packaged_emergency() -> None:
    from deploy.reachy.render_firewall import build_emergency_ruleset

    emergency = build_emergency_ruleset()
    canonical_tuntun_table_semantics(emergency)
    payload = json.dumps(emergency, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _run_nft(["--check", "--json", "--file", "-"], payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--boot", action="store_true")
    mode.add_argument("--emergency-baseline", action="store_true")
    mode.add_argument("--check-packaged-emergency", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.check_packaged_emergency:
        check_packaged_emergency()
    elif arguments.emergency_baseline:
        install_emergency_table()
    else:
        apply_for_current_boot()
    return 0


def _require_on_link_route(inputs: Any) -> dict[str, str]:
    address = inputs.endpoint.core_ipv4
    interface = inputs.network.reachy_ingress_interface
    lookup = _parse_ip_json(_run_ip(["-j", "-4", "route", "get", address, "oif", interface]))
    if (
        len(lookup) != 1
        or lookup[0].get("dev") != interface
        or lookup[0].get("gateway") is not None
    ):
        raise PermissionError("core_endpoint_not_on_link")
    routes = _parse_ip_json(
        _run_ip(["-j", "-4", "route", "show", "match", address, "dev", interface])
    )
    candidates: list[IPv4Network] = []
    for row in routes:
        try:
            network = IPv4Network(str(row.get("dst", "0.0.0.0/0")), strict=False)
        except ValueError:
            continue
        if (
            IPv4Address(address) in network
            and network.prefixlen > 0
            and row.get("dev") == interface
            and row.get("scope") == "link"
            and row.get("gateway") is None
        ):
            candidates.append(network)
    if not candidates:
        raise PermissionError("core_endpoint_not_on_link")
    route = max(candidates, key=lambda item: item.prefixlen)
    return {"route_prefix": route.with_prefixlen, "route_scope": "link"}


def _neighbor_binding_document(
    inputs: Any,
    rows: list[dict[str, Any]],
    route: dict[str, str],
) -> dict[str, Any]:
    if len(rows) != 1:
        raise PermissionError("neighbor_binding_missing_or_ambiguous")
    row = rows[0]
    state = row.get("state")
    states = (
        {state.upper()} if isinstance(state, str) else {str(item).upper() for item in state or ()}
    )
    expected = {
        "endpoint_generation": inputs.endpoint.generation,
        "network_generation": inputs.network.generation,
        "route_prefix": route["route_prefix"],
        "route_scope": route["route_scope"],
        "interface": inputs.network.reachy_ingress_interface,
        "ipv4": inputs.endpoint.core_ipv4,
        "link_address": inputs.endpoint.core_link_address.lower(),
        "neighbor_state": "PERMANENT",
    }
    observed = {
        **expected,
        "interface": row.get("dev"),
        "ipv4": row.get("dst"),
        "link_address": str(row.get("lladdr", "")).lower(),
        "neighbor_state": "PERMANENT" if "PERMANENT" in states else "UNVERIFIED",
    }
    if observed != expected:
        raise PermissionError("neighbor_binding_mismatch")
    return expected


def _require_tuntun_object(kind: str, item: object) -> None:
    if not isinstance(item, dict) or item.get("family") != "inet":
        raise PermissionError("firewall_semantic_mismatch")
    if kind == "table":
        if item.get("name") != "tuntun":
            raise PermissionError("firewall_semantic_mismatch")
        return
    if item.get("table") != "tuntun":
        raise PermissionError("firewall_semantic_mismatch")
    if kind == "chain":
        if item.get("name") not in {"input", "forward", "output"}:
            raise PermissionError("firewall_semantic_mismatch")
        return
    if kind == "rule" and item.get("chain") in {"input", "forward", "output"}:
        return
    raise PermissionError("firewall_semantic_mismatch")


def _without_volatile(value: Any, *, counter_value: bool = False) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_volatile(item, counter_value=key == "counter")
            for key, item in value.items()
            if key not in {"handle", "index"}
            and not (counter_value and key in {"packets", "bytes"})
        }
    if isinstance(value, list):
        return [_without_volatile(item, counter_value=counter_value) for item in value]
    return value


def _read_at_most(descriptor: int, max_bytes: int) -> bytes:
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("firewall read byte bound invalid")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65_536, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise PermissionError("firewall_fixed_input_size")
    return b"".join(chunks)


class contextlib_suppress_process_lookup:
    def __enter__(self) -> None:
        return None

    def __exit__(self, error_type: object, error: object, traceback: object) -> bool:
        return isinstance(error, ProcessLookupError)


if __name__ == "__main__":
    raise SystemExit(main())
