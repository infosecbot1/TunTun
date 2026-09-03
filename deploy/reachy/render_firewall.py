from __future__ import annotations

import hashlib
from typing import Annotated, Any

from pydantic import Field, field_validator
from tuntun_contracts.base import ContractModel, parse_contract_json
from tuntun_edge.config import ReachyNetworkConfigV1
from tuntun_edge.reachy.probe import CapabilityReport
from tuntun_edge.transport.commissioning import ReachyCoreEndpointV1

MAX_RESTORED_DOCUMENT_BYTES = 65_536


class FirewallInputs(ContractModel):
    endpoint: ReachyCoreEndpointV1
    network: ReachyNetworkConfigV1
    daemon_ports: Annotated[tuple[int, ...], Field(min_length=1, max_length=16)]
    endpoint_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    network_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("daemon_ports")
    @classmethod
    def exact_daemon_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if (
            any(type(port) is not int or not 1 <= port <= 65_535 for port in value)
            or len(set(value)) != len(value)
            or tuple(sorted(value)) != value
        ):
            raise ValueError("invalid firewall daemon port inventory")
        return value


def restore_firewall_inputs(
    endpoint_json: bytes,
    network_json: bytes,
    capability_json: bytes,
    *,
    available_interfaces: set[str],
) -> FirewallInputs:
    if type(available_interfaces) is not set or any(
        type(name) is not str for name in available_interfaces
    ):
        raise TypeError("available interface inventory must be exact set[str]")
    payloads = (endpoint_json, network_json, capability_json)
    if any(
        type(payload) is not bytes or not payload or len(payload) > MAX_RESTORED_DOCUMENT_BYTES
        for payload in payloads
    ):
        raise ValueError("firewall_input_document_size")
    endpoint = parse_contract_json(
        ReachyCoreEndpointV1,
        endpoint_json,
        max_bytes=MAX_RESTORED_DOCUMENT_BYTES,
        require_canonical=True,
    )
    network = parse_contract_json(
        ReachyNetworkConfigV1,
        network_json,
        max_bytes=MAX_RESTORED_DOCUMENT_BYTES,
        require_canonical=True,
    )
    capabilities = parse_contract_json(
        CapabilityReport,
        capability_json,
        max_bytes=MAX_RESTORED_DOCUMENT_BYTES,
        require_canonical=True,
    )
    if (
        network.reachy_ingress_interface == "lo"
        or network.reachy_ingress_interface not in available_interfaces
    ):
        raise PermissionError("reachy_ingress_interface_missing")
    if capabilities.source != "hardware":
        raise PermissionError("reachy_capabilities_not_hardware")
    if not (
        capabilities.secure_key_storage_available
        and capabilities.managed_app_lock_available
        and capabilities.competing_controller_detectable
        and capabilities.stop_during_playback_tested
    ):
        raise PermissionError("reachy_capabilities_not_runtime_usable")
    return FirewallInputs(
        endpoint=endpoint,
        network=network,
        daemon_ports=capabilities.daemon_ports,
        endpoint_payload_sha256=hashlib.sha256(endpoint_json).hexdigest(),
        network_payload_sha256=hashlib.sha256(network_json).hexdigest(),
        capability_payload_sha256=hashlib.sha256(capability_json).hexdigest(),
    )


def build_nftables_ruleset(inputs: FirewallInputs) -> dict[str, Any]:
    if type(inputs) is not FirewallInputs:
        raise TypeError("firewall inputs must be exact FirewallInputs")
    interface = inputs.network.reachy_ingress_interface
    ipv4 = inputs.endpoint.core_ipv4
    mac = inputs.endpoint.core_link_address
    return {
        "nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {"destroy": {"table": {"family": "inet", "name": "tuntun"}}},
            {"add": {"table": {"family": "inet", "name": "tuntun"}}},
            *_chains(),
            *_recovery_rules(),
            _input_rule(
                _match(_ct("state"), "established"),
                _match(_meta("iifname"), interface),
                _match(_payload("ip", "saddr"), ipv4),
                _match(_payload("tcp", "sport"), inputs.endpoint.port),
                _accept(),
            ),
            _output_rule(
                _match(_ct("state"), "established"),
                _match(_meta("oifname"), interface),
                _match(_payload("ip", "daddr"), ipv4),
                _match(_payload("tcp", "sport"), 22),
                _accept(),
            ),
            _input_rule(
                _match(_meta("iifname"), interface),
                _match(_payload("ether", "saddr"), mac),
                _match(_payload("ip", "saddr"), ipv4),
                _match(_payload("tcp", "dport"), 22),
                _accept(),
            ),
            _output_rule(
                _match(_meta("oifname"), interface),
                _match(_payload("ip", "daddr"), ipv4),
                _match(_payload("tcp", "dport"), inputs.endpoint.port),
                _accept(),
            ),
        ]
    }


def build_emergency_ruleset() -> dict[str, Any]:
    return {
        "nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {"destroy": {"table": {"family": "inet", "name": "tuntun"}}},
            {"add": {"table": {"family": "inet", "name": "tuntun"}}},
            *_chains(),
            *_recovery_rules(),
        ]
    }


def _chains() -> tuple[dict[str, Any], ...]:
    return (
        _chain("input"),
        _chain("forward"),
        _chain("output"),
    )


def _chain(name: str) -> dict[str, Any]:
    return {
        "add": {
            "chain": {
                "family": "inet",
                "table": "tuntun",
                "name": name,
                "type": "filter",
                "hook": name,
                "prio": 0,
                "policy": "drop",
            }
        }
    }


def _recovery_rules() -> tuple[dict[str, Any], ...]:
    return (
        _input_rule(_match(_meta("iifname"), "lo"), _accept()),
        _output_rule(_match(_meta("oifname"), "lo"), _accept()),
        _input_rule(
            _match(_payload("udp", "sport"), 67), _match(_payload("udp", "dport"), 68), _accept()
        ),
        _output_rule(
            _match(_payload("udp", "sport"), 68), _match(_payload("udp", "dport"), 67), _accept()
        ),
        _input_rule(
            _match(_payload("udp", "sport"), 547), _match(_payload("udp", "dport"), 546), _accept()
        ),
        _output_rule(
            _match(_payload("udp", "sport"), 546), _match(_payload("udp", "dport"), 547), _accept()
        ),
        _input_rule(
            _match(_meta("l4proto"), "icmp"),
            _match(
                _payload("icmp", "type"),
                {"set": ["destination-unreachable", "time-exceeded", "parameter-problem"]},
                "in",
            ),
            _accept(),
        ),
        _output_rule(
            _match(_meta("l4proto"), "icmp"),
            _match(
                _payload("icmp", "type"),
                {"set": ["destination-unreachable", "time-exceeded", "parameter-problem"]},
                "in",
            ),
            _accept(),
        ),
        _input_rule(
            _match(_meta("l4proto"), "ipv6-icmp"),
            _match(
                _payload("icmpv6", "type"),
                {
                    "set": [
                        "destination-unreachable",
                        "packet-too-big",
                        "time-exceeded",
                        "parameter-problem",
                        "nd-router-advert",
                        "nd-neighbor-solicit",
                        "nd-neighbor-advert",
                    ]
                },
                "in",
            ),
            _accept(),
        ),
        _output_rule(
            _match(_meta("l4proto"), "ipv6-icmp"),
            _match(
                _payload("icmpv6", "type"),
                {
                    "set": [
                        "destination-unreachable",
                        "packet-too-big",
                        "time-exceeded",
                        "parameter-problem",
                        "nd-router-solicit",
                        "nd-neighbor-solicit",
                        "nd-neighbor-advert",
                    ]
                },
                "in",
            ),
            _accept(),
        ),
    )


def _input_rule(*expressions: dict[str, Any]) -> dict[str, Any]:
    return _rule("input", *expressions)


def _output_rule(*expressions: dict[str, Any]) -> dict[str, Any]:
    return _rule("output", *expressions)


def _rule(chain: str, *expressions: dict[str, Any]) -> dict[str, Any]:
    return {
        "add": {
            "rule": {
                "family": "inet",
                "table": "tuntun",
                "chain": chain,
                "expr": list(expressions),
            }
        }
    }


def _match(left: dict[str, Any], right: Any, operator: str = "==") -> dict[str, Any]:
    return {"match": {"op": operator, "left": left, "right": right}}


def _payload(protocol: str, field: str) -> dict[str, Any]:
    return {"payload": {"protocol": protocol, "field": field}}


def _meta(key: str) -> dict[str, Any]:
    return {"meta": {"key": key}}


def _ct(key: str) -> dict[str, Any]:
    return {"ct": {"key": key}}


def _accept() -> dict[str, None]:
    return {"accept": None}
