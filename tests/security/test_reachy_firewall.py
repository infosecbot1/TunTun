from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError
from tuntun_contracts.base import ContractParseError, canonical_bytes
from tuntun_edge.config import ReachyNetworkConfigV1
from tuntun_edge.reachy.probe import CapabilityReport
from tuntun_edge.transport.commissioning import ReachyCoreEndpointV1

from deploy.reachy.render_firewall import build_nftables_ruleset, restore_firewall_inputs

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
BOOT_ID = UUID("00000000-0000-0000-0000-00000000c001")
BUILD_COMMIT = "a" * 40
RECEIPT_KEY = b"receipt-key-material-32-bytes-ok!!"


class Clock:
    def now(self) -> datetime:
        return NOW


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class FirewallCase:
    endpoint: ReachyCoreEndpointV1
    network: ReachyNetworkConfigV1
    capabilities: CapabilityReport

    @property
    def endpoint_json(self) -> bytes:
        return canonical_bytes(self.endpoint)

    @property
    def network_json(self) -> bytes:
        return canonical_bytes(self.network)

    @property
    def capabilities_json(self) -> bytes:
        return canonical_bytes(self.capabilities)

    def network_json_with_interface(self, value: str) -> bytes:
        body = self.network.model_dump(mode="python")
        body["reachy_ingress_interface"] = value
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def persisted_documents_with(
        self,
        document: str,
        field: str,
        invalid: Any,
    ) -> tuple[bytes, bytes, bytes]:
        endpoint = self.endpoint.model_dump(mode="python")
        network = self.network.model_dump(mode="python")
        capabilities = self.capabilities.model_dump(mode="python")
        target = {"endpoint": endpoint, "network": network, "capabilities": capabilities}[document]
        target[field] = invalid
        return (
            json.dumps(endpoint, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            json.dumps(network, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            json.dumps(capabilities, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

    def input_policy(self, ruleset: dict[str, Any]) -> str:
        return _chain_policy(ruleset, "input")

    def forward_policy(self, ruleset: dict[str, Any]) -> str:
        return _chain_policy(ruleset, "forward")

    def output_policy(self, ruleset: dict[str, Any]) -> str:
        return _chain_policy(ruleset, "output")

    def has_loopback_accept(self, ruleset: dict[str, Any]) -> bool:
        return any(
            _rule_has(rule, "iifname", "lo") or _rule_has(rule, "oifname", "lo")
            for rule in _rules(ruleset)
        )

    def has_required_icmp_and_dhcp(self, ruleset: dict[str, Any]) -> bool:
        encoded = json.dumps(ruleset, sort_keys=True, separators=(",", ":"))
        return (
            "icmp" in encoded
            and "ipv6-icmp" in encoded
            and any(
                _rule_has(rule, "sport", 67) and _rule_has(rule, "dport", 68)
                for rule in _rules(ruleset)
            )
            and any(
                _rule_has(rule, "sport", 68) and _rule_has(rule, "dport", 67)
                for rule in _rules(ruleset)
            )
        )

    def has_ipv6_ssh_accept(self, ruleset: dict[str, Any]) -> bool:
        for rule in _rules(ruleset):
            encoded = json.dumps(rule, sort_keys=True, separators=(",", ":"))
            if (
                _rule_has(rule, "dport", 22)
                and '"protocol":"ip6"' in encoded
                and '"accept"' in encoded
            ):
                return True
        return False

    def output_wss_match(self, ruleset: dict[str, Any]) -> tuple[str, str, int]:
        for rule in _rules(ruleset, chain="output"):
            if not _rule_has(rule, "dport", 7443):
                continue
            return (
                _match_right(rule, "oifname"),
                _match_right(rule, "daddr"),
                _match_right(rule, "dport"),
            )
        raise AssertionError("WSS output rule missing")

    def output_has_ether_destination_match(self, ruleset: dict[str, Any]) -> bool:
        for rule in _rules(ruleset, chain="output"):
            encoded = json.dumps(rule, sort_keys=True, separators=(",", ":"))
            if (
                _rule_has(rule, "dport", 7443)
                and '"protocol":"ether"' in encoded
                and '"field":"daddr"' in encoded
            ):
                return True
        return False

    def has_generic_established_accept(self, ruleset: dict[str, Any]) -> bool:
        for rule in _rules(ruleset):
            encoded = json.dumps(rule, sort_keys=True, separators=(",", ":"))
            if (
                '"state"' in encoded
                and '"established"' in encoded
                and '"accept"' in encoded
                and not any(
                    _rule_has(rule, field, port)
                    for field, port in (
                        ("dport", 7443),
                        ("sport", 7443),
                        ("dport", 22),
                        ("sport", 22),
                    )
                )
            ):
                return True
        return False

    def has_exact_wss_and_ssh_reply_rules(self, ruleset: dict[str, Any]) -> bool:
        encoded = json.dumps(ruleset, sort_keys=True, separators=(",", ":"))
        return (
            any(_rule_has(rule, "sport", 7443) for rule in _rules(ruleset))
            and any(_rule_has(rule, "dport", 7443) for rule in _rules(ruleset))
            and any(_rule_has(rule, "sport", 22) for rule in _rules(ruleset))
            and any(_rule_has(rule, "dport", 22) for rule in _rules(ruleset))
            and self.endpoint.core_ipv4 in encoded
            and self.endpoint.core_link_address in encoded
        )


@pytest.fixture()
def firewall_case() -> FirewallCase:
    endpoint = ReachyCoreEndpointV1(
        schema_version="tuntun.reachy-core-endpoint.v1",
        commissioning_uuid="00000000-0000-0000-0000-00000000c011",
        generation=7,
        certificate_generation=7,
        server_key_generation=7,
        trust_digest_generation=7,
        client_tls_key_generation=7,
        device_signing_key_generation=7,
        hmac_key_generation=7,
        core_ipv4="192.168.50.10",
        core_link_address="02:00:00:00:00:10",
        port=7443,
        household_ca_sha256=_digest("household-ca"),
        server_leaf_sha256=_digest("server-leaf"),
        server_key_id="ed25519:reachy-core:v7",
        server_public_key_sha256=_digest("server-public"),
        server_ip_sans=("192.168.50.10",),
        client_certificate_sha256=_digest("client-leaf"),
        client_tls_key_id="reachy-client-tls-g7-abc12345",
        client_tls_public_key_sha256=_digest("client-tls-public"),
        device_signing_key_id="ed25519:reachy-edge:v7",
        device_signing_public_key_sha256=_digest("device-public"),
        hmac_key_id="reachy-frame-hmac-g7-abc12345",
        hmac_key_sha256=_digest("hmac-root"),
        hmac_agreement_public_key_sha256=_digest("hmac-agreement"),
        dhcp_reservation_receipt_sha256=_digest("dhcp"),
        boot_identity_sha256=_digest("boot"),
        capability_evidence_sha256=_digest("capability"),
    )
    network = ReachyNetworkConfigV1(
        schema_version="tuntun.reachy-network-config.v1",
        generation=3,
        reachy_ingress_interface="eth0",
    )
    capabilities = CapabilityReport(
        schema_version="tuntun.reachy-capability-report.v1",
        source="hardware",
        probe_version="0.1.0",
        sdk_version="1.2.3",
        daemon_version="4.5.6",
        input_rate_hz=16000,
        input_channels=1,
        output_rate_hz=16000,
        output_channels=1,
        aec_available=True,
        doa_available=True,
        daemon_ports=(8000, 8001),
        secure_key_storage_available=True,
        managed_app_lock_available=True,
        competing_controller_detectable=True,
        stop_during_playback_tested=True,
        rtc_available=True,
        rtc_cold_boot_retains_utc=True,
        rtc_max_drift_seconds_30d=1.0,
        rtc_qualified=True,
    )
    return FirewallCase(endpoint=endpoint, network=network, capabilities=capabilities)


def test_rules_default_deny_ipv4_ipv6_and_bind_paired_mac(firewall_case: FirewallCase) -> None:
    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    rules = build_nftables_ruleset(inputs)
    encoded = json.dumps(rules, sort_keys=True, separators=(",", ":"))

    assert firewall_case.input_policy(rules) == "drop"
    assert firewall_case.forward_policy(rules) == "drop"
    assert firewall_case.output_policy(rules) == "drop"
    assert firewall_case.has_loopback_accept(rules)
    assert firewall_case.has_required_icmp_and_dhcp(rules)
    assert firewall_case.endpoint.core_ipv4 in encoded
    assert firewall_case.endpoint.core_link_address in encoded
    assert firewall_case.network.reachy_ingress_interface in encoded
    assert firewall_case.has_ipv6_ssh_accept(rules) is False
    assert firewall_case.output_wss_match(rules) == (
        firewall_case.network.reachy_ingress_interface,
        firewall_case.endpoint.core_ipv4,
        firewall_case.endpoint.port,
    )
    assert firewall_case.output_has_ether_destination_match(rules) is False
    assert firewall_case.has_generic_established_accept(rules) is False
    assert firewall_case.has_exact_wss_and_ssh_reply_rules(rules) is True


@pytest.mark.parametrize(
    ("document", "field", "invalid"),
    (
        ("network", "reachy_ingress_interface", 'eth0" accept; #'),
        ("network", "reachy_ingress_interface", "eth0\nadd rule inet tuntun input accept"),
        ("network", "reachy_ingress_interface", "lo"),
        ("endpoint", "core_link_address", "aa:bb:cc:dd:ee:ff accept"),
        ("endpoint", "core_link_address", "03:00:00:00:00:10"),
        ("endpoint", "core_link_address", "02:00:00:00:00:FF"),
        ("endpoint", "core_ipv4", "0.0.0.0"),
        ("endpoint", "core_ipv4", "8.8.8.8"),
        ("endpoint", "core_ipv4", "reachy-mini.local"),
        ("capabilities", "daemon_ports", [8000, 70000]),
        ("capabilities", "daemon_ports", [8001, 8000]),
        ("capabilities", "daemon_ports", [8000, 8000]),
        ("capabilities", "daemon_ports", []),
        ("capabilities", "daemon_ports", list(range(8000, 8017))),
    ),
)
def test_malformed_restored_value_is_rejected_before_render(
    firewall_case: FirewallCase,
    document: str,
    field: str,
    invalid: Any,
) -> None:
    restored = firewall_case.persisted_documents_with(document, field, invalid)

    with pytest.raises((ValueError, PermissionError, ContractParseError, ValidationError)):
        restore_firewall_inputs(*restored, available_interfaces={"lo", "eth0"})


def test_syntactically_valid_but_absent_interface_is_rejected(firewall_case: FirewallCase) -> None:
    with pytest.raises(PermissionError, match="reachy_ingress_interface_missing"):
        restore_firewall_inputs(
            firewall_case.endpoint_json,
            firewall_case.network_json_with_interface("eth9"),
            firewall_case.capabilities_json,
            available_interfaces={"lo", "eth0"},
        )


@pytest.mark.parametrize(
    "bad_endpoint",
    (
        b'{"schema_version":"duplicate","schema_version":"duplicate"}',
        b" " + b"{}",
        b'{"value":NaN}',
        b"{" + b'"x":[' * 40 + b"0" + b"]" * 40 + b"}",
    ),
)
def test_hostile_json_inputs_are_rejected_before_rule_build(
    firewall_case: FirewallCase,
    bad_endpoint: bytes,
) -> None:
    with pytest.raises((ContractParseError, ValueError)):
        restore_firewall_inputs(
            bad_endpoint,
            firewall_case.network_json,
            firewall_case.capabilities_json,
            available_interfaces={"lo", "eth0"},
        )


def test_oversized_restored_document_is_rejected_before_rule_build(
    firewall_case: FirewallCase,
) -> None:
    with pytest.raises(ValueError, match="firewall_input_document_size"):
        restore_firewall_inputs(
            b"{" + (b'"x":' + b'"y"' * 40_000) + b"}",
            firewall_case.network_json,
            firewall_case.capabilities_json,
            available_interfaces={"lo", "eth0"},
        )


def test_apply_ruleset_checks_applies_and_attests_only_inet_tuntun(
    firewall_case: FirewallCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    calls: list[list[str]] = []

    def fake_nft(arguments: list[str], payload: bytes | None = None) -> bytes:
        calls.append(arguments)
        if arguments == ["--json", "list", "table", "inet", "tuntun"]:
            return json.dumps(ruleset, sort_keys=True, separators=(",", ":")).encode("utf-8")
        assert payload is not None
        assert b"owner-vpn" not in payload
        return b""

    monkeypatch.setattr(module, "_run_nft", fake_nft)

    expected, observed = module.apply_ruleset(ruleset)

    assert expected == observed
    assert calls == [
        ["--check", "--json", "--file", "-"],
        ["--json", "--file", "-"],
        ["--json", "list", "table", "inet", "tuntun"],
    ]


def test_apply_ruleset_rejects_unrelated_mutation_before_nft_transaction(
    firewall_case: FirewallCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    mutated = build_nftables_ruleset(inputs)
    mutated["nftables"].append({"add": {"table": {"family": "inet", "name": "owner-vpn"}}})
    calls: list[list[str]] = []

    def fake_nft(arguments: list[str], payload: bytes | None = None) -> bytes:
        del payload
        calls.append(arguments)
        return b""

    monkeypatch.setattr(module, "_run_nft", fake_nft)

    with pytest.raises(PermissionError, match="firewall_semantic_mismatch"):
        module.apply_ruleset(mutated)

    assert calls == []


def test_post_apply_observation_failure_installs_emergency_table_and_blocks_edge(
    firewall_case: FirewallCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    mutation_batches: list[str] = []
    list_calls = 0

    def fake_nft(arguments: list[str], payload: bytes | None = None) -> bytes:
        nonlocal list_calls
        if arguments == ["--json", "list", "table", "inet", "tuntun"]:
            list_calls += 1
            if list_calls == 1:
                return b'{"bad":true}'
            from deploy.reachy.render_firewall import build_emergency_ruleset

            return json.dumps(
                build_emergency_ruleset(), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        if payload is not None:
            encoded = payload.decode("utf-8")
            mutation_batches.append("emergency" if '"policy":"drop"' in encoded else "normal")
        return b""

    monkeypatch.setattr(module, "_run_nft", fake_nft)

    with pytest.raises(module.FirewallDegradedError) as error:
        module.apply_ruleset(ruleset)

    assert error.value.reason_code == "observation_failed"
    assert mutation_batches[-1] == "emergency"


def test_emergency_table_is_observed_before_returning_receipt_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module
    from deploy.reachy.render_firewall import build_emergency_ruleset

    emergency = build_emergency_ruleset()
    calls: list[list[str]] = []

    def fake_nft(arguments: list[str], payload: bytes | None = None) -> bytes:
        calls.append(arguments)
        if arguments == ["--json", "list", "table", "inet", "tuntun"]:
            return json.dumps(emergency, sort_keys=True, separators=(",", ":")).encode("utf-8")
        assert payload is not None
        return b""

    monkeypatch.setattr(module, "_run_nft", fake_nft)

    observed_hash = module.install_emergency_table()

    assert len(observed_hash) == 64
    assert calls == [
        ["--json", "--file", "-"],
        ["--json", "list", "table", "inet", "tuntun"],
    ]


def test_emergency_table_observation_mismatch_does_not_claim_expected_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module
    from deploy.reachy.render_firewall import build_emergency_ruleset

    emergency = build_emergency_ruleset()
    observed = build_emergency_ruleset()
    observed["nftables"].append({"add": {"table": {"family": "inet", "name": "owner-vpn"}}})

    def fake_nft(arguments: list[str], payload: bytes | None = None) -> bytes:
        if arguments == ["--json", "list", "table", "inet", "tuntun"]:
            return json.dumps(observed, sort_keys=True, separators=(",", ":")).encode("utf-8")
        assert payload == json.dumps(emergency, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return b""

    monkeypatch.setattr(module, "_run_nft", fake_nft)

    with pytest.raises(PermissionError, match="firewall_emergency_semantic_mismatch"):
        module.install_emergency_table()


def test_routed_core_next_hop_is_rejected_before_neighbor_replace(
    firewall_case: FirewallCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    calls: list[list[str]] = []

    def fake_ip(arguments: list[str]) -> bytes:
        calls.append(arguments)
        if arguments[:5] == ["-j", "-4", "route", "get", "192.168.50.10"]:
            return b'[{"dst":"192.168.50.10","dev":"eth0","gateway":"192.168.50.1"}]'
        raise AssertionError("neighbor replace should not run after routed proof failure")

    monkeypatch.setattr(module, "_run_ip", fake_ip)

    with pytest.raises(PermissionError, match="core_endpoint_not_on_link"):
        module.install_neighbor_binding(inputs)

    assert calls == [["-j", "-4", "route", "get", "192.168.50.10", "oif", "eth0"]]


def test_default_only_link_route_is_rejected_before_neighbor_replace(
    firewall_case: FirewallCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    calls: list[list[str]] = []

    def fake_ip(arguments: list[str]) -> bytes:
        calls.append(arguments)
        if arguments[:4] == ["-j", "-4", "route", "get"]:
            return b'[{"dst":"192.168.50.10","dev":"eth0"}]'
        if arguments[:4] == ["-j", "-4", "route", "show"]:
            return b'[{"dst":"0.0.0.0/0","dev":"eth0","scope":"link"}]'
        if arguments[:3] == ["-4", "neigh", "replace"]:
            return b""
        if arguments[:4] == ["-j", "-4", "neigh", "show"]:
            return (
                b'[{"dst":"192.168.50.10","dev":"eth0",'
                b'"lladdr":"02:00:00:00:00:10","state":["PERMANENT"]}]'
            )
        raise AssertionError(arguments)

    monkeypatch.setattr(module, "_run_ip", fake_ip)

    with pytest.raises(PermissionError, match="core_endpoint_not_on_link"):
        module.install_neighbor_binding(inputs)

    assert calls == [
        ["-j", "-4", "route", "get", "192.168.50.10", "oif", "eth0"],
        ["-j", "-4", "route", "show", "match", "192.168.50.10", "dev", "eth0"],
    ]


def test_default_route_does_not_weaken_valid_specific_link_route(
    firewall_case: FirewallCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    calls: list[list[str]] = []

    def fake_ip(arguments: list[str]) -> bytes:
        calls.append(arguments)
        if arguments[:4] == ["-j", "-4", "route", "get"]:
            return b'[{"dst":"192.168.50.10","dev":"eth0"}]'
        if arguments[:4] == ["-j", "-4", "route", "show"]:
            return (
                b'[{"dst":"0.0.0.0/0","dev":"eth0","scope":"link"},'
                b'{"dst":"192.168.50.0/24","dev":"eth0","scope":"link"}]'
            )
        if arguments[:4] == ["-j", "-4", "neigh", "show"]:
            return (
                b'[{"dst":"192.168.50.10","dev":"eth0",'
                b'"lladdr":"02:00:00:00:00:10","state":["PERMANENT"]}]'
            )
        raise AssertionError(arguments)

    monkeypatch.setattr(module, "_run_ip", fake_ip)

    digest = module.require_neighbor_binding(inputs)

    expected_document = {
        "endpoint_generation": firewall_case.endpoint.generation,
        "network_generation": firewall_case.network.generation,
        "route_prefix": "192.168.50.0/24",
        "route_scope": "link",
        "interface": firewall_case.network.reachy_ingress_interface,
        "ipv4": firewall_case.endpoint.core_ipv4,
        "link_address": firewall_case.endpoint.core_link_address.lower(),
        "neighbor_state": "PERMANENT",
    }
    expected_digest = hashlib.sha256(
        json.dumps(expected_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert digest == expected_digest
    assert calls == [
        ["-j", "-4", "route", "get", "192.168.50.10", "oif", "eth0"],
        ["-j", "-4", "route", "show", "match", "192.168.50.10", "dev", "eth0"],
        ["-j", "-4", "neigh", "show", "to", "192.168.50.10", "dev", "eth0"],
    ]


def test_generation_bound_permanent_neighbor_binding_digest(
    firewall_case: FirewallCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    calls: list[list[str]] = []

    def fake_ip(arguments: list[str]) -> bytes:
        calls.append(arguments)
        if arguments[:4] == ["-j", "-4", "route", "get"]:
            return b'[{"dst":"192.168.50.10","dev":"eth0"}]'
        if arguments[:4] == ["-j", "-4", "route", "show"]:
            return b'[{"dst":"192.168.50.0/24","dev":"eth0","scope":"link"}]'
        if arguments[:3] == ["-4", "neigh", "replace"]:
            return b""
        if arguments[:4] == ["-j", "-4", "neigh", "show"]:
            return (
                b'[{"dst":"192.168.50.10","dev":"eth0",'
                b'"lladdr":"02:00:00:00:00:10","state":["PERMANENT"]}]'
            )
        raise AssertionError(arguments)

    monkeypatch.setattr(module, "_run_ip", fake_ip)

    digest = module.install_neighbor_binding(inputs)

    assert len(digest) == 64
    assert [
        "-4",
        "neigh",
        "replace",
        "192.168.50.10",
        "lladdr",
        "02:00:00:00:00:10",
        "nud",
        "permanent",
        "dev",
        "eth0",
    ] in calls


def test_current_boot_receipt_binds_inputs_rules_neighbor_and_signature(
    firewall_case: FirewallCase,
    tmp_path: Path,
) -> None:
    import deploy.reachy.apply_firewall as apply_module
    from deploy.reachy.boot_gate import (
        FirewallBootReceiptV1,
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
        require_current_boot_receipt,
    )

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    signer = LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY)
    repository = FirewallReceiptRepository(tmp_path / "receipt.json")
    receipt = issue_current_boot_receipt(
        inputs=inputs,
        ruleset=ruleset,
        observed_table=ruleset,
        neighbor_binding_sha256="b" * 64,
        boot_id=BOOT_ID,
        candidate_commit=BUILD_COMMIT,
        clock=Clock(),
        signer=signer,
        repository=repository,
    )

    assert type(receipt) is FirewallBootReceiptV1
    assert apply_module.canonical_tuntun_table_semantics(ruleset)
    assert (
        require_current_boot_receipt(
            repository=repository,
            signer=signer,
            endpoint_json=firewall_case.endpoint_json,
            network_json=firewall_case.network_json,
            capability_json=firewall_case.capabilities_json,
            available_interfaces={"lo", "eth0"},
            boot_id=BOOT_ID,
            candidate_commit=BUILD_COMMIT,
            observed_table=ruleset,
            observed_neighbor_binding_sha256="b" * 64,
        )
        == receipt
    )


@pytest.mark.parametrize("receipt_kind", ("normal", "degraded"))
def test_firewall_receipt_parent_fsync_failure_removes_uncommitted_receipt(
    firewall_case: FirewallCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receipt_kind: str,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
        issue_degraded_firewall_receipt,
    )

    tmp_path.chmod(0o700)
    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    signer = LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY)
    repository = FirewallReceiptRepository(tmp_path / "receipt.json")
    real_fsync = os.fsync
    directory_fsyncs = 0

    def fail_first_directory_fsync(fd: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 1:
                raise OSError("directory fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_first_directory_fsync)

    with pytest.raises(PermissionError, match="firewall_boot_gate_receipt_uncommitted"):
        if receipt_kind == "normal":
            issue_current_boot_receipt(
                inputs=inputs,
                ruleset=ruleset,
                observed_table=ruleset,
                neighbor_binding_sha256="b" * 64,
                boot_id=BOOT_ID,
                candidate_commit=BUILD_COMMIT,
                clock=Clock(),
                signer=signer,
                repository=repository,
            )
        else:
            issue_degraded_firewall_receipt(
                reason_code="apply_failed",
                emergency_rules_sha256="e" * 64,
                boot_id=BOOT_ID,
                clock=Clock(),
                signer=signer,
                repository=repository,
            )

    assert not repository.path.exists()
    assert directory_fsyncs >= 2


def test_firewall_receipt_require_rejects_visible_receipt_while_publication_marker_exists(
    firewall_case: FirewallCase,
    tmp_path: Path,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
    )

    tmp_path.chmod(0o700)
    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    signer = LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY)
    repository = FirewallReceiptRepository(tmp_path / "receipt.json")
    receipt = issue_current_boot_receipt(
        inputs=inputs,
        ruleset=ruleset,
        observed_table=ruleset,
        neighbor_binding_sha256="b" * 64,
        boot_id=BOOT_ID,
        candidate_commit=BUILD_COMMIT,
        clock=Clock(),
        signer=signer,
        repository=repository,
    )
    marker = tmp_path / ".receipt.json.publish"
    marker.write_bytes(b"publication pending")
    marker.chmod(0o600)

    with pytest.raises(PermissionError, match="firewall_boot_gate_receipt_uncommitted"):
        repository.require()

    marker.unlink()
    assert repository.require() == receipt


def test_firewall_receipt_post_rename_fsync_failure_retains_quarantine_marker_and_blocks_require(
    firewall_case: FirewallCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
    )

    tmp_path.chmod(0o700)
    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    signer = LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY)
    repository = FirewallReceiptRepository(tmp_path / "receipt.json")
    real_fsync = os.fsync
    directory_fsyncs = 0

    def fail_second_directory_fsync(fd: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 2:
                raise OSError("directory commit failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_second_directory_fsync)

    with pytest.raises(PermissionError, match="firewall_boot_gate_receipt_uncommitted"):
        issue_current_boot_receipt(
            inputs=inputs,
            ruleset=ruleset,
            observed_table=ruleset,
            neighbor_binding_sha256="b" * 64,
            boot_id=BOOT_ID,
            candidate_commit=BUILD_COMMIT,
            clock=Clock(),
            signer=signer,
            repository=repository,
        )

    assert directory_fsyncs >= 2
    assert (tmp_path / ".receipt.json.publish").exists()
    with pytest.raises(PermissionError, match="firewall_boot_gate_receipt_uncommitted"):
        repository.require()


def test_firewall_receipt_final_marker_removal_fsync_failure_keeps_require_fail_closed(
    firewall_case: FirewallCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
    )

    tmp_path.chmod(0o700)
    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    repository = FirewallReceiptRepository(tmp_path / "receipt.json")
    real_fsync = os.fsync
    directory_fsyncs = 0

    def fail_marker_removal_commit(fd: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 3:
                raise OSError("final marker removal fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_marker_removal_commit)

    with pytest.raises(PermissionError, match="firewall_boot_gate_receipt_uncommitted"):
        issue_current_boot_receipt(
            inputs=inputs,
            ruleset=ruleset,
            observed_table=ruleset,
            neighbor_binding_sha256="b" * 64,
            boot_id=BOOT_ID,
            candidate_commit=BUILD_COMMIT,
            clock=Clock(),
            signer=LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY),
            repository=repository,
        )

    assert directory_fsyncs >= 3
    assert (tmp_path / ".receipt.json.publish").exists()
    with pytest.raises(PermissionError, match="firewall_boot_gate_receipt_uncommitted"):
        repository.require()


def test_firewall_receipt_final_marker_restore_failure_quarantines_visible_receipt(
    firewall_case: FirewallCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
    )

    tmp_path.chmod(0o700)
    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    repository = FirewallReceiptRepository(tmp_path / "receipt.json")
    real_fsync = os.fsync
    real_open = os.open
    directory_fsyncs = 0
    publish_marker_creates = 0

    def fail_marker_removal_commit(fd: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 3:
                raise OSError("scripted directory durability failure")
        real_fsync(fd)

    def fail_publish_marker_restore(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal publish_marker_creates
        if path == ".receipt.json.publish" and flags & os.O_EXCL:
            publish_marker_creates += 1
            if publish_marker_creates == 2:
                raise PermissionError("scripted marker restoration failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "fsync", fail_marker_removal_commit)
    monkeypatch.setattr(os, "open", fail_publish_marker_restore)

    with pytest.raises(PermissionError, match="firewall_boot_gate_receipt_uncommitted"):
        issue_current_boot_receipt(
            inputs=inputs,
            ruleset=ruleset,
            observed_table=ruleset,
            neighbor_binding_sha256="b" * 64,
            boot_id=BOOT_ID,
            candidate_commit=BUILD_COMMIT,
            clock=Clock(),
            signer=LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY),
            repository=repository,
        )

    assert publish_marker_creates == 2
    assert repository.path.exists()
    assert (tmp_path / ".receipt.json.publish.quarantine").exists()
    with pytest.raises(PermissionError, match="firewall_boot_gate_receipt_uncommitted"):
        FirewallReceiptRepository(repository.path).require()


def test_losing_firewall_receipt_writer_does_not_remove_concurrent_publication_marker(
    firewall_case: FirewallCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
    )

    tmp_path.chmod(0o700)
    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    signer = LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY)
    repository = FirewallReceiptRepository(tmp_path / "receipt.json")
    real_open = os.open
    marker_name = ".receipt.json.publish"

    def concurrent_marker_owner(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == marker_name and flags & os.O_EXCL:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            try:
                os.write(descriptor, b"winner owns publication marker")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            raise FileExistsError("winner owns marker")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", concurrent_marker_owner)

    with pytest.raises(PermissionError, match="firewall_boot_gate_directory_permissions"):
        issue_current_boot_receipt(
            inputs=inputs,
            ruleset=ruleset,
            observed_table=ruleset,
            neighbor_binding_sha256="b" * 64,
            boot_id=BOOT_ID,
            candidate_commit=BUILD_COMMIT,
            clock=Clock(),
            signer=signer,
            repository=repository,
        )

    marker = tmp_path / marker_name
    assert marker.exists()
    with pytest.raises(PermissionError, match="firewall_boot_gate_receipt_uncommitted"):
        repository.require()


def test_firewall_receipt_repository_rejects_symlinked_receipt_path(
    firewall_case: FirewallCase,
    tmp_path: Path,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
    )

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    real_receipt = tmp_path / "real-receipt.json"
    link_receipt = tmp_path / "receipt.json"
    real_receipt.write_bytes(b"{}")
    real_receipt.chmod(0o600)
    link_receipt.symlink_to(real_receipt)

    with pytest.raises(PermissionError, match="firewall_boot_gate"):
        issue_current_boot_receipt(
            inputs=inputs,
            ruleset=ruleset,
            observed_table=ruleset,
            neighbor_binding_sha256="b" * 64,
            boot_id=BOOT_ID,
            candidate_commit=BUILD_COMMIT,
            clock=Clock(),
            signer=LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY),
            repository=FirewallReceiptRepository(link_receipt),
        )


def test_firewall_receipt_repository_rejects_symlinked_parent(
    firewall_case: FirewallCase,
    tmp_path: Path,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
    )

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    symlink_parent = tmp_path / "receipt-parent"
    symlink_parent.symlink_to(real_parent)

    with pytest.raises(PermissionError, match="firewall_boot_gate"):
        issue_current_boot_receipt(
            inputs=inputs,
            ruleset=ruleset,
            observed_table=ruleset,
            neighbor_binding_sha256="b" * 64,
            boot_id=BOOT_ID,
            candidate_commit=BUILD_COMMIT,
            clock=Clock(),
            signer=LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY),
            repository=FirewallReceiptRepository(symlink_parent / "receipt.json"),
        )


def test_firewall_receipt_repository_named_target_replacement_is_not_followed(
    firewall_case: FirewallCase,
    tmp_path: Path,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
    )

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    signer = LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY)
    repository = FirewallReceiptRepository(tmp_path / "receipt.json")

    issue_current_boot_receipt(
        inputs=inputs,
        ruleset=ruleset,
        observed_table=ruleset,
        neighbor_binding_sha256="b" * 64,
        boot_id=BOOT_ID,
        candidate_commit=BUILD_COMMIT,
        clock=Clock(),
        signer=signer,
        repository=repository,
    )
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    target.chmod(0o600)
    repository.path.unlink()
    repository.path.symlink_to(target)

    with pytest.raises(PermissionError, match="firewall_boot_gate"):
        issue_current_boot_receipt(
            inputs=inputs,
            ruleset=ruleset,
            observed_table=ruleset,
            neighbor_binding_sha256="b" * 64,
            boot_id=BOOT_ID,
            candidate_commit=BUILD_COMMIT,
            clock=Clock(),
            signer=signer,
            repository=repository,
        )

    assert repository.path.is_symlink()
    assert target.read_bytes() == b"{}"


def test_start_gate_blocks_dangling_degraded_receipt_marker_before_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tuntun_edge.security.key_store import EdgeKeyStore

    import deploy.reachy.apply_firewall as apply_module
    import deploy.reachy.boot_gate as gate_module

    key_root = tmp_path / "keys"
    EdgeKeyStore(key_root).write("firewall-receipt-v1", RECEIPT_KEY)
    boot_id_path = tmp_path / "boot-id"
    boot_id_path.write_text(str(BOOT_ID), encoding="ascii")
    boot_id_path.chmod(0o600)
    degraded_marker = tmp_path / "degraded-receipt.json"
    degraded_marker.symlink_to(tmp_path / "missing-receipt.json")
    reads: list[Path] = []

    def fake_read(path: Path, max_bytes: int, *, exact_mode: int | None = 0o600) -> bytes:
        del max_bytes, exact_mode
        reads.append(path)
        if path == boot_id_path:
            return str(BOOT_ID).encode("ascii")
        raise AssertionError("start gate read inputs after dangling degraded marker")

    monkeypatch.setattr(apply_module, "KEY_ROOT", key_root)
    monkeypatch.setattr(apply_module, "BOOT_ID_PATH", boot_id_path)
    monkeypatch.setattr(apply_module, "DEGRADED_RECEIPT_PATH", degraded_marker)
    monkeypatch.setattr(apply_module, "read_fixed_owner_file", fake_read)
    monkeypatch.setattr(apply_module, "install_emergency_table", lambda: "e" * 64)
    monkeypatch.setattr(gate_module, "issue_degraded_firewall_receipt", lambda **_: None)

    with pytest.raises(PermissionError, match="firewall_start_gate_failed"):
        gate_module.gate_current_boot()

    assert reads == [boot_id_path]


@pytest.mark.parametrize(
    "mutation",
    (
        "boot_id",
        "endpoint_generation",
        "network_generation",
        "candidate_commit",
        "neighbor_binding_sha256",
        "observed_rules_sha256",
        "signature_b64",
    ),
)
def test_edge_boot_gate_rejects_stale_or_mutated_receipt(
    firewall_case: FirewallCase,
    tmp_path: Path,
    mutation: str,
) -> None:
    from deploy.reachy.boot_gate import (
        FirewallReceiptRepository,
        LocalReceiptSigner,
        issue_current_boot_receipt,
        require_current_boot_receipt,
    )

    inputs = restore_firewall_inputs(
        firewall_case.endpoint_json,
        firewall_case.network_json,
        firewall_case.capabilities_json,
        available_interfaces={"lo", "eth0"},
    )
    ruleset = build_nftables_ruleset(inputs)
    signer = LocalReceiptSigner("firewall-receipt-v1", RECEIPT_KEY)
    repository = FirewallReceiptRepository(tmp_path / "receipt.json")
    receipt = issue_current_boot_receipt(
        inputs=inputs,
        ruleset=ruleset,
        observed_table=ruleset,
        neighbor_binding_sha256="b" * 64,
        boot_id=BOOT_ID,
        candidate_commit=BUILD_COMMIT,
        clock=Clock(),
        signer=signer,
        repository=repository,
    )
    replacement: Any = {
        "boot_id": UUID("00000000-0000-0000-0000-00000000c099"),
        "endpoint_generation": 99,
        "network_generation": 99,
        "candidate_commit": "c" * 40,
        "neighbor_binding_sha256": "c" * 64,
        "observed_rules_sha256": "c" * 64,
        "signature_b64": "A" * 43 + "=",
    }[mutation]
    mutated = receipt.model_copy(update={mutation: replacement})
    repository.replace_atomic(mutated)

    with pytest.raises(PermissionError, match="firewall_boot_gate"):
        require_current_boot_receipt(
            repository=repository,
            signer=signer,
            endpoint_json=firewall_case.endpoint_json,
            network_json=firewall_case.network_json,
            capability_json=firewall_case.capabilities_json,
            available_interfaces={"lo", "eth0"},
            boot_id=BOOT_ID,
            candidate_commit=BUILD_COMMIT,
            observed_table=ruleset,
            observed_neighbor_binding_sha256="b" * 64,
        )


def test_first_boot_installs_emergency_before_any_fallible_preflight_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import deploy.reachy.apply_firewall as module

    events: list[str] = []

    def fake_emergency() -> str:
        events.append("emergency")
        return "e" * 64

    def fake_read(path: Path, max_bytes: int, *, exact_mode: int | None = 0o600) -> bytes:
        del max_bytes, exact_mode
        events.append(f"read:{path}")
        raise PermissionError("missing input")

    monkeypatch.setattr(module, "install_emergency_table", fake_emergency)
    monkeypatch.setattr(module, "read_fixed_owner_file", fake_read)

    with pytest.raises(RuntimeError, match="firewall_preflight_failed"):
        module.apply_for_current_boot()

    assert events[0] == "emergency"


def test_firewall_systemd_units_preserve_required_ordering() -> None:
    baseline = Path("deploy/reachy/systemd/tuntun-reachy-firewall-baseline.service").read_text()
    normal = Path("deploy/reachy/systemd/tuntun-reachy-firewall.service").read_text()

    assert "Description=Install Tuntun emergency firewall before networking" in baseline
    assert "DefaultDependencies=no" in baseline
    assert "After=local-fs.target" in baseline
    assert "Before=network-pre.target" in baseline
    assert "RequiredBy=network-pre.target" in baseline
    assert (
        "ExecStart=/var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge/"
        "firewall/current/bin/python "
        "-m deploy.reachy.apply_firewall --emergency-baseline"
    ) in baseline
    assert "Description=Atomically apply and attest the Tuntun Reachy firewall table" in normal
    assert "Requires=tuntun-reachy-firewall-baseline.service" in normal
    assert "After=tuntun-reachy-firewall-baseline.service network-online.target" in normal
    assert (
        "ExecStart=/var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge/"
        "firewall/current/bin/python "
        "-m deploy.reachy.apply_firewall --boot"
    ) in normal


def test_nft_and_ip_runner_use_fixed_absolute_argv_shell_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    import deploy.reachy.apply_firewall as module

    calls: list[dict[str, Any]] = []

    class FakePipe:
        def __init__(self) -> None:
            read_fd, write_fd = os.pipe()
            os.close(write_fd)
            self._fd = read_fd

        def fileno(self) -> int:
            return self._fd

    class FakeProcess:
        def __init__(self, argv: list[str], **kwargs: Any) -> None:
            calls.append({"argv": argv, **kwargs})
            self.stdout = FakePipe()
            self.stderr = FakePipe()

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

        def kill(self) -> None:
            return None

    monkeypatch.setattr(subprocess, "Popen", FakeProcess)

    assert module._run_nft(["--json", "list", "table", "inet", "tuntun"]) == b""

    assert calls[0]["argv"] == [
        "/usr/sbin/nft",
        "--json",
        "list",
        "table",
        "inet",
        "tuntun",
    ]
    assert calls[0]["shell"] is False
    assert calls[0]["env"] == {"LC_ALL": "C"}


def _chain_policy(ruleset: dict[str, Any], name: str) -> str:
    for command in ruleset["nftables"]:
        chain = command.get("add", {}).get("chain")
        if chain is not None and chain["name"] == name:
            policy = chain["policy"]
            if not isinstance(policy, str):
                raise AssertionError(f"chain {name} policy is not a string")
            return policy
    raise AssertionError(f"chain {name} missing")


def _rules(ruleset: dict[str, Any], *, chain: str | None = None) -> Iterator[dict[str, Any]]:
    for command in ruleset["nftables"]:
        rule = command.get("add", {}).get("rule")
        if rule is not None and (chain is None or rule.get("chain") == chain):
            yield rule


def _rule_has(rule: dict[str, Any], field: str, value: object) -> bool:
    try:
        return bool(_match_right(rule, field) == value)
    except AssertionError:
        return False


def _match_right(rule: dict[str, Any], field: str) -> Any:
    for expression in rule.get("expr", ()):
        match = expression.get("match")
        if match is None:
            continue
        left = match.get("left", {})
        if left.get("field") == field or left.get("key") == field:
            return match.get("right")
        payload = left.get("payload")
        if isinstance(payload, dict) and payload.get("field") == field:
            return match.get("right")
        meta = left.get("meta")
        if isinstance(meta, dict) and meta.get("key") == field:
            return match.get("right")
    raise AssertionError(f"field {field} missing")
