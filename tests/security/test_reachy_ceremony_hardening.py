from __future__ import annotations

import hashlib
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest
from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_core.services.reachy.operator import OPERATOR_STATE_PATH
from tuntun_edge.bootstrap import commissioning as bootstrap
from tuntun_edge.transport import reachy_local_ceremony as ceremony
from tuntun_edge.transport.commissioning import ReachyCommissioningRequestV1
from tuntun_edge.transport.commissioning_repository import OPERATOR_STATE_NAME

ONE_TIME_CODE = "123456"
PINNED_HOST_KEY = hashlib.sha256(b"pinned-host-key").hexdigest()


def _digest(label: str | bytes) -> str:
    raw = label if isinstance(label, bytes) else label.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _uuid(value: int) -> str:
    return f"00000000-0000-4000-8000-{value:012d}"


def _request(generation: int = 1, *, core_ipv4: str = "192.168.50.10") -> dict[str, object]:
    return {
        "schema_version": "tuntun.reachy-commissioning-request.v1",
        "commissioning_uuid": _uuid(generation),
        "core_ipv4": core_ipv4,
        "core_link_address": "02:00:5e:00:53:01",
        "port": 7443,
        "boot_identity_sha256": _digest(f"boot-{generation}"),
        "capability_evidence_sha256": _digest(f"capability-{generation}"),
        "dhcp_reservation_receipt_sha256": _digest("dhcp-reservations"),
    }


def _request_model() -> ReachyCommissioningRequestV1:
    return ReachyCommissioningRequestV1.model_validate(_request())


def _dhcp_reservations() -> dict[str, object]:
    return {
        "schema_version": "tuntun.reachy-dhcp-reservations.v1",
        "reservations": [
            {
                "role": "core",
                "ipv4": "192.168.50.10",
                "link_address": "02:00:5e:00:53:01",
            },
            {
                "role": "reachy",
                "ipv4": "192.168.50.20",
                "link_address": "02:00:5e:00:53:02",
            },
        ],
    }


def _descriptor() -> dict[str, object]:
    return {
        "schema_version": "tuntun.reachy-local-ceremony.v1",
        "request": _request(),
        "one_time_code_sha256": _digest(ONE_TIME_CODE),
        "ssh": {
            "ssh_username": "tuntunops",
            "local_account_username": "tuntunops",
            "remote_id_username": "tuntunops",
            "key_only_reopen_username": "tuntunops",
            "observed_ssh_host_key_sha256": PINNED_HOST_KEY,
            "password_login_rejected": True,
            "default_password_login_rejected": True,
            "installer_privileges_bounded": True,
            "managed_app_privileges_bounded": True,
        },
        "capability": {
            "capability_report_sha256": _digest("capability-report"),
            "acceptance_receipt_sha256": _digest("acceptance-receipt"),
            "sdk_version": "1.2.3",
            "daemon_version": "4.5.6",
            "sdk_metadata_accepted": True,
        },
        "runtime": {
            "python_executable": "/venvs/apps_venv/bin/python3",
            "python_version": "3.12",
            "python_abi": "cp312",
            "sys_tags": ["cp312-cp312-linux_aarch64", "py3-none-any"],
            "edge_wheel_tags": ["py3-none-any"],
            "contracts_wheel_tags": ["py3-none-any"],
            "runtime_packages": [
                {"name": "python", "version": "3.12.9"},
                {"name": "reachy-mini", "version": "9.8.7"},
                {"name": "websockets", "version": "15.0.1"},
            ],
            "scratch_venv": {
                "python_executable": "/venvs/apps_venv/bin/python3",
                "system_site_packages": True,
                "offline": True,
                "no_deps": True,
                "installed_wheels": ["tuntun-contracts", "tuntun-edge"],
                "imported_modules": [
                    "tuntun_contracts",
                    "tuntun_edge",
                    "tuntun_edge.cli.main",
                    "tuntun_edge.transport.commissioning",
                ],
                "removed": True,
            },
        },
        "topology": {
            "core_inventory_id": "owner-approved-mac-2026-09-02",
            "office_laptop_inventory_id": "owner-approved-mac-2026-09-02",
            "accepted_mac_inventory_count": 1,
            "route_bearing_user_lan_interfaces": ["en0"],
            "asus_mesh_user_lan_interface": "en0",
            "reachy_ipv4": "192.168.50.20",
            "reachy_link_address": "02:00:5e:00:53:02",
            "core_ipv4": "192.168.50.10",
            "core_link_address": "02:00:5e:00:53:01",
            "same_l2_prefix_length": 24,
            "direct_same_l2": True,
            "be800_direct_attachment_disconnected": True,
            "ip_forwarding_enabled": False,
            "internet_sharing_enabled": False,
            "bridge_enabled": False,
            "secondary_listener_reachable": False,
            "gateway_bearing_routes": False,
            "dual_homed": False,
        },
        "route": {
            "binary": "/sbin/ip",
            "interface": "en0",
            "source_ipv4": "192.168.50.10",
            "destination_ipv4": "192.168.50.20",
            "prefix_length": 24,
            "scope": "link",
            "gateway_ipv4": None,
            "peer_link_address": "02:00:5e:00:53:02",
        },
    }


def _owner_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)


def _write_fixture(root: Path) -> bootstrap.ReachyCommissioningRoots:
    paths = bootstrap.explicit_test_roots(root)
    for directory in (
        paths.input_descriptor_path.parent,
        paths.state_root,
        paths.private_material_root,
        paths.certificate_root,
        paths.issuer_state_root,
        paths.operator_state_root,
    ):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
    dhcp = _dhcp_reservations()
    descriptor = _descriptor()
    request = cast(dict[str, object], descriptor["request"])
    request["dhcp_reservation_receipt_sha256"] = _digest(canonical_mapping_bytes(dhcp))
    _owner_write(paths.input_descriptor_path, canonical_mapping_bytes(descriptor))
    _owner_write(paths.pinned_host_key_path, f"{PINNED_HOST_KEY}\n".encode("ascii"))
    _owner_write(paths.dhcp_reservations_path, canonical_mapping_bytes(dhcp))
    return paths


def _bypass_key_identity_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ceremony,
        "commissioning_key_identity_contract_supports_required_ed25519_ids",
        lambda: True,
    )


def test_production_operator_projection_targets_core_fixed_file_without_host_touch() -> None:
    production_operator_root = bootstrap._operator_state_repository_root(bootstrap.PRODUCTION_ROOTS)

    assert production_operator_root == OPERATOR_STATE_PATH.parent
    assert production_operator_root / OPERATOR_STATE_NAME == (OPERATOR_STATE_PATH)


def test_production_builder_fails_closed_before_filesystem_or_synthetic_wiring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    touched: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        touched.append("constructor")
        raise AssertionError("production builder must fail before constructing collaborators")

    monkeypatch.setattr(bootstrap, "CommissioningRepository", forbidden)
    monkeypatch.setattr(bootstrap, "OwnerOnlyArtifactStore", forbidden)
    monkeypatch.setattr(bootstrap, "ReachyOperatorStateRepository", forbidden)
    monkeypatch.setattr(bootstrap, "SyntheticReachyPrivateMaterialGenerator", forbidden)
    monkeypatch.setattr(bootstrap, "SyntheticCoreCommissioningIssuer", forbidden)
    monkeypatch.setattr(bootstrap, "load_reachy_local_ceremony", forbidden)

    with pytest.raises(RuntimeError) as error:
        bootstrap.build_production_commissioning()

    assert str(error.value) == "Reachy local ceremony unavailable"
    assert "synthetic" not in str(error.value).lower()
    assert "/var/lib" not in str(error.value)
    assert touched == []


def test_test_root_builder_remains_synthetic_and_runtime_unusable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bypass_key_identity_gap(monkeypatch)
    _write_fixture(tmp_path)
    composition = bootstrap.build_commissioning_for_test_roots(tmp_path)

    state = composition.commission(ONE_TIME_CODE)

    with pytest.raises(PermissionError, match="commissioning_assurance_not_runtime_usable"):
        composition.repository.require_usable(state.endpoint)


def test_one_time_code_is_consumed_across_reopened_compositions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bypass_key_identity_gap(monkeypatch)
    _write_fixture(tmp_path)
    composition = bootstrap.build_commissioning_for_test_roots(tmp_path)

    first = composition.commission(ONE_TIME_CODE)

    reopened = composition.reopen()
    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        reopened.recommission(ONE_TIME_CODE)
    assert reopened.repository.require_current() == first


def test_one_time_code_consumption_survives_failure_after_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bypass_key_identity_gap(monkeypatch)
    paths = _write_fixture(tmp_path)
    composition = bootstrap.build_commissioning_for_test_roots(tmp_path)

    def fail_after_consumption(*_args: object, **_kwargs: object) -> None:
        raise ValueError("late proof issuance failure")

    monkeypatch.setattr(composition.ceremony._proof_authority, "issue", fail_after_consumption)
    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        composition.ceremony.issue_proof(
            operation="commission",
            request=_request_model(),
            current=None,
            one_time_code=ONE_TIME_CODE,
        )

    receipt_files = [
        path for path in paths.one_time_code_receipt_root.iterdir() if path.name.endswith(".json")
    ]
    assert len(receipt_files) == 1
    receipt_blob = b"\n".join(path.read_bytes() for path in receipt_files)
    assert ONE_TIME_CODE.encode("utf-8") not in receipt_blob
    assert _digest(ONE_TIME_CODE).encode("ascii") not in receipt_blob

    fresh = bootstrap.build_commissioning_for_test_roots(tmp_path)
    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        fresh.ceremony.issue_proof(
            operation="commission",
            request=_request_model(),
            current=None,
            one_time_code=ONE_TIME_CODE,
        )


def test_concurrent_reopened_compositions_consume_one_time_code_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bypass_key_identity_gap(monkeypatch)
    paths = _write_fixture(tmp_path)
    first = bootstrap.build_commissioning_for_test_roots(tmp_path)
    second = first.reopen()
    barrier = threading.Barrier(2)

    def attempt_proof(composition: bootstrap.ReachyCommissioningComposition) -> str:
        barrier.wait(timeout=5)
        try:
            composition.ceremony.issue_proof(
                operation="commission",
                request=composition.ceremony.current_rfc1918_request(),
                current=None,
                one_time_code=ONE_TIME_CODE,
            )
        except ceremony.ReachyLocalCeremonyError as error:
            return str(error)
        return "issued"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = [
            future.result(timeout=5)
            for future in (
                executor.submit(attempt_proof, first),
                executor.submit(attempt_proof, second),
            )
        ]

    assert sorted(results) == ["issued", "unsafe Reachy local ceremony"]
    receipt_files = [
        path for path in paths.one_time_code_receipt_root.iterdir() if path.name.endswith(".json")
    ]
    assert len(receipt_files) == 1
    assert stat.S_IMODE(receipt_files[0].stat().st_mode) == 0o600
    assert ONE_TIME_CODE not in receipt_files[0].name
    assert _digest(ONE_TIME_CODE) not in receipt_files[0].name
    assert ONE_TIME_CODE.encode("utf-8") not in receipt_files[0].read_bytes()


@pytest.mark.parametrize(
    "raw",
    (
        "relative/commissioning.json",
        "../commissioning.json",
        "/tmp/../commissioning.json",
        "//tmp/commissioning.json",
        "/tmp//commissioning.json",
    ),
)
def test_local_ceremony_path_helper_rejects_raw_ambient_or_noncanonical_spellings(
    raw: str,
) -> None:
    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        ceremony._absolute_lexical_path(raw)


def test_path_normalized_path_objects_remain_accepted() -> None:
    assert ceremony._absolute_lexical_path(Path("/tmp//tuntun-reachy")) == Path(
        "/tmp/tuntun-reachy"
    )


def test_test_root_builder_rejects_relative_root_before_repository_normalization() -> None:
    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        bootstrap.explicit_test_roots(Path("relative-root"))
