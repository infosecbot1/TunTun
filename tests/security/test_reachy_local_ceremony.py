from __future__ import annotations

import hashlib
import os
import socket
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_edge.bootstrap import commissioning as bootstrap
from tuntun_edge.transport import reachy_local_ceremony as ceremony
from tuntun_edge.transport.commissioning import ReachyCommissioningRequestV1

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


def _write_fixture(
    root: Path,
    *,
    descriptor: dict[str, object] | None = None,
    dhcp: dict[str, object] | None = None,
    pinned_host_key: str = PINNED_HOST_KEY,
) -> bootstrap.ReachyCommissioningRoots:
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
    selected_dhcp = _dhcp_reservations() if dhcp is None else dhcp
    selected_descriptor = _descriptor() if descriptor is None else descriptor
    request = cast(dict[str, object], selected_descriptor["request"])
    request["dhcp_reservation_receipt_sha256"] = _digest(canonical_mapping_bytes(selected_dhcp))
    _owner_write(paths.input_descriptor_path, canonical_mapping_bytes(selected_descriptor))
    _owner_write(paths.pinned_host_key_path, f"{pinned_host_key}\n".encode("ascii"))
    _owner_write(paths.dhcp_reservations_path, canonical_mapping_bytes(selected_dhcp))
    return paths


def _composition(root: Path) -> bootstrap.ReachyCommissioningComposition:
    return bootstrap.build_commissioning_for_test_roots(root)


def _request_model(
    generation: int = 1,
    *,
    core_ipv4: str = "192.168.50.10",
) -> ReachyCommissioningRequestV1:
    return ReachyCommissioningRequestV1.model_validate(_request(generation, core_ipv4=core_ipv4))


def test_production_composition_has_fixed_paths_and_no_parameters() -> None:
    assert bootstrap.PRODUCTION_ROOTS.input_descriptor_path == Path(
        "/etc/tuntun/reachy/commissioning.json"
    )
    assert bootstrap.PRODUCTION_ROOTS.pinned_host_key_path == Path(
        "/etc/tuntun/reachy/pinned-host-key.sha256"
    )
    assert bootstrap.PRODUCTION_ROOTS.dhcp_reservations_path == Path(
        "/etc/tuntun/reachy/dhcp-reservations.json"
    )
    assert bootstrap.PRODUCTION_ROOTS.state_root == Path("/var/lib/tuntun/reachy/commissioning")
    assert bootstrap.PRODUCTION_ROOTS.private_material_root == Path(
        "/var/lib/tuntun/reachy/private"
    )
    assert bootstrap.PRODUCTION_ROOTS.certificate_root == Path(
        "/var/lib/tuntun/reachy/certificates"
    )
    assert bootstrap.PRODUCTION_ROOTS.issuer_state_root == Path(
        "/var/lib/tuntun/reachy/issuer-state"
    )
    assert bootstrap.PRODUCTION_ROOTS.operator_state_root == Path(
        "/var/lib/tuntun/reachy/operator-state"
    )
    assert bootstrap.build_production_commissioning.__annotations__["return"] == (
        "ReachyCommissioningComposition"
    )
    assert bootstrap.build_production_commissioning.__defaults__ is None


@pytest.mark.parametrize(
    "mutation",
    ("descriptor_symlink", "descriptor_hardlink", "descriptor_wrong_mode", "noncanonical_json"),
)
def test_fixed_input_reader_rejects_unsafe_descriptor_files(
    tmp_path: Path,
    mutation: str,
) -> None:
    paths = _write_fixture(tmp_path)
    if mutation == "descriptor_symlink":
        target = paths.input_descriptor_path.with_name("real-commissioning.json")
        paths.input_descriptor_path.rename(target)
        paths.input_descriptor_path.symlink_to(target.name)
    elif mutation == "descriptor_hardlink":
        os.link(paths.input_descriptor_path, paths.input_descriptor_path.with_name("linked.json"))
    elif mutation == "descriptor_wrong_mode":
        paths.input_descriptor_path.chmod(0o640)
    else:
        paths.input_descriptor_path.write_text("{}\n", encoding="utf-8")
        paths.input_descriptor_path.chmod(0o600)

    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        _composition(tmp_path)


def test_fixed_input_reader_rejects_named_descriptor_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_fixture(tmp_path)
    replacement = paths.input_descriptor_path.with_name("replacement-commissioning.json")
    changed = _descriptor()
    cast(dict[str, object], changed["request"])["core_ipv4"] = "192.168.50.11"
    _owner_write(replacement, canonical_mapping_bytes(changed))
    displaced = paths.input_descriptor_path.with_name("displaced-commissioning.json")
    real_stat = ceremony.OS_MODULE.stat
    named_stats = 0

    def swap_on_second_named_stat(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal named_stats
        if path == paths.input_descriptor_path.name and dir_fd is not None and not follow_symlinks:
            named_stats += 1
            if named_stats == 2:
                os.replace(paths.input_descriptor_path, displaced)
                os.replace(replacement, paths.input_descriptor_path)
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(ceremony.OS_MODULE, "stat", swap_on_second_named_stat)

    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        _composition(tmp_path)

    assert named_stats >= 2


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("ssh", "ssh_username", "root"),
        ("ssh", "remote_id_username", "otheruser"),
        ("ssh", "password_login_rejected", False),
        ("ssh", "default_password_login_rejected", False),
        ("ssh", "installer_privileges_bounded", False),
        ("ssh", "managed_app_privileges_bounded", False),
        ("runtime", "python_executable", "/usr/bin/python3"),
        ("runtime", "python_version", "3.11"),
        ("runtime", "python_abi", "cp311"),
        ("runtime", "sys_tags", ["cp312-cp312-linux_aarch64"]),
        ("runtime", "edge_wheel_tags", ["cp312-cp312-linux_aarch64"]),
        ("runtime", "contracts_wheel_tags", ["cp312-cp312-linux_aarch64"]),
        ("capability", "sdk_metadata_accepted", False),
    ),
)
def test_ceremony_rejects_unbound_principal_interpreter_wheel_or_runtime_facts(
    tmp_path: Path,
    section: str,
    field: str,
    value: object,
) -> None:
    descriptor = _descriptor()
    cast(dict[str, object], descriptor[section])[field] = value
    _write_fixture(tmp_path, descriptor=descriptor)

    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        _composition(tmp_path).ceremony.issue_proof(
            operation="commission",
            request=_request_model(),
            current=None,
            one_time_code=ONE_TIME_CODE,
        )


@pytest.mark.parametrize(
    "runtime_packages",
    (
        [
            {"name": "python", "version": "3.12.9"},
            {"name": "reachy-mini", "version": "9.8.7"},
        ],
        [
            {"name": "python", "version": "3.12.9"},
            {"name": "reachy-mini", "version": "9.8.7"},
            {"name": "websockets", "version": "15.0.0"},
        ],
        [
            {"name": "python", "version": "3.12.9"},
            {"name": "reachy-mini", "version": "9.8.7"},
            {"name": "websockets", "version": "15.0.1"},
            {"name": "pip", "version": "24.0"},
        ],
    ),
)
def test_ceremony_requires_exact_closed_runtime_inventory(
    tmp_path: Path,
    runtime_packages: list[dict[str, str]],
) -> None:
    descriptor = _descriptor()
    cast(dict[str, object], descriptor["runtime"])["runtime_packages"] = runtime_packages
    _write_fixture(tmp_path, descriptor=descriptor)

    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        _composition(tmp_path).ceremony.issue_proof(
            operation="commission",
            request=_request_model(),
            current=None,
            one_time_code=ONE_TIME_CODE,
        )


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("topology", "core_inventory_id", "different-mac"),
        ("topology", "accepted_mac_inventory_count", 2),
        ("topology", "route_bearing_user_lan_interfaces", ["en0", "en1"]),
        ("topology", "asus_mesh_user_lan_interface", "en1"),
        ("topology", "direct_same_l2", False),
        ("topology", "same_l2_prefix_length", 16),
        ("topology", "be800_direct_attachment_disconnected", False),
        ("topology", "ip_forwarding_enabled", True),
        ("topology", "internet_sharing_enabled", True),
        ("topology", "bridge_enabled", True),
        ("topology", "secondary_listener_reachable", True),
        ("topology", "gateway_bearing_routes", True),
        ("topology", "dual_homed", True),
        ("route", "binary", "ip"),
        ("route", "interface", "en1"),
        ("route", "scope", "global"),
        ("route", "gateway_ipv4", "192.168.50.1"),
        ("route", "peer_link_address", "02:00:5e:00:53:09"),
    ),
)
def test_ceremony_rejects_non_direct_l2_or_single_home_topology_facts(
    tmp_path: Path,
    section: str,
    field: str,
    value: object,
) -> None:
    descriptor = _descriptor()
    cast(dict[str, object], descriptor[section])[field] = value
    _write_fixture(tmp_path, descriptor=descriptor)

    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        _composition(tmp_path).ceremony.issue_proof(
            operation="commission",
            request=_request_model(),
            current=None,
            one_time_code=ONE_TIME_CODE,
        )


def test_ceremony_rejects_dns_like_or_non_rfc1918_authority(tmp_path: Path) -> None:
    descriptor = _descriptor()
    cast(dict[str, object], descriptor["topology"])["reachy_ipv4"] = "reachy.local"
    cast(dict[str, object], descriptor["route"])["destination_ipv4"] = "reachy.local"
    _write_fixture(tmp_path, descriptor=descriptor)

    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        _composition(tmp_path)

    descriptor = _descriptor()
    cast(dict[str, object], descriptor["topology"])["reachy_ipv4"] = "203.0.113.20"
    cast(dict[str, object], descriptor["route"])["destination_ipv4"] = "203.0.113.20"
    _write_fixture(tmp_path, descriptor=descriptor)
    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        _composition(tmp_path).ceremony.issue_proof(
            operation="commission",
            request=_request_model(),
            current=None,
            one_time_code=ONE_TIME_CODE,
        )


def test_ceremony_rejects_incorrect_one_time_code_without_leaking_it(tmp_path: Path) -> None:
    _write_fixture(tmp_path)

    with pytest.raises(ceremony.ReachyLocalCeremonyError) as error:
        _composition(tmp_path).ceremony.issue_proof(
            operation="commission",
            request=_request_model(),
            current=None,
            one_time_code="654321",
        )

    assert str(error.value) == "unsafe Reachy local ceremony"
    assert "654321" not in str(error.value)


def test_ceremony_uses_no_dns_shell_subprocess_or_ambient_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("forbidden live host operation")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)

    composition = _composition(tmp_path)

    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        composition.ceremony.issue_proof(
            operation="commission",
            request=composition.ceremony.current_rfc1918_request(),
            current=None,
            one_time_code=ONE_TIME_CODE,
        )


def test_ceremony_reports_reviewed_commissioning_key_identity_gap(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    composition = _composition(tmp_path)

    assert not ceremony.commissioning_key_identity_contract_supports_required_ed25519_ids()
    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        composition.ceremony.issue_proof(
            operation="commission",
            request=_request_model(),
            current=None,
            one_time_code=ONE_TIME_CODE,
        )


def test_concrete_builder_fails_closed_before_state_when_key_identity_contract_is_unsound(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path)
    composition = _composition(tmp_path)

    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        composition.commission(ONE_TIME_CODE)

    assert not composition.repository.has_current()
    assert os.listdir(composition.key_store.root) == []
    assert os.listdir(composition.certificate_store.root) == []


def test_concrete_builder_uses_real_owner_only_repositories_for_state_and_artifacts(
    tmp_path: Path,
) -> None:
    paths = _write_fixture(tmp_path)
    composition = _composition(tmp_path)

    assert composition.repository.path == paths.state_root / "commissioning-state.json"
    assert stat.S_IMODE(os.stat(paths.state_root).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(paths.private_material_root).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(paths.certificate_root).st_mode) == 0o700


@pytest.mark.parametrize(
    "mutation",
    (
        lambda descriptor: cast(dict[str, object], descriptor["runtime"]).update(
            {
                "scratch_venv": {
                    **cast(
                        dict[str, object],
                        cast(dict[str, object], descriptor["runtime"])["scratch_venv"],
                    ),
                    "offline": False,
                }
            }
        ),
        lambda descriptor: cast(dict[str, object], descriptor["runtime"]).update(
            {
                "scratch_venv": {
                    **cast(
                        dict[str, object],
                        cast(dict[str, object], descriptor["runtime"])["scratch_venv"],
                    ),
                    "no_deps": False,
                }
            }
        ),
        lambda descriptor: cast(dict[str, object], descriptor["runtime"]).update(
            {
                "scratch_venv": {
                    **cast(
                        dict[str, object],
                        cast(dict[str, object], descriptor["runtime"])["scratch_venv"],
                    ),
                    "installed_wheels": ["tuntun-edge"],
                }
            }
        ),
        lambda descriptor: cast(dict[str, object], descriptor["runtime"]).update(
            {
                "scratch_venv": {
                    **cast(
                        dict[str, object],
                        cast(dict[str, object], descriptor["runtime"])["scratch_venv"],
                    ),
                    "removed": False,
                }
            }
        ),
    ),
)
def test_ceremony_requires_exact_scratch_venv_closure(
    tmp_path: Path,
    mutation: Callable[[dict[str, object]], object],
) -> None:
    descriptor = _descriptor()
    mutation(descriptor)
    _write_fixture(tmp_path, descriptor=descriptor)

    with pytest.raises(ceremony.ReachyLocalCeremonyError, match="unsafe Reachy local ceremony"):
        _composition(tmp_path).ceremony.issue_proof(
            operation="commission",
            request=_request_model(),
            current=None,
            one_time_code=ONE_TIME_CODE,
        )


def test_descriptor_transport_contains_only_public_material_fields() -> None:
    forbidden = {"private_key", "symmetric_key", "hmac_key", "password"}
    public_fields = set(ceremony.ReachyLocalCeremonyDescriptor.model_fields)

    assert not forbidden & public_fields
