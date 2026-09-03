from __future__ import annotations

from uuid import UUID

import pytest
from pydantic import ValidationError
from tuntun_contracts import (
    ReachyAssistantInventoryV1,
    ReachyBootIdentityV1,
    ReachyNetworkCountersV1,
    registered_contract_models,
)


def _network_counters_payload() -> dict[str, object]:
    return {
        "schema_version": "tuntun.reachy-network-counters.v1",
        "commissioning_generation": 4,
        "firewall_generation": 7,
        "counter_epoch": "a" * 64,
        "boot_uuid": UUID("00000000-0000-4000-8000-000000000001"),
        "sample_sequence": 9,
        "cumulative_package_download_dns_or_connect_count": 0,
    }


def test_reachy_assistant_qualification_contracts_are_public_and_registered() -> None:
    registered = set(registered_contract_models())
    assert {
        ReachyNetworkCountersV1,
        ReachyBootIdentityV1,
        ReachyAssistantInventoryV1,
    } <= registered


def test_network_counter_snapshot_is_closed_strict_and_bounded() -> None:
    snapshot = ReachyNetworkCountersV1.model_validate(_network_counters_payload())
    assert snapshot.boot_uuid == UUID("00000000-0000-4000-8000-000000000001")
    assert snapshot.counter_epoch == "a" * 64

    invalid_mutations = (
        {"schema_version": "tuntun.reachy-network-counters.v2"},
        {"commissioning_generation": 0},
        {"firewall_generation": 0},
        {"counter_epoch": "A" * 64},
        {"counter_epoch": "a" * 63},
        {"boot_uuid": "not-a-uuid"},
        {"sample_sequence": 0},
        {"sample_sequence": True},
        {"cumulative_package_download_dns_or_connect_count": -1},
        {"unexpected": "field"},
    )
    for mutation in invalid_mutations:
        with pytest.raises(ValidationError):
            ReachyNetworkCountersV1.model_validate(_network_counters_payload() | mutation)


def test_boot_identity_requires_one_positive_commissioning_generation() -> None:
    identity = ReachyBootIdentityV1.model_validate(
        {
            "schema_version": "tuntun.reachy-boot-identity.v1",
            "commissioning_generation": 4,
            "boot_uuid": UUID("00000000-0000-4000-8000-000000000001"),
        }
    )
    assert identity.commissioning_generation == 4

    with pytest.raises(ValidationError):
        ReachyBootIdentityV1.model_validate(
            {
                "schema_version": "tuntun.reachy-boot-identity.v1",
                "commissioning_generation": 0,
                "boot_uuid": UUID("00000000-0000-4000-8000-000000000001"),
            }
        )


def test_assistant_inventory_is_sorted_unique_closed_and_bounded() -> None:
    inventory = ReachyAssistantInventoryV1.model_validate(
        {
            "schema_version": "tuntun.reachy-assistant-inventory.v1",
            "managed_app_ids": ("com.tuntun.edge", "vendor.assistant"),
            "recovery_hook_ids": ("com.tuntun.recovery",),
        }
    )
    assert inventory.managed_app_ids == ("com.tuntun.edge", "vendor.assistant")

    invalid_values = (
        ("vendor.assistant", "com.tuntun.edge"),
        ("com.tuntun.edge", "com.tuntun.edge"),
        ("",),
        ("x" * 129,),
    )
    for value in invalid_values:
        with pytest.raises(ValidationError):
            ReachyAssistantInventoryV1.model_validate(
                {
                    "schema_version": "tuntun.reachy-assistant-inventory.v1",
                    "managed_app_ids": value,
                    "recovery_hook_ids": (),
                }
            )

    with pytest.raises(ValidationError):
        ReachyAssistantInventoryV1.model_validate(
            {
                "schema_version": "tuntun.reachy-assistant-inventory.v1",
                "managed_app_ids": tuple(f"app.{index:03d}" for index in range(257)),
                "recovery_hook_ids": (),
            }
        )
