from __future__ import annotations

from typing import Annotated, Any, Final, Literal
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator

from .base import ContractModel

_ASSISTANT_INVENTORY_ID_MAX_ITEMS: Final = 256
_ASSISTANT_INVENTORY_ID_MAX_LENGTH: Final = 128
_CROSS_FIELD_INVARIANTS_EXTENSION_KEY: Final = "x-tuntun-cross-field-invariants"
_ASSISTANT_INVENTORY_SCHEMA_EXTRA: Final[dict[str, Any]] = {
    _CROSS_FIELD_INVARIANTS_EXTENSION_KEY: [
        {
            "constraint": "sorted-unique-reachy-assistant-inventory-id-arrays",
            "fields": ["managed_app_ids", "recovery_hook_ids"],
            "relation": "each_array_sorted_unique",
            "runtime_authoritative": True,
        }
    ]
}
_AssistantInventoryId = Annotated[
    str,
    Field(min_length=1, max_length=_ASSISTANT_INVENTORY_ID_MAX_LENGTH),
]


class ReachyNetworkCountersV1(ContractModel):
    schema_version: Literal["tuntun.reachy-network-counters.v1"]
    commissioning_generation: Annotated[int, Field(ge=1)]
    firewall_generation: Annotated[int, Field(ge=1)]
    counter_epoch: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    boot_uuid: UUID
    sample_sequence: Annotated[int, Field(ge=1)]
    cumulative_package_download_dns_or_connect_count: Annotated[int, Field(ge=0)]


class ReachyBootIdentityV1(ContractModel):
    schema_version: Literal["tuntun.reachy-boot-identity.v1"]
    commissioning_generation: Annotated[int, Field(ge=1)]
    boot_uuid: UUID


class ReachyAssistantInventoryV1(ContractModel):
    model_config = ConfigDict(json_schema_extra=_ASSISTANT_INVENTORY_SCHEMA_EXTRA)

    schema_version: Literal["tuntun.reachy-assistant-inventory.v1"]
    managed_app_ids: Annotated[
        tuple[_AssistantInventoryId, ...],
        Field(max_length=_ASSISTANT_INVENTORY_ID_MAX_ITEMS),
    ]
    recovery_hook_ids: Annotated[
        tuple[_AssistantInventoryId, ...],
        Field(max_length=_ASSISTANT_INVENTORY_ID_MAX_ITEMS),
    ]

    @field_validator("managed_app_ids", "recovery_hook_ids")
    @classmethod
    def closed_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            tuple(sorted(value)) != value
            or len(set(value)) != len(value)
            or any(not 1 <= len(item) <= 128 for item in value)
        ):
            raise ValueError("invalid assistant inventory")
        return value
