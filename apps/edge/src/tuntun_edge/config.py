from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import Field
from tuntun_contracts.base import ContractModel

_REACHY_HARDWARE_FLAG = "TUNTUN_ALLOW_REACHY_HARDWARE"
InterfaceName = Annotated[
    str,
    Field(min_length=1, max_length=15, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$"),
]
ReachyIngressInterface = InterfaceName


class ReachyHardwareConfig(ContractModel):
    allow_hardware: bool = False


class ReachyNetworkConfigV1(ContractModel):
    schema_version: Literal["tuntun.reachy-network-config.v1"]
    generation: Annotated[int, Field(ge=1)]
    reachy_ingress_interface: InterfaceName


class EdgeConfig(ContractModel):
    media_backend: Literal["local"] = "local"
    gateway_port: Literal[7443] = 7443
    telemetry_enabled: Literal[False] = False
    controller_violation_fails_safe: Literal[True] = True
    reachy: ReachyHardwareConfig = Field(default_factory=ReachyHardwareConfig)


def _hardware_allowed(environ: Mapping[str, str]) -> bool:
    raw_value = environ.get(_REACHY_HARDWARE_FLAG)
    if raw_value is None or raw_value == "0":
        return False
    if raw_value == "1":
        return True
    raise ValueError(f"{_REACHY_HARDWARE_FLAG} must be exactly 1 to enable hardware")


def load_edge_config(environ: Mapping[str, str] | None = None) -> EdgeConfig:
    source = os.environ if environ is None else environ
    return EdgeConfig(reachy=ReachyHardwareConfig(allow_hardware=_hardware_allowed(source)))
