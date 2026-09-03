from __future__ import annotations

import os

import pytest


def _require_reachy_hardware_opt_in() -> None:
    if os.environ.get("TUNTUN_ALLOW_REACHY_HARDWARE") != "1":
        pytest.skip("TUNTUN_ALLOW_REACHY_HARDWARE=1 is required for physical Reachy tests")


@pytest.mark.reachy_hardware
@pytest.mark.asyncio
async def test_real_target_wss_uses_attested_permanent_neighbor() -> None:
    _require_reachy_hardware_opt_in()
    pytest.fail("Physical Reachy firewall/WSS acceptance must run on the supervised Reachy rig")


@pytest.mark.reachy_hardware
@pytest.mark.asyncio
async def test_real_target_wrong_neighbor_mac_blocks_wss_and_start_gate() -> None:
    _require_reachy_hardware_opt_in()
    pytest.fail("Physical Reachy firewall/WSS acceptance must run on the supervised Reachy rig")
