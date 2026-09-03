from __future__ import annotations

import os

import pytest
from tuntun_edge.reachy.probe import (
    ReachyHardwareNotAllowedError,
    probe_reachy_hardware_capabilities,
)

pytestmark = pytest.mark.reachy_hardware


def test_reachy_hardware_capability_probe_is_explicitly_enabled() -> None:
    try:
        probe_reachy_hardware_capabilities(environ=os.environ)
    except ReachyHardwareNotAllowedError as error:
        pytest.skip(str(error))

    pytest.fail("physical Reachy capability probing is intentionally not implemented in Task08")
