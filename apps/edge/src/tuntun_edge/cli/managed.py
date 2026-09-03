from __future__ import annotations

import asyncio

from tuntun_edge.bootstrap.managed import run_production_managed_edge


def managed() -> None:
    """Run the Reachy managed-app Edge process."""
    asyncio.run(run_production_managed_edge())
