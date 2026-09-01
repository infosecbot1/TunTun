from __future__ import annotations

from tuntun_core.services.sessions.turn_coordinator import TurnCoordinator


async def shutdown(coordinator: TurnCoordinator) -> None:
    """Stop the active Reachy turn through its full owned safety barrier."""

    if type(coordinator) is not TurnCoordinator:
        raise TypeError("coordinator must be an exact TurnCoordinator")
    active = coordinator.active_turn_id()
    if active is not None:
        await coordinator.cancel(active, "shutdown")
