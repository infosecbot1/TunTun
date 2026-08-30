from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import cast
from uuid import UUID

from tuntun_contracts.reachy import ReachyCommand, ReachyHealth, ReachyReceipt, SafetyReceipt

from .fake_providers import ExpectedCall, ObservedCall, _ScriptedFake


class FakeReachy(_ScriptedFake):
    def __init__(
        self,
        expectations: Iterable[ExpectedCall],
        observer: Callable[[ObservedCall], None] | None = None,
    ) -> None:
        super().__init__(expectations, observer)

    async def send(self, command: ReachyCommand) -> ReachyReceipt:
        return cast(ReachyReceipt, self._take("reachy.send", (command,)))

    async def health(self) -> ReachyHealth:
        return cast(ReachyHealth, self._take("reachy.health", ()))

    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
        return cast(SafetyReceipt, self._take("reachy.stop_all", (turn_id,)))
