from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from tuntun_contracts.reachy import ReachyCommand, ReachyHealth, ReachyReceipt, SafetyReceipt
from tuntun_contracts.reachy_media import parse_prefix


class Clock(Protocol):
    def now(self) -> datetime: ...


class ControlClient(Protocol):
    async def request_signed(self, command: ReachyCommand) -> ReachyReceipt: ...

    async def request_health_signed(self) -> ReachyHealth: ...

    async def request_stop_all_signed(
        self,
        command: ReachyCommand,
    ) -> tuple[ReachyReceipt, SafetyReceipt]: ...


def validate_prefix_before_allocation(prefix: bytes) -> tuple[int, int, int, int]:
    return parse_prefix(prefix)


class ReachyGateway:
    def __init__(self, authenticated_control: ControlClient, clock: Clock) -> None:
        self._control = authenticated_control
        self._clock = clock

    async def send(self, command: ReachyCommand) -> ReachyReceipt:
        if type(command) is not ReachyCommand:
            raise TypeError("reachy command must be exact ReachyCommand")
        receipt = await self._control.request_signed(command)
        if type(receipt) is not ReachyReceipt or receipt.command_id != command.command_id:
            raise RuntimeError("reachy_receipt_binding_mismatch")
        return receipt

    async def health(self) -> ReachyHealth:
        health = await self._control.request_health_signed()
        if type(health) is not ReachyHealth:
            raise RuntimeError("reachy_health_contract_mismatch")
        return health

    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
        if turn_id is not None and type(turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        command = ReachyCommand(
            command_id=uuid4(),
            turn_id=turn_id,
            kind="stop_all",
            state=None,
            media_stream_id=None,
            gesture_id=None,
            expires_at=self._clock.now() + timedelta(seconds=2),
        )
        receipt, safety = await self._control.request_stop_all_signed(command)
        if type(receipt) is not ReachyReceipt or receipt.command_id != command.command_id:
            raise RuntimeError("reachy_receipt_binding_mismatch")
        if type(safety) is not SafetyReceipt:
            raise RuntimeError("reachy_safety_receipt_contract_mismatch")
        if safety.turn_id != turn_id:
            raise RuntimeError("reachy_safety_receipt_binding_mismatch")
        all_safe = safety.playback_stopped and safety.motion_stopped and safety.buffers_cleared
        if receipt.accepted is not all_safe:
            raise RuntimeError("reachy_command_and_safety_receipt_mismatch")
        return safety


__all__ = ("ReachyGateway", "validate_prefix_before_allocation")
