from __future__ import annotations

from typing import Protocol

from tuntun_contracts.base import canonical_bytes, parse_contract_json
from tuntun_contracts.reachy import (
    ReachyCommand,
    ReachyHealth,
    ReachyReceipt,
    SafetyReceipt,
    StopAllReceiptBundleV1,
)
from tuntun_contracts.reachy_wire import MAX_CONTROL_PAYLOAD_BYTES, FramePurpose


class SignedControlSession(Protocol):
    async def exchange_signed(self, *, purpose: FramePurpose, payload: bytes) -> bytes: ...


class AuthenticatedControlClient:
    """Typed codec over the paired mTLS and signed/HMAC duplex channel."""

    def __init__(self, session: SignedControlSession) -> None:
        self._channel = session

    async def request_signed(self, command: ReachyCommand) -> ReachyReceipt:
        if type(command) is not ReachyCommand:
            raise TypeError("reachy command must be exact ReachyCommand")
        body = await self._channel.exchange_signed(
            purpose="reachy.command.v1",
            payload=canonical_bytes(command),
        )
        receipt = parse_contract_json(
            ReachyReceipt,
            body,
            max_bytes=MAX_CONTROL_PAYLOAD_BYTES,
            require_canonical=True,
        )
        if receipt.command_id != command.command_id:
            raise PermissionError("reachy_control_response_binding_mismatch")
        return receipt

    async def request_health_signed(self) -> ReachyHealth:
        body = await self._channel.exchange_signed(
            purpose="reachy.health.v1",
            payload=b'{"request":"health"}',
        )
        return parse_contract_json(
            ReachyHealth,
            body,
            max_bytes=MAX_CONTROL_PAYLOAD_BYTES,
            require_canonical=True,
        )

    async def request_stop_all_signed(
        self,
        command: ReachyCommand,
    ) -> tuple[ReachyReceipt, SafetyReceipt]:
        if type(command) is not ReachyCommand:
            raise TypeError("reachy command must be exact ReachyCommand")
        if command.kind != "stop_all":
            raise ValueError("stop transport requires stop_all command")
        body = await self._channel.exchange_signed(
            purpose="reachy.stop_all.v1",
            payload=canonical_bytes(command),
        )
        bundle = parse_contract_json(
            StopAllReceiptBundleV1,
            body,
            max_bytes=MAX_CONTROL_PAYLOAD_BYTES,
            require_canonical=True,
        )
        receipt = bundle.command_receipt
        safety = bundle.safety_receipt
        if receipt.command_id != command.command_id or safety.turn_id != command.turn_id:
            raise PermissionError("reachy_stop_response_binding_mismatch")
        return receipt, safety


__all__ = ("AuthenticatedControlClient", "SignedControlSession")
