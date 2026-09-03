"""PTT bridge that upgrades a pinned SSH dispatcher stdio stream into Task 1 frames."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Mapping
from uuid import UUID

from tuntun_contracts.poc.framing import (
    MAX_FEED_BYTES,
    AckPayload,
    ControlFrame,
    ControlKind,
    FrameDecoder,
    FrameErrorCode,
    FrameProtocolError,
    PcmFrame,
    PttControl,
    PttDuplexGuard,
    PttErrorReason,
    PttInputMode,
    PttSessionOutcome,
    SafetyPayload,
    StreamDirection,
    encode_control_frame,
)

from .commissioning import (
    ReachyA05CommissioningRepository,
    ReachyA05StateExpectation,
    ReachyA05StateStatus,
)
from .ssh_forced import (
    DispatchVerb,
    ProcessFactory,
    SshBridgeError,
    SshForcedCommandProcess,
    SshStderrSummary,
)

PTT_CLEANUP_SECONDS = 3.5


class SshPttBridgeError(PermissionError):
    """Content-free PTT bridge failure."""

    def __init__(self) -> None:
        super().__init__("ssh-ptt-bridge-rejected")

    def __repr__(self) -> str:
        return "SshPttBridgeError()"


class SshPttBridge:
    def __init__(
        self,
        *,
        process: SshForcedCommandProcess,
        turn_id: UUID,
        input_mode: PttInputMode,
        expected_generation: int,
    ) -> None:
        self._process = process
        self._turn_id = turn_id
        self._input_mode = input_mode
        self._expected_generation = expected_generation
        self._guard = PttDuplexGuard(turn_id=turn_id, input_mode=input_mode)
        self._receive_decoder = FrameDecoder()
        self._closed = False
        self._cleanup_started = False
        self._final_outcome: PttSessionOutcome | None = None
        self._next_core_sequence = 0
        self._next_edge_sequence = 0
        self._now = 0.0
        self._close_lock = asyncio.Lock()

    @classmethod
    async def connect(
        cls,
        repository: ReachyA05CommissioningRepository,
        *,
        turn_id: UUID,
        input_mode: PttInputMode,
        operation_id: UUID,
        expectation: ReachyA05StateExpectation,
        process_factory: ProcessFactory | None = None,
    ) -> SshPttBridge:
        process = await SshForcedCommandProcess.spawn(
            repository,
            expectation=expectation,
            process_factory=process_factory,
        )
        if (
            process.target.status is not ReachyA05StateStatus.ACTIVE
            or process.target.ptt_input_mode is not input_mode
        ):
            await process.close()
            raise SshPttBridgeError()
        bridge = cls(
            process=process,
            turn_id=turn_id,
            input_mode=input_mode,
            expected_generation=process.target.state_generation,
        )
        try:
            response = await process.dispatch(
                DispatchVerb.RUN_PTT,
                operation_id=operation_id,
                expected_generation=process.target.state_generation,
                payload={"turn_id": str(turn_id), "input_mode": input_mode.value},
            )
            if response.payload != {"input_mode": input_mode.value, "ready": True}:
                raise SshPttBridgeError()
        except BaseException as error:
            await bridge._fail_closed(
                PttErrorReason.PROTOCOL_REJECTED,
                primary_error=error,
            )
            raise
        return bridge

    @property
    def final_outcome(self) -> PttSessionOutcome | None:
        return self._final_outcome

    @property
    def stderr_summary(self) -> SshStderrSummary:
        return self._process.stderr_summary

    async def send(self, frame: bytes) -> None:
        if self._closed:
            raise SshPttBridgeError()
        try:
            parsed = _decode_one_frame(frame)
            self._guard.accept(StreamDirection.CORE_TO_EDGE, parsed, now=self._tick())
            self._next_core_sequence = max(self._next_core_sequence, parsed.sequence + 1)
            if isinstance(parsed, ControlFrame):
                if parsed.control.kind in {
                    ControlKind.ABORT,
                    ControlKind.ERROR,
                    ControlKind.SAFETY_ACK,
                }:
                    self._cleanup_started = True
                if parsed.control.kind is ControlKind.SAFETY_ACK:
                    if not isinstance(parsed.control.payload, AckPayload):
                        raise SshPttBridgeError()
                    self._final_outcome = (
                        PttSessionOutcome.COMPLETED
                        if parsed.control.payload.accepted
                        else PttSessionOutcome.CLEANUP_INCOMPLETE
                    )
            await self._process.write(frame)
        except asyncio.CancelledError as error:
            await self._fail_closed(PttErrorReason.PROTOCOL_REJECTED, primary_error=error)
            raise
        except (SshPttBridgeError, FrameProtocolError, SshBridgeError):
            bridge_error = SshPttBridgeError()
            await self._fail_closed(
                PttErrorReason.PROTOCOL_REJECTED,
                primary_error=bridge_error,
            )
            raise bridge_error from None

    async def receive(self, max_bytes: int) -> bytes:
        if self._closed:
            raise SshPttBridgeError()
        try:
            if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FEED_BYTES:
                raise SshPttBridgeError()
            raw = await self._process.read(max_bytes)
            if not raw:
                await self._fail_closed(PttErrorReason.PEER_CLOSED)
                return b""
            frames = self._receive_decoder.feed(raw)
            for frame in frames:
                self._guard.accept(StreamDirection.EDGE_TO_CORE, frame, now=self._tick())
                self._next_edge_sequence = max(self._next_edge_sequence, frame.sequence + 1)
                if isinstance(frame, ControlFrame):
                    self._observe_edge_control(frame.control)
            return raw
        except asyncio.CancelledError as error:
            await self._fail_closed(PttErrorReason.PROTOCOL_REJECTED, primary_error=error)
            raise
        except (SshPttBridgeError, FrameProtocolError, SshBridgeError):
            bridge_error = SshPttBridgeError()
            await self._fail_closed(
                PttErrorReason.PROTOCOL_REJECTED,
                primary_error=bridge_error,
            )
            raise bridge_error from None

    async def close(self, *, reason: PttErrorReason = PttErrorReason.TURN_CANCELLED) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            await self._cleanup_and_close(reason, primary_error=None)

    async def _fail_closed(
        self,
        reason: PttErrorReason,
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        if self._closed:
            return
        self._closed = True
        await self._cleanup_and_close(reason, primary_error=primary_error)

    async def _cleanup_and_close(
        self,
        reason: PttErrorReason,
        *,
        primary_error: BaseException | None,
    ) -> None:
        local_error = primary_error
        try:
            await self._cleanup_protocol(reason)
        except BaseException as error:
            self._force_cleanup_incomplete()
            if local_error is None:
                local_error = error
            else:
                local_error.add_note("additional PTT cleanup failure")
        try:
            await self._process.close()
        except BaseException as close_error:
            self._force_cleanup_incomplete()
            if local_error is not None:
                local_error.add_note("additional SSH process close failure")
            elif isinstance(close_error, asyncio.CancelledError):
                raise
            else:
                raise SshPttBridgeError() from None
        if local_error is not None and primary_error is None:
            raise local_error

    def _force_cleanup_incomplete(self) -> None:
        self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE

    async def _cleanup_protocol(self, reason: PttErrorReason) -> None:
        if self._final_outcome is not None:
            return
        if not self._cleanup_started:
            abort = encode_control_frame(
                sequence=self._next_core_sequence,
                control=PttControl.abort(self._turn_id, reason),
            )
            with contextlib.suppress(SshPttBridgeError, FrameProtocolError):
                self._guard.accept(
                    StreamDirection.CORE_TO_EDGE,
                    _decode_one_frame(abort),
                    now=self._tick(),
                )
            self._next_core_sequence += 1
            self._cleanup_started = True
            with contextlib.suppress(SshBridgeError):
                await self._process.write(abort)
        try:
            receipt = await asyncio.wait_for(
                self._read_until_receipt(),
                timeout=PTT_CLEANUP_SECONDS,
            )
        except (TimeoutError, SshBridgeError, FrameProtocolError):
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            return
        if receipt is None:
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            return
        accepted = receipt.receipt.is_complete()
        ack = encode_control_frame(
            sequence=self._next_core_sequence,
            control=PttControl.safety_ack(self._turn_id, accepted=accepted),
        )
        self._next_core_sequence += 1
        try:
            await self._process.write(ack)
        except SshBridgeError:
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE
            return
        self._final_outcome = (
            _reason_to_outcome(reason) if accepted else PttSessionOutcome.CLEANUP_INCOMPLETE
        )

    async def _read_until_receipt(self) -> SafetyPayload | None:
        while True:
            raw = await self._process.read(MAX_FEED_BYTES)
            if not raw:
                return None
            frames = self._receive_decoder.feed(raw)
            for frame in frames:
                self._guard.accept(StreamDirection.EDGE_TO_CORE, frame, now=self._tick())
                self._next_edge_sequence = max(self._next_edge_sequence, frame.sequence + 1)
                if isinstance(frame, ControlFrame):
                    self._observe_edge_control(frame.control)
                    if frame.control.kind is ControlKind.SAFETY_RECEIPT:
                        if not isinstance(frame.control.payload, SafetyPayload):
                            raise FrameProtocolError(FrameErrorCode.INVALID_CONTROL)
                        return frame.control.payload

    def _observe_edge_control(self, control: PttControl) -> None:
        if control.kind in {ControlKind.STOP, ControlKind.CANCEL, ControlKind.ERROR}:
            self._cleanup_started = True
        if (
            control.kind is ControlKind.SAFETY_RECEIPT
            and isinstance(control.payload, SafetyPayload)
            and not control.payload.receipt.is_complete()
        ):
            self._final_outcome = PttSessionOutcome.CLEANUP_INCOMPLETE

    def _tick(self) -> float:
        self._now += 0.001
        return self._now


def _decode_one_frame(raw: bytes) -> ControlFrame | PcmFrame:
    decoder = FrameDecoder()
    frames = decoder.feed(raw)
    decoder.finish()
    if len(frames) != 1:
        raise SshPttBridgeError()
    return frames[0]


def _reason_to_outcome(reason: PttErrorReason) -> PttSessionOutcome:
    mapping: Mapping[PttErrorReason, PttSessionOutcome] = {
        PttErrorReason.PROTOCOL_REJECTED: PttSessionOutcome.PROTOCOL_REJECTED,
        PttErrorReason.TURN_CANCELLED: PttSessionOutcome.CANCELLED,
        PttErrorReason.CAPTURE_FAILED: PttSessionOutcome.CAPTURE_FAILED,
        PttErrorReason.PROVIDER_FAILED: PttSessionOutcome.PROVIDER_FAILED,
        PttErrorReason.PLAYBACK_FAILED: PttSessionOutcome.PLAYBACK_FAILED,
        PttErrorReason.CLEANUP_INCOMPLETE: PttSessionOutcome.CLEANUP_INCOMPLETE,
        PttErrorReason.PEER_CLOSED: PttSessionOutcome.PEER_CLOSED,
        PttErrorReason.SESSION_TIMEOUT: PttSessionOutcome.SESSION_TIMEOUT,
    }
    return mapping[reason]
