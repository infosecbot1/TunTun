# packages/contracts/src/tuntun_contracts/reachy.py
from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .base import Commitment, ContractModel


class ReachyState(StrEnum):
    BOOTING = "booting"
    CONNECTING = "connecting"
    IDLE = "idle"
    WAKE_LISTENING = "wake_listening"
    THINKING = "thinking"
    SPEAKING = "speaking"
    MUTED = "muted"
    PRIVACY = "privacy"
    OFFLINE_ESSENTIAL = "offline_essential"
    ERROR_SAFE = "error_safe"
    SHUTTING_DOWN = "shutting_down"


class ReachyCommand(ContractModel):
    command_id: UUID
    turn_id: UUID | None
    kind: Literal["state", "playback", "gesture", "stop_all"]
    state: ReachyState | None = None
    media_stream_id: UUID | None = None
    gesture_id: Annotated[str | None, Field(default=None, pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def exact_payload(self) -> Self:
        present = (
            self.state is not None,
            self.media_stream_id is not None,
            self.gesture_id is not None,
        )
        expected = {
            "state": (True, False, False),
            "playback": (False, True, False),
            "gesture": (False, False, True),
            "stop_all": (False, False, False),
        }[self.kind]
        if present != expected:
            raise ValueError("reachy command payload mismatch")
        if self.kind in {"playback", "gesture"} and self.turn_id is None:
            raise ValueError("turn-scoped Reachy command required")
        return self


class ReachyReceipt(ContractModel):
    command_id: UUID
    accepted: bool
    reason_code: str


class ReachyHealth(ContractModel):
    state: ReachyState
    daemon_connected: bool
    queue_depth: Annotated[int, Field(ge=0)]


class SafetyReceipt(ContractModel):
    turn_id: UUID | None
    playback_stopped: bool
    motion_stopped: bool
    buffers_cleared: bool


class StopAllReceiptBundleV1(ContractModel):
    schema_version: Literal["tuntun.reachy-stop-all-receipts.v1"] = (
        "tuntun.reachy-stop-all-receipts.v1"
    )
    command_receipt: ReachyReceipt
    safety_receipt: SafetyReceipt


class StopSignal(ContractModel):
    signal_id: UUID
    source: Literal["edge_keyword", "physical_input", "owner_console", "watchdog"]
    occurred_at: AwareDatetime


class CameraWindowGrant(ContractModel):
    grant_id: UUID
    household_id: UUID
    device_id: UUID
    session_id: UUID
    turn_id: UUID
    subject_id: UUID | None
    action_name: Literal["identity.enroll", "identity.observe"]
    purpose: Literal["explicit_enrollment", "active_conversation_identity"]
    max_frames: Annotated[int, Field(ge=1, le=20)]
    max_frame_bytes: Annotated[int, Field(ge=1, le=1_048_576)]
    max_total_bytes: Annotated[int, Field(ge=1, le=10_485_760)]
    max_frames_per_second: Annotated[int, Field(ge=1, le=2)]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    grant_commitment: Commitment

    @model_validator(mode="after")
    def bounded_window(self) -> Self:
        expected_purpose = {
            "identity.enroll": "explicit_enrollment",
            "identity.observe": "active_conversation_identity",
        }[self.action_name]
        if self.purpose != expected_purpose:
            raise ValueError("camera action purpose mismatch")
        if (
            self.expires_at <= self.issued_at
            or (self.expires_at - self.issued_at).total_seconds() > 10
        ):
            raise ValueError("camera window must be positive and at most 10 seconds")
        if self.max_frames * self.max_frame_bytes < self.max_total_bytes:
            raise ValueError("camera aggregate bound exceeds frame bounds")
        if self.purpose == "explicit_enrollment" and self.subject_id is None:
            raise ValueError("enrollment camera window requires subject")
        return self


# packages/contracts/src/tuntun_contracts/reachy.py ends here.
