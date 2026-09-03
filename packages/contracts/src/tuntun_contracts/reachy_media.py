from __future__ import annotations

import hmac
import math
import struct
from _thread import LockType
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from threading import Lock
from typing import Final
from uuid import UUID

from pydantic_core import TzInfo as PydanticTzInfo

from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.reachy import CameraWindowGrant

PREFIX: Final = struct.Struct(">4sBBHI")
MEDIA_MAGIC: Final = b"TTN1"
MEDIA_TYPE_AUDIO: Final = 1
MEDIA_TYPE_CAMERA: Final = 2
MAX_HEADER: Final = 4_096
MAX_AUDIO_PAYLOAD: Final = 65_536
MAX_CAMERA_PAYLOAD: Final = 1_048_576
MAX_CAMERA_GRANT_TOTAL_BYTES: Final = 10_485_760
MAX_CAMERA_GRANT_SECONDS: Final = 10
MAX_CAMERA_GRANT_FRAMES: Final = 20
MAX_CAMERA_GRANT_FPS: Final = 2
CAMERA_GRANT_PURPOSE: Final = "reachy.camera.grant"
JCS_MAX_SAFE_INTEGER: Final = 2**53 - 1

_CLOSURE_REASONS: Final = frozenset(
    {"privacy", "cancel", "identity_completion", "expiry", "disconnect"}
)
_TRUSTED_FIXED_TZINFO_TYPES: Final = (timezone, PydanticTzInfo)


def parse_prefix(data: bytes) -> tuple[int, int, int, int]:
    if type(data) is not bytes:
        raise TypeError("media prefix must be bytes")
    if len(data) != PREFIX.size:
        raise ValueError("invalid media prefix length")

    magic, media_type, flags, header_len, payload_len = PREFIX.unpack(data)
    if magic != MEDIA_MAGIC:
        raise ValueError("invalid media magic")
    if media_type not in {MEDIA_TYPE_AUDIO, MEDIA_TYPE_CAMERA}:
        raise ValueError("unsupported media type")
    if flags != 0:
        raise ValueError("media flags must be zero")
    if header_len > MAX_HEADER:
        raise ValueError("media header too large")

    maximum_payload = MAX_CAMERA_PAYLOAD if media_type == MEDIA_TYPE_CAMERA else MAX_AUDIO_PAYLOAD
    if payload_len > maximum_payload:
        raise ValueError("media payload too large")
    return media_type, flags, header_len, payload_len


def _require_exact_int(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    return value


def _require_exact_uuid(value: object, *, label: str) -> UUID:
    if type(value) is not UUID:
        raise TypeError(f"{label} must be a UUID")
    return value


def _require_optional_exact_uuid(value: object, *, label: str) -> UUID | None:
    if value is None:
        return None
    return _require_exact_uuid(value, label=label)


def _require_exact_str(value: object, *, label: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{label} must be a string")
    return value


def _normalize_aware_utc(value: datetime, *, label: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    offset = value.utcoffset()
    if type(offset) is not timedelta:
        raise ValueError(f"{label} must be timezone-aware")
    if type(value.tzinfo) not in _TRUSTED_FIXED_TZINFO_TYPES:
        raise ValueError(f"{label} must use datetime.timezone or pydantic fixed-offset timezone")
    return value.astimezone(UTC)


def _validate_hmac_root(hmac_root: bytes) -> bytes:
    if type(hmac_root) is not bytes or len(hmac_root) != 32:
        raise ValueError("camera_hmac_root_invalid")
    return hmac_root


def _commitment_body(grant: CameraWindowGrant) -> bytes:
    if type(grant) is not CameraWindowGrant:
        raise TypeError("camera grant must be exactly CameraWindowGrant")
    return canonical_mapping_bytes(grant.model_dump(mode="python", exclude={"grant_commitment"}))


def _verify_grant_commitment(grant: CameraWindowGrant, hmac_root: bytes) -> None:
    try:
        expected = commit_private(
            hmac_root,
            grant.grant_commitment.key_id,
            CAMERA_GRANT_PURPOSE,
            _commitment_body(grant),
        )
    except (TypeError, ValueError, OverflowError) as error:
        raise PermissionError("camera_grant_commitment_invalid") from error
    if (
        grant.grant_commitment.algorithm != expected.algorithm
        or grant.grant_commitment.key_id != expected.key_id
        or not hmac.compare_digest(
            grant.grant_commitment.value_b64,
            expected.value_b64,
        )
    ):
        raise PermissionError("camera_grant_commitment_invalid")


def _validate_grant_caps(
    grant: CameraWindowGrant, issued_at: datetime, expires_at: datetime
) -> None:
    try:
        max_frames = _require_exact_int(grant.max_frames, label="camera max frames")
        max_frame_bytes = _require_exact_int(
            grant.max_frame_bytes,
            label="camera max frame bytes",
        )
        max_total_bytes = _require_exact_int(
            grant.max_total_bytes,
            label="camera max total bytes",
        )
        max_frames_per_second = _require_exact_int(
            grant.max_frames_per_second,
            label="camera max frames per second",
        )
    except TypeError as error:
        raise PermissionError("camera_grant_exceeds_phase1_cap") from error

    lifetime = expires_at - issued_at
    if (
        lifetime <= timedelta()
        or lifetime > timedelta(seconds=MAX_CAMERA_GRANT_SECONDS)
        or not 1 <= max_frames <= MAX_CAMERA_GRANT_FRAMES
        or not 1 <= max_frame_bytes <= MAX_CAMERA_PAYLOAD
        or not 1 <= max_total_bytes <= MAX_CAMERA_GRANT_TOTAL_BYTES
        or not 1 <= max_frames_per_second <= MAX_CAMERA_GRANT_FPS
        or max_frames * max_frame_bytes < max_total_bytes
    ):
        raise PermissionError("camera_grant_exceeds_phase1_cap")


@dataclass(frozen=True, slots=True)
class _CameraGrantSnapshot:
    grant_id: UUID
    household_id: UUID
    device_id: UUID
    session_id: UUID
    turn_id: UUID
    subject_id: UUID | None
    action_name: str
    purpose: str
    max_frames: int
    max_frame_bytes: int
    max_total_bytes: int
    max_frames_per_second: int

    @property
    def binding(self) -> tuple[UUID, UUID, UUID, UUID, UUID, UUID | None, str, str]:
        return (
            self.grant_id,
            self.household_id,
            self.device_id,
            self.session_id,
            self.turn_id,
            self.subject_id,
            self.action_name,
            self.purpose,
        )


def _snapshot_grant(grant: CameraWindowGrant) -> _CameraGrantSnapshot:
    return _CameraGrantSnapshot(
        grant_id=grant.grant_id,
        household_id=grant.household_id,
        device_id=grant.device_id,
        session_id=grant.session_id,
        turn_id=grant.turn_id,
        subject_id=grant.subject_id,
        action_name=grant.action_name,
        purpose=grant.purpose,
        max_frames=_require_exact_int(grant.max_frames, label="camera max frames"),
        max_frame_bytes=_require_exact_int(
            grant.max_frame_bytes,
            label="camera max frame bytes",
        ),
        max_total_bytes=_require_exact_int(
            grant.max_total_bytes,
            label="camera max total bytes",
        ),
        max_frames_per_second=_require_exact_int(
            grant.max_frames_per_second,
            label="camera max frames per second",
        ),
    )


class CameraWindow:
    _bytes_remaining: int
    _closed: bool
    _expires_at_utc: datetime
    _frames_remaining: int
    _grant: CameraWindowGrant
    _initialized: bool
    _issued_at_utc: datetime
    _last_frame_at: datetime | None
    _lock: LockType
    _next_sequence: int
    _snapshot: _CameraGrantSnapshot

    __slots__ = (
        "_bytes_remaining",
        "_closed",
        "_expires_at_utc",
        "_frames_remaining",
        "_grant",
        "_initialized",
        "_issued_at_utc",
        "_last_frame_at",
        "_lock",
        "_next_sequence",
        "_snapshot",
    )

    def __init__(
        self,
        *,
        grant: CameraWindowGrant,
        snapshot: _CameraGrantSnapshot,
        issued_at_utc: datetime,
        expires_at_utc: datetime,
    ) -> None:
        del grant, snapshot, issued_at_utc, expires_at_utc
        raise TypeError("use CameraWindow.open")

    def _initialize(
        self,
        *,
        grant: CameraWindowGrant,
        snapshot: _CameraGrantSnapshot,
        issued_at_utc: datetime,
        expires_at_utc: datetime,
    ) -> None:
        if getattr(self, "_initialized", False):
            raise RuntimeError("camera window already initialized")
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_grant", grant.model_copy(deep=True))
        object.__setattr__(self, "_snapshot", snapshot)
        object.__setattr__(self, "_frames_remaining", snapshot.max_frames)
        object.__setattr__(self, "_bytes_remaining", snapshot.max_total_bytes)
        object.__setattr__(self, "_issued_at_utc", issued_at_utc)
        object.__setattr__(self, "_expires_at_utc", expires_at_utc)
        object.__setattr__(self, "_next_sequence", 0)
        object.__setattr__(self, "_last_frame_at", None)
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("camera window state is read-only")
        object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        return (
            f"CameraWindow(grant_id={self._snapshot.grant_id!r}, "
            f"frames_remaining={self._frames_remaining!r}, "
            f"bytes_remaining={self._bytes_remaining!r}, "
            f"next_sequence={self._next_sequence!r}, closed={self._closed!r})"
        )

    @property
    def grant(self) -> CameraWindowGrant:
        return self._grant.model_copy(deep=True)

    @property
    def frames_remaining(self) -> int:
        return self._frames_remaining

    @property
    def bytes_remaining(self) -> int:
        return self._bytes_remaining

    @property
    def next_sequence(self) -> int:
        return self._next_sequence

    @property
    def last_frame_at(self) -> datetime | None:
        return self._last_frame_at

    @property
    def closed(self) -> bool:
        return self._closed

    @classmethod
    def open(
        cls,
        grant: CameraWindowGrant,
        hmac_root: bytes,
        now: datetime,
    ) -> CameraWindow:
        if cls is not CameraWindow:
            raise TypeError("camera window type must be exact")
        if type(grant) is not CameraWindowGrant:
            raise TypeError("camera grant must be exactly CameraWindowGrant")
        root = _validate_hmac_root(hmac_root)
        issued_at = _normalize_aware_utc(grant.issued_at, label="camera issued_at")
        expires_at = _normalize_aware_utc(grant.expires_at, label="camera expires_at")
        now_utc = _normalize_aware_utc(now, label="camera now")
        _validate_grant_caps(grant, issued_at, expires_at)
        _verify_grant_commitment(grant, root)
        snapshot = _snapshot_grant(grant)

        if now_utc < issued_at:
            raise PermissionError("camera_window_not_yet_valid")
        if now_utc > expires_at:
            raise PermissionError("camera_window_expired")
        window = object.__new__(CameraWindow)
        window._initialize(
            grant=grant,
            snapshot=snapshot,
            issued_at_utc=issued_at,
            expires_at_utc=expires_at,
        )
        return window

    def consume(
        self,
        *,
        grant_id: UUID,
        household_id: UUID,
        device_id: UUID,
        session_id: UUID,
        turn_id: UUID,
        subject_id: UUID | None,
        action_name: str,
        purpose: str,
        sequence: int,
        payload_size: int,
        now: datetime,
    ) -> None:
        with self._lock:
            if self._closed:
                raise PermissionError("camera_window_closed")

            supplied = (
                _require_exact_uuid(grant_id, label="camera grant_id"),
                _require_exact_uuid(household_id, label="camera household_id"),
                _require_exact_uuid(device_id, label="camera device_id"),
                _require_exact_uuid(session_id, label="camera session_id"),
                _require_exact_uuid(turn_id, label="camera turn_id"),
                _require_optional_exact_uuid(subject_id, label="camera subject_id"),
                _require_exact_str(action_name, label="camera action_name"),
                _require_exact_str(purpose, label="camera purpose"),
            )
            if supplied != self._snapshot.binding:
                raise PermissionError("camera_grant_binding_mismatch")

            checked_sequence = _require_exact_int(sequence, label="camera sequence")
            checked_payload_size = _require_exact_int(
                payload_size,
                label="camera payload size",
            )
            now_utc = _normalize_aware_utc(now, label="camera now")
            if now_utc > self._expires_at_utc:
                raise PermissionError("camera_window_expired")
            if checked_sequence < 0 or checked_sequence > JCS_MAX_SAFE_INTEGER:
                raise ValueError("camera sequence outside bounds")
            if checked_sequence != self._next_sequence:
                raise ValueError("camera_sequence_mismatch")
            if checked_payload_size < 0 or checked_payload_size > MAX_CAMERA_PAYLOAD:
                raise ValueError("camera payload size outside bounds")
            if checked_payload_size > self._snapshot.max_frame_bytes:
                raise ValueError("camera payload size outside grant frame cap")
            if self._frames_remaining <= 0:
                raise ValueError("camera frame quota exhausted")

            if self._last_frame_at is not None:
                interval = (now_utc - self._last_frame_at).total_seconds()
                minimum_interval = 1 / self._snapshot.max_frames_per_second
                if interval < 0:
                    raise ValueError("camera monotonic time rollback")
                if interval < minimum_interval and not math.isclose(
                    interval,
                    minimum_interval,
                    rel_tol=0,
                    abs_tol=1e-12,
                ):
                    raise ValueError("camera frame rate exceeded")
            if checked_payload_size > self._bytes_remaining:
                raise ValueError("camera byte quota exhausted")

            object.__setattr__(self, "_next_sequence", self._next_sequence + 1)
            object.__setattr__(self, "_frames_remaining", self._frames_remaining - 1)
            object.__setattr__(
                self,
                "_bytes_remaining",
                self._bytes_remaining - checked_payload_size,
            )
            object.__setattr__(self, "_last_frame_at", now_utc)

    def close(self, reason: str) -> None:
        with self._lock:
            if self._closed:
                raise PermissionError("camera_window_closed")
            if type(reason) is not str or reason not in _CLOSURE_REASONS:
                raise ValueError("invalid camera closure reason")
            object.__setattr__(self, "_closed", True)


__all__ = [
    "CAMERA_GRANT_PURPOSE",
    "CameraWindow",
    "MAX_AUDIO_PAYLOAD",
    "MAX_CAMERA_PAYLOAD",
    "MAX_HEADER",
    "MEDIA_MAGIC",
    "MEDIA_TYPE_AUDIO",
    "MEDIA_TYPE_CAMERA",
    "PREFIX",
    "parse_prefix",
]
