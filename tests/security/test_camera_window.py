from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import Any, cast
from uuid import UUID

import pytest
from tuntun_contracts.base import Commitment, canonical_mapping_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.reachy import CameraWindowGrant
from tuntun_contracts.reachy_media import MAX_CAMERA_PAYLOAD, CameraWindow
from tuntun_edge.transport.media import MAX_AUDIO_PAYLOAD, MediaQuota

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
ROOT = bytes(range(32))
HMAC_KEY_ID = "camera-hmac-v1"


class _CameraGrantSubclass(CameraWindowGrant):
    pass


class _AlwaysEqual:
    def __eq__(self, other: object) -> bool:
        return True


class _CustomUTC(tzinfo):
    def utcoffset(self, dt: datetime | None) -> timedelta:
        return timedelta()

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta()

    def tzname(self, dt: datetime | None) -> str:
        return "custom-utc"


def _uuid(value: int) -> UUID:
    return UUID(int=value)


def _commitment_body(grant: CameraWindowGrant) -> bytes:
    return canonical_mapping_bytes(grant.model_dump(mode="python", exclude={"grant_commitment"}))


def _recommit(grant: CameraWindowGrant, root: bytes = ROOT) -> CameraWindowGrant:
    return grant.model_copy(
        update={
            "grant_commitment": commit_private(
                root,
                HMAC_KEY_ID,
                "reachy.camera.grant",
                _commitment_body(grant),
            )
        }
    )


def _grant(
    *,
    root: bytes = ROOT,
    issued_at: datetime = NOW,
    expires_at: datetime | None = None,
    max_frames: int = 20,
    max_frame_bytes: int = 1_000_000,
    max_total_bytes: int = 10_000_000,
    max_frames_per_second: int = 2,
) -> CameraWindowGrant:
    draft = CameraWindowGrant(
        grant_id=_uuid(1001),
        household_id=_uuid(1002),
        device_id=_uuid(1003),
        session_id=_uuid(1004),
        turn_id=_uuid(1005),
        subject_id=_uuid(1006),
        action_name="identity.enroll",
        purpose="explicit_enrollment",
        max_frames=max_frames,
        max_frame_bytes=max_frame_bytes,
        max_total_bytes=max_total_bytes,
        max_frames_per_second=max_frames_per_second,
        issued_at=issued_at,
        expires_at=expires_at or issued_at + timedelta(seconds=10),
        grant_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id=HMAC_KEY_ID,
            value_b64="A" * 43 + "=",
        ),
    )
    return _recommit(draft, root)


def _frame(
    grant: CameraWindowGrant,
    *,
    sequence: object = 0,
    payload_size: object = 1,
    now: datetime = NOW,
    **overrides: object,
) -> dict[str, object]:
    values: dict[str, object] = {
        "grant_id": grant.grant_id,
        "household_id": grant.household_id,
        "device_id": grant.device_id,
        "session_id": grant.session_id,
        "turn_id": grant.turn_id,
        "subject_id": grant.subject_id,
        "action_name": grant.action_name,
        "purpose": grant.purpose,
        "sequence": sequence,
        "payload_size": payload_size,
        "now": now,
    }
    values.update(overrides)
    return values


def _camera_state(window: CameraWindow) -> tuple[int, int, int, datetime | None, bool]:
    return (
        window.frames_remaining,
        window.bytes_remaining,
        window.next_sequence,
        window.last_frame_at,
        window.closed,
    )


def _quota_state(quota: MediaQuota) -> tuple[float, float | None, int]:
    return (quota.started_mono, quota.last_frame_mono, quota.bytes_received)


def _consume(window: CameraWindow, frame: Mapping[str, object]) -> None:
    window.consume(**cast(Any, dict(frame)))


def _accept_audio(quota: MediaQuota, params: Mapping[str, object]) -> None:
    quota.accept_audio(**cast(Any, dict(params)))


def test_camera_window_recomputes_commitment_normalizes_utc_and_does_not_retain_root() -> None:
    issued = datetime(2026, 9, 3, 20, 0, tzinfo=timezone(timedelta(hours=8)))
    grant = _grant(issued_at=issued, expires_at=issued + timedelta(seconds=10))

    window = CameraWindow.open(grant, ROOT, NOW)

    assert window.frames_remaining == 20
    assert window.bytes_remaining == 10_000_000
    assert not hasattr(window, "hmac_root")
    assert ROOT.hex() not in repr(window)
    assert ROOT.hex() not in repr(window.grant.model_dump(mode="python"))


@pytest.mark.parametrize("bad_root", (b"c" * 31, b"c" * 33, bytearray(b"c" * 32), True))
def test_camera_window_requires_exact_32_byte_hmac_root(bad_root: object) -> None:
    with pytest.raises(ValueError, match="camera_hmac_root_invalid"):
        CameraWindow.open(_grant(), bad_root, NOW)  # type: ignore[arg-type]


def test_camera_window_requires_exact_grant_type() -> None:
    grant = _CameraGrantSubclass.model_validate(_grant().model_dump(mode="python"))

    with pytest.raises(TypeError, match="camera grant must be exactly CameraWindowGrant"):
        CameraWindow.open(grant, ROOT, NOW)


def test_camera_window_rejects_stateful_or_custom_timezone_inputs() -> None:
    now = datetime(2026, 9, 3, 12, 0, tzinfo=_CustomUTC())

    with pytest.raises(ValueError, match="camera now must use datetime.timezone"):
        CameraWindow.open(_grant(), ROOT, now)


def test_camera_window_accepts_json_parsed_contract_fixed_offset_timestamps() -> None:
    grant = CameraWindowGrant.model_validate_json(_grant().model_dump_json())

    window = CameraWindow.open(grant, ROOT, NOW)

    assert window.frames_remaining == grant.max_frames


@pytest.mark.parametrize(
    "mutation",
    (
        {"grant_id": _uuid(9001)},
        {"household_id": _uuid(9002)},
        {"device_id": _uuid(9003)},
        {"session_id": _uuid(9004)},
        {"turn_id": _uuid(9005)},
        {"subject_id": _uuid(9006)},
    ),
)
def test_camera_window_rejects_mutated_grant_by_independent_recomputation(
    mutation: dict[str, object],
) -> None:
    grant = _grant().model_copy(update=mutation)

    with pytest.raises(PermissionError, match="camera_grant_commitment_invalid"):
        CameraWindow.open(grant, ROOT, NOW)


@pytest.mark.parametrize(
    "mutation",
    (
        {"max_frames": 21},
        {"max_frame_bytes": MAX_CAMERA_PAYLOAD + 1},
        {"max_total_bytes": 10_485_761},
        {"max_frames_per_second": 3},
        {"expires_at": NOW + timedelta(seconds=10, microseconds=1)},
    ),
)
def test_camera_window_revalidates_phase1_caps_after_valid_commitment(
    mutation: dict[str, object],
) -> None:
    grant = _recommit(_grant().model_copy(update=mutation))

    with pytest.raises(PermissionError, match="camera_grant_exceeds_phase1_cap"):
        CameraWindow.open(grant, ROOT, NOW)


def test_camera_window_expiry_is_inclusive_and_rejects_after_without_consuming() -> None:
    grant = _grant(max_frames=2, max_total_bytes=2)
    window = CameraWindow.open(grant, ROOT, grant.expires_at)

    _consume(window, _frame(grant, now=grant.expires_at))
    state = _camera_state(window)
    with pytest.raises(PermissionError, match="camera_window_expired"):
        _consume(
            window,
            _frame(
                grant,
                sequence=1,
                payload_size=1,
                now=grant.expires_at + timedelta(microseconds=1),
            ),
        )
    assert _camera_state(window) == state


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("grant_id", _uuid(2001)),
        ("household_id", _uuid(2002)),
        ("device_id", _uuid(2003)),
        ("session_id", _uuid(2004)),
        ("turn_id", _uuid(2005)),
        ("subject_id", _uuid(2006)),
        ("action_name", "identity.observe"),
        ("purpose", "active_conversation_identity"),
    ),
)
def test_camera_window_binds_every_identity_action_and_purpose(
    field: str,
    replacement: object,
) -> None:
    grant = _grant()
    window = CameraWindow.open(grant, ROOT, NOW)
    state = _camera_state(window)

    with pytest.raises(PermissionError, match="camera_grant_binding_mismatch"):
        frame = _frame(grant)
        frame[field] = replacement
        _consume(window, frame)
    assert _camera_state(window) == state


def test_camera_window_rejects_binding_objects_that_only_compare_equal() -> None:
    grant = _grant()
    window = CameraWindow.open(grant, ROOT, NOW)
    state = _camera_state(window)

    with pytest.raises(TypeError, match="camera grant_id must be a UUID"):
        _consume(window, _frame(grant, grant_id=_AlwaysEqual()))
    assert _camera_state(window) == state


def test_camera_window_uses_immutable_grant_snapshot_for_later_enforcement() -> None:
    grant = _grant(
        max_frames=2,
        max_frame_bytes=1,
        max_total_bytes=2,
        max_frames_per_second=2,
    )
    window = CameraWindow.open(grant, ROOT, NOW)
    _consume(window, _frame(grant, sequence=0, payload_size=1, now=NOW))

    public_grant = window.grant
    object.__setattr__(public_grant, "max_frames_per_second", 1000)
    state = _camera_state(window)

    with pytest.raises(ValueError, match="camera frame rate exceeded"):
        _consume(
            window,
            _frame(
                grant,
                sequence=1,
                payload_size=1,
                now=NOW + timedelta(milliseconds=10),
            ),
        )
    assert _camera_state(window) == state


def test_camera_window_public_state_is_read_only_and_close_cannot_be_reopened() -> None:
    grant = _grant()
    window = CameraWindow.open(grant, ROOT, NOW)
    window.close("cancel")
    state = _camera_state(window)

    for name, value in (
        ("frames_remaining", 20),
        ("bytes_remaining", 10_000_000),
        ("next_sequence", 0),
        ("last_frame_at", None),
        ("closed", False),
    ):
        with pytest.raises(AttributeError):
            setattr(window, name, value)

    with pytest.raises(PermissionError, match="camera_window_closed"):
        _consume(window, _frame(grant, sequence=0, payload_size=1, now=NOW))
    assert _camera_state(window) == state


def test_camera_window_uses_strict_sequence_and_rejected_frames_do_not_consume() -> None:
    grant = _grant(max_frames=2, max_total_bytes=20)
    window = CameraWindow.open(grant, ROOT, NOW)
    _consume(window, _frame(grant, sequence=0, payload_size=5, now=NOW))
    state = _camera_state(window)

    with pytest.raises(ValueError, match="camera_sequence_mismatch"):
        _consume(
            window,
            _frame(grant, sequence=2, payload_size=5, now=NOW + timedelta(seconds=0.5)),
        )
    assert _camera_state(window) == state

    _consume(window, _frame(grant, sequence=1, payload_size=5, now=NOW + timedelta(seconds=0.5)))
    assert window.frames_remaining == 0
    assert window.bytes_remaining == 10


@pytest.mark.parametrize(
    ("kwargs", "error_type", "message"),
    (
        ({"sequence": True}, TypeError, "camera sequence must be an integer"),
        ({"sequence": -1}, ValueError, "camera sequence outside bounds"),
        ({"sequence": 2**53}, ValueError, "camera sequence outside bounds"),
        ({"payload_size": True}, TypeError, "camera payload size must be an integer"),
        ({"payload_size": -1}, ValueError, "camera payload size outside bounds"),
        ({"payload_size": 1_000_001}, ValueError, "camera payload size outside grant frame cap"),
    ),
)
def test_camera_window_rejects_malformed_frame_numbers_without_state_mutation(
    kwargs: dict[str, object],
    error_type: type[Exception],
    message: str,
) -> None:
    grant = _grant()
    window = CameraWindow.open(grant, ROOT, NOW)
    state = _camera_state(window)

    with pytest.raises(error_type, match=message):
        frame = _frame(grant)
        frame.update(kwargs)
        _consume(window, frame)
    assert _camera_state(window) == state


def test_camera_window_rate_and_byte_rejections_do_not_consume_counters() -> None:
    grant = _grant(max_frames=2, max_total_bytes=1_000_000)
    window = CameraWindow.open(grant, ROOT, NOW)
    _consume(window, _frame(grant, sequence=0, payload_size=999_999, now=NOW))

    for kwargs, message in (
        (
            {"sequence": 1, "payload_size": 1, "now": NOW + timedelta(seconds=0.499)},
            "camera frame rate exceeded",
        ),
        (
            {"sequence": 1, "payload_size": 2, "now": NOW + timedelta(seconds=0.5)},
            "camera byte quota exhausted",
        ),
    ):
        state = _camera_state(window)
        with pytest.raises(ValueError, match=message):
            frame = _frame(grant)
            frame.update(kwargs)
            _consume(window, frame)
        assert _camera_state(window) == state

    _consume(window, _frame(grant, sequence=1, payload_size=1, now=NOW + timedelta(seconds=0.5)))
    with pytest.raises(ValueError, match="camera frame quota exhausted"):
        _consume(window, _frame(grant, sequence=2, payload_size=1, now=NOW + timedelta(seconds=1)))


def test_terminal_close_is_irreversible_and_invalid_reason_does_not_close() -> None:
    grant = _grant()
    window = CameraWindow.open(grant, ROOT, NOW)

    with pytest.raises(ValueError, match="invalid camera closure reason"):
        window.close("debug")
    _consume(window, _frame(grant, sequence=0, payload_size=1, now=NOW))

    window.close("identity_completion")
    with pytest.raises(PermissionError, match="camera_window_closed"):
        _consume(
            window,
            _frame(grant, sequence=1, payload_size=1, now=NOW + timedelta(seconds=0.5)),
        )
    with pytest.raises(PermissionError, match="camera_window_closed"):
        window.close("disconnect")


def test_media_quota_accepts_audio_boundaries() -> None:
    quota = MediaQuota(started_mono=10.0)

    for index in range(128):
        quota.accept_audio(
            payload_size=MAX_AUDIO_PAYLOAD,
            duration_ms=200,
            now_mono=10.0 + (index * 0.02),
        )

    assert quota.bytes_received == 8_388_608
    assert quota.last_frame_mono == 10.0 + (127 * 0.02)


def test_media_quota_rejects_initial_state_beyond_turn_window() -> None:
    with pytest.raises(ValueError, match="audio turn duration cap exceeded"):
        MediaQuota(started_mono=10.0, last_frame_mono=100.001)


def test_media_quota_public_state_is_read_only_and_cannot_be_reinitialized() -> None:
    quota = MediaQuota(started_mono=10.0)
    quota.accept_audio(payload_size=1, duration_ms=20, now_mono=10.0)
    state = _quota_state(quota)

    for name, value in (
        ("started_mono", 0.0),
        ("last_frame_mono", None),
        ("bytes_received", 0),
    ):
        with pytest.raises(AttributeError):
            setattr(quota, name, value)

    with pytest.raises(RuntimeError, match="audio quota already initialized"):
        MediaQuota.__init__(quota, started_mono=0.0)
    assert _quota_state(quota) == state


@pytest.mark.parametrize(
    ("kwargs", "error_type", "message"),
    (
        ({"payload_size": True}, TypeError, "audio payload size must be an integer"),
        ({"payload_size": -1}, ValueError, "audio frame byte cap exceeded"),
        ({"payload_size": MAX_AUDIO_PAYLOAD + 1}, ValueError, "audio frame byte cap exceeded"),
        ({"duration_ms": True}, TypeError, "audio duration must be an integer"),
        ({"duration_ms": 0}, ValueError, "audio frame duration cap exceeded"),
        ({"duration_ms": 201}, ValueError, "audio frame duration cap exceeded"),
        ({"now_mono": math.nan}, ValueError, "audio monotonic time invalid"),
        ({"now_mono": math.inf}, ValueError, "audio monotonic time invalid"),
        ({"now_mono": 9.999}, ValueError, "audio monotonic time rollback"),
        ({"now_mono": 100.001}, ValueError, "audio turn duration cap exceeded"),
    ),
)
def test_media_quota_rejects_malformed_or_out_of_window_audio_without_mutation(
    kwargs: dict[str, Any],
    error_type: type[Exception],
    message: str,
) -> None:
    quota = MediaQuota(started_mono=10.0)
    state = _quota_state(quota)
    params: dict[str, Any] = {"payload_size": 1, "duration_ms": 20, "now_mono": 10.0}
    params.update(kwargs)

    with pytest.raises(error_type, match=message):
        _accept_audio(quota, params)
    assert _quota_state(quota) == state


def test_media_quota_rejects_rate_rollback_and_total_cap_without_mutation() -> None:
    quota = MediaQuota(started_mono=10.0)
    quota.accept_audio(payload_size=MAX_AUDIO_PAYLOAD, duration_ms=20, now_mono=10.0)

    for params, message in (
        (
            {"payload_size": 1, "duration_ms": 20, "now_mono": 10.019},
            "audio frame rate exceeded",
        ),
        (
            {"payload_size": 1, "duration_ms": 20, "now_mono": 9.999},
            "audio monotonic time rollback",
        ),
    ):
        state = _quota_state(quota)
        with pytest.raises(ValueError, match=message):
            _accept_audio(quota, params)
        assert _quota_state(quota) == state

    quota = MediaQuota(started_mono=10.0, last_frame_mono=10.0, bytes_received=8_388_608)
    state = _quota_state(quota)
    with pytest.raises(ValueError, match="audio turn byte cap exceeded"):
        quota.accept_audio(payload_size=1, duration_ms=20, now_mono=10.02)
    assert _quota_state(quota) == state
