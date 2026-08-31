from __future__ import annotations

from struct import Struct
from uuid import UUID

import pytest
import tuntun_contracts
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule
from pydantic import ValidationError
from tuntun_contracts.base import canonical_bytes, registered_contract_models
from tuntun_contracts.poc import framing
from tuntun_contracts.poc.framing import (
    TRANSPORT_AUDIO_FORMAT,
    AckPayload,
    ControlFrame,
    ControlKind,
    EmptyPayload,
    FrameDecoder,
    FrameErrorCode,
    FrameHeader,
    FrameKind,
    FrameProtocolError,
    GuardDisposition,
    GuardedFrame,
    PcmFrame,
    PttControl,
    PttDuplexGuard,
    PttErrorReason,
    PttInputMode,
    PttSafetyReceipt,
    PttSessionOutcome,
    PttStopSource,
    SafetyPayload,
    SessionPayload,
    StartPayload,
    StreamDirection,
    encode_control_frame,
    encode_pcm_frame,
)
from tuntun_contracts.speech import AudioFormat

TURN_ID = UUID("12345678-1234-5678-1234-567812345678")
PREFIX = Struct(">4sBBHII16s")


def wire_control(
    body: bytes,
    *,
    turn_id: UUID = TURN_ID,
    sequence: int = 0,
    magic: bytes = b"TTPT",
    version: int = 1,
    kind: int = FrameKind.CONTROL,
    flags: int = 0,
    declared_length: int | None = None,
) -> bytes:
    length = len(body) if declared_length is None else declared_length
    return PREFIX.pack(magic, version, kind, flags, sequence, length, turn_id.bytes) + body


def complete_receipt(*, turn_id: UUID = TURN_ID, complete: bool = True) -> PttSafetyReceipt:
    return PttSafetyReceipt(
        turn_id=turn_id,
        new_capture_rejected=complete,
        recording_stopped=complete,
        playback_stopped=complete,
        motion_stopped=complete,
        audio_reactive_disabled=complete,
        owned_buffers_cleared=complete,
    )


def control_frame(sequence: int, control: PttControl) -> ControlFrame:
    return ControlFrame(turn_id=TURN_ID, sequence=sequence, control=control)


def pcm_frame(sequence: int, *, size: int = 2) -> PcmFrame:
    return PcmFrame(turn_id=TURN_ID, sequence=sequence, pcm=b"\x00\x00" * (size // 2))


def accept(
    guard: PttDuplexGuard,
    direction: StreamDirection,
    frame: ControlFrame | PcmFrame,
    now: float,
) -> GuardedFrame:
    return guard.accept(direction, frame, now=now)


def opened_guard(
    mode: PttInputMode,
    *,
    start_at: float = 0.0,
) -> PttDuplexGuard:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=mode)
    assert (
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(0, PttControl.session_open(TURN_ID, mode)),
            start_at,
        ).disposition
        is GuardDisposition.ACCEPTED
    )
    assert (
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(0, PttControl.session_ready(TURN_ID, mode)),
            start_at + 0.01,
        ).disposition
        is GuardDisposition.ACCEPTED
    )
    return guard


def test_control_frame_round_trip_has_exact_prefix() -> None:
    control = PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)

    encoded = encode_control_frame(sequence=0, control=control)

    assert encoded[:32] == PREFIX.pack(
        b"TTPT",
        1,
        FrameKind.CONTROL,
        0,
        0,
        len(encoded) - 32,
        TURN_ID.bytes,
    )
    decoder = FrameDecoder()
    assert decoder.feed(encoded[:7]) == ()
    assert decoder.feed(encoded[7:]) == (
        ControlFrame(turn_id=TURN_ID, sequence=0, control=control),
    )


def test_pcm_round_trip_is_turn_bound_and_sample_aligned() -> None:
    pcm = b"\x01\x00\x02\x00"

    encoded = encode_pcm_frame(turn_id=TURN_ID, sequence=7, pcm=pcm)

    assert encoded[:32] == PREFIX.pack(b"TTPT", 1, FrameKind.PCM, 0, 7, len(pcm), TURN_ID.bytes)
    assert FrameDecoder().feed(encoded) == (PcmFrame(turn_id=TURN_ID, sequence=7, pcm=pcm),)


def test_decoder_handles_fragmented_and_coalesced_frames() -> None:
    control = PttControl.heartbeat(TURN_ID)
    first = encode_control_frame(sequence=0, control=control)
    second = encode_pcm_frame(turn_id=TURN_ID, sequence=1, pcm=b"\x00\x00")
    decoder = FrameDecoder()

    assert decoder.feed(first[:31]) == ()
    assert decoder.feed(first[31:] + second) == (
        ControlFrame(turn_id=TURN_ID, sequence=0, control=control),
        PcmFrame(turn_id=TURN_ID, sequence=1, pcm=b"\x00\x00"),
    )


def test_control_envelope_has_closed_canonical_payload_shapes() -> None:
    receipt = complete_receipt()
    controls = (
        (PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL), SessionPayload),
        (PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL), SessionPayload),
        (PttControl.ptt_start(TURN_ID), EmptyPayload),
        (PttControl.ptt_submit(TURN_ID), EmptyPayload),
        (PttControl.heartbeat(TURN_ID), EmptyPayload),
        (PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT), StartPayload),
        (PttControl.capture_end(TURN_ID), EmptyPayload),
        (PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT), StartPayload),
        (PttControl.playback_end(TURN_ID), EmptyPayload),
        (PttControl.stop(TURN_ID), EmptyPayload),
        (PttControl.cancel(TURN_ID), EmptyPayload),
        (
            PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED),
            type(PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED).payload),
        ),
        (PttControl.safety_receipt(TURN_ID, receipt), SafetyPayload),
        (PttControl.safety_ack(TURN_ID, accepted=True), AckPayload),
        (
            PttControl.error(TURN_ID, PttErrorReason.PLAYBACK_FAILED),
            type(PttControl.error(TURN_ID, PttErrorReason.PLAYBACK_FAILED).payload),
        ),
    )

    assert {item.value for item in ControlKind} == {
        "session_open",
        "session_ready",
        "ptt_start",
        "ptt_submit",
        "heartbeat",
        "capture_start",
        "capture_end",
        "playback_start",
        "playback_end",
        "stop",
        "cancel",
        "abort",
        "safety_receipt",
        "safety_ack",
        "error",
    }
    for control, payload_type in controls:
        assert set(control.model_dump(mode="python")) == {"kind", "turn_id", "payload"}
        assert type(control.payload) is payload_type
        assert canonical_bytes(control) == canonical_bytes(control)


def test_all_public_protocol_enums_have_exact_closed_values() -> None:
    assert {item.value for item in FrameKind} == {1, 2}
    assert {item.value for item in PttInputMode} == {
        "reachy_local",
        "core_terminal_toggle",
    }
    assert {item.value for item in StreamDirection} == {
        "edge_to_core",
        "core_to_edge",
    }
    assert {item.value for item in GuardDisposition} == {"accepted", "late_discarded"}
    assert {item.value for item in PttStopSource} == {
        "supervisor_input",
        "core_abort",
        "peer_eof",
        "watchdog",
        "protocol_rejected",
    }
    assert {item.value for item in PttErrorReason} == {
        "protocol_rejected",
        "turn_cancelled",
        "capture_failed",
        "provider_failed",
        "playback_failed",
        "cleanup_incomplete",
        "peer_closed",
        "session_timeout",
    }
    assert {item.value for item in PttSessionOutcome} == {
        "completed",
        "cancelled",
        "peer_closed",
        "protocol_rejected",
        "capture_failed",
        "provider_failed",
        "playback_failed",
        "cleanup_incomplete",
        "session_timeout",
    }
    assert {item.value for item in FrameErrorCode} == {
        "closed",
        "feed_too_large",
        "too_many_frames",
        "invalid_prefix",
        "invalid_length",
        "invalid_control",
        "turn_mismatch",
        "truncated",
        "invalid_sequence",
        "invalid_direction",
        "invalid_order",
        "pcm_limit",
        "duration_limit",
        "rate_limit",
        "invalid_clock",
    }


def test_every_closed_control_kind_round_trips_through_canonical_wire_json() -> None:
    receipt = complete_receipt()
    controls = (
        PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL),
        PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL),
        PttControl.ptt_start(TURN_ID),
        PttControl.ptt_submit(TURN_ID),
        PttControl.heartbeat(TURN_ID),
        PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
        PttControl.capture_end(TURN_ID),
        PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
        PttControl.playback_end(TURN_ID),
        PttControl.stop(TURN_ID),
        PttControl.cancel(TURN_ID),
        PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED),
        PttControl.safety_receipt(TURN_ID, receipt),
        PttControl.safety_ack(TURN_ID, accepted=True),
        PttControl.error(TURN_ID, PttErrorReason.PLAYBACK_FAILED),
    )

    for sequence, control in enumerate(controls):
        assert FrameDecoder().feed(encode_control_frame(sequence=sequence, control=control)) == (
            ControlFrame(turn_id=TURN_ID, sequence=sequence, control=control),
        )


def test_disposable_poc_models_do_not_expand_frozen_root_exports_or_registry() -> None:
    assert not hasattr(tuntun_contracts, "PttControl")
    assert not hasattr(tuntun_contracts, "PttSafetyReceipt")
    assert all(
        not model.__module__.startswith("tuntun_contracts.poc")
        for model in registered_contract_models()
    )


def test_control_frame_value_rejects_a_mismatched_envelope_turn() -> None:
    other_turn = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    with pytest.raises(FrameProtocolError) as caught:
        ControlFrame(
            turn_id=TURN_ID,
            sequence=0,
            control=PttControl.heartbeat(other_turn),
        )

    assert caught.value.code is FrameErrorCode.TURN_MISMATCH


@pytest.mark.parametrize(
    ("kind", "payload_length"),
    (
        (FrameKind.CONTROL, 0),
        (FrameKind.CONTROL, 4_097),
        (FrameKind.PCM, 0),
        (FrameKind.PCM, 3),
        (FrameKind.PCM, 65_538),
    ),
)
def test_frame_header_value_rejects_lengths_invalid_for_its_kind(
    kind: FrameKind,
    payload_length: int,
) -> None:
    with pytest.raises(FrameProtocolError) as caught:
        FrameHeader(
            turn_id=TURN_ID,
            sequence=0,
            kind=kind,
            payload_length=payload_length,
        )

    assert caught.value.code is FrameErrorCode.INVALID_LENGTH


@pytest.mark.parametrize("pcm", (b"", b"\x00", b"\x00\x00" * 32_769))
def test_pcm_frame_value_rejects_empty_unaligned_or_oversized_pcm(pcm: bytes) -> None:
    with pytest.raises(FrameProtocolError) as caught:
        PcmFrame(turn_id=TURN_ID, sequence=0, pcm=pcm)

    assert caught.value.code is FrameErrorCode.INVALID_LENGTH


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (
        ("magic", b"NOPE", FrameErrorCode.INVALID_PREFIX),
        ("version", 2, FrameErrorCode.INVALID_PREFIX),
        ("kind", 3, FrameErrorCode.INVALID_PREFIX),
        ("flags", 1, FrameErrorCode.INVALID_PREFIX),
        ("declared_length", 0, FrameErrorCode.INVALID_LENGTH),
        ("declared_length", 4_097, FrameErrorCode.INVALID_LENGTH),
    ),
)
def test_decoder_rejects_each_bad_control_prefix_field(
    field: str,
    value: bytes | int,
    expected: FrameErrorCode,
) -> None:
    kwargs: dict[str, bytes | int] = {field: value}
    encoded = wire_control(b"{}", **kwargs)  # type: ignore[arg-type]
    decoder = FrameDecoder()

    with pytest.raises(FrameProtocolError) as caught:
        decoder.feed(encoded)

    assert caught.value.code is expected
    assert caught.value.__context__ is None
    with pytest.raises(FrameProtocolError) as closed:
        decoder.feed(b"")
    assert closed.value.code is FrameErrorCode.CLOSED


def test_oversized_control_is_rejected_from_the_prefix_before_body_arrives() -> None:
    decoder = FrameDecoder()

    with pytest.raises(FrameProtocolError) as caught:
        decoder.feed(wire_control(b"", declared_length=4_097))

    assert caught.value.code is FrameErrorCode.INVALID_LENGTH


@pytest.mark.parametrize(
    "body",
    (
        b"\xff",
        b"not-json",
        b'{"kind":"heartbeat","kind":"stop","payload":{},"turn_id":"12345678-1234-5678-1234-567812345678"}',
        b'{"payload":{},"kind":"heartbeat","turn_id":"12345678-1234-5678-1234-567812345678"}',
        b'{"kind":"heartbeat","payload":{},"turn_id":"12345678-1234-5678-1234-567812345678","extra":1}',
        b'{"kind":"heartbeat","payload":{"accepted":true},"turn_id":"12345678-1234-5678-1234-567812345678"}',
        b'{"kind":"unknown","payload":{},"turn_id":"12345678-1234-5678-1234-567812345678"}',
    ),
)
def test_decoder_rejects_hostile_or_noncanonical_control_json(body: bytes) -> None:
    decoder = FrameDecoder()

    with pytest.raises(FrameProtocolError) as caught:
        decoder.feed(wire_control(body))

    assert caught.value.code is FrameErrorCode.INVALID_CONTROL
    assert caught.value.__suppress_context__ is True
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_decoder_rejects_prefix_and_envelope_turn_mismatch() -> None:
    other_turn = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    body = canonical_bytes(PttControl.heartbeat(other_turn))

    with pytest.raises(FrameProtocolError) as caught:
        FrameDecoder().feed(wire_control(body))

    assert caught.value.code is FrameErrorCode.TURN_MISMATCH


def test_nested_receipt_turn_must_match_the_control_turn() -> None:
    other_turn = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    with pytest.raises(ValidationError):
        PttControl(
            kind=ControlKind.SAFETY_RECEIPT,
            turn_id=TURN_ID,
            payload=SafetyPayload(receipt=complete_receipt(turn_id=other_turn)),
        )


@pytest.mark.parametrize("pcm", (b"", b"\x00", b"\x00\x00" * 32_769))
def test_pcm_encoder_rejects_zero_unaligned_or_oversized_pcm(pcm: bytes) -> None:
    with pytest.raises(FrameProtocolError) as caught:
        encode_pcm_frame(turn_id=TURN_ID, sequence=0, pcm=pcm)

    assert caught.value.code is FrameErrorCode.INVALID_LENGTH


def test_decoder_empty_feed_and_clean_finish_then_rejects_reuse() -> None:
    decoder = FrameDecoder()

    assert decoder.feed(b"") == ()
    assert decoder.finish() is None
    with pytest.raises(FrameProtocolError) as caught:
        decoder.feed(b"")
    assert caught.value.code is FrameErrorCode.CLOSED
    with pytest.raises(FrameProtocolError) as second_finish:
        decoder.finish()
    assert second_finish.value.code is FrameErrorCode.CLOSED


def test_decoder_finish_rejects_a_truncated_frame_and_poison_reuse() -> None:
    decoder = FrameDecoder()
    decoder.feed(b"TTPT")

    with pytest.raises(FrameProtocolError) as caught:
        decoder.finish()

    assert caught.value.code is FrameErrorCode.TRUNCATED
    with pytest.raises(FrameProtocolError) as closed:
        decoder.feed(b"")
    assert closed.value.code is FrameErrorCode.CLOSED


def test_decoder_abort_clears_partial_input_is_idempotent_and_rejects_reuse() -> None:
    decoder = FrameDecoder()
    decoder.feed(b"TTPT")

    decoder.abort()
    decoder.abort()

    with pytest.raises(FrameProtocolError) as caught:
        decoder.feed(b"")
    assert caught.value.code is FrameErrorCode.CLOSED


def test_same_feed_valid_then_invalid_is_atomic_and_poisoned() -> None:
    valid = encode_control_frame(sequence=0, control=PttControl.heartbeat(TURN_ID))
    invalid = wire_control(b"{}", sequence=1, magic=b"NOPE")
    decoder = FrameDecoder()

    with pytest.raises(FrameProtocolError) as caught:
        decoder.feed(valid + invalid)

    assert caught.value.code is FrameErrorCode.INVALID_PREFIX
    with pytest.raises(FrameProtocolError) as closed:
        decoder.feed(valid)
    assert closed.value.code is FrameErrorCode.CLOSED


def test_decoder_rejects_a_feed_larger_than_65536_exact_bytes() -> None:
    decoder = FrameDecoder()

    with pytest.raises(FrameProtocolError) as caught:
        decoder.feed(b"x" * 65_537)

    assert caught.value.code is FrameErrorCode.FEED_TOO_LARGE


@pytest.mark.parametrize("not_bytes", (bytearray(b""), memoryview(b"")))
def test_decoder_requires_exact_bytes_feed(not_bytes: bytearray | memoryview) -> None:
    decoder = FrameDecoder()

    with pytest.raises(FrameProtocolError) as caught:
        decoder.feed(not_bytes)  # type: ignore[arg-type]

    assert caught.value.code is FrameErrorCode.INVALID_PREFIX
    with pytest.raises(FrameProtocolError) as closed:
        decoder.feed(b"")
    assert closed.value.code is FrameErrorCode.CLOSED


def test_decoder_rejects_65_coalesced_frames_without_returning_a_partial_tuple() -> None:
    encoded = b"".join(
        encode_control_frame(sequence=sequence, control=PttControl.heartbeat(TURN_ID))
        for sequence in range(65)
    )

    with pytest.raises(FrameProtocolError) as caught:
        FrameDecoder().feed(encoded)

    assert caught.value.code is FrameErrorCode.TOO_MANY_FRAMES


def test_representations_do_not_expose_pcm_or_parser_sentinels() -> None:
    secret = "DO_NOT_LOG_7f0b"
    frame = PcmFrame(turn_id=TURN_ID, sequence=4, pcm=secret.encode() + b"0")
    error = FrameProtocolError(FrameErrorCode.INVALID_CONTROL)

    assert secret not in repr(frame)
    assert secret not in repr(error)
    assert secret not in str(error)
    assert "pcm_bytes=16" in repr(frame)


def test_control_payload_rejects_wrong_closed_model_even_when_fields_overlap() -> None:
    with pytest.raises(ValidationError):
        PttControl(
            kind=ControlKind.SAFETY_ACK,
            turn_id=TURN_ID,
            payload=EmptyPayload(),
        )


def test_alternate_audio_format_remains_representable_but_not_transport_equal() -> None:
    alternate = AudioFormat(
        sample_format="float32_le",
        sample_rate_hz=48_000,
        channels=2,
        interleaved=True,
        channel_layout="stereo",
    )

    control = PttControl.capture_start(TURN_ID, alternate)

    assert isinstance(control.payload, StartPayload)
    assert control.payload.audio_format != TRANSPORT_AUDIO_FORMAT


def test_transport_audio_format_is_the_exact_frozen_wire_format() -> None:
    assert (
        AudioFormat(
            sample_format="s16le",
            sample_rate_hz=16_000,
            channels=1,
            interleaved=False,
            channel_layout="mono",
        )
        == TRANSPORT_AUDIO_FORMAT
    )


def test_reachy_local_duplex_happy_path_requires_receipt_and_ack() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    capture_start = control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT))

    guarded = accept(guard, StreamDirection.EDGE_TO_CORE, capture_start, 0.02)

    assert guarded == GuardedFrame(
        direction=StreamDirection.EDGE_TO_CORE,
        frame=capture_start,
        disposition=GuardDisposition.ACCEPTED,
    )
    assert guard.state == "capturing"
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.03)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.capture_end(TURN_ID)),
        0.04,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.05,
    )
    accept(guard, StreamDirection.CORE_TO_EDGE, pcm_frame(2), 0.06)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(3, PttControl.playback_end(TURN_ID)),
        0.07,
    )
    receipt = complete_receipt()
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(4, PttControl.safety_receipt(TURN_ID, receipt)),
        0.08,
    )
    assert guard.state == "receipt_received"
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(4, PttControl.safety_ack(TURN_ID, accepted=True)),
        0.09,
    )

    assert guard.state == "acknowledged"
    assert guard.finish() is PttSessionOutcome.COMPLETED


@pytest.mark.parametrize("submit_before_capture", (True, False))
def test_terminal_toggle_accepts_submit_before_or_after_capture_open(
    submit_before_capture: bool,
) -> None:
    guard = opened_guard(PttInputMode.CORE_TERMINAL_TOGGLE)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.ptt_start(TURN_ID)),
        0.02,
    )
    if submit_before_capture:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.ptt_submit(TURN_ID)),
            0.03,
        )
        assert guard.state == "arming_submit_pending"
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
            0.04,
        )
    else:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
            0.03,
        )
        assert guard.state == "capturing"
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.ptt_submit(TURN_ID)),
            0.04,
        )
    assert guard.state == "capture_submit_pending"
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.05)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.capture_end(TURN_ID)),
        0.06,
    )

    assert guard.state == "capture_closed"


def test_mode_echo_mismatch_poisons_the_guard() -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(0, PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL)),
        0.0,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(
                0,
                PttControl.session_ready(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            ),
            0.01,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER
    assert guard.state == "aborted"
    with pytest.raises(FrameProtocolError) as closed:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(1, PttControl.heartbeat(TURN_ID)),
            0.02,
        )
    assert closed.value.code is FrameErrorCode.CLOSED


def test_cleanup_crossing_still_rejects_a_wrong_mode_session_ready() -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(0, PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL)),
        0.0,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.01,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(
                0,
                PttControl.session_ready(TURN_ID, PttInputMode.CORE_TERMINAL_TOGGLE),
            ),
            0.02,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER
    assert guard.state == "aborted"


def test_cleanup_rejects_capture_start_when_session_open_never_arrived() -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(0, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.0,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(0, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
            0.01,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER
    assert guard.state == "aborted"


def test_cleanup_rejects_capture_start_before_late_session_ready() -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(0, PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL)),
        0.0,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.01,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(0, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
            0.02,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER
    assert guard.state == "aborted"


def test_cleanup_shadow_advances_valid_late_handshake_without_regressing_cleanup() -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(0, PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL)),
        0.0,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.01,
    )

    ready = accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(0, PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL)),
        0.02,
    )
    assert ready.disposition is GuardDisposition.LATE_DISCARDED
    assert guard.state == "cleanup_required"

    started = accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.03,
    )
    assert started.disposition is GuardDisposition.LATE_DISCARDED
    assert guard.state == "cleanup_required"
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.04)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.safety_receipt(TURN_ID, complete_receipt())),
        0.05,
    )
    assert guard.state == "receipt_received"

    ended = accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(4, PttControl.capture_end(TURN_ID)),
        0.06,
    )
    assert ended.disposition is GuardDisposition.LATE_DISCARDED
    assert guard.state == "receipt_received"


def test_cleanup_rejects_duplicate_session_ready_after_shadow_handshake() -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(0, PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL)),
        0.0,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.01,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(0, PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL)),
        0.02,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(1, PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL)),
            0.03,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER
    assert guard.state == "aborted"


@pytest.mark.parametrize(
    ("mode", "direction", "control"),
    (
        (
            PttInputMode.CORE_TERMINAL_TOGGLE,
            StreamDirection.CORE_TO_EDGE,
            PttControl.ptt_start(TURN_ID),
        ),
        (
            PttInputMode.REACHY_LOCAL,
            StreamDirection.EDGE_TO_CORE,
            PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
        ),
    ),
)
def test_input_or_capture_before_session_ready_is_rejected(
    mode: PttInputMode,
    direction: StreamDirection,
    control: PttControl,
) -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=mode)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(0, PttControl.session_open(TURN_ID, mode)),
        0.0,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            direction,
            control_frame(0 if direction is StreamDirection.EDGE_TO_CORE else 1, control),
            0.01,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER


def test_core_ptt_is_forbidden_in_reachy_local_mode() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(1, PttControl.ptt_start(TURN_ID)),
            0.02,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER


@pytest.mark.parametrize("duplicate", ("start", "submit_before_start", "submit"))
def test_terminal_duplicate_or_out_of_order_input_is_rejected(duplicate: str) -> None:
    guard = opened_guard(PttInputMode.CORE_TERMINAL_TOGGLE)
    if duplicate != "submit_before_start":
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(1, PttControl.ptt_start(TURN_ID)),
            0.02,
        )
    if duplicate == "submit":
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.ptt_submit(TURN_ID)),
            0.03,
        )
        sequence = 3
        now = 0.04
        control = PttControl.ptt_submit(TURN_ID)
    elif duplicate == "start":
        sequence = 2
        now = 0.03
        control = PttControl.ptt_start(TURN_ID)
    else:
        sequence = 1
        now = 0.02
        control = PttControl.ptt_submit(TURN_ID)

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(sequence, control),
            now,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER


def test_capture_end_requires_media_and_terminal_submit() -> None:
    local = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        local,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.02,
    )
    with pytest.raises(FrameProtocolError) as empty:
        accept(
            local,
            StreamDirection.EDGE_TO_CORE,
            control_frame(2, PttControl.capture_end(TURN_ID)),
            0.03,
        )
    assert empty.value.code is FrameErrorCode.INVALID_ORDER

    terminal = opened_guard(PttInputMode.CORE_TERMINAL_TOGGLE)
    accept(
        terminal,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.ptt_start(TURN_ID)),
        0.02,
    )
    accept(
        terminal,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.03,
    )
    accept(terminal, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.04)
    with pytest.raises(FrameProtocolError) as no_submit:
        accept(
            terminal,
            StreamDirection.EDGE_TO_CORE,
            control_frame(3, PttControl.capture_end(TURN_ID)),
            0.05,
        )
    assert no_submit.value.code is FrameErrorCode.INVALID_ORDER


def test_playback_requires_closed_capture_and_nonempty_media() -> None:
    early = opened_guard(PttInputMode.REACHY_LOCAL)
    with pytest.raises(FrameProtocolError) as before_capture:
        accept(
            early,
            StreamDirection.CORE_TO_EDGE,
            control_frame(1, PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
            0.02,
        )
    assert before_capture.value.code is FrameErrorCode.INVALID_ORDER

    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.02,
    )
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.03)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.capture_end(TURN_ID)),
        0.04,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.05,
    )
    with pytest.raises(FrameProtocolError) as empty_playback:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.playback_end(TURN_ID)),
            0.06,
        )
    assert empty_playback.value.code is FrameErrorCode.INVALID_ORDER


def test_media_start_requires_exact_transport_format() -> None:
    alternate = AudioFormat(
        sample_format="float32_le",
        sample_rate_hz=48_000,
        channels=2,
        interleaved=True,
        channel_layout="stereo",
    )
    guard = opened_guard(PttInputMode.REACHY_LOCAL)

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(1, PttControl.capture_start(TURN_ID, alternate)),
            0.02,
        )

    assert caught.value.code is FrameErrorCode.INVALID_CONTROL


def test_cleanup_latches_monotonically_and_late_frames_consume_sequences() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.02,
    )
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.03)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.stop(TURN_ID)),
        0.04,
    )
    assert guard.state == "cleanup_required"
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.05,
    )
    late_pcm = accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(4), 0.06)
    late_heartbeat = accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(2, PttControl.heartbeat(TURN_ID)),
        0.07,
    )
    assert late_pcm.disposition is GuardDisposition.LATE_DISCARDED
    assert late_heartbeat.disposition is GuardDisposition.LATE_DISCARDED
    assert guard.state == "cleanup_required"

    receipt = complete_receipt()
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(5, PttControl.safety_receipt(TURN_ID, receipt)),
        0.08,
    )
    assert guard.state == "receipt_received"
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(3, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.09,
    )
    capture_end_crossing = accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(6, PttControl.capture_end(TURN_ID)),
        0.10,
    )
    assert capture_end_crossing.disposition is GuardDisposition.LATE_DISCARDED
    assert guard.state == "receipt_received"
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(4, PttControl.safety_ack(TURN_ID, accepted=True)),
        0.11,
    )

    assert guard.finish() is PttSessionOutcome.CANCELLED


def test_same_direction_repeated_cleanup_preserves_the_first_reason() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )

    repeated = accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(2, PttControl.error(TURN_ID, PttErrorReason.PLAYBACK_FAILED)),
        0.03,
    )

    assert repeated.disposition is GuardDisposition.ACCEPTED
    assert guard.state == "cleanup_required"
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.safety_receipt(TURN_ID, complete_receipt())),
        0.04,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(3, PttControl.safety_ack(TURN_ID, accepted=True)),
        0.05,
    )
    assert guard.finish() is PttSessionOutcome.PROVIDER_FAILED


def test_edge_stop_racing_terminal_submit_discards_the_valid_submit() -> None:
    guard = opened_guard(PttInputMode.CORE_TERMINAL_TOGGLE)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.ptt_start(TURN_ID)),
        0.02,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.03,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(2, PttControl.stop(TURN_ID)),
        0.04,
    )

    crossing = accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(2, PttControl.ptt_submit(TURN_ID)),
        0.05,
    )

    assert crossing.disposition is GuardDisposition.LATE_DISCARDED
    assert guard.state == "cleanup_required"


def test_edge_stop_racing_playback_discards_bounded_playback_pcm() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.02,
    )
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.03)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.capture_end(TURN_ID)),
        0.04,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.05,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(4, PttControl.stop(TURN_ID)),
        0.06,
    )

    crossing = accept(guard, StreamDirection.CORE_TO_EDGE, pcm_frame(2), 0.07)

    assert crossing.disposition is GuardDisposition.LATE_DISCARDED
    assert guard.state == "cleanup_required"


def test_core_abort_racing_capture_start_pcm_and_end_discards_valid_crossings() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )

    start = accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.03,
    )
    pcm = accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.04)
    end = accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.capture_end(TURN_ID)),
        0.05,
    )

    assert {start.disposition, pcm.disposition, end.disposition} == {
        GuardDisposition.LATE_DISCARDED
    }
    assert guard.state == "cleanup_required"


@pytest.mark.parametrize("heartbeat_after_receipt", (False, True))
def test_heartbeat_receipt_crossing_is_late_discarded_in_both_orders(
    heartbeat_after_receipt: bool,
) -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )
    if not heartbeat_after_receipt:
        heartbeat = accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.heartbeat(TURN_ID)),
            0.03,
        )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.safety_receipt(TURN_ID, complete_receipt())),
        0.04,
    )
    if heartbeat_after_receipt:
        heartbeat = accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.heartbeat(TURN_ID)),
            0.05,
        )

    assert heartbeat.disposition is GuardDisposition.LATE_DISCARDED
    assert guard.state == "receipt_received"
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(3, PttControl.safety_ack(TURN_ID, accepted=True)),
        0.06,
    )
    assert guard.finish() is PttSessionOutcome.PROVIDER_FAILED


def test_abort_receipt_crossing_records_the_first_failure_outcome() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.safety_receipt(TURN_ID, complete_receipt())),
        0.03,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(2, PttControl.safety_ack(TURN_ID, accepted=True)),
        0.04,
    )

    assert guard.finish() is PttSessionOutcome.PROVIDER_FAILED


def test_receipt_abort_crossing_records_the_first_cleanup_outcome() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.02,
    )
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.03)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.capture_end(TURN_ID)),
        0.04,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.05,
    )
    accept(guard, StreamDirection.CORE_TO_EDGE, pcm_frame(2), 0.06)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(3, PttControl.playback_end(TURN_ID)),
        0.07,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(4, PttControl.safety_receipt(TURN_ID, complete_receipt())),
        0.08,
    )

    repeated = accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(4, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.09,
    )

    assert repeated.disposition is GuardDisposition.ACCEPTED
    assert guard.state == "receipt_received"
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(5, PttControl.safety_ack(TURN_ID, accepted=True)),
        0.10,
    )
    assert guard.finish() is PttSessionOutcome.PROVIDER_FAILED


def test_cleanup_rejects_playback_start_without_completed_capture() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
            0.03,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER


def test_cleanup_rejects_terminal_capture_start_without_ptt_start() -> None:
    guard = opened_guard(PttInputMode.CORE_TERMINAL_TOGGLE)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
            0.03,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER


def test_false_receipt_and_matching_false_ack_close_as_cleanup_incomplete() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(
            1,
            PttControl.safety_receipt(TURN_ID, complete_receipt(complete=False)),
        ),
        0.03,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(2, PttControl.safety_ack(TURN_ID, accepted=False)),
        0.04,
    )

    assert guard.state == "acknowledged"
    assert guard.finish() is PttSessionOutcome.CLEANUP_INCOMPLETE


def test_negative_ack_conservatively_rejects_a_complete_receipt() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.safety_receipt(TURN_ID, complete_receipt())),
        0.03,
    )

    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(2, PttControl.safety_ack(TURN_ID, accepted=False)),
        0.04,
    )

    assert guard.state == "acknowledged"
    assert guard.finish() is PttSessionOutcome.CLEANUP_INCOMPLETE


def test_positive_ack_rejects_an_incomplete_receipt() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(
            1,
            PttControl.safety_receipt(TURN_ID, complete_receipt(complete=False)),
        ),
        0.03,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.safety_ack(TURN_ID, accepted=True)),
            0.04,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER


@pytest.mark.parametrize("fault", ("turn", "sequence", "direction"))
def test_cleanup_still_rejects_wrong_turn_sequence_or_direction(fault: str) -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.02,
    )
    direction = StreamDirection.CORE_TO_EDGE
    frame: ControlFrame
    if fault == "turn":
        other_turn = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        frame = ControlFrame(
            turn_id=other_turn,
            sequence=2,
            control=PttControl.heartbeat(other_turn),
        )
    elif fault == "sequence":
        frame = control_frame(3, PttControl.heartbeat(TURN_ID))
    else:
        direction = StreamDirection.EDGE_TO_CORE
        frame = control_frame(1, PttControl.heartbeat(TURN_ID))

    with pytest.raises(FrameProtocolError) as caught:
        accept(guard, direction, frame, 0.03)

    assert (
        caught.value.code
        is {
            "turn": FrameErrorCode.TURN_MISMATCH,
            "sequence": FrameErrorCode.INVALID_SEQUENCE,
            "direction": FrameErrorCode.INVALID_DIRECTION,
        }[fault]
    )
    assert guard.state == "aborted"


def test_post_ack_input_and_premature_finish_are_rejected() -> None:
    premature = opened_guard(PttInputMode.REACHY_LOCAL)
    with pytest.raises(FrameProtocolError) as early:
        premature.finish()
    assert early.value.code is FrameErrorCode.INVALID_ORDER

    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.TURN_CANCELLED)),
        0.02,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.safety_receipt(TURN_ID, complete_receipt())),
        0.03,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(2, PttControl.safety_ack(TURN_ID, accepted=True)),
        0.04,
    )
    with pytest.raises(FrameProtocolError) as post_ack:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(3, PttControl.heartbeat(TURN_ID)),
            0.05,
        )
    assert post_ack.value.code is FrameErrorCode.INVALID_ORDER


def test_post_ack_cleanup_request_cannot_regress_the_monotonic_state() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.TURN_CANCELLED)),
        0.02,
    )
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.safety_receipt(TURN_ID, complete_receipt())),
        0.03,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(2, PttControl.safety_ack(TURN_ID, accepted=True)),
        0.04,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(3, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
            0.05,
        )

    assert caught.value.code is FrameErrorCode.INVALID_ORDER
    assert guard.state == "aborted"


def guard_at_state(state: str) -> PttDuplexGuard:
    if state == "wait_session_open":
        return PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    if state == "wait_session_ready":
        guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(
                0,
                PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL),
            ),
            0.0,
        )
        return guard
    if state in {"arming", "arming_submit_pending", "capture_submit_pending"}:
        guard = opened_guard(PttInputMode.CORE_TERMINAL_TOGGLE)
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(1, PttControl.ptt_start(TURN_ID)),
            0.02,
        )
        if state == "arming":
            return guard
        if state == "arming_submit_pending":
            accept(
                guard,
                StreamDirection.CORE_TO_EDGE,
                control_frame(2, PttControl.ptt_submit(TURN_ID)),
                0.03,
            )
            return guard
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
            0.03,
        )
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.ptt_submit(TURN_ID)),
            0.04,
        )
        return guard

    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    if state == "ready":
        return guard
    if state in {"cleanup_required", "receipt_received", "acknowledged"}:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
            0.02,
        )
        if state == "cleanup_required":
            return guard
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(1, PttControl.safety_receipt(TURN_ID, complete_receipt())),
            0.03,
        )
        if state == "receipt_received":
            return guard
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(2, PttControl.safety_ack(TURN_ID, accepted=True)),
            0.04,
        )
        return guard
    if state == "aborted":
        guard.abort()
        return guard

    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.02,
    )
    if state == "capturing":
        return guard
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.03)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.capture_end(TURN_ID)),
        0.04,
    )
    if state == "capture_closed":
        return guard
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.05,
    )
    if state == "playing":
        return guard
    accept(guard, StreamDirection.CORE_TO_EDGE, pcm_frame(2), 0.06)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(3, PttControl.playback_end(TURN_ID)),
        0.07,
    )
    return guard


@pytest.mark.parametrize(
    "state",
    (
        "wait_session_open",
        "wait_session_ready",
        "ready",
        "arming",
        "arming_submit_pending",
        "capturing",
        "capture_submit_pending",
        "capture_closed",
        "playing",
        "playback_closed",
        "cleanup_required",
        "receipt_received",
        "acknowledged",
        "aborted",
    ),
)
def test_guard_abort_is_idempotent_from_every_state_and_closes_admission(state: str) -> None:
    guard = guard_at_state(state)
    assert guard.state == state

    guard.abort()
    guard.abort()

    assert guard.state == "aborted"
    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(0, PttControl.heartbeat(TURN_ID)),
            1.0,
        )
    assert caught.value.code is FrameErrorCode.CLOSED


def test_sequences_are_independent_exact_and_never_accept_bool() -> None:
    wrong_edge = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    accept(
        wrong_edge,
        StreamDirection.CORE_TO_EDGE,
        control_frame(0, PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL)),
        0.0,
    )
    with pytest.raises(FrameProtocolError) as skipped:
        accept(
            wrong_edge,
            StreamDirection.EDGE_TO_CORE,
            control_frame(1, PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL)),
            0.01,
        )
    assert skipped.value.code is FrameErrorCode.INVALID_SEQUENCE

    with pytest.raises(FrameProtocolError) as boolean:
        ControlFrame(
            turn_id=TURN_ID,
            sequence=True,  # type: ignore[arg-type]
            control=PttControl.heartbeat(TURN_ID),
        )
    assert boolean.value.code is FrameErrorCode.INVALID_SEQUENCE


@pytest.mark.parametrize("now", (True, float("nan"), float("inf"), float("-inf")))
def test_guard_rejects_boolean_or_nonfinite_clock(now: float) -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(0, PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL)),
            now,
        )

    assert caught.value.code is FrameErrorCode.INVALID_CLOCK


def test_guard_rejects_decreasing_clock() -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(0, PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL)),
        2.0,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(0, PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL)),
            1.0,
        )

    assert caught.value.code is FrameErrorCode.INVALID_CLOCK


@pytest.mark.parametrize(
    "now",
    (2**53 + 1, 10**10_000),
    ids=("precision_alias", "float_overflow"),
)
def test_guard_rejects_an_integer_clock_not_exactly_representable_as_float(now: int) -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(0, PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL)),
            now,
        )

    assert caught.value.code is FrameErrorCode.INVALID_CLOCK
    assert guard.state == "aborted"


def test_pcm_frame_limit_is_6400_bytes() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.02,
    )

    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2, size=6_400), 0.03)
    with pytest.raises(FrameProtocolError) as caught:
        accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(3, size=6_402), 0.04)

    assert caught.value.code is FrameErrorCode.PCM_LIMIT


def test_rolling_rate_allows_50_frames_but_rejects_51_in_closed_second() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL, start_at=-0.2)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        -0.1,
    )
    for index in range(50):
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            pcm_frame(index + 2),
            index * 0.02,
        )

    with pytest.raises(FrameProtocolError) as caught:
        accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(52), 1.0)

    assert caught.value.code is FrameErrorCode.RATE_LIMIT


def test_rolling_rate_releases_a_frame_only_after_one_second() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL, start_at=-0.2)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        -0.1,
    )
    for index in range(50):
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            pcm_frame(index + 2),
            index * 0.02,
        )

    result = accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(52), 1.000_001)

    assert result.disposition is GuardDisposition.ACCEPTED


def test_sample_duration_allows_exactly_90_seconds_then_rejects_more() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL, start_at=-0.2)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        -0.1,
    )
    for index in range(450):
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            pcm_frame(index + 2, size=6_400),
            index * 0.021,
        )

    with pytest.raises(FrameProtocolError) as caught:
        accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(452), 9.46)

    assert caught.value.code is FrameErrorCode.DURATION_LIMIT


def test_exactly_90_seconds_of_samples_can_close_capture() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL, start_at=-0.2)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        -0.1,
    )
    for index in range(450):
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            pcm_frame(index + 2, size=6_400),
            index * 0.021,
        )

    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(452, PttControl.capture_end(TURN_ID)),
        9.46,
    )

    assert guard.state == "capture_closed"


def test_media_wall_deadline_is_not_extended_by_heartbeat() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL, start_at=-1.0)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.0,
    )
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.1)
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.heartbeat(TURN_ID)),
        89.9,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            control_frame(3, PttControl.capture_end(TURN_ID)),
            90.000_001,
        )

    assert caught.value.code is FrameErrorCode.DURATION_LIMIT


def test_overdue_cleanup_control_remains_admissible() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL, start_at=-1.0)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.0,
    )
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(2), 0.1)

    result = accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(3, PttControl.stop(TURN_ID)),
        100.0,
    )

    assert result.disposition is GuardDisposition.ACCEPTED
    assert guard.state == "cleanup_required"


def test_late_discarded_media_still_enforces_frame_limit() -> None:
    guard = opened_guard(PttInputMode.REACHY_LOCAL)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.02,
    )
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(1, PttControl.abort(TURN_ID, PttErrorReason.PROVIDER_FAILED)),
        0.03,
    )

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            pcm_frame(2, size=6_402),
            0.04,
        )

    assert caught.value.code is FrameErrorCode.PCM_LIMIT


def test_direction_byte_limit_is_enforced_independently_of_sample_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(framing, "MAX_MEDIA_SAMPLES", 10_000_000)
    guard = opened_guard(PttInputMode.REACHY_LOCAL, start_at=-1.0)
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)),
        0.0,
    )
    sequence = 2
    total = 0
    now = 0.0
    while total < 8_388_608:
        size = min(6_400, 8_388_608 - total)
        now += 0.021
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            pcm_frame(sequence, size=size),
            now,
        )
        total += size
        sequence += 1

    with pytest.raises(FrameProtocolError) as caught:
        accept(
            guard,
            StreamDirection.EDGE_TO_CORE,
            pcm_frame(sequence),
            now + 0.021,
        )

    assert caught.value.code is FrameErrorCode.PCM_LIMIT


@given(
    magic=st.binary(min_size=4, max_size=4),
    version=st.integers(min_value=0, max_value=255),
    raw_kind=st.integers(min_value=0, max_value=255),
    flags=st.integers(min_value=0, max_value=65_535),
    sequence=st.integers(min_value=0, max_value=2**32 - 1),
    payload_length=st.integers(min_value=0, max_value=2**32 - 1),
    raw_turn=st.binary(min_size=16, max_size=16),
)
@settings(max_examples=100, deadline=None)
def test_decoder_property_generated_header_fields_fail_closed_and_poison(
    magic: bytes,
    version: int,
    raw_kind: int,
    flags: int,
    sequence: int,
    payload_length: int,
    raw_turn: bytes,
) -> None:
    decoder = FrameDecoder()
    header = PREFIX.pack(
        magic,
        version,
        raw_kind,
        flags,
        sequence,
        payload_length,
        raw_turn,
    )

    with pytest.raises(FrameProtocolError) as caught:
        decoder.feed(header)
        decoder.finish()

    assert caught.value.code in FrameErrorCode
    with pytest.raises(FrameProtocolError) as closed:
        decoder.feed(b"")
    assert closed.value.code is FrameErrorCode.CLOSED


@given(
    mode=st.sampled_from(tuple(PttInputMode)),
    submit_before_capture=st.booleans(),
)
@settings(max_examples=12, deadline=None)
def test_guard_property_valid_paths_cover_both_input_modes(
    mode: PttInputMode,
    submit_before_capture: bool,
) -> None:
    guard = opened_guard(mode)
    core_sequence = 1
    edge_sequence = 1
    now = 0.02
    if mode is PttInputMode.CORE_TERMINAL_TOGGLE:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(core_sequence, PttControl.ptt_start(TURN_ID)),
            now,
        )
        core_sequence += 1
        now += 0.01
        if submit_before_capture:
            accept(
                guard,
                StreamDirection.CORE_TO_EDGE,
                control_frame(core_sequence, PttControl.ptt_submit(TURN_ID)),
                now,
            )
            core_sequence += 1
            now += 0.01
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(
            edge_sequence,
            PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
        ),
        now,
    )
    edge_sequence += 1
    now += 0.01
    if mode is PttInputMode.CORE_TERMINAL_TOGGLE and not submit_before_capture:
        accept(
            guard,
            StreamDirection.CORE_TO_EDGE,
            control_frame(core_sequence, PttControl.ptt_submit(TURN_ID)),
            now,
        )
        core_sequence += 1
        now += 0.01
    accept(guard, StreamDirection.EDGE_TO_CORE, pcm_frame(edge_sequence), now)
    edge_sequence += 1
    now += 0.01
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(edge_sequence, PttControl.capture_end(TURN_ID)),
        now,
    )
    edge_sequence += 1
    now += 0.01
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(
            core_sequence,
            PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT),
        ),
        now,
    )
    core_sequence += 1
    now += 0.01
    accept(guard, StreamDirection.CORE_TO_EDGE, pcm_frame(core_sequence), now)
    core_sequence += 1
    now += 0.01
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(core_sequence, PttControl.playback_end(TURN_ID)),
        now,
    )
    core_sequence += 1
    now += 0.01
    accept(
        guard,
        StreamDirection.EDGE_TO_CORE,
        control_frame(
            edge_sequence,
            PttControl.safety_receipt(TURN_ID, complete_receipt()),
        ),
        now,
    )
    now += 0.01
    accept(
        guard,
        StreamDirection.CORE_TO_EDGE,
        control_frame(core_sequence, PttControl.safety_ack(TURN_ID, accepted=True)),
        now,
    )

    assert guard.finish() is PttSessionOutcome.COMPLETED


@given(
    mode=st.sampled_from(tuple(PttInputMode)),
    invalid_case=st.sampled_from(("duplicate_ready", "premature_playback", "wrong_input_owner")),
)
@settings(max_examples=12, deadline=None)
def test_guard_property_invalid_transitions_poison_both_input_modes(
    mode: PttInputMode,
    invalid_case: str,
) -> None:
    guard = opened_guard(mode)
    if invalid_case == "duplicate_ready":
        direction = StreamDirection.EDGE_TO_CORE
        frame = control_frame(1, PttControl.session_ready(TURN_ID, mode))
    elif invalid_case == "premature_playback":
        direction = StreamDirection.CORE_TO_EDGE
        frame = control_frame(1, PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT))
    elif mode is PttInputMode.REACHY_LOCAL:
        direction = StreamDirection.CORE_TO_EDGE
        frame = control_frame(1, PttControl.ptt_start(TURN_ID))
    else:
        direction = StreamDirection.EDGE_TO_CORE
        frame = control_frame(1, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT))

    with pytest.raises(FrameProtocolError) as caught:
        accept(guard, direction, frame, 0.02)

    assert caught.value.code is FrameErrorCode.INVALID_ORDER
    with pytest.raises(FrameProtocolError) as closed:
        accept(guard, direction, frame, 0.03)
    assert closed.value.code is FrameErrorCode.CLOSED


@given(
    pcm=st.binary(min_size=1, max_size=3_200).map(lambda value: value + b"\x00" * (len(value) % 2)),
    cuts=st.lists(st.integers(min_value=1, max_value=512), min_size=0, max_size=20),
)
@settings(max_examples=40, deadline=None)
def test_decoder_property_arbitrary_fragmentation_round_trips(
    pcm: bytes,
    cuts: list[int],
) -> None:
    if not pcm:
        pcm = b"\x00\x00"
    encoded = encode_pcm_frame(turn_id=TURN_ID, sequence=17, pcm=pcm)
    decoder = FrameDecoder()
    offset = 0
    frames: list[ControlFrame | PcmFrame] = []
    for width in cuts:
        frames.extend(decoder.feed(encoded[offset : offset + width]))
        offset += width
        if offset >= len(encoded):
            break
    if offset < len(encoded):
        frames.extend(decoder.feed(encoded[offset:]))

    assert frames == [PcmFrame(turn_id=TURN_ID, sequence=17, pcm=pcm)]
    decoder.finish()


@given(raw=st.binary(max_size=256))
@settings(max_examples=80, deadline=None)
def test_decoder_property_arbitrary_bytes_fail_closed_without_uncontrolled_error(
    raw: bytes,
) -> None:
    decoder = FrameDecoder()
    try:
        decoder.feed(raw)
        decoder.finish()
    except FrameProtocolError as error:
        assert error.code in FrameErrorCode
        decoder.abort()


@given(
    sequence=st.integers(min_value=1, max_value=2**32 - 1),
    choose_other_turn=st.booleans(),
)
@settings(max_examples=30, deadline=None)
def test_guard_property_sequence_or_turn_substitution_poisons_once(
    sequence: int,
    choose_other_turn: bool,
) -> None:
    guard = PttDuplexGuard(turn_id=TURN_ID, input_mode=PttInputMode.REACHY_LOCAL)
    frame_turn = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") if choose_other_turn else TURN_ID
    frame = ControlFrame(
        turn_id=frame_turn,
        sequence=sequence,
        control=PttControl.session_open(frame_turn, PttInputMode.REACHY_LOCAL),
    )

    with pytest.raises(FrameProtocolError) as caught:
        guard.accept(StreamDirection.CORE_TO_EDGE, frame, now=0.0)

    assert caught.value.code in {FrameErrorCode.TURN_MISMATCH, FrameErrorCode.INVALID_SEQUENCE}
    with pytest.raises(FrameProtocolError) as closed:
        guard.accept(StreamDirection.CORE_TO_EDGE, frame, now=0.1)
    assert closed.value.code is FrameErrorCode.CLOSED


class _ReachyLocalGuardMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.guard = PttDuplexGuard(
            turn_id=TURN_ID,
            input_mode=PttInputMode.REACHY_LOCAL,
        )
        self.model_state = "wait_session_open"
        self.core_sequence = 0
        self.edge_sequence = 0
        self.now = 0.0
        self.capture_has_pcm = False
        self.playback_has_pcm = False

    def _core(self, control: PttControl) -> None:
        self.guard.accept(
            StreamDirection.CORE_TO_EDGE,
            control_frame(self.core_sequence, control),
            now=self.now,
        )
        self.core_sequence += 1
        self.now += 0.01

    def _edge(self, frame: ControlFrame | PcmFrame) -> None:
        if isinstance(frame, ControlFrame):
            frame = control_frame(self.edge_sequence, frame.control)
        else:
            frame = pcm_frame(self.edge_sequence, size=len(frame.pcm))
        self.guard.accept(StreamDirection.EDGE_TO_CORE, frame, now=self.now)
        self.edge_sequence += 1
        self.now += 0.01

    @rule()
    def observe_without_mutation(self) -> None:
        assert self.guard.state == self.model_state

    @precondition(lambda self: self.model_state == "wait_session_open")
    @rule()
    def open_session(self) -> None:
        self._core(PttControl.session_open(TURN_ID, PttInputMode.REACHY_LOCAL))
        self.model_state = "wait_session_ready"

    @precondition(lambda self: self.model_state == "wait_session_ready")
    @rule()
    def ready_session(self) -> None:
        self._edge(control_frame(0, PttControl.session_ready(TURN_ID, PttInputMode.REACHY_LOCAL)))
        self.model_state = "ready"

    @precondition(lambda self: self.model_state == "ready")
    @rule()
    def start_capture(self) -> None:
        self._edge(control_frame(0, PttControl.capture_start(TURN_ID, TRANSPORT_AUDIO_FORMAT)))
        self.model_state = "capturing"

    @precondition(lambda self: self.model_state == "capturing")
    @rule()
    def capture_pcm(self) -> None:
        self._edge(pcm_frame(0))
        self.capture_has_pcm = True

    @precondition(lambda self: self.model_state == "capturing" and self.capture_has_pcm)
    @rule()
    def close_capture(self) -> None:
        self._edge(control_frame(0, PttControl.capture_end(TURN_ID)))
        self.model_state = "capture_closed"

    @precondition(lambda self: self.model_state == "capture_closed")
    @rule()
    def start_playback(self) -> None:
        self._core(PttControl.playback_start(TURN_ID, TRANSPORT_AUDIO_FORMAT))
        self.model_state = "playing"

    @precondition(lambda self: self.model_state == "playing")
    @rule()
    def playback_pcm(self) -> None:
        frame = pcm_frame(self.core_sequence)
        self.guard.accept(StreamDirection.CORE_TO_EDGE, frame, now=self.now)
        self.core_sequence += 1
        self.now += 0.01
        self.playback_has_pcm = True

    @precondition(lambda self: self.model_state == "playing" and self.playback_has_pcm)
    @rule()
    def close_playback(self) -> None:
        self._core(PttControl.playback_end(TURN_ID))
        self.model_state = "playback_closed"

    @precondition(lambda self: self.model_state == "playback_closed")
    @rule()
    def normal_receipt(self) -> None:
        self._edge(control_frame(0, PttControl.safety_receipt(TURN_ID, complete_receipt())))
        self.model_state = "receipt_received"

    @precondition(
        lambda self: (
            self.model_state
            not in {"cleanup_required", "receipt_received", "acknowledged", "aborted"}
        )
    )
    @rule()
    def abort_to_cleanup(self) -> None:
        self._core(PttControl.abort(TURN_ID, PttErrorReason.TURN_CANCELLED))
        self.model_state = "cleanup_required"

    @precondition(lambda self: self.model_state == "cleanup_required")
    @rule()
    def cleanup_receipt(self) -> None:
        self._edge(control_frame(0, PttControl.safety_receipt(TURN_ID, complete_receipt())))
        self.model_state = "receipt_received"

    @precondition(lambda self: self.model_state == "receipt_received")
    @rule()
    def acknowledge(self) -> None:
        self._core(PttControl.safety_ack(TURN_ID, accepted=True))
        self.model_state = "acknowledged"

    @invariant()
    def model_matches_guard(self) -> None:
        assert self.guard.state == self.model_state


TestReachyLocalGuardMachine = _ReachyLocalGuardMachine.TestCase
TestReachyLocalGuardMachine.settings = settings(
    max_examples=20,
    stateful_step_count=25,
    deadline=None,
)
