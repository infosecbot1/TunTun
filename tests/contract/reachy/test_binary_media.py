from __future__ import annotations

import struct

import pytest
from tuntun_contracts.reachy_media import (
    MAX_AUDIO_PAYLOAD,
    MAX_CAMERA_PAYLOAD,
    MAX_HEADER,
    PREFIX,
    parse_prefix,
)


def _prefix(
    *,
    magic: bytes = b"TTN1",
    media_type: int = 1,
    flags: int = 0,
    header_len: int = 0,
    payload_len: int = 0,
) -> bytes:
    return struct.pack(">4sBBHI", magic, media_type, flags, header_len, payload_len)


def test_parse_prefix_accepts_exact_audio_and_camera_boundaries() -> None:
    assert PREFIX.size == 12
    assert parse_prefix(
        _prefix(media_type=1, header_len=MAX_HEADER, payload_len=MAX_AUDIO_PAYLOAD)
    ) == (1, 0, MAX_HEADER, MAX_AUDIO_PAYLOAD)
    assert parse_prefix(
        _prefix(media_type=2, header_len=MAX_HEADER, payload_len=MAX_CAMERA_PAYLOAD)
    ) == (2, 0, MAX_HEADER, MAX_CAMERA_PAYLOAD)


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        (b"", "invalid media prefix length"),
        (_prefix()[:-1], "invalid media prefix length"),
        (_prefix() + b"x", "invalid media prefix length"),
        (bytearray(_prefix()), "media prefix must be bytes"),
        (memoryview(_prefix()), "media prefix must be bytes"),
        (True, "media prefix must be bytes"),
    ),
)
def test_parse_prefix_rejects_non_exact_input_before_unpack(
    raw: object,
    message: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        parse_prefix(raw)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        (_prefix(magic=b"TNT1"), "invalid media magic"),
        (_prefix(media_type=0), "unsupported media type"),
        (_prefix(media_type=3), "unsupported media type"),
        (_prefix(media_type=255), "unsupported media type"),
        (_prefix(flags=1), "media flags must be zero"),
        (_prefix(header_len=MAX_HEADER + 1), "media header too large"),
        (
            _prefix(media_type=1, payload_len=MAX_AUDIO_PAYLOAD + 1),
            "media payload too large",
        ),
        (
            _prefix(media_type=2, payload_len=MAX_CAMERA_PAYLOAD + 1),
            "media payload too large",
        ),
    ),
)
def test_parse_prefix_rejects_unknown_types_flags_and_oversized_lengths(
    raw: bytes,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        parse_prefix(raw)


def test_edge_media_reexports_shared_parser_and_constants() -> None:
    from tuntun_edge.transport.media import (
        MAX_CAMERA_PAYLOAD as EDGE_MAX_CAMERA_PAYLOAD,
    )
    from tuntun_edge.transport.media import (
        MAX_HEADER as EDGE_MAX_HEADER,
    )
    from tuntun_edge.transport.media import (
        parse_prefix as edge_parse_prefix,
    )

    assert EDGE_MAX_CAMERA_PAYLOAD == MAX_CAMERA_PAYLOAD
    assert EDGE_MAX_HEADER == MAX_HEADER
    assert edge_parse_prefix(_prefix(media_type=2, payload_len=1)) == (2, 0, 0, 1)


def test_parse_prefix_never_requires_payload_allocation_for_huge_declared_lengths() -> None:
    def build_huge_camera_prefix() -> bytes:
        return _prefix(
            media_type=2,
            payload_len=2**32 - 1,
        )

    with pytest.raises(ValueError, match="media payload too large"):
        parse_prefix(build_huge_camera_prefix())
