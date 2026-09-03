from __future__ import annotations

import asyncio

import pytest
from tuntun_edge.audio.buffer import MAX_TURN_BYTES, AudioRing


def test_ring_keeps_newest_five_seconds_with_partial_trimming() -> None:
    ring = AudioRing(bytes_per_second=32_000, pre_roll_seconds=5, turn_limit_bytes=MAX_TURN_BYTES)

    ring.append_pre_wake(b"a" * 96_000)
    ring.append_pre_wake(b"b" * 96_000)

    assert ring.pre_wake_size == 160_000
    assert ring.snapshot_pre_wake() == (b"a" * 64_000) + (b"b" * 96_000)

    ring.append_pre_wake(b"c" * 192_000)

    assert ring.pre_wake_size == 160_000
    assert ring.snapshot_pre_wake() == b"c" * 160_000


def test_ring_rejects_invalid_exact_int_bounds() -> None:
    invalid_args = (
        {"bytes_per_second": True, "pre_roll_seconds": 5, "turn_limit_bytes": MAX_TURN_BYTES},
        {"bytes_per_second": 32_000, "pre_roll_seconds": 2, "turn_limit_bytes": MAX_TURN_BYTES},
        {"bytes_per_second": 32_000, "pre_roll_seconds": 6, "turn_limit_bytes": MAX_TURN_BYTES},
        {"bytes_per_second": 32_000, "pre_roll_seconds": 5, "turn_limit_bytes": True},
        {"bytes_per_second": 32_000, "pre_roll_seconds": 5, "turn_limit_bytes": MAX_TURN_BYTES + 1},
    )

    for kwargs in invalid_args:
        with pytest.raises((TypeError, ValueError)):
            AudioRing(**kwargs)


def test_ring_rejects_post_wake_over_cap_before_mutation() -> None:
    ring = AudioRing(bytes_per_second=32_000, pre_roll_seconds=3, turn_limit_bytes=8)
    ring.begin_turn()
    ring.append_post_wake(b"abcd")

    with pytest.raises(ValueError, match="audio-ring-turn-limit"):
        ring.append_post_wake(b"efghi")

    assert ring.post_wake_size == 4
    assert ring.snapshot_post_wake() == b"abcd"


def test_ring_evicts_pre_wake_to_keep_total_turn_snapshot_at_limit() -> None:
    ring = AudioRing(bytes_per_second=4, pre_roll_seconds=3, turn_limit_bytes=12)
    ring.append_pre_wake(b"a" * 12)
    ring.begin_turn()

    ring.append_post_wake(b"b")

    assert ring.pre_wake_size == 11
    assert ring.post_wake_size == 1
    assert ring.snapshot_turn() == (b"a" * 11) + b"b"
    assert len(ring.snapshot_turn()) == 12


def test_ring_post_wake_growth_reclaims_pre_roll_before_post_cap_rejection() -> None:
    ring = AudioRing(bytes_per_second=4, pre_roll_seconds=3, turn_limit_bytes=12)
    ring.append_pre_wake(b"a" * 12)
    ring.begin_turn()

    ring.append_post_wake(b"b" * 8)
    assert ring.snapshot_turn() == (b"a" * 4) + (b"b" * 8)

    ring.append_post_wake(b"c" * 4)
    assert ring.pre_wake_size == 0
    assert ring.post_wake_size == 12
    assert ring.snapshot_turn() == (b"b" * 8) + (b"c" * 4)

    with pytest.raises(ValueError, match="audio-ring-turn-limit"):
        ring.append_post_wake(b"d")

    assert ring.snapshot_turn() == (b"b" * 8) + (b"c" * 4)


def test_ring_pre_wake_append_during_turn_respects_remaining_snapshot_budget() -> None:
    ring = AudioRing(bytes_per_second=4, pre_roll_seconds=3, turn_limit_bytes=12)
    ring.begin_turn()
    ring.append_post_wake(b"b" * 8)

    ring.append_pre_wake(b"a" * 12)

    assert ring.pre_wake_size == 4
    assert ring.post_wake_size == 8
    assert ring.snapshot_turn() == (b"a" * 4) + (b"b" * 8)
    assert len(ring.snapshot_turn()) == 12


def test_ring_clear_wipes_post_wake_and_drops_pre_wake() -> None:
    ring = AudioRing(bytes_per_second=32_000, pre_roll_seconds=3, turn_limit_bytes=MAX_TURN_BYTES)
    ring.append_pre_wake(b"a" * 32)
    ring.begin_turn()
    ring.append_post_wake(b"b" * 32)

    post_buffer = ring._post_wake  # noqa: SLF001 - verifies best-effort wipe without logging audio.
    ring.clear()

    assert ring.pre_wake_size == 0
    assert ring.post_wake_size == 0
    assert ring.snapshot_pre_wake() == b""
    assert ring.snapshot_post_wake() == b""
    assert post_buffer == bytearray()


@pytest.mark.asyncio
async def test_ring_is_owned_by_one_event_loop() -> None:
    ring = AudioRing(bytes_per_second=32_000, pre_roll_seconds=3, turn_limit_bytes=MAX_TURN_BYTES)
    ring.append_pre_wake(b"a")

    async def mutate_from_new_loop() -> str:
        try:
            ring.append_pre_wake(b"b")
        except RuntimeError as error:
            return str(error)
        return "accepted"

    result = await asyncio.to_thread(lambda: asyncio.run(mutate_from_new_loop()))

    assert result == "audio-ring-event-loop-owner"
    assert ring.snapshot_pre_wake() == b"a"
