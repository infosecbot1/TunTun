from __future__ import annotations

import os
from pathlib import Path

import pytest
from tuntun_contracts.poc.framing import PttSessionOutcome
from tuntun_core.adapters.poc.fake_voice import (
    FakeVoiceScript,
    run_fake_simulated_turn,
    scan_tree_for_raw_sentinels,
)


@pytest.mark.asyncio
async def test_fake_loop_does_not_retain_raw_transcript_answer_or_audio(
    tmp_path: Path,
) -> None:
    sentinel_text = "PRIVATE-HINGLISH-SENTINEL-nani-ka-dawai"
    sentinel_answer = "PRIVATE-ANSWER-SENTINEL-calendar-mat-batao"
    sentinel_pcm = b"PRIVATE-PCM-SENTINEL"
    managed_tree = tmp_path / "managed"
    managed_tree.mkdir()

    outcome = await run_fake_simulated_turn(
        FakeVoiceScript(
            utterance=sentinel_text,
            language="hinglish",
            response=sentinel_answer,
            capture_pcm=sentinel_pcm + b"\x00\x00",
        ),
        managed_tree=managed_tree,
    )

    assert outcome is PttSessionOutcome.COMPLETED
    assert (
        scan_tree_for_raw_sentinels(
            managed_tree,
            (sentinel_text.encode("utf-8"), sentinel_answer.encode("utf-8"), sentinel_pcm),
        )
        == ()
    )


@pytest.mark.asyncio
async def test_repeated_warm_fake_runs_keep_descriptor_growth_bounded(tmp_path: Path) -> None:
    managed_tree = tmp_path / "managed"
    managed_tree.mkdir()
    fd_root = Path("/dev/fd")
    before = len(tuple(fd_root.iterdir())) if fd_root.exists() else 0

    for index in range(12):
        outcome = await run_fake_simulated_turn(
            FakeVoiceScript(
                utterance=f"PRIVATE-SENTINEL-{index}",
                language=("en", "hi", "hinglish")[index % 3],
                response=f"PRIVATE-REPLY-{index}",
            ),
            managed_tree=managed_tree,
        )
        assert outcome is PttSessionOutcome.COMPLETED
        assert (
            scan_tree_for_raw_sentinels(managed_tree, (f"PRIVATE-SENTINEL-{index}".encode(),)) == ()
        )

    after = len(tuple(fd_root.iterdir())) if fd_root.exists() else before

    assert after <= before + 8
    assert "PRIVATE-SENTINEL" not in repr(os.environ)
