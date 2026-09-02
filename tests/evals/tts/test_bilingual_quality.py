from __future__ import annotations

import json
from pathlib import Path


def test_bilingual_tts_fixture_covers_english_hindi_and_hinglish() -> None:
    corpus = json.loads(
        Path("tests/evals/tts/fixtures/en-hi-hinglish-v1.json").read_text(encoding="utf-8")
    )

    assert {item["language"] for item in corpus["utterances"]} == {"en", "hi", "hinglish"}
    assert all(item["expected_intelligible"] is True for item in corpus["utterances"])
    assert corpus["schema_version"] == "tts-bilingual-quality-v1"
