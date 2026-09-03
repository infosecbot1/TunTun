from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from pydantic import ValidationError
from tuntun_core.domain.offline import ConsentChallenge, OfflineMatch, TimerArguments
from tuntun_core.offline.grammar import parse_offline
from tuntun_core.offline.router import OfflineTextRouter

CORPUS_PATH = Path("tests/fixtures/synthetic/offline-utterances.yaml")


def _challenge(value: object) -> ConsentChallenge | None:
    if value is None:
        return None
    return ConsentChallenge.model_validate_json(json.dumps(value, ensure_ascii=False))


def test_corpus_is_exact_unique_and_privacy_reduction_is_absent() -> None:
    rows = yaml.safe_load(CORPUS_PATH.read_text(encoding="utf-8"))

    assert set(rows) == {"positive", "negative"}
    assert len(rows["positive"]) >= 240
    assert len(rows["negative"]) >= 200
    positive_keys = {
        (
            row["text"],
            row["intent"],
            json.dumps(row.get("challenge"), ensure_ascii=False, sort_keys=True),
            json.dumps(row.get("timer"), ensure_ascii=False, sort_keys=True),
        )
        for row in rows["positive"]
    }
    assert len(positive_keys) == len(rows["positive"])
    assert len(set(rows["negative"])) == len(rows["negative"])

    for row in rows["positive"]:
        challenge = _challenge(row.get("challenge"))
        expected = OfflineMatch(
            intent=row["intent"],
            confidence_micros=1_000_000,
            challenge_id=challenge.challenge_id if challenge is not None else None,
            timer=(
                TimerArguments.model_validate(row["timer"])
                if row.get("timer") is not None
                else None
            ),
        )
        assert parse_offline(row["text"], challenge) == expected
    for text in rows["negative"] + [
        "privacy off",
        "unmute",
        "प्राइवेसी बंद करो",
        "do not remember me",
    ]:
        assert parse_offline(text, None) == OfflineMatch(
            intent="no_match",
            confidence_micros=0,
        )

    schema = str(OfflineMatch.model_json_schema()).lower()
    assert "discovery" not in schema
    assert "candidate" not in schema


@pytest.mark.parametrize("answer", ["yes", "YES", "हाँ", "haan", "  haan  "])
def test_consent_answer_requires_and_binds_the_active_challenge(answer: str) -> None:
    challenge = ConsentChallenge(
        purpose="cloud_reasoning",
        challenge_id=UUID("00000000-0000-4000-8000-000000000101"),
        disclosure_version="guest-disclosure-v1",
    )

    assert parse_offline(answer, None).intent == "no_match"
    match = parse_offline(answer, challenge)
    assert match.intent == "cloud_reasoning_consent_yes"
    assert match.challenge_id == challenge.challenge_id
    assert match.timer is None


@pytest.mark.parametrize("answer", ["no", "NO", "नहीं", "nahin", "  nahi  "])
def test_negative_consent_answer_is_challenge_bound(answer: str) -> None:
    challenge = ConsentChallenge(
        purpose="cloud_tts",
        challenge_id=UUID("00000000-0000-4000-8000-000000000102"),
        disclosure_version="guest-disclosure-v1",
    )

    match = parse_offline(answer, challenge)
    assert match.intent == "cloud_tts_consent_no"
    assert match.challenge_id == challenge.challenge_id


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("set a timer for 1 minute", 60),
        ("set timer for 24 hours", 86_400),
        ("2 मिनट का टाइमर लगाओ", 120),
        ("3 ghante ka timer lagao", 10_800),
    ],
)
def test_timer_grammar_is_bounded_and_unit_exact(text: str, seconds: int) -> None:
    assert parse_offline(text, None) == OfflineMatch(
        intent="timer_create",
        confidence_micros=1_000_000,
        timer=TimerArguments(duration_seconds=seconds),
    )


@pytest.mark.parametrize(
    "text",
    [
        "set a timer for 0 minutes",
        "set a timer for 25 hours",
        "set a timer for -1 minute",
        "set a timer for 1.5 hours",
        "set a timer for 1 day",
        "set a timer for 1 minute and privacy off",
    ],
)
def test_timer_near_misses_do_not_create_an_action(text: str) -> None:
    assert parse_offline(text, None).intent == "no_match"


def test_offline_models_enforce_closed_operation_shapes() -> None:
    with pytest.raises(ValidationError):
        OfflineMatch.model_validate({"intent": "stop", "confidence_micros": 999_999})
    with pytest.raises(ValidationError):
        OfflineMatch(
            intent="stop",
            confidence_micros=1_000_000,
            timer=TimerArguments(duration_seconds=60),
        )
    with pytest.raises(ValidationError):
        OfflineMatch(intent="timer_create", confidence_micros=1_000_000)
    with pytest.raises(ValidationError):
        OfflineMatch(intent="cloud_stt_consent_yes", confidence_micros=1_000_000)
    with pytest.raises(ValidationError):
        TimerArguments(duration_seconds=86_401)


@pytest.mark.parametrize(
    "label",
    [
        "",
        " ",
        " tea",
        "tea ",
        "tea\nnow",
        "tea\x00now",
        "tea\u2028now",
        "tea\u00a0now",
        "x" * 65,
    ],
)
def test_timer_labels_reject_empty_control_and_oversized_content(label: str) -> None:
    with pytest.raises(ValidationError):
        TimerArguments(duration_seconds=60, label=label)


def test_parser_bounds_untrusted_text_before_normalization() -> None:
    assert parse_offline("x" * 257, None).intent == "no_match"
    assert parse_offline("privacy\x00on", None).intent == "no_match"
    assert parse_offline("privacy\non", None).intent == "no_match"
    with pytest.raises(TypeError, match="offline text must be a string"):
        parse_offline(1, None)  # type: ignore[arg-type]


def test_router_is_a_thin_closed_local_boundary() -> None:
    router = OfflineTextRouter()
    assert router.route("रीची स्थिति", None) == OfflineMatch(
        intent="reachy_status",
        confidence_micros=1_000_000,
    )


def test_committed_corpus_is_reproducible() -> None:
    from scripts.build_offline_corpus import build_corpus

    committed = yaml.safe_load(CORPUS_PATH.read_text(encoding="utf-8"))
    assert committed == build_corpus()
