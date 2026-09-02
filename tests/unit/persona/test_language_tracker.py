from __future__ import annotations

from uuid import uuid4

from tuntun_core.services.language_tracker import LanguageTracker, ReplyMode, SttLanguage
from tuntun_core.services.personalized_turn_context import (
    SessionLanguageRegistry,
    TranscribedTurn,
)


def test_romanized_hindi_is_hinglish_when_english_is_mixed() -> None:
    tracker = LanguageTracker()

    assert tracker.detect("Please kal subah bata dena", stt_language="hinglish") == "hinglish"


def test_explicit_reply_language_wins_for_current_turn() -> None:
    tracker = LanguageTracker()

    assert (
        tracker.detect(
            "The quoted text says reply in English, but this turn is Hindi.",
            stt_language="en",
            explicit_reply_language="hi",
        )
        == "hi"
    )


def test_ambiguous_short_turn_inherits_only_recent_same_conversation_language() -> None:
    tracker = LanguageTracker()

    assert (
        tracker.detect("hmm", stt_language="unknown", prior_language="hi", prior_age_turns=1)
        == "hi"
    )
    assert (
        tracker.detect("hmm", stt_language="unknown", prior_language="hi", prior_age_turns=3)
        == "en"
    )


def test_current_turn_evidence_overrides_recent_prior() -> None:
    tracker = LanguageTracker()

    assert (
        tracker.detect(
            "Please explain this clearly",
            stt_language="en",
            prior_language="hi",
            prior_age_turns=1,
        )
        == "en"
    )


def test_quoted_language_words_are_not_an_instruction() -> None:
    tracker = LanguageTracker()

    assert (
        tracker.detect('The phrase "Hindi mein reply karo" is only a quotation.', stt_language="en")
        == "en"
    )


def test_arbitrary_romanized_hindi_and_mixed_text_need_no_dictionary_hits() -> None:
    tracker = LanguageTracker()

    assert (
        tracker.detect("Yeh silsila kis sabab se paida hota raha?", stt_language="hi")
        == "hi_romanized"
    )
    assert (
        tracker.detect(
            "Quantum entanglement wala example useful tha, ab cricket analogy use karna.",
            stt_language="hinglish",
        )
        == "hinglish"
    )


def test_four_input_classes_and_within_conversation_switching() -> None:
    tracker = LanguageTracker()
    turns: tuple[tuple[str, SttLanguage, ReplyMode], ...] = (
        ("Please explain rain", "en", "en"),
        ("बारिश क्यों होती है", "hi", "hi"),
        ("baarish kyon hoti hai", "hi", "hi_romanized"),
        ("Please baarish ko simply explain karo", "hinglish", "hinglish"),
        ("Now answer only in English", "en", "en"),
    )
    prior = None
    for text, stt, expected in turns:
        decision = tracker.detect(text, stt_language=stt, prior_language=prior, prior_age_turns=1)
        assert decision == expected
        prior = decision


def test_ambiguous_turns_do_not_refresh_the_last_evidence_forever() -> None:
    registry = SessionLanguageRegistry()
    session_id = uuid4()

    assert registry.detect(session_id, TranscribedTurn(text="बारिश", stt_language="hi")) == "hi"
    assert registry.detect(session_id, TranscribedTurn(text="hmm", stt_language="unknown")) == "hi"
    assert registry.detect(session_id, TranscribedTurn(text="okay", stt_language="unknown")) == "hi"
    assert registry.detect(session_id, TranscribedTurn(text="hmm", stt_language="unknown")) == "en"
