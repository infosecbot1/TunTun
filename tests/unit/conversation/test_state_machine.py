from dataclasses import FrozenInstanceError
from typing import cast

import pytest
from tuntun_core.domain.conversation import Transition, TurnEvent, TurnState, transition

_CANCELLATION_EFFECTS = (
    "cancel_turn",
    "stop_reachy",
    "reconcile_budget",
    "clear_ephemeral",
)
_STOP_EFFECTS = (
    "stop_reachy",
    "cancel_turn",
    "reconcile_budget",
    "clear_ephemeral",
)
_PRIVACY_EFFECTS = (
    "close_media_egress",
    "cancel_turn",
    "stop_reachy",
    "reconcile_budget",
    "clear_ephemeral",
)
_INVARIANT_FAILURE_EFFECTS = ("close_media_egress", "stop_reachy")
_BARGE_IN_EFFECTS = (*_STOP_EFFECTS, "queue_wake_after_safe_idle")
_ACTIVE_STATES = (
    TurnState.AWAKE,
    TurnState.LISTENING,
    TurnState.TRANSCRIBING,
    TurnState.IDENTIFYING,
    TurnState.AUTHORIZING,
    TurnState.THINKING,
    TurnState.SPEAKING,
)
_LATCHED_SAFETY_STATES = (TurnState.PRIVACY, TurnState.ERROR_SAFE)

_LEGAL_TRANSITIONS = {
    (TurnState.IDLE, TurnEvent.WAKE): Transition(TurnState.AWAKE, ()),
    (TurnState.AWAKE, TurnEvent.AUDIO_OPEN): Transition(TurnState.LISTENING, ()),
    (TurnState.LISTENING, TurnEvent.AUDIO_END): Transition(TurnState.TRANSCRIBING, ()),
    (TurnState.TRANSCRIBING, TurnEvent.TRANSCRIPT): Transition(TurnState.IDENTIFYING, ()),
    (TurnState.IDENTIFYING, TurnEvent.IDENTITY): Transition(TurnState.AUTHORIZING, ()),
    (TurnState.AUTHORIZING, TurnEvent.AUTHORIZED): Transition(TurnState.THINKING, ()),
    (TurnState.THINKING, TurnEvent.RESPONSE): Transition(TurnState.SPEAKING, ()),
    (TurnState.SPEAKING, TurnEvent.PLAYBACK_END): Transition(
        TurnState.IDLE,
        ("finish_turn", "clear_ephemeral"),
    ),
    (TurnState.SPEAKING, TurnEvent.WAKE): Transition(TurnState.IDLE, _BARGE_IN_EFFECTS),
    **{
        (state, TurnEvent.STOP): Transition(TurnState.IDLE, _STOP_EFFECTS)
        for state in _ACTIVE_STATES
    },
    **{
        (state, event): Transition(TurnState.IDLE, _CANCELLATION_EFFECTS)
        for state in _ACTIVE_STATES
        for event in (
            TurnEvent.CANCEL,
            TurnEvent.TIMEOUT,
            TurnEvent.DISCONNECT,
        )
    },
    **{
        (state, TurnEvent.PRIVACY): Transition(TurnState.PRIVACY, _PRIVACY_EFFECTS)
        for state in _ACTIVE_STATES
    },
    **{
        (state, TurnEvent.INVARIANT_FAILURE): Transition(
            TurnState.ERROR_SAFE,
            _INVARIANT_FAILURE_EFFECTS,
        )
        for state in _ACTIVE_STATES
    },
}


@pytest.mark.parametrize(
    ("state", "event", "expected"),
    [
        (TurnState.IDLE, TurnEvent.WAKE, TurnState.AWAKE),
        (TurnState.AWAKE, TurnEvent.AUDIO_OPEN, TurnState.LISTENING),
        (TurnState.LISTENING, TurnEvent.AUDIO_END, TurnState.TRANSCRIBING),
        (TurnState.TRANSCRIBING, TurnEvent.TRANSCRIPT, TurnState.IDENTIFYING),
        (TurnState.IDENTIFYING, TurnEvent.IDENTITY, TurnState.AUTHORIZING),
        (TurnState.AUTHORIZING, TurnEvent.AUTHORIZED, TurnState.THINKING),
        (TurnState.THINKING, TurnEvent.RESPONSE, TurnState.SPEAKING),
        (TurnState.SPEAKING, TurnEvent.PLAYBACK_END, TurnState.IDLE),
    ],
)
def test_happy_path(
    state: TurnState,
    event: TurnEvent,
    expected: TurnState,
) -> None:
    assert transition(state, event).state is expected


@pytest.mark.parametrize("state", _ACTIVE_STATES)
def test_stop_is_accepted_from_every_active_state(state: TurnState) -> None:
    result = transition(state, TurnEvent.STOP)
    assert result.state is TurnState.IDLE
    assert result.effects == _STOP_EFFECTS
    assert result.effects[0] == "stop_reachy"


def test_privacy_preempts_thinking() -> None:
    result = transition(TurnState.THINKING, TurnEvent.PRIVACY)
    assert result.state is TurnState.PRIVACY
    assert result.effects[0] == "close_media_egress"


def test_illegal_transition_fails_closed() -> None:
    with pytest.raises(ValueError, match=r"illegal transition IDLE \+ RESPONSE"):
        transition(TurnState.IDLE, TurnEvent.RESPONSE)


@pytest.mark.parametrize(
    "event",
    (TurnEvent.CANCEL, TurnEvent.TIMEOUT, TurnEvent.DISCONNECT),
)
@pytest.mark.parametrize("state", _ACTIVE_STATES)
def test_other_cancellation_events_are_exact_from_every_active_state(
    state: TurnState,
    event: TurnEvent,
) -> None:
    result = transition(state, event)
    assert result.state is TurnState.IDLE
    assert result.effects == _CANCELLATION_EFFECTS


@pytest.mark.parametrize("state", _ACTIVE_STATES)
def test_privacy_is_exact_from_every_active_state(state: TurnState) -> None:
    result = transition(state, TurnEvent.PRIVACY)
    assert result.state is TurnState.PRIVACY
    assert result.effects == _PRIVACY_EFFECTS


@pytest.mark.parametrize("state", _ACTIVE_STATES)
def test_invariant_failure_is_exact_from_every_active_state(state: TurnState) -> None:
    result = transition(state, TurnEvent.INVARIANT_FAILURE)
    assert result.state is TurnState.ERROR_SAFE
    assert result.effects == _INVARIANT_FAILURE_EFFECTS


@pytest.mark.parametrize("event", [event for event in TurnEvent if event is not TurnEvent.WAKE])
def test_idle_rejects_every_event_except_wake(event: TurnEvent) -> None:
    with pytest.raises(ValueError, match=rf"illegal transition IDLE \+ {event.name}"):
        transition(TurnState.IDLE, event)


@pytest.mark.parametrize("event", tuple(TurnEvent))
@pytest.mark.parametrize("state", _LATCHED_SAFETY_STATES)
def test_safety_states_cannot_be_cleared_without_owner_recovery(
    state: TurnState,
    event: TurnEvent,
) -> None:
    with pytest.raises(ValueError, match=rf"illegal transition {state.name} \+ {event.name}"):
        transition(state, event)


@pytest.mark.parametrize(
    ("state", "event"),
    (
        (TurnState.AWAKE, TurnEvent.RESPONSE),
        (TurnState.LISTENING, TurnEvent.WAKE),
        (TurnState.TRANSCRIBING, TurnEvent.AUDIO_OPEN),
        (TurnState.IDENTIFYING, TurnEvent.TRANSCRIPT),
        (TurnState.AUTHORIZING, TurnEvent.IDENTITY),
        (TurnState.THINKING, TurnEvent.AUTHORIZED),
        (TurnState.SPEAKING, TurnEvent.RESPONSE),
    ),
)
def test_invalid_active_transition_fails_closed(state: TurnState, event: TurnEvent) -> None:
    with pytest.raises(ValueError, match=rf"illegal transition {state.name} \+ {event.name}"):
        transition(state, event)


def test_normal_completion_requests_finish_and_ephemeral_cleanup() -> None:
    result = transition(TurnState.SPEAKING, TurnEvent.PLAYBACK_END)
    assert result.state is TurnState.IDLE
    assert result.effects == ("finish_turn", "clear_ephemeral")


def test_wake_while_speaking_stops_playback_before_safe_reopen() -> None:
    result = transition(TurnState.SPEAKING, TurnEvent.WAKE)
    assert result == Transition(TurnState.IDLE, _BARGE_IN_EFFECTS)
    assert result.effects[0] == "stop_reachy"
    assert result.effects[-1] == "queue_wake_after_safe_idle"


@pytest.mark.parametrize("event", tuple(TurnEvent))
@pytest.mark.parametrize("state", tuple(TurnState))
def test_complete_state_event_matrix_is_closed(state: TurnState, event: TurnEvent) -> None:
    expected = _LEGAL_TRANSITIONS.get((state, event))
    if expected is None:
        with pytest.raises(ValueError, match=rf"illegal transition {state.name} \+ {event.name}"):
            transition(state, event)
    else:
        assert transition(state, event) == expected


@pytest.mark.parametrize(
    ("state", "event"),
    (
        (TurnState.SPEAKING.value, TurnEvent.STOP),
        (TurnState.SPEAKING, TurnEvent.STOP.value),
        (object(), TurnEvent.STOP),
        (TurnState.SPEAKING, object()),
    ),
)
def test_transition_requires_exact_enum_types(state: object, event: object) -> None:
    with pytest.raises(TypeError, match="state and event must be exact enums"):
        transition(cast(TurnState, state), cast(TurnEvent, event))


def test_transition_and_effects_are_immutable() -> None:
    result = transition(TurnState.SPEAKING, TurnEvent.PLAYBACK_END)
    assert type(result.effects) is tuple

    with pytest.raises(FrozenInstanceError):
        result.state = TurnState.ERROR_SAFE


def test_repeated_transition_has_no_mutable_state() -> None:
    first = transition(TurnState.THINKING, TurnEvent.RESPONSE)
    second = transition(TurnState.THINKING, TurnEvent.RESPONSE)
    assert first == second
    assert first.effects == second.effects == ()
