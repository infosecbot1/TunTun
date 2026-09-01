from dataclasses import dataclass
from enum import StrEnum


class TurnState(StrEnum):
    IDLE = "idle"
    AWAKE = "awake"
    LISTENING = "listening"
    TRANSCRIBING = "transcribing"
    IDENTIFYING = "identifying"
    AUTHORIZING = "authorizing"
    THINKING = "thinking"
    SPEAKING = "speaking"
    PRIVACY = "privacy"
    ERROR_SAFE = "error_safe"


class TurnEvent(StrEnum):
    WAKE = "wake"
    AUDIO_OPEN = "audio_open"
    AUDIO_END = "audio_end"
    TRANSCRIPT = "transcript"
    IDENTITY = "identity"
    AUTHORIZED = "authorized"
    RESPONSE = "response"
    PLAYBACK_END = "playback_end"
    STOP = "stop"
    PRIVACY = "privacy"
    CANCEL = "cancel"
    TIMEOUT = "timeout"
    DISCONNECT = "disconnect"
    INVARIANT_FAILURE = "invariant_failure"


@dataclass(frozen=True, slots=True)
class Transition:
    state: TurnState
    effects: tuple[str, ...]


_ACTIVE_STATES = frozenset(
    {
        TurnState.AWAKE,
        TurnState.LISTENING,
        TurnState.TRANSCRIBING,
        TurnState.IDENTIFYING,
        TurnState.AUTHORIZING,
        TurnState.THINKING,
        TurnState.SPEAKING,
    }
)
_STOP_EFFECTS = ("stop_reachy", "cancel_turn", "reconcile_budget", "clear_ephemeral")
_CANCELLATION_EFFECTS = (
    "cancel_turn",
    "stop_reachy",
    "reconcile_budget",
    "clear_ephemeral",
)

_FORWARD = {
    (TurnState.IDLE, TurnEvent.WAKE): Transition(TurnState.AWAKE, ()),
    (TurnState.AWAKE, TurnEvent.AUDIO_OPEN): Transition(TurnState.LISTENING, ()),
    (TurnState.LISTENING, TurnEvent.AUDIO_END): Transition(TurnState.TRANSCRIBING, ()),
    (TurnState.TRANSCRIBING, TurnEvent.TRANSCRIPT): Transition(TurnState.IDENTIFYING, ()),
    (TurnState.IDENTIFYING, TurnEvent.IDENTITY): Transition(TurnState.AUTHORIZING, ()),
    (TurnState.AUTHORIZING, TurnEvent.AUTHORIZED): Transition(TurnState.THINKING, ()),
    (TurnState.THINKING, TurnEvent.RESPONSE): Transition(TurnState.SPEAKING, ()),
    (
        TurnState.SPEAKING,
        TurnEvent.PLAYBACK_END,
    ): Transition(TurnState.IDLE, ("finish_turn", "clear_ephemeral")),
    (
        TurnState.SPEAKING,
        TurnEvent.WAKE,
    ): Transition(
        TurnState.IDLE,
        (*_STOP_EFFECTS, "queue_wake_after_safe_idle"),
    ),
}


def transition(state: TurnState, event: TurnEvent) -> Transition:
    if type(state) is not TurnState or type(event) is not TurnEvent:
        raise TypeError("state and event must be exact enums")
    if state in _ACTIVE_STATES and event is TurnEvent.STOP:
        return Transition(TurnState.IDLE, _STOP_EFFECTS)
    if state in _ACTIVE_STATES and event in {
        TurnEvent.CANCEL,
        TurnEvent.TIMEOUT,
        TurnEvent.DISCONNECT,
    }:
        return Transition(TurnState.IDLE, _CANCELLATION_EFFECTS)
    if state in _ACTIVE_STATES and event is TurnEvent.PRIVACY:
        return Transition(
            TurnState.PRIVACY,
            (
                "close_media_egress",
                "cancel_turn",
                "stop_reachy",
                "reconcile_budget",
                "clear_ephemeral",
            ),
        )
    if state in _ACTIVE_STATES and event is TurnEvent.INVARIANT_FAILURE:
        return Transition(TurnState.ERROR_SAFE, ("close_media_egress", "stop_reachy"))
    forward = _FORWARD.get((state, event))
    if forward is None:
        raise ValueError(f"illegal transition {state.name} + {event.name}")
    return forward
