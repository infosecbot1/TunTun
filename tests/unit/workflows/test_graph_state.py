from __future__ import annotations

import json
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tuntun_core.workflows.state import GraphState


def test_graph_state_is_closed_strict_and_content_free() -> None:
    state = GraphState(
        turn_id=uuid4(),
        phase="ingress",
        cancelled=False,
        content_commitments=("a" * 64,),
    )

    encoded = json.dumps(state.model_dump(mode="json"), sort_keys=True)
    for forbidden in (
        "audio",
        "wav",
        "transcript",
        "answer",
        "prompt",
        "messages",
        "memory_body",
        "tts_text",
        "pcm",
        "provider_response",
        "profile",
        "subject_name",
        "start_attempted",
        "played",
    ):
        assert forbidden not in encoded
        assert forbidden not in GraphState.model_fields
    assert GraphState.model_json_schema()["properties"]["content_commitments"]["maxItems"] == 16


@pytest.mark.parametrize(
    "changes",
    (
        {"turn_id": "00000000-0000-0000-0000-000000000001"},
        {"phase": "arbitrary"},
        {"cancelled": 0},
        {"content_commitments": ("A" * 64,)},
        {"content_commitments": ("a" * 64, "a" * 64)},
        {"content_commitments": tuple(f"{index:064x}" for index in range(17))},
        {"raw_transcript": "private"},
    ),
)
def test_graph_state_rejects_coercion_duplicates_unknown_phases_and_extra_content(
    changes: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "turn_id": uuid4(),
        "phase": "ingress",
        "cancelled": False,
        "content_commitments": (),
    }
    values.update(changes)

    with pytest.raises((TypeError, ValidationError, ValueError)):
        GraphState(**values)  # type: ignore[arg-type]
