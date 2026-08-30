from __future__ import annotations

import json
from pathlib import Path

from tuntun_contracts.base import canonical_mapping_bytes
from tuntun_testing.scenario import ScenarioRunner
from tuntun_testing.scenario_io import read_scenario_input

ROOT = Path(__file__).absolute().parents[2]
SCENARIO = Path("tests/fixtures/scenarios/guest-hinglish.yaml")


def test_real_port_chain_is_byte_deterministic_and_observable() -> None:
    value = read_scenario_input(SCENARIO, trusted_root=ROOT)
    first = ScenarioRunner().run(value)
    second = ScenarioRunner().run(value)
    expected_events = (
        "wake.detected",
        "audio.synthetic",
        "route.authorize",
        "stt.transcribe",
        "route.consume",
        "identity.resolve",
        "route.authorize",
        "llm.complete",
        "route.consume",
        "route.authorize",
        "tts.synthesize",
        "route.consume",
        "reachy.send",
        "audit.append",
    )
    assert first.canonical_json() == second.canonical_json()
    assert first.events == expected_events
    assert first.identity == "guest"
    assert first.usage.input_audio_bytes == 16
    assert first.usage.output_audio_bytes == 16
    decoded = json.loads(first.canonical_json())
    assert canonical_mapping_bytes(decoded) == first.canonical_json()


def test_turn_index_changes_ids_but_remains_deterministic() -> None:
    value = read_scenario_input(SCENARIO, trusted_root=ROOT)
    zero = ScenarioRunner().run(value, turn_index=0)
    one = ScenarioRunner().run(value, turn_index=1)
    assert zero.turn_id != one.turn_id
    assert zero.canonical_json() != one.canonical_json()
    assert ScenarioRunner().run(value, turn_index=1) == one
