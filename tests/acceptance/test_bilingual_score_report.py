from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from tuntun_contracts.base import canonical_mapping_bytes

from evals.scorers.corpus_bound import calibration_corpus_sha256
from evals.verify_bilingual_report import (
    BilingualReportBuilder,
    production_gate_readiness,
    verify_report,
)
from tests.acceptance.test_bilingual_personas import _bilingual_rows
from tests.acceptance.test_child_safety_corpus import _child_rows
from tests.acceptance.test_evaluator_calibration import _write_minimum_calibration_corpus


def test_signed_report_recomputes_metrics_and_binds_candidate(
    valid_report: dict[str, Any],
    verifier: _Verifier,
) -> None:
    decision = verify_report(
        valid_report,
        verifier,
        allow_test_report=True,
        **valid_report["expected_inputs"],
    )
    assert decision.allowed


def test_multiturn_bilingual_results_allow_same_case_id_with_distinct_turns(
    valid_report: dict[str, Any],
    verifier: _Verifier,
) -> None:
    duplicate_bilingual = [
        row for row in valid_report["complete_case_results"] if row["case_id"] == "bilingual-000"
    ]
    assert len(duplicate_bilingual) == 2
    assert {row["turn_id"] for row in duplicate_bilingual} == {
        "bilingual-000-turn-1",
        "bilingual-000-turn-2",
    }
    assert verify_report(
        valid_report,
        verifier,
        allow_test_report=True,
        **valid_report["expected_inputs"],
    ).allowed


def test_partial_report_verifier_refuses_production_gate_without_artifacts(
    valid_report: dict[str, Any],
    verifier: _Verifier,
) -> None:
    with pytest.raises(PermissionError, match="production verification requires"):
        verify_report(valid_report, verifier, **valid_report["expected_inputs"])


def test_partial_report_signing_requires_explicit_test_mode(verifier: _Verifier) -> None:
    builder = BilingualReportBuilder(verifier, signer_key_id="ed25519:tuntun-eval-report:v1")
    with pytest.raises(PermissionError, match="production signing requires"):
        builder.sign(_base_report(_complete_results(), corpus_inventory=_complete_inventory()))


def test_each_bilingual_case_requires_two_to_four_turn_results(
    report_builder: BilingualReportBuilder,
) -> None:
    with pytest.raises(ValueError, match="bilingual turn|turn inventory"):
        report_builder.sign(
            _base_report(
                _single_turn_bilingual_results(),
                corpus_inventory=_complete_inventory(),
            )
        )


def test_reply_modes_roles_and_child_safety_evidence_are_bounded(
    report_builder: BilingualReportBuilder,
) -> None:
    with pytest.raises(ValueError, match="reply mode"):
        report_builder.sign(
            _base_report(
                (_case_result("bilingual-000", "bilingual", expected_reply_mode="pirate"),),
                corpus_inventory=_complete_inventory(),
            )
        )
    with pytest.raises(ValueError, match="role"):
        report_builder.sign(
            _base_report(
                (_case_result("bilingual-000", "bilingual", resolved_role="neighbor"),),
                corpus_inventory=_complete_inventory(),
            )
        )
    with pytest.raises(ValueError, match="child adversarial"):
        report_builder.sign(
            _base_report(
                _complete_results(dangerous_instruction_count=1),
                corpus_inventory=_complete_inventory(),
            )
        )


def test_report_builder_requires_complete_corpus_inventory(
    report_builder: BilingualReportBuilder,
) -> None:
    with pytest.raises(ValueError, match="corpus_inventory"):
        report_builder.sign(_base_report(_tiny_results()))
    with pytest.raises(ValueError, match="inventory"):
        report_builder.sign(
            _base_report(
                _tiny_results(),
                corpus_inventory={
                    "bilingual_case_ids": (),
                    "child_adversarial_case_ids": (),
                    "child_benign_case_ids": (),
                },
            )
        )


def test_report_inventory_must_include_reviewed_turn_ids(
    report_builder: BilingualReportBuilder,
) -> None:
    with pytest.raises(ValueError, match="turn inventory"):
        report_builder.sign(
            _base_report(
                _complete_results(),
                corpus_inventory=_case_only_inventory(),
            )
        )


def test_fabricated_turn_ids_not_bound_to_reviewed_inventory_are_rejected(
    report_builder: BilingualReportBuilder,
) -> None:
    results = [dict(row) for row in _complete_results()]
    replacements = iter(("fabricated-turn-a", "fabricated-turn-b"))
    for row in results:
        if row["case_id"] == "bilingual-000":
            row["turn_id"] = next(replacements)

    with pytest.raises(ValueError, match="turn inventory"):
        report_builder.sign(
            _base_report(
                tuple(results),
                corpus_inventory=_complete_inventory(),
            )
        )


def test_production_gate_is_no_go_without_reviewed_corpora_or_evaluator_artifacts() -> None:
    decision = production_gate_readiness(
        model_lock_path="evals/models/evaluator-models.lock.json",
        bilingual_corpus_path="evals/cases/bilingual-family.jsonl",
        child_safety_corpus_path="evals/cases/child-safety-v1.jsonl",
        calibration_corpus_path="evals/cases/evaluator-calibration-v1.jsonl",
    )
    assert not decision.allowed
    assert decision.reason.startswith("NO-GO:")


def test_production_gate_is_no_go_without_artifact_runtime_and_calibration(
    tmp_path: Path,
) -> None:
    bilingual_corpus = tmp_path / "bilingual-family.jsonl"
    child_corpus = tmp_path / "child-safety-v1.jsonl"
    calibration_corpus = tmp_path / "evaluator-calibration-v1.jsonl"
    model_lock = tmp_path / "evaluator-models.lock.json"
    _write_jsonl(bilingual_corpus, _bilingual_rows())
    _write_jsonl(child_corpus, _child_rows())
    _write_minimum_calibration_corpus(calibration_corpus)
    _write_json(
        model_lock,
        {
            "schema_version": "tuntun.evaluator-model-lock.v1",
            "status": "provisioned",
            "calibration_corpus_sha256": calibration_corpus_sha256(calibration_corpus),
            "language": {
                "artifact_path": str(tmp_path / "missing-language.ftz"),
                "artifact_sha256": "a" * 64,
                "minimum_span_confidence_micros": 900_000,
                "license": "fixture-reviewed",
                "source_revision": "fixture",
                "license_reviewed": True,
            },
            "leakage": {
                "artifact_path": str(tmp_path / "missing-nli"),
                "artifact_tree_sha256": "b" * 64,
                "minimum_entailment_micros": 900_000,
                "license": "fixture-reviewed",
                "source_revision": "fixture",
                "license_reviewed": True,
            },
        },
    )

    decision = production_gate_readiness(
        model_lock_path=model_lock,
        bilingual_corpus_path=bilingual_corpus,
        child_safety_corpus_path=child_corpus,
        calibration_corpus_path=calibration_corpus,
    )

    assert not decision.allowed
    assert "artifact" in decision.reason or "calibration" in decision.reason


@pytest.mark.parametrize(
    "mutation",
    (
        "signature",
        "candidate",
        "model",
        "prompt",
        "policy",
        "corpus",
        "scorer",
        "evaluator_model",
        "calibration",
        "child_corpus",
        "case_result",
        "case_ids",
        "aggregate",
        "expired",
        "future_issued",
        "unbounded_lifetime",
    ),
)
def test_tamper_or_stale_binding_blocks(
    valid_report: dict[str, Any],
    verifier: _Verifier,
    mutation: str,
) -> None:
    with pytest.raises(ValueError):
        verify_report(
            _mutate_report(valid_report, mutation),
            verifier,
            allow_test_report=True,
            **valid_report["expected_inputs"],
        )


def test_label_counts_cannot_substitute_for_executed_results(
    report_builder: BilingualReportBuilder,
) -> None:
    with pytest.raises(ValueError, match="complete_case_results"):
        report_builder.sign({"labels": {"hi": 70, "en": 70, "mixed": 70, "hi_romanized": 70}})


@pytest.fixture
def verifier() -> _Verifier:
    return _Verifier(secret=b"report-test-secret")


@pytest.fixture
def report_builder(verifier: _Verifier) -> BilingualReportBuilder:
    return BilingualReportBuilder(
        verifier,
        signer_key_id="test-ed25519:tuntun-eval-report:v1",
        allow_test_signing=True,
    )


@pytest.fixture
def valid_report(report_builder: BilingualReportBuilder) -> dict[str, Any]:
    expected_inputs = {
        "candidate_commit": "a" * 40,
        "model_id": "gpt-5.6-sol",
        "prompt_bundle_sha256": "b" * 64,
        "policy_sha256": "c" * 64,
        "corpus_sha256": "d" * 64,
        "scorer_sha256": "e" * 64,
        "evaluator_model_lock_sha256": "f" * 64,
        "calibration_corpus_sha256": "1" * 64,
        "child_safety_corpus_sha256": "2" * 64,
        "now": datetime(2026, 8, 27, 12, 0, tzinfo=UTC),
    }
    report = report_builder.sign(
        _base_report(_complete_results(), corpus_inventory=_complete_inventory())
    )
    report["expected_inputs"] = expected_inputs
    return report


def _base_report(
    complete_case_results: tuple[dict[str, object], ...],
    *,
    corpus_inventory: Mapping[str, object] | None = None,
) -> dict[str, object]:
    report: dict[str, object] = {
        "candidate_commit": "a" * 40,
        "model_id": "gpt-5.6-sol",
        "prompt_bundle_sha256": "b" * 64,
        "policy_sha256": "c" * 64,
        "corpus_sha256": "d" * 64,
        "scorer_sha256": "e" * 64,
        "evaluator_model_lock_sha256": "f" * 64,
        "calibration_corpus_sha256": "1" * 64,
        "child_safety_corpus_sha256": "2" * 64,
        "issued_at": datetime(2026, 8, 27, 11, 55, tzinfo=UTC),
        "expires_at": datetime(2026, 8, 27, 12, 55, tzinfo=UTC),
        "complete_case_results": complete_case_results,
    }
    if corpus_inventory is not None:
        report["corpus_inventory"] = corpus_inventory
    return report


def _complete_inventory() -> dict[str, object]:
    inventory = _case_only_inventory()
    turn_ids_by_case: dict[str, tuple[str, ...]] = {}
    for case_id in inventory["bilingual_case_ids"]:
        turn_ids_by_case[case_id] = (f"{case_id}-turn-1", f"{case_id}-turn-2")
    for case_id in inventory["child_adversarial_case_ids"]:
        turn_ids_by_case[case_id] = (f"{case_id}-turn-1",)
    for case_id in inventory["child_benign_case_ids"]:
        turn_ids_by_case[case_id] = (f"{case_id}-turn-1",)
    return cast(dict[str, object], inventory | {"turn_ids_by_case": turn_ids_by_case})


def _case_only_inventory() -> dict[str, tuple[str, ...]]:
    return {
        "bilingual_case_ids": tuple(f"bilingual-{index:03d}" for index in range(280)),
        "child_adversarial_case_ids": tuple(f"child-adv-{index:03d}" for index in range(360)),
        "child_benign_case_ids": tuple(f"child-benign-{index:03d}" for index in range(120)),
    }


def _complete_results(*, dangerous_instruction_count: int = 0) -> tuple[dict[str, object], ...]:
    inventory = _case_only_inventory()
    rows: list[dict[str, object]] = []
    for case_id in inventory["bilingual_case_ids"]:
        rows.append(_case_result(case_id, "bilingual", turn_id=f"{case_id}-turn-1"))
        rows.append(_case_result(case_id, "bilingual", turn_id=f"{case_id}-turn-2"))
    for case_id in inventory["child_adversarial_case_ids"]:
        rows.append(
            _case_result(
                case_id,
                "child_adversarial",
                child_safe=True,
                dangerous_instruction_count=dangerous_instruction_count,
                turn_id=f"{case_id}-turn-1",
            )
        )
    for case_id in inventory["child_benign_case_ids"]:
        rows.append(
            _case_result(
                case_id,
                "child_benign",
                benign_appropriate=True,
                turn_id=f"{case_id}-turn-1",
            )
        )
    return tuple(rows)


def _single_turn_bilingual_results() -> tuple[dict[str, object], ...]:
    inventory = _case_only_inventory()
    rows: list[dict[str, object]] = []
    for case_id in inventory["bilingual_case_ids"]:
        rows.append(_case_result(case_id, "bilingual", turn_id=f"{case_id}-turn-1"))
    for case_id in inventory["child_adversarial_case_ids"]:
        rows.append(
            _case_result(
                case_id,
                "child_adversarial",
                child_safe=True,
                turn_id=f"{case_id}-turn-1",
            )
        )
    for case_id in inventory["child_benign_case_ids"]:
        rows.append(
            _case_result(
                case_id,
                "child_benign",
                benign_appropriate=True,
                turn_id=f"{case_id}-turn-1",
            )
        )
    return tuple(rows)


def _tiny_results() -> tuple[dict[str, object], ...]:
    return (
        _case_result("bilingual-1", "bilingual"),
        _case_result("child-adv-1", "child_adversarial", child_safe=True),
    )


def _case_result(
    case_id: str,
    case_kind: str,
    *,
    turn_id: str | None = None,
    expected_reply_mode: str = "en",
    resolved_role: str | None = None,
    language_ok: bool = True,
    child_safe: bool = False,
    benign_appropriate: bool = False,
    dangerous_instruction_count: int = 0,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "case_kind": case_kind,
        "turn_id": turn_id or f"{case_id}-turn-1",
        "expected_reply_mode": expected_reply_mode,
        "observed_reply_mode": "en" if language_ok else "hi",
        "language_ok": language_ok,
        "resolved_role": resolved_role or ("guest" if case_kind != "bilingual" else "adult"),
        "expected_role": "guest" if case_kind != "bilingual" else "adult",
        "leaked_claim_ids": (),
        "boundary_isolated": True,
        "search_calls": 0,
        "action_proposals": 0,
        "memory_proposals": 0,
        "secrecy_promises": 0,
        "dangerous_instruction_count": dangerous_instruction_count,
        "unnecessary_refusal": False,
        "child_adversarial_safe": child_safe,
        "benign_age_language_appropriate": benign_appropriate,
        "answer_sha256": "3" * 64,
        "provider_attempt_sha256": "4" * 64,
    }


def _mutate_report(report: dict[str, Any], mutation: str) -> dict[str, Any]:
    mutated = deepcopy(report)
    mutated.pop("expected_inputs", None)
    mapping = {
        "candidate": ("candidate_commit", "0" * 40),
        "model": ("model_id", "other-model"),
        "prompt": ("prompt_bundle_sha256", "0" * 64),
        "policy": ("policy_sha256", "0" * 64),
        "corpus": ("corpus_sha256", "0" * 64),
        "scorer": ("scorer_sha256", "0" * 64),
        "evaluator_model": ("evaluator_model_lock_sha256", "0" * 64),
        "calibration": ("calibration_corpus_sha256", "0" * 64),
        "child_corpus": ("child_safety_corpus_sha256", "0" * 64),
    }
    if mutation == "signature":
        mutated["signature"] = "00" + mutated["signature"][2:]
    elif mutation in mapping:
        key, value = mapping[mutation]
        mutated[key] = value
    elif mutation == "case_result":
        mutated["complete_case_results"][0]["language_ok"] = False
    elif mutation == "case_ids":
        ids = list(mutated["corpus_inventory"]["bilingual_case_ids"])
        ids[1] = "missing-bilingual"
        mutated["corpus_inventory"]["bilingual_case_ids"] = tuple(ids)
    elif mutation == "aggregate":
        mutated["aggregate_metrics"]["language_following_micros"] = 1
    elif mutation == "expired":
        mutated["expires_at"] = datetime(2026, 8, 27, 11, 59, tzinfo=UTC)
        return BilingualReportBuilder(
            _Verifier(secret=b"report-test-secret"),
            signer_key_id=mutated["signer_key_id"],
            allow_test_signing=True,
        ).sign(mutated)
    elif mutation == "future_issued":
        mutated["issued_at"] = datetime(2026, 8, 27, 12, 1, tzinfo=UTC)
        mutated["expires_at"] = datetime(2026, 8, 27, 12, 55, tzinfo=UTC)
        return BilingualReportBuilder(
            _Verifier(secret=b"report-test-secret"),
            signer_key_id=mutated["signer_key_id"],
            allow_test_signing=True,
        ).sign(mutated)
    elif mutation == "unbounded_lifetime":
        mutated["expires_at"] = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
        return BilingualReportBuilder(
            _Verifier(secret=b"report-test-secret"),
            signer_key_id=mutated["signer_key_id"],
            allow_test_signing=True,
        ).sign(mutated)
    else:
        raise AssertionError(mutation)
    return mutated


class _Verifier:
    def __init__(self, *, secret: bytes) -> None:
        self._secret = secret

    def sign(self, payload: bytes, key_id: str) -> str:
        import hashlib

        return hashlib.sha256(self._secret + key_id.encode("utf-8") + payload).hexdigest()

    def verify(self, payload: bytes, signature: str, key_id: str) -> bool:
        return self.sign(payload, key_id) == signature


def _write_jsonl(path: Path, rows: tuple[dict[str, object], ...] | list[dict[str, object]]) -> None:
    path.write_bytes(b"".join(canonical_mapping_bytes(row) + b"\n" for row in rows))


def _write_json(path: Path, row: dict[str, object]) -> None:
    path.write_bytes(canonical_mapping_bytes(row))
