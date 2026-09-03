from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from tuntun_contracts.base import canonical_mapping_bytes, parse_contract_json

from evals.cases.bilingual_schema import BilingualPersonaCaseV1
from evals.judges.pinned_language import read_regular_file_bytes

CORPUS = Path("evals/cases/bilingual-family.jsonl")
ROW_MAX_BYTES = 32_768
EXPECTED_BILINGUAL_CASES = 280
EXPECTED_FAMILY_CASES = 240
EXPECTED_GUEST_CASES = 40
CORPUS_FILE_MAX_BYTES = ROW_MAX_BYTES * (EXPECTED_BILINGUAL_CASES + 1)


class CorpusProvisioningError(FileNotFoundError):
    """Raised when a reviewed Task15 corpus is not locally provisioned."""


def build_cases(path: Path = CORPUS) -> list[BilingualPersonaCaseV1]:
    corpus_path = Path(path)
    if not corpus_path.exists():
        raise CorpusProvisioningError(
            f"reviewed bilingual corpus is not locally provisioned: {corpus_path}"
        )
    payload = read_regular_file_bytes(
        corpus_path,
        max_bytes=CORPUS_FILE_MAX_BYTES,
        label="bilingual corpus",
    )
    rows: list[BilingualPersonaCaseV1] = []
    for line_number, line in enumerate(payload.splitlines(), start=1):
        if len(line) > ROW_MAX_BYTES:
            raise ValueError(f"bilingual corpus row {line_number} too large")
        raw = line.strip()
        if not raw:
            continue
        rows.append(
            parse_contract_json(
                BilingualPersonaCaseV1,
                raw,
                max_bytes=ROW_MAX_BYTES,
                require_canonical=False,
            )
        )
        if len(rows) > EXPECTED_BILINGUAL_CASES:
            raise ValueError("bilingual corpus has too many cases")
    validate_bilingual_corpus(rows)
    return rows


def validate_bilingual_corpus(cases: Iterable[BilingualPersonaCaseV1]) -> None:
    rows = tuple(cases)
    identifiers = [row.case_id for row in rows]
    receipts = [row.review_receipt_id for row in rows]
    if len(rows) != EXPECTED_BILINGUAL_CASES or len(set(identifiers)) != EXPECTED_BILINGUAL_CASES:
        raise ValueError("bilingual corpus requires 280 unique reviewed cases")
    if len(set(receipts)) != len(receipts):
        raise ValueError("bilingual corpus review receipts must be unique")
    family = [case for case in rows if case.persona.role != "guest"]
    guest = [case for case in rows if case.persona.role == "guest"]
    if len(family) != EXPECTED_FAMILY_CASES or len(guest) != EXPECTED_GUEST_CASES:
        raise ValueError("bilingual corpus requires 240 family and 40 guest cases")
    input_classes = {turn.expected.input_class for case in family for turn in case.turns}
    if input_classes != {"english", "hindi_devanagari", "hindi_romanized", "mixed"}:
        raise ValueError("bilingual family corpus must cover all four input classes")
    counts = Counter(turn.expected.input_class for case in rows for turn in case.turns)
    if counts["hindi_romanized"] < 60 or counts["mixed"] < 60:
        raise ValueError("bilingual corpus lacks reviewed romanized or mixed coverage")
    distinct_romanized = {
        turn.user_text
        for case in rows
        for turn in case.turns
        if turn.expected.input_class == "hindi_romanized"
    }
    distinct_mixed = {
        turn.user_text
        for case in rows
        for turn in case.turns
        if turn.expected.input_class == "mixed"
    }
    if len(distinct_romanized) < 60 or len(distinct_mixed) < 60:
        raise ValueError("bilingual corpus needs distinct romanized and mixed utterances")
    switched = sum(
        len({turn.expected.input_class for turn in case.turns}) > 1 for case in rows
    )
    if switched < 40:
        raise ValueError("bilingual corpus needs 40 within-conversation switches")


def canonical_corpus_bytes(path: Path = CORPUS) -> bytes:
    rows = [case.model_dump(mode="python") for case in build_cases(path)]
    return b"".join(canonical_mapping_bytes(row) + b"\n" for row in rows)


def corpus_sha256(path: Path = CORPUS) -> str:
    return hashlib.sha256(canonical_corpus_bytes(path)).hexdigest()
