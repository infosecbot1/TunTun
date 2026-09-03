from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, cast

from pydantic import Field, model_validator
from tuntun_contracts.base import ContractModel, canonical_mapping_bytes, parse_bounded_json_value

ReplyMode = Literal["en", "hi", "hi_romanized", "hinglish"]
_TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
_HASH_PATTERN = r"^[0-9a-f]{64}$"
_LOCK_MAX_BYTES = 65_536
_ARTIFACT_FILE_MAX_BYTES = 1_073_741_824


class EvaluatorProvisioningError(PermissionError):
    """Raised when pinned evaluator artifacts are absent or not review-approved."""


class SpanLanguageModel(Protocol):
    def predict(self, spans: tuple[str, ...]) -> tuple[tuple[str, int], ...]: ...


@dataclass(frozen=True, slots=True)
class PrivateFileSnapshot:
    path: Path
    sha256: str
    owner: tempfile.TemporaryDirectory[str]


class LanguageEvaluatorLock(ContractModel):
    artifact_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    artifact_sha256: Annotated[str, Field(pattern=_HASH_PATTERN)]
    minimum_span_confidence_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    license: Annotated[str, Field(min_length=1, max_length=256)]
    source_revision: Annotated[str, Field(min_length=1, max_length=256)]
    license_reviewed: bool


class LeakageEvaluatorLock(ContractModel):
    artifact_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    artifact_tree_sha256: Annotated[str, Field(pattern=_HASH_PATTERN)]
    minimum_entailment_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    license: Annotated[str, Field(min_length=1, max_length=256)]
    source_revision: Annotated[str, Field(min_length=1, max_length=256)]
    license_reviewed: bool


class ProvisionedEvaluatorModelLock(ContractModel):
    schema_version: Literal["tuntun.evaluator-model-lock.v1"]
    status: Literal["provisioned"]
    calibration_corpus_sha256: Annotated[str, Field(pattern=_HASH_PATTERN)]
    language: LanguageEvaluatorLock
    leakage: LeakageEvaluatorLock

    @model_validator(mode="after")
    def artifacts_are_reviewed(self) -> ProvisionedEvaluatorModelLock:
        if not self.language.license_reviewed or not self.leakage.license_reviewed:
            raise ValueError("evaluator artifact license review is required")
        return self


class BlockedEvaluatorModelLock(ContractModel):
    schema_version: Literal["tuntun.evaluator-model-lock.v1"]
    status: Literal["blocked_missing_local_artifacts"]
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    required_artifacts: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = Field(
        min_length=2,
        max_length=8,
    )

    @model_validator(mode="before")
    @classmethod
    def arrays_from_json_rows_are_tuples(cls, value: Any) -> Any:
        if isinstance(value, dict) and type(value.get("required_artifacts")) is list:
            updated = dict(value)
            updated["required_artifacts"] = tuple(updated["required_artifacts"])
            return updated
        return value


def read_evaluator_model_lock(lock_path: Path) -> ProvisionedEvaluatorModelLock:
    raw = _read_canonical_control_file(Path(lock_path), max_bytes=_LOCK_MAX_BYTES)
    parsed = parse_bounded_json_value(raw, max_bytes=_LOCK_MAX_BYTES)
    if not isinstance(parsed, dict):
        raise ValueError("evaluator lock root must be an object")
    status = parsed.get("status")
    if status == "blocked_missing_local_artifacts":
        lock = BlockedEvaluatorModelLock.model_validate(parsed, strict=True)
        raise EvaluatorProvisioningError(lock.reason)
    if status != "provisioned":
        raise ValueError("evaluator lock status invalid")
    return ProvisionedEvaluatorModelLock.model_validate_json(raw, strict=True)


def canonical_json_file_sha256(path: Path, *, max_bytes: int = _LOCK_MAX_BYTES) -> str:
    raw = _read_canonical_control_file(Path(path), max_bytes=max_bytes)
    return hashlib.sha256(raw).hexdigest()


def _read_canonical_control_file(path: Path, *, max_bytes: int) -> bytes:
    if type(max_bytes) is not int or not 1 <= max_bytes <= _LOCK_MAX_BYTES:
        raise ValueError("invalid evaluator control file bound")
    raw = read_regular_file_bytes(Path(path), max_bytes=max_bytes, label="evaluator control file")
    if not 1 <= len(raw) <= max_bytes:
        raise ValueError("evaluator control file size invalid")
    parsed = parse_bounded_json_value(raw, max_bytes=max_bytes)
    if not isinstance(parsed, dict):
        raise ValueError("evaluator control file root must be an object")
    if canonical_mapping_bytes(parsed) != raw:
        raise ValueError("evaluator control file must be canonical JSON")
    return raw


def _resolve_artifact_path(lock_path: Path, artifact_path: str) -> Path:
    candidate = Path(artifact_path)
    if not candidate.is_absolute():
        candidate = lock_path.parent / candidate
    return candidate


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(
        read_regular_file_bytes(
            path,
            max_bytes=_ARTIFACT_FILE_MAX_BYTES,
            label="evaluator artifact",
        )
    )
    return digest.hexdigest()


def snapshot_file_artifact(path: Path, *, expected_sha256: str) -> PrivateFileSnapshot:
    _require_sha256(expected_sha256, name="language artifact sha256")
    payload = read_regular_file_bytes(
        path,
        max_bytes=_ARTIFACT_FILE_MAX_BYTES,
        label="evaluator artifact",
    )
    observed = hashlib.sha256(payload).hexdigest()
    if observed != expected_sha256:
        raise EvaluatorProvisioningError("language judge artifact digest mismatch")
    owner: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(
        prefix="tuntun-eval-language-"
    )
    try:
        snapshot_path = Path(owner.name) / Path(path).name
        _write_private_bytes(snapshot_path, payload)
    except BaseException:
        owner.cleanup()
        raise
    return PrivateFileSnapshot(snapshot_path, observed, owner)


def _write_private_bytes(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
    finally:
        os.close(descriptor)


def read_regular_file_bytes(path: Path, *, max_bytes: int, label: str) -> bytes:
    if type(max_bytes) is not int or not 1 <= max_bytes <= _ARTIFACT_FILE_MAX_BYTES:
        raise ValueError(f"invalid {label} bound")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise EvaluatorProvisioningError(f"{label} is not provisioned: {path}") from None
    except OSError:
        raise EvaluatorProvisioningError(f"unsafe {label}") from None
    try:
        before = os.fstat(descriptor)
        named_before = os.stat(path, follow_symlinks=False)
        _require_safe_file(before, named_before, label=label)
        if not 1 <= before.st_size <= max_bytes:
            raise EvaluatorProvisioningError(f"{label} size invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1_048_576, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise EvaluatorProvisioningError(f"{label} size invalid")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(path, follow_symlinks=False)
        if (
            total != before.st_size
            or _stable_identity(before) != _stable_identity(after)
            or (before.st_dev, before.st_ino) != (named_before.st_dev, named_before.st_ino)
            or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
        ):
            raise EvaluatorProvisioningError(f"unsafe {label}")
        _require_safe_file(after, named_after, label=label)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_safe_file(opened: os.stat_result, named: os.stat_result, *, label: str) -> None:
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_uid not in {0, os.geteuid()}
        or opened.st_mode & 0o022
        or opened.st_nlink != 1
    ):
        raise EvaluatorProvisioningError(f"unsafe {label}")


def _stable_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def enable_offline_evaluator_runtime() -> None:
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_DATASETS_OFFLINE"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"


class FastTextSpanModel:
    def __init__(
        self,
        artifact: Path,
        snapshot_owner: tempfile.TemporaryDirectory[str] | None = None,
    ) -> None:
        enable_offline_evaluator_runtime()
        try:
            import fasttext  # type: ignore[import-not-found]
        except ImportError as error:
            raise EvaluatorProvisioningError("fasttext runtime is not provisioned") from error

        self._snapshot_owner = snapshot_owner
        self._model = fasttext.load_model(str(artifact))

    def predict(self, spans: tuple[str, ...]) -> tuple[tuple[str, int], ...]:
        predictions: list[tuple[str, int]] = []
        for span in spans:
            labels, probabilities = self._model.predict(span.replace("\n", " "), k=1)
            predictions.append(
                (labels[0].removeprefix("__label__"), round(probabilities[0] * 1_000_000))
            )
        return tuple(predictions)


class PinnedLanguageJudge:
    def __init__(
        self,
        model: SpanLanguageModel,
        *,
        threshold_micros: int,
        artifact_sha256: str,
    ) -> None:
        if type(threshold_micros) is not int or not 0 <= threshold_micros <= 1_000_000:
            raise ValueError("invalid language threshold")
        _require_sha256(artifact_sha256, name="language artifact sha256")
        self._model = model
        self._threshold = threshold_micros
        self.artifact_sha256 = artifact_sha256

    @classmethod
    def from_lock(cls, lock_path: str | Path) -> PinnedLanguageJudge:
        enable_offline_evaluator_runtime()
        lock_file = Path(lock_path)
        lock = read_evaluator_model_lock(lock_file)
        artifact = _resolve_artifact_path(lock_file, lock.language.artifact_path)
        snapshot = snapshot_file_artifact(
            artifact,
            expected_sha256=lock.language.artifact_sha256,
        )
        return cls(
            FastTextSpanModel(snapshot.path, snapshot.owner),
            threshold_micros=lock.language.minimum_span_confidence_micros,
            artifact_sha256=snapshot.sha256,
        )

    def classify(self, answer: str) -> ReplyMode:
        if type(answer) is not str:
            raise TypeError("answer must be an exact str")
        tokens = _TOKEN.findall(answer)
        if not tokens:
            raise ValueError("language judge requires text")
        spans = _spans(tokens)
        accepted = [
            _normalize_label(label)
            for label, confidence in self._model.predict(spans)
            if confidence >= self._threshold and _normalize_label(label) is not None
        ]
        if not accepted:
            raise ValueError("language judge below calibrated confidence")
        counts = Counter(cast(str, label) for label in accepted)
        hindi_latin = counts["hin_Latn"]
        hindi_deva = counts["hin_Deva"]
        english = counts["eng_Latn"]
        hindi = hindi_latin + hindi_deva
        if english and hindi and _is_balanced_switch(english, hindi):
            return "hinglish"
        if hindi_deva >= max(hindi_latin, english):
            return "hi"
        if hindi_latin >= english:
            return "hi_romanized"
        return "en"


def _spans(tokens: list[str]) -> tuple[str, ...]:
    if len(tokens) <= 3:
        return (" ".join(tokens),)
    spans: list[str] = []
    for index in range(0, len(tokens), 2):
        chunk = tokens[index : index + 3]
        if len(chunk) < 2 and spans:
            break
        spans.append(" ".join(chunk))
    return tuple(spans)


def _normalize_label(label: str) -> str | None:
    if label in {"eng_Latn", "hin_Latn", "hin_Deva"}:
        return label
    if label == "en":
        return "eng_Latn"
    if label in {"hi", "hi_romanized"}:
        return "hin_Latn"
    if label == "hinglish":
        return "eng_Latn"
    return None


def _is_balanced_switch(english: int, hindi: int) -> bool:
    total = english + hindi
    return total < 4 or min(english, hindi) / total >= 0.20


def _require_sha256(value: object, *, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"invalid {name}")
