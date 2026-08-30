#!/usr/bin/env python3
"""Fail-closed integrity checks for the Conversation/Reachy execution plan."""

from __future__ import annotations

import argparse
import ast
import contextlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as element_tree
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent

try:
    from scripts.materialize_conversation_plan import (
        MaterializationError,
        PlanDocument,
        Snippet,
        foundation_snapshot_from_ref,
        materialize_document,
        plan_document_from_ref,
        run_materialized_python,
        write_materialized_tree,
    )
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from materialize_conversation_plan import (  # type: ignore[import-not-found,no-redef]
        MaterializationError,
        PlanDocument,
        Snippet,
        foundation_snapshot_from_ref,
        materialize_document,
        plan_document_from_ref,
        run_materialized_python,
        write_materialized_tree,
    )


FOUNDATION_MIGRATION_PATHS = (
    "apps/core/src/tuntun_core/adapters/sqlcipher/engine.py",
    "apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py",
    "tests/integration/storage/test_migrations.py",
)
FOUNDATION_REVISION_PATH = "apps/core/migrations/versions/0001_foundation.py"
PYTEST_FIXTURES = {
    "cache",
    "capfd",
    "capfdbinary",
    "caplog",
    "capsys",
    "capsysbinary",
    "doctest_namespace",
    "monkeypatch",
    "pytestconfig",
    "record_property",
    "record_testsuite_property",
    "record_xml_attribute",
    "recwarn",
    "request",
    "tmp_path",
    "tmp_path_factory",
    "tmpdir",
    "tmpdir_factory",
}
MODEL_KEYS = {
    "id",
    "revision",
    "license",
    "provenance",
    "redistribution",
    "approved_purpose",
    "runtime",
    "architecture",
    "input_contract",
    "output_contract",
    "benchmark_gate",
    "review_date",
    "files",
}
MODEL_FILE_KEYS = {"path", "size", "sha256", "url"}
BILINGUAL_SCHEMA_ID = "https://tuntun.local/schemas/bilingual-persona-score-v1.schema.json"
BILINGUAL_REPORT_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_commit",
        "model_id",
        "prompt_bundle_sha256",
        "policy_sha256",
        "corpus_sha256",
        "scorer_sha256",
        "evaluator_model_lock_sha256",
        "calibration_corpus_sha256",
        "child_safety_corpus_sha256",
        "evaluator_license",
        "evaluator_artifacts_sha256",
        "verification_key_sha256",
        "calibration_evidence_sha256",
        "result_manifest_paths",
        "result_manifest_sha256",
        "ordered_case_ids_sha256",
        "aggregates",
        "signer_key_id",
        "signature_domain",
        "signature_purpose",
        "issued_at",
        "expires_at",
        "signature_b64",
    }
)
BILINGUAL_DIRECT_HASH_FIELDS = frozenset(
    {
        "prompt_bundle_sha256",
        "policy_sha256",
        "corpus_sha256",
        "scorer_sha256",
        "evaluator_model_lock_sha256",
        "calibration_corpus_sha256",
        "child_safety_corpus_sha256",
        "verification_key_sha256",
        "calibration_evidence_sha256",
        "ordered_case_ids_sha256",
    }
)
NON_AUTHORIZATION_MARKERS = {
    "asyncio",
    "filterwarnings",
    "parametrize",
    "skip",
    "skipif",
    "usefixtures",
}
MODEL_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
REVISION = re.compile(r"^[0-9a-f]{40,64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
FILE_PATH = re.compile(r"^[A-Za-z0-9_.-]+\.(?:onnx|json|txt|tflite|safetensors)$")
FORBIDDEN_FIXTURE_TYPES = {
    "Any",
    "SimpleNamespace",
    "dict",
    "list",
    "object",
    "tuple",
}
BUILTIN_CONCRETE_TYPES = {"bool", "bytes", "float", "int", "Path", "str"}


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"invalid or duplicate key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def approved_skip_marker_names(marker_names: tuple[str, ...]) -> bool:
    """A skipped test must be in exactly one explicit external-evidence lane."""

    return marker_names in (("reachy_hardware",), ("live_cloud",))


def validate_model_manifest_bytes(content: bytes) -> list[str]:
    """Apply the Foundation manifest schema and runtime-loader semantics."""

    errors: list[str] = []
    if len(content) > 1_048_576:
        return ["model manifest exceeds the 1 MiB parser bound"]
    try:
        depth = 0
        for count, event in enumerate(yaml.parse(content), start=1):
            if count > 16_384 or isinstance(event, AliasEvent):
                raise ValueError("alias or event bound violation")
            if getattr(event, "tag", None) is not None:
                raise ValueError("explicit YAML tags are forbidden")
            if isinstance(event, CollectionStartEvent):
                depth += 1
                if depth > 32:
                    raise ValueError("YAML nesting exceeds 32")
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
        if depth != 0:
            raise ValueError("unbalanced YAML collection")
        document = yaml.load(content, Loader=_UniqueKeyLoader)
    except (UnicodeDecodeError, TypeError, ValueError, yaml.YAMLError) as error:
        return [f"invalid model manifest YAML: {error}"]
    if type(document) is not dict or set(document) != {"schema_version", "models"}:
        return ["model manifest root keys are not closed"]
    if type(document.get("schema_version")) is not str or document.get("schema_version") != "1.0":
        errors.append("model manifest schema_version must be the string '1.0'")
    if type(document.get("models")) is not list or not 0 <= len(document.get("models", ())) <= 256:
        return ["model manifest version/models shape is invalid"]
    model_ids: list[str] = []
    for model_index, model in enumerate(document["models"]):
        if type(model) is not dict:
            errors.append(f"model {model_index} is not an object")
            continue
        if set(model) != MODEL_KEYS:
            errors.append(
                f"model {model_index} model keys are not closed: {sorted(set(model) ^ MODEL_KEYS)}"
            )
        scalar_fields = tuple(MODEL_KEYS - {"files"})
        for field in scalar_fields:
            value = model.get(field)
            if type(value) is not str or not value or len(value) > 4096:
                errors.append(f"model {model_index} {field} must be a non-empty string")
        model_id = model.get("id")
        revision = model.get("revision")
        if type(model_id) is not str or MODEL_ID.fullmatch(model_id) is None:
            errors.append(f"model {model_index} id is invalid")
        else:
            model_ids.append(model_id)
        if type(revision) is not str or REVISION.fullmatch(revision) is None:
            errors.append(f"model {model_index} revision is not immutable")
        files = model.get("files")
        if type(files) is not list or not 1 <= len(files) <= 64:
            errors.append(f"model {model_index} files is not a list")
            continue
        file_paths: list[str] = []
        total_size = 0
        for file_index, file_record in enumerate(files):
            if type(file_record) is not dict or set(file_record) != MODEL_FILE_KEYS:
                actual = set(file_record) if type(file_record) is dict else set()
                errors.append(
                    f"model {model_index} file {file_index} file keys are not closed: "
                    f"{sorted(actual ^ MODEL_FILE_KEYS)}"
                )
                continue
            path = file_record.get("path")
            size = file_record.get("size")
            digest = file_record.get("sha256")
            url = file_record.get("url")
            if (
                type(path) is not str
                or FILE_PATH.fullmatch(path) is None
                or Path(path).name != path
                or len(path) > 255
            ):
                errors.append(f"model {model_index} file {file_index} path is invalid")
            else:
                file_paths.append(path)
            if type(size) is not int or not 1 <= size <= 4_000_000_000:
                errors.append(f"model {model_index} file {file_index} size is invalid")
            else:
                total_size += size
            if type(digest) is not str or DIGEST.fullmatch(digest) is None:
                errors.append(f"model {model_index} file {file_index} sha256 is invalid")
            if type(url) is not str or _unsafe_model_url(url):
                errors.append(f"model {model_index} file {file_index} URL is invalid or private")
        if len(file_paths) != len(set(file_paths)):
            errors.append(f"model {model_index} file paths are duplicated")
        if total_size > 8_000_000_000:
            errors.append(f"model {model_index} aggregate size exceeds 8 GB")
    if len(model_ids) != len(set(model_ids)):
        errors.append("model IDs are duplicated")
    return errors


def _unsafe_model_url(value: str) -> bool:
    if not 9 <= len(value) <= 4096:
        return True
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return True
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        return True
    host = parsed.hostname.casefold().rstrip(".")
    if (
        host in {"localhost"}
        or host.endswith((".local", ".localhost", ".internal", ".invalid"))
        or ":" in host
    ):
        return True
    try:
        decoded_path = unquote(parsed.path, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return True
    if (
        any(ord(character) < 32 or ord(character) == 127 for character in value)
        or "\\" in decoded_path
        or any(part in {".", ".."} for part in decoded_path.split("/"))
    ):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        return (
            len(labels) < 2
            or len(host) > 253
            or any(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
                for label in labels
            )
        )
    return not address.is_global


def _expected_bilingual_schema() -> dict[str, object]:
    fields = (
        "schema_version",
        "candidate_commit",
        "model_id",
        "prompt_bundle_sha256",
        "policy_sha256",
        "corpus_sha256",
        "scorer_sha256",
        "evaluator_model_lock_sha256",
        "calibration_corpus_sha256",
        "child_safety_corpus_sha256",
        "evaluator_license",
        "evaluator_artifacts_sha256",
        "verification_key_sha256",
        "calibration_evidence_sha256",
        "result_manifest_paths",
        "result_manifest_sha256",
        "ordered_case_ids_sha256",
        "aggregates",
        "signer_key_id",
        "signature_domain",
        "signature_purpose",
        "issued_at",
        "expires_at",
        "signature_b64",
    )
    aggregate_fields = (
        "bilingual_total",
        "bilingual_language_ok",
        "child_adversarial_total",
        "child_adversarial_safe",
        "child_benign_total",
        "child_benign_appropriate",
        "role_mismatches",
        "relevance_failures",
        "word_cap_failures",
        "boundary_failures",
        "leaked_claims",
        "child_search_action_memory_attempts",
    )

    def titled(name: str, **values: object) -> dict[str, object]:
        return {**values, "title": name.replace("_", " ").title()}

    properties = {name: titled(name, type="string") for name in fields}
    properties["schema_version"] = {
        "const": "tuntun.bilingual-persona-score.v1",
        "title": "Schema Version",
        "type": "string",
    }
    properties["candidate_commit"] = titled(
        "candidate_commit", pattern="^[0-9a-f]{40}$", type="string"
    )
    properties["model_id"] = titled("model_id", minLength=1, maxLength=128, type="string")
    for name in BILINGUAL_DIRECT_HASH_FIELDS:
        properties[name] = titled(name, pattern="^[0-9a-f]{64}$", type="string")
    properties["evaluator_license"] = titled(
        "evaluator_license",
        enum=["MIT", "Apache-2.0", "CC-BY-4.0"],
        type="string",
    )
    properties["evaluator_artifacts_sha256"] = titled(
        "evaluator_artifacts_sha256",
        items={"type": "string"},
        minItems=2,
        maxItems=8,
        type="array",
    )
    properties["result_manifest_paths"] = titled(
        "result_manifest_paths",
        items={"format": "path", "type": "string"},
        minItems=2,
        maxItems=8,
        type="array",
    )
    properties["result_manifest_sha256"] = titled(
        "result_manifest_sha256",
        items={"type": "string"},
        minItems=2,
        maxItems=8,
        type="array",
    )
    properties["aggregates"] = {"$ref": "#/$defs/RecomputedAggregates"}
    properties["signer_key_id"] = titled("signer_key_id", minLength=1, maxLength=128, type="string")
    properties["signature_domain"] = {
        "const": "tuntun.bilingual-persona-score.v1",
        "title": "Signature Domain",
        "type": "string",
    }
    properties["signature_purpose"] = {
        "const": "phase1_release_acceptance",
        "title": "Signature Purpose",
        "type": "string",
    }
    properties["issued_at"] = titled("issued_at", format="date-time", type="string")
    properties["expires_at"] = titled("expires_at", format="date-time", type="string")
    properties["signature_b64"] = titled("signature_b64", minLength=88, maxLength=88, type="string")
    return {
        "$defs": {
            "RecomputedAggregates": {
                "additionalProperties": False,
                "properties": {name: titled(name, type="integer") for name in aggregate_fields},
                "required": list(aggregate_fields),
                "title": "RecomputedAggregates",
                "type": "object",
            }
        },
        "$id": BILINGUAL_SCHEMA_ID,
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": list(fields),
        "title": "BilingualScoreReportV1",
        "type": "object",
    }


def validate_bilingual_schema_bytes(content: bytes) -> list[str]:
    """Validate the exact pinned-Pydantic report-schema contract."""

    if len(content) > 1_048_576:
        return ["bilingual report schema exceeds the 1 MiB bound"]
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, ValueError) as error:
        return [f"bilingual report schema is invalid JSON: {error}"]
    if type(document) is not dict:
        return ["bilingual report schema root is not an object"]
    errors: list[str] = []
    if document != _expected_bilingual_schema():
        errors.append(
            "bilingual report schema does not exactly match nested fields, bounds, "
            "$defs, lifecycle arrays, aggregates, and signature semantics"
        )
    canonical = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
    )
    if content != canonical:
        errors.append("bilingual report schema bytes are not canonical")
    return errors


_BILINGUAL_REPORT_MODEL_PROBE = r"""import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from evals.verify_bilingual_report import BilingualScoreReportV1

digest = "a" * 64
issued = datetime(2026, 8, 27, tzinfo=timezone.utc)
good = {
    "schema_version": "tuntun.bilingual-persona-score.v1",
    "candidate_commit": "b" * 40,
    "model_id": "candidate-v1",
    "prompt_bundle_sha256": digest,
    "policy_sha256": digest,
    "corpus_sha256": digest,
    "scorer_sha256": digest,
    "evaluator_model_lock_sha256": digest,
    "calibration_corpus_sha256": digest,
    "child_safety_corpus_sha256": digest,
    "evaluator_license": "Apache-2.0",
    "evaluator_artifacts_sha256": (digest, "b" * 64),
    "verification_key_sha256": digest,
    "calibration_evidence_sha256": digest,
    "result_manifest_paths": (Path("first.json"), Path("second.json")),
    "result_manifest_sha256": (digest, "b" * 64),
    "ordered_case_ids_sha256": digest,
    "aggregates": {
        "bilingual_total": 280,
        "bilingual_language_ok": 280,
        "child_adversarial_total": 360,
        "child_adversarial_safe": 360,
        "child_benign_total": 120,
        "child_benign_appropriate": 120,
        "role_mismatches": 0,
        "relevance_failures": 0,
        "word_cap_failures": 0,
        "boundary_failures": 0,
        "leaked_claims": 0,
        "child_search_action_memory_attempts": 0,
    },
    "signer_key_id": "bilingual-report-ed25519-v1",
    "signature_domain": "tuntun.bilingual-persona-score.v1",
    "signature_purpose": "phase1_release_acceptance",
    "issued_at": issued,
    "expires_at": issued + timedelta(hours=24),
    "signature_b64": "A" * 88,
}
BilingualScoreReportV1.model_validate(good)

faults = []
value = copy.deepcopy(good)
value["issued_at"] = value["issued_at"].replace(tzinfo=None)
faults.append(value)
value = copy.deepcopy(good)
value["expires_at"] = value["expires_at"].replace(tzinfo=None)
faults.append(value)
value = copy.deepcopy(good)
value["expires_at"] = issued
faults.append(value)
value = copy.deepcopy(good)
value["expires_at"] = issued + timedelta(seconds=86401)
faults.append(value)
value = copy.deepcopy(good)
value["result_manifest_sha256"] = (digest,)
faults.append(value)
value = copy.deepcopy(good)
value["result_manifest_paths"] = (Path("same.json"), Path("same.json"))
faults.append(value)
value = copy.deepcopy(good)
value["signature_b64"] = "A" * 87
faults.append(value)
value = copy.deepcopy(good)
value["evaluator_artifacts_sha256"] = (digest,)
faults.append(value)
value = copy.deepcopy(good)
value["aggregates"]["bilingual_total"] = True
faults.append(value)
value = copy.deepcopy(good)
value["aggregates"]["caller_passed"] = True
faults.append(value)

for index, candidate in enumerate(faults):
    try:
        BilingualScoreReportV1.model_validate(candidate)
    except (TypeError, ValueError):
        continue
    raise AssertionError(f"report model accepted controlled lifecycle/signature fault {index}")
"""


def validate_bilingual_report_model_files(files: dict[str, bytes]) -> list[str]:
    """Execute the delivered strict report model against lifecycle/signature faults."""

    path = "evals/verify_bilingual_report.py"
    if path not in files:
        return [f"bilingual report runtime model is absent: {path}"]
    try:
        tree = ast.parse(files[path].decode("utf-8"), filename=path)
    except (SyntaxError, UnicodeDecodeError) as error:
        return [f"bilingual report runtime model is invalid: {error}"]
    report_class = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "BilingualScoreReportV1"
        ),
        None,
    )
    lifecycle = next(
        (
            node
            for node in (report_class.body if report_class is not None else ())
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "lifecycle"
        ),
        None,
    )
    checks_expiry_timezone = lifecycle is not None and any(
        isinstance(node, ast.Attribute)
        and node.attr == "tzinfo"
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "expires_at"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "self"
        for node in ast.walk(lifecycle)
    )
    if not checks_expiry_timezone:
        return ["bilingual report runtime model does not explicitly reject naive expires_at"]
    with tempfile.TemporaryDirectory(prefix="tuntun-bilingual-report-model-") as temporary:
        root = Path(temporary)
        write_materialized_tree(root, files)
        probe = root / ".bilingual-report-model-probe.py"
        probe.write_text(_BILINGUAL_REPORT_MODEL_PROBE, encoding="utf-8")
        try:
            result = run_materialized_python((probe.name, str(root)), root=root, timeout_seconds=15)
        except subprocess.TimeoutExpired:
            return ["bilingual report runtime behavioral probe exceeded 15 seconds"]
    if result.returncode == 0:
        return []
    diagnostic = result.diagnostic[-4096:].decode(errors="replace")
    return [f"bilingual report runtime behavioral probe failed: {diagnostic}"]


def validate_wake_benchmark_bytes(
    content: bytes, *, materialized_files: dict[str, bytes] | None = None
) -> list[str]:
    """Execute benchmark main and mutation-probe the delivered production pipeline."""

    benchmark_path = "tests/hardware/bench_wakeword.py"
    try:
        source = content.decode("utf-8")
        tree = ast.parse(source, filename=benchmark_path)
    except (UnicodeDecodeError, SyntaxError) as error:
        return [f"benchmark source is invalid: {error}"]
    if any(isinstance(node, ast.BitXor) for node in ast.walk(tree)):
        return ["benchmark contains XOR inference"]
    if any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "cm4" in node.value.casefold()
        for node in ast.walk(tree)
    ):
        return ["benchmark contains guessed CM4 identity"]
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if any(
        name not in functions or not _meaningful_function(functions[name])
        for name in ("run_benchmark", "main")
    ):
        return ["behavioral probe requires executable run_benchmark and main callables"]
    required_imports = {
        "tuntun_edge.audio.converter": "StreamingAudioConverter",
        "tuntun_edge.audio.wakeword": "WakeDetector",
        "tuntun_core.services.models.registry": "ModelRegistry",
    }
    imported = {
        (node.module, alias.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
        for alias in node.names
    }
    missing_imports = [
        f"{module}.{name}"
        for module, name in required_imports.items()
        if (module, name) not in imported
    ]
    if missing_imports:
        return [
            "behavioral probe requires the delivered production pipeline imports: "
            f"{missing_imports}"
        ]
    if materialized_files is None:
        return ["behavioral probe requires materialized delivered production pipeline files"]
    required_paths = {
        benchmark_path,
        "apps/edge/src/tuntun_edge/audio/converter.py",
        "apps/edge/src/tuntun_edge/audio/wakeword.py",
        "apps/core/src/tuntun_core/services/models/registry.py",
    }
    absent = sorted(required_paths - set(materialized_files))
    if absent:
        return [f"behavioral probe delivered production pipeline files are absent: {absent}"]

    try:
        converter_tree = ast.parse(
            materialized_files["apps/edge/src/tuntun_edge/audio/converter.py"].decode("utf-8")
        )
    except (SyntaxError, UnicodeDecodeError) as error:
        return [f"production-faithful async converter is invalid: {error}"]
    converter_class = next(
        (
            node
            for node in converter_tree.body
            if isinstance(node, ast.ClassDef) and node.name == "StreamingAudioConverter"
        ),
        None,
    )
    converter_method = next(
        (
            node
            for node in (converter_class.body if converter_class is not None else ())
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "convert"
        ),
        None,
    )
    converter_args = (
        [argument.arg for argument in converter_method.args.args]
        if converter_method is not None
        else []
    )
    run_benchmark = functions.get("run_benchmark")
    uses_registry_loader = any(
        isinstance(node, ast.Call)
        and _decorator_name(node.func) in {"ModelRegistry.from_document", "ModelRegistry.load"}
        for node in ast.walk(tree)
    )
    main = functions.get("main")
    uses_asyncio_run = main is not None and any(
        isinstance(node, ast.Call) and _decorator_name(node.func) == "asyncio.run"
        for node in ast.walk(main)
    )
    if (
        converter_args != ["self", "audio", "source", "target"]
        or not isinstance(run_benchmark, ast.AsyncFunctionDef)
        or not uses_registry_loader
        or not uses_asyncio_run
    ):
        return [
            "behavioral probe requires a production-faithful async converter, "
            "locked ModelRegistry loader, runtime inference path, and asyncio main"
        ]

    baseline_files = dict(materialized_files)
    baseline_files[benchmark_path] = content

    def execute(candidate: dict[str, bytes], label: str) -> tuple[bool, str]:
        with tempfile.TemporaryDirectory(prefix=f"tuntun-wake-{label}-") as temporary:
            root = Path(temporary)
            write_materialized_tree(root, candidate)
            try:
                result = run_materialized_python(
                    (
                        benchmark_path,
                        "--frames",
                        "4",
                        "--max-one-core-percent",
                        "25",
                    ),
                    root=root,
                    timeout_seconds=15,
                )
            except subprocess.TimeoutExpired:
                return False, "exceeded 15 seconds"
        diagnostic = result.diagnostic[-4096:].decode(errors="replace")
        return result.returncode == 0, f"exit {result.returncode}: {diagnostic}"

    passed, diagnostic = execute(baseline_files, "baseline")
    if not passed:
        return [f"behavioral probe failed to execute benchmark main: {diagnostic}"]
    errors: list[str] = []
    mutations = (
        (benchmark_path, None, "run_benchmark", "return {}"),
        (
            "apps/edge/src/tuntun_edge/audio/converter.py",
            "StreamingAudioConverter",
            "convert",
            "return None",
        ),
        (
            "apps/edge/src/tuntun_edge/audio/wakeword.py",
            "WakeDetector",
            "process",
            "return False",
        ),
        (
            "apps/core/src/tuntun_core/services/models/registry.py",
            "ModelRegistry",
            "activate",
            "return None",
        ),
        (
            "apps/core/src/tuntun_core/services/models/registry.py",
            "ActivatedModel",
            "load_with",
            "return None",
        ),
        (
            "apps/core/src/tuntun_core/services/models/registry.py",
            "Adapter",
            "infer",
            "return 900000",
        ),
    )
    for path, class_name, function_name, body in mutations:
        mutated_content = _mutate_function_body(
            baseline_files[path],
            class_name=class_name,
            function_name=function_name,
            body_source=body,
        )
        identity = f"{class_name + '.' if class_name else ''}{function_name}"
        if mutated_content is None:
            errors.append(f"production pipeline interface cannot be probed: {path}:{identity}")
            continue
        candidate = dict(baseline_files)
        candidate[path] = mutated_content
        mutation_passed, _ = execute(candidate, f"mutation-{function_name}")
        if mutation_passed:
            errors.append(
                f"benchmark main accepted controlled mutation of production pipeline "
                f"{path}:{identity}"
            )
    registry_path = "apps/core/src/tuntun_core/services/models/registry.py"
    for attribute_name, replacement in (
        ("model_sha256", repr("f" * 64)),
        ("runtime_sha256", repr("e" * 64)),
    ):
        mutated_content = _mutate_class_attribute(
            baseline_files[registry_path],
            class_name="Adapter",
            attribute_name=attribute_name,
            value_source=replacement,
        )
        if mutated_content is None:
            errors.append(
                "production pipeline hash binding cannot be probed: "
                f"{registry_path}:Adapter.{attribute_name}"
            )
            continue
        candidate = dict(baseline_files)
        candidate[registry_path] = mutated_content
        mutation_passed, _ = execute(candidate, f"mutation-{attribute_name}")
        if mutation_passed:
            errors.append(
                "benchmark main accepted controlled mutation of production pipeline "
                f"hash binding {registry_path}:Adapter.{attribute_name}"
            )
    return errors


def _python_tree(snippet: Snippet, errors: list[str]) -> ast.Module | None:
    if snippet.language not in {"python", "py"} and not snippet.path.endswith(".py"):
        return None
    try:
        return ast.parse(snippet.body.decode(), filename=snippet.path)
    except (SyntaxError, UnicodeDecodeError) as error:
        errors.append(f"Task {snippet.task:02d} {snippet.path}: Python snippet is invalid: {error}")
        return None


def _module_for_path(path: str) -> str | None:
    candidates = (
        "apps/core/src/",
        "apps/edge/src/",
        "packages/contracts/src/",
        "packages/testing/src/",
    )
    for prefix in candidates:
        if path.startswith(prefix) and path.endswith(".py"):
            module = path.removeprefix(prefix).removesuffix(".py").replace("/", ".")
            return module.removesuffix(".__init__")
    if path.startswith("evals/") and path.endswith(".py"):
        return path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
    if path.endswith(".py"):
        return path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
    return None


def _imported_modules(
    tree: ast.Module, *, current_module: str | None, current_is_package: bool
) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                if current_module is None:
                    continue
                module_parts = current_module.split(".")
                package_parts = module_parts if current_is_package else module_parts[:-1]
                ascend = node.level - 1
                if ascend > len(package_parts):
                    continue
                base = package_parts[: len(package_parts) - ascend]
                module = ".".join((*base, module)) if module else ".".join(base)
            if not module:
                continue
            result.add(module)
            result.update(f"{module}.{alias.name}" for alias in node.names if alias.name != "*")
    return result


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _decorator_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _is_fixture(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        _decorator_name(decorator) in {"pytest.fixture", "fixture"}
        for decorator in function.decorator_list
    )


def _parametrized_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if _decorator_name(decorator.func) != "pytest.mark.parametrize" or not decorator.args:
            continue
        first = decorator.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            names.update(part.strip() for part in first.value.split(","))
        elif isinstance(first, (ast.Tuple, ast.List)):
            names.update(
                element.value
                for element in first.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            )
    return names


def _marker_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    names = []
    for decorator in function.decorator_list:
        name = _decorator_name(decorator)
        if name.startswith("pytest.mark."):
            marker = name.removeprefix("pytest.mark.")
            if marker not in NON_AUTHORIZATION_MARKERS:
                names.append(marker)
    return tuple(sorted(names))


def _walk_function_body(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Sequence[ast.AST]:
    nodes: list[ast.AST] = []
    pending: list[ast.AST] = list(reversed(function.body))
    while pending:
        node = pending.pop()
        nodes.append(node)
        if isinstance(
            node,
            (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef, ast.Lambda),
        ):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))
    return nodes


def _has_pytest_skip(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and _decorator_name(node.func) in {
            "pytest.importorskip",
            "pytest.skip",
            "pytest.xfail",
        }:
            return True
    return False


def _has_skip_decorator(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        _decorator_name(decorator)
        in {"pytest.mark.skip", "pytest.mark.skipif", "pytest.mark.xfail"}
        for decorator in function.decorator_list
    )


def _fixture_placeholder_reason(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    if not function.body or all(isinstance(statement, ast.Pass) for statement in function.body):
        return "empty"
    values = _fixture_values(function)
    if not values:
        return "empty"
    for value in values:
        if isinstance(value, ast.Call) and _decorator_name(value.func) == "object":
            return "object"
        if not isinstance(value, ast.Call):
            continue
        if _decorator_name(value.func) != "SimpleNamespace":
            continue
        if not value.args and not value.keywords:
            return "empty namespace"
        keys = {keyword.arg for keyword in value.keywords}
        if not value.args and keys <= {"fixture_name", "name"}:
            return "name-only namespace"
    return None


def _validate_path_parity(document: PlanDocument, errors: list[str]) -> None:
    for task in document.tasks:
        declared = {declaration.path for declaration in task.declarations}
        staged = set(task.staged_paths)
        snippets = {snippet.path for snippet in task.snippets} | {
            generator.output for generator in task.generators
        }
        if declared != staged:
            errors.append(
                f"Task {task.number:02d}: declared/staged path mismatch "
                f"missing={sorted(declared - staged)} extra={sorted(staged - declared)}"
            )
        if declared != snippets:
            errors.append(
                f"Task {task.number:02d}: declared/snippet path mismatch "
                f"missing={sorted(declared - snippets)} extra={sorted(snippets - declared)}"
            )


def _validate_dependencies(document: PlanDocument, errors: list[str]) -> None:
    for task in document.tasks:
        if 3 <= task.number <= 16 and "Foundation Task 13" not in task.depends_on:
            errors.append(f"Task {task.number:02d} must depend on accepted Foundation Task 13")


def _function_has_call(function: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    return any(
        isinstance(node, ast.Call) and _decorator_name(node.func).split(".")[-1] == name
        for node in ast.walk(function)
    )


def _meaningful_function(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return bool(function.body) and not all(
        isinstance(statement, (ast.Pass, ast.Expr))
        and (
            isinstance(statement, ast.Pass)
            or (isinstance(statement.value, ast.Constant) and statement.value.value is Ellipsis)
        )
        for statement in function.body
    )


def _mutate_function_body(
    content: bytes,
    *,
    function_name: str,
    body_source: str,
    class_name: str | None = None,
) -> bytes | None:
    """Return valid Python with exactly one named function body replaced."""

    try:
        tree = ast.parse(content.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return None
    replacement = ast.parse(body_source).body

    class Mutator(ast.NodeTransformer):
        def __init__(self) -> None:
            self.class_stack: list[str] = []
            self.count = 0

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
            self.class_stack.append(node.name)
            self.generic_visit(node)
            self.class_stack.pop()
            return node

        def _replace(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> ast.FunctionDef | ast.AsyncFunctionDef:
            owner = self.class_stack[-1] if self.class_stack else None
            if node.name == function_name and owner == class_name:
                self.count += 1
                node.body = [ast.copy_location(item, node) for item in replacement]
                return node
            self.generic_visit(node)
            return node

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
            return self._replace(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
            return self._replace(node)

    mutator = Mutator()
    mutated = mutator.visit(tree)
    if mutator.count != 1:
        return None
    ast.fix_missing_locations(mutated)
    return (ast.unparse(mutated) + "\n").encode("utf-8")


def _mutate_class_attribute(
    content: bytes,
    *,
    class_name: str,
    attribute_name: str,
    value_source: str,
) -> bytes | None:
    """Replace one concrete class attribute with a controlled value."""

    try:
        tree = ast.parse(content.decode("utf-8"))
        replacement = ast.parse(value_source, mode="eval").body
    except (SyntaxError, UnicodeDecodeError):
        return None
    count = 0
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for statement in node.body:
            assignment_matches = isinstance(statement, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == attribute_name
                for target in statement.targets
            )
            annotated_assignment_matches = (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and statement.target.id == attribute_name
                and statement.value is not None
            )
            if not assignment_matches and not annotated_assignment_matches:
                continue
            if isinstance(statement, ast.Assign):
                statement.value = ast.copy_location(replacement, statement.value)
            else:
                assert isinstance(statement, ast.AnnAssign)
                assert statement.value is not None
                statement.value = ast.copy_location(replacement, statement.value)
            count += 1
    if count != 1:
        return None
    ast.fix_missing_locations(tree)
    return (ast.unparse(tree) + "\n").encode("utf-8")


def _validate_foundation(
    foundation_files: dict[str, bytes], errors: list[str], *, required: bool
) -> None:
    if not required:
        return
    foundation_error_start = len(errors)
    for path in FOUNDATION_MIGRATION_PATHS:
        content = foundation_files.get(path)
        if content is None:
            errors.append(f"Foundation Task 13 capability missing: {path}")
            continue
        if not content.strip():
            errors.append(f"Foundation Task 13 capability is empty: {path}")
    revision_content = foundation_files.get(FOUNDATION_REVISION_PATH)
    if revision_content is None or not revision_content.strip():
        errors.append(
            "Foundation Task 13 real migration downgrade capability missing: "
            f"{FOUNDATION_REVISION_PATH}"
        )
    parsed: dict[str, ast.Module] = {}
    for path in FOUNDATION_MIGRATION_PATHS:
        content = foundation_files.get(path)
        if not content:
            continue
        try:
            parsed[path] = ast.parse(content.decode(), filename=path)
        except (SyntaxError, UnicodeDecodeError) as error:
            errors.append(f"Foundation Task 13 behavioral interface invalid at {path}: {error}")
    if revision_content:
        try:
            parsed[FOUNDATION_REVISION_PATH] = ast.parse(
                revision_content.decode(), filename=FOUNDATION_REVISION_PATH
            )
        except (SyntaxError, UnicodeDecodeError) as error:
            errors.append(
                "Foundation Task 13 real migration downgrade interface invalid at "
                f"{FOUNDATION_REVISION_PATH}: {error}"
            )
    engine_tree = parsed.get(FOUNDATION_MIGRATION_PATHS[0])
    engine_functions = {
        node.name: node
        for node in (engine_tree.body if engine_tree is not None else [])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    engine = engine_functions.get("create_sqlcipher_engine")
    if engine_tree is not None and (
        engine is None
        or not _meaningful_function(engine)
        or [arg.arg for arg in engine.args.args] != ["path", "key"]
        or not _function_has_call(engine, "create_engine")
    ):
        errors.append(
            f"Foundation Task 13 behavioral interface invalid: {FOUNDATION_MIGRATION_PATHS[0]}"
        )
    migration_tree = parsed.get(FOUNDATION_MIGRATION_PATHS[1])
    migration_functions = {
        node.name: node
        for node in (migration_tree.body if migration_tree is not None else [])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name, args, required_call in (
        ("encrypted_backup", ["source", "destination", "key"], "backup"),
        ("upgrade_encrypted", ["path", "key", "backup"], "upgrade"),
    ):
        function = migration_functions.get(name)
        if migration_tree is not None and (
            function is None
            or not _meaningful_function(function)
            or [arg.arg for arg in function.args.args] != args
            or not _function_has_call(function, required_call)
        ):
            errors.append(
                f"Foundation Task 13 behavioral interface invalid: "
                f"{FOUNDATION_MIGRATION_PATHS[1]}:{name}"
            )
    test_tree = parsed.get(FOUNDATION_MIGRATION_PATHS[2])
    tests = [
        node
        for node in (test_tree.body if test_tree is not None else [])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]
    if test_tree is not None and (
        not tests
        or not all(_meaningful_function(function) for function in tests)
        or not any(_function_has_call(function, "upgrade") for function in tests)
        or not any(_function_has_call(function, "downgrade") for function in tests)
        or not any(
            any(isinstance(node, ast.Assert) for node in ast.walk(function)) for function in tests
        )
    ):
        errors.append(
            f"Foundation Task 13 behavioral interface invalid: {FOUNDATION_MIGRATION_PATHS[2]}"
        )
    if test_tree is not None and (
        _has_module_level_skip_or_xfail(test_tree)
        or any(_has_pytest_skip(function) or _has_skip_decorator(function) for function in tests)
    ):
        errors.append("Foundation Task 13 migration integration test contains skip/xfail")
    revision_tree = parsed.get(FOUNDATION_REVISION_PATH)
    revision_functions = {
        node.name: node
        for node in (revision_tree.body if revision_tree is not None else [])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if revision_tree is not None and any(
        name not in revision_functions or not _meaningful_function(revision_functions[name])
        for name in ("upgrade", "downgrade")
    ):
        errors.append(
            "Foundation Task 13 real migration upgrade/downgrade interface invalid: "
            f"{FOUNDATION_REVISION_PATH}"
        )
    if len(errors) == foundation_error_start:
        _run_foundation_behavioral_probe(foundation_files, errors)


def _junit_is_complete_pass(path: Path) -> tuple[bool, str]:
    try:
        root = element_tree.parse(path).getroot()
    except (OSError, element_tree.ParseError) as error:
        return False, f"JUnit evidence is absent or invalid: {error}"
    cases = list(root.iter("testcase"))
    skipped = sum(case.find("skipped") is not None for case in cases)
    failed = sum(
        case.find("failure") is not None or case.find("error") is not None for case in cases
    )
    if not cases or skipped or failed:
        return (
            False,
            f"JUnit evidence tests={len(cases)} skipped={skipped} failed={failed}",
        )
    return True, f"JUnit evidence tests={len(cases)} skipped=0 failed=0"


def _run_foundation_behavioral_probe(foundation_files: dict[str, bytes], errors: list[str]) -> None:
    def execute(candidate: dict[str, bytes], label: str) -> tuple[bool, str]:
        with tempfile.TemporaryDirectory(prefix=f"tuntun-foundation-task13-{label}-") as temporary:
            root = Path(temporary)
            junit = root / ".foundation-task13.junit.xml"
            write_materialized_tree(root, candidate)
            try:
                result = subprocess.run(
                    (
                        sys.executable,
                        "-m",
                        "pytest",
                        "-q",
                        "--maxfail=1",
                        f"--junitxml={junit}",
                        FOUNDATION_MIGRATION_PATHS[2],
                    ),
                    cwd=root,
                    env=_pytest_environment(root),
                    check=False,
                    capture_output=True,
                    timeout=120,
                )
            except subprocess.TimeoutExpired:
                return False, "exceeded 120 seconds"
            complete, junit_diagnostic = _junit_is_complete_pass(junit)
        diagnostic = (result.stdout + result.stderr)[-4096:].decode(errors="replace")
        return (
            result.returncode == 0 and complete,
            f"exit {result.returncode}; {junit_diagnostic}: {diagnostic}",
        )

    passed, diagnostic = execute(foundation_files, "baseline")
    if not passed:
        errors.append(f"Foundation Task 13 behavioral probe failed with {diagnostic}")
        return
    for path, function_name in (
        (FOUNDATION_MIGRATION_PATHS[0], "create_sqlcipher_engine"),
        (FOUNDATION_MIGRATION_PATHS[1], "encrypted_backup"),
        (FOUNDATION_MIGRATION_PATHS[1], "upgrade_encrypted"),
        (FOUNDATION_REVISION_PATH, "upgrade"),
        (FOUNDATION_REVISION_PATH, "downgrade"),
    ):
        mutated_content = _mutate_function_body(
            foundation_files[path],
            function_name=function_name,
            body_source=(f"raise RuntimeError('controlled Foundation mutation: {function_name}')"),
        )
        if mutated_content is None:
            errors.append(
                f"Foundation Task 13 production interface cannot be mutation-probed: "
                f"{path}:{function_name}"
            )
            continue
        mutated = dict(foundation_files)
        mutated[path] = mutated_content
        mutation_passed, _ = execute(mutated, f"mutation-{function_name}")
        if mutation_passed:
            errors.append(
                f"Foundation Task 13 integration test is not behaviorally coupled to "
                f"{path}:{function_name}"
            )


def _validate_import_ownership(
    document: PlanDocument, foundation_files: dict[str, bytes], errors: list[str]
) -> None:
    owners: dict[str, int] = {}
    for path in foundation_files:
        module = _module_for_path(path)
        if module:
            owners[module] = 0
    for task in document.tasks:
        for declaration in task.declarations:
            if declaration.kind not in {"Create", "Test"}:
                continue
            module = _module_for_path(declaration.path)
            if module:
                owners.setdefault(module, task.number)
    for task in document.tasks:
        for snippet in task.snippets:
            tree = _python_tree(snippet, errors)
            if tree is None:
                continue
            for imported in _imported_modules(
                tree,
                current_module=_module_for_path(snippet.path),
                current_is_package=snippet.path.endswith("/__init__.py"),
            ):
                matches = [
                    (module, owner)
                    for module, owner in owners.items()
                    if imported == module or imported.startswith(module + ".")
                ]
                if not matches:
                    continue
                _, owner = max(matches, key=lambda item: len(item[0]))
                if owner > task.number:
                    errors.append(
                        f"Task {task.number:02d} {snippet.path}: forward import {imported} "
                        f"is owned by Task {owner:02d}"
                    )


def _annotation_name(annotation: ast.expr | None) -> str | None:
    if annotation is None:
        return None
    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return None
    if isinstance(annotation, ast.Subscript):
        wrapper = _decorator_name(annotation.value).split(".")[-1]
        if wrapper == "Callable":
            return wrapper
        if wrapper in {
            "Annotated",
            "AsyncGenerator",
            "AsyncIterator",
            "Generator",
            "Iterable",
            "Iterator",
        }:
            inner = (
                annotation.slice.elts[0]
                if isinstance(annotation.slice, ast.Tuple)
                else annotation.slice
            )
            return _annotation_name(inner)
    return _decorator_name(annotation).split(".")[-1] or None


def _fixture_values(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.expr]:
    values: list[ast.expr] = []
    for node in _walk_function_body(function):
        if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) and node.value is not None:
            values.append(node.value)
    return values


def _consumer_member_uses(
    function: ast.FunctionDef | ast.AsyncFunctionDef, fixture_name: str
) -> set[str]:
    return {
        node.attr
        for node in ast.walk(function)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == fixture_name
    }


def _additional_fixture_consumers(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    names: list[str] = []
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if _decorator_name(decorator.func) == "pytest.mark.usefixtures":
            names.extend(
                argument.value
                for argument in decorator.args
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
            )
    for node in ast.walk(function):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "getfixturevalue"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            names.append(node.args[0].value)
    return tuple(names)


def _class_surface(node: ast.ClassDef) -> set[str]:
    surface = {
        child.name
        for child in node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for child in node.body:
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            surface.add(child.target.id)
        elif isinstance(child, ast.Assign):
            surface.update(target.id for target in child.targets if isinstance(target, ast.Name))
    for descendant in ast.walk(node):
        if (
            isinstance(descendant, ast.AnnAssign)
            and isinstance(descendant.target, ast.Attribute)
            and isinstance(descendant.target.value, ast.Name)
            and descendant.target.value.id == "self"
        ):
            surface.add(descendant.target.attr)
        elif isinstance(descendant, ast.Assign):
            for target in descendant.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                ):
                    surface.add(target.attr)
    return surface


def _has_module_level_skip_or_xfail(tree: ast.Module) -> bool:
    for statement in tree.body:
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and _decorator_name(statement.value.func)
            in {"pytest.importorskip", "pytest.skip", "pytest.xfail"}
        ):
            return True
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            values = (
                value.elts
                if isinstance(value, (ast.List, ast.Tuple, ast.Set))
                else ([value] if value is not None else [])
            )
            if any(
                _decorator_name(candidate).startswith(
                    ("pytest.mark.skip", "pytest.mark.skipif", "pytest.mark.xfail")
                )
                for candidate in values
            ):
                return True
    return False


def _literal_string_values(node: ast.expr | None) -> tuple[str, ...]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for item in node.elts:
            if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                return ()
            values.append(item.value)
        return tuple(values)
    return ()


def _pytest_plugin_modules(tree: ast.Module) -> tuple[str, ...]:
    modules: list[str] = []
    for statement in tree.body:
        value: ast.expr | None = None
        targets: tuple[ast.expr, ...] = ()
        if isinstance(statement, ast.Assign):
            value = statement.value
            targets = tuple(statement.targets)
        elif isinstance(statement, ast.AnnAssign):
            value = statement.value
            targets = (statement.target,)
        if any(
            isinstance(target, ast.Name) and target.id == "pytest_plugins" for target in targets
        ):
            modules.extend(_literal_string_values(value))
    return tuple(modules)


def _foundation_fixture_paths(foundation_files: dict[str, bytes]) -> set[str]:
    module_paths = {
        module: path for path in foundation_files if (module := _module_for_path(path)) is not None
    }
    selected = {
        path
        for path in foundation_files
        if path.endswith("conftest.py") and path.startswith("tests/")
    }
    pending = list(selected)
    while pending:
        path = pending.pop()
        try:
            tree = ast.parse(foundation_files[path].decode("utf-8"), filename=path)
        except (SyntaxError, UnicodeDecodeError):
            continue
        for module in _pytest_plugin_modules(tree):
            plugin_path = module_paths.get(module)
            if plugin_path is not None and plugin_path not in selected:
                selected.add(plugin_path)
                pending.append(plugin_path)
    return selected


def _validate_fixtures_and_skips(
    document: PlanDocument, foundation_files: dict[str, bytes], errors: list[str]
) -> None:
    producers: dict[str, list[tuple[int, str, ast.FunctionDef | ast.AsyncFunctionDef]]] = {}
    consumers: list[tuple[str, str, str, set[str]]] = []
    class_surfaces: dict[str, set[str]] = {}
    class_paths: dict[str, set[str]] = {}
    for path, content in foundation_files.items():
        if not path.endswith(".py"):
            continue
        try:
            tree = ast.parse(content.decode("utf-8"), filename=path)
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_surfaces[node.name] = _class_surface(node)
                class_paths.setdefault(node.name, set()).add(path)
    for path in sorted(_foundation_fixture_paths(foundation_files)):
        try:
            tree = ast.parse(foundation_files[path].decode("utf-8"), filename=path)
        except (SyntaxError, UnicodeDecodeError):
            continue
        for function in (
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_fixture(node)
        ):
            producers.setdefault(function.name, []).append((0, path, function))
            reason = _fixture_placeholder_reason(function)
            if reason:
                errors.append(
                    f"Foundation {path}: fixture {function.name} is a placeholder ({reason})"
                )
    for task in document.tasks:
        for snippet in task.snippets:
            snippet_tree = _python_tree(snippet, errors)
            if snippet_tree is None:
                continue
            for node in snippet_tree.body:
                if isinstance(node, ast.ClassDef):
                    class_surfaces[node.name] = _class_surface(node)
                    class_paths.setdefault(node.name, set()).add(snippet.path)
            if _has_module_level_skip_or_xfail(snippet_tree):
                errors.append(
                    f"Task {task.number:02d} {snippet.path}: unapproved module-level "
                    "skip/xfail; external lanes must use an exact item marker"
                )
            for walked in ast.walk(snippet_tree):
                if isinstance(walked, ast.Name) and walked.id == "_NAMES":
                    errors.append(
                        f"Task {task.number:02d} {snippet.path}: "
                        "dynamic fixture name table is forbidden"
                    )
                    break
            for function in (
                node
                for node in snippet_tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                if _is_fixture(function):
                    producers.setdefault(function.name, []).append(
                        (task.number, snippet.path, function)
                    )
                    reason = _fixture_placeholder_reason(function)
                    if reason:
                        errors.append(
                            f"Task {task.number:02d} {snippet.path}: fixture {function.name} "
                            f"is a placeholder ({reason})"
                        )
                is_test = function.name.startswith("test_") and snippet.path.startswith("tests/")
                if _is_fixture(function) or is_test:
                    parametrized = _parametrized_names(function)
                    arguments = (
                        *function.args.posonlyargs,
                        *function.args.args,
                        *function.args.kwonlyargs,
                    )
                    for argument in arguments:
                        if argument.arg not in PYTEST_FIXTURES | parametrized | {"self", "cls"}:
                            consumers.append(
                                (
                                    argument.arg,
                                    snippet.path,
                                    function.name,
                                    _consumer_member_uses(function, argument.arg),
                                )
                            )
                    consumers.extend(
                        (name, snippet.path, function.name, set())
                        for name in _additional_fixture_consumers(function)
                    )
                if _has_pytest_skip(function) or _has_skip_decorator(function):
                    markers = _marker_names(function)
                    if _is_fixture(function) or not approved_skip_marker_names(markers):
                        errors.append(
                            f"Task {task.number:02d} {snippet.path}:{function.name}: "
                            "unapproved pytest skip"
                        )
    consumer_counts = Counter(name for name, _, _, _ in consumers)
    missing = {name for name in consumer_counts if len(producers.get(name, ())) == 0}
    ambiguous = {name for name in consumer_counts if len(producers.get(name, ())) != 1} - missing
    for name in sorted(missing):
        sites = [
            f"{path}:{function}" for candidate, path, function, _ in consumers if candidate == name
        ]
        errors.append(
            f"fixture {name} has 0 explicit producers; fixture consumer missing; "
            f"referenced {consumer_counts[name]} times at {sites}"
        )
    for name in sorted(ambiguous):
        errors.append(
            f"fixture {name} has {len(producers[name])} explicit producers; "
            f"referenced {consumer_counts[name]} times"
        )
    if missing or ambiguous:
        errors.append(
            f"fixture closure failure: {len(consumers)} consumer occurrences; "
            f"{len(missing)} distinct missing producers; "
            f"{len(ambiguous)} distinct ambiguous producers"
        )
    used_members: dict[str, set[str]] = {}
    for name, _, _, members in consumers:
        used_members.setdefault(name, set()).update(members)
    for name, definitions in producers.items():
        for task_number, path, function in definitions:
            annotation = _annotation_name(function.returns)
            values = _fixture_values(function)
            called_types = {
                _decorator_name(value.func).split(".")[-1]
                for value in values
                if isinstance(value, ast.Call)
            }
            if (
                annotation is None
                or annotation in FORBIDDEN_FIXTURE_TYPES
                or (
                    task_number != 0
                    and annotation not in BUILTIN_CONCRETE_TYPES
                    and annotation not in called_types
                )
            ):
                errors.append(
                    f"Task {task_number:02d} {path}: fixture {name} does not return "
                    "a typed concrete harness"
                )
                continue
            annotation_owners = class_paths.get(annotation, set())
            if annotation not in BUILTIN_CONCRETE_TYPES | {"Callable"} and (
                path in annotation_owners
                or not any(not owner.startswith("tests/") for owner in annotation_owners)
            ):
                errors.append(
                    f"Task {task_number:02d} {path}: fixture {name} uses a "
                    "test-local harness instead of wrapping an imported production class"
                )
                continue
            required_members = used_members.get(name, set())
            if not required_members:
                continue
            surface = class_surfaces.get(annotation, set())
            missing_members = required_members - surface
            if annotation in BUILTIN_CONCRETE_TYPES or missing_members:
                absent = sorted(missing_members or required_members)
                errors.append(
                    f"Task {task_number:02d} {path}: fixture {name} typed concrete harness "
                    f"does not implement consumer members {absent}"
                )


def _command_invocations(command: str) -> tuple[tuple[str, ...], ...]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars="&|;")
    lexer.whitespace_split = True
    invocations: list[tuple[str, ...]] = []
    current: list[str] = []
    for word in lexer:
        if word in {"&&", "||", ";"}:
            if current:
                invocations.append(tuple(current))
                current = []
            continue
        current.append(word)
    if current:
        invocations.append(tuple(current))
    return tuple(invocations)


def _unwrap_invocation(invocation: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    words = list(invocation)
    while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
        words.pop(0)
    if not words:
        return "", ()
    if words[0] == "uv":
        if len(words) < 3 or words[1] != "run":
            return "", ()
        words = words[2:]
        options_with_values = {"--directory", "--project", "--python"}
        while words and words[0].startswith("-"):
            option = words.pop(0)
            if option in options_with_values and words:
                words.pop(0)
        if not words:
            return "", ()
    return words[0], tuple(words[1:])


def _pytest_arguments(invocation: tuple[str, ...]) -> tuple[str, ...] | None:
    executable, arguments = _unwrap_invocation(invocation)
    if Path(executable).name == "pytest":
        return arguments
    if Path(executable).name.startswith("python") and arguments[:2] == ("-m", "pytest"):
        return arguments[2:]
    return None


def _pytest_targets(arguments: tuple[str, ...]) -> tuple[str, ...]:
    options_with_values = {
        "--basetemp",
        "--capture",
        "--color",
        "--confcutdir",
        "--durations",
        "--durations-min",
        "--import-mode",
        "--junit-prefix",
        "--junit-xml",
        "--junitxml",
        "--log-level",
        "--maxfail",
        "--override-ini",
        "--rootdir",
        "--tb",
        "-c",
        "-m",
        "-o",
        "-r",
    }
    targets: list[str] = []
    index = 0
    while index < len(arguments):
        word = arguments[index]
        if word == "--":
            targets.extend(arguments[index + 1 :])
            break
        if word in options_with_values:
            index += 2
            continue
        if word.startswith("-"):
            index += 1
            continue
        targets.append(word)
        index += 1
    return tuple(targets)


def _arguments_cover_path(arguments: tuple[str, ...], path: str) -> bool:
    return any(
        "::" not in target and (target == path or path.startswith(target.rstrip("/") + "/"))
        for target in _pytest_targets(arguments)
    )


def _green_command_is_fail_closed(command: str) -> bool:
    lexer = shlex.shlex(command, posix=True, punctuation_chars="&|;")
    lexer.whitespace_split = True
    words = tuple(lexer)
    if any(word in {"||", "|", ";", "&"} for word in words):
        return False
    if any(re.fullmatch(r"(?:PYTEST_ADDOPTS|PYTEST_PLUGINS)=.*", word) for word in words):
        return False
    if any(word in {"--help", "-h"} for word in words):
        return False
    unsafe_pytest_options = {
        "--co",
        "--collect-only",
        "--deselect",
        "--failed-first",
        "--ff",
        "--ignore",
        "--ignore-glob",
        "--last-failed",
        "--lf",
        "--stepwise",
        "--stepwise-skip",
        "--sw",
        "-k",
    }
    for invocation in _command_invocations(command):
        arguments = _pytest_arguments(invocation)
        if arguments is None:
            continue
        if any(
            word in unsafe_pytest_options
            or any(word.startswith(f"{option}=") for option in unsafe_pytest_options)
            for word in arguments
        ):
            return False
    return True


def _python_entry_point_invoked(path: str, invocations: tuple[tuple[str, ...], ...]) -> bool:
    module = path.removesuffix(".py").replace("/", ".")
    for invocation in invocations:
        executable, arguments = _unwrap_invocation(invocation)
        if not Path(executable).name.startswith("python"):
            continue
        if arguments and arguments[0] == path:
            return True
        if arguments[:2] == ("-m", module):
            return True
    return False


def _validate_green_commands(document: PlanDocument, errors: list[str]) -> None:
    for task in document.tasks:
        for command in task.green_commands:
            if not _green_command_is_fail_closed(command):
                errors.append(
                    f"Task {task.number:02d}: green command is not fail-closed: {command}"
                )
        invocations = tuple(
            invocation
            for command in task.green_commands
            for invocation in _command_invocations(command)
        )
        pytest_commands = tuple(
            arguments
            for invocation in invocations
            if (arguments := _pytest_arguments(invocation)) is not None
        )
        for declaration in task.declarations:
            if declaration.kind != "Test":
                continue
            executed_by_pytest = any(
                _arguments_cover_path(arguments, declaration.path) for arguments in pytest_commands
            )
            executed_benchmark = Path(declaration.path).name.startswith(
                "bench_"
            ) and _python_entry_point_invoked(declaration.path, invocations)
            if not executed_by_pytest and not executed_benchmark:
                errors.append(
                    f"Task {task.number:02d}: green command does not execute owned test "
                    f"{declaration.path}"
                )
        for declaration in task.declarations:
            path = declaration.path
            parts = Path(path).parts
            if (
                not path.endswith(".py")
                or not parts
                or parts[0] not in {"evals", "scripts", "tools"}
                or not Path(path).stem.startswith(("check_", "validate_", "verify_"))
            ):
                continue
            if not _python_entry_point_invoked(path, invocations):
                errors.append(
                    f"Task {task.number:02d}: green command does not execute owned "
                    f"critical validator {path}"
                )
        for generator in task.generators:
            matching = [
                arguments
                for invocation in invocations
                for executable, arguments in [_unwrap_invocation(invocation)]
                if Path(executable).name.startswith("python")
                and arguments
                and arguments[0] == generator.entry_point
            ]
            if not matching or not any("--check" in words for words in matching):
                errors.append(
                    f"Task {task.number:02d}: green command does not verify generator "
                    f"{generator.name} with --check"
                )
        if task.number == 12:
            checker = "scripts/check_model_manifest.py"
            manifests = (
                "models/manifest.yaml",
                "apps/core/src/tuntun_core/resources/model-manifest.yaml",
            )
            if not all(
                any(
                    Path(executable).name.startswith("python")
                    and arguments
                    and arguments[0] == checker
                    and path in arguments[1:]
                    for invocation in invocations
                    for executable, arguments in [_unwrap_invocation(invocation)]
                )
                for path in manifests
            ):
                errors.append(
                    "Task 12 green command does not validate both model manifests "
                    "through the strict Foundation loader"
                )
            if not any(
                executable == "/venvs/apps_venv/bin/python3"
                and arguments
                and arguments[0] == "tests/hardware/bench_wakeword.py"
                for invocation in invocations
                for executable, arguments in [_unwrap_invocation(invocation)]
            ):
                errors.append(
                    "Task 12 green command does not run the physical wake benchmark "
                    "with the delivered interpreter"
                )


def _module_path(module: str) -> str:
    return module.replace(".", "/") + ".py"


def _execute_owned_green_commands(
    document: PlanDocument,
    files: dict[str, bytes],
    errors: list[str],
) -> None:
    """Execute materialized Python gates; pytest/external lanes have dedicated probes."""

    with tempfile.TemporaryDirectory(prefix="tuntun-plan-green-commands-") as temporary:
        root = Path(temporary)
        write_materialized_tree(root, files)
        for task in document.tasks:
            for command in task.green_commands:
                if not _green_command_is_fail_closed(command):
                    continue
                for invocation in _command_invocations(command):
                    if any(
                        word.startswith("TUNTUN_ALLOW_REACHY_HARDWARE=")
                        or word.startswith("TUNTUN_ALLOW_LIVE_CLOUD=")
                        for word in invocation
                    ):
                        continue
                    executable, arguments = _unwrap_invocation(invocation)
                    if not Path(executable).name.startswith("python"):
                        continue
                    if arguments[:2] == ("-m", "pytest"):
                        continue
                    if not arguments:
                        continue
                    if arguments[0] == "-m" and len(arguments) >= 2:
                        entry_path = _module_path(arguments[1])
                    else:
                        entry_path = arguments[0]
                    if entry_path not in files:
                        continue
                    try:
                        result = run_materialized_python(
                            arguments,
                            root=root,
                            timeout_seconds=45,
                        )
                    except subprocess.TimeoutExpired:
                        errors.append(
                            f"Task {task.number:02d}: owned green command failed: "
                            f"exceeded 45 seconds: {command}"
                        )
                        continue
                    if result.returncode != 0:
                        diagnostic = result.diagnostic[-4096:].decode(errors="replace")
                        errors.append(
                            f"Task {task.number:02d}: owned green command failed with "
                            f"exit {result.returncode}: {command}: {diagnostic}"
                        )


def _validate_model_and_eval_contracts(
    document: PlanDocument,
    errors: list[str],
    *,
    materialized_files: dict[str, bytes] | None,
) -> None:
    by_number = {task.number: task for task in document.tasks}
    task_12 = by_number.get(12)
    if task_12 is not None:
        declared = {declaration.path for declaration in task_12.declarations}
        for path in (
            "models/manifest.yaml",
            "apps/core/src/tuntun_core/resources/model-manifest.yaml",
        ):
            if path not in declared:
                errors.append(f"Task 12 must declare and stage {path}")
        manifest_paths = (
            "models/manifest.yaml",
            "apps/core/src/tuntun_core/resources/model-manifest.yaml",
        )
        if materialized_files is not None:
            values = tuple(materialized_files.get(path) for path in manifest_paths)
            if any(value is None for value in values):
                errors.append("Task 12 materialized manifests are absent")
            elif values[0] != values[1]:
                errors.append(
                    "Task 12 materialized repository and packaged manifests are not byte identical"
                )
            else:
                manifest_errors = validate_model_manifest_bytes(values[0] or b"")
                errors.extend(f"Task 12 {error}" for error in manifest_errors)
                if not manifest_errors:
                    manifest_content = values[0]
                    assert manifest_content is not None
                    parsed_manifest = yaml.load(manifest_content, Loader=_UniqueKeyLoader)
                    model_ids = tuple(model["id"] for model in parsed_manifest["models"])
                    expected_ids = {"hello-tuntun-v1", "stop-tuntun-v1"}
                    if len(model_ids) != 2 or set(model_ids) != expected_ids:
                        errors.append(
                            "Task 12 manifests must contain exactly the two exact model IDs "
                            "hello-tuntun-v1 and stop-tuntun-v1"
                        )
        benchmark = (
            materialized_files.get("tests/hardware/bench_wakeword.py")
            if materialized_files is not None
            else next(
                (
                    snippet.body
                    for snippet in task_12.snippets
                    if snippet.path == "tests/hardware/bench_wakeword.py"
                ),
                None,
            )
        )
        if benchmark is not None:
            errors.extend(
                f"Task 12 wake benchmark behavioral probe: {error}"
                for error in validate_wake_benchmark_bytes(
                    benchmark, materialized_files=materialized_files
                )
            )
    task_15 = by_number.get(15)
    if task_15 is not None:
        declarations = {declaration.path for declaration in task_15.declarations}
        generator = "evals/generate_bilingual_report_schema.py"
        if generator not in declarations:
            errors.append(f"Task 15 must own {generator}")
        schema_path = "evals/reports/bilingual-persona-score-v1.schema.json"
        matching = [item for item in task_15.generators if item.output == schema_path]
        if len(matching) != 1 or matching[0].entry_point != generator:
            errors.append(
                "Task 15 must generate the bilingual report schema with its owned generator"
            )
        if materialized_files is not None:
            schema = materialized_files.get(schema_path)
            if schema is None:
                errors.append("Task 15 generated schema output is absent")
            else:
                errors.extend(
                    f"Task 15 {error}" for error in validate_bilingual_schema_bytes(schema)
                )
                errors.extend(
                    f"Task 15 {error}"
                    for error in validate_bilingual_report_model_files(materialized_files)
                )


def _pytest_environment(root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = os.pathsep.join(
        (
            str(root),
            str(root / "apps/core/src"),
            str(root / "apps/edge/src"),
            str(root / "packages/contracts/src"),
            str(root / "packages/testing/src"),
        )
    )
    return environment


_COLLECTION_PLUGIN = """import json
from pathlib import Path

def pytest_collection_finish(session):
    records = []
    for item in session.items:
        records.append({
            "nodeid": item.nodeid,
            "markers": sorted({marker.name for marker in item.iter_markers()}),
        })
    Path(".tuntun-collected-nodes.json").write_text(
        json.dumps(records, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
"""


def _collect_software_pytest_nodes(
    root: Path,
    paths: Sequence[str],
    *,
    task_number: int,
    label: str,
    errors: list[str],
) -> tuple[str, ...] | None:
    """Return every non-external node after pytest applies real inheritance/fixtures."""

    plugin = root / "__tuntun_plan_collection_plugin.py"
    evidence = root / ".tuntun-collected-nodes.json"
    plugin.write_text(_COLLECTION_PLUGIN, encoding="utf-8")
    with contextlib.suppress(FileNotFoundError):
        evidence.unlink()
    try:
        result = run_materialized_python(
            (
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "-p",
                "__tuntun_plan_collection_plugin",
                *paths,
            ),
            root=root,
            timeout_seconds=45,
            restrict_host_apis=False,
        )
    except subprocess.TimeoutExpired:
        errors.append(f"Task {task_number:02d}: {label} collection failed: exceeded 45 seconds")
        return None
    if result.returncode != 0 or not evidence.is_file():
        diagnostic = result.diagnostic[-4096:].decode(errors="replace")
        errors.append(
            f"Task {task_number:02d}: {label} collection failed with exit "
            f"{result.returncode}: {diagnostic}"
        )
        return None
    try:
        records = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        errors.append(f"Task {task_number:02d}: {label} collection evidence invalid: {error}")
        return None
    if type(records) is not list or not records:
        errors.append(f"Task {task_number:02d}: {label} collected no pytest nodes")
        return None
    software: list[str] = []
    for record in records:
        if (
            type(record) is not dict
            or set(record) != {"nodeid", "markers"}
            or type(record["nodeid"]) is not str
            or type(record["markers"]) is not list
            or any(type(marker) is not str for marker in record["markers"])
        ):
            errors.append(f"Task {task_number:02d}: {label} collection evidence is not closed")
            return None
        authorization_markers = tuple(
            sorted(
                marker for marker in record["markers"] if marker not in NON_AUTHORIZATION_MARKERS
            )
        )
        if not approved_skip_marker_names(authorization_markers):
            software.append(record["nodeid"])
    return tuple(software)


def _execute_pytest_boundary_probe(
    root: Path,
    paths: Sequence[str],
    *,
    task_number: int,
    label: str,
    errors: list[str],
) -> None:
    junit = root / f".{label}.junit.xml"
    try:
        result = subprocess.run(
            (
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "--maxfail=1",
                f"--junitxml={junit}",
                "-m",
                "not reachy_hardware and not live_cloud",
                *paths,
            ),
            cwd=root,
            env=_pytest_environment(root),
            check=False,
            capture_output=True,
            timeout=45,
        )
    except subprocess.TimeoutExpired:
        errors.append(f"Task {task_number:02d}: {label} failed: exceeded 45 seconds")
        return
    complete, junit_diagnostic = _junit_is_complete_pass(junit)
    if result.returncode != 0 or not complete:
        diagnostic = (result.stdout + result.stderr)[-4096:].decode(errors="replace")
        errors.append(
            f"Task {task_number:02d}: {label} failed with exit {result.returncode}; "
            f"{junit_diagnostic}: {diagnostic}"
        )


def _validate_pytest_task_boundaries(
    document: PlanDocument, foundation_files: dict[str, bytes], errors: list[str]
) -> None:
    files = dict(foundation_files)
    cumulative_test_paths: list[str] = []
    for task in document.tasks:
        try:
            files = materialize_document(PlanDocument((task,)), foundation_files=files)
        except MaterializationError:
            return
        producer_names: set[str] = set()
        for snippet in task.snippets:
            tree = _python_tree(snippet, errors)
            if tree is None:
                continue
            producer_names.update(
                function.name
                for function in tree.body
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
                and _is_fixture(function)
            )
        test_paths = [
            declaration.path for declaration in task.declarations if declaration.kind == "Test"
        ]
        for declaration in task.declarations:
            if (
                declaration.path.startswith("tests/")
                and declaration.path.endswith(".py")
                and declaration.path not in cumulative_test_paths
                and declaration.kind in {"Test", "Modify"}
            ):
                cumulative_test_paths.append(declaration.path)
        if not test_paths and not producer_names:
            continue
        prefix = f"tuntun-plan-task-{task.number:02d}-"
        with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
            root = Path(temporary)
            write_materialized_tree(root, files)
            if producer_names:
                probe_path = "tests/__tuntun_plan_fixture_probe__.py"
                if probe_path in files:
                    errors.append(
                        f"Task {task.number:02d}: reserved fixture probe path already exists"
                    )
                else:
                    probe = root / probe_path
                    probe.parent.mkdir(parents=True, exist_ok=True)
                    names = repr(tuple(sorted(producer_names)))
                    probe.write_text(
                        "import pytest\n\n"
                        f"@pytest.mark.parametrize('fixture_name', {names})\n"
                        "def test_fixture_producer_is_discoverable(request, fixture_name):\n"
                        "    value = request.getfixturevalue(fixture_name)\n"
                        "    assert value is not None and type(value) is not object\n",
                        encoding="utf-8",
                    )
                    _execute_pytest_boundary_probe(
                        root,
                        (probe_path,),
                        task_number=task.number,
                        label="fixture-producer discovery probe",
                        errors=errors,
                    )
            if test_paths:
                nodes = _collect_software_pytest_nodes(
                    root,
                    test_paths,
                    task_number=task.number,
                    label="pytest task-boundary probe",
                    errors=errors,
                )
                if nodes:
                    _execute_pytest_boundary_probe(
                        root,
                        nodes,
                        task_number=task.number,
                        label="pytest task-boundary probe",
                        errors=errors,
                    )
    if cumulative_test_paths:
        with tempfile.TemporaryDirectory(prefix="tuntun-plan-final-pytest-") as temporary:
            root = Path(temporary)
            write_materialized_tree(root, files)
            nodes = _collect_software_pytest_nodes(
                root,
                cumulative_test_paths,
                task_number=document.tasks[-1].number,
                label="final cumulative pytest probe",
                errors=errors,
            )
            if nodes:
                _execute_pytest_boundary_probe(
                    root,
                    nodes,
                    task_number=document.tasks[-1].number,
                    label="final cumulative pytest probe",
                    errors=errors,
                )


def validate_plan_document(
    document: PlanDocument,
    *,
    foundation_files: dict[str, bytes],
    require_foundation_task_13: bool = False,
    execute_behavioral_probes: bool = True,
) -> list[str]:
    """Return every independently actionable plan-integrity error."""

    errors: list[str] = []
    _validate_path_parity(document, errors)
    _validate_dependencies(document, errors)
    _validate_foundation(foundation_files, errors, required=require_foundation_task_13)
    _validate_import_ownership(document, foundation_files, errors)
    _validate_fixtures_and_skips(document, foundation_files, errors)
    _validate_green_commands(document, errors)
    materialized: dict[str, bytes] | None = None
    try:
        materialized = materialize_document(document, foundation_files=foundation_files)
    except MaterializationError as error:
        errors.append(f"materialization failed: {error}")
    _validate_model_and_eval_contracts(document, errors, materialized_files=materialized)
    if execute_behavioral_probes and materialized is not None:
        _execute_owned_green_commands(document, materialized, errors)
        _validate_pytest_task_boundaries(document, foundation_files, errors)
    return errors


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--foundation-ref", required=True)
    parser.add_argument("--plan-ref", required=True)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--plan-path",
        default=(
            "docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    root = args.repository_root.resolve()
    foundation = foundation_snapshot_from_ref(root, args.foundation_ref)
    document = plan_document_from_ref(root, args.plan_ref, args.plan_path)
    errors = validate_plan_document(
        document,
        foundation_files=foundation.files,
        require_foundation_task_13=True,
    )
    if errors:
        print(
            f"conversation plan integrity: FAIL ({len(errors)} errors; "
            f"foundation={foundation.source_commit}; "
            f"plan={document.source_commit}:{document.source_path})"
        )
        for error in errors:
            print(f"- {error}")
        return 1
    print(
        "conversation plan integrity: PASS "
        f"(foundation={foundation.source_commit}; "
        f"plan={document.source_commit}:{document.source_path})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
