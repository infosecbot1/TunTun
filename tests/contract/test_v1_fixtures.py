from __future__ import annotations

# The import split below deliberately bootstraps the uninstalled root namespace.
# ruff: noqa: E402
import json
import os
import subprocess
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import ModuleType
from typing import cast

# The root project is not an installed package; preserve package-import coverage
# without changing workspace metadata or adding a suite-wide import side effect.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from tuntun_contracts import (
    actions,
    audit,
    budget,
    events,
    identity,
    memory,
    policy,
    ports,
    provider,
    reachy,
    speech,
)
from tuntun_contracts.base import (
    Commitment,
    ContractModel,
    ContractParseError,
    canonical_bytes,
    parse_contract_json,
    registered_contract_models,
)

from scripts import contract_fixture_builders, generate_contract_fixtures
from scripts.contract_fixture_builders import (
    BUILDERS,
    REQUIRED_SEMANTIC_MODELS,
    SCHEMA_ONLY_MODELS,
    FixtureFactory,
    fixture_registry,
    semantic_specs,
)
from scripts.contract_generator_common import open_generated_directory_snapshot

FIXTURE_ROOT = ROOT / "packages/contracts/fixtures/v1"
EXPECTED_GROUP_MODULES: Mapping[str, tuple[ModuleType, ...]] = {
    "actions": (actions,),
    "audit": (audit,),
    "budget": (budget,),
    "events": (events, ports),
    "identity": (identity,),
    "memory": (memory,),
    "policy": (policy,),
    "provider": (provider,),
    "reachy": (reachy,),
    "speech": (speech,),
}
EXPECTED_GROUP_COUNTS = {
    "actions": 23,
    "audit": 2,
    "budget": 11,
    "events": 7,
    "identity": 5,
    "memory": 14,
    "policy": 10,
    "provider": 9,
    "reachy": 7,
    "speech": 5,
}
EXPECTED_SEMANTIC_MODELS = frozenset(
    {
        Commitment,
        events.EventEnvelope,
        events.SignedEventEnvelope,
        speech.AuthorizedTranscriptionRequest,
        speech.AuthorizedSynthesisRequest,
        identity.IdentityEvidence,
        identity.IdentityRequest,
        identity.IdentityDecision,
        memory.EpisodicContent,
        memory.MemoryProposalDraft,
        memory.MemoryProposal,
        memory.MemoryRecord,
        memory.MemoryQuery,
        memory.ApprovedMemory,
        memory.DecideMemoryProposal,
        actions.TimerCreateActionDraft,
        actions.TimerTargetActionDraft,
        actions.SafetyActionDraft,
        actions.PrivacyReductionActionDraft,
        actions.ComponentStatusActionDraft,
        actions.DiagnosticActionDraft,
        actions.MemoryActionDraft,
        actions.ProfileActionDraft,
        actions.ConsentActionDraft,
        actions.IdentityActionDraft,
        actions.ProviderActionDraft,
        actions.CredentialActionDraft,
        actions.AuditActionDraft,
        actions.BackupActionDraft,
        actions.SearchActionDraft,
        actions.SecurityFindingActionDraft,
        actions.ReleaseP1R0ActionDraft,
        actions.LatencyDeviationActionDraft,
        actions.FamilyStageReviewActionDraft,
        actions.ValidatedActionProposal,
        policy.PolicyRequest,
        policy.PolicyDecision,
        policy.AuthenticationRequest,
        policy.AuthenticationChallenge,
        policy.AuthGrant,
        policy.AuthContext,
        policy.AdminSessionPrincipal,
        policy.TimerIntent,
        provider.SanitizedProviderRequest,
        provider.RedactionReceipt,
        budget.BudgetReservationRequest,
        budget.BudgetReservation,
        budget.ProviderUsageReceiptV1,
        budget.BudgetReconciliationRequest,
        reachy.ReachyCommand,
        reachy.CameraWindowGrant,
    }
)
EXPECTED_PRIVACY_HEADINGS = (
    "## Assets",
    "## Actors",
    "## Trust boundaries",
    "## Foundation mitigations",
    "## Out of scope",
)
EXPECTED_INVENTORY_ROWS = {
    "Configuration",
    "Secrets",
    "Event receipts",
    "Audit receipts",
    "Provider price and budget metadata",
    "Model metadata",
    "Synthetic contract fixtures",
    "Raw audio",
    "Conversation transcripts",
    "Camera frames",
}


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return cast(dict[str, object], value)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AssertionError(f"duplicate fixture JSON key: {key}")
        result[key] = value
    return result


def _fixture_documents(
    *names: str,
) -> dict[str, tuple[bytes, dict[str, object]]]:
    result: dict[str, tuple[bytes, dict[str, object]]] = {}
    with open_generated_directory_snapshot(
        FIXTURE_ROOT,
        generate_contract_fixtures.FIXTURE_FILENAMES,
    ) as snapshot:
        for name in names:
            raw = snapshot.read_bytes(f"{name}.json")
            assert 1 <= len(raw) <= 4 * 1024 * 1024
            parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
            result[name] = (raw, _mapping(parsed))
    return result


def _fixture_document(name: str) -> tuple[bytes, dict[str, object]]:
    return _fixture_documents(name)[name]


def _walk_schema_nodes(value: object) -> Iterator[dict[str, object]]:
    node = _mapping(value)
    yield node
    for mapping_name in ("$defs", "properties"):
        children = node.get(mapping_name)
        if children is not None:
            for child in _mapping(children).values():
                yield from _walk_schema_nodes(child)
    items = node.get("items")
    if items is not None:
        yield from _walk_schema_nodes(items)
    for union_name in ("anyOf", "oneOf"):
        alternatives = node.get(union_name)
        if alternatives is not None:
            assert isinstance(alternatives, list)
            for alternative in alternatives:
                yield from _walk_schema_nodes(alternative)


def _independent_fixture_registry() -> dict[str, dict[str, type[ContractModel]]]:
    result: dict[str, dict[str, type[ContractModel]]] = {}
    for group, owning_modules in EXPECTED_GROUP_MODULES.items():
        models: dict[str, type[ContractModel]] = {}
        for module in owning_modules:
            for name, value in vars(module).items():
                if (
                    isinstance(value, type)
                    and issubclass(value, ContractModel)
                    and value is not ContractModel
                    and value.__module__ == module.__name__
                ):
                    models[name] = value
        result[group] = dict(sorted(models.items()))
    result["events"]["Commitment"] = Commitment
    result["events"] = dict(sorted(result["events"].items()))
    return dict(sorted(result.items()))


def test_fixture_registry_matches_the_independent_93_model_oracle() -> None:
    preview = FixtureFactory.preview()
    assert preview.uuid_json() == "00000000-0000-0000-0000-000000000001"
    assert preview.time_json() == "2026-08-27T00:00:00+00:00"
    expected = _independent_fixture_registry()
    expected_models = {model_type for models in expected.values() for model_type in models.values()}
    assert {name: len(models) for name, models in expected.items()} == EXPECTED_GROUP_COUNTS
    assert len(expected_models) == 93
    assert expected_models == set(registered_contract_models())
    assert fixture_registry() == expected
    assert set(BUILDERS) == expected_models


def test_semantic_partition_matches_an_independent_exact_oracle() -> None:
    assert len(EXPECTED_SEMANTIC_MODELS) == 51
    assert len(SCHEMA_ONLY_MODELS) == 42
    assert set(semantic_specs()) == set(EXPECTED_SEMANTIC_MODELS)
    assert set(REQUIRED_SEMANTIC_MODELS) == set(EXPECTED_SEMANTIC_MODELS)
    assert not (set(REQUIRED_SEMANTIC_MODELS) & set(SCHEMA_ONLY_MODELS))
    assert set(REQUIRED_SEMANTIC_MODELS) | set(SCHEMA_ONLY_MODELS) == set(BUILDERS)


def test_repaired_task5_correlations_are_explicit_and_valid() -> None:
    specs = semantic_specs()
    expected_fields: dict[type[ContractModel], frozenset[str]] = {
        speech.AuthorizedTranscriptionRequest: frozenset(
            {"request_id", "turn_id", "audio_commitment", "language_hints", "route"}
        ),
        speech.AuthorizedSynthesisRequest: frozenset(
            {
                "request_id",
                "turn_id",
                "text_commitment",
                "segment_index",
                "segment_count",
                "route",
            }
        ),
        identity.IdentityEvidence: frozenset({"observed_at", "expires_at"}),
        identity.IdentityDecision: frozenset({"status", "subject_id"}),
        policy.PolicyDecision: frozenset({"effect", "required_assurance"}),
        policy.AuthenticationRequest: frozenset({"subject_id", "binding"}),
        policy.AuthenticationChallenge: frozenset({"subject_id", "binding"}),
        policy.AuthGrant: frozenset(
            {
                "subject_id",
                "binding",
                "assurance",
                "assurance_source",
                "issued_at",
                "expires_at",
            }
        ),
        policy.AuthContext: frozenset(
            {"grant_id", "subject_id", "binding", "assurance", "assurance_source"}
        ),
        policy.AdminSessionPrincipal: frozenset(
            {"authenticated_at", "idle_expires_at", "absolute_expires_at"}
        ),
        policy.TimerIntent: frozenset({"operation", "duration_seconds", "label_commitment"}),
        provider.SanitizedProviderRequest: frozenset({"request_id", "provider", "model", "route"}),
        actions.ValidatedActionProposal: frozenset({"draft", "binding"}),
        budget.ProviderUsageReceiptV1: frozenset({"category", "billable_usage"}),
        reachy.CameraWindowGrant: frozenset(
            {
                "subject_id",
                "action_name",
                "purpose",
                "max_frames",
                "max_frame_bytes",
                "max_total_bytes",
                "max_frames_per_second",
                "issued_at",
                "expires_at",
            }
        ),
        memory.MemoryProposalDraft: frozenset(
            {
                "operation",
                "content",
                "audience",
                "target_memory_id",
                "expected_version",
                "source_receipt_ids",
            }
        ),
        memory.MemoryRecord: frozenset({"version", "content", "audience"}),
        memory.ApprovedMemory: frozenset({"content", "audience", "source_receipt_ids"}),
        memory.DecideMemoryProposal: frozenset({"decision", "edited_content"}),
    }
    assert {model_type: specs[model_type].fields for model_type in expected_fields} == (
        expected_fields
    )

    factory = FixtureFactory.preview()
    action_types: tuple[type[ContractModel], ...] = (
        actions.TimerCreateActionDraft,
        actions.TimerTargetActionDraft,
        actions.SafetyActionDraft,
        actions.PrivacyReductionActionDraft,
        actions.ComponentStatusActionDraft,
        actions.DiagnosticActionDraft,
        actions.MemoryActionDraft,
        actions.ProfileActionDraft,
        actions.ConsentActionDraft,
        actions.IdentityActionDraft,
        actions.ProviderActionDraft,
        actions.CredentialActionDraft,
        actions.AuditActionDraft,
        actions.BackupActionDraft,
        actions.SearchActionDraft,
        actions.SecurityFindingActionDraft,
        actions.ReleaseP1R0ActionDraft,
        actions.LatencyDeviationActionDraft,
        actions.FamilyStageReviewActionDraft,
    )
    for model_type in action_types:
        payload = factory.build(model_type).model_dump(mode="json")
        action_name = payload["action_name"]
        resource_type = payload["resource_type"]
        assert isinstance(action_name, str) and isinstance(resource_type, str)
        assert actions.ACTION_RESOURCE_TYPE_BY_NAME[action_name] == resource_type

    memory_action = factory.build(actions.MemoryActionDraft)
    profile_action = factory.build(actions.ProfileActionDraft)
    consent_action = factory.build(actions.ConsentActionDraft)
    identity_action = factory.build(actions.IdentityActionDraft)
    credential_action = factory.build(actions.CredentialActionDraft)
    backup_action = factory.build(actions.BackupActionDraft)
    search_action = factory.build(actions.SearchActionDraft)
    latency_action = factory.build(actions.LatencyDeviationActionDraft)
    assert memory_action.memory_proposal is not None
    assert memory_action.resource_id == memory_action.memory_proposal.proposal_id
    assert profile_action.resource_id == profile_action.subject_id
    assert consent_action.resource_id == consent_action.subject_id
    assert identity_action.resource_id == identity_action.subject_id
    assert credential_action.resource_id == credential_action.credential_id
    assert backup_action.resource_id == backup_action.backup_id
    assert search_action.resource_id == search_action.subject_id
    assert latency_action.resource_id == latency_action.run_id

    validated = factory.build(actions.ValidatedActionProposal)
    assert validated.binding.proposal_id == validated.draft.proposal_id
    assert validated.binding.idempotency_key == validated.draft.idempotency_key
    assert validated.binding.action_name == validated.draft.action_name
    assert validated.binding.resource_type == validated.draft.resource_type
    assert validated.binding.resource_id == validated.draft.resource_id
    assert validated.binding.parameter_commitment == validated.draft.parameters_commitment
    stt = factory.build(speech.AuthorizedTranscriptionRequest)
    tts = factory.build(speech.AuthorizedSynthesisRequest)
    request = factory.build(provider.SanitizedProviderRequest)
    assert (stt.request_id, stt.turn_id, stt.audio_commitment) == (
        stt.route.request_id,
        stt.route.turn_id,
        stt.route.request_commitment,
    )
    assert stt.route.purpose == "cloud_stt"
    assert (tts.request_id, tts.turn_id, tts.text_commitment) == (
        tts.route.request_id,
        tts.route.turn_id,
        tts.route.request_commitment,
    )
    assert tts.route.purpose == "cloud_tts" and tts.segment_index < tts.segment_count
    assert (request.request_id, request.provider.value, request.model) == (
        request.route.request_id,
        request.route.provider,
        request.route.model,
    )
    assert request.route.purpose == "cloud_reasoning"

    evidence = factory.build(identity.IdentityEvidence)
    decision = factory.build(identity.IdentityDecision)
    policy_decision = factory.build(policy.PolicyDecision)
    auth_request = factory.build(policy.AuthenticationRequest)
    challenge = factory.build(policy.AuthenticationChallenge)
    grant = factory.build(policy.AuthGrant)
    context = factory.build(policy.AuthContext)
    admin = factory.build(policy.AdminSessionPrincipal)
    timer = factory.build(policy.TimerIntent)
    assert evidence.observed_at <= evidence.expires_at
    assert (decision.status.value == "verified") == (decision.subject_id is not None)
    assert policy_decision.effect.value == "allow"
    assert policy_decision.required_assurance is None
    assert auth_request.subject_id == auth_request.binding.subject_id
    assert challenge.subject_id == challenge.binding.subject_id
    assert grant.subject_id == grant.binding.subject_id and grant.issued_at < grant.expires_at
    assert context.subject_id == context.binding.subject_id
    assert context.grant_id is None and context.assurance_source == "guest"
    assert admin.authenticated_at < admin.idle_expires_at <= admin.absolute_expires_at
    assert timer.operation == "create"
    assert timer.duration_seconds is not None and timer.label_commitment is not None

    usage = factory.build(budget.ProviderUsageReceiptV1)
    camera = factory.build(reachy.CameraWindowGrant)
    proposal_draft = factory.build(memory.MemoryProposalDraft)
    memory_record = factory.build(memory.MemoryRecord)
    approved = factory.build(memory.ApprovedMemory)
    rejected = factory.build(memory.DecideMemoryProposal)
    assert budget.usage_total(usage.billable_usage) > 0
    assert (camera.action_name, camera.purpose) == (
        "identity.enroll",
        "explicit_enrollment",
    )
    assert memory_record.version == 1
    assert len(proposal_draft.source_receipt_ids) == len(set(proposal_draft.source_receipt_ids))
    assert len(approved.source_receipt_ids) == len(set(approved.source_receipt_ids))
    assert rejected.decision == "reject" and rejected.edited_content is None


def test_semantic_misclassification_fails_before_output_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    semantic_model = next(iter(EXPECTED_SEMANTIC_MODELS))
    monkeypatch.setattr(
        contract_fixture_builders,
        "SCHEMA_ONLY_MODELS",
        frozenset({*SCHEMA_ONLY_MODELS, semantic_model}),
    )
    output = tmp_path / "fixtures"
    monkeypatch.setattr(generate_contract_fixtures, "OUTPUT_DIRECTORY", output)
    assert generate_contract_fixtures.main(["--write"]) == 1
    assert not output.exists()


def test_all_93_schemas_use_the_exact_supported_keyword_and_format_matrix() -> None:
    keywords: set[str] = set()
    schema_types: set[str] = set()
    formats: set[str] = set()
    patterns: set[str] = set()
    for model_type in registered_contract_models():
        schema = model_type.model_json_schema(
            mode="validation",
            ref_template="#/$defs/{model}",
        )
        contract_fixture_builders._validate_schema_vocabulary(
            _mapping(schema),
            label=model_type.__name__,
        )
        for node in _walk_schema_nodes(schema):
            keywords.update(node)
            if isinstance(value := node.get("type"), str):
                schema_types.add(value)
            if isinstance(value := node.get("format"), str):
                formats.add(value)
            if isinstance(value := node.get("pattern"), str):
                patterns.add(value)
    assert keywords == set(contract_fixture_builders.SUPPORTED_SCHEMA_KEYWORDS)
    assert schema_types == set(contract_fixture_builders.SUPPORTED_SCHEMA_TYPES)
    assert formats == set(contract_fixture_builders.SUPPORTED_SCHEMA_FORMATS)
    assert patterns == set(contract_fixture_builders._PATTERN_VALUES)


def test_schema_builder_executes_every_claimed_shape_and_format() -> None:
    factory = FixtureFactory.preview()

    def value(schema: dict[str, object], root: dict[str, object] | None = None) -> object:
        actual_root = schema if root is None else root
        contract_fixture_builders._validate_schema_vocabulary(actual_root, label="matrix")
        return factory._schema_value(schema, actual_root)

    assert value({"const": "fixed"}) == "fixed"
    assert value({"enum": [None, "first"]}) == "first"
    assert value({"anyOf": [{"type": "null"}, {"type": "string"}]}) == "x"
    assert value({"oneOf": [{"type": "boolean"}, {"type": "integer"}]}) is False
    assert value(
        {
            "additionalProperties": False,
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
            "type": "object",
        }
    ) == {"name": "x"}
    assert value(
        {
            "items": {"type": "boolean"},
            "maxItems": 2,
            "minItems": 1,
            "type": "array",
        }
    ) == [False]
    assert value({"maxLength": 2, "minLength": 2, "type": "string"}) == "xx"
    assert value({"default": "ignored", "title": "Text", "type": "string"}) == "x"
    for pattern, witness in contract_fixture_builders._PATTERN_VALUES.items():
        assert value({"pattern": pattern, "type": "string"}) == witness
    assert value({"format": "uuid", "type": "string"}) == ("00000000-0000-0000-0000-000000000001")
    assert value({"format": "date-time", "type": "string"}) == ("2026-08-27T00:00:00+00:00")
    assert value({"format": "binary", "minLength": 2, "type": "string"}) == "xx"
    assert value({"maximum": 3, "minimum": 2, "type": "integer"}) == 2
    assert value({"type": "boolean"}) is False
    assert value({"type": "null"}) is None
    root: dict[str, object] = {
        "$defs": {"Alias": {"type": "string"}},
        "$ref": "#/$defs/Alias",
    }
    assert value(root, root) == "x"
    discriminated: dict[str, object] = {
        "$defs": {"Choice": {"const": "choice"}},
        "discriminator": {
            "mapping": {"choice": "#/$defs/Choice"},
            "propertyName": "kind",
        },
        "oneOf": [{"$ref": "#/$defs/Choice"}],
    }
    assert value(discriminated, discriminated) == "choice"


@pytest.mark.parametrize(
    "schema",
    (
        {"examples": ["x"], "type": "string"},
        {"type": "number"},
        {"type": ["string", "null"]},
        {"format": "email", "type": "string"},
        {"pattern": "^unclaimed$", "type": "string"},
        {"additionalProperties": True, "properties": {}, "type": "object"},
        {"allOf": [{"type": "string"}]},
        {"discriminator": {"propertyName": "kind"}, "oneOf": [{"type": "string"}]},
        {"properties": {}, "required": ["missing"], "type": "object"},
    ),
)
def test_schema_builder_rejects_every_unclaimed_shape(schema: dict[str, object]) -> None:
    with pytest.raises(contract_fixture_builders.FixtureBuildError):
        contract_fixture_builders._validate_schema_vocabulary(schema, label="rejected")


@pytest.mark.parametrize("name", tuple(EXPECTED_GROUP_MODULES))
def test_fixture_file_is_closed_complete_and_byte_deterministic(name: str) -> None:
    raw, document = _fixture_document(name)
    assert set(document) == {"canonical_examples", "examples", "schema_version"}
    assert document["schema_version"] == "1.0"
    examples = _mapping(document["examples"])
    canonical_examples = _mapping(document["canonical_examples"])
    models = _independent_fixture_registry()[name]
    assert set(examples) == set(canonical_examples) == set(models)
    assert raw == generate_contract_fixtures.render()[f"{name}.json"]
    for model_name, model_type in models.items():
        example_raw = json.dumps(
            examples[model_name],
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        model = parse_contract_json(
            model_type,
            example_raw,
            max_bytes=1_048_576,
            require_canonical=False,
        )
        canonical = canonical_examples[model_name]
        assert isinstance(canonical, str)
        assert canonical_bytes(model).decode("utf-8") == canonical
        assert (
            canonical_bytes(
                parse_contract_json(
                    model_type,
                    canonical.encode("utf-8"),
                    max_bytes=1_048_576,
                    require_canonical=True,
                )
            ).decode("utf-8")
            == canonical
        )


def test_binary_speech_fixture_uses_strict_json_ingress() -> None:
    _, document = _fixture_document("speech")
    example = _mapping(_mapping(document["examples"])["SpeechChunk"])
    model = parse_contract_json(
        speech.SpeechChunk,
        json.dumps(example, separators=(",", ":")).encode("utf-8"),
        max_bytes=1_048_576,
        require_canonical=False,
    )
    assert model.pcm == b""


def test_memory_create_replace_delete_and_durable_audiences_are_closed() -> None:
    documents = _fixture_documents("memory", "actions")
    _, memory_document = documents["memory"]
    _, actions_document = documents["actions"]
    memory_examples = _mapping(memory_document["examples"])
    action_examples = _mapping(actions_document["examples"])
    delete = _mapping(memory_examples["MemoryProposalDraft"])
    create = _mapping(_mapping(memory_examples["MemoryProposal"])["draft"])
    replace = _mapping(_mapping(action_examples["MemoryActionDraft"])["memory_proposal"])
    assert (create["operation"], create["audience"]) == (
        "create",
        "subject_private",
    )
    assert (replace["operation"], replace["audience"]) == (
        "replace",
        "subject_private",
    )
    assert (delete["operation"], delete["audience"]) == ("delete", None)
    for model_name in ("MemoryRecord", "ApprovedMemory"):
        assert _mapping(memory_examples[model_name])["audience"] == "subject_private"


def test_missing_or_unknown_memory_audience_fails_validation() -> None:
    _, document = _fixture_document("memory")
    examples = _mapping(document["examples"])
    approved = _mapping(examples["ApprovedMemory"])
    missing = dict(approved)
    missing.pop("audience")
    unknown = {**approved, "audience": "unknown"}
    for payload in (missing, unknown):
        with pytest.raises(ContractParseError):
            parse_contract_json(
                memory.ApprovedMemory,
                json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                max_bytes=1_048_576,
                require_canonical=False,
            )


def test_privacy_documents_have_the_exact_required_structure_and_closed_rows() -> None:
    threat = (ROOT / "docs/privacy/threat-model.md").read_text(encoding="utf-8")
    headings = tuple(line for line in threat.splitlines() if line.startswith("## "))
    assert headings == EXPECTED_PRIVACY_HEADINGS
    for required in (
        "SQLCipher database and Keychain roots",
        "owner, family subject, and Guest",
        "Reachy ↔ LAN ↔ Mac",
        "browser ↔ owner API",
        "Mac ↔ provider",
        "build ↔ dependency and model sources",
        "Task 3 private-data and structural scans",
        "manifest hashes and audit triggers",
        "different EUID",
        "ACL_TYPE_EXTENDED",
        "non-owner write ACLs",
        "non-POSIX ACL filesystems are unsupported",
        "noncooperative same-EUID filesystem mutation",
        "stable process umask",
        "honor the retained parent-directory flock",
    ):
        assert required in threat

    inventory = (ROOT / "docs/privacy/data-flow-inventory.md").read_text(encoding="utf-8")
    table_lines = [line for line in inventory.splitlines() if line.startswith("|")]
    assert len(table_lines) == 12
    assert table_lines[0] == (
        "| Data class | Source | Purpose | Processor | Durable location | Egress | "
        "Retention/deletion | Key |"
    )
    assert table_lines[1] == "| --- | --- | --- | --- | --- | --- | --- | --- |"
    rows = {
        columns[0]: columns
        for line in table_lines[2:]
        if len(columns := [item.strip() for item in line.strip("|").split("|")]) == 8
    }
    assert len(rows) == 10
    assert set(rows) == EXPECTED_INVENTORY_ROWS
    for name in ("Raw audio", "Conversation transcripts", "Camera frames"):
        columns = rows[name]
        assert columns[3] == "not processed by foundation"
        assert columns[4] == "none"
        assert columns[5] == "none"
        assert columns[6] == "not retained"


def test_fixture_generator_direct_and_package_check_modes_match() -> None:
    commands = (
        [sys.executable, "scripts/generate_contract_fixtures.py", "--check"],
        [sys.executable, "-m", "scripts.generate_contract_fixtures", "--check"],
    )
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env={**os.environ, "PYTHONHASHSEED": "1"},
            check=False,
            capture_output=True,
        )
        assert completed.returncode == 0
        assert completed.stdout == completed.stderr == b""
