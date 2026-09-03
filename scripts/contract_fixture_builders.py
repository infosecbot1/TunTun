from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import ModuleType
from typing import Final, Literal, TypeAlias, TypeVar, cast
from uuid import UUID

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
    reachy_assistant_qualification,
    reachy_operator,
    reachy_time,
    speech,
)
from tuntun_contracts.base import (
    Commitment,
    ContractModel,
    JSONValue,
    canonical_bytes,
    parse_contract_json,
    registered_contract_models,
)

ContractT = TypeVar("ContractT", bound=ContractModel)
FixtureBuilder: TypeAlias = Callable[["FixtureFactory"], ContractModel]  # noqa: UP040
SemanticValues: TypeAlias = Callable[["FixtureFactory"], dict[str, JSONValue]]  # noqa: UP040
MAX_SCHEMA_ITEMS = 32
ALLOWED_LARGE_ARRAY_MAX_ITEMS: Final[Mapping[tuple[str, ...], int]] = {
    ("ReachyAssistantInventoryV1", "properties", "managed_app_ids"): 256,
    ("ReachyAssistantInventoryV1", "properties", "recovery_hook_ids"): 256,
}
SUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {
        "$defs",
        "$ref",
        "additionalProperties",
        "anyOf",
        "const",
        "default",
        "discriminator",
        "enum",
        "format",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "oneOf",
        "pattern",
        "properties",
        "required",
        "title",
        "type",
        "x-tuntun-cross-field-invariants",
        "x-tuntun-field-safety",
    }
)
SUPPORTED_SCHEMA_TYPES = frozenset({"array", "boolean", "integer", "null", "object", "string"})
SUPPORTED_SCHEMA_FORMATS = frozenset({"binary", "date-time", "uuid"})

FIXTURE_GROUP_MODULES: Mapping[str, tuple[ModuleType, ...]] = {
    "actions": (actions,),
    "audit": (audit,),
    "budget": (budget,),
    "events": (events, ports),
    "identity": (identity,),
    "memory": (memory,),
    "policy": (policy,),
    "provider": (provider,),
    "reachy": (reachy, reachy_assistant_qualification, reachy_operator, reachy_time),
    "speech": (speech,),
}


class FixtureBuildError(RuntimeError):
    """A fixture cannot be proved deterministic, complete, and valid."""


@dataclass(frozen=True)
class SemanticSpec:
    fields: frozenset[str]
    values: SemanticValues


def _model_json(model: ContractModel) -> dict[str, JSONValue]:
    return cast(dict[str, JSONValue], model.model_dump(mode="json"))


def fixture_registry() -> dict[str, dict[str, type[ContractModel]]]:
    result: dict[str, dict[str, type[ContractModel]]] = {}
    seen: set[type[ContractModel]] = set()
    for group, owning_modules in FIXTURE_GROUP_MODULES.items():
        models: dict[str, type[ContractModel]] = {}
        for module in owning_modules:
            for name, value in vars(module).items():
                if (
                    isinstance(value, type)
                    and issubclass(value, ContractModel)
                    and value is not ContractModel
                    and value.__module__ == module.__name__
                ):
                    model_type = value
                    if name in models or model_type in seen:
                        raise FixtureBuildError("duplicate fixture model ownership")
                    models[name] = model_type
                    seen.add(model_type)
        result[group] = dict(sorted(models.items()))
    if Commitment in seen or "Commitment" in result["events"]:
        raise FixtureBuildError("Commitment fixture ownership is ambiguous")
    result["events"]["Commitment"] = Commitment
    result["events"] = dict(sorted(result["events"].items()))
    seen.add(Commitment)
    if seen != set(registered_contract_models()):
        raise FixtureBuildError("fixture registry differs from the public registry")
    return dict(sorted(result.items()))


_PATTERN_VALUES: Mapping[str, str] = {
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])$": "2026-08",
    r"^[0-9a-f]{40,64}$": "0" * 40,
    r"^[0-9a-f]{64}$": "0" * 64,
    r"^[A-Za-z0-9+/]{43}=$": "A" * 43 + "=",
    r"^[A-Za-z0-9+/]{86}==$": "A" * 86 + "==",
    r"^(?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)$": "1.2.3",
    r"^[A-Za-z0-9_.:-]+$": "fixture-v1",
    r"^[a-z][a-z0-9_-]{0,63}$": "fixture",
    r"^[a-z][a-z0-9_]{0,63}$": "fixture",
    (
        r"^(?:"
        r"[a-z_][a-z0-9_-]{0,2}"
        r"|[a-qs-z_][a-z0-9_-]{3}"
        r"|r[a-np-z0-9_-][a-z0-9_-]{2}"
        r"|ro[a-np-z0-9_-][a-z0-9_-]"
        r"|roo[a-su-z0-9_-]"
        r"|[a-z_][a-z0-9_-]{4,31}"
        r")$"
    ): "tuntunops",
    r"^[a-z][a-z0-9_.-]{1,127}$": "fixture.item",
    (
        r"^(?:"
        r"10[.](?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
        r"[.](?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
        r"[.](?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
        r"|172[.](?:1[6-9]|2[0-9]|3[0-1])"
        r"[.](?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
        r"[.](?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
        r"|192[.]168[.](?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
        r"[.](?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
        r")$"
    ): "192.168.10.20",
    r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$": ("ed25519:fixture:v1"),
}


def _schema_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FixtureBuildError(f"{label} must be a string-keyed schema object")
    return cast(dict[str, object], value)


def _validate_schema_vocabulary(schema: dict[str, object], *, label: str) -> None:
    unknown = set(schema) - SUPPORTED_SCHEMA_KEYWORDS
    if unknown:
        raise FixtureBuildError(f"{label} uses unsupported schema keywords")
    schema_type = schema.get("type")
    if schema_type is not None and (
        not isinstance(schema_type, str) or schema_type not in SUPPORTED_SCHEMA_TYPES
    ):
        raise FixtureBuildError(f"{label} uses an unsupported schema type")
    title = schema.get("title")
    if title is not None and not isinstance(title, str):
        raise FixtureBuildError(f"{label} title is malformed")
    reference = schema.get("$ref")
    if reference is not None and (
        not isinstance(reference, str) or not reference.startswith("#/$defs/")
    ):
        raise FixtureBuildError(f"{label} reference is unsupported")
    string_format = schema.get("format")
    if string_format is not None and string_format not in SUPPORTED_SCHEMA_FORMATS:
        raise FixtureBuildError(f"{label} format is unsupported")
    pattern = schema.get("pattern")
    if pattern is not None and pattern not in _PATTERN_VALUES:
        raise FixtureBuildError(f"{label} pattern is unsupported")
    additional = schema.get("additionalProperties")
    if additional is not None and additional is not False:
        raise FixtureBuildError(f"{label} must be a closed object schema")
    for bound_name in (
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
    ):
        bound = schema.get(bound_name)
        if bound is not None and type(bound) is not int:
            raise FixtureBuildError(f"{label} {bound_name} is malformed")
    enum = schema.get("enum")
    if enum is not None and (not isinstance(enum, list) or not enum):
        raise FixtureBuildError(f"{label} enum is malformed")
    for mapping_name in ("$defs", "properties"):
        mapping_value = schema.get(mapping_name)
        if mapping_value is None:
            continue
        mapping = _schema_mapping(mapping_value, f"{label}/{mapping_name}")
        for name, child in mapping.items():
            _validate_schema_vocabulary(
                _schema_mapping(child, f"{label}/{mapping_name}/{name}"),
                label=f"{label}/{mapping_name}/{name}",
            )
    properties = _schema_mapping(schema.get("properties", {}), f"{label}/properties")
    required = schema.get("required")
    if required is not None and (
        not isinstance(required, list)
        or not all(isinstance(name, str) for name in required)
        or len(required) != len(set(required))
        or not set(required) <= set(properties)
    ):
        raise FixtureBuildError(f"{label} required fields are malformed")
    items = schema.get("items")
    if items is not None:
        _validate_schema_vocabulary(
            _schema_mapping(items, f"{label}/items"),
            label=f"{label}/items",
        )
    for union_name in ("anyOf", "oneOf"):
        alternatives = schema.get(union_name)
        if alternatives is None:
            continue
        if not isinstance(alternatives, list) or not alternatives:
            raise FixtureBuildError(f"{label} {union_name} is malformed")
        for index, alternative in enumerate(alternatives):
            child_label = f"{label}/{union_name}/{index}"
            _validate_schema_vocabulary(
                _schema_mapping(alternative, child_label),
                label=child_label,
            )
    discriminator = schema.get("discriminator")
    if discriminator is not None:
        closed = _schema_mapping(discriminator, f"{label}/discriminator")
        if set(closed) != {"mapping", "propertyName"}:
            raise FixtureBuildError(f"{label} discriminator is malformed")
        property_name = closed["propertyName"]
        mapping = _schema_mapping(closed["mapping"], f"{label}/discriminator/mapping")
        if (
            not isinstance(property_name, str)
            or not mapping
            or not all(
                isinstance(value, str) and value.startswith("#/$defs/")
                for value in mapping.values()
            )
        ):
            raise FixtureBuildError(f"{label} discriminator is malformed")


class FixtureFactory:
    def __init__(self, *, first_uuid: int) -> None:
        if not 1 <= first_uuid < 2**128:
            raise ValueError("first_uuid must fit one nonzero UUID")
        self._next_uuid = first_uuid

    @classmethod
    def preview(cls) -> FixtureFactory:
        return cls(first_uuid=1)

    def uuid(self) -> UUID:
        if self._next_uuid >= 2**128:
            raise FixtureBuildError("fixture UUID range exhausted")
        value = UUID(int=self._next_uuid)
        self._next_uuid += 1
        return value

    def uuid_json(self) -> str:
        return str(self.uuid())

    def time(self, *, offset_microseconds: int = 0) -> datetime:
        return datetime(2026, 8, 27, tzinfo=UTC) + timedelta(microseconds=offset_microseconds)

    def time_json(self, *, offset_microseconds: int = 0) -> str:
        return self.time(offset_microseconds=offset_microseconds).isoformat()

    def _registered_by_schema_name(self) -> dict[str, type[ContractModel]]:
        result: dict[str, type[ContractModel]] = {}
        for model_type in registered_contract_models():
            if model_type.__name__ in result:
                raise FixtureBuildError("contract schema names are not unique")
            result[model_type.__name__] = model_type
        return result

    def _schema_value(
        self,
        schema: dict[str, object],
        root: dict[str, object],
        *,
        path: tuple[str, ...] = (),
    ) -> JSONValue:
        reference = schema.get("$ref")
        if reference is not None:
            if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
                raise FixtureBuildError("fixture schema reference is unsupported")
            name = reference.removeprefix("#/$defs/")
            registered = self._registered_by_schema_name().get(name)
            if registered is not None:
                return _model_json(self.build(registered))
            definitions = _schema_mapping(root.get("$defs", {}), "$defs")
            if name not in definitions:
                raise FixtureBuildError("fixture schema reference does not resolve")
            return self._schema_value(
                _schema_mapping(definitions[name], f"$defs/{name}"),
                root,
                path=(*path, "$defs", name),
            )

        if "const" in schema:
            return cast(JSONValue, schema["const"])
        enum = schema.get("enum")
        if enum is not None:
            if not isinstance(enum, list) or not enum:
                raise FixtureBuildError("fixture enum is empty or malformed")
            non_null = [value for value in enum if value is not None]
            return cast(JSONValue, non_null[0] if non_null else None)

        for union_key in ("oneOf", "anyOf"):
            alternatives = schema.get(union_key)
            if alternatives is not None:
                if not isinstance(alternatives, list) or not alternatives:
                    raise FixtureBuildError("fixture union is empty or malformed")
                ordered = [
                    alternative
                    for alternative in alternatives
                    if not (isinstance(alternative, dict) and alternative.get("type") == "null")
                ] or alternatives
                failures: list[FixtureBuildError] = []
                for alternative in ordered:
                    try:
                        return self._schema_value(
                            _schema_mapping(alternative, union_key),
                            root,
                            path=(*path, union_key, str(len(failures))),
                        )
                    except FixtureBuildError as error:
                        failures.append(error)
                raise FixtureBuildError("no fixture union branch is supported") from failures[-1]

        schema_type = schema.get("type")
        if schema_type == "object":
            properties = _schema_mapping(schema.get("properties", {}), "properties")
            required = schema.get("required", [])
            if not isinstance(required, list) or not all(
                isinstance(name, str) for name in required
            ):
                raise FixtureBuildError("fixture required-field list is malformed")
            return {
                name: self._schema_value(
                    _schema_mapping(properties[name], f"property {name}"),
                    root,
                    path=(*path, "properties", name),
                )
                for name in required
            }
        if schema_type == "array":
            item_schema = _schema_mapping(schema.get("items", {}), "array items")
            minimum = schema.get("minItems", 0)
            maximum = schema.get("maxItems", MAX_SCHEMA_ITEMS)
            if (
                type(minimum) is not int
                or type(maximum) is not int
                or minimum < 0
                or maximum < minimum
                or minimum > MAX_SCHEMA_ITEMS
                or (
                    maximum > MAX_SCHEMA_ITEMS
                    and ALLOWED_LARGE_ARRAY_MAX_ITEMS.get(path) != maximum
                )
            ):
                raise FixtureBuildError("fixture array bounds are invalid")
            return [self._schema_value(item_schema, root) for _ in range(minimum)]
        if schema_type == "string":
            minimum = schema.get("minLength", 0)
            maximum = schema.get("maxLength", 4096)
            if (
                type(minimum) is not int
                or type(maximum) is not int
                or minimum < 0
                or maximum < minimum
                or maximum > 65_536
            ):
                raise FixtureBuildError("fixture string bounds are invalid")
            string_format = schema.get("format")
            if string_format == "uuid":
                return self.uuid_json()
            if string_format == "date-time":
                return self.time_json()
            if string_format == "binary":
                return "x" * minimum
            if string_format is not None:
                raise FixtureBuildError("fixture string format is unsupported")
            pattern = schema.get("pattern")
            if pattern is not None:
                if not isinstance(pattern, str) or pattern not in _PATTERN_VALUES:
                    raise FixtureBuildError("fixture string pattern is unsupported")
                value = _PATTERN_VALUES[pattern]
                if not minimum <= len(value) <= maximum:
                    raise FixtureBuildError("fixture pattern value violates length bounds")
                return value
            length = max(1, minimum)
            if length > maximum:
                raise FixtureBuildError("fixture string cannot satisfy its bounds")
            return "x" * length
        if schema_type == "integer":
            minimum = schema.get("minimum", 0)
            if type(minimum) is not int:
                raise FixtureBuildError("fixture integer minimum is invalid")
            maximum = schema.get("maximum")
            if maximum is not None and (type(maximum) is not int or minimum > maximum):
                raise FixtureBuildError("fixture integer bounds are invalid")
            return minimum
        if schema_type == "boolean":
            return False
        if schema_type == "null":
            return None
        raise FixtureBuildError("fixture schema shape is unsupported")

    def schema_payload(self, model_type: type[ContractModel]) -> dict[str, JSONValue]:
        if model_type not in BUILDERS:
            raise FixtureBuildError("fixture model is not registered")
        schema = _schema_mapping(
            model_type.model_json_schema(
                mode="validation",
                ref_template="#/$defs/{model}",
            ),
            model_type.__name__,
        )
        _validate_schema_vocabulary(schema, label=model_type.__name__)
        payload = self._schema_value(schema, schema, path=(model_type.__name__,))
        if not isinstance(payload, dict):
            raise FixtureBuildError("contract model schema did not produce an object")
        return payload

    def validate_payload(
        self,
        model_type: type[ContractT],
        payload: Mapping[str, JSONValue],
    ) -> ContractT:
        raw = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return parse_contract_json(
            model_type,
            raw,
            max_bytes=1_048_576,
            require_canonical=False,
        )

    def memory_proposal_draft(
        self,
        operation: str,
        *,
        subject_id: str | None = None,
    ) -> memory.MemoryProposalDraft:
        if operation not in {"create", "replace", "delete"}:
            raise ValueError("unsupported memory proposal operation")
        payload = self.schema_payload(memory.MemoryProposalDraft)
        payload.update(
            {
                "operation": operation,
                "subject_id": subject_id or self.uuid_json(),
                "source_receipt_ids": [self.uuid_json()],
            }
        )
        if operation == "delete":
            payload.update(
                {
                    "content": None,
                    "audience": None,
                    "target_memory_id": self.uuid_json(),
                    "expected_version": 1,
                }
            )
        else:
            payload.update(
                {
                    "content": _model_json(self.build(memory.PreferenceContent)),
                    "audience": "subject_private",
                    "target_memory_id": (None if operation == "create" else self.uuid_json()),
                    "expected_version": None if operation == "create" else 1,
                }
            )
        return self.validate_payload(memory.MemoryProposalDraft, payload)

    def validated_semantic(self, model_type: type[ContractT]) -> ContractT:
        spec = semantic_specs()[model_type]
        values = spec.values(self)
        if not spec.fields <= set(values):
            raise FixtureBuildError("semantic fixture omitted a correlated field")
        unknown = set(values) - set(model_type.model_fields)
        if unknown:
            raise FixtureBuildError("semantic fixture supplied an unknown field")
        payload = self.schema_payload(model_type)
        payload.update(values)
        return self.validate_payload(model_type, payload)

    def validated_schema_only(self, model_type: type[ContractT]) -> ContractT:
        if model_type not in SCHEMA_ONLY_MODELS:
            raise FixtureBuildError("semantic model reached schema-only generation")
        return self.validate_payload(model_type, self.schema_payload(model_type))

    def build(self, model_type: type[ContractT]) -> ContractT:
        try:
            builder = BUILDERS[model_type]
        except KeyError as error:
            raise FixtureBuildError("fixture model is not classified") from error
        model = builder(self)
        if type(model) is not model_type:
            raise FixtureBuildError("fixture builder returned the wrong model type")
        reparsed = parse_contract_json(
            model_type,
            canonical_bytes(model),
            max_bytes=1_048_576,
            require_canonical=True,
        )
        return reparsed


def action_base(
    factory: FixtureFactory,
    action_name: str,
    resource_type: str,
    resource_id: str | None = None,
) -> dict[str, JSONValue]:
    return {
        "action_name": action_name,
        "resource_type": resource_type,
        "resource_id": resource_id or factory.uuid_json(),
    }


def _timer_target_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    timer_id = factory.uuid_json()
    return {
        **action_base(factory, "timer.cancel", "timer", timer_id),
        "timer_id": timer_id,
    }


def _memory_proposal_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    return {"draft": _model_json(factory.memory_proposal_draft("create"))}


def _memory_action_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    subject_id = factory.uuid_json()
    proposal = factory.memory_proposal_draft("replace", subject_id=subject_id)
    return {
        **action_base(factory, "memory.propose", "memory", str(proposal.proposal_id)),
        "subject_id": subject_id,
        "proposal_id_ref": None,
        "memory_id": None,
        "expected_version": None,
        "decision": None,
        "edited_content": None,
        "memory_proposal": _model_json(proposal),
        "export_format": None,
    }


def _credential_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    credential_id = factory.uuid_json()
    return {
        **action_base(
            factory,
            "credential.passkey.revoke",
            "credential",
            credential_id,
        ),
        "credential_id": credential_id,
        "capability": None,
        "ceremony_id": None,
        "expected_version": 1,
    }


def _backup_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    backup_id = factory.uuid_json()
    return {
        **action_base(factory, "backup.restore", "backup", backup_id),
        "backup_id": backup_id,
        "recipient_key_id": None,
        "manifest_sha256": "0" * 64,
    }


def _profile_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    subject_id = factory.uuid_json()
    return {
        **action_base(factory, "profile.revoke", "profile", subject_id),
        "subject_id": subject_id,
        "profile_class": None,
        "target_profile_class": None,
        "display_label": None,
        "guardian_id": None,
        "persona_traits": None,
        "clear_persona_traits": False,
        "expected_version": 1,
        "guardian_generation": None,
    }


def _consent_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    subject_id = factory.uuid_json()
    return {
        **action_base(factory, "consent.grant", "consent", subject_id),
        "subject_id": subject_id,
        "purpose": "personalization",
        "expected_latest_receipt_id": None,
        "guardian_generation": None,
    }


def _identity_action_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    subject_id = factory.uuid_json()
    return {
        **action_base(factory, "identity.enroll", "identity", subject_id),
        "subject_id": subject_id,
        "modality": "face",
        "enrollment_id": None,
        "expected_profile_version": 1,
        "expected_consent_receipt_id": factory.uuid_json(),
        "reenrollment_days": 180,
    }


def _search_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    subject_id = factory.uuid_json()
    return {
        **action_base(factory, "search.profile_mode.change", "search", subject_id),
        "subject_id": subject_id,
        "expected_profile_version": 1,
        "mode": "no_web",
        "expected_web_consent_receipt_id": None,
        "provider_review_version": None,
        "pricing_version": None,
        "privacy_generation": None,
        "feature_generation": None,
        "activation_issued_at": None,
        "activation_expires_at": None,
        "max_passes": None,
        "max_sources": None,
        "max_duration_seconds": None,
        "no_memory": None,
        "no_authenticated_sites": None,
        "no_files": None,
        "no_tools": None,
    }


def _route(
    factory: FixtureFactory,
    *,
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"],
    provider_name: Literal["openai", "qwen"] = "openai",
    model: str = "fixture-model",
) -> provider.RouteAuthorization:
    payload = factory.schema_payload(provider.RouteAuthorization)
    payload.update(
        {
            "purpose": purpose,
            "provider": provider_name,
            "model": model,
        }
    )
    return factory.validate_payload(provider.RouteAuthorization, payload)


def _transcription_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    route = _route(factory, purpose="cloud_stt", model="fixture-stt")
    return {
        "request_id": str(route.request_id),
        "turn_id": str(route.turn_id),
        "audio_commitment": _model_json(route.request_commitment),
        "language_hints": ["en", "hi"],
        "route": _model_json(route),
    }


def _synthesis_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    route = _route(factory, purpose="cloud_tts", model="fixture-tts")
    return {
        "request_id": str(route.request_id),
        "turn_id": str(route.turn_id),
        "text_commitment": _model_json(route.request_commitment),
        "segment_index": 0,
        "segment_count": 1,
        "route": _model_json(route),
    }


def _provider_request_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    route = _route(factory, purpose="cloud_reasoning")
    return {
        "request_id": str(route.request_id),
        "provider": route.provider,
        "model": route.model,
        "route": _model_json(route),
    }


def _binding(
    factory: FixtureFactory,
    *,
    subject_id: str | None,
    draft: actions.ActionProposalDraft | None = None,
) -> actions.ActionBinding:
    payload = factory.schema_payload(actions.ActionBinding)
    payload["subject_id"] = subject_id
    if draft is not None:
        payload.update(
            {
                "proposal_id": str(draft.proposal_id),
                "idempotency_key": str(draft.idempotency_key),
                "action_name": draft.action_name,
                "resource_type": draft.resource_type,
                "resource_id": None if draft.resource_id is None else str(draft.resource_id),
                "parameter_commitment": _model_json(draft.parameters_commitment),
            }
        )
    return factory.validate_payload(actions.ActionBinding, payload)


def _validated_action_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    draft = factory.build(actions.TimerCreateActionDraft)
    binding = _binding(factory, subject_id=factory.uuid_json(), draft=draft)
    return {"draft": _model_json(draft), "binding": _model_json(binding)}


def _authentication_request_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    subject_id = factory.uuid_json()
    return {
        "subject_id": subject_id,
        "binding": _model_json(_binding(factory, subject_id=subject_id)),
    }


def _authentication_challenge_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    return _authentication_request_values(factory)


def _auth_grant_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    subject_id = factory.uuid_json()
    return {
        "subject_id": subject_id,
        "binding": _model_json(_binding(factory, subject_id=subject_id)),
        "assurance": "confirmed",
        "assurance_source": "explicit_confirmation",
        "issued_at": factory.time_json(),
        "expires_at": factory.time_json(offset_microseconds=1),
    }


def _auth_context_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    return {
        "grant_id": None,
        "subject_id": None,
        "binding": _model_json(_binding(factory, subject_id=None)),
        "assurance": "guest",
        "assurance_source": "guest",
    }


def _latency_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    run_id = factory.uuid_json()
    return {
        **action_base(factory, "release.latency.accept", "soak_run", run_id),
        "run_id": run_id,
    }


def _operator_state_values(factory: FixtureFactory) -> dict[str, JSONValue]:
    ssh_username = "tuntunops"
    accepted_payload = factory.schema_payload(reachy_operator.ReachyAcceptedCapabilityV1)
    accepted_payload["ssh_username"] = ssh_username
    accepted = factory.validate_payload(
        reachy_operator.ReachyAcceptedCapabilityV1,
        accepted_payload,
    )
    return {
        "ssh_username": ssh_username,
        "reachy_ipv4": "192.168.10.20",
        "core_ipv4": "192.168.10.10",
        "accepted_capability": _model_json(accepted),
    }


def semantic_specs() -> dict[type[ContractModel], SemanticSpec]:
    return {
        Commitment: SemanticSpec(
            frozenset({"algorithm", "key_id", "value_b64"}),
            lambda _factory: {
                "algorithm": "HMAC-SHA-256",
                "key_id": "fixture-v1",
                "value_b64": "A" * 43 + "=",
            },
        ),
        events.EventEnvelope: SemanticSpec(
            frozenset({"event_type", "payload"}),
            lambda factory: {
                "event_type": "speech.wake_detected",
                "payload": _model_json(factory.build(events.WakeDetectedPayload)),
            },
        ),
        events.SignedEventEnvelope: SemanticSpec(
            frozenset({"envelope", "signing_key_id", "signature_b64"}),
            lambda factory: {
                "envelope": _model_json(factory.build(events.EventEnvelope)),
                "signing_key_id": "ed25519:fixture:v1",
                "signature_b64": "A" * 86 + "==",
            },
        ),
        speech.AuthorizedTranscriptionRequest: SemanticSpec(
            frozenset({"request_id", "turn_id", "audio_commitment", "language_hints", "route"}),
            _transcription_values,
        ),
        speech.AuthorizedSynthesisRequest: SemanticSpec(
            frozenset(
                {
                    "request_id",
                    "turn_id",
                    "text_commitment",
                    "segment_index",
                    "segment_count",
                    "route",
                }
            ),
            _synthesis_values,
        ),
        identity.IdentityEvidence: SemanticSpec(
            frozenset({"observed_at", "expires_at"}),
            lambda factory: {
                "observed_at": factory.time_json(),
                "expires_at": factory.time_json(),
            },
        ),
        identity.IdentityRequest: SemanticSpec(
            frozenset({"evidence"}),
            lambda _factory: {"evidence": []},
        ),
        identity.IdentityDecision: SemanticSpec(
            frozenset({"status", "subject_id"}),
            lambda factory: {"status": "verified", "subject_id": factory.uuid_json()},
        ),
        memory.EpisodicContent: SemanticSpec(
            frozenset({"participant_ids"}),
            lambda _factory: {"participant_ids": []},
        ),
        memory.MemoryProposalDraft: SemanticSpec(
            frozenset(
                {
                    "operation",
                    "content",
                    "audience",
                    "target_memory_id",
                    "expected_version",
                    "source_receipt_ids",
                }
            ),
            lambda factory: _model_json(factory.memory_proposal_draft("delete")),
        ),
        memory.MemoryProposal: SemanticSpec(
            frozenset({"draft"}),
            _memory_proposal_values,
        ),
        memory.MemoryRecord: SemanticSpec(
            frozenset({"version", "content", "audience"}),
            lambda factory: {
                "version": 1,
                "content": _model_json(factory.build(memory.PreferenceContent)),
                "audience": "subject_private",
            },
        ),
        memory.MemoryQuery: SemanticSpec(
            frozenset({"kinds"}),
            lambda _factory: {"kinds": ["working"]},
        ),
        memory.ApprovedMemory: SemanticSpec(
            frozenset({"content", "audience", "source_receipt_ids"}),
            lambda factory: {
                "content": _model_json(factory.build(memory.PreferenceContent)),
                "audience": "subject_private",
                "source_receipt_ids": [factory.uuid_json()],
            },
        ),
        memory.DecideMemoryProposal: SemanticSpec(
            frozenset({"decision", "edited_content"}),
            lambda _factory: {"decision": "reject", "edited_content": None},
        ),
        actions.TimerCreateActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type", "resource_id"}),
            lambda factory: action_base(factory, "timer.create", "timer"),
        ),
        actions.TimerTargetActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type", "resource_id", "timer_id"}),
            _timer_target_values,
        ),
        actions.SafetyActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type"}),
            lambda factory: {
                **action_base(factory, "privacy.on", "privacy"),
                "reason_code": "fixture",
            },
        ),
        actions.PrivacyReductionActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type", "typed_confirmation"}),
            lambda factory: {
                **action_base(factory, "privacy.off", "privacy"),
                "typed_confirmation": "TURN OFF PRIVACY",
            },
        ),
        actions.ComponentStatusActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type", "component"}),
            lambda factory: {
                **action_base(factory, "system.status", "system"),
                "component": "system",
            },
        ),
        actions.DiagnosticActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type"}),
            lambda factory: {
                **action_base(factory, "reachy.gesture_test", "reachy"),
                "registered_asset_id": "fixture.asset",
            },
        ),
        actions.MemoryActionDraft: SemanticSpec(
            frozenset(
                {
                    "action_name",
                    "resource_type",
                    "resource_id",
                    "subject_id",
                    "proposal_id_ref",
                    "memory_id",
                    "expected_version",
                    "decision",
                    "edited_content",
                    "memory_proposal",
                    "export_format",
                }
            ),
            _memory_action_values,
        ),
        actions.ProfileActionDraft: SemanticSpec(
            frozenset(
                {
                    "action_name",
                    "resource_type",
                    "resource_id",
                    "subject_id",
                    "profile_class",
                    "target_profile_class",
                    "display_label",
                    "guardian_id",
                    "persona_traits",
                    "clear_persona_traits",
                    "expected_version",
                    "guardian_generation",
                }
            ),
            _profile_values,
        ),
        actions.ConsentActionDraft: SemanticSpec(
            frozenset(
                {
                    "action_name",
                    "resource_type",
                    "resource_id",
                    "subject_id",
                    "expected_latest_receipt_id",
                    "guardian_generation",
                }
            ),
            _consent_values,
        ),
        actions.IdentityActionDraft: SemanticSpec(
            frozenset(
                {
                    "action_name",
                    "resource_type",
                    "resource_id",
                    "subject_id",
                    "modality",
                    "enrollment_id",
                    "expected_profile_version",
                    "expected_consent_receipt_id",
                    "reenrollment_days",
                }
            ),
            _identity_action_values,
        ),
        actions.ProviderActionDraft: SemanticSpec(
            frozenset(
                {
                    "action_name",
                    "resource_type",
                    "provider",
                    "enabled",
                    "review_record_id",
                    "hard_limit_micros_sgd",
                    "access_mode",
                    "expected_provider_version",
                    "expected_budget_version",
                    "expected_access_version",
                }
            ),
            lambda factory: {
                **action_base(factory, "provider.review", "provider"),
                "provider": "openai",
                "enabled": None,
                "review_record_id": None,
                "hard_limit_micros_sgd": None,
                "access_mode": None,
                "expected_provider_version": 1,
                "expected_budget_version": None,
                "expected_access_version": None,
            },
        ),
        actions.CredentialActionDraft: SemanticSpec(
            frozenset(
                {
                    "action_name",
                    "resource_type",
                    "resource_id",
                    "credential_id",
                    "capability",
                    "ceremony_id",
                    "expected_version",
                }
            ),
            _credential_values,
        ),
        actions.AuditActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type", "from_ordinal"}),
            lambda factory: {
                **action_base(factory, "audit.verify", "audit"),
                "from_ordinal": 1,
            },
        ),
        actions.BackupActionDraft: SemanticSpec(
            frozenset(
                {
                    "action_name",
                    "resource_type",
                    "resource_id",
                    "backup_id",
                    "recipient_key_id",
                    "manifest_sha256",
                }
            ),
            _backup_values,
        ),
        actions.SearchActionDraft: SemanticSpec(
            frozenset(
                {
                    "action_name",
                    "resource_type",
                    "resource_id",
                    "subject_id",
                    "mode",
                    "expected_web_consent_receipt_id",
                    "provider_review_version",
                    "pricing_version",
                    "privacy_generation",
                    "feature_generation",
                    "activation_issued_at",
                    "activation_expires_at",
                    "max_passes",
                    "max_sources",
                    "max_duration_seconds",
                    "no_memory",
                    "no_authenticated_sites",
                    "no_files",
                    "no_tools",
                }
            ),
            _search_values,
        ),
        actions.SecurityFindingActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type"}),
            lambda factory: action_base(
                factory,
                "security.finding.suppress",
                "security_finding",
            ),
        ),
        actions.ReleaseP1R0ActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type"}),
            lambda factory: action_base(factory, "release.p1r0", "release_candidate"),
        ),
        actions.LatencyDeviationActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type", "resource_id", "run_id"}),
            _latency_values,
        ),
        actions.FamilyStageReviewActionDraft: SemanticSpec(
            frozenset({"action_name", "resource_type"}),
            lambda factory: action_base(
                factory,
                "release.family_stage.review",
                "family_stage",
            ),
        ),
        actions.ValidatedActionProposal: SemanticSpec(
            frozenset({"draft", "binding"}),
            _validated_action_values,
        ),
        policy.PolicyRequest: SemanticSpec(
            frozenset({"action"}),
            lambda factory: {"action": _model_json(factory.build(actions.TimerCreateActionDraft))},
        ),
        policy.PolicyDecision: SemanticSpec(
            frozenset({"effect", "required_assurance"}),
            lambda _factory: {"effect": "allow", "required_assurance": None},
        ),
        policy.AuthenticationRequest: SemanticSpec(
            frozenset({"subject_id", "binding"}),
            _authentication_request_values,
        ),
        policy.AuthenticationChallenge: SemanticSpec(
            frozenset({"subject_id", "binding"}),
            _authentication_challenge_values,
        ),
        policy.AuthGrant: SemanticSpec(
            frozenset(
                {
                    "subject_id",
                    "binding",
                    "assurance",
                    "assurance_source",
                    "issued_at",
                    "expires_at",
                }
            ),
            _auth_grant_values,
        ),
        policy.AuthContext: SemanticSpec(
            frozenset({"grant_id", "subject_id", "binding", "assurance", "assurance_source"}),
            _auth_context_values,
        ),
        policy.AdminSessionPrincipal: SemanticSpec(
            frozenset({"authenticated_at", "idle_expires_at", "absolute_expires_at"}),
            lambda factory: {
                "authenticated_at": factory.time_json(),
                "idle_expires_at": factory.time_json(offset_microseconds=1),
                "absolute_expires_at": factory.time_json(offset_microseconds=2),
            },
        ),
        policy.TimerIntent: SemanticSpec(
            frozenset({"operation", "duration_seconds", "label_commitment"}),
            lambda factory: {
                "operation": "create",
                "duration_seconds": 1,
                "label_commitment": _model_json(factory.build(Commitment)),
            },
        ),
        provider.SanitizedProviderRequest: SemanticSpec(
            frozenset({"request_id", "provider", "model", "route"}),
            _provider_request_values,
        ),
        provider.RedactionReceipt: SemanticSpec(
            frozenset({"removed_categories"}),
            lambda _factory: {"removed_categories": []},
        ),
        budget.BudgetReservationRequest: SemanticSpec(
            frozenset({"category", "usage_ceiling", "month_key"}),
            lambda _factory: {
                "category": "llm",
                "usage_ceiling": {
                    "category": "llm",
                    "input_tokens": 1,
                    "output_tokens": 0,
                },
                "month_key": "2026-08",
            },
        ),
        budget.BudgetReservation: SemanticSpec(
            frozenset({"outcome", "amount_micros_sgd", "pricing_commitment"}),
            lambda factory: {
                "outcome": "allow",
                "amount_micros_sgd": 1,
                "pricing_commitment": _model_json(factory.build(Commitment)),
            },
        ),
        budget.BudgetAccountingContext: SemanticSpec(
            frozenset(
                {
                    "category",
                    "usage_ceiling",
                    "primary_accounting_basis",
                    "missing_evidence_policy",
                }
            ),
            lambda _factory: {
                "category": "llm",
                "usage_ceiling": {
                    "category": "llm",
                    "input_tokens": 1,
                    "output_tokens": 0,
                },
                "primary_accounting_basis": "provider_reported_exact",
                "missing_evidence_policy": "freeze_unknown_overage",
            },
        ),
        budget.ProviderUsageReceiptV1: SemanticSpec(
            frozenset({"category", "billable_usage"}),
            lambda _factory: {
                "category": "llm",
                "billable_usage": {
                    "category": "llm",
                    "input_tokens": 1,
                    "output_tokens": 0,
                },
            },
        ),
        budget.BudgetReconciliationRequest: SemanticSpec(
            frozenset({"proofs"}),
            lambda _factory: {"proofs": []},
        ),
        reachy.ReachyCommand: SemanticSpec(
            frozenset({"kind", "state", "media_stream_id", "gesture_id"}),
            lambda _factory: {
                "kind": "state",
                "state": "idle",
                "media_stream_id": None,
                "gesture_id": None,
            },
        ),
        reachy.CameraWindowGrant: SemanticSpec(
            frozenset(
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
            lambda factory: {
                "subject_id": factory.uuid_json(),
                "action_name": "identity.enroll",
                "purpose": "explicit_enrollment",
                "max_frames": 2,
                "max_frame_bytes": 1024,
                "max_total_bytes": 2048,
                "max_frames_per_second": 1,
                "issued_at": factory.time_json(),
                "expires_at": factory.time_json(offset_microseconds=5_000_000),
            },
        ),
        reachy_assistant_qualification.ReachyAssistantInventoryV1: SemanticSpec(
            frozenset({"managed_app_ids", "recovery_hook_ids"}),
            lambda _factory: {
                "managed_app_ids": [],
                "recovery_hook_ids": [],
            },
        ),
        reachy_operator.ReachyOperatorStateV1: SemanticSpec(
            frozenset({"ssh_username", "reachy_ipv4", "core_ipv4", "accepted_capability"}),
            _operator_state_values,
        ),
    }


REQUIRED_SEMANTIC_MODELS: frozenset[type[ContractModel]] = frozenset(semantic_specs())
SCHEMA_ONLY_MODELS: frozenset[type[ContractModel]] = frozenset(
    {
        events.WakeDetectedPayload,
        events.StopRequestedPayload,
        ports.TurnInput,
        ports.TurnOutput,
        speech.AudioFormat,
        speech.OfflineSynthesisRequest,
        speech.TranscriptResult,
        speech.SpeechChunk,
        identity.PersonaTraits,
        identity.PersonaProjection,
        memory.WorkingContent,
        memory.SemanticContent,
        memory.PreferenceContent,
        memory.ProceduralContent,
        memory.RelationalContent,
        memory.PolicyContent,
        memory.ProposalContext,
        actions.ActionDraftBase,
        actions.ActionBinding,
        actions.ActionReceipt,
        policy.AuthenticationResponse,
        policy.CurrentOwnerAuthority,
        provider.RouteAuthorization,
        provider.RouteAuthorizationRequest,
        provider.RouteConsumption,
        provider.ProviderResponseReceipt,
        provider.SanitizedProviderMessage,
        provider.SanitizedToolReference,
        provider.ProviderResponse,
        budget.LlmUsageUnits,
        budget.SttUsageUnits,
        budget.TtsUsageUnits,
        budget.WebSearchUsageUnits,
        budget.BudgetSettlementRequest,
        budget.BudgetSettlement,
        budget.TransportProof,
        audit.AuditDraft,
        audit.AuditReceipt,
        reachy.ReachyReceipt,
        reachy.ReachyHealth,
        reachy.SafetyReceipt,
        reachy.StopAllReceiptBundleV1,
        reachy.StopSignal,
        reachy_assistant_qualification.ReachyBootIdentityV1,
        reachy_assistant_qualification.ReachyNetworkCountersV1,
        reachy_operator.ReachyAcceptedCapabilityV1,
        reachy_time.CoreTimeProofV1,
        reachy_time.CoreTimeRequestV1,
    }
)


def _semantic_builder(model_type: type[ContractModel]) -> FixtureBuilder:
    def build_semantic(factory: FixtureFactory) -> ContractModel:
        return factory.validated_semantic(model_type)

    return build_semantic


def _schema_builder(model_type: type[ContractModel]) -> FixtureBuilder:
    def build_schema_only(factory: FixtureFactory) -> ContractModel:
        return factory.validated_schema_only(model_type)

    return build_schema_only


SEMANTIC_BUILDERS: dict[type[ContractModel], FixtureBuilder] = {
    model_type: _semantic_builder(model_type) for model_type in REQUIRED_SEMANTIC_MODELS
}
SCHEMA_ONLY_BUILDERS: dict[type[ContractModel], FixtureBuilder] = {
    model_type: _schema_builder(model_type) for model_type in SCHEMA_ONLY_MODELS
}
BUILDERS = SEMANTIC_BUILDERS | SCHEMA_ONLY_BUILDERS


def validate_builder_partition() -> None:
    semantic = set(semantic_specs())
    if semantic != set(REQUIRED_SEMANTIC_MODELS):
        raise FixtureBuildError("semantic fixture classification drifted")
    if semantic & set(SCHEMA_ONLY_MODELS):
        raise FixtureBuildError("semantic and schema-only fixtures overlap")
    public = {
        model_type for models in fixture_registry().values() for model_type in models.values()
    }
    if set(BUILDERS) != public:
        raise FixtureBuildError("fixture builders do not cover the public registry")


validate_builder_partition()
