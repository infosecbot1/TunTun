from __future__ import annotations

import asyncio
import keyword
from collections.abc import Callable
from concurrent.futures import Future as ConcurrentFuture
from dataclasses import MISSING, FrozenInstanceError, make_dataclass
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from enum import Enum
from functools import lru_cache
from threading import Condition, Lock
from types import (
    AsyncGeneratorType,
    CodeType,
    CoroutineType,
    FunctionType,
    GeneratorType,
    GetSetDescriptorType,
    MemberDescriptorType,
)
from typing import Protocol, cast
from uuid import UUID, SafeUUID
from zoneinfo import ZoneInfo

import tuntun_contracts
from pydantic_core import TzInfo
from tuntun_contracts.base import ContractModel, registered_contract_models
from tuntun_core.services.transactions.protocols import (
    AsyncUnitOfWorkProtocol,
    UnitOfWorkProtocol,
)


class RepositoryFactory[RepositoryT](Protocol):
    def __call__(self, transaction: UnitOfWorkProtocol) -> RepositoryT: ...


class _RejectedDeferredResult(TypeError):
    def __init__(
        self,
        values: tuple[object, ...],
        message: str,
    ) -> None:
        super().__init__(message)
        self.values = values


class _OwnedResultEnvelope[ResultT]:
    __slots__ = ("captured_sources", "record_sources", "snapshot")

    def __init__(
        self,
        snapshot: ResultT,
        record_sources: tuple[object, ...],
        captured_sources: tuple[object, ...],
    ) -> None:
        self.snapshot = snapshot
        self.record_sources = record_sources
        self.captured_sources = captured_sources


class _ResultInspection:
    def __init__(self, root: object, message: str) -> None:
        self.root = root
        self.message = message
        self.retained: list[object] = [root]
        self.retained_ids: set[int] = {id(root)}
        self.snapshots: dict[int, object] = {}
        self.shallow_sources: dict[int, object] = {}
        # Strong source references make integer identity memoization sound even
        # when another alias removes a traversed object and CPython would
        # otherwise reuse its id before this inspection finishes.
        self.sources: dict[int, object] = {id(root): root}
        self.record_sources: list[object] = []
        self.record_source_ids: set[int] = set()
        self.requires_terminal_handoff = False
        self.seen: set[int] = set()
        self.visiting: set[int] = set()
        self.rejected = False

    def retain(self, value: object) -> None:
        identity = id(value)
        if identity not in self.retained_ids:
            self.retained_ids.add(identity)
            self.retained.append(value)

    def reject(self, value: object) -> None:
        self.rejected = True
        self.retain(value)

    def retain_record_source(self, value: object) -> None:
        identity = id(value)
        self.retain(value)
        self.requires_terminal_handoff = True
        if identity not in self.record_source_ids:
            self.record_source_ids.add(identity)
            self.record_sources.append(value)

    def capture(self, value: object) -> None:
        self.sources[id(value)] = value

    def capture_mapping(self, source: dict[object, object]) -> None:
        for key, value in source.items():
            self.capture(key)
            self.capture(value)

    def capture_members(self, source: list[object] | set[object]) -> None:
        for value in source:
            self.capture(value)

    def require_terminal_source_handoff(self) -> None:
        self.requires_terminal_handoff = True

    def captured_sources_for_handoff(self) -> tuple[object, ...]:
        if not self.requires_terminal_handoff:
            return ()
        return tuple(self.sources.values())

    def raise_if_rejected(self) -> None:
        if self.rejected:
            # Retain both the root graph and each exact rejected object. The
            # latter remains safe even if another alias mutates a built-in
            # container after this inspection discovered a nested capability.
            raise _RejectedDeferredResult(tuple(self.retained), self.message)


_SAFE_ATOMIC_TYPES = (
    type(None),
    bool,
    int,
    float,
    str,
    bytes,
    Decimal,
    date,
    time,
    timedelta,
)

_CODE_FINGERPRINT_ATTRIBUTES = (
    "co_argcount",
    "co_posonlyargcount",
    "co_kwonlyargcount",
    "co_nlocals",
    "co_flags",
    "co_code",
    "co_consts",
    "co_names",
    "co_varnames",
    "co_freevars",
    "co_cellvars",
)


def _exported_contract_enum_types() -> tuple[type[Enum], ...]:
    result: list[type[Enum]] = []
    for name in tuntun_contracts.__all__:
        exported: object = getattr(tuntun_contracts, name)
        if (
            isinstance(exported, type)
            and issubclass(exported, Enum)
            and not any(exported is enum_type for enum_type in result)
        ):
            result.append(exported)
    return tuple(result)


_CONTRACT_ENUM_TYPES = _exported_contract_enum_types()
_REGISTERED_CONTRACT_MODEL_TYPES = registered_contract_models()
_REGISTERED_CONTRACT_FIELDS = tuple(
    (model_type, tuple(model_type.model_fields)) for model_type in _REGISTERED_CONTRACT_MODEL_TYPES
)


def _canonical_enum_members(
    enum_types: tuple[type[Enum], ...],
) -> tuple[tuple[Enum, type[Enum], str, object, int], ...]:
    return tuple(
        (
            member,
            enum_type,
            object.__getattribute__(member, "_name_"),
            object.__getattribute__(member, "_value_"),
            index,
        )
        for enum_type in enum_types
        for index, member in enumerate(enum_type)
    )


_CONTRACT_ENUM_MEMBERS = _canonical_enum_members(_CONTRACT_ENUM_TYPES)
_SAFE_UUID_MEMBERS = _canonical_enum_members((SafeUUID,))
_UNSAFE_METADATA = object()
_MAX_SYNCHRONOUS_RECORD_FIELDS = 64
_MAX_SYNCHRONOUS_RECORD_FIELD_NAME_LENGTH = 128
_MAX_SYNCHRONOUS_RECORD_FIELD_NAME_CHARS = 4096
_MAX_SYNCHRONOUS_RECORD_SHAPES = 128
_OWNED_RECORD_SEAL = object()
_OWNED_RECORD_SEAL_ATTRIBUTE = "__tuntun_owned_record_seal__"
_OWNED_RECORD_FIELDS_ATTRIBUTE = "__tuntun_owned_record_fields__"
_OWNED_RECORD_TYPES: dict[tuple[str, ...], type[object]] = {}
_OWNED_RECORD_TYPES_LOCK = Lock()
_OWNED_RECORD_TYPES_CONDITION = Condition(_OWNED_RECORD_TYPES_LOCK)
_OWNED_RECORD_SHAPE_RESERVATIONS: set[tuple[str, ...]] = set()


class _SealedOwnedRecordMeta(type):
    def __setattr__(cls, name: str, value: object) -> None:
        namespace = type.__getattribute__(cls, "__dict__")
        if namespace.get(_OWNED_RECORD_SEAL_ATTRIBUTE) is _OWNED_RECORD_SEAL:
            raise TypeError("module-owned synchronous data record type is sealed")
        type.__setattr__(cls, name, value)

    def __delattr__(cls, name: str) -> None:
        namespace = type.__getattribute__(cls, "__dict__")
        if namespace.get(_OWNED_RECORD_SEAL_ATTRIBUTE) is _OWNED_RECORD_SEAL:
            raise TypeError("module-owned synchronous data record type is sealed")
        type.__delattr__(cls, name)


class _SealedOwnedRecordBase(metaclass=_SealedOwnedRecordMeta):
    __slots__ = ()


type.__setattr__(
    _SealedOwnedRecordBase,
    _OWNED_RECORD_SEAL_ATTRIBUTE,
    _OWNED_RECORD_SEAL,
)


class _FingerprintTraversal:
    def __init__(self, inspection: _ResultInspection | None) -> None:
        self.inspection = inspection
        self.sources: dict[int, object] = {}
        self.visiting: set[int] = set()

    def enter(self, value: object) -> bool:
        identity = id(value)
        self.sources[identity] = value
        if self.inspection is not None:
            # Make every metadata/function object discoverable by the terminal
            # snapshot-failure path before recursing into any mutable state.
            self.inspection.sources[identity] = value
        if identity in self.visiting:
            if self.inspection is not None:
                _reject_metadata_value(value, self.inspection)
            return False
        self.visiting.add(identity)
        return True

    def leave(self, value: object) -> None:
        self.visiting.remove(id(value))


def _closure_fingerprint(
    value: object,
    owner_type: type[object],
    inspection: _ResultInspection | None = None,
    owner_aliases: tuple[type[object], ...] = (),
    traversal: _FingerprintTraversal | None = None,
) -> tuple[object, ...] | None:
    if value is owner_type or any(value is alias for alias in owner_aliases):
        return ("owner-type",)
    if value is object:
        return ("builtins-object",)
    if value is FrozenInstanceError:
        return ("frozen-instance-error",)
    if type(value) is set and not value:
        return ("empty-set",)
    if type(value) is FunctionType:
        nested = _function_fingerprint(
            value,
            owner_type,
            inspection,
            owner_aliases,
            traversal,
        )
        return None if nested is None else ("function", nested)
    if inspection is not None:
        _reject_metadata_value(value, inspection)
    return None


def _reject_metadata_value(value: object, inspection: _ResultInspection) -> None:
    _inspect_data_value(value, inspection)
    inspection.reject(value)


def _metadata_fingerprint(
    value: object,
    inspection: _ResultInspection | None = None,
    traversal: _FingerprintTraversal | None = None,
) -> object:
    active_traversal = traversal or _FingerprintTraversal(inspection)
    if not active_traversal.enter(value):
        return _UNSAFE_METADATA
    try:
        return _metadata_fingerprint_body(value, inspection, active_traversal)
    finally:
        active_traversal.leave(value)


def _metadata_fingerprint_body(
    value: object,
    inspection: _ResultInspection | None,
    traversal: _FingerprintTraversal,
) -> object:
    value_type = type(value)
    if value is None:
        return ("none",)
    if value_type is bool:
        return ("bool", value)
    if value_type is int:
        return ("int", value)
    if value_type is float:
        return ("float", value)
    if value_type is str:
        return ("str", value)
    if value_type is bytes:
        return ("bytes", value)
    if value_type is tuple:
        tuple_items: list[object] = []
        valid = True
        for item in cast(tuple[object, ...], value):
            fingerprint = _metadata_fingerprint(item, inspection, traversal)
            if fingerprint is _UNSAFE_METADATA:
                valid = False
            else:
                tuple_items.append(fingerprint)
        return ("tuple", tuple(tuple_items)) if valid else _UNSAFE_METADATA
    if value_type is frozenset:
        frozen = cast(frozenset[object], value)
        if any(type(item) is not str for item in frozen):
            if inspection is not None:
                for item in frozen:
                    if type(item) is not str:
                        _reject_metadata_value(item, inspection)
            return _UNSAFE_METADATA
        return ("frozenset", tuple(sorted(cast(frozenset[str], frozen))))
    if value_type is dict:
        source = cast(dict[object, object], value).copy()
        if inspection is not None:
            inspection.capture_mapping(source)
        dictionary_items: list[tuple[str, object]] = []
        valid = True
        for key, item in source.items():
            if type(key) is not str:
                if inspection is not None:
                    _reject_metadata_value(key, inspection)
                    _reject_metadata_value(item, inspection)
                valid = False
                continue
            fingerprint = _metadata_fingerprint(item, inspection, traversal)
            if fingerprint is _UNSAFE_METADATA:
                valid = False
                continue
            dictionary_items.append((key, fingerprint))
        return (
            (
                "dict",
                tuple(sorted(dictionary_items, key=lambda item: item[0])),
            )
            if valid
            else _UNSAFE_METADATA
        )
    if value_type is CodeType:
        code_items: list[object] = []
        valid = True
        for name in _CODE_FINGERPRINT_ATTRIBUTES:
            fingerprint = _metadata_fingerprint(
                getattr(value, name),
                inspection,
                traversal,
            )
            if fingerprint is _UNSAFE_METADATA:
                valid = False
            else:
                code_items.append(fingerprint)
        return ("code", tuple(code_items)) if valid else _UNSAFE_METADATA
    if inspection is not None:
        _reject_metadata_value(value, inspection)
    return _UNSAFE_METADATA


def _function_fingerprint(
    value: object,
    owner_type: type[object],
    inspection: _ResultInspection | None = None,
    owner_aliases: tuple[type[object], ...] = (),
    traversal: _FingerprintTraversal | None = None,
) -> tuple[object, ...] | None:
    if type(value) is not FunctionType:
        if inspection is not None:
            _reject_metadata_value(value, inspection)
        return None
    active_traversal = traversal or _FingerprintTraversal(inspection)
    if not active_traversal.enter(value):
        return None
    try:
        return _function_fingerprint_body(
            value,
            owner_type,
            inspection,
            owner_aliases,
            active_traversal,
        )
    finally:
        active_traversal.leave(value)


def _function_fingerprint_body(
    value: FunctionType,
    owner_type: type[object],
    inspection: _ResultInspection | None,
    owner_aliases: tuple[type[object], ...],
    traversal: _FingerprintTraversal,
) -> tuple[object, ...] | None:
    code = value.__code__
    raw_annotations = value.__annotations__
    raw_function_state = value.__dict__
    valid = True
    if type(raw_annotations) is dict:
        annotations = cast(dict[object, object], raw_annotations).copy()
        if inspection is not None:
            inspection.capture(raw_annotations)
            inspection.capture_mapping(annotations)
    else:
        annotations = {}
        if inspection is not None:
            _reject_metadata_value(raw_annotations, inspection)
        valid = False
    if type(raw_function_state) is dict:
        function_state = cast(dict[object, object], raw_function_state).copy()
        if inspection is not None:
            inspection.capture(raw_function_state)
            inspection.capture_mapping(function_state)
    else:
        function_state = {}
        if inspection is not None:
            _reject_metadata_value(raw_function_state, inspection)
        valid = False
    annotation_items: list[tuple[str, object]] = []
    for key, annotation in annotations.items():
        if type(key) is not str:
            if inspection is not None:
                _reject_metadata_value(key, inspection)
                _reject_metadata_value(annotation, inspection)
            valid = False
            continue
        if type(annotation) is str or annotation is object:
            annotation_fingerprint: object = ("field-annotation",)
        elif annotation is None:
            annotation_fingerprint = ("none",)
        else:
            if inspection is not None:
                _reject_metadata_value(annotation, inspection)
            valid = False
            continue
        annotation_items.append((key, annotation_fingerprint))
    function_state_items: list[tuple[str, object]] = []
    for key, state_value in function_state.items():
        if type(key) is not str:
            if inspection is not None:
                _reject_metadata_value(key, inspection)
                _reject_metadata_value(state_value, inspection)
            valid = False
            continue
        state_fingerprint: object
        if key == "__wrapped__":
            state_fingerprint = _function_fingerprint(
                state_value,
                owner_type,
                inspection,
                owner_aliases,
                traversal,
            )
            if state_fingerprint is None:
                valid = False
                continue
        else:
            state_fingerprint = _metadata_fingerprint(
                state_value,
                inspection,
                traversal,
            )
            if state_fingerprint is _UNSAFE_METADATA:
                valid = False
                continue
        function_state_items.append((key, state_fingerprint))
    closure: list[tuple[object, ...]] = []
    for cell in value.__closure__ or ():
        try:
            content = cell.cell_contents
        except ValueError:
            valid = False
            continue
        fingerprint = _closure_fingerprint(
            content,
            owner_type,
            inspection,
            owner_aliases,
            traversal,
        )
        if fingerprint is None:
            valid = False
        else:
            closure.append(fingerprint)
    code_fingerprint = _metadata_fingerprint(code, inspection, traversal)
    defaults_fingerprint = _metadata_fingerprint(
        value.__defaults__,
        inspection,
        traversal,
    )
    kwdefaults_fingerprint = _metadata_fingerprint(
        value.__kwdefaults__,
        inspection,
        traversal,
    )
    if (
        code_fingerprint is _UNSAFE_METADATA
        or defaults_fingerprint is _UNSAFE_METADATA
        or kwdefaults_fingerprint is _UNSAFE_METADATA
    ):
        valid = False
    if not valid:
        return None
    return (
        code_fingerprint,
        defaults_fingerprint,
        kwdefaults_fingerprint,
        tuple(sorted(annotation_items)),
        tuple(sorted(function_state_items)),
        tuple(closure),
    )


def _metadata_matches(
    actual: object,
    expected: object,
    inspection: _ResultInspection | None = None,
) -> bool:
    actual_fingerprint = _metadata_fingerprint(actual, inspection)
    expected_fingerprint = _metadata_fingerprint(expected)
    matches = (
        actual_fingerprint is not _UNSAFE_METADATA
        and expected_fingerprint is not _UNSAFE_METADATA
        and actual_fingerprint == expected_fingerprint
    )
    if not matches and inspection is not None:
        # A closed class/Field/function metadata snapshot can be the last
        # reference after a concurrent caller removes the live class entry.
        # Transfer the exact mismatch before the local snapshot unwinds.
        _reject_metadata_value(actual, inspection)
    return matches


def _bounded_record_field_names(field_names: tuple[str, ...]) -> bool:
    return (
        len(field_names) <= _MAX_SYNCHRONOUS_RECORD_FIELDS
        and all(
            0 < len(name) <= _MAX_SYNCHRONOUS_RECORD_FIELD_NAME_LENGTH
            and name.isidentifier()
            and not keyword.iskeyword(name)
            and name not in (_OWNED_RECORD_SEAL_ATTRIBUTE, _OWNED_RECORD_FIELDS_ATTRIBUTE)
            for name in field_names
        )
        and sum(len(name) for name in field_names) <= _MAX_SYNCHRONOUS_RECORD_FIELD_NAME_CHARS
    )


@lru_cache(maxsize=128)
def _reference_record_type(field_names: tuple[str, ...]) -> type[object]:
    if not _bounded_record_field_names(field_names):
        raise ValueError("synchronous data record field shape exceeds its closed bound")
    return cast(
        type[object],
        make_dataclass(
            "_SynchronousDataRecord",
            [(name, object) for name in field_names],
            frozen=True,
            slots=True,
        ),
    )


def _owned_record_type(field_names: tuple[str, ...]) -> type[object]:
    if not _bounded_record_field_names(field_names):
        raise ValueError("synchronous data record field shape exceeds its closed bound")
    with _OWNED_RECORD_TYPES_CONDITION:
        existing = _OWNED_RECORD_TYPES.get(field_names)
        if existing is not None:
            if field_names in _OWNED_RECORD_SHAPE_RESERVATIONS:
                _OWNED_RECORD_SHAPE_RESERVATIONS.remove(field_names)
                _OWNED_RECORD_TYPES_CONDITION.notify_all()
            return existing
        if field_names not in _OWNED_RECORD_SHAPE_RESERVATIONS:
            raise RuntimeError("synchronous data record shape was not reserved")
        try:
            owned_type = cast(
                type[object],
                make_dataclass(
                    "_SynchronousDataRecord",
                    [(name, object) for name in field_names],
                    bases=(_SealedOwnedRecordBase,),
                    frozen=True,
                    slots=True,
                ),
            )
            type.__setattr__(owned_type, _OWNED_RECORD_FIELDS_ATTRIBUTE, field_names)
            # Seal last: all subsequent ordinary class setattr/delattr operations,
            # including special-method replacement, fail before changing behavior.
            type.__setattr__(owned_type, _OWNED_RECORD_SEAL_ATTRIBUTE, _OWNED_RECORD_SEAL)
            _OWNED_RECORD_TYPES[field_names] = owned_type
            return owned_type
        finally:
            _OWNED_RECORD_SHAPE_RESERVATIONS.remove(field_names)
            _OWNED_RECORD_TYPES_CONDITION.notify_all()


def _reserve_owned_record_shape(field_names: tuple[str, ...]) -> bool:
    with _OWNED_RECORD_TYPES_CONDITION:
        while field_names in _OWNED_RECORD_SHAPE_RESERVATIONS:
            _OWNED_RECORD_TYPES_CONDITION.wait()
        if _OWNED_RECORD_TYPES.get(field_names) is not None:
            return False
        if (
            len(_OWNED_RECORD_TYPES) + len(_OWNED_RECORD_SHAPE_RESERVATIONS)
            >= _MAX_SYNCHRONOUS_RECORD_SHAPES
        ):
            raise ValueError("synchronous data record shape cache is exhausted")
        _OWNED_RECORD_SHAPE_RESERVATIONS.add(field_names)
        return True


def _release_owned_record_shape_reservation(
    field_names: tuple[str, ...],
    reserved: bool,
) -> None:
    if not reserved:
        return
    with _OWNED_RECORD_TYPES_CONDITION:
        if field_names in _OWNED_RECORD_SHAPE_RESERVATIONS:
            _OWNED_RECORD_SHAPE_RESERVATIONS.remove(field_names)
            _OWNED_RECORD_TYPES_CONDITION.notify_all()


def _function_closed_values(value: object) -> tuple[object, ...]:
    if type(value) is not FunctionType:
        return ()
    contents: list[object] = []
    for cell in value.__closure__ or ():
        try:
            contents.append(cell.cell_contents)
        except ValueError:
            continue
    return tuple(contents)


def _candidate_slots_owner_types(
    record_type: type[object],
    namespace: dict[str, object],
) -> tuple[type[object], ...]:
    candidates: list[type[object]] = []
    for function_name in ("__setattr__", "__delattr__"):
        for content in _function_closed_values(namespace.get(function_name)):
            if (
                type(content) is type
                and content is not record_type
                and content is not FrozenInstanceError
                and not any(content is candidate for candidate in candidates)
            ):
                candidates.append(cast(type[object], content))
    return tuple(candidates)


def _retain_record_metadata_value(
    value: object,
    record_type: type[object],
    inspection: _ResultInspection,
) -> None:
    if type(value) is FunctionType:
        _function_fingerprint(value, record_type, inspection)
        inspection.reject(value)
    else:
        _reject_metadata_value(value, inspection)


def _snapshot_plain_type_namespace(
    record_type: type[object],
    inspection: _ResultInspection,
) -> tuple[dict[str, object], bool]:
    namespace: dict[str, object] = {}
    valid = True
    namespace_proxy = type.__getattribute__(record_type, "__dict__")
    for key, value in namespace_proxy.items():
        inspection.capture(key)
        inspection.capture(value)
        if type(key) is not str:
            _inspect_data_value(key, inspection)
            inspection.reject(key)
            _retain_record_metadata_value(value, record_type, inspection)
            valid = False
            continue
        namespace[key] = value
    return namespace, valid


def _validated_slots_owner_aliases(
    record_type: type[object],
    actual_namespace: dict[str, object],
    reference: type[object],
    reference_namespace: dict[str, object],
    inspection: _ResultInspection,
) -> tuple[type[object], ...]:
    actual_candidates = _candidate_slots_owner_types(record_type, actual_namespace)
    reference_candidates = _candidate_slots_owner_types(reference, reference_namespace)
    if len(reference_candidates) != 1:
        raise RuntimeError("trusted synchronous record owner shape drifted")
    reference_owner_namespace = dict(vars(reference_candidates[0]))
    validated: list[type[object]] = []
    for candidate in actual_candidates:
        candidate_namespace, candidate_valid = _snapshot_plain_type_namespace(
            candidate,
            inspection,
        )
        if candidate_namespace.keys() != reference_owner_namespace.keys():
            candidate_valid = False
            for key, item in candidate_namespace.items():
                if type(key) is not str or key not in reference_owner_namespace:
                    _reject_metadata_value(key, inspection)
                    _retain_record_metadata_value(item, record_type, inspection)

        for attribute in ("__name__", "__qualname__", "__module__"):
            candidate_value = type.__getattribute__(candidate, attribute)
            record_value = type.__getattribute__(record_type, attribute)
            if (
                type(candidate_value) is not str
                or type(record_value) is not str
                or candidate_value != record_value
            ):
                _reject_metadata_value(candidate_value, inspection)
                candidate_valid = False
        if type.__getattribute__(candidate, "__bases__") != (object,):
            inspection.reject(candidate)
            candidate_valid = False

        for name, item in candidate_namespace.items():
            if name in ("__dict__", "__weakref__"):
                if (
                    type(item) is not GetSetDescriptorType
                    or item.__name__ != name
                    or item.__objclass__ is not candidate
                ):
                    _retain_record_metadata_value(item, record_type, inspection)
                    candidate_valid = False
                continue
            outer_item = actual_namespace.get(name, _UNSAFE_METADATA)
            if name == "__dataclass_fields__" and type(item) is dict and type(outer_item) is dict:
                hidden_fields = cast(dict[object, object], item).copy()
                inspection.capture_mapping(hidden_fields)
                outer_fields = cast(dict[object, object], outer_item)
                keys_are_closed = all(type(field_name) is str for field_name in hidden_fields)
                fields_match = keys_are_closed and (hidden_fields.keys() == outer_fields.keys())
                for field_name, field_value in hidden_fields.items():
                    if (
                        type(field_name) is not str
                        or field_name not in outer_fields
                        or field_value is not outer_fields[field_name]
                    ):
                        _reject_metadata_value(field_name, inspection)
                        _reject_metadata_value(field_value, inspection)
                        fields_match = False
                if not fields_match:
                    inspection.reject(item)
                    candidate_valid = False
                continue
            if outer_item is _UNSAFE_METADATA or item is not outer_item:
                _retain_record_metadata_value(item, record_type, inspection)
                candidate_valid = False
        if candidate_valid:
            validated.append(candidate)
        else:
            inspection.reject(candidate)
    if len(validated) != 1:
        for candidate in actual_candidates:
            inspection.reject(candidate)
        return ()
    return tuple(validated)


def _has_exact_generated_record_shape(
    record_type: type[object],
    field_names: tuple[str, ...],
    actual_namespace: dict[str, object],
    inspection: _ResultInspection,
) -> bool:
    reference = _reference_record_type(field_names)
    reference_namespace = dict(vars(reference))
    valid = True
    owner_aliases = _validated_slots_owner_aliases(
        record_type,
        actual_namespace,
        reference,
        reference_namespace,
        inspection,
    )
    reference_owner_aliases = _candidate_slots_owner_types(reference, reference_namespace)
    if len(owner_aliases) != 1:
        valid = False

    # Fingerprint every caller-owned function before any shape check can
    # return. Each function fingerprint takes closed copies of annotations and
    # function state, and transfers every unsafe nested value to inspection.
    actual_function_fingerprints: dict[str, tuple[object, ...] | None] = {}
    for name, candidate in actual_namespace.items():
        if type(candidate) is FunctionType:
            fingerprint = _function_fingerprint(
                candidate,
                record_type,
                inspection,
                owner_aliases,
            )
            actual_function_fingerprints[name] = fingerprint
            if fingerprint is None:
                inspection.reject(candidate)
                valid = False

    if actual_namespace.keys() != reference_namespace.keys():
        valid = False
        for key, candidate in actual_namespace.items():
            if type(key) is not str or key not in reference_namespace:
                _reject_metadata_value(key, inspection)
                if type(candidate) is FunctionType:
                    # The closed fingerprint above already inspected its
                    # mutable annotations/state; retain the direct function too.
                    inspection.reject(candidate)
                else:
                    _reject_metadata_value(candidate, inspection)

    actual_parameters = actual_namespace.get("__dataclass_params__", _UNSAFE_METADATA)
    reference_parameters = reference_namespace["__dataclass_params__"]
    parameter_names = (
        "init",
        "repr",
        "eq",
        "order",
        "unsafe_hash",
        "frozen",
        "match_args",
        "kw_only",
        "slots",
        "weakref_slot",
    )
    if type(actual_parameters) is not type(reference_parameters):
        if actual_parameters is not _UNSAFE_METADATA:
            _reject_metadata_value(actual_parameters, inspection)
        valid = False
    else:
        for name in parameter_names:
            if not _metadata_matches(
                object.__getattribute__(actual_parameters, name),
                object.__getattribute__(reference_parameters, name),
                inspection,
            ):
                valid = False

    raw_annotations = actual_namespace.get("__annotations__", _UNSAFE_METADATA)
    annotations: dict[object, object] = {}
    if type(raw_annotations) is not dict:
        if raw_annotations is not _UNSAFE_METADATA:
            _reject_metadata_value(raw_annotations, inspection)
        valid = False
    else:
        annotations = cast(dict[object, object], raw_annotations).copy()
        inspection.capture(raw_annotations)
        inspection.capture_mapping(annotations)
    annotation_names = tuple(annotations)
    annotation_names_are_closed = True
    for annotation_name, annotation in annotations.items():
        if type(annotation_name) is not str or type(annotation) is not str:
            _reject_metadata_value(annotation_name, inspection)
            _reject_metadata_value(annotation, inspection)
            if type(annotation_name) is not str:
                annotation_names_are_closed = False
            valid = False
    if not annotation_names_are_closed or annotation_names != field_names:
        inspection.reject(raw_annotations)
        valid = False

    actual_module = actual_namespace.get("__module__", _UNSAFE_METADATA)
    if type(actual_module) is not str:
        if actual_module is not _UNSAFE_METADATA:
            _reject_metadata_value(actual_module, inspection)
        valid = False
    actual_doc = actual_namespace.get("__doc__", _UNSAFE_METADATA)
    if type(actual_doc) is not str and actual_doc is not None:
        if actual_doc is not _UNSAFE_METADATA:
            _reject_metadata_value(actual_doc, inspection)
        valid = False
    for metadata_name, expected in (
        ("__match_args__", field_names),
        ("__slots__", field_names),
    ):
        actual = actual_namespace.get(metadata_name, _UNSAFE_METADATA)
        if actual is _UNSAFE_METADATA or not _metadata_matches(
            actual,
            expected,
            inspection,
        ):
            valid = False

    actual_fields = actual_namespace.get("__dataclass_fields__", _UNSAFE_METADATA)
    reference_fields = reference_namespace["__dataclass_fields__"]
    if type(actual_fields) is not dict:
        if actual_fields is not _UNSAFE_METADATA:
            _reject_metadata_value(actual_fields, inspection)
        actual_fields = {}
        valid = False
    actual_field_map = cast(dict[object, object], actual_fields)
    field_names_are_closed = True
    for field_key, candidate in actual_field_map.items():
        if type(field_key) is not str or field_key not in field_names:
            _reject_metadata_value(field_key, inspection)
            _reject_metadata_value(candidate, inspection)
            if type(field_key) is not str:
                field_names_are_closed = False
            valid = False
    if not field_names_are_closed or tuple(actual_field_map) != field_names:
        valid = False

    for name in field_names:
        if name not in actual_field_map:
            valid = False
            continue
        actual_field = actual_field_map[name]
        reference_field = reference_fields[name]
        if type(actual_field) is not type(reference_field):
            _reject_metadata_value(actual_field, inspection)
            valid = False
            continue

        actual_field_name = object.__getattribute__(actual_field, "name")
        actual_field_type = object.__getattribute__(actual_field, "type")
        actual_default = object.__getattribute__(actual_field, "default")
        actual_default_factory = object.__getattribute__(actual_field, "default_factory")
        actual_metadata = object.__getattribute__(actual_field, "metadata")
        actual_field_type_marker = object.__getattribute__(actual_field, "_field_type")
        reference_metadata = object.__getattribute__(reference_field, "metadata")
        reference_field_type_marker = object.__getattribute__(reference_field, "_field_type")
        if not _metadata_matches(actual_field_name, name, inspection):
            valid = False
        expected_annotation = annotations.get(name, _UNSAFE_METADATA)
        if type(actual_field_type) is not str or expected_annotation is _UNSAFE_METADATA:
            _reject_metadata_value(actual_field_type, inspection)
            valid = False
        elif not _metadata_matches(actual_field_type, expected_annotation, inspection):
            valid = False
        if actual_default is not MISSING:
            _reject_metadata_value(actual_default, inspection)
            valid = False
        if actual_default_factory is not MISSING:
            _reject_metadata_value(actual_default_factory, inspection)
            valid = False
        if actual_metadata is not reference_metadata:
            _reject_metadata_value(actual_metadata, inspection)
            valid = False
        if actual_field_type_marker is not reference_field_type_marker:
            _reject_metadata_value(actual_field_type_marker, inspection)
            valid = False
        for attribute in ("init", "repr", "hash", "compare", "kw_only"):
            if not _metadata_matches(
                object.__getattribute__(actual_field, attribute),
                object.__getattribute__(reference_field, attribute),
                inspection,
            ):
                valid = False

        actual_descriptor = actual_namespace.get(name, _UNSAFE_METADATA)
        if actual_descriptor is _UNSAFE_METADATA:
            valid = False
        elif type(actual_descriptor) is not type(reference_namespace[name]):
            _reject_metadata_value(actual_descriptor, inspection)
            valid = False

    for name, expected in reference_namespace.items():
        if type(expected) is not FunctionType:
            continue
        actual = actual_namespace.get(name, _UNSAFE_METADATA)
        expected_fingerprint = _function_fingerprint(
            expected,
            reference,
            owner_aliases=reference_owner_aliases,
        )
        actual_fingerprint = actual_function_fingerprints.get(name)
        if (
            actual is _UNSAFE_METADATA
            or type(actual) is not FunctionType
            or actual_fingerprint is None
            or actual_fingerprint != expected_fingerprint
        ):
            if actual is not _UNSAFE_METADATA:
                if type(actual) is FunctionType:
                    inspection.reject(actual)
                else:
                    _reject_metadata_value(actual, inspection)
            valid = False
    return valid


def _inspect_datetime(value: datetime, inspection: _ResultInspection) -> datetime:
    zone = value.tzinfo
    if (
        zone is not None
        and type(zone) is not timezone
        and type(zone) is not ZoneInfo
        and type(zone) is not TzInfo
    ):
        inspection.reject(value)
    return value


def _inspect_time(value: time, inspection: _ResultInspection) -> time:
    zone = value.tzinfo
    if (
        zone is not None
        and type(zone) is not timezone
        and type(zone) is not ZoneInfo
        and type(zone) is not TzInfo
    ):
        inspection.reject(value)
    return value


def _exact_type_in(value_type: type[object], candidates: tuple[type[object], ...]) -> bool:
    return any(value_type is candidate for candidate in candidates)


def _canonical_enum_state(
    value: object,
    canonical_members: tuple[tuple[Enum, type[Enum], str, object, int], ...],
) -> tuple[type[Enum], str, object, int] | None:
    for member, enum_type, name, member_value, sort_order in canonical_members:
        if value is member:
            return enum_type, name, member_value, sort_order
    return None


def _inspect_enum_singleton_state(
    value: object,
    canonical_members: tuple[tuple[Enum, type[Enum], str, object, int], ...],
    inspection: _ResultInspection,
) -> bool:
    canonical = _canonical_enum_state(value, canonical_members)
    if canonical is None:
        inspection.reject(value)
        return False
    enum_type, name, member_value, sort_order = canonical
    state = object.__getattribute__(value, "__dict__")
    if type(state) is not dict:
        inspection.reject(state)
        return False
    source = cast(dict[object, object], state).copy()
    inspection.capture_mapping(source)
    expected = {
        "_value_": member_value,
        "_name_": name,
        "__objclass__": enum_type,
        "_sort_order_": sort_order,
    }
    valid = True
    present_keys: set[str] = set()
    for key, item in source.items():
        if type(key) is not str or key not in expected:
            _inspect_data_value(key, inspection)
            _inspect_data_value(item, inspection)
            inspection.reject(key)
            inspection.reject(item)
            valid = False
            continue
        present_keys.add(key)
        expected_item = expected[key]
        if key == "__objclass__":
            item_matches = item is expected_item
        else:
            item_matches = _metadata_matches(item, expected_item)
        if not item_matches:
            _inspect_data_value(item, inspection)
            inspection.reject(item)
            valid = False
    if len(source) != len(expected) or present_keys != set(expected):
        inspection.reject(value)
        valid = False
    return valid


def _inspect_uuid(value: UUID, inspection: _ResultInspection) -> object:
    integer = object.__getattribute__(value, "int")
    safety = object.__getattribute__(value, "is_safe")
    valid_integer = type(integer) is int and 0 <= integer < 1 << 128
    if not valid_integer:
        _inspect_data_value(integer, inspection)
        inspection.reject(integer)
    valid_safety = _canonical_enum_state(safety, _SAFE_UUID_MEMBERS) is not None
    if not valid_safety:
        _inspect_data_value(safety, inspection)
        inspection.reject(safety)
    elif not _inspect_enum_singleton_state(safety, _SAFE_UUID_MEMBERS, inspection):
        valid_safety = False
    if not valid_integer or not valid_safety:
        return value
    snapshot = UUID(int=cast(int, integer), is_safe=cast(SafeUUID, safety))
    inspection.snapshots[id(value)] = snapshot
    return snapshot


def _owned_record_field_names(
    record_type: type[object],
    inspection: _ResultInspection,
) -> tuple[str, ...] | None:
    if type(record_type) is not _SealedOwnedRecordMeta:
        return None
    namespace = type.__getattribute__(record_type, "__dict__")
    seal: object = None
    raw_field_names: object = None
    namespace_valid = True
    for key, item in namespace.items():
        if type(key) is not str:
            _inspect_data_value(key, inspection)
            _inspect_data_value(item, inspection)
            inspection.reject(key)
            inspection.reject(item)
            namespace_valid = False
        elif key == _OWNED_RECORD_SEAL_ATTRIBUTE:
            seal = item
        elif key == _OWNED_RECORD_FIELDS_ATTRIBUTE:
            raw_field_names = item
    if not namespace_valid or seal is not _OWNED_RECORD_SEAL:
        return None
    if type(raw_field_names) is not tuple or any(
        type(field_name) is not str for field_name in raw_field_names
    ):
        return None
    field_names = cast(tuple[str, ...], raw_field_names)
    with _OWNED_RECORD_TYPES_LOCK:
        if _OWNED_RECORD_TYPES.get(field_names) is not record_type:
            return None
    return field_names


def _inspect_owned_record(
    value: object,
    record_type: type[object],
    field_names: tuple[str, ...],
    inspection: _ResultInspection,
) -> object:
    namespace = type.__getattribute__(record_type, "__dict__")
    descriptors: list[MemberDescriptorType] = []
    for field_name in field_names:
        descriptor = namespace.get(field_name)
        if (
            type(descriptor) is not MemberDescriptorType
            or descriptor.__name__ != field_name
            or descriptor.__objclass__ is not record_type
        ):
            if descriptor is not None:
                _reject_metadata_value(descriptor, inspection)
            inspection.reject(value)
            continue
        descriptors.append(descriptor)
    if inspection.rejected or len(descriptors) != len(field_names):
        return value
    snapshot_fields = [
        _inspect_data_value(descriptor.__get__(value, record_type), inspection)
        for descriptor in descriptors
    ]
    if inspection.rejected:
        return value
    snapshot = object.__new__(record_type)
    for field_name, field_value in zip(field_names, snapshot_fields, strict=True):
        object.__setattr__(snapshot, field_name, field_value)
    inspection.snapshots[id(value)] = snapshot
    return snapshot


def _inspect_frozen_record(value: object, inspection: _ResultInspection) -> object:
    inspection.retain_record_source(value)
    record_type = type(value)
    if type(record_type) is not type:
        inspection.reject(value)
        return value
    record_namespace, namespace_valid = _snapshot_plain_type_namespace(
        record_type,
        inspection,
    )
    if not namespace_valid:
        inspection.reject(value)
    raw_record_fields = record_namespace.get("__dataclass_fields__")
    if type(raw_record_fields) is not dict:
        if raw_record_fields is not None:
            _reject_metadata_value(raw_record_fields, inspection)
        inspection.reject(value)
        return value
    record_fields = cast(dict[object, object], raw_record_fields).copy()
    inspection.capture(raw_record_fields)
    inspection.capture_mapping(record_fields)
    record_namespace["__dataclass_fields__"] = record_fields
    raw_field_names = tuple(record_fields)
    if any(type(field_name) is not str for field_name in raw_field_names):
        for field_name in raw_field_names:
            _inspect_data_value(field_name, inspection)
            inspection.reject(field_name)
        inspection.reject(value)
        return value
    field_names = cast(tuple[str, ...], raw_field_names)
    if not _bounded_record_field_names(field_names):
        inspection.reject(value)
        return value
    reserved = _reserve_owned_record_shape(field_names)
    try:
        return _inspect_reserved_frozen_record(
            value,
            record_type,
            field_names,
            record_namespace,
            inspection,
        )
    finally:
        _release_owned_record_shape_reservation(field_names, reserved)


def _inspect_reserved_frozen_record(
    value: object,
    record_type: type[object],
    field_names: tuple[str, ...],
    record_namespace: dict[str, object],
    inspection: _ResultInspection,
) -> object:
    raw_descriptors = tuple(record_namespace.get(field_name) for field_name in field_names)
    descriptors_valid = True
    for field_name, descriptor in zip(field_names, raw_descriptors, strict=True):
        if (
            type(descriptor) is not MemberDescriptorType
            or descriptor.__name__ != field_name
            or descriptor.__objclass__ is not record_type
        ):
            if descriptor is not None:
                _reject_metadata_value(descriptor, inspection)
            descriptors_valid = False
    shape_valid = _has_exact_generated_record_shape(
        record_type,
        field_names,
        record_namespace,
        inspection,
    )
    if (
        type.__getattribute__(record_type, "__dictoffset__") != 0
        or type.__getattribute__(record_type, "__bases__") != (object,)
        or not descriptors_valid
        or not shape_valid
    ):
        inspection.reject(value)
        return value
    field_descriptors = cast(tuple[MemberDescriptorType, ...], raw_descriptors)
    snapshot_fields: list[tuple[str, object]] = []
    for field_name, descriptor in zip(field_names, field_descriptors, strict=True):
        snapshot_fields.append(
            (
                field_name,
                _inspect_data_value(descriptor.__get__(value, record_type), inspection),
            )
        )
    if inspection.rejected:
        return value
    # Return a closed module-owned generated shape. The caller's structurally
    # matching class remains mutable after validation and therefore cannot be
    # retained by the owned result graph without reopening a TOCTOU hook.
    snapshot = object.__new__(_owned_record_type(field_names))
    for field_name, field_value in snapshot_fields:
        object.__setattr__(snapshot, field_name, field_value)
    inspection.snapshots[id(value)] = snapshot
    return snapshot


def _inspect_contract(value: ContractModel, inspection: _ResultInspection) -> object:
    contract_type = type(value)
    declared_fields = next(
        fields
        for registered_type, fields in _REGISTERED_CONTRACT_FIELDS
        if contract_type is registered_type
    )
    source_state = object.__getattribute__(value, "__dict__")
    source_fields_set = object.__getattribute__(value, "__pydantic_fields_set__")
    extra = object.__getattribute__(value, "__pydantic_extra__")
    private = object.__getattribute__(value, "__pydantic_private__")
    if extra is not None:
        _inspect_data_value(extra, inspection)
        inspection.reject(extra)
    if private is not None:
        _inspect_data_value(private, inspection)
        inspection.reject(private)
    if type(source_state) is not dict:
        _inspect_data_value(source_state, inspection)
        inspection.reject(source_state)
    if type(source_fields_set) is not set:
        _inspect_data_value(source_fields_set, inspection)
        inspection.reject(source_fields_set)
    if type(source_state) is not dict or type(source_fields_set) is not set:
        return value

    snapshot_fields = _inspect_data_value(source_state, inspection)
    snapshot_fields_set = _inspect_data_value(source_fields_set, inspection)
    raw_state = cast(dict[object, object], inspection.shallow_sources[id(source_state)])
    raw_fields_set = cast(set[object], inspection.shallow_sources[id(source_fields_set)])
    declared_field_names = set(declared_fields)
    present_field_names: set[str] = set()
    for field_name, field_value in raw_state.items():
        if type(field_name) is str and field_name in declared_field_names:
            present_field_names.add(field_name)
        else:
            _inspect_data_value(field_name, inspection)
            _inspect_data_value(field_value, inspection)
            inspection.reject(field_name)
            inspection.reject(field_value)
    if present_field_names != declared_field_names or len(raw_state) != len(declared_fields):
        inspection.reject(value)
    for fields_set_entry in raw_fields_set:
        if type(fields_set_entry) is not str or fields_set_entry not in declared_field_names:
            _inspect_data_value(fields_set_entry, inspection)
            inspection.reject(fields_set_entry)

    if inspection.rejected:
        return value
    if type(snapshot_fields) is not dict or type(snapshot_fields_set) is not set:
        inspection.reject(value)
        return value
    snapshot = object.__new__(contract_type)
    object.__setattr__(snapshot, "__dict__", snapshot_fields)
    object.__setattr__(snapshot, "__pydantic_fields_set__", snapshot_fields_set)
    object.__setattr__(snapshot, "__pydantic_extra__", None)
    object.__setattr__(snapshot, "__pydantic_private__", None)
    inspection.snapshots[id(value)] = snapshot
    return snapshot


def _inspect_data_value(value: object, inspection: _ResultInspection) -> object:
    identity = id(value)
    inspection.sources[identity] = value
    if identity in inspection.visiting:
        inspection.reject(value)
        return value
    if identity in inspection.snapshots:
        return inspection.snapshots[identity]
    if identity in inspection.seen:
        return value
    inspection.seen.add(identity)

    value_type = type(value)
    if value_type is datetime:
        return _inspect_datetime(cast(datetime, value), inspection)
    if value_type is time:
        return _inspect_time(cast(time, value), inspection)
    if _exact_type_in(value_type, _SAFE_ATOMIC_TYPES):
        return value
    if value_type is UUID:
        return _inspect_uuid(cast(UUID, value), inspection)
    if _exact_type_in(value_type, cast(tuple[type[object], ...], _CONTRACT_ENUM_TYPES)):
        _inspect_enum_singleton_state(value, _CONTRACT_ENUM_MEMBERS, inspection)
        return value

    is_contract = any(value_type is model_type for model_type in _REGISTERED_CONTRACT_MODEL_TYPES)
    owned_record_fields = _owned_record_field_names(value_type, inspection)
    is_builtin_container = (
        value_type is dict
        or value_type is list
        or value_type is tuple
        or value_type is set
        or value_type is frozenset
    )
    is_record = False
    if type(value_type) is type:
        namespace_proxy = type.__getattribute__(value_type, "__dict__")
        for key in namespace_proxy:
            if type(key) is not str:
                _inspect_data_value(key, inspection)
                inspection.reject(key)
            elif key == "__dataclass_fields__":
                is_record = True
    if (
        not is_builtin_container
        and not is_contract
        and not is_record
        and owned_record_fields is None
    ):
        inspection.reject(value)
        return value

    inspection.visiting.add(identity)
    try:
        if type(value) is dict:
            source = cast(dict[object, object], value).copy()
            inspection.shallow_sources[identity] = source
            inspection.require_terminal_source_handoff()
            inspection.capture_mapping(source)
            snapshot: dict[object, object] = {}
            inspection.snapshots[identity] = snapshot
            dict_items = [
                (_inspect_data_value(key, inspection), _inspect_data_value(item, inspection))
                for key, item in source.items()
            ]
            if not inspection.rejected:
                snapshot.update(dict_items)
                if len(snapshot) != len(source):
                    # Normalization must not silently merge distinct caller
                    # keys (for example, equal module-owned record snapshots
                    # produced from two unequal caller record classes).
                    for key, item in source.items():
                        inspection.retain(key)
                        inspection.retain(item)
                    inspection.reject(value)
            return snapshot
        if type(value) is list:
            source_list = cast(list[object], value).copy()
            inspection.shallow_sources[identity] = source_list
            inspection.require_terminal_source_handoff()
            inspection.capture_members(source_list)
            snapshot_list: list[object] = []
            inspection.snapshots[identity] = snapshot_list
            snapshot_list.extend(_inspect_data_value(item, inspection) for item in source_list)
            return snapshot_list
        if type(value) is tuple:
            source_tuple = cast(tuple[object, ...], value)
            snapshot_tuple = tuple([_inspect_data_value(item, inspection) for item in source_tuple])
            inspection.snapshots[identity] = snapshot_tuple
            return snapshot_tuple
        if type(value) is set:
            source_set = cast(set[object], value).copy()
            inspection.shallow_sources[identity] = source_set
            inspection.require_terminal_source_handoff()
            inspection.capture_members(source_set)
            snapshot_set: set[object] = set()
            inspection.snapshots[identity] = snapshot_set
            set_items = [_inspect_data_value(item, inspection) for item in source_set]
            if not inspection.rejected:
                snapshot_set.update(set_items)
                if len(snapshot_set) != len(source_set):
                    for item in source_set:
                        inspection.retain(item)
                    inspection.reject(value)
            return snapshot_set
        if type(value) is frozenset:
            source_frozenset = cast(frozenset[object], value)
            frozenset_items = [_inspect_data_value(item, inspection) for item in source_frozenset]
            if inspection.rejected:
                return value
            snapshot_frozenset = frozenset(frozenset_items)
            if len(snapshot_frozenset) != len(source_frozenset):
                for item in source_frozenset:
                    inspection.retain(item)
                inspection.reject(value)
                return value
            inspection.snapshots[identity] = snapshot_frozenset
            return snapshot_frozenset
        if owned_record_fields is not None:
            return _inspect_owned_record(
                value,
                value_type,
                owned_record_fields,
                inspection,
            )
        if is_contract:
            return _inspect_contract(cast(ContractModel, value), inspection)
        if is_record:
            return _inspect_frozen_record(value, inspection)
        inspection.reject(value)
        return value
    finally:
        inspection.visiting.remove(identity)


def _reject_awaitable[ResultT](
    result: ResultT,
    message: str = "repository operations must return a synchronous data value",
) -> ResultT:
    inspection = _ResultInspection(result, message)
    try:
        result_type = type(result)
        declares_await = False
        native_deferred = False
        # `type.__getattribute__` still honors data descriptors installed on a
        # caller metaclass. Reject that class shape using only exact `type()`
        # identity before reading its MRO or any class namespace.
        if type(result_type) is not type:
            inspection.reject(result)
        else:
            result_mro = cast(tuple[type[object], ...], tuple(type.mro(result_type)))
            native_deferred = (
                result_type is CoroutineType
                or result_type is GeneratorType
                or result_type is AsyncGeneratorType
                or any(base is asyncio.Future or base is ConcurrentFuture for base in result_mro)
            )
            for base in result_mro:
                namespace_proxy = type.__getattribute__(base, "__dict__")
                for key, value in namespace_proxy.items():
                    if type(key) is not str:
                        _inspect_data_value(key, inspection)
                        _inspect_data_value(value, inspection)
                        inspection.reject(key)
                        inspection.reject(value)
                        declares_await = True
                    elif key == "__await__":
                        declares_await = True
    except BaseException as error:
        inspection.reject(result)
        rejection = _RejectedDeferredResult(tuple(inspection.retained), message)
        rejection.add_note("synchronous awaitable classification failed")
        raise rejection from error
    if native_deferred or declares_await:
        inspection.reject(result)
    inspection.raise_if_rejected()
    return result


def _reject_worker_result[ResultT](
    result: ResultT,
    message: str = "repository operations must return a synchronous data value",
) -> _OwnedResultEnvelope[ResultT]:
    inspection = _ResultInspection(result, message)
    try:
        snapshot = _inspect_data_value(result, inspection)
    except BaseException as error:
        # The traversal records a strong source before touching any nested
        # structure. Transfer every discovered source into the rejection so a
        # concurrent alias removal cannot finalize it while worker frames
        # unwind under the active transaction and writer lock.
        for source in tuple(inspection.sources.values()):
            inspection.retain(source)
        inspection.reject(result)
        rejection = _RejectedDeferredResult(tuple(inspection.retained), message)
        rejection.add_note("synchronous result snapshot failed before ownership transfer")
        raise rejection from error
    inspection.raise_if_rejected()
    return _OwnedResultEnvelope(
        cast(ResultT, snapshot),
        tuple(inspection.record_sources),
        inspection.captured_sources_for_handoff(),
    )


class AsyncRepositoryFacade[RepositoryT]:
    """Bind a synchronous repository to one async transaction worker."""

    def __init__(
        self,
        uow: AsyncUnitOfWorkProtocol,
        repository_factory: RepositoryFactory[RepositoryT],
    ) -> None:
        self._uow = uow
        self._repository_factory = repository_factory

    async def run[ResultT](self, operation: Callable[[RepositoryT], ResultT]) -> ResultT:
        def invoke(transaction: UnitOfWorkProtocol) -> ResultT:
            repository = _reject_awaitable(self._repository_factory(transaction))
            # The owning async UOW applies the single terminal snapshot after
            # this worker operation returns; duplicating it here doubles peak
            # memory and briefly creates an otherwise unreachable full graph.
            return operation(repository)

        return await self._uow.run_sync(invoke)
