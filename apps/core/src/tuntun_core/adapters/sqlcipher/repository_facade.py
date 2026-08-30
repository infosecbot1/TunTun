from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from concurrent.futures import Future as ConcurrentFuture
from dataclasses import MISSING, FrozenInstanceError, fields, is_dataclass, make_dataclass
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from enum import Enum
from functools import lru_cache
from typing import Protocol, cast
from uuid import UUID
from zoneinfo import ZoneInfo

import tuntun_contracts
from sqlalchemy.engine import Connection, Engine, Result, Transaction
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


class _ResultInspection:
    def __init__(self, root: object, message: str) -> None:
        self.root = root
        self.message = message
        self.retained: list[object] = [root]
        self.retained_ids: set[int] = {id(root)}
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
    UUID,
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


def _exported_contract_enum_types() -> frozenset[type[Enum]]:
    result: set[type[Enum]] = set()
    for name in tuntun_contracts.__all__:
        exported: object = getattr(tuntun_contracts, name)
        if isinstance(exported, type) and issubclass(exported, Enum):
            result.add(exported)
    return frozenset(result)


_CONTRACT_ENUM_TYPES = _exported_contract_enum_types()


def _closure_fingerprint(
    value: object,
    owner_type: type[object],
) -> tuple[object, ...] | None:
    if value is owner_type:
        return ("owner-type",)
    if value is object:
        return ("builtins-object",)
    if value is FrozenInstanceError:
        return ("frozen-instance-error",)
    if type(value) is set and not value:
        return ("empty-set",)
    if inspect.isfunction(value):
        nested = _function_fingerprint(value, owner_type)
        return None if nested is None else ("function", nested)
    return None


def _function_fingerprint(
    value: object,
    owner_type: type[object],
) -> tuple[object, ...] | None:
    if not inspect.isfunction(value):
        return None
    code = value.__code__
    wrapped = getattr(value, "__wrapped__", None)
    closure: list[tuple[object, ...]] = []
    for cell in value.__closure__ or ():
        try:
            content = cell.cell_contents
        except ValueError:
            return None
        fingerprint = _closure_fingerprint(content, owner_type)
        if fingerprint is None:
            return None
        closure.append(fingerprint)
    return (
        *(getattr(code, name) for name in _CODE_FINGERPRINT_ATTRIBUTES),
        value.__defaults__,
        value.__kwdefaults__,
        frozenset(value.__annotations__),
        frozenset(value.__dict__),
        tuple(closure),
        _function_fingerprint(wrapped, owner_type),
    )


@lru_cache(maxsize=128)
def _reference_record_type(field_names: tuple[str, ...]) -> type[object]:
    return cast(
        type[object],
        make_dataclass(
            "_SynchronousDataRecord",
            [(name, object) for name in field_names],
            frozen=True,
            slots=True,
        ),
    )


def _has_exact_generated_record_shape(
    record_type: type[object],
    field_names: tuple[str, ...],
) -> bool:
    reference = _reference_record_type(field_names)
    actual_namespace = vars(record_type)
    reference_namespace = vars(reference)
    if actual_namespace.keys() != reference_namespace.keys():
        return False
    actual_parameters = record_type.__dataclass_params__  # type: ignore[attr-defined]
    reference_parameters = reference.__dataclass_params__  # type: ignore[attr-defined]
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
    if type(actual_parameters) is not type(reference_parameters) or any(
        getattr(actual_parameters, name) != getattr(reference_parameters, name)
        for name in parameter_names
    ):
        return False
    annotations = actual_namespace["__annotations__"]
    if (
        type(actual_namespace["__module__"]) is not str
        or type(actual_namespace["__doc__"]) not in (str, type(None))
        or type(annotations) is not dict
        or tuple(annotations) != field_names
        or any(type(annotation) is not str for annotation in annotations.values())
        or actual_namespace["__match_args__"] != field_names
        or actual_namespace["__slots__"] != field_names
    ):
        return False
    actual_fields = actual_namespace["__dataclass_fields__"]
    reference_fields = reference_namespace["__dataclass_fields__"]
    if type(actual_fields) is not dict or tuple(actual_fields) != field_names:
        return False
    for name in field_names:
        actual_field = actual_fields[name]
        reference_field = reference_fields[name]
        if (
            type(actual_field) is not type(reference_field)
            or actual_field.name != name
            or type(actual_field.type) is not str
            or actual_field.type != annotations[name]
            or actual_field.default is not MISSING
            or actual_field.default_factory is not MISSING
            or actual_field.metadata is not reference_field.metadata
            or actual_field._field_type is not reference_field._field_type
            or (
                actual_field.init,
                actual_field.repr,
                actual_field.hash,
                actual_field.compare,
                actual_field.kw_only,
            )
            != (
                reference_field.init,
                reference_field.repr,
                reference_field.hash,
                reference_field.compare,
                reference_field.kw_only,
            )
            or type(actual_namespace[name]) is not type(reference_namespace[name])
        ):
            return False
    for name, expected in reference_namespace.items():
        if inspect.isfunction(expected) and _function_fingerprint(
            actual_namespace[name], record_type
        ) != _function_fingerprint(expected, reference):
            return False
    return True


def _inspect_datetime(value: datetime, inspection: _ResultInspection) -> None:
    zone = value.tzinfo
    if zone is not None and type(zone) is not timezone and type(zone) is not ZoneInfo:
        inspection.reject(value)


def _inspect_time(value: time, inspection: _ResultInspection) -> None:
    zone = value.tzinfo
    if zone is not None and type(zone) is not timezone and type(zone) is not ZoneInfo:
        inspection.reject(value)


def _inspect_frozen_record(value: object, inspection: _ResultInspection) -> None:
    record_type = type(value)
    parameters = getattr(record_type, "__dataclass_params__", None)
    record_fields = fields(value)  # type: ignore[arg-type]
    field_names = tuple(field.name for field in record_fields)
    if (
        parameters is None
        or not parameters.frozen
        or type(record_type) is not type
        or getattr(record_type, "__dictoffset__", 0) != 0
        or record_type.__bases__ != (object,)
        or not _has_exact_generated_record_shape(record_type, field_names)
    ):
        inspection.reject(value)
        return
    for field in record_fields:
        _inspect_data_value(object.__getattribute__(value, field.name), inspection)


def _inspect_contract(value: ContractModel, inspection: _ResultInspection) -> None:
    if type(value) not in registered_contract_models():
        inspection.reject(value)
        return
    if value.__pydantic_extra__ or value.__pydantic_private__:
        inspection.reject(value)
        return
    for field_name in type(value).model_fields:
        _inspect_data_value(object.__getattribute__(value, field_name), inspection)


def _inspect_data_value(value: object, inspection: _ResultInspection) -> None:
    identity = id(value)
    if identity in inspection.visiting:
        inspection.reject(value)
        return
    if identity in inspection.seen:
        return
    inspection.seen.add(identity)

    if isinstance(value, (asyncio.Future, ConcurrentFuture)) or inspect.isasyncgen(value):
        inspection.reject(value)
        return
    if inspect.isgenerator(value):
        inspection.reject(value)
        return
    if inspect.isawaitable(value):
        inspection.reject(value)
        return
    if isinstance(value, Result):
        inspection.reject(value)
        return
    if isinstance(value, (Connection, Engine, Transaction, UnitOfWorkProtocol)):
        inspection.reject(value)
        return
    if callable(value):
        inspection.reject(value)
        return
    if type(value) is datetime:
        _inspect_datetime(value, inspection)
        return
    if type(value) is time:
        _inspect_time(value, inspection)
        return
    if type(value) in _SAFE_ATOMIC_TYPES:
        return
    if isinstance(value, Enum):
        if type(value) not in _CONTRACT_ENUM_TYPES:
            inspection.reject(value)
            return
        _inspect_data_value(value.value, inspection)
        return

    inspection.visiting.add(identity)
    try:
        if type(value) is dict:
            for key, item in cast(dict[object, object], value).items():
                _inspect_data_value(key, inspection)
                _inspect_data_value(item, inspection)
        elif type(value) in (list, tuple, set, frozenset):
            container = cast(
                list[object] | tuple[object, ...] | set[object] | frozenset[object], value
            )
            for item in container:
                _inspect_data_value(item, inspection)
        elif isinstance(value, ContractModel):
            _inspect_contract(value, inspection)
        elif is_dataclass(value) and not isinstance(value, type):
            _inspect_frozen_record(value, inspection)
        else:
            inspection.reject(value)
    finally:
        inspection.visiting.remove(identity)


def _reject_awaitable[ResultT](
    result: ResultT,
    message: str = "repository operations must return a synchronous data value",
) -> ResultT:
    inspection = _ResultInspection(result, message)
    if (
        isinstance(result, (asyncio.Future, ConcurrentFuture))
        or inspect.isasyncgen(result)
        or inspect.isgenerator(result)
        or inspect.isawaitable(result)
    ):
        inspection.reject(result)
    inspection.raise_if_rejected()
    return result


def _reject_worker_result[ResultT](
    result: ResultT,
    message: str = "repository operations must return a synchronous data value",
) -> ResultT:
    inspection = _ResultInspection(result, message)
    _inspect_data_value(result, inspection)
    inspection.raise_if_rejected()
    return result


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
            return _reject_worker_result(operation(repository))

        return await self._uow.run_sync(invoke)
