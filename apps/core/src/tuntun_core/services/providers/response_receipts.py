from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Literal, Protocol, cast
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import (
    Commitment,
    ContractParseError,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_contract_json,
)
from tuntun_contracts.budget import ProviderUsageReceiptV1
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.provider import ProviderResponseReceipt, RouteAuthorization
from tuntun_core.services.budget.evidence import BudgetEvidenceQuarantined
from tuntun_core.services.providers.output_validator import AssistantTurn
from tuntun_core.services.providers.redaction_repository import AsyncUnitOfWorkFactory
from tuntun_core.services.storage_time import parse_utc_storage, utc_storage
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol

_OUTPUT_SCHEMA_VERSION: Final[Literal["assistant-turn-v1"]] = "assistant-turn-v1"
_MAX_ASSISTANT_OUTPUT_BYTES = 32_000


class _ClockPort(Protocol):
    def now(self) -> datetime: ...


class _AuditPort(Protocol):
    async def append(self, uow: AsyncUnitOfWorkProtocol, draft: AuditDraft) -> None: ...


class _UsageEvidencePort(Protocol):
    def require_provider_usage_receipt(
        self,
        call: Mapping[str, object],
        reservation: Mapping[str, object],
        now: datetime,
    ) -> ProviderUsageReceiptV1: ...


@dataclass(frozen=True, slots=True)
class VerifiedProviderResponseReceipt:
    receipt: ProviderResponseReceipt

    def __post_init__(self) -> None:
        if type(self.receipt) is not ProviderResponseReceipt:
            raise TypeError("receipt must be an exact ProviderResponseReceipt")

    @property
    def receipt_id(self) -> UUID:
        return self.receipt.receipt_id

    def require_scope(
        self,
        household_id: UUID,
        subject_id: UUID | None,
        session_id: UUID,
        turn_id: UUID,
    ) -> None:
        if (
            self.receipt.household_id != household_id
            or self.receipt.subject_id != subject_id
            or self.receipt.session_id != session_id
            or self.receipt.turn_id != turn_id
        ):
            raise PermissionError("provider_response_receipt_binding")


class ProviderResponseReceiptRepository:
    def __init__(self, uow_factory: AsyncUnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    @property
    def uow_factory(self) -> AsyncUnitOfWorkFactory:
        return self._uow_factory

    def load_for_authorization_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        authorization_id: UUID,
    ) -> ProviderResponseReceipt | None:
        row = (
            transaction.exec_driver_sql(
                "SELECT * FROM provider_response_receipts WHERE authorization_id=?",
                (str(authorization_id),),
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _receipt_from_row(cast(Mapping[str, Any], row))

    def load_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        receipt_id: UUID,
    ) -> ProviderResponseReceipt | None:
        row = (
            transaction.exec_driver_sql(
                "SELECT * FROM provider_response_receipts WHERE id=?",
                (str(receipt_id),),
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _receipt_from_row(cast(Mapping[str, Any], row))

    def count_for_authorization_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        authorization_id: UUID,
    ) -> int:
        return int(
            transaction.exec_driver_sql(
                "SELECT count(*) FROM provider_response_receipts WHERE authorization_id=?",
                (str(authorization_id),),
            ).scalar_one()
        )

    def bind_succeeded_call_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        route: RouteAuthorization,
        response_commitment: Commitment,
    ) -> None:
        changed = transaction.exec_driver_sql(
            "UPDATE provider_calls SET response_hmac_key_id=?,response_hmac_b64=? "
            "WHERE request_id=? AND attempt_id=? AND authorization_id=? "
            "AND budget_reservation_id=? AND provider=? AND model=? "
            "AND purpose='cloud_reasoning' AND outcome='succeeded' "
            "AND transport_phase='finished' AND response_hmac_key_id IS NULL "
            "AND response_hmac_b64 IS NULL",
            (
                response_commitment.key_id,
                response_commitment.value_b64,
                str(route.request_id),
                str(route.attempt_id),
                str(route.authorization_id),
                str(route.budget_reservation_id),
                route.provider,
                route.model,
            ),
        )
        if int(changed.rowcount) != 1:
            existing = self.load_for_authorization_in_transaction(
                transaction,
                route.authorization_id,
            )
            if (
                existing is None
                or existing.response_commitment.key_id != response_commitment.key_id
                or not hmac.compare_digest(
                    existing.response_commitment.value_b64,
                    response_commitment.value_b64,
                )
            ):
                raise PermissionError("provider_response_receipt_commitment")

    def insert_in_transaction(
        self,
        transaction: UnitOfWorkProtocol,
        receipt: ProviderResponseReceipt,
    ) -> bool:
        inserted = transaction.exec_driver_sql(
            "INSERT OR IGNORE INTO provider_response_receipts "
            "(id,request_id,attempt_id,authorization_id,household_id,subject_id,session_id,"
            "turn_id,provider,model,output_schema_version,response_hmac_key_id,"
            "response_hmac_b64,receipt_hmac_key_id,receipt_hmac_b64,produced_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(receipt.receipt_id),
                str(receipt.request_id),
                str(receipt.attempt_id),
                str(receipt.authorization_id),
                str(receipt.household_id),
                None if receipt.subject_id is None else str(receipt.subject_id),
                str(receipt.session_id),
                str(receipt.turn_id),
                receipt.provider,
                receipt.model,
                receipt.output_schema_version,
                receipt.response_commitment.key_id,
                receipt.response_commitment.value_b64,
                receipt.receipt_hmac_key_id,
                receipt.receipt_hmac_b64,
                utc_storage(receipt.produced_at),
            ),
        )
        return bool(inserted.rowcount == 1)


class ProviderResponseReceiptService:
    def __init__(
        self,
        *,
        uow_factory: AsyncUnitOfWorkFactory,
        repository: ProviderResponseReceiptRepository,
        commitment_root: bytes,
        key_id: str,
        clock: _ClockPort,
        audit: _AuditPort,
        usage_evidence: _UsageEvidencePort,
        assistant_turn_adapter: type[AssistantTurn],
    ) -> None:
        if type(commitment_root) is not bytes or len(commitment_root) != 32:
            raise ValueError("provider response commitment root must be 32 bytes")
        if assistant_turn_adapter is not AssistantTurn:
            raise TypeError("assistant_turn_adapter must be AssistantTurn")
        self._uow_factory = uow_factory
        self._repository = repository
        self._root = commitment_root
        self._key_id = key_id
        self._clock = clock
        self._audit = audit
        self._usage_evidence = usage_evidence
        self._adapter = assistant_turn_adapter

    async def validate_and_record(
        self,
        route: RouteAuthorization,
        raw_json: bytes | str,
        *,
        provider_usage_receipt_id: UUID | None,
    ) -> ProviderResponseReceipt:
        raw = raw_json.encode("utf-8", errors="strict") if type(raw_json) is str else raw_json
        if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_ASSISTANT_OUTPUT_BYTES:
            raise ValueError("assistant output byte cap")
        try:
            turn = parse_contract_json(
                self._adapter,
                raw,
                max_bytes=_MAX_ASSISTANT_OUTPUT_BYTES,
                require_canonical=False,
            )
        except (ContractParseError, ValidationError) as error:
            raise ValueError("assistant output invalid") from error
        return await self.record(
            route,
            turn,
            provider_usage_receipt_id=provider_usage_receipt_id,
        )

    async def record(
        self,
        route: RouteAuthorization,
        turn: AssistantTurn,
        *,
        provider_usage_receipt_id: UUID | None,
    ) -> ProviderResponseReceipt:
        if type(route) is not RouteAuthorization:
            raise TypeError("route must be an exact RouteAuthorization")
        if type(turn) is not self._adapter:
            raise TypeError("turn must be an exact AssistantTurn")
        if route.purpose != "cloud_reasoning":
            raise PermissionError("provider_response_receipt_binding")
        if provider_usage_receipt_id is None:
            raise PermissionError("provider_response_usage_unverified")
        turn_body = canonical_bytes(turn)
        if not 1 <= len(turn_body) <= _MAX_ASSISTANT_OUTPUT_BYTES:
            raise ValueError("assistant output byte cap")
        now = self._clock.now()
        response_commitment = commit_private(
            self._root,
            self._key_id,
            "provider.response.assistant-turn.v1",
            turn_body,
        )
        receipt = self._build_receipt(route, response_commitment, now)
        try:
            async with self._uow_factory() as uow:
                existing = await uow.run_sync(
                    lambda transaction: self._repository.load_for_authorization_in_transaction(
                        transaction,
                        route.authorization_id,
                    )
                )
                if existing is not None:
                    self._require_receipt_exact(existing, route, response_commitment)
                    await uow.run_sync(
                        lambda transaction: self._require_exact_succeeded_usage(
                            transaction,
                            route,
                            provider_usage_receipt_id,
                            now,
                        )
                    )
                    await uow.rollback()
                    return existing

                await uow.run_sync(
                    lambda transaction: self._require_exact_succeeded_usage(
                        transaction,
                        route,
                        provider_usage_receipt_id,
                        now,
                    )
                )
                await uow.run_sync(
                    lambda transaction: self._repository.bind_succeeded_call_in_transaction(
                        transaction,
                        route,
                        response_commitment,
                    )
                )
                inserted = await uow.run_sync(
                    lambda transaction: self._repository.insert_in_transaction(
                        transaction,
                        receipt,
                    )
                )
                if not inserted:
                    existing = await uow.run_sync(
                        lambda transaction: (
                            self._repository.load_for_authorization_in_transaction(
                                transaction,
                                route.authorization_id,
                            )
                        )
                    )
                    if existing is None:
                        raise PermissionError("provider_response_receipt_insert_conflict")
                    self._require_receipt_exact(existing, route, response_commitment)
                    await uow.rollback()
                    return existing
                await self._audit.append(uow, self._audit_draft(route, response_commitment, now))
                await uow.commit()
                return receipt
        except IntegrityError:
            raise PermissionError("provider_response_receipt_insert_conflict") from None
        raise RuntimeError("provider_response_receipt_record_unreachable")

    async def require_exact(
        self,
        receipt_id: UUID,
        route: RouteAuthorization,
        turn: AssistantTurn,
        *,
        provider_usage_receipt_id: UUID | None,
    ) -> VerifiedProviderResponseReceipt:
        if provider_usage_receipt_id is None:
            raise PermissionError("provider_response_usage_unverified")
        turn_body = canonical_bytes(turn)
        if len(turn_body) > _MAX_ASSISTANT_OUTPUT_BYTES:
            raise ValueError("assistant output byte cap")
        response_commitment = commit_private(
            self._root,
            self._key_id,
            "provider.response.assistant-turn.v1",
            turn_body,
        )
        now = self._clock.now()
        async with self._uow_factory() as uow:
            receipt = await uow.run_sync(
                lambda transaction: self._repository.load_in_transaction(transaction, receipt_id)
            )
            if receipt is None:
                await uow.rollback()
                raise PermissionError("provider_response_receipt_binding")
            verified_receipt = receipt
            self._require_receipt_exact(verified_receipt, route, response_commitment)
            await uow.run_sync(
                lambda transaction: self._require_exact_succeeded_usage(
                    transaction,
                    route,
                    provider_usage_receipt_id,
                    now,
                )
            )
            await uow.rollback()
        return VerifiedProviderResponseReceipt(verified_receipt)

    async def count_for_authorization(self, authorization_id: UUID) -> int:
        async with self._uow_factory() as uow:
            count = await uow.run_sync(
                lambda transaction: self._repository.count_for_authorization_in_transaction(
                    transaction,
                    authorization_id,
                )
            )
            await uow.rollback()
        return count

    def _build_receipt(
        self,
        route: RouteAuthorization,
        response_commitment: Commitment,
        now: datetime,
    ) -> ProviderResponseReceipt:
        receipt_id = uuid4()
        unsigned: dict[str, Any] = {
            "receipt_id": receipt_id,
            "request_id": route.request_id,
            "attempt_id": route.attempt_id,
            "authorization_id": route.authorization_id,
            "household_id": route.household_id,
            "subject_id": route.subject_id,
            "session_id": route.session_id,
            "turn_id": route.turn_id,
            "provider": route.provider,
            "model": route.model,
            "output_schema_version": _OUTPUT_SCHEMA_VERSION,
            "response_commitment": response_commitment,
            "receipt_hmac_key_id": self._key_id,
            "produced_at": now,
        }
        signature = commit_private(
            self._root,
            self._key_id,
            "provider.response-receipt.v1",
            canonical_mapping_bytes(_jsonable(unsigned)),
        )
        return ProviderResponseReceipt(
            receipt_id=receipt_id,
            request_id=route.request_id,
            attempt_id=route.attempt_id,
            authorization_id=route.authorization_id,
            household_id=route.household_id,
            subject_id=route.subject_id,
            session_id=route.session_id,
            turn_id=route.turn_id,
            provider=route.provider,
            model=route.model,
            output_schema_version=_OUTPUT_SCHEMA_VERSION,
            response_commitment=response_commitment,
            receipt_hmac_key_id=self._key_id,
            receipt_hmac_b64=signature.value_b64,
            produced_at=now,
        )

    def _require_receipt_exact(
        self,
        receipt: ProviderResponseReceipt,
        route: RouteAuthorization,
        response_commitment: Commitment,
    ) -> None:
        if not self._valid_receipt_hmac(receipt):
            raise PermissionError("provider_response_receipt_hmac")
        expected_scope = (
            route.request_id,
            route.attempt_id,
            route.authorization_id,
            route.household_id,
            route.subject_id,
            route.session_id,
            route.turn_id,
            route.provider,
            route.model,
            _OUTPUT_SCHEMA_VERSION,
        )
        actual_scope = (
            receipt.request_id,
            receipt.attempt_id,
            receipt.authorization_id,
            receipt.household_id,
            receipt.subject_id,
            receipt.session_id,
            receipt.turn_id,
            receipt.provider,
            receipt.model,
            receipt.output_schema_version,
        )
        if actual_scope != expected_scope:
            raise PermissionError("provider_response_receipt_binding")
        if (
            receipt.response_commitment.key_id != response_commitment.key_id
            or not hmac.compare_digest(
                receipt.response_commitment.value_b64,
                response_commitment.value_b64,
            )
        ):
            raise PermissionError("provider_response_receipt_commitment")

    def _valid_receipt_hmac(self, receipt: ProviderResponseReceipt) -> bool:
        if receipt.receipt_hmac_key_id != self._key_id:
            return False
        unsigned = receipt.model_dump(mode="python", exclude={"receipt_hmac_b64"})
        expected = commit_private(
            self._root,
            receipt.receipt_hmac_key_id,
            "provider.response-receipt.v1",
            canonical_mapping_bytes(_jsonable(unsigned)),
        )
        return bool(hmac.compare_digest(expected.value_b64, receipt.receipt_hmac_b64))

    def _require_exact_succeeded_usage(
        self,
        transaction: UnitOfWorkProtocol,
        route: RouteAuthorization,
        provider_usage_receipt_id: UUID,
        now: datetime,
    ) -> None:
        call = cast(
            Mapping[str, object] | None,
            transaction.exec_driver_sql(
                "SELECT * FROM provider_calls WHERE request_id=? AND attempt_id=? "
                "AND authorization_id=? AND budget_reservation_id=? AND provider=? "
                "AND model=? AND purpose='cloud_reasoning' AND outcome='succeeded' "
                "AND transport_phase='finished' AND finished_at IS NOT NULL "
                "AND provider_usage_json IS NOT NULL "
                "AND provider_usage_receipt_key_id IS NOT NULL "
                "AND provider_usage_receipt_hmac_b64 IS NOT NULL",
                (
                    str(route.request_id),
                    str(route.attempt_id),
                    str(route.authorization_id),
                    str(route.budget_reservation_id),
                    route.provider,
                    route.model,
                ),
            )
            .mappings()
            .one_or_none(),
        )
        reservation = cast(
            Mapping[str, object] | None,
            transaction.exec_driver_sql(
                "SELECT * FROM budget_reservations WHERE id=? AND request_id=? "
                "AND attempt_id=? AND provider=? AND model=? AND category='llm'",
                (
                    str(route.budget_reservation_id),
                    str(route.request_id),
                    str(route.attempt_id),
                    route.provider,
                    route.model,
                ),
            )
            .mappings()
            .one_or_none(),
        )
        if call is None or reservation is None:
            raise PermissionError("provider_response_usage_unverified")
        try:
            usage_receipt = self._usage_evidence.require_provider_usage_receipt(
                call,
                reservation,
                now,
            )
        except BudgetEvidenceQuarantined as error:
            raise PermissionError("provider_response_usage_unverified") from error
        if usage_receipt.receipt_id != provider_usage_receipt_id:
            raise PermissionError("provider_response_usage_receipt_mismatch")

    def _audit_draft(
        self,
        route: RouteAuthorization,
        response_commitment: Commitment,
        now: datetime,
    ) -> AuditDraft:
        payload_commitment = commit_private(
            self._root,
            self._key_id,
            "provider.response-receipt.audit.v1",
            canonical_mapping_bytes(
                {
                    "authorization_id": route.authorization_id,
                    "response_commitment": response_commitment.model_dump(mode="python"),
                }
            ),
        )
        return AuditDraft(
            event_id=uuid4(),
            occurred_at=now,
            actor_pseudonym="provider-output",
            action_code="provider.response.receipt.created",
            outcome="succeeded",
            reason_code="validated_assistant_turn",
            correlation_id=route.turn_id,
            payload_commitment=payload_commitment,
        )


def _receipt_from_row(row: Mapping[str, Any]) -> ProviderResponseReceipt:
    produced_at = row["produced_at"]
    parsed_at = parse_utc_storage(produced_at) if type(produced_at) is str else produced_at
    if type(parsed_at) is not datetime:
        raise ValueError("provider response receipt timestamp invalid")
    provider = _literal_provider(row["provider"])
    output_schema_version = _literal_output_schema(row["output_schema_version"])
    return ProviderResponseReceipt(
        receipt_id=UUID(_row_str(row, "id")),
        request_id=UUID(_row_str(row, "request_id")),
        attempt_id=UUID(_row_str(row, "attempt_id")),
        authorization_id=UUID(_row_str(row, "authorization_id")),
        household_id=UUID(_row_str(row, "household_id")),
        subject_id=None
        if row["subject_id"] is None
        else UUID(_row_str(row, "subject_id")),
        session_id=UUID(_row_str(row, "session_id")),
        turn_id=UUID(_row_str(row, "turn_id")),
        provider=provider,
        model=_row_str(row, "model"),
        output_schema_version=output_schema_version,
        response_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id=_row_str(row, "response_hmac_key_id"),
            value_b64=_row_str(row, "response_hmac_b64"),
        ),
        receipt_hmac_key_id=_row_str(row, "receipt_hmac_key_id"),
        receipt_hmac_b64=_row_str(row, "receipt_hmac_b64"),
        produced_at=parsed_at,
    )


def _row_str(row: Mapping[str, Any], key: str) -> str:
    value = row[key]
    if type(value) is not str:
        raise ValueError("provider response receipt row invalid")
    return value


def _literal_provider(value: object) -> Literal["openai", "qwen"]:
    if value not in {"openai", "qwen"}:
        raise ValueError("provider response receipt provider invalid")
    return cast(Literal["openai", "qwen"], value)


def _literal_output_schema(value: object) -> Literal["assistant-turn-v1"]:
    if value != _OUTPUT_SCHEMA_VERSION:
        raise ValueError("provider response receipt schema invalid")
    return _OUTPUT_SCHEMA_VERSION


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return value
