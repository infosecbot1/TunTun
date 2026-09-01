from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal, cast
from uuid import UUID, uuid4

import rfc8785
from tuntun_contracts.base import ContractModel, canonical_bytes, parse_contract_json
from tuntun_contracts.budget import (
    MAX_CHARGE_MICROS_SGD,
    BudgetReconciliationRequest,
    BudgetReservation,
    BudgetReservationRequest,
    BudgetSettlement,
    BudgetSettlementRequest,
    ProviderUsageReceiptV1,
    TransportProof,
    TtsUsageUnits,
    UsageUnits,
)
from tuntun_core.services.budget.evidence import (
    BudgetEvidenceQuarantined,
    parse_usage_units_json,
)
from tuntun_core.services.budget.month import singapore_month_key
from tuntun_core.services.budget.pricing import MAX_AGGREGATE_MICROS_SGD, Pricing, checked_add
from tuntun_core.services.storage_time import utc_storage

BudgetOutcome = Literal[
    "allow",
    "allow_soft_warning",
    "deny_hard_limit",
    "deny_unknown_price",
    "deny_cloud_egress_frozen",
]


class BudgetTurnBindingV1(ContractModel):
    household_id: UUID
    turn_id: UUID
    request_id: UUID
    attempt_id: UUID


@dataclass(frozen=True, slots=True)
class BudgetAccountingContext:
    category: str
    usage_ceiling: UsageUnits
    primary_accounting_basis: str
    missing_evidence_policy: str


class BudgetGuard:
    def __init__(
        self,
        uow_factory: Any,
        clock: Any,
        catalog: Any,
        reviews: Any,
        evidence: Any,
        hard_limit: int,
        soft_limit: int = 100_000_000,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._catalog = catalog
        self._reviews = reviews
        self._pricing = Pricing(catalog, clock)
        self._evidence = evidence
        self._hard_limit = hard_limit
        self._soft_limit = soft_limit

    async def reserve(self, request: BudgetReservationRequest) -> BudgetReservation:
        now = self._clock.now()
        if request.month_key != singapore_month_key(now):
            raise PermissionError("budget_month_mismatch")
        purpose = {
            "stt": "cloud_stt",
            "llm": "cloud_reasoning",
            "tts": "cloud_tts",
        }.get(request.category)
        if purpose is None:
            raise PermissionError("budget_category_not_activated")
        reservation_id = uuid4()
        expires_at = now + timedelta(minutes=15)
        try:
            quote = self._pricing.quote(request.provider, request.model, request.usage_ceiling)
            snapshot = self._evidence.issue_pricing_snapshot(request, quote)
        except (BudgetEvidenceQuarantined, PermissionError, ValueError, OverflowError):
            quote = None
            snapshot = None

        def reserve_locked(db: Any) -> BudgetReservation:
            self._reviews.require_current(db, request.provider, request.model, purpose, now)
            freeze_key = f"budget.cloud_egress_freeze.{request.month_key}"
            frozen = (
                db.exec_driver_sql(
                    "SELECT 1 FROM runtime_settings WHERE key=?",
                    (freeze_key,),
                ).fetchone()
                is not None
            )
            rows = db.exec_driver_sql(
                "SELECT state,reserved_micros_sgd,charged_micros_sgd "
                "FROM budget_reservations WHERE month_key=? "
                "AND state IN ('reserved','sent','settled')",
                (request.month_key,),
            ).fetchall()
            total = 0
            for state, reserved, charged in rows:
                amount = charged if state == "settled" else reserved
                if amount is None:
                    raise PermissionError("budget_terminal_amount_missing")
                total = checked_add(total, int(amount))
            authoritative = 0 if quote is None else quote.amount_micros_sgd
            if not 0 <= authoritative <= MAX_CHARGE_MICROS_SGD:
                raise OverflowError("budget_arithmetic_out_of_bounds")
            projected = checked_add(total, authoritative)
            warning_key = f"budget.soft_warning.{request.month_key}"
            warned = (
                db.exec_driver_sql(
                    "SELECT 1 FROM runtime_settings WHERE key=?",
                    (warning_key,),
                ).fetchone()
                is not None
            )
            outcome: BudgetOutcome = (
                "deny_cloud_egress_frozen"
                if frozen
                else "deny_unknown_price"
                if quote is None
                else "deny_hard_limit"
                if projected > self._hard_limit
                else "allow_soft_warning"
                if projected > self._soft_limit and not warned
                else "allow"
            )
            state = "reserved" if outcome in {"allow", "allow_soft_warning"} else "denied"
            reserved = authoritative if state == "reserved" else 0
            persisted_snapshot = (
                None if outcome in {"deny_unknown_price", "deny_cloud_egress_frozen"} else snapshot
            )
            if persisted_snapshot is None:
                snapshot_json = None
                primary_accounting_basis = None
                missing_evidence_policy = None
                pricing_version = None
                price_source_sha256 = None
                fx_version = None
                fx_source_sha256 = None
                pricing_commitment_key_id = None
                pricing_commitment_hmac_b64 = None
            else:
                if quote is None:
                    raise PermissionError("budget_pricing_snapshot_invalid")
                snapshot_json = persisted_snapshot.canonical_json
                primary_accounting_basis = quote.primary_accounting_basis
                missing_evidence_policy = quote.missing_evidence_policy
                pricing_version = quote.pricing_version
                price_source_sha256 = quote.price_source_sha256
                fx_version = quote.fx_version
                fx_source_sha256 = quote.fx_source_sha256
                pricing_commitment_key_id = persisted_snapshot.commitment.key_id
                pricing_commitment_hmac_b64 = persisted_snapshot.commitment.value_b64
            reservation_insert = db.exec_driver_sql(
                "INSERT INTO budget_reservations "
                "(id,request_id,attempt_id,month_key,category,provider,model,outcome,"
                "usage_ceiling_json,reserved_micros_sgd,charged_micros_sgd,"
                "price_snapshot_json,primary_accounting_basis,missing_evidence_policy,"
                "pricing_version,price_source_sha256,fx_version,fx_source_sha256,"
                "pricing_commitment_key_id,pricing_commitment_hmac_b64,estimate_overrun,"
                "state,gateway_ordering_version,transport_phase,created_at,expires_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,1,'not_claimed',?,?)",
                (
                    str(reservation_id),
                    str(request.request_id),
                    str(request.attempt_id),
                    request.month_key,
                    request.category,
                    request.provider,
                    request.model,
                    outcome,
                    rfc8785.dumps(request.usage_ceiling.model_dump(mode="json")).decode("utf-8"),
                    reserved,
                    None,
                    snapshot_json,
                    primary_accounting_basis,
                    missing_evidence_policy,
                    pricing_version,
                    price_source_sha256,
                    fx_version,
                    fx_source_sha256,
                    pricing_commitment_key_id,
                    pricing_commitment_hmac_b64,
                    state,
                    utc_storage(now),
                    utc_storage(expires_at),
                ),
            )
            if reservation_insert.rowcount != 1:
                raise PermissionError("budget_reservation_insert_failed")
            mapping = canonical_bytes(
                BudgetTurnBindingV1(
                    household_id=request.household_id,
                    turn_id=request.turn_id,
                    request_id=request.request_id,
                    attempt_id=request.attempt_id,
                )
            ).decode("utf-8")
            binding_insert = db.exec_driver_sql(
                "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES(?,?,1,?)",
                (f"budget.turn.{reservation_id}", mapping, utc_storage(now)),
            )
            if binding_insert.rowcount != 1:
                raise PermissionError("budget_turn_binding_insert_failed")
            if outcome == "allow_soft_warning":
                db.exec_driver_sql(
                    "INSERT INTO runtime_settings(key,value_json,version,updated_at) "
                    "VALUES(?,?,1,?)",
                    (warning_key, '{"emitted":true}', utc_storage(now)),
                )
            return BudgetReservation(
                reservation_id=reservation_id,
                request_id=request.request_id,
                attempt_id=request.attempt_id,
                outcome=outcome,
                amount_micros_sgd=reserved,
                pricing_commitment=None
                if persisted_snapshot is None
                else persisted_snapshot.commitment,
                expires_at=expires_at,
            )

        async with self._uow_factory() as uow:
            result = await uow.run_sync(reserve_locked)
            await uow.commit()
            return cast(BudgetReservation, result)

    async def require_accounting_context(
        self,
        route: Any,
        consumption: Any,
    ) -> BudgetAccountingContext:
        async with self._uow_factory() as uow:

            def require(db: Any) -> BudgetAccountingContext:
                row = (
                    db.exec_driver_sql(
                        "SELECT * FROM budget_reservations WHERE id=?",
                        (str(route.budget_reservation_id),),
                    )
                    .mappings()
                    .one_or_none()
                )
                expected_category = {
                    "cloud_stt": "stt",
                    "cloud_reasoning": "llm",
                    "cloud_tts": "tts",
                }.get(route.purpose)
                if row is None or expected_category is None:
                    raise PermissionError("budget_accounting_context_missing")
                if (
                    row["request_id"] != str(route.request_id)
                    or row["attempt_id"] != str(route.attempt_id)
                    or row["provider"] != route.provider
                    or row["model"] != route.model
                    or row["category"] != expected_category
                    or row["state"] != "sent"
                    or row["transport_phase"] != "marked_sent"
                    or consumption.request_id != route.request_id
                    or consumption.attempt_id != route.attempt_id
                    or consumption.provider != route.provider
                    or consumption.model != route.model
                    or consumption.purpose != route.purpose
                ):
                    raise PermissionError("budget_accounting_context_binding_mismatch")
                quote = self._evidence.require_pricing_snapshot(row)
                usage = parse_usage_units_json(row["usage_ceiling_json"])
                if isinstance(usage, TtsUsageUnits) and (
                    consumption.input_units != usage.characters
                    or route.max_input_units != usage.characters
                ):
                    raise PermissionError("tts_request_character_binding_mismatch")
                return BudgetAccountingContext(
                    category=expected_category,
                    usage_ceiling=usage,
                    primary_accounting_basis=quote.primary_accounting_basis,
                    missing_evidence_policy=quote.missing_evidence_policy,
                )

            result = await uow.run_sync(require)
            await uow.rollback()
            return cast(BudgetAccountingContext, result)

    async def mark_sent(self, reservation_id: UUID, attempt_id: UUID) -> None:
        now = self._clock.now()

        def mark_pair(db: Any) -> None:
            reservation_month = db.exec_driver_sql(
                "SELECT month_key FROM budget_reservations WHERE id=? AND attempt_id=?",
                (str(reservation_id), str(attempt_id)),
            ).fetchone()
            if reservation_month is None:
                raise PermissionError("reservation_not_markable_sent")
            frozen = db.exec_driver_sql(
                "SELECT 1 FROM runtime_settings WHERE key=?",
                (f"budget.cloud_egress_freeze.{reservation_month[0]}",),
            ).fetchone()
            if frozen is not None:
                raise PermissionError("budget_cloud_egress_frozen")
            call = db.exec_driver_sql(
                "SELECT id,provider_usage_json,provider_usage_receipt_key_id,"
                "provider_usage_receipt_hmac_b64 FROM provider_calls "
                "WHERE budget_reservation_id=? AND attempt_id=? "
                "AND gateway_ordering_version=1 AND transport_phase='claim_begun' "
                "AND outcome='started'",
                (str(reservation_id), str(attempt_id)),
            ).fetchone()
            if call is None or any(value is not None for value in call[1:]):
                raise PermissionError("provider_claim_proof_missing")
            reservation = db.exec_driver_sql(
                "UPDATE budget_reservations SET state='sent',transport_phase='marked_sent' "
                "WHERE id=? AND attempt_id=? AND state='reserved' AND expires_at>? "
                "AND gateway_ordering_version=1 AND transport_phase='claim_begun'",
                (str(reservation_id), str(attempt_id), utc_storage(now)),
            )
            if reservation.rowcount != 1:
                raise PermissionError("reservation_not_markable_sent")
            provider = db.exec_driver_sql(
                "UPDATE provider_calls SET transport_phase='marked_sent' WHERE id=? "
                "AND budget_reservation_id=? AND attempt_id=? AND outcome='started' "
                "AND gateway_ordering_version=1 AND transport_phase='claim_begun'",
                (call[0], str(reservation_id), str(attempt_id)),
            )
            if provider.rowcount != 1:
                raise PermissionError("provider_claim_phase_race")

        async with self._uow_factory() as uow:
            await uow.run_sync(mark_pair)
            await uow.commit()

    @staticmethod
    def _record_freeze(
        db: Any,
        *,
        month_key: str,
        reason: str,
        total: int | None,
        hard_limit: int,
        reservation_id: UUID,
        now: datetime,
    ) -> None:
        payload = json.dumps(
            {
                "reason_code": reason,
                "month_key": month_key,
                "overage_known": total is not None,
                "effective_micros_sgd": total,
                "hard_limit_micros_sgd": hard_limit,
                "reservation_id": str(reservation_id),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        db.exec_driver_sql(
            "INSERT INTO runtime_settings(key,value_json,version,updated_at) "
            "VALUES(?,?,1,?) ON CONFLICT(key) DO NOTHING",
            (f"budget.cloud_egress_freeze.{month_key}", payload, utc_storage(now)),
        )
        db.exec_driver_sql(
            "INSERT INTO runtime_settings(key,value_json,version,updated_at) "
            "VALUES(?,?,1,?) ON CONFLICT(key) DO NOTHING",
            (f"budget.owner_alert.{month_key}.{reservation_id}", payload, utc_storage(now)),
        )

    async def _freeze_evidence_quarantine(
        self,
        request: BudgetSettlementRequest,
        now: datetime,
        reason: str,
    ) -> None:
        async with self._uow_factory() as uow:

            def freeze(db: Any) -> None:
                row = db.exec_driver_sql(
                    "SELECT month_key FROM budget_reservations WHERE id=? AND attempt_id=?",
                    (str(request.reservation_id), str(request.attempt_id)),
                ).fetchone()
                if row is not None:
                    self._record_freeze(
                        db,
                        month_key=row[0],
                        reason=reason,
                        total=None,
                        hard_limit=self._hard_limit,
                        reservation_id=request.reservation_id,
                        now=now,
                    )

            await uow.run_sync(freeze)
            await uow.commit()

    def _settle_locked(
        self,
        db: Any,
        request: BudgetSettlementRequest,
        now: datetime,
    ) -> BudgetSettlement:
        reservation = (
            db.exec_driver_sql(
                "SELECT * FROM budget_reservations WHERE id=? AND attempt_id=?",
                (str(request.reservation_id), str(request.attempt_id)),
            )
            .mappings()
            .one_or_none()
        )
        if (
            reservation is None
            or reservation["state"] not in {"reserved", "sent"}
            or reservation["outcome"] not in {"allow", "allow_soft_warning"}
        ):
            raise PermissionError("reservation_not_settleable")
        snapshot = self._evidence.require_pricing_snapshot(reservation)
        calls = (
            db.exec_driver_sql(
                "SELECT * FROM provider_calls WHERE budget_reservation_id=? AND attempt_id=?",
                (str(request.reservation_id), str(request.attempt_id)),
            )
            .mappings()
            .all()
        )
        if reservation["gateway_ordering_version"] != 1 or len(calls) > 1:
            raise PermissionError("budget_transport_proof_quarantined")
        call = None if not calls else calls[0]
        receipt: ProviderUsageReceiptV1 | None = None
        force_conservative = False
        receipt_columns = (
            "provider_usage_json",
            "provider_usage_receipt_key_id",
            "provider_usage_receipt_hmac_b64",
        )
        if call is None:
            if (
                reservation["state"] == "reserved"
                and reservation["transport_phase"] == "not_claimed"
            ):
                raise PermissionError("proven_unsent_requires_release")
            raise PermissionError("budget_transport_proof_quarantined")
        if call["gateway_ordering_version"] != 1:
            raise PermissionError("budget_transport_proof_quarantined")
        if call["outcome"] == "started":
            if (
                reservation["state"] == "reserved"
                and reservation["transport_phase"] == "claim_begun"
                and call["transport_phase"] == "claim_begun"
                and all(call[name] is None for name in receipt_columns)
            ):
                raise PermissionError("proven_unsent_requires_release")
            if (
                reservation["state"] != "sent"
                or call["transport_phase"] != reservation["transport_phase"]
                or call["transport_phase"] not in {"marked_sent", "network_invocation_starting"}
                or any(call[name] is not None for name in receipt_columns)
            ):
                raise PermissionError("budget_transport_proof_quarantined")
            force_conservative = True
            closed = db.exec_driver_sql(
                "UPDATE provider_calls SET outcome='ambiguous',"
                "transport_phase='finished',finished_at=? "
                "WHERE id=? AND outcome='started' AND gateway_ordering_version=1 "
                "AND transport_phase=?",
                (utc_storage(now), call["id"], call["transport_phase"]),
            )
            if closed.rowcount != 1:
                raise PermissionError("budget_transport_proof_quarantined")
        elif (
            call["outcome"] not in {"succeeded", "failed", "cancelled", "ambiguous"}
            or call["transport_phase"] != "finished"
            or call["finished_at"] is None
            or reservation["transport_phase"] != "finished"
        ):
            raise PermissionError("budget_transport_proof_quarantined")
        else:
            force_conservative = call["outcome"] != "succeeded"
            present = tuple(call[name] is not None for name in receipt_columns)
            if len(set(present)) != 1:
                raise BudgetEvidenceQuarantined("provider_usage_partial_unknown_overage")
            if call["outcome"] != "succeeded" and any(present):
                raise PermissionError("budget_transport_proof_quarantined")
            if call["outcome"] == "succeeded" and all(present):
                receipt = self._evidence.require_provider_usage_receipt(call, reservation, now)
            elif call["outcome"] == "succeeded":
                raise BudgetEvidenceQuarantined("provider_usage_missing_unknown_overage")
        receipt_is_full_reservation = (
            receipt is not None and receipt.accounting_basis == "conservative_full_reservation"
        )
        reserved = int(reservation["reserved_micros_sgd"])
        if receipt is None:
            actual: int | None = None
        elif receipt_is_full_reservation:
            actual = reserved
        else:
            actual = self._pricing.amount_from_snapshot(snapshot, receipt.billable_usage)
        conservative = force_conservative or actual is None or receipt_is_full_reservation
        if conservative:
            charged = max(reserved, 0 if actual is None else actual)
        elif actual is None:
            raise BudgetEvidenceQuarantined("provider_usage_missing_unknown_overage")
        else:
            charged = actual
        if not 0 <= charged <= MAX_CHARGE_MICROS_SGD:
            raise BudgetEvidenceQuarantined("provider_usage_out_of_range_unknown_overage")
        rows = db.exec_driver_sql(
            "SELECT id,state,reserved_micros_sgd,charged_micros_sgd "
            "FROM budget_reservations WHERE month_key=? AND id<>? "
            "AND state IN ('reserved','sent','settled')",
            (reservation["month_key"], str(request.reservation_id)),
        ).fetchall()
        monthly_after = charged
        if monthly_after > MAX_AGGREGATE_MICROS_SGD:
            raise OverflowError("budget_arithmetic_out_of_bounds")
        for _id, state, other_reserved, other_charged in rows:
            amount = other_charged if state == "settled" else other_reserved
            if amount is None:
                raise BudgetEvidenceQuarantined("budget_total_missing_unknown_overage")
            monthly_after = checked_add(monthly_after, int(amount))
        estimate_overrun = charged > reserved
        hard_cap_exceeded = monthly_after > self._hard_limit
        freeze_reason = (
            "hard_cap_actual_exceeded"
            if hard_cap_exceeded
            else "estimate_overrun"
            if estimate_overrun
            else None
        )
        changed = db.exec_driver_sql(
            "UPDATE budget_reservations SET state='settled',transport_phase='finished',"
            "charged_micros_sgd=?,estimate_overrun=?,settled_at=?,reconciled_at=? "
            "WHERE id=? AND attempt_id=? AND state IN ('reserved','sent')",
            (
                charged,
                int(estimate_overrun),
                utc_storage(now),
                utc_storage(now),
                str(request.reservation_id),
                str(request.attempt_id),
            ),
        )
        if changed.rowcount != 1:
            raise PermissionError("reservation_not_settleable")
        usage_json = (
            "null" if receipt is None else self._evidence.canonical_usage(receipt.billable_usage)
        )
        receipt_json = None if receipt is None else self._evidence.canonical_receipt(receipt)
        receipt_key = None if receipt is None else receipt.receipt_commitment.key_id
        receipt_hmac = None if receipt is None else receipt.receipt_commitment.value_b64
        ledger_insert = db.exec_driver_sql(
            "INSERT INTO cost_ledger "
            "(id,reservation_id,month_key,reserved_micros_sgd,charged_micros_sgd,"
            "usage_json,provider_usage_receipt_json,provider_usage_receipt_key_id,"
            "provider_usage_receipt_hmac_b64,accounting_basis,"
            "reservation_primary_accounting_basis,reservation_missing_evidence_policy,"
            "conservative_estimate_used,estimate_overrun,hard_cap_exceeded,"
            "pricing_version,price_source_sha256,fx_version,fx_source_sha256,settled_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                str(request.reservation_id),
                reservation["month_key"],
                reserved,
                charged,
                usage_json,
                receipt_json,
                receipt_key,
                receipt_hmac,
                None if receipt is None else receipt.accounting_basis,
                reservation["primary_accounting_basis"],
                reservation["missing_evidence_policy"],
                int(conservative),
                int(estimate_overrun),
                int(hard_cap_exceeded),
                reservation["pricing_version"],
                reservation["price_source_sha256"],
                reservation["fx_version"],
                reservation["fx_source_sha256"],
                utc_storage(now),
            ),
        )
        if ledger_insert.rowcount != 1:
            raise PermissionError("budget_ledger_insert_failed")
        if freeze_reason is not None:
            self._record_freeze(
                db,
                month_key=reservation["month_key"],
                reason=freeze_reason,
                total=monthly_after,
                hard_limit=self._hard_limit,
                reservation_id=request.reservation_id,
                now=now,
            )
        return BudgetSettlement(
            reservation_id=request.reservation_id,
            charged_micros_sgd=charged,
            conservative_estimate_used=conservative,
            estimate_overrun=estimate_overrun,
            cloud_egress_frozen=freeze_reason is not None,
        )

    async def settle(self, request: BudgetSettlementRequest) -> BudgetSettlement:
        now = self._clock.now()
        try:
            async with self._uow_factory() as uow:
                result = await uow.run_sync(
                    lambda db: self._settle_locked(db, request, now)
                )
                await uow.commit()
                return cast(BudgetSettlement, result)
        except BudgetEvidenceQuarantined as error:
            await self._freeze_evidence_quarantine(request, now, error.reason_code)
            raise PermissionError(error.reason_code) from error
        except OverflowError as error:
            reason = "budget_total_invalid_unknown_overage"
            await self._freeze_evidence_quarantine(request, now, reason)
            raise PermissionError(reason) from error

    def _release_unsent_locked(
        self,
        db: Any,
        reservation_id: UUID,
        attempt_id: UUID,
        now: datetime,
    ) -> None:
        reservation = db.exec_driver_sql(
            "SELECT state,gateway_ordering_version,transport_phase,outcome "
            "FROM budget_reservations WHERE id=? AND attempt_id=?",
            (str(reservation_id), str(attempt_id)),
        ).fetchone()
        calls = db.exec_driver_sql(
            "SELECT id,gateway_ordering_version,transport_phase,outcome,"
            "provider_usage_json,provider_usage_receipt_key_id,"
            "provider_usage_receipt_hmac_b64 "
            "FROM provider_calls WHERE budget_reservation_id=? AND attempt_id=?",
            (str(reservation_id), str(attempt_id)),
        ).fetchall()
        proven = (
            reservation is not None
            and tuple(reservation[:2]) == ("reserved", 1)
            and reservation[3] in {"allow", "allow_soft_warning"}
            and (
                (reservation[2] == "not_claimed" and calls == [])
                or (
                    reservation[2] == "claim_begun"
                    and len(calls) == 1
                    and tuple(calls[0][1:4]) == (1, "claim_begun", "started")
                    and all(value is None for value in calls[0][4:])
                )
            )
        )
        if not proven:
            raise PermissionError("sent_reservation_requires_settlement")
        if calls:
            closed = db.exec_driver_sql(
                "UPDATE provider_calls SET outcome='cancelled',"
                "transport_phase='finished',finished_at=? "
                "WHERE id=? AND outcome='started' AND gateway_ordering_version=1 "
                "AND transport_phase='claim_begun'",
                (utc_storage(now), calls[0][0]),
            )
            if closed.rowcount != 1:
                raise PermissionError("sent_reservation_requires_settlement")
        cursor = db.exec_driver_sql(
            "UPDATE budget_reservations SET state='released',"
            "transport_phase='finished',reconciled_at=? "
            "WHERE id=? AND attempt_id=? AND state='reserved' "
            "AND gateway_ordering_version=1 AND transport_phase=?",
            (utc_storage(now), str(reservation_id), str(attempt_id), reservation[2]),
        )
        if cursor.rowcount != 1:
            raise PermissionError("sent_reservation_requires_settlement")

    async def _release_proven_unsent(self, reservation_id: UUID, attempt_id: UUID) -> None:
        now = self._clock.now()
        async with self._uow_factory() as uow:
            await uow.run_sync(
                lambda db: self._release_unsent_locked(db, reservation_id, attempt_id, now)
            )
            await uow.commit()

    async def release_unsent(
        self,
        reservation_id: UUID,
        attempt_id: UUID,
        proof: TransportProof,
    ) -> None:
        if (
            proof.reservation_id != reservation_id
            or proof.attempt_id != attempt_id
            or proof.disposition != "never_sent"
        ):
            raise PermissionError("proof_does_not_establish_unsent")
        await self._release_proven_unsent(reservation_id, attempt_id)

    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[BudgetSettlement, ...]:
        supplied = {(proof.reservation_id, proof.attempt_id): proof for proof in request.proofs}
        if len(supplied) != len(request.proofs):
            raise PermissionError("duplicate_turn_reconciliation_proof")
        async with self._uow_factory() as uow:

            def load_bound(db: Any) -> tuple[tuple[UUID, UUID, str], ...]:
                rows = db.exec_driver_sql(
                    "SELECT key,value_json FROM runtime_settings "
                    "WHERE key LIKE 'budget.turn.%' AND json_extract(value_json,'$.turn_id')=?",
                    (str(request.turn_id),),
                ).fetchall()
                bound = []
                for key, value_json in rows:
                    binding = parse_contract_json(
                        BudgetTurnBindingV1,
                        value_json.encode("utf-8", errors="strict"),
                        max_bytes=1_024,
                        require_canonical=True,
                    )
                    reservation_id = UUID(key.removeprefix("budget.turn."))
                    row = db.exec_driver_sql(
                        "SELECT request_id,attempt_id,state FROM budget_reservations WHERE id=?",
                        (str(reservation_id),),
                    ).fetchone()
                    if (
                        row is None
                        or UUID(row[0]) != binding.request_id
                        or UUID(row[1]) != binding.attempt_id
                        or binding.turn_id != request.turn_id
                    ):
                        raise PermissionError("reservation_turn_binding_corrupt")
                    bound.append((reservation_id, UUID(row[1]), row[2]))
                return tuple(bound)

            bound = await uow.run_sync(load_bound)
            await uow.rollback()
        bound_pairs = {(reservation_id, attempt_id) for reservation_id, attempt_id, _ in bound}
        if not set(supplied).issubset(bound_pairs):
            raise PermissionError("reservation_turn_mismatch")
        settlements = []
        for reservation_id, attempt_id, state in bound:
            if state in {"settled", "released", "denied"}:
                continue
            proof = supplied.get((reservation_id, attempt_id))
            if proof is not None and proof.disposition == "never_sent":
                await self.release_unsent(reservation_id, attempt_id, proof)
            elif proof is not None:
                settlements.append(
                    await self.settle(
                        BudgetSettlementRequest(
                            reservation_id=reservation_id,
                            attempt_id=attempt_id,
                        )
                    )
                )
            else:
                try:
                    await self._release_proven_unsent(reservation_id, attempt_id)
                except PermissionError as error:
                    if str(error) != "sent_reservation_requires_settlement":
                        raise
                    settlements.append(
                        await self.settle(
                            BudgetSettlementRequest(
                                reservation_id=reservation_id,
                                attempt_id=attempt_id,
                            )
                        )
                    )
        return tuple(settlements)
