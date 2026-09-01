from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from tuntun_contracts.budget import BudgetSettlementRequest
from tuntun_core.services.budget.evidence import BudgetEvidenceQuarantined
from tuntun_core.services.storage_time import utc_storage


class ReconciliationEvidenceQuarantined(Exception):
    def __init__(self, request: BudgetSettlementRequest, reason_code: str) -> None:
        super().__init__(reason_code)
        self.request = request
        self.reason_code = reason_code


class ExpiredBudgetReconciler:
    def __init__(
        self,
        uow_factory: Any,
        clock: Any,
        guard: Any,
        batch_size: int = 1000,
        interval_seconds: float = 60.0,
    ) -> None:
        if (
            isinstance(interval_seconds, bool)
            or not isinstance(interval_seconds, (int, float))
            or not 0.001 <= interval_seconds <= 60.0
        ):
            raise ValueError("budget_reconciliation_interval_invalid")
        self._uow_factory = uow_factory
        self._clock = clock
        self._guard = guard
        self._batch_size = batch_size
        self._interval_seconds = float(interval_seconds)

    async def _reconcile_batch(self, *, restart_cutoff: datetime | None = None) -> int:
        now = self._clock.now()
        boundary_column = "expires_at" if restart_cutoff is None else "created_at"
        boundary = now if restart_cutoff is None else restart_cutoff
        try:
            async with self._uow_factory() as uow:

                def reconcile_locked(db: Any) -> int:
                    rows = db.exec_driver_sql(
                        "SELECT id,attempt_id,state,outcome,"
                        "gateway_ordering_version,transport_phase "
                        "FROM budget_reservations WHERE state IN ('reserved','sent') "
                        f"AND {boundary_column}<=? ORDER BY {boundary_column},id LIMIT ?",
                        (utc_storage(boundary), self._batch_size),
                    ).fetchall()
                    changed = 0
                    for reservation_id, attempt_id, state, outcome, ordering, phase in rows:
                        calls = db.exec_driver_sql(
                            "SELECT gateway_ordering_version,transport_phase,outcome,"
                            "provider_usage_json,provider_usage_receipt_key_id,"
                            "provider_usage_receipt_hmac_b64 "
                            "FROM provider_calls WHERE budget_reservation_id=? AND attempt_id=?",
                            (reservation_id, attempt_id),
                        ).fetchall()
                        invalid_shape = (
                            outcome not in {"allow", "allow_soft_warning"}
                            or ordering != 1
                            or len(calls) > 1
                        )
                        if invalid_shape:
                            raise PermissionError("budget_transport_proof_quarantined")
                        proven_unsent = state == "reserved" and (
                            (phase == "not_claimed" and calls == [])
                            or (
                                phase == "claim_begun"
                                and len(calls) == 1
                                and tuple(calls[0][:3]) == (1, "claim_begun", "started")
                                and all(value is None for value in calls[0][3:])
                            )
                        )
                        reservation_uuid = UUID(reservation_id)
                        attempt_uuid = UUID(attempt_id)
                        if proven_unsent:
                            self._guard._release_unsent_locked(
                                db,
                                reservation_uuid,
                                attempt_uuid,
                                now,
                            )
                        else:
                            request = BudgetSettlementRequest(
                                reservation_id=reservation_uuid,
                                attempt_id=attempt_uuid,
                            )
                            try:
                                self._guard._settle_locked(db, request, now)
                            except BudgetEvidenceQuarantined as error:
                                raise ReconciliationEvidenceQuarantined(
                                    request,
                                    error.reason_code,
                                ) from error
                            except OverflowError as error:
                                raise ReconciliationEvidenceQuarantined(
                                    request,
                                    "budget_total_invalid_unknown_overage",
                                ) from error
                        changed += 1
                    return changed

                changed = await uow.run_sync(reconcile_locked)
                await uow.commit()
                return cast(int, changed)
        except ReconciliationEvidenceQuarantined as error:
            await self._guard._freeze_evidence_quarantine(
                error.request,
                now,
                error.reason_code,
            )
            raise RuntimeError(error.reason_code) from error

    async def reconcile_batch(self) -> int:
        return await self._reconcile_batch()

    async def reconcile_restart_batch(self, cutoff: datetime) -> int:
        return await self._reconcile_batch(restart_cutoff=cutoff)

    async def drain_before_ready(self) -> None:
        while await self.reconcile_batch() == self._batch_size:
            pass

    async def drain_restart_open_attempts(self, cutoff: datetime) -> None:
        while await self.reconcile_restart_batch(cutoff) == self._batch_size:
            pass

    async def run_periodically(self, stop: Any) -> None:
        while not stop.is_set():
            await self.reconcile_batch()
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self._interval_seconds)
