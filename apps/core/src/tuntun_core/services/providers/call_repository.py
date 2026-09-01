from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy.exc import IntegrityError
from tuntun_contracts.ports import ClockPort
from tuntun_contracts.provider import RouteAuthorization, RouteConsumption
from tuntun_core.services.providers.redaction_repository import (
    AsyncUnitOfWorkFactory,
    RedactionReceiptRepository,
)
from tuntun_core.services.providers.route_verifier import verify_route_consumption
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol

_CATEGORY = {
    "cloud_stt": "stt",
    "cloud_reasoning": "llm",
    "cloud_tts": "tts",
}


def _utc_storage(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError("stored timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ProviderCallRepository:
    def __init__(
        self,
        uow_factory: AsyncUnitOfWorkFactory,
        clock: ClockPort,
        receipts: RedactionReceiptRepository,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._receipts = receipts

    @property
    def uow_factory(self) -> AsyncUnitOfWorkFactory:
        return self._uow_factory

    async def begin(
        self,
        route: RouteAuthorization,
        consumption: RouteConsumption,
        redaction_receipt_id: UUID | None,
    ) -> UUID:
        call_id = uuid4()
        now = self._clock.now()
        verify_route_consumption(route, consumption, now=now)

        def claim(db: UnitOfWorkProtocol) -> None:
            if route.purpose == "cloud_stt":
                if redaction_receipt_id is not None:
                    raise PermissionError("redaction_receipt_forbidden")
            else:
                if redaction_receipt_id is None:
                    raise PermissionError("redaction_receipt_binding_mismatch")
                self._receipts.require_bound_in_transaction(
                    db,
                    receipt_id=redaction_receipt_id,
                    purpose=route.purpose,
                    output_commitment=consumption.request_commitment,
                    maximum_sensitivity=route.maximum_sensitivity,
                )
            changed = db.exec_driver_sql(
                "UPDATE budget_reservations SET transport_phase='claim_begun' "
                "WHERE id=? AND request_id=? AND attempt_id=? AND provider=? AND model=? "
                "AND category=? AND state='reserved' AND gateway_ordering_version=1 "
                "AND transport_phase='not_claimed' AND expires_at>?",
                (
                    str(route.budget_reservation_id),
                    str(route.request_id),
                    str(route.attempt_id),
                    route.provider,
                    route.model,
                    _CATEGORY[route.purpose],
                    _utc_storage(now),
                ),
            )
            if changed.rowcount != 1:
                raise PermissionError("reservation_not_claimable")
            inserted = db.exec_driver_sql(
                "INSERT INTO provider_calls "
                "(id,request_id,attempt_id,authorization_id,budget_reservation_id,purpose,"
                "provider,model,redaction_receipt_id,request_hmac_key_id,request_hmac_b64,"
                "category,outcome,gateway_ordering_version,transport_phase,started_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,'claim_begun',?)",
                (
                    str(call_id),
                    str(route.request_id),
                    str(route.attempt_id),
                    str(route.authorization_id),
                    str(route.budget_reservation_id),
                    route.purpose,
                    route.provider,
                    route.model,
                    None if redaction_receipt_id is None else str(redaction_receipt_id),
                    consumption.request_commitment.key_id,
                    consumption.request_commitment.value_b64,
                    _CATEGORY[route.purpose],
                    "started",
                    _utc_storage(now),
                ),
            )
            if inserted.rowcount != 1:
                raise PermissionError("provider_call_claim_conflict")

        try:
            async with self._uow_factory() as uow:
                await uow.run_sync(claim)
                await uow.commit()
        except IntegrityError:
            raise PermissionError("provider_call_claim_conflict") from None
        return call_id

    async def mark_network_invocation_starting(self, call_id: UUID) -> None:
        def advance(db: UnitOfWorkProtocol) -> None:
            row = db.exec_driver_sql(
                "SELECT budget_reservation_id,attempt_id,provider_usage_json,"
                "provider_usage_receipt_key_id,provider_usage_receipt_hmac_b64 "
                "FROM provider_calls "
                "WHERE id=? AND outcome='started' AND gateway_ordering_version=1 "
                "AND transport_phase='marked_sent'",
                (str(call_id),),
            ).fetchone()
            if row is None or any(value is not None for value in row[2:]):
                raise PermissionError("provider_call_not_markable_network")
            reservation_id, attempt_id = row[:2]
            reservation = db.exec_driver_sql(
                "UPDATE budget_reservations SET transport_phase='network_invocation_starting' "
                "WHERE id=? AND attempt_id=? AND state='sent' "
                "AND gateway_ordering_version=1 AND transport_phase='marked_sent'",
                (reservation_id, attempt_id),
            )
            if reservation.rowcount != 1:
                raise PermissionError("budget_proof_pair_mismatch")
            call = db.exec_driver_sql(
                "UPDATE provider_calls SET transport_phase='network_invocation_starting' "
                "WHERE id=? AND outcome='started' AND gateway_ordering_version=1 "
                "AND transport_phase='marked_sent'",
                (str(call_id),),
            )
            if call.rowcount != 1:
                raise PermissionError("provider_call_phase_race")

        async with self._uow_factory() as uow:
            await uow.run_sync(advance)
            await uow.commit()

    async def finish(self, call_id: UUID, outcome: str) -> None:
        if outcome not in {"succeeded", "failed", "cancelled", "ambiguous"}:
            raise ValueError("invalid provider call outcome")
        now = self._clock.now()

        def finish_pair(db: UnitOfWorkProtocol) -> None:
            row = db.exec_driver_sql(
                "SELECT budget_reservation_id,attempt_id,transport_phase FROM provider_calls "
                "WHERE id=? AND outcome='started' AND gateway_ordering_version=1",
                (str(call_id),),
            ).fetchone()
            if row is None:
                raise PermissionError("provider_call_not_finishable")
            reservation_id, attempt_id, phase = row
            if phase == "claim_begun":
                raise PermissionError("provider_call_unsent_requires_release")
            if phase not in {"marked_sent", "network_invocation_starting"}:
                raise PermissionError("provider_call_not_finishable")
            call = db.exec_driver_sql(
                "UPDATE provider_calls SET outcome=?,transport_phase='finished',finished_at=? "
                "WHERE id=? AND outcome='started' AND transport_phase=?",
                (outcome, _utc_storage(now), str(call_id), phase),
            )
            if call.rowcount != 1:
                raise PermissionError("provider_call_finish_race")
            reservation = db.exec_driver_sql(
                "UPDATE budget_reservations SET transport_phase='finished' "
                "WHERE id=? AND attempt_id=? AND state='sent' "
                "AND gateway_ordering_version=1 AND transport_phase=?",
                (reservation_id, attempt_id, phase),
            )
            if reservation.rowcount != 1:
                raise PermissionError("provider_reservation_finish_race")

        async with self._uow_factory() as uow:
            await uow.run_sync(finish_pair)
            await uow.commit()
