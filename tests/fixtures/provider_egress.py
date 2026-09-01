# tests/fixtures/provider_egress.py
from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from types import SimpleNamespace
from typing import Literal
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from tuntun_contracts.audit import AuditReceipt
from tuntun_contracts.base import Commitment, Sensitivity, canonical_bytes, canonical_mapping_bytes
from tuntun_contracts.budget import (
    BudgetReservationRequest,
    BudgetSettlementRequest,
    LlmUsageUnits,
    ProviderUsageReceiptV1,
)
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.provider import (
    RedactionReceipt,
    RouteAuthorization,
    RouteAuthorizationRequest,
    RouteConsumption,
)
from tuntun_contracts.reachy import SafetyReceipt
from tuntun_core.bootstrap.container import CoreContainer
from tuntun_core.services.budget.catalog import PriceCatalog
from tuntun_core.services.budget.guard import BudgetGuard
from tuntun_core.services.budget.month import singapore_month_key
from tuntun_core.services.budget.reconciler import ExpiredBudgetReconciler
from tuntun_core.services.providers.call_repository import ProviderCallRepository
from tuntun_core.services.providers.gateway import ProviderGateway, ProviderUsageObservation
from tuntun_core.services.providers.reasoning_wire import (
    build_openai_reasoning_wire_request,
)
from tuntun_core.services.providers.redaction_repository import (
    AsyncUnitOfWorkFactory,
    RedactionReceiptRepository,
)
from tuntun_core.services.providers.redactor import Redactor
from tuntun_core.services.providers.route_authorization import RouteAuthorizationEnvelopeV1
from tuntun_core.services.providers.route_verifier import authorization_from_request
from tuntun_core.services.storage_time import utc_storage
from tuntun_testing.fake_clock import FakeClock

from tests.fixtures.provider_routes import RouteDatabase

pytest_plugins = ("tests.fixtures.provider_routes", "tests.fixtures.budget")

_ROOT = b"k" * 32
_KEY_ID = "route-hmac-v1"
_PURPOSES = frozenset({"cloud_stt", "cloud_reasoning", "cloud_tts"})
_RECEIPT_MUTATIONS = frozenset(
    {
        "valid",
        "missing",
        "present",
        "swapped",
        "wrong_purpose",
        "wrong_output_commitment",
        "wrong_sensitivity",
    }
)
_FAULTS = frozenset(
    {
        "after_reservation_update",
        "after_call_insert",
        "before_call_insert_ignore",
        "after_network_reservation_update",
        "after_call_finish",
        "reservation_finish_cas_lost",
    }
)
_BOUNDARY_MUTATIONS = frozenset(
    {
        "secret_in_input",
        "secret_in_canonical_body",
        "email_in_canonical_body",
        "phone_in_canonical_body",
        "session_label_in_canonical_body",
    }
)


def _other_commitment(label: str) -> Commitment:
    return commit_private(
        _ROOT,
        _KEY_ID,
        "provider.request.test-mutation",
        canonical_mapping_bytes({"label": label}),
    )


@dataclass(frozen=True, slots=True)
class ProviderContext:
    route: RouteAuthorization
    consumption: RouteConsumption
    receipt: RedactionReceipt | None
    canonical_body: bytes


def _artifact(
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"],
    *,
    receipt_id: UUID | None = None,
    user_text: str = "Email me at person@example.test",
) -> tuple[RedactionReceipt | None, bytes, int]:
    if purpose == "cloud_stt":
        body = canonical_mapping_bytes({"audio_sha256": "a" * 64, "model": "gpt-transcribe"})
        return None, body, 1_000
    redactor = Redactor(
        root_key=_ROOT,
        key_id=_KEY_ID,
        receipt_id_factory=(lambda: receipt_id or uuid4()),
    )
    if purpose == "cloud_reasoning":
        draft = redactor.sanitize(
            purpose=purpose,
            session_label="session-1",
            system_text="Answer briefly",
            user_text=user_text,
            memory_texts=("session-1 prefers concise answers",),
        )
        _, body = build_openai_reasoning_wire_request(
            model="gpt-5.6-sol",
            messages=draft.provider_messages,
            allowed_tools=(),
            max_output_tokens=512,
            store=False,
            output_schema={
                "type": "object",
                "properties": {"answer": {"type": "string"}},
                "required": ["answer"],
                "additionalProperties": False,
            },
        )
        units = sum(len(message.content.encode("utf-8")) for message in draft.provider_messages)
    else:
        draft = redactor.sanitize(
            purpose=purpose,
            session_label="session-1",
            system_text=None,
            user_text="Read this safely",
            memory_texts=(),
        )
        body = canonical_mapping_bytes(
            {
                "input": draft.user_text,
                "model": "tts-1",
                "response_format": "pcm",
                "voice": "alloy",
            }
        )
        units = len(draft.user_text)
    receipt = redactor.finalize(
        draft,
        purpose=purpose,
        canonical_provider_body=body,
        policy_version="provider-redaction-v1",
        maximum_sensitivity=Sensitivity.PERSONAL,
    )
    return receipt, body, units


async def _seed_reservation(
    factory: AsyncUnitOfWorkFactory,
    route: RouteAuthorization,
    clock: FakeClock,
) -> None:
    category = {"cloud_stt": "stt", "cloud_reasoning": "llm", "cloud_tts": "tts"}[route.purpose]
    accounting = "request_bound_exact" if category == "tts" else "provider_reported_exact"
    now = clock.now()
    values = (
        str(route.budget_reservation_id),
        str(route.request_id),
        str(route.attempt_id),
        now.strftime("%Y-%m"),
        category,
        route.provider,
        route.model,
        "allow",
        10_000,
        json.dumps({"category": category}, separators=(",", ":")),
        "{}",
        accounting,
        "freeze_unknown_overage",
        "test-pricing-v1",
        "a" * 64,
        "test-fx-v1",
        "b" * 64,
        _KEY_ID,
        _other_commitment("pricing").value_b64,
        "reserved",
        1,
        "not_claimed",
        utc_storage(now),
        utc_storage(now + timedelta(minutes=5)),
    )
    async with factory() as uow:

        def insert_reservation(db) -> int:
            return db.exec_driver_sql(
                "INSERT INTO budget_reservations "
                "(id,request_id,attempt_id,month_key,category,provider,model,outcome,"
                "reserved_micros_sgd,usage_ceiling_json,price_snapshot_json,"
                "primary_accounting_basis,missing_evidence_policy,pricing_version,"
                "price_source_sha256,fx_version,fx_source_sha256,pricing_commitment_key_id,"
                "pricing_commitment_hmac_b64,state,gateway_ordering_version,transport_phase,"
                "created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                values,
            ).rowcount

        if await uow.run_sync(insert_reservation) != 1:
            raise RuntimeError("test reservation insert lost ownership")
        await uow.commit()


async def _create_context(
    factory: AsyncUnitOfWorkFactory,
    repository: RedactionReceiptRepository,
    clock: FakeClock,
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"],
    *,
    receipt: RedactionReceipt | None = None,
    canonical_body: bytes | None = None,
    input_units: int | None = None,
    persist_receipt: bool = True,
    request_id: UUID | None = None,
) -> ProviderContext:
    generated_receipt, generated_body, units = _artifact(purpose)
    receipt = generated_receipt if receipt is None and purpose != "cloud_stt" else receipt
    body = generated_body if canonical_body is None else canonical_body
    units = units if input_units is None else input_units
    if receipt is not None and persist_receipt:
        await repository.record(receipt)
    model = {"cloud_stt": "gpt-transcribe", "cloud_reasoning": "gpt-5.6-sol", "cloud_tts": "tts-1"}[
        purpose
    ]
    commitment = (
        receipt.output_commitment
        if receipt is not None
        else commit_private(_ROOT, _KEY_ID, f"provider.request.{purpose}", body)
    )
    request = RouteAuthorizationRequest(
        request_id=request_id or uuid4(),
        attempt_id=uuid4(),
        purpose=purpose,
        household_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        turn_id=uuid4(),
        provider="openai",
        model=model,
        request_commitment=commitment,
        max_input_bytes=max(len(body), 1),
        max_input_units=max(units, 1),
        privacy_receipt_id=uuid4(),
        consent_receipt_ids=(uuid4(),),
        budget_reservation_id=uuid4(),
        maximum_sensitivity=Sensitivity.PERSONAL,
    )
    route = authorization_from_request(
        request,
        authorization_id=uuid4(),
        expires_at=clock.now() + timedelta(seconds=30),
    )
    consumption = RouteConsumption(
        request_id=route.request_id,
        attempt_id=route.attempt_id,
        purpose=route.purpose,
        household_id=route.household_id,
        subject_id=route.subject_id,
        session_id=route.session_id,
        turn_id=route.turn_id,
        provider=route.provider,
        model=route.model,
        request_commitment=route.request_commitment,
        input_bytes=len(body),
        input_units=units,
        consumed_at=clock.now(),
    )
    await _seed_reservation(factory, route, clock)
    return ProviderContext(route, consumption, receipt, body)


class BoundAuthorizerFake:
    def __init__(self, context: ProviderContext) -> None:
        self.context = context

    async def authorize(self, request):
        raise AssertionError(f"gateway must not authorize: {request!r}")

    async def consume(self, authorization_id: UUID, supplied: RouteConsumption) -> None:
        if (
            authorization_id != self.context.route.authorization_id
            or supplied != self.context.consumption
        ):
            raise PermissionError("route_consumption_mismatch")


class SqlBudgetPortFake:
    def __init__(self, factory: AsyncUnitOfWorkFactory, clock: FakeClock) -> None:
        self._factory = factory
        self._clock = clock

    async def mark_sent(self, reservation_id: UUID, attempt_id: UUID) -> None:
        now = utc_storage(self._clock.now())

        def mark(db) -> None:
            call_count = db.exec_driver_sql(
                "SELECT count(*) FROM provider_calls WHERE budget_reservation_id=? "
                "AND attempt_id=? AND outcome='started' AND gateway_ordering_version=1 "
                "AND transport_phase='claim_begun' AND provider_usage_json IS NULL "
                "AND provider_usage_receipt_key_id IS NULL "
                "AND provider_usage_receipt_hmac_b64 IS NULL",
                (str(reservation_id), str(attempt_id)),
            ).scalar_one()
            if call_count != 1:
                raise PermissionError("task04_mark_sent_proof_mismatch")
            reservation = db.exec_driver_sql(
                "UPDATE budget_reservations SET state='sent',transport_phase='marked_sent' "
                "WHERE id=? AND attempt_id=? AND outcome IN ('allow','allow_soft_warning') "
                "AND state='reserved' AND gateway_ordering_version=1 "
                "AND transport_phase='claim_begun' AND expires_at>?",
                (str(reservation_id), str(attempt_id), now),
            )
            call = db.exec_driver_sql(
                "UPDATE provider_calls SET transport_phase='marked_sent' "
                "WHERE budget_reservation_id=? AND attempt_id=? AND outcome='started' "
                "AND gateway_ordering_version=1 AND transport_phase='claim_begun'",
                (str(reservation_id), str(attempt_id)),
            )
            if reservation.rowcount != 1 or call.rowcount != 1:
                raise PermissionError("task04_mark_sent_proof_mismatch")

        async with self._factory() as uow:
            await uow.run_sync(mark)
            await uow.commit()

    async def reserve(self, request):
        raise AssertionError(f"Task04 gateway must not reserve: {request!r}")

    async def settle(self, request):
        raise AssertionError(f"Task04 gateway must not settle: {request!r}")

    async def release_unsent(self, reservation_id, attempt_id, proof):
        raise AssertionError((reservation_id, attempt_id, proof))

    async def reconcile_turn(self, request):
        raise AssertionError(f"Task04 gateway must not reconcile: {request!r}")


class GatewayCase:
    def __init__(
        self,
        context: ProviderContext,
        mark_sent_error: BaseException | None,
        clock: FakeClock,
    ) -> None:
        self.context = context
        self.mark_sent_error = mark_sent_error
        self.clock = clock
        self.events: list[str] = []
        self.finish_calls: list[str] = []

    async def send(self) -> str:
        case = self

        class Authorizer:
            async def consume(self, authorization_id, supplied):
                del authorization_id, supplied
                case.events.append("consume")

        class Budget:
            async def mark_sent(self, reservation_id, attempt_id):
                del reservation_id, attempt_id
                case.events.append("mark_sent")
                if case.mark_sent_error is not None:
                    raise case.mark_sent_error

            async def require_accounting_context(self, route, consumption):
                del route, consumption
                case.events.append("accounting")
                return SimpleNamespace(
                    category="llm",
                    usage_ceiling=LlmUsageUnits(category="llm", input_tokens=2, output_tokens=2),
                    primary_accounting_basis="provider_reported_exact",
                    missing_evidence_policy="freeze_unknown_overage",
                )

        class Calls:
            async def begin(self, route, supplied, receipt_id):
                del route, supplied, receipt_id
                case.events.append("call_started")
                return case.context.route.attempt_id

            async def mark_network_invocation_starting(self, call_id):
                del call_id
                case.events.append("network_starting")

            async def finish(self, call_id, outcome, route, receipt=None):
                del call_id
                del route, receipt
                case.events.append(outcome)
                case.finish_calls.append(outcome)

        class Evidence:
            def attest_provider_usage(self, **_values):
                return SimpleNamespace(receipt_id=uuid4())

        async def invoke() -> str:
            case.events.append("network")
            return "ok"

        async def observe(_result):
            return ProviderUsageObservation(
                LlmUsageUnits(category="llm", input_tokens=1, output_tokens=1),
                "gateway_case_resp_1",
            )

        gateway = ProviderGateway(Authorizer(), Budget(), Calls(), Evidence(), self.clock)
        return await gateway.send(
            self.context.route,
            self.context.consumption,
            self.context.receipt.receipt_id if self.context.receipt else None,
            invoke,
            observe,
        )


async def _proof_rows(factory: AsyncUnitOfWorkFactory, route: RouteAuthorization):
    def select_rows(db):
        reservation = db.exec_driver_sql(
            "SELECT state,gateway_ordering_version,transport_phase "
            "FROM budget_reservations WHERE id=? AND attempt_id=?",
            (str(route.budget_reservation_id), str(route.attempt_id)),
        ).fetchone()
        call = db.exec_driver_sql(
            "SELECT id,gateway_ordering_version,transport_phase,outcome "
            "FROM provider_calls WHERE budget_reservation_id=? AND attempt_id=?",
            (str(route.budget_reservation_id), str(route.attempt_id)),
        ).fetchone()
        return tuple(row if row is None else tuple(row) for row in (reservation, call))

    async with factory() as uow:
        rows = await uow.run_sync(select_rows)
        await uow.rollback()
    return rows


class ProviderCallBindingCase:
    def __init__(self, harness: ProviderEgressHarness, purpose: str, receipt_mutation: str) -> None:
        if purpose not in _PURPOSES or receipt_mutation not in _RECEIPT_MUTATIONS:
            raise ValueError("unknown provider-call binding case")
        self._harness = harness
        self._purpose = purpose
        self._mutation = receipt_mutation
        self.context: ProviderContext | None = None
        self.receipt: RedactionReceipt | None = None

    async def _prepare(self) -> None:
        if self.context is not None:
            return
        context = await _create_context(
            self._harness.factory,
            self._harness.redaction_receipt_repository,
            self._harness.clock,
            self._purpose,  # type: ignore[arg-type]
        )
        supplied = context.receipt
        if self._mutation in {"missing"}:
            supplied = None
        elif self._mutation == "present":
            supplied = RedactionReceipt(
                receipt_id=uuid4(),
                purpose="cloud_reasoning",
                input_commitment=_other_commitment("present-input"),
                output_commitment=_other_commitment("present-output"),
                removed_categories=(),
                removed_count=0,
                policy_version="provider-redaction-v1",
                maximum_sensitivity=Sensitivity.PERSONAL,
            )
        elif supplied is not None and self._mutation != "valid":
            change: dict[str, object] = {"receipt_id": uuid4()}
            if self._mutation in {"swapped", "wrong_output_commitment"}:
                change["output_commitment"] = _other_commitment(self._mutation)
            elif self._mutation == "wrong_purpose":
                change["purpose"] = (
                    "cloud_tts" if context.route.purpose == "cloud_reasoning" else "cloud_reasoning"
                )
            elif self._mutation == "wrong_sensitivity":
                change["maximum_sensitivity"] = Sensitivity.RESTRICTED
            supplied = supplied.model_copy(update=change)
            await self._harness.redaction_receipt_repository.record(supplied)
        self.context = context
        self.receipt = supplied

    async def begin(self) -> UUID:
        await self._prepare()
        assert self.context is not None
        return await self._harness.provider_call_repository.begin(
            self.context.route,
            self.context.consumption,
            None if self.receipt is None else self.receipt.receipt_id,
        )

    async def persisted_proof_rows(self):
        await self._prepare()
        assert self.context is not None
        return await _proof_rows(self._harness.factory, self.context.route)

    async def persisted_redaction_receipt_id(self) -> UUID | None:
        await self._prepare()
        assert self.context is not None
        async with self._harness.factory() as uow:
            value = await uow.run_sync(
                lambda db: db.exec_driver_sql(
                    "SELECT redaction_receipt_id FROM provider_calls WHERE attempt_id=?",
                    (str(self.context.route.attempt_id),),
                ).scalar_one()
            )
            await uow.rollback()
        return None if value is None else UUID(value)


class CallRepositoryFaultCase:
    def __init__(self, harness: ProviderEgressHarness, fault: str | None) -> None:
        if fault is not None and fault not in _FAULTS:
            raise ValueError("unknown provider-call repository fault")
        self._harness = harness
        self._fault = fault
        self.context: ProviderContext | None = None
        self._call_id: UUID | None = None
        self.provider_call_finished_at: str | None = None

    async def _prepare(self) -> None:
        if self.context is None:
            self.context = await _create_context(
                self._harness.factory,
                self._harness.redaction_receipt_repository,
                self._harness.clock,
                "cloud_reasoning",
            )

    async def _trigger(self, phase: str) -> str:
        await self._prepare()
        assert self.context is not None
        name = f"test_provider_fault_{uuid4().hex}"
        attempt = str(self.context.route.attempt_id)
        if phase == "after_reservation_update":
            sql = (
                f"CREATE TRIGGER {name} AFTER UPDATE OF transport_phase ON budget_reservations "
                f"WHEN NEW.attempt_id='{attempt}' AND NEW.transport_phase='claim_begun' "
                "BEGIN SELECT RAISE(ABORT,'injected claim fault'); END"
            )
        elif phase == "after_call_insert":
            sql = (
                f"CREATE TRIGGER {name} AFTER INSERT ON provider_calls "
                f"WHEN NEW.attempt_id='{attempt}' "
                "BEGIN SELECT RAISE(ABORT,'injected claim fault'); END"
            )
        elif phase == "before_call_insert_ignore":
            sql = (
                f"CREATE TRIGGER {name} BEFORE INSERT ON provider_calls "
                f"WHEN NEW.attempt_id='{attempt}' "
                "BEGIN SELECT RAISE(IGNORE); END"
            )
        elif phase == "after_network_reservation_update":
            sql = (
                f"CREATE TRIGGER {name} AFTER UPDATE OF transport_phase ON budget_reservations "
                f"WHEN NEW.attempt_id='{attempt}' "
                "AND NEW.transport_phase='network_invocation_starting' "
                "BEGIN SELECT RAISE(ABORT,'injected network fault'); END"
            )
        elif phase == "after_call_finish":
            sql = (
                f"CREATE TRIGGER {name} AFTER UPDATE OF transport_phase ON provider_calls "
                f"WHEN NEW.attempt_id='{attempt}' AND NEW.transport_phase='finished' "
                "BEGIN SELECT RAISE(ABORT,'injected finish fault'); END"
            )
        elif phase == "reservation_finish_cas_lost":
            sql = (
                f"CREATE TRIGGER {name} BEFORE UPDATE OF transport_phase ON budget_reservations "
                f"WHEN NEW.attempt_id='{attempt}' AND NEW.transport_phase='finished' "
                "BEGIN SELECT RAISE(IGNORE); END"
            )
        else:
            raise ValueError("unknown trigger phase")
        async with self._harness.factory() as uow:
            await uow.run_sync(lambda db: db.exec_driver_sql(sql).rowcount)
            await uow.commit()
        return name

    async def _drop_trigger(self, name: str | None) -> None:
        if name is None:
            return
        async with self._harness.factory() as uow:
            await uow.run_sync(
                lambda db: db.exec_driver_sql(f"DROP TRIGGER IF EXISTS {name}").rowcount
            )
            await uow.commit()

    async def begin(self) -> UUID:
        await self._prepare()
        assert self.context is not None
        name = (
            await self._trigger(self._fault)
            if self._fault
            in {
                "after_reservation_update",
                "after_call_insert",
                "before_call_insert_ignore",
            }
            else None
        )
        try:
            self._call_id = await self._harness.provider_call_repository.begin(
                self.context.route,
                self.context.consumption,
                self.context.receipt.receipt_id if self.context.receipt else None,
            )
            return self._call_id
        finally:
            await self._drop_trigger(name)

    async def mark_sent(self) -> None:
        await self._prepare()
        assert self.context is not None
        await self._harness.budget_port_fake.mark_sent(
            self.context.route.budget_reservation_id,
            self.context.route.attempt_id,
        )

    async def mark_network_invocation_starting(self) -> None:
        assert self._call_id is not None
        name = await self._trigger("after_network_reservation_update")
        try:
            await self._harness.provider_call_repository.mark_network_invocation_starting(
                self._call_id
            )
        finally:
            await self._drop_trigger(name)

    async def finish(self, call_id: UUID, outcome: str) -> None:
        assert self.context is not None
        name = (
            await self._trigger(self._fault)
            if self._fault in {"after_call_finish", "reservation_finish_cas_lost"}
            else None
        )
        try:
            await self._harness.provider_call_repository.finish(
                call_id, outcome, self.context.route, None
            )
        finally:
            await self._drop_trigger(name)
        async with self._harness.factory() as uow:
            self.provider_call_finished_at = await uow.run_sync(
                lambda db: db.exec_driver_sql(
                    "SELECT finished_at FROM provider_calls WHERE id=?", (str(call_id),)
                ).scalar_one()
            )
            await uow.rollback()

    def clear_fault(self) -> None:
        self._fault = None

    async def persisted_proof_rows(self):
        await self._prepare()
        assert self.context is not None
        return await _proof_rows(self._harness.factory, self.context.route)

    async def persisted_phases(self) -> tuple[str, str]:
        reservation, call = await self.persisted_proof_rows()
        assert reservation is not None and call is not None
        return reservation[2], call[2]


class ProviderBoundaryCase:
    def __init__(
        self,
        harness: ProviderEgressHarness,
        *,
        user_text: str = "safe",
        mutation: str | None = None,
    ) -> None:
        if mutation is not None and mutation not in _BOUNDARY_MUTATIONS:
            raise ValueError("unknown provider-boundary mutation")
        self._harness = harness
        self.user_text = user_text
        self.mutation = mutation
        self.request_id = uuid4()
        self.receipt_id = uuid4()
        self.captured_provider_body = b""
        self.network_calls = 0

    async def run_reasoning(self) -> None:
        user_text = (
            "".join(("Use sk-", "proj-", "abcdefghijkl", "mnopqrstuv"))
            if self.mutation == "secret_in_input"
            else self.user_text
        )
        redactor = Redactor(_ROOT, _KEY_ID, receipt_id_factory=lambda: self.receipt_id)
        draft = redactor.sanitize(
            purpose="cloud_reasoning",
            session_label="session-1",
            system_text="Answer briefly",
            user_text=user_text,
            memory_texts=(),
        )
        _, body = build_openai_reasoning_wire_request(
            model="gpt-5.6-sol",
            messages=draft.provider_messages,
            allowed_tools=(),
            max_output_tokens=512,
            store=False,
            output_schema={"type": "object", "additionalProperties": False},
        )
        units = sum(len(message.content.encode("utf-8")) for message in draft.provider_messages)
        injected = {
            "secret_in_canonical_body": "".join(("sk-", "proj-", "abcdefghijkl", "mnopqrstuv")),
            "email_in_canonical_body": "person@example.test",
            "phone_in_canonical_body": "+65 8123 4567",
            "session_label_in_canonical_body": "session-1",
        }.get(self.mutation)
        if injected is not None:
            payload = json.loads(body)
            payload["injected"] = injected
            body = canonical_mapping_bytes(payload)
        receipt = redactor.finalize(
            draft,
            purpose="cloud_reasoning",
            canonical_provider_body=body,
            policy_version="provider-redaction-v1",
            maximum_sensitivity=Sensitivity.PERSONAL,
        )
        context, _reservation, guard = await _create_production_context(
            self._harness.factory,
            self._harness.clock,
            self._harness.catalog,
            self._harness.provider_reviews,
            self._harness.budget_evidence,
            seed_response_scope=False,
            supplied_receipt=receipt,
            supplied_body=body,
            supplied_units=units,
            supplied_request_id=self.request_id,
        )
        calls = ProviderCallRepository(
            self._harness.factory,
            self._harness.clock,
            self._harness.redaction_receipt_repository,
            self._harness.budget_evidence,
        )
        gateway = ProviderGateway(
            BoundAuthorizerFake(context),
            guard,
            calls,
            self._harness.budget_evidence,
            self._harness.clock,
        )

        async def capture() -> str:
            self.network_calls += 1
            self.captured_provider_body = body
            return "ok"

        async def observe(_result):
            return ProviderUsageObservation(
                LlmUsageUnits(category="llm", input_tokens=2, output_tokens=2),
                "boundary_resp_1",
            )

        await gateway.send(context.route, context.consumption, receipt.receipt_id, capture, observe)

    async def _count(self, table: str, column: str, value: UUID) -> int:
        if (table, column) not in {("redaction_receipts", "id"), ("provider_calls", "request_id")}:
            raise ValueError("unapproved test count target")
        async with self._harness.factory() as uow:
            count = await uow.run_sync(
                lambda db: db.exec_driver_sql(
                    f"SELECT count(*) FROM {table} WHERE {column}=?", (str(value),)
                ).scalar_one()
            )
            await uow.rollback()
        return count

    async def redaction_receipt_count(self) -> int:
        return await self._count("redaction_receipts", "id", self.receipt_id)

    async def provider_call_count(self) -> int:
        return await self._count("provider_calls", "request_id", self.request_id)

    async def serialized_receipt_and_call_rows(self) -> str:
        def select_rows(db):
            receipt_rows = db.exec_driver_sql(
                "SELECT * FROM redaction_receipts WHERE id=?",
                (str(self.receipt_id),),
            ).fetchall()
            call_rows = db.exec_driver_sql(
                "SELECT * FROM provider_calls WHERE request_id=?",
                (str(self.request_id),),
            ).fetchall()
            return tuple(tuple(tuple(row) for row in group) for group in (receipt_rows, call_rows))

        async with self._harness.factory() as uow:
            rows = await uow.run_sync(select_rows)
            await uow.rollback()
        return json.dumps(rows, sort_keys=True)


async def _seed_response_scope(
    factory: AsyncUnitOfWorkFactory, route: RouteAuthorization, clock: FakeClock
) -> None:
    device_id = uuid4()
    now = utc_storage(clock.now())
    envelope = RouteAuthorizationEnvelopeV1(
        route=route,
        subject_authority_generation=(7 if route.subject_id is not None else None),
    )
    async with factory() as uow:

        def seed(transaction) -> None:
            transaction.exec_driver_sql(
                "INSERT INTO households"
                "(id,display_label_ciphertext,timezone,created_at) "
                "VALUES(?,?,?,?)",
                (
                    str(route.household_id),
                    b"test-household",
                    "Asia/Singapore",
                    now,
                ),
            )
            transaction.exec_driver_sql(
                "INSERT INTO devices"
                "(id,household_id,kind,certificate_fingerprint,"
                "signing_public_key,signing_key_id,last_sequence,paired_at) "
                "VALUES(?,?,?,?,?,?,0,?)",
                (
                    str(device_id),
                    str(route.household_id),
                    "reachy",
                    f"test-{device_id}",
                    b"x" * 32,
                    "test-signing-v1",
                    now,
                ),
            )
            transaction.exec_driver_sql(
                "INSERT INTO sessions"
                "(id,household_id,device_id,state,speaker_subject_id,"
                "opened_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
                (
                    str(route.session_id),
                    str(route.household_id),
                    str(device_id),
                    "open",
                    None if route.subject_id is None else str(route.subject_id),
                    now,
                    now,
                ),
            )
            transaction.exec_driver_sql(
                "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES(?,?,1,?)",
                (
                    f"route.authorization.{route.authorization_id}",
                    canonical_bytes(envelope).decode("utf-8"),
                    now,
                ),
            )

        await uow.run_sync(seed)
        await uow.commit()


async def _create_production_context(
    factory: AsyncUnitOfWorkFactory,
    clock: FakeClock,
    catalog: PriceCatalog,
    provider_reviews,
    budget_evidence,
    *,
    seed_response_scope: bool,
    supplied_receipt: RedactionReceipt | None = None,
    supplied_body: bytes | None = None,
    supplied_units: int | None = None,
    supplied_request_id: UUID | None = None,
    usage_ceiling=None,
    hard_limit: int = 150_000_000,
    soft_limit: int = 100_000_000,
):
    receipt_repository = RedactionReceiptRepository(factory, clock)
    guard = BudgetGuard(
        factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
        hard_limit=hard_limit,
        soft_limit=soft_limit,
    )
    generated_receipt, generated_body, generated_units = _artifact("cloud_reasoning")
    receipt = generated_receipt if supplied_receipt is None else supplied_receipt
    body = generated_body if supplied_body is None else supplied_body
    units = generated_units if supplied_units is None else supplied_units
    assert receipt is not None
    await receipt_repository.record(receipt)
    request_id = supplied_request_id or uuid4()
    attempt_id = uuid4()
    household_id, subject_id, session_id, turn_id = uuid4(), uuid4(), uuid4(), uuid4()
    usage = (
        LlmUsageUnits(category="llm", input_tokens=2, output_tokens=2)
        if usage_ceiling is None
        else usage_ceiling
    )
    reservation = await guard.reserve(
        BudgetReservationRequest(
            household_id=household_id,
            turn_id=turn_id,
            request_id=request_id,
            attempt_id=attempt_id,
            provider="openai",
            model="gpt-5.6-sol",
            category="llm",
            usage_ceiling=usage,
            month_key=singapore_month_key(clock.now()),
        )
    )
    if reservation.outcome not in {"allow", "allow_soft_warning"}:
        raise RuntimeError("production gateway fixture reservation denied")
    request = RouteAuthorizationRequest(
        request_id=request_id,
        attempt_id=attempt_id,
        purpose="cloud_reasoning",
        household_id=household_id,
        subject_id=subject_id,
        session_id=session_id,
        turn_id=turn_id,
        provider="openai",
        model="gpt-5.6-sol",
        request_commitment=receipt.output_commitment,
        max_input_bytes=len(body),
        max_input_units=max(units, 1),
        privacy_receipt_id=uuid4(),
        consent_receipt_ids=(uuid4(),),
        budget_reservation_id=reservation.reservation_id,
        maximum_sensitivity=Sensitivity.PERSONAL,
    )
    route = authorization_from_request(
        request,
        authorization_id=uuid4(),
        expires_at=clock.now() + timedelta(seconds=30),
    )
    consumption = RouteConsumption(
        request_id=route.request_id,
        attempt_id=route.attempt_id,
        purpose=route.purpose,
        household_id=route.household_id,
        subject_id=route.subject_id,
        session_id=route.session_id,
        turn_id=route.turn_id,
        provider=route.provider,
        model=route.model,
        request_commitment=route.request_commitment,
        input_bytes=len(body),
        input_units=units,
        consumed_at=clock.now(),
    )
    if seed_response_scope:
        await _seed_response_scope(factory, route, clock)
    return ProviderContext(route, consumption, receipt, body), reservation, guard


class TransactionalAuditPort:
    """Test audit port whose effect commits or rolls back with the receipt."""

    def __init__(self, factory: AsyncUnitOfWorkFactory, root: bytes, key_id: str) -> None:
        self._factory, self._root, self._key_id = factory, root, key_id

    async def append(self, uow, draft):
        def append_locked(transaction):
            previous = transaction.exec_driver_sql(
                "SELECT ordinal,public_hash_hex FROM audit_receipts ORDER BY ordinal DESC LIMIT 1",
            ).fetchone()
            ordinal = 1 if previous is None else int(previous[0]) + 1
            previous_hash = None if previous is None else previous[1]
            body = canonical_bytes(draft)
            public_hash = hashlib.sha256(
                (b"" if previous_hash is None else previous_hash.encode("ascii")) + body
            ).hexdigest()
            signature = commit_private(
                self._root,
                self._key_id,
                "audit.test-transactional",
                canonical_mapping_bytes(
                    {
                        "ordinal": ordinal,
                        "previous_public_hash_hex": previous_hash,
                        "public_hash_hex": public_hash,
                        "draft": draft.model_dump(mode="json"),
                    }
                ),
            )
            receipt_id = uuid4()
            transaction.exec_driver_sql(
                "INSERT INTO audit_receipts"
                "(id,ordinal,previous_public_hash_hex,public_hash_hex,"
                "hmac_key_id,hmac_b64,canonical_body_json,occurred_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    str(receipt_id),
                    ordinal,
                    previous_hash,
                    public_hash,
                    signature.key_id,
                    signature.value_b64,
                    body.decode("utf-8"),
                    utc_storage(draft.occurred_at),
                ),
            )
            return AuditReceipt(
                receipt_id=receipt_id,
                ordinal=ordinal,
                public_hash_hex=public_hash,
                hmac_key_id=signature.key_id,
                hmac_b64=signature.value_b64,
                occurred_at=draft.occurred_at,
            )

        return await uow.run_sync(append_locked)

    async def count(self, action_code: str) -> int:
        async with self._factory() as uow:
            bodies = await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "SELECT canonical_body_json FROM audit_receipts",
                    )
                    .scalars()
                    .all()
                )
            )
            await uow.rollback()
        return sum(json.loads(body).get("action_code") == action_code for body in bodies)


class _RecordingProviderCallRepository(ProviderCallRepository):
    def __init__(self, *args, owner, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._owner = owner

    async def finish(self, call_id, outcome, route, receipt=None) -> None:
        await super().finish(call_id, outcome, route, receipt)
        self._owner.provider_terminal_count += 1
        if receipt is not None:
            self._owner._receipts[receipt.receipt_id] = receipt
            self._owner.receipt_commitment = receipt.receipt_commitment
            self._owner.usage_receipt_count += 1
            self._owner.events.append("usage_receipt_committed")


class ProductionProviderGatewayCase:
    def __init__(
        self,
        *,
        factory: AsyncUnitOfWorkFactory,
        clock: FakeClock,
        catalog: PriceCatalog,
        provider_reviews,
        evidence,
        context: ProviderContext,
        reservation,
        guard: BudgetGuard,
        valid_usage: bool,
        reported_usage,
        provider_response_identifier,
        hard_limit: int,
        soft_limit: int,
    ) -> None:
        self.factory, self.clock, self.catalog = factory, clock, catalog
        self.provider_reviews, self.evidence = provider_reviews, evidence
        self.context = context
        self.route, self.consumption = context.route, context.consumption
        assert context.receipt is not None
        self.redaction_receipt_id = context.receipt.receipt_id
        self.budget_guard = guard
        self.settlement_request = BudgetSettlementRequest(
            reservation_id=self.route.budget_reservation_id,
            attempt_id=self.route.attempt_id,
        )
        self.exact_snapshot_price = reservation.amount_micros_sgd
        self.valid_usage = valid_usage
        self.reported_usage = reported_usage
        self.provider_response_identifier = provider_response_identifier
        self.hard_limit, self.soft_limit = hard_limit, soft_limit
        self.call_id = None
        self.events: list[str] = []
        self._receipts: dict[UUID, ProviderUsageReceiptV1] = {}
        self.provider_terminal_count = 0
        self.usage_receipt_count = 0
        self.cloud_egress_frozen = False
        self.freeze_receipt = None
        self.receipt_commitment = None
        self.redaction_receipt_repository = RedactionReceiptRepository(factory, clock)
        self.provider_call_repository = _RecordingProviderCallRepository(
            factory,
            clock,
            self.redaction_receipt_repository,
            evidence,
            owner=self,
        )
        self.gateway = ProviderGateway(
            BoundAuthorizerFake(context),
            guard,
            self.provider_call_repository,
            evidence,
            clock,
        )

    async def invoke(self):
        async def invoke_network():
            self.events.append("network_invoked")
            return "ok"

        async def observe(_result):
            usage = self.reported_usage
            if usage is None and self.valid_usage:
                usage = LlmUsageUnits(category="llm", input_tokens=2, output_tokens=2)
            return ProviderUsageObservation(usage, self.provider_response_identifier)

        result = await self.gateway.send(
            self.route,
            self.consumption,
            self.redaction_receipt_id,
            invoke_network,
            observe,
        )
        self.events.append("gateway_result_returned")
        return result

    async def begin_claim(self):
        if self.call_id is None:
            self.call_id = await self.provider_call_repository.begin(
                self.route,
                self.consumption,
                self.redaction_receipt_id,
            )
        return self.call_id

    async def mark_sent(self) -> None:
        await self.begin_claim()
        await self.budget_guard.mark_sent(
            self.route.budget_reservation_id,
            self.route.attempt_id,
        )

    async def mark_network_invocation_starting(self) -> None:
        await self.mark_sent()
        await self.provider_call_repository.mark_network_invocation_starting(self.call_id)

    async def finish(self, outcome, receipt=None) -> None:
        if self.call_id is None:
            raise AssertionError("provider call must be claimed before finish")
        await self.provider_call_repository.finish(self.call_id, outcome, self.route, receipt)

    async def expire(self) -> None:
        self.clock.advance(timedelta(seconds=901))

    async def reconcile_expired(self) -> int:
        return await ExpiredBudgetReconciler(
            self.factory,
            self.clock,
            self.budget_guard,
        ).reconcile_batch()

    async def reconcile_restart(self, cutoff=None) -> int:
        return await ExpiredBudgetReconciler(
            self.factory,
            self.clock,
            self.budget_guard,
        ).reconcile_restart_batch(cutoff or self.clock.now())

    async def reservation_row(self):
        async with self.factory() as uow:

            def load(transaction):
                return dict(
                    transaction.exec_driver_sql(
                        "SELECT * FROM budget_reservations WHERE id=?",
                        (str(self.route.budget_reservation_id),),
                    )
                    .mappings()
                    .one()
                )

            row = await uow.run_sync(load)
            await uow.rollback()
        return SimpleNamespace(**row)

    async def ledger_row(self):
        async with self.factory() as uow:

            def load(transaction):
                row = (
                    transaction.exec_driver_sql(
                        "SELECT * FROM cost_ledger WHERE reservation_id=?",
                        (str(self.route.budget_reservation_id),),
                    )
                    .mappings()
                    .one_or_none()
                )
                return None if row is None else dict(row)

            row = await uow.run_sync(load)
            await uow.rollback()
        return None if row is None else SimpleNamespace(**row)

    async def ledger_count(self) -> int:
        return (await self.proof_rows())[2]

    async def owner_alert_count(self) -> int:
        async with self.factory() as uow:
            count = await uow.run_sync(
                lambda transaction: transaction.exec_driver_sql(
                    "SELECT count(*) FROM runtime_settings WHERE key LIKE 'budget.owner_alert.%'",
                ).scalar_one()
            )
            await uow.rollback()
        return int(count)

    async def budget_marker_counts(self) -> tuple[int, int]:
        async with self.factory() as uow:

            def load(transaction) -> tuple[int, int]:
                freezes = transaction.exec_driver_sql(
                    "SELECT count(*) FROM runtime_settings "
                    "WHERE key LIKE 'budget.cloud_egress_freeze.%'",
                ).scalar_one()
                alerts = transaction.exec_driver_sql(
                    "SELECT count(*) FROM runtime_settings WHERE key LIKE 'budget.owner_alert.%'",
                ).scalar_one()
                return int(freezes), int(alerts)

            counts = await uow.run_sync(load)
            await uow.rollback()
        return counts

    async def tamper_pricing_source_digest(self) -> None:
        async with self.factory() as uow:
            await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE budget_reservations SET price_source_sha256=? WHERE id=?",
                        ("f" * 64, str(self.route.budget_reservation_id)),
                    ).rowcount
                )
            )
            await uow.commit()

    async def tamper_pricing_evidence(self, fault) -> None:
        column, value = {
            "snapshot": ("price_snapshot_json", "{}"),
            "hmac": ("pricing_commitment_hmac_b64", _other_commitment("pricing-hmac").value_b64),
            "policy": ("pricing_version", "openai-substituted"),
        }[fault]
        async with self.factory() as uow:
            await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        f"UPDATE budget_reservations SET {column}=? WHERE id=?",
                        (value, str(self.route.budget_reservation_id)),
                    ).rowcount
                )
            )
            await uow.commit()

    async def tamper_transport_phase_mismatch(self) -> None:
        await self.begin_claim()
        async with self.factory() as uow:
            await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE provider_calls SET transport_phase='marked_sent' WHERE id=?",
                        (str(self.call_id),),
                    ).rowcount
                )
            )
            await uow.commit()

    async def install_ledger_ignore_trigger(self) -> str:
        name = f"test_budget_ledger_ignore_{self.route.attempt_id.hex}"
        async with self.factory() as uow:
            await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        f"CREATE TRIGGER {name} BEFORE INSERT ON cost_ledger "
                        "BEGIN SELECT RAISE(IGNORE); END",
                    ).rowcount
                )
            )
            await uow.commit()
        return name

    async def install_budget_marker_ignore_trigger(
        self,
        marker: Literal["freeze", "owner_alert"],
    ) -> str:
        reservation = await self.reservation_row()
        key = (
            f"budget.cloud_egress_freeze.{reservation.month_key}"
            if marker == "freeze"
            else f"budget.owner_alert.{reservation.month_key}.{self.route.budget_reservation_id}"
        )
        name = f"test_budget_{marker}_ignore_{self.route.attempt_id.hex}"
        async with self.factory() as uow:

            def install_trigger(transaction) -> None:
                transaction.exec_driver_sql(
                    f"CREATE TRIGGER {name} BEFORE INSERT ON runtime_settings "
                    f"WHEN NEW.key='{key}' "
                    "BEGIN SELECT RAISE(IGNORE); END",
                )

            await uow.run_sync(install_trigger)
            await uow.commit()
        return name

    async def drop_trigger(self, name) -> None:
        async with self.factory() as uow:
            await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(f"DROP TRIGGER IF EXISTS {name}").rowcount
                )
            )
            await uow.commit()

    async def drop_live_catalog_after_reserve(self) -> None:
        self.budget_guard = await self.restart_budget_guard(PriceCatalog(prices=(), fx=None))

    async def provider_call_row(self):
        async with self.factory() as uow:

            def load(transaction):
                return dict(
                    transaction.exec_driver_sql(
                        "SELECT * FROM provider_calls WHERE attempt_id=?",
                        (str(self.route.attempt_id),),
                    )
                    .mappings()
                    .one()
                )

            row = await uow.run_sync(load)
            await uow.rollback()
        return SimpleNamespace(**row)

    def receipt(self, receipt_id):
        return self._receipts[receipt_id]

    async def restart_budget_guard(self, catalog=None):
        return BudgetGuard(
            self.factory,
            self.clock,
            self.catalog if catalog is None else catalog,
            self.provider_reviews,
            self.evidence,
            hard_limit=self.hard_limit,
            soft_limit=self.soft_limit,
        )

    async def settle(self):
        try:
            return await self.budget_guard.settle(self.settlement_request)
        finally:
            await self._refresh_freeze()

    async def proof_rows(self):
        async with self.factory() as uow:

            def load(transaction):
                reservation = transaction.exec_driver_sql(
                    "SELECT state,transport_phase,charged_micros_sgd "
                    "FROM budget_reservations WHERE id=?",
                    (str(self.route.budget_reservation_id),),
                ).fetchone()
                call = transaction.exec_driver_sql(
                    "SELECT outcome,transport_phase,finished_at IS NOT NULL FROM provider_calls "
                    "WHERE attempt_id=?",
                    (str(self.route.attempt_id),),
                ).fetchone()
                ledger_count = transaction.exec_driver_sql(
                    "SELECT count(*) FROM cost_ledger WHERE reservation_id=?",
                    (str(self.route.budget_reservation_id),),
                ).scalar_one()
                return (
                    None if reservation is None else tuple(reservation),
                    None if call is None else tuple(call),
                    int(ledger_count),
                )

            reservation, call, ledger_count = await uow.run_sync(load)
            await uow.rollback()
        return reservation, call, ledger_count

    async def tamper_receipt(self, fault) -> None:
        row = await self.provider_call_row()
        receipt = ProviderUsageReceiptV1.model_validate_json(row.provider_usage_json)
        raw = row.provider_usage_json
        key = row.provider_usage_receipt_key_id
        mac = row.provider_usage_receipt_hmac_b64
        if fault == "receipt_json":
            raw = '{"schema_version":"tuntun.provider-usage-receipt.v1"}'
        elif fault == "outer_key":
            key = "budget-evidence-other"
        elif fault == "outer_hmac":
            mac = _other_commitment("outer-hmac").value_b64
        else:
            updates = {
                "attempt": {"attempt_id": uuid4()},
                "provider": {"provider": "qwen"},
                "model": {"model": "other-model"},
            }[fault]
            raw = self.evidence.canonical_receipt(receipt.model_copy(update=updates))
        async with self.factory() as uow:
            await uow.run_sync(
                lambda transaction: (
                    transaction.exec_driver_sql(
                        "UPDATE provider_calls SET provider_usage_json=?,"
                        "provider_usage_receipt_key_id=?,provider_usage_receipt_hmac_b64=? "
                        "WHERE attempt_id=?",
                        (raw, key, mac, str(self.route.attempt_id)),
                    ).rowcount
                )
            )
            await uow.commit()

    async def _refresh_freeze(self) -> None:
        async with self.factory() as uow:
            value = await uow.run_sync(
                lambda transaction: transaction.exec_driver_sql(
                    "SELECT value_json FROM runtime_settings "
                    "WHERE key LIKE 'budget.cloud_egress_freeze.%'",
                ).scalar_one_or_none()
            )
            await uow.rollback()
        if value is not None:
            self.cloud_egress_frozen = True
            self.freeze_receipt = SimpleNamespace(**json.loads(value))

    async def assert_unknown_overage_freezes_without_ledger(self) -> None:
        with pytest.raises(PermissionError, match="unknown_overage"):
            await self.settle()
        assert self.cloud_egress_frozen
        assert self.freeze_receipt.overage_known is False
        assert (await self.proof_rows())[2] == 0


class _FakeStream:
    def __init__(self) -> None:
        self._chunks = iter((b"hello", b""))

    def __aiter__(self):
        return self

    async def __anext__(self):
        chunk = next(self._chunks, None)
        if chunk is None:
            raise StopAsyncIteration
        return chunk


class ProductionStreamGatewayCase:
    def __init__(self, base: ProductionProviderGatewayCase) -> None:
        self._base = base
        self.gateway = base.gateway
        self.route = base.route
        self.consumption = base.consumption
        self.redaction_receipt_id = base.redaction_receipt_id
        self.events = base.events
        self.ledger_rows_for_attempt = 0

    @property
    def provider_terminal_count(self):
        return self._base.provider_terminal_count

    @property
    def usage_receipt_count(self):
        return self._base.usage_receipt_count

    @asynccontextmanager
    async def open_response(self):
        yield _FakeStream()

    async def observe(self, _response):
        return ProviderUsageObservation(
            LlmUsageUnits(category="llm", input_tokens=2, output_tokens=2),
            "stream_resp_1",
        )

    async def consume_to_eof(self, response) -> None:
        async for _chunk in response:
            pass

    async def restart_and_reconcile(self) -> None:
        await self._base.settle()
        self.ledger_rows_for_attempt = (await self._base.proof_rows())[2]


class _ProductionReachySafety:
    def __init__(self) -> None:
        self.calls = []

    async def stop_all(self, turn_id):
        self.calls.append(turn_id)
        if turn_id is not None:
            raise AssertionError("global startup safety requires turn_id=None")
        return SafetyReceipt(
            turn_id=None,
            playback_stopped=True,
            motion_stopped=True,
            buffers_cleared=True,
        )


class _ProductionContainerCase:
    def __init__(self, container, context, reachy) -> None:
        self.container = container
        self.context = context
        self.reachy = reachy

    def __getattr__(self, name):
        return getattr(self.container, name)


class ProviderEgressHarness:
    def __init__(
        self,
        factory: AsyncUnitOfWorkFactory,
        clock: FakeClock,
        context: ProviderContext,
        catalog: PriceCatalog,
        provider_reviews,
        budget_evidence,
    ) -> None:
        self.factory = factory
        self.clock = clock
        self.catalog = catalog
        self.provider_reviews = provider_reviews
        self.budget_evidence = budget_evidence
        self.route = context.route
        self.consumption = context.consumption
        assert context.receipt is not None
        self.finalized_redaction_receipt = context.receipt
        self.redaction_receipt_repository = RedactionReceiptRepository(factory, clock)
        self.provider_call_repository = ProviderCallRepository(
            factory,
            clock,
            self.redaction_receipt_repository,
        )
        self.budget_port_fake = SqlBudgetPortFake(factory, clock)

    @classmethod
    async def create(
        cls,
        route_database: RouteDatabase,
        factory: AsyncUnitOfWorkFactory,
        clock: FakeClock,
        catalog: PriceCatalog,
        provider_reviews,
        budget_evidence,
    ) -> ProviderEgressHarness:
        del route_database
        repository = RedactionReceiptRepository(factory, clock)
        context = await _create_context(
            factory,
            repository,
            clock,
            "cloud_reasoning",
        )
        return cls(factory, clock, context, catalog, provider_reviews, budget_evidence)

    async def aclose(self) -> None:
        # Per-case triggers are dropped in `finally`; DB/UOW ownership remains
        # with provider_routes fixtures.
        return None

    def gateway_case(self, *, mark_sent_error: BaseException | None = None) -> GatewayCase:
        context = ProviderContext(
            self.route, self.consumption, self.finalized_redaction_receipt, b"{}"
        )
        return GatewayCase(context, mark_sent_error, self.clock)

    def provider_call_binding_case(
        self,
        *,
        purpose: str,
        receipt_mutation: str,
    ) -> ProviderCallBindingCase:
        return ProviderCallBindingCase(self, purpose, receipt_mutation)

    def call_repository_fault_case(self, fault: str | None) -> CallRepositoryFaultCase:
        return CallRepositoryFaultCase(self, fault)

    def provider_boundary_case(self, **values) -> ProviderBoundaryCase:
        return ProviderBoundaryCase(self, **values)


@pytest.fixture
def async_uow_factory(route_uow_factory):
    return route_uow_factory


@pytest.fixture
def clock(route_clock):
    return route_clock


@pytest_asyncio.fixture
async def provider_egress_harness(
    route_database: RouteDatabase,
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
) -> AsyncIterator[ProviderEgressHarness]:
    harness = await ProviderEgressHarness.create(
        route_database,
        async_uow_factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
    )
    try:
        yield harness
    finally:
        await harness.aclose()


@pytest.fixture
def finalized_redaction_receipt(provider_egress_harness):
    return provider_egress_harness.finalized_redaction_receipt


@pytest.fixture
def redaction_receipt_repository(provider_egress_harness):
    return provider_egress_harness.redaction_receipt_repository


@pytest.fixture
def route(provider_egress_harness):
    return provider_egress_harness.route


@pytest.fixture
def consumption(provider_egress_harness):
    return provider_egress_harness.consumption


@pytest.fixture
def redaction_receipt_id(provider_egress_harness):
    return provider_egress_harness.finalized_redaction_receipt.receipt_id


@pytest.fixture
def gateway_case(provider_egress_harness) -> Callable[..., GatewayCase]:
    return provider_egress_harness.gateway_case


@pytest.fixture
def provider_call_binding_case(provider_egress_harness):
    return provider_egress_harness.provider_call_binding_case


@pytest.fixture
def call_repository_fault_case(provider_egress_harness):
    return provider_egress_harness.call_repository_fault_case


@pytest.fixture
def core_container(provider_egress_harness):
    raise RuntimeError("core_container fixture was replaced by production_core_container")


@pytest.fixture
def budget_port_fake(provider_egress_harness):
    return provider_egress_harness.budget_port_fake


@pytest.fixture
def provider_boundary_case(provider_egress_harness):
    return provider_egress_harness.provider_boundary_case


@pytest.fixture
def provider_gateway(provider_egress_harness):
    raise RuntimeError(
        "provider_gateway fixture was replaced by production_core_container.provider_gateway"
    )


@pytest_asyncio.fixture
async def production_core_container(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
):
    context, _reservation, _guard = await _create_production_context(
        async_uow_factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
        seed_response_scope=False,
    )
    return CoreContainer(
        sqlcipher_uow_factory=async_uow_factory,
        clock=clock,
        route_authorizer=BoundAuthorizerFake(context),
        price_catalog=catalog,
        provider_reviews=provider_reviews,
        budget_evidence=budget_evidence,
    )


@pytest_asyncio.fixture
async def production_container(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    runtime_provider_identities,
    budget_evidence,
    tmp_path,
):
    from tuntun_core.bootstrap.container import ProductionContainer

    context, _reservation, _guard = await _create_production_context(
        async_uow_factory,
        clock,
        catalog,
        provider_reviews,
        budget_evidence,
        seed_response_scope=True,
    )
    state_root = tmp_path / "production-state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    reachy = _ProductionReachySafety()
    container = ProductionContainer.build(
        configured_state_root=state_root,
        reachy=reachy,
        sqlcipher_uow_factory=async_uow_factory,
        clock=clock,
        route_authorizer=BoundAuthorizerFake(context),
        price_catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
    )
    try:
        yield _ProductionContainerCase(container, context, reachy)
    finally:
        container.core_process_lease.release_after_shutdown()


@pytest.fixture
def production_provider_gateway_case(
    async_uow_factory,
    clock,
    catalog,
    provider_reviews,
    budget_evidence,
):
    async def create(
        *,
        valid_usage: bool = True,
        reported_usage=None,
        provider_response_identifier="resp_1",
        seed_response_scope: bool = False,
        usage_ceiling=None,
        hard_limit: int = 150_000_000,
        soft_limit: int = 100_000_000,
    ):
        context, reservation, guard = await _create_production_context(
            async_uow_factory,
            clock,
            catalog,
            provider_reviews,
            budget_evidence,
            seed_response_scope=seed_response_scope,
            usage_ceiling=usage_ceiling,
            hard_limit=hard_limit,
            soft_limit=soft_limit,
        )
        return ProductionProviderGatewayCase(
            factory=async_uow_factory,
            clock=clock,
            catalog=catalog,
            provider_reviews=provider_reviews,
            evidence=budget_evidence,
            context=context,
            reservation=reservation,
            guard=guard,
            valid_usage=valid_usage,
            reported_usage=reported_usage,
            provider_response_identifier=provider_response_identifier,
            hard_limit=hard_limit,
            soft_limit=soft_limit,
        )

    return create


@pytest.fixture
def production_stream_gateway_case(production_provider_gateway_case):
    async def create():
        return ProductionStreamGatewayCase(
            await production_provider_gateway_case(valid_usage=True),
        )

    return create
