# tests/fixtures/provider_egress.py
from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from tuntun_contracts.base import Commitment, Sensitivity, canonical_mapping_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.provider import (
    RedactionReceipt,
    RouteAuthorization,
    RouteAuthorizationRequest,
    RouteConsumption,
)
from tuntun_core.bootstrap.container import CoreContainer
from tuntun_core.services.providers.call_repository import ProviderCallRepository
from tuntun_core.services.providers.gateway import ProviderGateway
from tuntun_core.services.providers.reasoning_wire import (
    build_openai_reasoning_wire_request,
)
from tuntun_core.services.providers.redaction_repository import (
    AsyncUnitOfWorkFactory,
    RedactionReceiptRepository,
)
from tuntun_core.services.providers.redactor import Redactor
from tuntun_core.services.providers.route_verifier import authorization_from_request
from tuntun_testing.fake_clock import FakeClock

from tests.fixtures.provider_routes import RouteDatabase

pytest_plugins = ("tests.fixtures.provider_routes",)

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


def _utc_storage(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError("stored timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


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
        _utc_storage(now),
        _utc_storage(now + timedelta(minutes=5)),
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
        now = _utc_storage(self._clock.now())

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
    def __init__(self, context: ProviderContext, mark_sent_error: BaseException | None) -> None:
        self.context = context
        self.mark_sent_error = mark_sent_error
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

        class Calls:
            async def begin(self, route, supplied, receipt_id):
                del route, supplied, receipt_id
                case.events.append("call_started")
                return case.context.route.attempt_id

            async def mark_network_invocation_starting(self, call_id):
                del call_id
                case.events.append("network_starting")

            async def finish(self, call_id, outcome):
                del call_id
                case.events.append(outcome)
                case.finish_calls.append(outcome)

        async def invoke() -> str:
            case.events.append("network")
            return "ok"

        gateway = ProviderGateway(Authorizer(), Budget(), Calls())  # type: ignore[arg-type]
        return await gateway.send(
            self.context.route,
            self.context.consumption,
            self.context.receipt.receipt_id if self.context.receipt else None,
            invoke,
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
        name = (
            await self._trigger(self._fault)
            if self._fault in {"after_call_finish", "reservation_finish_cas_lost"}
            else None
        )
        try:
            await self._harness.provider_call_repository.finish(call_id, outcome)
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
        await self._harness.redaction_receipt_repository.record(receipt)
        context = await _create_context(
            self._harness.factory,
            self._harness.redaction_receipt_repository,
            self._harness.clock,
            "cloud_reasoning",
            receipt=receipt,
            canonical_body=body,
            input_units=units,
            persist_receipt=False,
            request_id=self.request_id,
        )
        calls = ProviderCallRepository(
            self._harness.factory,
            self._harness.clock,
            self._harness.redaction_receipt_repository,
        )
        gateway = ProviderGateway(
            BoundAuthorizerFake(context),
            SqlBudgetPortFake(self._harness.factory, self._harness.clock),
            calls,
        )

        async def capture() -> str:
            self.network_calls += 1
            self.captured_provider_body = body
            return "ok"

        await gateway.send(context.route, context.consumption, receipt.receipt_id, capture)

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


class ProviderEgressHarness:
    def __init__(
        self,
        factory: AsyncUnitOfWorkFactory,
        clock: FakeClock,
        context: ProviderContext,
    ) -> None:
        self.factory = factory
        self.clock = clock
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
        self.core_container = CoreContainer(
            sqlcipher_uow_factory=factory,
            clock=clock,
            route_authorizer=BoundAuthorizerFake(context),
        )
        self.provider_gateway = self.core_container.build_provider_gateway(self.budget_port_fake)

    @classmethod
    async def create(
        cls,
        route_database: RouteDatabase,
        factory: AsyncUnitOfWorkFactory,
        clock: FakeClock,
    ) -> ProviderEgressHarness:
        del route_database
        repository = RedactionReceiptRepository(factory, clock)
        context = await _create_context(
            factory,
            repository,
            clock,
            "cloud_reasoning",
        )
        return cls(factory, clock, context)

    async def aclose(self) -> None:
        # Per-case triggers are dropped in `finally`; DB/UOW ownership remains
        # with provider_routes fixtures.
        return None

    def gateway_case(self, *, mark_sent_error: BaseException | None = None) -> GatewayCase:
        context = ProviderContext(
            self.route, self.consumption, self.finalized_redaction_receipt, b"{}"
        )
        return GatewayCase(context, mark_sent_error)

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
) -> AsyncIterator[ProviderEgressHarness]:
    harness = await ProviderEgressHarness.create(
        route_database,
        async_uow_factory,
        clock,
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
    return provider_egress_harness.core_container


@pytest.fixture
def budget_port_fake(provider_egress_harness):
    return provider_egress_harness.budget_port_fake


@pytest.fixture
def provider_boundary_case(provider_egress_harness):
    return provider_egress_harness.provider_boundary_case


@pytest.fixture
def provider_gateway(provider_egress_harness):
    return provider_egress_harness.provider_gateway
