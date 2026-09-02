from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from tuntun_contracts.budget import LlmUsageUnits
from tuntun_core.services.providers.gateway import (
    ProviderGateway,
    ProviderNotSentError,
    ProviderUsageObservation,
    ProviderUsageUnknownError,
)

pytest_plugins = ("tests.fixtures.provider_egress",)


@pytest.mark.asyncio
async def test_receipt_commit_precedes_final_gateway_result(
    route, consumption, redaction_receipt_id, clock
) -> None:
    events = []

    class Authorizer:
        async def consume(self, _authorization_id, _supplied) -> None:
            events.append("consume")

    class Budget:
        async def mark_sent(self, _reservation_id, _attempt_id) -> None:
            events.append("mark_sent")

        async def require_accounting_context(self, _route, _consumption):
            events.append("accounting")
            return SimpleNamespace(
                category="llm",
                usage_ceiling=LlmUsageUnits(category="llm", input_tokens=2, output_tokens=2),
                primary_accounting_basis="provider_reported_exact",
                missing_evidence_policy="freeze_unknown_overage",
            )

    class Calls:
        async def begin(self, _route, _supplied, _receipt_id):
            events.append("claim")
            return uuid4()

        async def mark_network_invocation_starting(self, _call_id) -> None:
            events.append("network_starting")

        async def finish(self, _call_id, outcome, _route, receipt) -> None:
            events.append((outcome, None if receipt is None else "receipt"))

    class Evidence:
        def attest_provider_usage(self, **_values):
            events.append("attest")
            return SimpleNamespace(receipt_id=uuid4())

    async def network() -> str:
        events.append("network")
        return "ok"

    async def observe(_result):
        events.append("observe")
        return ProviderUsageObservation(
            LlmUsageUnits(category="llm", input_tokens=1, output_tokens=1),
            "resp_1",
        )

    result = await ProviderGateway(
        Authorizer(),
        Budget(),
        Calls(),
        Evidence(),
        clock,
    ).send(route, consumption, redaction_receipt_id, network, observe)
    events.append("returned")
    assert result.value == "ok" and result.provider_usage_receipt_id is not None
    assert events == [
        "consume",
        "claim",
        "mark_sent",
        "accounting",
        "network_starting",
        "network",
        "observe",
        "attest",
        ("succeeded", "receipt"),
        "returned",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt_present", (False, True))
async def test_commit_then_cancel_retries_only_the_exact_success_terminalization(
    route,
    consumption,
    redaction_receipt_id,
    clock,
    receipt_present,
) -> None:
    class Authorizer:
        async def consume(self, *_args) -> None:
            return None

    class Budget:
        async def mark_sent(self, *_args) -> None:
            return None

        async def require_accounting_context(self, *_args):
            return SimpleNamespace(
                category="llm",
                usage_ceiling=LlmUsageUnits(category="llm", input_tokens=2, output_tokens=2),
                primary_accounting_basis="provider_reported_exact",
                missing_evidence_policy="freeze_unknown_overage",
            )

    class Calls:
        def __init__(self) -> None:
            self.finishes = []

        async def begin(self, *_args):
            return uuid4()

        async def mark_network_invocation_starting(self, *_args) -> None:
            return None

        async def finish(self, _call_id, outcome, _route, receipt) -> None:
            self.finishes.append((outcome, receipt is not None))
            if len(self.finishes) == 1:
                raise asyncio.CancelledError
            assert self.finishes[-1] == self.finishes[0]

    class Evidence:
        def attest_provider_usage(self, **_values):
            return SimpleNamespace(receipt_id=uuid4())

    calls = Calls()
    gateway = ProviderGateway(Authorizer(), Budget(), calls, Evidence(), clock)

    async def network() -> str:
        return "ok"

    async def observe(_result):
        return ProviderUsageObservation(
            (
                LlmUsageUnits(category="llm", input_tokens=1, output_tokens=1)
                if receipt_present
                else None
            ),
            "resp_1",
        )

    with pytest.raises(asyncio.CancelledError):
        await gateway.send(route, consumption, redaction_receipt_id, network, observe)
    assert calls.finishes == [
        ("succeeded", receipt_present),
        ("succeeded", receipt_present),
    ]


@pytest.mark.asyncio
async def test_task05_preserves_typed_pre_network_mark_sent_failure(
    route,
    consumption,
    redaction_receipt_id,
    clock,
) -> None:
    events = []

    class Authorizer:
        async def consume(self, *_args) -> None:
            events.append("consume")

    class Budget:
        async def mark_sent(self, *_args) -> None:
            events.append("mark_sent")
            raise RuntimeError("synthetic mark_sent failure")

    class Calls:
        async def begin(self, *_args):
            events.append("claim")
            return uuid4()

        async def finish(self, *_args) -> None:
            events.append("finish")

    class Evidence:
        pass

    gateway = ProviderGateway(Authorizer(), Budget(), Calls(), Evidence(), clock)

    async def network() -> str:
        events.append("network")
        return "unreachable"

    async def observe(_result):
        raise AssertionError("unreachable")

    with pytest.raises(ProviderNotSentError) as caught:
        await gateway.send(route, consumption, redaction_receipt_id, network, observe)
    assert isinstance(caught.value.cause, RuntimeError)
    assert events == ["consume", "claim", "mark_sent"]


@pytest.mark.asyncio
async def test_stream_lease_finalize_is_the_terminal_output_barrier(
    production_stream_gateway_case,
) -> None:
    case = await production_stream_gateway_case()
    async with case.gateway.open_stream(
        case.route,
        case.consumption,
        case.redaction_receipt_id,
        case.open_response,
        case.observe,
    ) as lease:
        await case.consume_to_eof(lease.response)
        await lease.finalize()
        case.events.append("terminal_output_exposed")
        assert (await lease.finalize()) == lease.provider_usage_receipt_id
    assert case.events.index("usage_receipt_committed") < case.events.index(
        "terminal_output_exposed"
    )
    assert case.provider_terminal_count == case.usage_receipt_count == 1


@pytest.mark.asyncio
async def test_unfinalized_stream_closes_once_as_unknown_overage(
    production_stream_gateway_case,
) -> None:
    case = await production_stream_gateway_case()
    with pytest.raises(ProviderUsageUnknownError, match="closed_before_finalize"):
        async with case.gateway.open_stream(
            case.route,
            case.consumption,
            case.redaction_receipt_id,
            case.open_response,
            case.observe,
        ):
            pass
    await case.restart_and_reconcile()
    assert case.provider_terminal_count == case.ledger_rows_for_attempt == 1
    assert case.usage_receipt_count == 0
