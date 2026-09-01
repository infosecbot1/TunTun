# tests/unit/providers/test_gateway_ordering.py
import asyncio

import pytest
from tuntun_core.services.providers.gateway import (
    ProviderGateway,
    ProviderNotSentCancellation,
    ProviderNotSentError,
)

pytest_plugins = ("tests.fixtures.provider_egress",)


@pytest.mark.asyncio
async def test_consume_precedes_mark_sent_and_network(
    route, consumption, redaction_receipt_id
) -> None:
    events = []

    class Authorizer:
        async def consume(self, authorization_id, supplied):
            events.append("consume")

    class Budget:
        async def mark_sent(self, reservation_id, attempt_id):
            events.append("mark_sent")

    class Calls:
        async def begin(self, route, supplied, receipt_id):
            events.append("call_started")
            return route.attempt_id

        async def mark_network_invocation_starting(self, call_id):
            events.append("network_starting")

        async def finish(self, call_id, outcome):
            events.append(outcome)

    async def network():
        events.append("network")
        return "ok"

    assert (
        await ProviderGateway(Authorizer(), Budget(), Calls()).send(
            route, consumption, redaction_receipt_id, network
        )
        == "ok"
    )
    assert events == [
        "consume",
        "call_started",
        "mark_sent",
        "network_starting",
        "network",
        "succeeded",
    ]


@pytest.mark.asyncio
async def test_mark_sent_failure_leaves_claim_open_and_never_starts_network(
    gateway_case,
) -> None:
    case = gateway_case(mark_sent_error=RuntimeError("budget failed"))
    with pytest.raises(ProviderNotSentError, match="provider_network_not_started") as caught:
        await case.send()
    assert isinstance(caught.value.cause, RuntimeError)
    assert case.events == ["consume", "call_started", "mark_sent"]
    assert case.finish_calls == []


@pytest.mark.asyncio
async def test_mark_sent_cancellation_is_classified_before_network(gateway_case) -> None:
    case = gateway_case(mark_sent_error=asyncio.CancelledError())
    with pytest.raises(ProviderNotSentCancellation):
        await case.send()
    assert case.events == ["consume", "call_started", "mark_sent"]
    assert case.finish_calls == []
