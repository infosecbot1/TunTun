from __future__ import annotations

import httpx
from tuntun_core.adapters.openai.errors import translate_openai_error


def test_transport_error_after_gateway_claim_is_never_releasable_as_unsent() -> None:
    error = httpx.ConnectError("synthetic secret must not be serialized")

    translated = translate_openai_error(error, after_claim=True)

    assert translated.disposition == "unknown"
    assert translated.status_code == 0
    assert translated.evidence_code == "openai_transport"
    assert "secret" not in str(translated)


def test_only_preclaim_transport_failure_can_be_proven_never_sent() -> None:
    translated = translate_openai_error(httpx.ConnectError("synthetic"), after_claim=False)

    assert translated.disposition == "never_sent"
