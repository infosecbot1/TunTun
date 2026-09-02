from __future__ import annotations

from tuntun_core.adapters.openai.client import build_openai_client


def test_openai_client_disables_sdk_retries_redirects_and_hooks() -> None:
    client = build_openai_client("sk-test-synthetic")

    assert client.max_retries == 0
    assert client._client.follow_redirects is False
    assert client._client.event_hooks == {"request": [], "response": []}
    assert client._client.trust_env is False
