from __future__ import annotations

import httpx

from openai import AsyncOpenAI


def build_openai_client(api_key: str) -> AsyncOpenAI:
    if type(api_key) is not str or not api_key:
        raise ValueError("OpenAI API key required")
    transport = httpx.AsyncHTTPTransport(
        retries=0,
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
    )
    http_client = httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,
        event_hooks={"request": [], "response": []},
        trust_env=False,
    )
    return AsyncOpenAI(
        api_key=api_key,
        max_retries=0,
        http_client=http_client,
    )
