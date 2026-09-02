from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_official_binary_stream_has_no_usage_and_settles_request_bound_exact(
    tts_accounting_case,
) -> None:
    case = await tts_accounting_case(
        text="Hello नमस्ते",
        response_headers={"x-request-id": "req_tts_1"},
        binary_chunks=(b"pcm-1", b"pcm-2"),
    )

    chunks = [chunk async for chunk in case.adapter.synthesize(case.request)]
    settlement = await case.settle()

    assert b"".join(chunk.pcm for chunk in chunks) == b"pcm-1pcm-2"
    assert chunks[-1].final and chunks[-1].pcm == b""
    assert all(not chunk.final and chunk.pcm for chunk in chunks[:-1])
    assert case.sent_body == {
        "model": "tts-1",
        "voice": "alloy",
        "input": "Hello नमस्ते",
        "response_format": "pcm",
    }
    assert case.receipt.accounting_basis == "request_bound_exact"
    assert case.receipt.billable_usage.characters == len("Hello नमस्ते")
    assert settlement.charged_micros_sgd == 23
    assert settlement.conservative_estimate_used is False
    assert case.gateway.finalized is True


@pytest.mark.asyncio
async def test_tts_character_under_reservation_denies_before_network(tts_accounting_case) -> None:
    case = await tts_accounting_case(text="नमस्ते", reserved_characters=5)

    with pytest.raises(PermissionError, match="tts_request_character_binding_mismatch"):
        _ = [chunk async for chunk in case.adapter.synthesize(case.request)]

    assert case.sent_body == {}


@pytest.mark.asyncio
async def test_tts_pcm_cap_blocks_terminal_chunk_after_finalize(tts_accounting_case) -> None:
    case = await tts_accounting_case(binary_chunks=(b"a" * 65_536, b"b" * 65_536))

    chunks = [chunk async for chunk in case.adapter.synthesize(case.request)]

    assert all(len(chunk.pcm) <= 65_536 for chunk in chunks)
    assert chunks[-1].final
    assert case.gateway.finalized
