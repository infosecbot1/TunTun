from __future__ import annotations

import pytest
from tuntun_contracts.provider import RouteAuthorization
from tuntun_contracts.speech import AuthorizedSynthesisRequest


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
async def test_tts_accepts_4096_multibyte_nfc_characters(tts_accounting_case) -> None:
    text = "ठ" * 4_096
    case = await tts_accounting_case(text=text, binary_chunks=(b"pcm",))

    chunks = [chunk async for chunk in case.adapter.synthesize(case.request)]

    assert case.sent_body["input"] == text
    assert chunks[-1].final is True
    assert case.receipt.billable_usage.characters == 4_096


@pytest.mark.asyncio
async def test_tts_rejects_4097_characters_before_network(tts_accounting_case) -> None:
    case = await tts_accounting_case(text="ठ" * 4_096)
    request = AuthorizedSynthesisRequest.model_construct(
        request_id=case.request.request_id,
        turn_id=case.request.turn_id,
        text="ठ" * 4_097,
        text_commitment=case.request.text_commitment,
        segment_index=case.request.segment_index,
        segment_count=case.request.segment_count,
        language=case.request.language,
        dlp_receipt_id=case.request.dlp_receipt_id,
        route=case.route,
    )

    with pytest.raises(ValueError, match="tts_text_must_be_bounded_nfc"):
        _ = [chunk async for chunk in case.adapter.synthesize(request)]

    assert case.sent_body == {}


@pytest.mark.asyncio
async def test_tts_rejects_non_tts_1_model_before_gateway(tts_accounting_case) -> None:
    case = await tts_accounting_case()
    wrong_route = RouteAuthorization.model_validate(
        case.route.model_dump(mode="python") | {"model": "tts-1-hd"}
    )
    request = AuthorizedSynthesisRequest.model_validate(
        case.request.model_dump(mode="python") | {"route": wrong_route}
    )

    with pytest.raises(PermissionError, match="openai_tts_route_required"):
        _ = [chunk async for chunk in case.adapter.synthesize(request)]

    assert case.sent_body == {}
    assert case.gateway.finalized is False


@pytest.mark.asyncio
async def test_tts_pcm_cap_blocks_terminal_chunk_after_finalize(tts_accounting_case) -> None:
    case = await tts_accounting_case(binary_chunks=(b"a" * 65_536, b"b" * 65_536))

    chunks = [chunk async for chunk in case.adapter.synthesize(case.request)]

    assert all(len(chunk.pcm) <= 65_536 for chunk in chunks)
    assert chunks[-1].final
    assert case.gateway.finalized
