# tests/security/test_provider_boundary.py
import pytest

pytest_plugins = ("tests.fixtures.provider_egress",)


@pytest.mark.asyncio
async def test_private_contact_never_reaches_capture_receipts_calls_logs_or_errors(
    provider_boundary_case, caplog
) -> None:
    sentinel = "family-secret-sentinel@example.test"
    case = provider_boundary_case(user_text=f"Please contact {sentinel}")
    await case.run_reasoning()
    assert sentinel not in case.captured_provider_body.decode("utf-8")
    assert "[CONTACT]" in case.captured_provider_body.decode("utf-8")
    assert sentinel not in await case.serialized_receipt_and_call_rows()
    assert sentinel not in caplog.text


@pytest.mark.asyncio
async def test_prohibited_secret_or_second_pass_failure_creates_zero_egress_proof(
    provider_boundary_case,
) -> None:
    for mutation in (
        "secret_in_input",
        "secret_in_canonical_body",
        "email_in_canonical_body",
        "phone_in_canonical_body",
        "session_label_in_canonical_body",
    ):
        case = provider_boundary_case(mutation=mutation)
        with pytest.raises(ValueError, match="PROHIBITED_SECRET|SECOND_PASS_REJECTED"):
            await case.run_reasoning()
        assert case.network_calls == 0
        assert await case.redaction_receipt_count() == 0
        assert await case.provider_call_count() == 0


def test_search_categories_are_not_registered_in_task04(provider_gateway) -> None:
    assert provider_gateway.supported_purposes == frozenset(
        {"cloud_stt", "cloud_reasoning", "cloud_tts"}
    )
