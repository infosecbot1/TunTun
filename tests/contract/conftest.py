# tests/contract/conftest.py
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

import pytest
from tuntun_contracts.base import Commitment


@pytest.fixture
def valid_action_fields() -> Callable[[str], dict[str, object]]:
    def build(action_name: str) -> dict[str, object]:
        return {
            "proposal_id": UUID(int=901),
            "schema_version": "1.0",
            "action_name": action_name,
            "resource_type": action_name.split(".", 1)[0],
            "resource_id": UUID(int=902),
            "parameters_commitment": Commitment(
                algorithm="HMAC-SHA-256",
                key_id="action-hmac-v1",
                value_b64="A" * 43 + "=",
            ),
            "uncertainty_micros": 0,
            "expires_at": datetime(2026, 8, 27, tzinfo=UTC),
            "idempotency_key": UUID(int=903),
        }

    return build
