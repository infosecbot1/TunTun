# tests/unit/providers/test_commitments.py
import pytest
from tuntun_contracts.commitments import commit_private


def test_commitments_are_deterministic_and_purpose_separated() -> None:
    root = bytes(range(32))
    body = b'{"value":"family"}'
    first = commit_private(root, "route-hmac-v1", "redaction.input", body)
    assert first == commit_private(root, "route-hmac-v1", "redaction.input", body)
    assert first != commit_private(root, "route-hmac-v1", "audit.payload", body)
    assert first.algorithm == "HMAC-SHA-256"
    assert first.key_id == "route-hmac-v1"
    assert len(first.value_b64) == 44


@pytest.mark.parametrize(
    ("root", "purpose", "error"),
    ((b"short", "redaction.input", "root"), (b"k" * 32, "не-ascii", "ASCII")),
)
def test_commitment_inputs_fail_closed(root, purpose, error) -> None:
    with pytest.raises((TypeError, ValueError), match=error):
        commit_private(root, "route-hmac-v1", purpose, b"{}")
