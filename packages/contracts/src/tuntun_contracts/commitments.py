import base64
import hmac
from hashlib import sha256

from tuntun_contracts.base import Commitment


def derive_purpose_key(root_key: bytes, purpose: str) -> bytes:
    if type(root_key) is not bytes or len(root_key) != 32:
        raise ValueError("commitment root must be 32 bytes")
    if type(purpose) is not str:
        raise TypeError("commitment purpose must be a string")
    try:
        purpose_bytes = purpose.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("commitment purpose must be ASCII") from error
    if not 1 <= len(purpose_bytes) <= 128:
        raise ValueError("commitment purpose length outside bounds")
    # RFC 5869 HKDF-Extract and one-block HKDF-Expand for SHA-256/L=32.
    prk = hmac.new(b"TUNTUN-HMAC-KDF-V1", root_key, sha256).digest()
    info = b"purpose\x00" + len(purpose_bytes).to_bytes(2, "big") + purpose_bytes
    return hmac.new(prk, info + b"\x01", sha256).digest()


def commit_private(
    root_key: bytes,
    key_id: str,
    purpose: str,
    canonical_body: bytes,
) -> Commitment:
    if type(canonical_body) is not bytes:
        raise TypeError("canonical body must be bytes")
    purpose_key = derive_purpose_key(root_key, purpose)
    purpose_bytes = purpose.encode("ascii")
    framed = (
        b"TUNTUN-HMAC-V1\x00"
        + len(purpose_bytes).to_bytes(2, "big")
        + purpose_bytes
        + len(canonical_body).to_bytes(8, "big")
        + canonical_body
    )
    digest = hmac.new(purpose_key, framed, sha256).digest()
    return Commitment(
        algorithm="HMAC-SHA-256",
        key_id=key_id,
        value_b64=base64.b64encode(digest).decode("ascii"),
    )
