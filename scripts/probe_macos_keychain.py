from __future__ import annotations

import argparse
import hmac
import os
import secrets
import sys
from collections.abc import Sequence
from uuid import uuid4

from tuntun_core.adapters.keychain.macos import MacOSKeychainSecretProvider
from tuntun_core.adapters.keychain.provider import SecretProvider

PROBE_ENVIRONMENT_ACK = "TUNTUN_ALLOW_KEYCHAIN_PROBE"
PROBE_SERVICE = "tuntun.probe.keychain"


def probe_keychain_round_trip(
    provider: SecretProvider,
    service: str,
    account: str,
    value: bytes,
) -> None:
    if provider.exists(service, account):
        raise RuntimeError("Keychain probe slot already exists")
    try:
        provider.set(service, account, value)
        if not hmac.compare_digest(provider.get(service, account), value):
            raise RuntimeError("Keychain probe readback mismatch")
    finally:
        provider.delete(service, account)
    if provider.exists(service, account):
        raise RuntimeError("Keychain probe cleanup failed")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--acknowledge-keychain-write", action="store_true")
    arguments = parser.parse_args(argv)
    if not arguments.acknowledge_keychain_write or os.environ.get(PROBE_ENVIRONMENT_ACK) != "1":
        raise RuntimeError("Keychain probe requires explicit dual acknowledgement")
    try:
        account = f"round-trip-{uuid4()}"
        value = secrets.token_bytes(32)
        probe_keychain_round_trip(
            MacOSKeychainSecretProvider(),
            PROBE_SERVICE,
            account,
            value,
        )
    except Exception:
        print("macOS Keychain probe: FAIL", file=sys.stderr)
        return 1
    print("macOS Keychain probe: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
