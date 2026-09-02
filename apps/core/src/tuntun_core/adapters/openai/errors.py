from __future__ import annotations

from typing import Literal

import httpx
from tuntun_core.services.providers.attempts import TransientProviderError

from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAIError


def translate_openai_error(
    error: BaseException,
    *,
    after_claim: bool,
) -> TransientProviderError:
    disposition: Literal["never_sent", "sent", "unknown"] = (
        "unknown" if after_claim else "never_sent"
    )
    if isinstance(error, APIStatusError):
        status_code = int(error.status_code)
        evidence_code = f"http_{status_code}"
        if 400 <= status_code < 500 and status_code not in {408, 409, 429}:
            disposition = "sent"
    elif isinstance(error, (httpx.TimeoutException, APITimeoutError)):
        status_code = 408
        evidence_code = "http_408"
    elif isinstance(error, (httpx.TransportError, APIConnectionError, OpenAIError)):
        status_code = 0
        evidence_code = "openai_transport"
    else:
        raise TypeError("not an OpenAI transport error")
    return TransientProviderError(status_code, disposition, evidence_code)
