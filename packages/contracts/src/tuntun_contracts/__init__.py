from typing import Final

from .base import (
    JCS_MAX_SAFE_INTEGER,
    JCS_MIN_SAFE_INTEGER,
    Commitment,
    ContractModel,
    ContractParseError,
    JSONValue,
    Sensitivity,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_bounded_json_value,
    parse_contract_json,
    registered_contract_models,
)
from .events import (
    EventEnvelope,
    EventPayload,
    EventType,
    SignedEventEnvelope,
    StopRequestedPayload,
    WakeDetectedPayload,
)

__version__: str = "0.1.0.dev0"

_REGISTERED_CONTRACT_MODELS: Final[tuple[type[ContractModel], ...]] = (
    Commitment,
    EventEnvelope,
    SignedEventEnvelope,
    StopRequestedPayload,
    WakeDetectedPayload,
)

__all__ = (
    "JCS_MAX_SAFE_INTEGER",
    "JCS_MIN_SAFE_INTEGER",
    "JSONValue",
    "Commitment",
    "ContractModel",
    "ContractParseError",
    "EventEnvelope",
    "EventPayload",
    "EventType",
    "Sensitivity",
    "SignedEventEnvelope",
    "StopRequestedPayload",
    "WakeDetectedPayload",
    "__version__",
    "canonical_bytes",
    "canonical_mapping_bytes",
    "parse_bounded_json_value",
    "parse_contract_json",
    "registered_contract_models",
)
