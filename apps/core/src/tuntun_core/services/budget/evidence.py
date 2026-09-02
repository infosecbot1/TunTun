from __future__ import annotations

import hmac
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, cast
from uuid import UUID, uuid4

import rfc8785
from pydantic import Field, TypeAdapter, ValidationError
from tuntun_contracts.base import (
    Commitment,
    ContractModel,
    ContractParseError,
    parse_bounded_json_value,
    parse_contract_json,
)
from tuntun_contracts.budget import ProviderUsageReceiptV1, UsageUnits, usage_total
from tuntun_contracts.commitments import commit_private
from tuntun_core.services.budget.pricing import PriceQuote
from tuntun_core.services.storage_time import utc_storage

UsageAdapter: TypeAdapter[Any] = TypeAdapter(UsageUnits)
MAX_PRICING_SNAPSHOT_BYTES = 131_072
MAX_USAGE_CEILING_BYTES = 8_192


class PricingSnapshotV1(ContractModel):
    request_id: UUID
    attempt_id: UUID
    usage_ceiling: UsageUnits
    quote: dict[str, Any] = Field(min_length=1, max_length=32)


def parse_usage_units_json(raw: str) -> UsageUnits:
    if not isinstance(raw, str):
        raise ContractParseError("usage ceiling JSON invalid")
    encoded = raw.encode("utf-8", errors="strict")
    value = parse_bounded_json_value(
        encoded,
        max_bytes=MAX_USAGE_CEILING_BYTES,
        max_depth=8,
        max_containers=32,
        max_structure_tokens=128,
    )
    try:
        usage = UsageAdapter.validate_python(value, strict=True)
    except ValidationError as error:
        raise ContractParseError("usage ceiling JSON schema invalid") from error
    if rfc8785.dumps(usage.model_dump(mode="json")) != encoded:
        raise ContractParseError("usage ceiling JSON is not canonical")
    return cast(UsageUnits, usage)


class BudgetEvidenceQuarantined(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class SignedPricingSnapshot:
    canonical_json: str
    commitment: Commitment


class BudgetEvidenceService:
    def __init__(self, root_key: bytes, key_id: str, clock: Any) -> None:
        if len(root_key) != 32:
            raise ValueError("budget evidence root must be 32 bytes")
        self._root = root_key
        self._key_id = key_id
        self._clock = clock

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return rfc8785.dumps(value)

    @staticmethod
    def _valid_response_identifier(value: object) -> bool:
        if not isinstance(value, str) or value != unicodedata.normalize("NFC", value):
            return False
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeError:
            return False
        return 1 <= len(encoded) <= 256 and all(
            unicodedata.category(character) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
            for character in value
        )

    @classmethod
    def _jsonable(cls, value: Any) -> Any:
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, datetime):
            return utc_storage(value)
        if hasattr(value, "model_dump"):
            return cls._jsonable(value.model_dump(mode="python"))
        if isinstance(value, dict):
            return {key: cls._jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._jsonable(item) for item in value]
        return value

    def _commit(self, purpose: str, value: object) -> Commitment:
        return commit_private(
            self._root,
            self._key_id,
            purpose,
            self._canonical(self._jsonable(value)),
        )

    def issue_pricing_snapshot(
        self,
        request: Any,
        quote: PriceQuote,
    ) -> SignedPricingSnapshot:
        quote_value = parse_bounded_json_value(
            self._canonical(self._jsonable(asdict(quote))),
            max_bytes=MAX_PRICING_SNAPSHOT_BYTES,
            max_depth=16,
            max_containers=256,
            max_structure_tokens=2_048,
        )
        try:
            assert isinstance(quote_value, dict)
            payload = PricingSnapshotV1(
                request_id=request.request_id,
                attempt_id=request.attempt_id,
                usage_ceiling=request.usage_ceiling,
                quote=quote_value,
            )
        except (AssertionError, ValidationError) as error:
            raise BudgetEvidenceQuarantined("budget_pricing_snapshot_invalid") from error
        canonical = self._canonical(payload.model_dump(mode="json"))
        commitment = commit_private(
            self._root,
            self._key_id,
            "budget.pricing-snapshot.v1",
            canonical,
        )
        return SignedPricingSnapshot(canonical.decode("utf-8"), commitment)

    def require_pricing_snapshot(self, reservation: Any) -> PriceQuote:
        try:
            raw = reservation["price_snapshot_json"]
            if not isinstance(raw, str):
                raise ValueError("pricing snapshot missing")
            payload = parse_contract_json(
                PricingSnapshotV1,
                raw.encode("utf-8", errors="strict"),
                max_bytes=MAX_PRICING_SNAPSHOT_BYTES,
                require_canonical=True,
            )
            canonical = self._canonical(payload.model_dump(mode="json"))
            if reservation["pricing_commitment_key_id"] != self._key_id:
                raise ValueError("unaccepted pricing evidence key")
            expected = commit_private(
                self._root,
                reservation["pricing_commitment_key_id"],
                "budget.pricing-snapshot.v1",
                canonical,
            )
            if not hmac.compare_digest(
                expected.value_b64,
                reservation["pricing_commitment_hmac_b64"],
            ):
                raise ValueError("pricing HMAC mismatch")
            quote = PriceQuote.from_mapping(payload.quote)
            duplicated = (
                quote.provider,
                quote.model,
                quote.category,
                quote.primary_accounting_basis,
                quote.missing_evidence_policy,
                quote.pricing_version,
                quote.price_source_sha256,
                quote.fx_version,
                quote.fx_source_sha256,
            )
            persisted = (
                reservation["provider"],
                reservation["model"],
                reservation["category"],
                reservation["primary_accounting_basis"],
                reservation["missing_evidence_policy"],
                reservation["pricing_version"],
                reservation["price_source_sha256"],
                reservation["fx_version"],
                reservation["fx_source_sha256"],
            )
            if (
                duplicated != persisted
                or str(payload.request_id) != reservation["request_id"]
                or str(payload.attempt_id) != reservation["attempt_id"]
                or payload.usage_ceiling
                != parse_usage_units_json(reservation["usage_ceiling_json"])
                or quote.amount_micros_sgd != reservation["reserved_micros_sgd"]
            ):
                raise ValueError("pricing binding mismatch")
            return quote
        except (
            ContractParseError,
            KeyError,
            TypeError,
            ValueError,
            OverflowError,
        ) as error:
            raise BudgetEvidenceQuarantined("budget_pricing_snapshot_invalid") from error

    def attest_provider_usage(
        self,
        *,
        call_id: UUID,
        route: Any,
        category: str,
        accounting_basis: str,
        billable_usage: UsageUnits,
        provider_response_identifier: str,
    ) -> ProviderUsageReceiptV1:
        if (
            billable_usage.category != category
            or usage_total(billable_usage) <= 0
            or accounting_basis
            not in {
                "provider_reported_exact",
                "request_bound_exact",
                "conservative_full_reservation",
            }
            or not self._valid_response_identifier(provider_response_identifier)
        ):
            raise BudgetEvidenceQuarantined("provider_usage_invalid_unknown_overage")
        response_commitment = self._commit(
            "provider.response-id.v1",
            {
                "provider": route.provider,
                "model": route.model,
                "response_identifier": provider_response_identifier,
                "accounting_basis": accounting_basis,
                "billable_usage": billable_usage.model_dump(mode="json"),
            },
        )
        values = {
            "schema_version": "tuntun.provider-usage-receipt.v1",
            "receipt_id": uuid4(),
            "provider_call_id": call_id,
            "reservation_id": route.budget_reservation_id,
            "request_id": route.request_id,
            "attempt_id": route.attempt_id,
            "authorization_id": route.authorization_id,
            "provider": route.provider,
            "model": route.model,
            "category": category,
            "accounting_basis": accounting_basis,
            "billable_usage": billable_usage,
            "provider_response_commitment": response_commitment,
            "observed_at": self._clock.now(),
        }
        commitment = self._commit("provider.usage-receipt.v1", self._jsonable(values))
        return ProviderUsageReceiptV1(**values, receipt_commitment=commitment)

    def canonical_receipt(self, receipt: ProviderUsageReceiptV1) -> str:
        return self._canonical(self._jsonable(receipt)).decode("utf-8")

    def canonical_usage(self, billable_usage: UsageUnits) -> str:
        return self._canonical(self._jsonable(billable_usage)).decode("utf-8")

    def require_attested_receipt(self, receipt: ProviderUsageReceiptV1) -> str:
        if type(receipt) is not ProviderUsageReceiptV1:
            raise BudgetEvidenceQuarantined("budget_usage_receipt_invalid_unknown_overage")
        unsigned = receipt.model_dump(mode="python", exclude={"receipt_commitment"})
        expected = self._commit("provider.usage-receipt.v1", unsigned)
        if (
            receipt.receipt_commitment.key_id != self._key_id
            or expected.key_id != receipt.receipt_commitment.key_id
            or not hmac.compare_digest(
                expected.value_b64,
                receipt.receipt_commitment.value_b64,
            )
        ):
            raise BudgetEvidenceQuarantined("budget_usage_receipt_invalid_unknown_overage")
        return self.canonical_receipt(receipt)

    def require_provider_usage_receipt(
        self,
        call: Any,
        reservation: Any,
        now: datetime,
    ) -> ProviderUsageReceiptV1:
        try:
            raw_receipt = call["provider_usage_json"]
            if type(raw_receipt) is not str:
                raise ValueError("usage receipt JSON encoding invalid")
            receipt = parse_contract_json(
                ProviderUsageReceiptV1,
                raw_receipt.encode("utf-8"),
                max_bytes=65_536,
                require_canonical=True,
            )
            canonical = self.canonical_receipt(receipt)
            if canonical != call["provider_usage_json"]:
                raise ValueError("noncanonical usage receipt")
            self.require_attested_receipt(receipt)
            if (
                receipt.receipt_commitment.key_id != call["provider_usage_receipt_key_id"]
                or receipt.receipt_commitment.value_b64 != call["provider_usage_receipt_hmac_b64"]
            ):
                raise ValueError("usage receipt HMAC mismatch")
            bound = (
                str(receipt.provider_call_id),
                str(receipt.reservation_id),
                str(receipt.request_id),
                str(receipt.attempt_id),
                str(receipt.authorization_id),
                receipt.provider,
                receipt.model,
                receipt.category,
            )
            stored = (
                call["id"],
                call["budget_reservation_id"],
                call["request_id"],
                call["attempt_id"],
                call["authorization_id"],
                call["provider"],
                call["model"],
                call["category"],
            )
            reservation_bound = (
                str(receipt.reservation_id),
                str(receipt.request_id),
                str(receipt.attempt_id),
                receipt.provider,
                receipt.model,
                receipt.category,
            )
            if (
                bound != stored
                or reservation_bound
                != (
                    reservation["id"],
                    reservation["request_id"],
                    reservation["attempt_id"],
                    reservation["provider"],
                    reservation["model"],
                    reservation["category"],
                )
                or receipt.observed_at > now
            ):
                raise ValueError("usage receipt binding mismatch")
            policy = (
                reservation["primary_accounting_basis"],
                reservation["missing_evidence_policy"],
            )
            allowed = {policy[0]}
            if policy[1] == "conservative_full_reservation":
                allowed.add("conservative_full_reservation")
            ceiling = parse_usage_units_json(reservation["usage_ceiling_json"])
            if receipt.accounting_basis not in allowed:
                raise ValueError("usage receipt accounting basis mismatch")
            if (
                receipt.accounting_basis in {"request_bound_exact", "conservative_full_reservation"}
                and receipt.billable_usage != ceiling
            ):
                raise ValueError("usage receipt ceiling binding mismatch")
            return receipt
        except (
            ValidationError,
            ContractParseError,
            KeyError,
            TypeError,
            ValueError,
            OverflowError,
        ) as error:
            raise BudgetEvidenceQuarantined(
                "budget_usage_receipt_invalid_unknown_overage"
            ) from error
