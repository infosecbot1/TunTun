from __future__ import annotations

import asyncio
import hmac
import json
import re
from contextlib import AbstractAsyncContextManager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from types import MappingProxyType, TracebackType
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

import rfc8785
from rfc8785._impl import _Value as Rfc8785Value
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import Commitment
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.policy import AuthContext
from tuntun_core.services.audit.ledger import AsyncAuditLedger
from tuntun_core.services.identity.consent import (
    AuthenticationPort,
    ConsentService,
    GuestSessionConsentService,
    IdentityMutationCoordinator,
)
from tuntun_core.services.identity.profiles import ProfileService
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWork

_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$", flags=re.ASCII)
_TASK1_SECRET_MATERIAL_SLOTS = MappingProxyType(
    {
        "profile": ("tuntun.identity.profile", "root-v1", "key-id-v1"),
        "receipt": ("tuntun.identity.receipts", "root-v1", "key-id-v1"),
        "action_parameters": (
            "tuntun.identity.action-parameters",
            "root-v1",
            "key-id-v1",
        ),
        "audit_chain": ("tuntun.identity.audit-chain", "root-v1", "key-id-v1"),
        "audit_payload": ("tuntun.identity.audit-payload", "root-v1", "key-id-v1"),
    }
)


@dataclass(frozen=True, slots=True)
class Task1IdentityKeyMaterial:
    root_key: bytes
    key_id: str


@dataclass(frozen=True, slots=True)
class Task1IdentityKeyBundle:
    profile: Task1IdentityKeyMaterial
    receipt: Task1IdentityKeyMaterial
    action_parameters: Task1IdentityKeyMaterial
    audit_chain: Task1IdentityKeyMaterial
    audit_payload: Task1IdentityKeyMaterial

    def __post_init__(self) -> None:
        materials = (
            self.profile,
            self.receipt,
            self.action_parameters,
            self.audit_chain,
            self.audit_payload,
        )
        roots = tuple(_require_task1_root(item.root_key) for item in materials)
        key_ids = tuple(_require_task1_key_id(item.key_id) for item in materials)
        if len(set(roots)) != len(roots):
            raise ValueError("task1 identity key roots must be distinct")
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("task1 identity key ids must be distinct")


Task1IdentityKeySlot = Literal[
    "profile",
    "receipt",
    "action_parameters",
    "audit_chain",
    "audit_payload",
]


class Task1IdentityKeyProviderPort(Protocol):
    def current_keys(self) -> Task1IdentityKeyBundle: ...


class Task1SecretProvider(Protocol):
    def get(self, service: str, account: str) -> bytes: ...


class SecretProviderTask1IdentityKeyProvider:
    def __init__(self, provider: Task1SecretProvider) -> None:
        self._provider = provider

    def current_keys(self) -> Task1IdentityKeyBundle:
        try:
            return Task1IdentityKeyBundle(
                profile=self._load("profile"),
                receipt=self._load("receipt"),
                action_parameters=self._load("action_parameters"),
                audit_chain=self._load("audit_chain"),
                audit_payload=self._load("audit_payload"),
            )
        except Exception:
            raise RuntimeError("task1_identity_key_material_invalid") from None

    def _load(self, slot: Task1IdentityKeySlot) -> Task1IdentityKeyMaterial:
        service, root_account, key_id_account = _TASK1_SECRET_MATERIAL_SLOTS[slot]
        root = self._provider.get(service, root_account)
        key_id_bytes = self._provider.get(service, key_id_account)
        if type(key_id_bytes) is not bytes:
            raise ValueError("task1 identity key id must be bytes")
        try:
            key_id = key_id_bytes.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("task1 identity key id must be ASCII") from None
        return Task1IdentityKeyMaterial(
            _require_task1_root(root),
            _require_task1_key_id(key_id),
        )


class PrivateCommitmentService:
    def __init__(self, material: Task1IdentityKeyMaterial) -> None:
        self._root_key = _require_task1_root(material.root_key)
        self.key_id = _require_task1_key_id(material.key_id)

    def commit_private(self, purpose: str, payload: bytes) -> Commitment:
        return commit_private(self._root_key, self.key_id, purpose, payload)


def _require_task1_root(value: object) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("task1 identity key root must be exact 32 bytes")
    root = value
    if len(set(root)) == 1:
        raise ValueError("task1 identity key root must not be a known deterministic fixture")
    return root


def _require_task1_key_id(value: object) -> str:
    if type(value) is not str or _KEY_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("task1 identity key id must be bounded canonical ASCII")
    return value


@dataclass(frozen=True, slots=True)
class _ActiveIdentityScope:
    uow: IdentityUnitOfWork
    owner: asyncio.Task[object]


@dataclass(frozen=True, slots=True)
class Task1IdentityMutationServices:
    profiles: ProfileService
    consents: ConsentService
    guest_consents: GuestSessionConsentService
    mutations: IdentityMutationCoordinator
    authentication: AuthenticationPort
    audit_ledger: IdentityAuditLedger


class IdentityUnitOfWorkContextFactory(Protocol):
    def __call__(self) -> AbstractAsyncContextManager[IdentityUnitOfWork]: ...


class SqlIdentityMutationScope:
    def __init__(self, uow_factory: IdentityUnitOfWorkContextFactory) -> None:
        self._uow_factory = uow_factory
        self._active: ContextVar[_ActiveIdentityScope | None] = ContextVar(
            f"task1_identity_active_uow_{id(self)}",
            default=None,
        )

    def open(self) -> AbstractAsyncContextManager[IdentityUnitOfWork]:
        return _SqlIdentityMutationContext(self)

    def require_active_uow(self) -> IdentityUnitOfWork:
        active = self._active.get()
        current = asyncio.current_task()
        if active is None or current is None or active.owner is not current:
            raise RuntimeError("no active atomic mutation scope")
        return active.uow

    def _reject_nested_active(self) -> None:
        current = asyncio.current_task()
        if current is None:
            raise RuntimeError("identity mutation scope requires an asyncio task")
        active = self._active.get()
        if active is not None and active.owner is current:
            raise RuntimeError("nested identity mutation scope")

    def _set_active(self, uow: IdentityUnitOfWork) -> Token[_ActiveIdentityScope | None]:
        current = asyncio.current_task()
        if current is None:
            raise RuntimeError("identity mutation scope requires an asyncio task")
        active = self._active.get()
        if active is not None and active.owner is current:
            raise RuntimeError("nested identity mutation scope")
        return self._active.set(_ActiveIdentityScope(uow, current))

    def _clear_active(self, token: Token[_ActiveIdentityScope | None]) -> None:
        self._active.reset(token)

    def _open_uow(self) -> AbstractAsyncContextManager[IdentityUnitOfWork]:
        return self._uow_factory()


class _SqlIdentityMutationContext:
    def __init__(self, scope: SqlIdentityMutationScope) -> None:
        self._scope = scope
        self._context: AbstractAsyncContextManager[IdentityUnitOfWork] | None = None
        self._uow: IdentityUnitOfWork | None = None
        self._token: Token[_ActiveIdentityScope | None] | None = None

    async def __aenter__(self) -> IdentityUnitOfWork:
        self._scope._reject_nested_active()
        context = self._scope._open_uow()
        uow = await context.__aenter__()
        self._context = context
        self._uow = uow
        try:
            self._token = self._scope._set_active(uow)
        except BaseException as activation_error:
            try:
                await context.__aexit__(
                    type(activation_error),
                    activation_error,
                    activation_error.__traceback__,
                )
            except BaseException as cleanup_error:
                activation_error.add_note(
                    "identity mutation scope cleanup failure after rejected activation: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            self._context = None
            self._uow = None
            raise
        return uow

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if self._token is not None:
            self._scope._clear_active(self._token)
        if self._context is None:
            return False
        return (await self._context.__aexit__(exc_type, exc, traceback)) is True


class IdentityAuditLedger:
    def __init__(self, ledger: AsyncAuditLedger) -> None:
        self._ledger = ledger

    async def append(self, uow: IdentityUnitOfWork, draft: AuditDraft) -> None:
        await self._ledger.append(uow, draft)


class HmacReceiptSigner:
    def __init__(self, root_key: bytes, *, key_id: str) -> None:
        if type(root_key) is not bytes or len(root_key) != 32:
            raise ValueError("receipt signer root key must be 32 bytes")
        if type(key_id) is not str or not key_id:
            raise ValueError("receipt signer key id required")
        self._root_key = root_key
        self.key_id = key_id

    def sign_fields(self, purpose: str, fields: tuple[object, ...]) -> tuple[str, bytes]:
        body = rfc8785.dumps(
            cast(
                Rfc8785Value,
                {
                    "fields": [_receipt_field_json(item) for item in fields],
                    "purpose": purpose,
                },
            )
        )
        digest = hmac.new(
            self._root_key,
            purpose.encode("ascii") + b"\0" + body,
            "sha256",
        ).digest()
        return self.key_id, digest

    def verify_fields(
        self,
        purpose: str,
        key_id: str,
        fields: tuple[object, ...],
        expected_hmac: bytes,
    ) -> bool:
        if key_id != self.key_id:
            return False
        _key_id, digest = self.sign_fields(purpose, fields)
        return hmac.compare_digest(digest, expected_hmac)


class UnavailableTask1Authentication:
    async def consume_in_uow(
        self,
        uow: IdentityUnitOfWork,
        grant_id: UUID,
        binding: object,
    ) -> AuthContext:
        del uow, grant_id, binding
        raise RuntimeError("task1_authentication_unavailable")


class Task1ConsentRevocationAuditMapper:
    def __init__(self, commitments: PrivateCommitmentService) -> None:
        self._commitments = commitments

    def revoked(self, event: object, auth: AuthContext) -> AuditDraft:
        payload = json.dumps(
            {"event": _receipt_field_json(event), "kind": "identity_consent_revoked"},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return AuditDraft(
            event_id=uuid4(),
            occurred_at=auth.consumed_at,
            actor_pseudonym=_audit_actor_pseudonym(auth, self._commitments),
            action_code="consent.revoked",
            outcome="recorded",
            reason_code="ok",
            correlation_id=uuid4(),
            payload_commitment=self._commitments.commit_private("audit.payload", payload),
        )


def _receipt_field_json(value: object) -> object:
    if hasattr(value, "value"):
        return _receipt_field_json(value.value)
    if isinstance(value, UUID):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [_receipt_field_json(item) for item in value]
    if isinstance(value, list):
        return [_receipt_field_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _receipt_field_json(item) for key, item in value.items()}
    return value


def _audit_actor_pseudonym(
    auth: AuthContext,
    commitments: PrivateCommitmentService,
) -> str:
    if auth.subject_id is None:
        return "actor:guest"
    payload = rfc8785.dumps(
        cast(
            Rfc8785Value,
            {"actor_subject_id": str(auth.subject_id)},
        )
    )
    commitment = commitments.commit_private("audit.actor.subject", payload)
    return f"actor:pseudonym:v1:{commitment.value_b64}"
