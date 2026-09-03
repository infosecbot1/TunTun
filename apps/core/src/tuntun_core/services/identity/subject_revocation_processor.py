from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid5

from tuntun_core.services.identity.subject_revocation import SubjectRevocationEvent
from tuntun_core.services.identity.subject_revocation_handlers import (
    ALLOWED_DOWNSTREAM_DISPOSITIONS,
    DeferredEffect,
    EffectRepositoryPort,
    _OnceHandler,
)

POST_COMMIT_FAMILIES = (
    "provider_routes",
    "search_capabilities",
    "action_authorities",
    "memory_authorities",
)
ALLOWED_DISPOSITIONS = ALLOWED_DOWNSTREAM_DISPOSITIONS


@dataclass(frozen=True, slots=True)
class SubjectRevocationProcessingReceipt:
    id: UUID
    dispositions: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class DeferredRevocationProcessing:
    leased_until: datetime


class SubjectRevocationProcessor:
    def __init__(self, handlers: Mapping[str, _OnceHandler]) -> None:
        if set(handlers) != set(POST_COMMIT_FAMILIES):
            raise RuntimeError("complete_post_commit_revocation_handlers_required")
        effect_repositories = {id(handler.effect_repository) for handler in handlers.values()}
        if len(effect_repositories) != 1:
            raise RuntimeError("one_revocation_effect_repository_required")
        self._handlers = handlers
        self._effects: EffectRepositoryPort = next(iter(handlers.values())).effect_repository

    @property
    def available(self) -> bool:
        if set(self._handlers) != set(POST_COMMIT_FAMILIES):
            return False
        for handler in self._handlers.values():
            handler.require_stage_match()
        return True

    @property
    def handlers(self) -> Mapping[str, _OnceHandler]:
        return self._handlers

    async def recover_stale_effect_claims(self, now: datetime) -> int:
        return await self._effects.recover_stale(now)

    async def reconcile_once(
        self,
        event: SubjectRevocationEvent,
        *,
        idempotency_key: UUID,
        lease_owner: UUID,
        now: datetime,
    ) -> SubjectRevocationProcessingReceipt | DeferredRevocationProcessing:
        event_id = event.id
        if idempotency_key != event_id:
            raise PermissionError("subject_revocation_idempotency_mismatch")
        dispositions: list[tuple[str, str]] = []
        for family in POST_COMMIT_FAMILIES:
            disposition = await self._handlers[family].reconcile_started_once(
                event_id=event_id,
                subject_id=event.subject_id,
                through_generation=event.new_authority_generation - 1,
                idempotency_key=uuid5(event_id, family),
                lease_owner=lease_owner,
                now=now,
            )
            if isinstance(disposition, DeferredEffect):
                return DeferredRevocationProcessing(disposition.leased_until)
            if disposition not in ALLOWED_DISPOSITIONS:
                raise RuntimeError("invalid_subject_revocation_disposition")
            dispositions.append((family, disposition))
        return SubjectRevocationProcessingReceipt(
            id=uuid5(event_id, "aggregate"),
            dispositions=tuple(dispositions),
        )
