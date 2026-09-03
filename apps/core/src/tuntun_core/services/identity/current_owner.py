from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Protocol, cast
from uuid import UUID

from tuntun_contracts.policy import CurrentOwnerAuthority
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.identity_uow import (
    IdentityUnitOfWork,
    IdentityUnitOfWorkFactory,
)


class _RowMappingSource(Protocol):
    @property
    def _mapping(self) -> Mapping[str, object]: ...


def _row_to_dict(row: object | None) -> dict[str, object] | None:
    if row is None:
        return None
    return dict(cast(_RowMappingSource, row)._mapping)


class CurrentOwnerAuthorityRepository:
    def __init__(self, uow_factory: IdentityUnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def require_exact(
        self,
        household_id: UUID,
        subject_id: UUID,
        *,
        owner_generation: int,
        profile_version: int,
        now: datetime,
    ) -> CurrentOwnerAuthority:
        async with self._uow_factory() as uow:
            values = await uow.run_sync(
                lambda transaction: _row_to_dict(
                    transaction.exec_driver_sql(
                        "SELECT owner.household_id AS authority_household_id,"
                        "owner.subject_id,owner.owner_generation,"
                        "subject.household_id AS subject_household_id,"
                        "subject.version AS profile_version,subject.active,subject.revoked_at,"
                        "subject.profile_class "
                        "FROM current_owner_authority AS owner "
                        "JOIN subjects AS subject ON subject.id=owner.subject_id "
                        "AND subject.household_id=owner.household_id "
                        "WHERE owner.household_id=? AND owner.subject_id=?",
                        (str(household_id), str(subject_id)),
                    ).fetchone()
                )
            )
            await uow.rollback()
        if values is None:
            raise PermissionError("current_owner_authority_required")
        if (
            str(values["authority_household_id"]) != str(household_id)
            or str(values["subject_household_id"]) != str(household_id)
            or str(values["subject_id"]) != str(subject_id)
            or int(str(values["owner_generation"])) != owner_generation
            or int(str(values["profile_version"])) != profile_version
            or int(str(values["active"])) != 1
            or values["revoked_at"] is not None
            or str(values["profile_class"]) != "owner"
        ):
            raise PermissionError("current_owner_authority_required")
        return CurrentOwnerAuthority(
            household_id=household_id,
            subject_id=subject_id,
            owner_generation=owner_generation,
            profile_version=profile_version,
            observed_at=now,
        )

    async def install_in_uow(
        self,
        uow: IdentityUnitOfWork,
        household_id: UUID,
        subject_id: UUID,
        *,
        owner_generation: int,
        changed_at: datetime,
    ) -> None:
        validation = await uow.run_sync(
            lambda transaction: (
                _row_to_dict(
                    transaction.exec_driver_sql(
                        "SELECT household_id,profile_class,active,revoked_at "
                        "FROM subjects WHERE id=?",
                        (str(subject_id),),
                    ).fetchone()
                ),
                _row_to_dict(
                    transaction.exec_driver_sql(
                        "SELECT owner_generation FROM current_owner_authority WHERE household_id=?",
                        (str(household_id),),
                    ).fetchone()
                ),
            )
        )
        subject, current = validation
        if (
            subject is None
            or str(subject["household_id"]) != str(household_id)
            or str(subject["profile_class"]) != "owner"
            or int(str(subject["active"])) != 1
            or subject["revoked_at"] is not None
        ):
            raise PermissionError("current_owner_authority_required")
        if current is not None and owner_generation <= int(str(current["owner_generation"])):
            raise PermissionError("current_owner_generation_not_monotonic")
        await uow.run_sync(
            lambda transaction: (
                transaction.exec_driver_sql(
                    "INSERT INTO current_owner_authority "
                    "(household_id,subject_id,owner_generation,changed_at) VALUES (?,?,?,?) "
                    "ON CONFLICT(household_id) DO UPDATE SET subject_id=excluded.subject_id,"
                    "owner_generation=excluded.owner_generation,changed_at=excluded.changed_at",
                    (
                        str(household_id),
                        str(subject_id),
                        owner_generation,
                        utc_storage(changed_at),
                    ),
                ).rowcount
            )
        )
