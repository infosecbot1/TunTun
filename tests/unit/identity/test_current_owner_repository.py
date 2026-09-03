# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.services.identity.current_owner import CurrentOwnerAuthorityRepository
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWorkFactory

from tests.identity_support import _apply_identity_migration


def _sqlite_identity_engine(tmp_path) -> sa.Engine:
    engine = sa.create_engine(f"sqlite+pysqlite:///{tmp_path / f'{uuid4()}.sqlite3'}", future=True)
    _apply_identity_migration(engine)
    return engine


def _insert_household(connection: sa.Connection, household_id: UUID, now) -> None:
    connection.exec_driver_sql(
        "INSERT OR IGNORE INTO households (id,display_label_ciphertext,timezone,created_at) "
        "VALUES (?,?,?,?)",
        (str(household_id), b"household-label", "Asia/Singapore", utc_storage(now)),
    )


def _insert_subject(
    connection: sa.Connection,
    *,
    subject_id: UUID,
    household_id: UUID,
    now,
    profile_class: str = "owner",
    active: int = 1,
    revoked: bool = False,
    version: int = 1,
    authority_generation: int = 1,
) -> None:
    _insert_household(connection, household_id, now)
    connection.exec_driver_sql(
        "INSERT INTO subjects "
        "(id,household_id,guardian_id,guardian_generation,profile_class,"
        "encrypted_display_label,encrypted_persona_traits,current_consent_receipt_ids,"
        "active,authority_generation,version,next_reenrollment_reminder_at,"
        "created_at,updated_at,revoked_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            str(subject_id),
            str(household_id),
            None,
            0,
            profile_class,
            b"profile-label-ciphertext-has-enough-bytes",
            None,
            b"[]",
            active,
            authority_generation,
            version,
            None,
            utc_storage(now),
            utc_storage(now),
            utc_storage(now) if revoked else None,
        ),
    )


def _sql_current_owner_repository(
    engine: sa.Engine,
) -> tuple[IdentityUnitOfWorkFactory, CurrentOwnerAuthorityRepository]:
    uow_factory = AsyncUnitOfWorkFactory(engine)
    identity_factory = cast(IdentityUnitOfWorkFactory, uow_factory)
    return (
        identity_factory,
        CurrentOwnerAuthorityRepository(identity_factory),
    )


@pytest.mark.asyncio
async def test_current_owner_pointer_requires_active_exact_subject_generation_and_version(
    current_owner_repository,
    owner,
    now,
) -> None:
    snapshot = await current_owner_repository.require_exact(
        owner.household_id,
        owner.id,
        owner_generation=1,
        profile_version=owner.version,
        now=now,
    )

    assert (snapshot.subject_id, snapshot.owner_generation, snapshot.profile_version) == (
        owner.id,
        1,
        owner.version,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    ["owner_replaced", "owner_generation_changed", "profile_version_changed", "owner_revoked"],
)
async def test_stale_owner_snapshot_is_rejected(current_owner_scenario, change) -> None:
    stale = await current_owner_scenario.snapshot_then(change)

    with pytest.raises(PermissionError, match="current_owner_authority_required"):
        await current_owner_scenario.repository.require_exact(
            stale.household_id,
            stale.subject_id,
            owner_generation=stale.owner_generation,
            profile_version=stale.profile_version,
            now=current_owner_scenario.now,
        )


@pytest.mark.asyncio
async def test_sql_current_owner_pointer_rejects_cross_household_restored_row(
    tmp_path,
    now,
) -> None:
    engine = _sqlite_identity_engine(tmp_path)
    pointer_household_id = uuid4()
    subject_household_id = uuid4()
    subject_id = uuid4()
    with engine.begin() as connection:
        _insert_household(connection, pointer_household_id, now)
        _insert_subject(
            connection,
            subject_id=subject_id,
            household_id=subject_household_id,
            now=now,
        )
        connection.exec_driver_sql(
            "INSERT INTO current_owner_authority "
            "(household_id,subject_id,owner_generation,changed_at) VALUES (?,?,?,?)",
            (str(pointer_household_id), str(subject_id), 1, utc_storage(now)),
        )
    _factory, repository = _sql_current_owner_repository(engine)

    with pytest.raises(PermissionError, match="current_owner_authority_required"):
        await repository.require_exact(
            pointer_household_id,
            subject_id,
            owner_generation=1,
            profile_version=1,
            now=now,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "subject_state",
    ["missing", "cross_household", "adult", "inactive", "revoked"],
)
async def test_install_current_owner_requires_live_same_household_owner_subject(
    tmp_path,
    now,
    subject_state,
) -> None:
    engine = _sqlite_identity_engine(tmp_path)
    household_id = uuid4()
    subject_id = uuid4()
    with engine.begin() as connection:
        _insert_household(connection, household_id, now)
        if subject_state != "missing":
            _insert_subject(
                connection,
                subject_id=subject_id,
                household_id=uuid4() if subject_state == "cross_household" else household_id,
                now=now,
                profile_class="adult" if subject_state == "adult" else "owner",
                active=0 if subject_state in {"inactive", "revoked"} else 1,
                revoked=subject_state == "revoked",
            )
    uow_factory, repository = _sql_current_owner_repository(engine)

    async with uow_factory() as uow:
        with pytest.raises(PermissionError, match="current_owner_authority_required"):
            await repository.install_in_uow(
                uow,
                household_id,
                subject_id,
                owner_generation=1,
                changed_at=now,
            )


@pytest.mark.asyncio
async def test_install_current_owner_requires_strictly_increasing_owner_generation(
    tmp_path,
    now,
) -> None:
    engine = _sqlite_identity_engine(tmp_path)
    household_id = uuid4()
    old_owner_id = uuid4()
    new_owner_id = uuid4()
    with engine.begin() as connection:
        _insert_subject(
            connection,
            subject_id=old_owner_id,
            household_id=household_id,
            now=now,
            active=0,
        )
        _insert_subject(
            connection,
            subject_id=new_owner_id,
            household_id=household_id,
            now=now,
        )
        connection.exec_driver_sql(
            "INSERT INTO current_owner_authority "
            "(household_id,subject_id,owner_generation,changed_at) VALUES (?,?,?,?)",
            (str(household_id), str(old_owner_id), 2, utc_storage(now)),
        )
    uow_factory, repository = _sql_current_owner_repository(engine)

    for stale_generation in (1, 2):
        async with uow_factory() as uow:
            with pytest.raises(PermissionError, match="current_owner_generation_not_monotonic"):
                await repository.install_in_uow(
                    uow,
                    household_id,
                    new_owner_id,
                    owner_generation=stale_generation,
                    changed_at=now,
                )

    async with uow_factory() as uow:
        await repository.install_in_uow(
            uow,
            household_id,
            new_owner_id,
            owner_generation=3,
            changed_at=now,
        )
        await uow.commit()

    installed = await repository.require_exact(
        household_id,
        new_owner_id,
        owner_generation=3,
        profile_version=1,
        now=now,
    )
    assert installed.subject_id == new_owner_id
