from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from threading import get_ident

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine


@dataclass(frozen=True, slots=True)
class MigratedDatabase:
    engine: Engine
    path: Path
    key: bytes


@pytest.fixture
def migrated_database(tmp_path: Path) -> Iterator[MigratedDatabase]:
    root = Path(os.path.realpath(tmp_path)) / "private"
    root.mkdir(mode=0o700)
    path = root / "foundation.db"
    key = bytes(range(32))
    config = Config("apps/core/alembic.ini")
    config.attributes["sqlcipher_path"] = path
    config.attributes["sqlcipher_key"] = key
    command.upgrade(config, "head")
    fixture = MigratedDatabase(create_sqlcipher_engine(path, key), path, key)
    try:
        yield fixture
    finally:
        fixture.engine.dispose()
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
            candidate.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class CreatedHousehold:
    household_id: str
    worker_ident: int


class BoundHouseholdFacade:
    def __init__(self, uow: object) -> None:
        self._uow = uow

    async def insert_synthetic(self, household_id: str) -> CreatedHousehold:
        def insert(transaction: object) -> CreatedHousehold:
            transaction.execute(  # type: ignore[attr-defined]
                text(
                    "INSERT INTO households"
                    "(id,display_label_ciphertext,timezone,created_at) "
                    "VALUES(:id,:label,'Asia/Singapore',:now)"
                ),
                {
                    "id": household_id,
                    "label": b"ciphertext",
                    "now": "2026-08-27T01:02:03.000004Z",
                },
            )
            return CreatedHousehold(household_id, get_ident())

        return await self._uow.run_sync(insert)  # type: ignore[attr-defined,no-any-return]


class HouseholdFacadeFactory:
    def bind(self, uow: object) -> BoundHouseholdFacade:
        return BoundHouseholdFacade(uow)


class CommitSignalProbe:
    def __init__(self, *, fail: bool = False) -> None:
        self.offer_count = 0
        self._fail = fail

    def offer_nowait(self) -> None:
        self.offer_count += 1
        if self._fail:
            raise RuntimeError("synthetic post-commit signal failure")


@pytest.fixture
def household_repository_facade() -> HouseholdFacadeFactory:
    return HouseholdFacadeFactory()


@pytest.fixture
def nonblocking_commit_signal() -> CommitSignalProbe:
    return CommitSignalProbe()


@pytest.fixture
def failing_nonblocking_commit_signal() -> CommitSignalProbe:
    return CommitSignalProbe(fail=True)
