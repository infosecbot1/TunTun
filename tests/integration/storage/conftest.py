from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
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
