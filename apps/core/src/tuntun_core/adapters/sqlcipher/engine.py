from __future__ import annotations

from pathlib import Path
from typing import cast

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.pool import NullPool

from .connection import open_sqlcipher


def create_sqlcipher_engine(path: Path, key: bytes) -> Engine:
    """Create an unpooled SQLAlchemy engine whose only opener is SQLCipher."""

    if type(key) is not bytes or len(key) != 32:
        raise ValueError("SQLCipher key must be exactly 32 bytes")

    def _connect() -> DBAPIConnection:
        return cast(DBAPIConnection, open_sqlcipher(path, key))

    return create_engine(
        "sqlite://",
        creator=_connect,
        poolclass=NullPool,
        future=True,
    )
