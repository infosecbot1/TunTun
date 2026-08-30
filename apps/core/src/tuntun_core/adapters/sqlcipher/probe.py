from __future__ import annotations

import platform
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from sqlcipher3 import dbapi2 as sqlcipher3  # type: ignore[import-untyped]

from .connection import (
    SQLCIPHER_OPEN_FLAGS,
    QualifiedSQLCipherConnection,
    open_sqlcipher,
    qualified_database_identity,
)


@dataclass(frozen=True, slots=True)
class StorageProbe:
    operating_system: str
    architecture: str
    python: str
    driver: str
    sqlite: str
    cipher: str
    open_flags: int
    integrity_ok: bool
    mode: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def probe_storage(path: Path, key: bytes) -> StorageProbe:
    db = cast(QualifiedSQLCipherConnection, open_sqlcipher(path, key))
    try:
        db.revalidate_storage_path()
        qualified_database_identity(path)
        cipher = str(db.execute("PRAGMA cipher_version").fetchone()[0])
        integrity = not db.execute("PRAGMA cipher_integrity_check").fetchall()
        return StorageProbe(
            platform.platform(),
            platform.machine(),
            platform.python_version(),
            "sqlcipher3==0.6.2",
            sqlcipher3.sqlite_version,
            cipher,
            SQLCIPHER_OPEN_FLAGS,
            integrity,
            "0o600",
        )
    finally:
        db.close()
