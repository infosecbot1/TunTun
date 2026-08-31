from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, Transaction
from tuntun_core.config.secure_paths import (
    OwnedDirectory,
    absolute_lexical_path,
    ensure_private_directory,
    open_owned_directory,
)

from .connection import FileIdentity, SQLCipherCleanupError, open_sqlcipher
from .engine import create_sqlcipher_engine

_CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
_OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
_CLEANUP_NOTE = "additional encrypted-backup cleanup failure"
_QUARANTINE_NOTE = "initialization path guard remains quarantined"


def _migration_config_path() -> Path:
    module = Path(__file__).resolve()
    candidates = (
        module.parents[2] / "_migration_assets" / "alembic.ini",
        module.parents[4] / "alembic.ini",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("packaged Alembic configuration is unavailable")


_MIGRATION_CONFIG = _migration_config_path()


class _GuardedConnection(Protocol):
    def execute(self, sql: str, parameters: object = ...) -> object: ...

    def backup(self, target: object) -> None: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...

    def revalidate_storage_path(self) -> None: ...

    def storage_identities(
        self,
    ) -> tuple[FileIdentity, tuple[tuple[str, FileIdentity], ...]]: ...


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _require_private_regular(
    value: os.stat_result,
    *,
    parent_device: int,
) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_dev != parent_device
    ):
        raise PermissionError("unsafe database path")


def _stat_at(parent: OwnedDirectory, name: str) -> os.stat_result:
    value = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    _require_private_regular(value, parent_device=parent.device)
    return value


def _close_fd(fd: int, primary: BaseException | None = None) -> None:
    try:
        os.close(fd)
    except BaseException:
        if primary is None:
            raise
        primary.add_note(_CLEANUP_NOTE)


def _close_connection(
    connection: _GuardedConnection | None,
    primary: BaseException | None,
) -> tuple[BaseException | None, bool]:
    if connection is None:
        return primary, True
    try:
        connection.close()
    except BaseException as error:
        if primary is None:
            primary = error
        else:
            primary.add_note(_CLEANUP_NOTE)
        try:
            connection.storage_identities()
        except PermissionError:
            # QualifiedSQLCipherConnection clears its guard only after the
            # SQLCipher handle, registry reservation and parent are released.
            return primary, True
        except BaseException:
            pass
        return primary, False
    return primary, True


@dataclass(slots=True)
class _ReservedDestination:
    path: Path
    parent: OwnedDirectory
    main_identity: tuple[int, int]
    sidecar_identities: dict[str, tuple[int, int]] = field(default_factory=dict)

    @classmethod
    def create(cls, path: Path) -> _ReservedDestination:
        absolute = absolute_lexical_path(path)
        owned = ensure_private_directory(absolute.parent)
        parent = open_owned_directory(owned.path)
        fd: int | None = None
        primary: BaseException | None = None
        created = False
        created_identity: tuple[int, int] | None = None
        try:
            parent.revalidate()
            fd = os.open(absolute.name, _CREATE_FLAGS, 0o600, dir_fd=parent.fd)
            created = True
            created_identity = _identity(os.fstat(fd))
            os.fchmod(fd, 0o600)
            opened = os.fstat(fd)
            named = _stat_at(parent, absolute.name)
            if _identity(opened) != _identity(named):
                raise PermissionError("unsafe database path")
            os.fsync(fd)
            os.fsync(parent.fd)
            _close_fd(fd)
            fd = None
            result = cls(absolute, parent, _identity(named))
            parent = cast(OwnedDirectory, None)
            return result
        except BaseException as error:
            primary = error
            if created:
                try:
                    named = os.stat(
                        absolute.name,
                        dir_fd=parent.fd,
                        follow_symlinks=False,
                    )
                    if created_identity is not None and _identity(named) == created_identity:
                        os.unlink(absolute.name, dir_fd=parent.fd)
                        os.fsync(parent.fd)
                except FileNotFoundError:
                    pass
                except BaseException:
                    error.add_note(_CLEANUP_NOTE)
            raise
        finally:
            if fd is not None:
                _close_fd(fd, primary)
            if parent is not None:
                try:
                    parent.close()
                except BaseException:
                    if primary is None:
                        raise
                    primary.add_note(_CLEANUP_NOTE)

    def bind(self, connection: _GuardedConnection) -> None:
        connection.revalidate_storage_path()
        main, sidecars = connection.storage_identities()
        if (main.device, main.inode) != self.main_identity:
            raise PermissionError("unsafe database path")
        self.sidecar_identities = {
            suffix: (identity.device, identity.inode) for suffix, identity in sidecars
        }

    def revalidate(self) -> None:
        self.parent.revalidate()
        if _identity(_stat_at(self.parent, self.path.name)) != self.main_identity:
            raise PermissionError("unsafe database path")

    def fsync(self) -> None:
        self.revalidate()
        fd = os.open(self.path.name, _OPEN_FLAGS, dir_fd=self.parent.fd)
        primary: BaseException | None = None
        try:
            opened = os.fstat(fd)
            _require_private_regular(opened, parent_device=self.parent.device)
            if _identity(opened) != self.main_identity:
                raise PermissionError("unsafe database path")
            os.fsync(fd)
            os.fsync(self.parent.fd)
        except BaseException as error:
            primary = error
            raise
        finally:
            _close_fd(fd, primary)

    def remove(self, primary: BaseException) -> None:
        identities = {
            self.path.name: self.main_identity,
            **{
                self.path.name + suffix: identity
                for suffix, identity in self.sidecar_identities.items()
            },
        }
        changed = False
        for name, expected in identities.items():
            try:
                named = os.stat(name, dir_fd=self.parent.fd, follow_symlinks=False)
                if _identity(named) != expected:
                    raise PermissionError("unsafe database path")
                os.unlink(name, dir_fd=self.parent.fd)
                changed = True
            except FileNotFoundError:
                continue
            except BaseException:
                primary.add_note(_CLEANUP_NOTE)
        if changed:
            try:
                os.fsync(self.parent.fd)
            except BaseException:
                primary.add_note(_CLEANUP_NOTE)

    def close(self, primary: BaseException | None = None) -> BaseException | None:
        try:
            self.parent.close()
        except BaseException as error:
            if primary is None:
                return error
            primary.add_note(_CLEANUP_NOTE)
        return primary


def _existing_database_identity(path: Path) -> tuple[Path, tuple[int, int], int]:
    absolute = absolute_lexical_path(path)
    with open_owned_directory(absolute.parent) as parent:
        parent.revalidate()
        value = _stat_at(parent, absolute.name)
        return absolute, _identity(value), value.st_size


def _connection_identity(connection: _GuardedConnection) -> tuple[int, int]:
    connection.revalidate_storage_path()
    main, _ = connection.storage_identities()
    return main.device, main.inode


def _copy_encrypted_pages(
    source: _GuardedConnection,
    destination: _GuardedConnection,
) -> None:
    checkpoint = cast(
        tuple[int, int, int] | None,
        source.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(),  # type: ignore[attr-defined]
    )
    if checkpoint != (0, 0, 0):
        raise RuntimeError("encrypted backup source checkpoint failed")
    source.backup(destination)


def _encrypted_backup_from_open_source(
    source_db: _GuardedConnection,
    destination: Path,
    key: bytes,
    *,
    close_source: bool,
) -> None:
    destination_db: _GuardedConnection | None = None
    reservation: _ReservedDestination | None = None
    cleanup_identities_bound = True
    initialization_guard_retained = False
    error: BaseException | None = None
    try:
        reservation = _ReservedDestination.create(destination)
        destination_db = cast(_GuardedConnection, open_sqlcipher(reservation.path, key))
        reservation.bind(destination_db)
        _copy_encrypted_pages(source_db, destination_db)
        destination_db.commit()
        integrity_errors = cast(
            list[tuple[str]],
            destination_db.execute("PRAGMA cipher_integrity_check").fetchall(),  # type: ignore[attr-defined]
        )
        if integrity_errors:
            raise RuntimeError("encrypted backup integrity failed")
        checkpoint = cast(
            tuple[int, int, int] | None,
            destination_db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(),  # type: ignore[attr-defined]
        )
        if checkpoint != (0, 0, 0):
            raise RuntimeError("encrypted backup checkpoint failed")
        reservation.bind(destination_db)
        source_db.revalidate_storage_path()
    except BaseException as caught:
        error = caught
        if isinstance(caught, SQLCipherCleanupError):
            destination_db = cast(_GuardedConnection, caught.connection)
            initialization_guard_retained = caught.guard is not None
            assert reservation is not None
            try:
                reservation.bind(destination_db)
            except BaseException:
                cleanup_identities_bound = False
                caught.add_note(_CLEANUP_NOTE)

    error, destination_released = _close_connection(destination_db, error)
    if initialization_guard_retained:
        destination_released = False
        assert error is not None
        error.add_note(_QUARANTINE_NOTE)
    if close_source:
        error, _ = _close_connection(source_db, error)

    if reservation is not None:
        if error is None:
            try:
                reservation.fsync()
            except BaseException as caught:
                error = caught
        if error is not None and destination_released and cleanup_identities_bound:
            reservation.remove(error)
        elif error is not None and not initialization_guard_retained and not destination_released:
            error.add_note("encrypted backup retained because destination close failed")
        elif error is not None and not initialization_guard_retained:
            error.add_note("encrypted backup retained because cleanup identities were unavailable")
        error = reservation.close(error)

    if error is not None:
        raise error.with_traceback(error.__traceback__)


def encrypted_backup(source: Path, destination: Path, key: bytes) -> None:
    """Create one exclusive, encrypted and durable pre-migration backup."""

    source_path, expected_source, source_size = _existing_database_identity(source)
    if source_size == 0:
        raise RuntimeError("encrypted backup source database is empty")
    source_db: _GuardedConnection | None = None
    error: BaseException | None = None
    try:
        source_db = cast(_GuardedConnection, open_sqlcipher(source_path, key))
        if _connection_identity(source_db) != expected_source:
            raise PermissionError("unsafe database path")
    except BaseException as caught:
        error = caught
    if error is not None:
        error, _ = _close_connection(source_db, error)
        assert error is not None
        raise error.with_traceback(error.__traceback__)
    assert source_db is not None
    _encrypted_backup_from_open_source(
        source_db,
        destination,
        key,
        close_source=True,
    )


def _config(
    path: Path,
    key: bytes,
    connection: Connection | None = None,
) -> Config:
    config = Config(os.fspath(_MIGRATION_CONFIG))
    config.attributes["sqlcipher_path"] = path
    config.attributes["sqlcipher_key"] = key
    if connection is not None:
        config.attributes["sqlalchemy_connection"] = connection
    return config


def upgrade_encrypted(path: Path, key: bytes, backup: Path | None) -> None:
    """Upgrade a SQLCipher database, requiring a durable backup if it exists."""

    absolute = absolute_lexical_path(path)
    fresh: _ReservedDestination | None = None
    try:
        existing_path, expected_identity, size = _existing_database_identity(absolute)
    except (FileNotFoundError, PermissionError):
        try:
            fresh = _ReservedDestination.create(absolute)
        except FileExistsError:
            # A creator won the race after the missing observation. Reclassify
            # it as existing; it may never bypass the backup requirement.
            existing_path, expected_identity, size = _existing_database_identity(absolute)
        else:
            existing_path = fresh.path
            expected_identity = fresh.main_identity
            size = 0

    if fresh is None:
        if size == 0:
            raise RuntimeError("existing database is empty; owner repair required")
        if backup is None:
            raise RuntimeError("existing database requires encrypted pre-migration backup")

    engine: Engine | None = None
    connection: Connection | None = None
    transaction: Transaction | None = None
    guard: _GuardedConnection | None = None
    initialization_connection: _GuardedConnection | None = None
    cleanup_identities_bound = True
    initialization_guard_retained = False
    error: BaseException | None = None
    connection_released = True
    try:
        engine = create_sqlcipher_engine(existing_path, key)
        connection = engine.connect()
        guard = cast(_GuardedConnection, connection.connection.driver_connection)
        if _connection_identity(guard) != expected_identity:
            raise PermissionError("unsafe database path")
        if fresh is not None:
            fresh.bind(guard)
        data_version: int | None = None
        if fresh is None:
            assert backup is not None
            # Keep one source connection alive across the copy. Its data_version
            # changes only for commits made by another connection; the backup's
            # checkpoint runs on this same connection and therefore cannot look
            # like an external writer.
            data_version = int(connection.exec_driver_sql("PRAGMA data_version").scalar_one())
            connection.commit()
            _encrypted_backup_from_open_source(
                guard,
                backup,
                key,
                close_source=False,
            )
            if _connection_identity(guard) != expected_identity:
                raise PermissionError("unsafe database path")
        # The engine stays in DB-API autocommit mode so ordinary reads never
        # reserve the writer slot. Migrations establish both SQLAlchemy's
        # logical transaction and SQLite's exact writer transaction here.
        transaction = connection.begin()
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        if data_version is not None:
            locked_data_version = int(
                connection.exec_driver_sql("PRAGMA data_version").scalar_one()
            )
            if locked_data_version != data_version:
                raise RuntimeError("database changed during encrypted backup")
        command.upgrade(_config(existing_path, key, connection), "head")
        transaction.commit()
        transaction = None
        checkpoint = cast(
            tuple[int, int, int] | None,
            guard.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(),  # type: ignore[attr-defined]
        )
        if checkpoint != (0, 0, 0):
            raise RuntimeError("encrypted migration checkpoint failed")
        if fresh is not None:
            fresh.bind(guard)
    except BaseException as caught:
        error = caught
        if isinstance(caught, SQLCipherCleanupError):
            initialization_connection = cast(_GuardedConnection, caught.connection)
            initialization_guard_retained = caught.guard is not None
            if fresh is not None:
                try:
                    fresh.bind(initialization_connection)
                except BaseException:
                    cleanup_identities_bound = False
                    caught.add_note(_CLEANUP_NOTE)

    if transaction is not None and transaction.is_active:
        try:
            transaction.rollback()
        except BaseException:
            assert error is not None
            error.add_note(_CLEANUP_NOTE)

    if connection is not None:
        try:
            connection.close()
        except BaseException as close_error:
            if error is None:
                error = close_error
            else:
                error.add_note(_CLEANUP_NOTE)
            connection_released = False
            if guard is not None:
                try:
                    guard.storage_identities()
                except PermissionError:
                    connection_released = True
                except BaseException:
                    pass

    if initialization_connection is not None:
        error, initialization_released = _close_connection(initialization_connection, error)
        if initialization_guard_retained:
            initialization_released = False
            assert error is not None
            error.add_note(_QUARANTINE_NOTE)
        connection_released = connection_released and initialization_released

    if engine is not None:
        try:
            engine.dispose()
        except BaseException as dispose_error:
            if error is None:
                error = dispose_error
            else:
                error.add_note(_CLEANUP_NOTE)

    if fresh is not None:
        if error is None:
            try:
                fresh.fsync()
            except BaseException as caught:
                error = caught
        if error is not None and connection_released and cleanup_identities_bound:
            fresh.remove(error)
        elif error is not None and not initialization_guard_retained and not connection_released:
            error.add_note("fresh database retained because migration connection close failed")
        elif error is not None and not initialization_guard_retained:
            error.add_note("fresh database retained because cleanup identities were unavailable")
        error = fresh.close(error)

    if error is not None:
        raise error.with_traceback(error.__traceback__)
