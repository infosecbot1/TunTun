from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Literal

from sqlcipher3 import dbapi2 as sqlcipher3  # type: ignore[import-untyped]
from tuntun_core.config.secure_paths import (
    OwnedDirectory,
    ensure_private_directory,
    open_owned_directory,
)

NOFOLLOW = os.O_NOFOLLOW
CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NONBLOCK | NOFOLLOW
# Official SQLite value; sqlcipher3 0.6.2 does not export it.
# https://sqlite.org/c3ref/c_open_autoproxy.html
SQLITE_OPEN_NOFOLLOW = 0x01000000
SQLCIPHER_OPEN_FLAGS = (
    sqlcipher3.SQLITE_OPEN_READWRITE
    | sqlcipher3.SQLITE_OPEN_FULLMUTEX
    | sqlcipher3.SQLITE_OPEN_PRIVATECACHE
    | SQLITE_OPEN_NOFOLLOW
)
_OPEN_LOCK = Lock()


def _reported_owner(name: str, value: os.stat_result) -> int:
    del name
    return value.st_uid


def _reported_device(name: str, value: os.stat_result) -> int:
    del name
    return value.st_dev


def _absolute_database_path(path: Path) -> Path:
    try:
        raw = os.fspath(path)
        if (
            type(raw) is not str
            or not raw
            or "\x00" in raw
            or raw.startswith(os.sep * 2)
            or any(component in {".", ".."} for component in raw.split(os.sep))
        ):
            raise PermissionError("unsafe database path")
        absolute = Path(os.path.abspath(raw))
        if absolute == Path("/") or absolute.name in {"", ".", ".."}:
            raise PermissionError("unsafe database path")
        return absolute
    except OSError:
        raise PermissionError("unsafe database path") from None


@dataclass(frozen=True, slots=True)
class FileIdentity:
    device: int
    inode: int
    owner: int
    mode: int
    links: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> FileIdentity:
        return cls(
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_mode,
            value.st_nlink,
        )


def _require_file(parent: OwnedDirectory, name: str) -> FileIdentity:
    named = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(named.st_mode)
        or _reported_owner(name, named) != os.geteuid()
        or named.st_nlink != 1
        or stat.S_IMODE(named.st_mode) != 0o600
        or _reported_device(name, named) != parent.device
    ):
        raise PermissionError("unsafe database path")
    return FileIdentity.from_stat(named)


def _optional_file(parent: OwnedDirectory, name: str) -> FileIdentity | None:
    try:
        return _require_file(parent, name)
    except FileNotFoundError:
        return None


def _create_exclusive_main(parent: OwnedDirectory, name: str) -> FileIdentity:
    fd = os.open(name, CREATE_FLAGS, 0o600, dir_fd=parent.fd)
    try:
        os.fchmod(fd, 0o600)
        opened = os.fstat(fd)
        named = _require_file(parent, name)
        if not stat.S_ISREG(opened.st_mode) or FileIdentity.from_stat(opened) != named:
            raise PermissionError("unsafe database path")
    finally:
        # Creation is allowed only before any reservation, and this close must
        # complete before sqlcipher3.connect can own a lock-bearing descriptor.
        os.close(fd)
    if _require_file(parent, name) != named:
        raise PermissionError("unsafe database path")
    return named


@dataclass(slots=True)
class _RegistryState:
    main_identity: FileIdentity
    active: int = 0
    initializing: int = 0
    failed_closes: int = 0


@dataclass(frozen=True, slots=True)
class RegistrySnapshot:
    main_identity: FileIdentity
    active: int
    initializing: int
    failed_closes: int


@dataclass(slots=True)
class _Reservation:
    path: Path
    main_identity: FileIdentity
    phase: Literal["initializing", "active"] = "initializing"
    failed_close: bool = False
    released: bool = False


_ACTIVE_DATABASES: dict[Path, _RegistryState] = {}


def _reject_registered_identity_alias(path: Path, identity: FileIdentity) -> None:
    aliases = [
        state
        for registered_path, state in _ACTIVE_DATABASES.items()
        if registered_path != path
        and (state.main_identity.device, state.main_identity.inode)
        == (identity.device, identity.inode)
    ]
    if any(state.failed_closes for state in aliases):
        raise RuntimeError("prior SQLCipher close failed; retry close or abort process")
    if aliases:
        raise PermissionError("unsafe database path")


def _registry_snapshot(path: Path) -> RegistrySnapshot | None:
    absolute = _absolute_database_path(path)
    with _OPEN_LOCK:
        state = _ACTIVE_DATABASES.get(absolute)
        if state is None:
            return None
        return RegistrySnapshot(
            state.main_identity,
            state.active,
            state.initializing,
            state.failed_closes,
        )


def _reserve_initializing(path: Path, identity: FileIdentity) -> _Reservation:
    _reject_registered_identity_alias(path, identity)
    state = _ACTIVE_DATABASES.get(path)
    if state is None:
        state = _RegistryState(identity)
        _ACTIVE_DATABASES[path] = state
    elif state.main_identity != identity:
        raise PermissionError("unsafe database path")
    if state.failed_closes:
        raise RuntimeError("prior SQLCipher close failed; retry close or abort process")
    state.initializing += 1
    return _Reservation(path, identity)


def _publish_reservation(reservation: _Reservation) -> None:
    state = _ACTIVE_DATABASES[reservation.path]
    if reservation.phase != "initializing" or reservation.released:
        raise RuntimeError("invalid database reservation")
    state.initializing -= 1
    state.active += 1
    reservation.phase = "active"


def _mark_reservation_close_failed(reservation: _Reservation) -> None:
    if reservation.released or reservation.failed_close:
        return
    _ACTIVE_DATABASES[reservation.path].failed_closes += 1
    reservation.failed_close = True


def _remove_empty_registry(path: Path, state: _RegistryState) -> None:
    if state.active == state.initializing == state.failed_closes == 0:
        del _ACTIVE_DATABASES[path]


def _rollback_reservation_after_close(reservation: _Reservation) -> None:
    state = _ACTIVE_DATABASES[reservation.path]
    if reservation.phase != "initializing" or reservation.released:
        raise RuntimeError("invalid database reservation")
    state.initializing -= 1
    if reservation.failed_close:
        state.failed_closes -= 1
    reservation.released = True
    _remove_empty_registry(reservation.path, state)


def _release_reservation_after_close(reservation: _Reservation) -> None:
    state = _ACTIVE_DATABASES[reservation.path]
    if reservation.phase != "active" or reservation.released:
        raise RuntimeError("invalid database reservation")
    state.active -= 1
    if reservation.failed_close:
        state.failed_closes -= 1
    reservation.released = True
    _remove_empty_registry(reservation.path, state)


@dataclass(slots=True)
class DatabasePathGuard:
    path: Path
    parent: OwnedDirectory
    main_identity: FileIdentity
    reservation: _Reservation
    sidecar_identities: tuple[tuple[str, FileIdentity], ...] = ()
    _registry_released: bool = False
    _closed: bool = False

    def qualify_materialized_sidecars(self) -> None:
        previous = dict(self.sidecar_identities)
        current = []
        try:
            for suffix in ("-wal", "-shm"):
                identity = _require_file(self.parent, self.path.name + suffix)
                if suffix in previous and previous[suffix] != identity:
                    raise PermissionError("unsafe database path")
                current.append((suffix, identity))
        except OSError:
            raise PermissionError("unsafe database path") from None
        self.sidecar_identities = tuple(current)

    def revalidate(self) -> None:
        if self._closed:
            raise PermissionError("unsafe database path")
        try:
            self.parent.revalidate()
            if _require_file(self.parent, self.path.name) != self.main_identity:
                raise PermissionError("unsafe database path")
            for suffix, identity in self.sidecar_identities:
                if _require_file(self.parent, self.path.name + suffix) != identity:
                    raise PermissionError("unsafe database path")
        except OSError:
            raise PermissionError("unsafe database path") from None

    def publish_locked(self) -> None:
        _publish_reservation(self.reservation)

    def mark_sqlcipher_close_failed_locked(self) -> None:
        _mark_reservation_close_failed(self.reservation)

    def _release_registry_after_sqlcipher_close_locked(self) -> None:
        if self._registry_released:
            return
        if self.reservation.phase == "initializing":
            _rollback_reservation_after_close(self.reservation)
        else:
            _release_reservation_after_close(self.reservation)
        self._registry_released = True

    def _close_parent_after_release(self) -> None:
        if not self._closed:
            self.parent.close()
            self._closed = True

    def rollback_connect_failure_locked(self) -> None:
        # No returned SQLCipher handle exists: connect either was not called or
        # its failing constructor/deallocator completed before control returned.
        self._release_registry_after_sqlcipher_close_locked()
        self._close_parent_after_release()


def _open_qualified_database(path: Path) -> DatabasePathGuard:
    absolute = _absolute_database_path(path)
    registered = _ACTIVE_DATABASES.get(absolute)
    if registered is not None and registered.failed_closes:
        raise RuntimeError("prior SQLCipher close failed; retry close or abort process")
    parent: OwnedDirectory | None = None
    try:
        identity = ensure_private_directory(absolute.parent)
        parent = open_owned_directory(identity.path)
        parent.revalidate()
        main = _optional_file(parent, absolute.name)
        if main is None:
            if registered is not None:
                raise PermissionError("unsafe database path")
            main = _create_exclusive_main(parent, absolute.name)
        elif registered is not None and registered.main_identity != main:
            raise PermissionError("unsafe database path")
        _reject_registered_identity_alias(absolute, main)
        sidecars = tuple(
            (suffix, value)
            for suffix in ("-wal", "-shm")
            if (value := _optional_file(parent, absolute.name + suffix)) is not None
        )
        reservation = _reserve_initializing(absolute, main)
        guard = DatabasePathGuard(absolute, parent, main, reservation, sidecars)
        parent = None
        return guard
    except OSError:
        raise PermissionError("unsafe database path") from None
    finally:
        if parent is not None:
            parent.close()


def qualified_database_identity(path: Path) -> tuple[int, int]:
    with _OPEN_LOCK:
        absolute = _absolute_database_path(path)
        try:
            identity = ensure_private_directory(absolute.parent)
            with open_owned_directory(identity.path) as parent:
                parent.revalidate()
                main = _require_file(parent, absolute.name)
                _reject_registered_identity_alias(absolute, main)
                registered = _ACTIVE_DATABASES.get(absolute)
                if registered is not None and registered.main_identity != main:
                    raise PermissionError("unsafe database path")
                return main.device, main.inode
        except OSError:
            raise PermissionError("unsafe database path") from None


class SQLCipherCleanupError(RuntimeError):
    def __init__(
        self,
        connection: sqlcipher3.Connection,
        initialization_error: BaseException,
        close_error: BaseException,
        guard: DatabasePathGuard | None,
    ) -> None:
        super().__init__(
            "SQLCipher initialization failed and close failed; retry close or abort process"
        )
        self.connection = connection
        self.guard = guard
        self.initialization_error = initialization_error
        self.close_error = close_error


class QualifiedSQLCipherConnection(sqlcipher3.Connection):  # type: ignore[misc]
    _path_guard: DatabasePathGuard | None = None

    def _bind_path_guard(self, guard: DatabasePathGuard) -> None:
        if self._path_guard is not None:
            raise RuntimeError("path guard already bound")
        self._path_guard = guard

    def revalidate_storage_path(self) -> None:
        if self._path_guard is None:
            raise PermissionError("unsafe database path")
        self._path_guard.revalidate()

    def guarded_parent_descriptor(self) -> int:
        if self._path_guard is None:
            raise PermissionError("unsafe database path")
        return self._path_guard.parent.fd

    def storage_identities(
        self,
    ) -> tuple[FileIdentity, tuple[tuple[str, FileIdentity], ...]]:
        if self._path_guard is None:
            raise PermissionError("unsafe database path")
        return self._path_guard.main_identity, self._path_guard.sidecar_identities

    def _close_sqlcipher_base(self) -> None:
        super().close()

    def _close_after_initialization_failure_locked(self) -> None:
        guard = self._path_guard
        if guard is None:
            self._close_sqlcipher_base()
            return
        try:
            self._close_sqlcipher_base()
        except BaseException:
            guard.mark_sqlcipher_close_failed_locked()
            raise
        guard._release_registry_after_sqlcipher_close_locked()
        guard._close_parent_after_release()
        self._path_guard = None

    def close(self) -> None:
        guard = self._path_guard
        if guard is None:
            self._close_sqlcipher_base()
            return
        with _OPEN_LOCK:
            try:
                self._close_sqlcipher_base()
            except BaseException:
                guard.mark_sqlcipher_close_failed_locked()
                raise
            guard._release_registry_after_sqlcipher_close_locked()
        guard._close_parent_after_release()
        self._path_guard = None

    def __del__(self) -> None:
        # Leak protection only. A failure becomes Python's unraisable cleanup
        # report; it never releases the reservation or parent out of order.
        if self._path_guard is not None:
            self.close()


_CHECKPOINTS = frozenset(
    {
        "key_validation",
        "keyed_read",
        "wal_activation",
        "sidecar_metadata",
        "integrity",
    }
)


def _initialization_checkpoint(name: str) -> None:
    if name not in _CHECKPOINTS:
        raise AssertionError("unknown initialization checkpoint")


def open_sqlcipher(path: Path, key: bytes) -> sqlcipher3.Connection:
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("SQLCipher key must be exactly 32 bytes")
    if sqlcipher3.sqlite_version_info < (3, 31, 0):
        raise RuntimeError("bundled SQLite lacks SQLITE_OPEN_NOFOLLOW")
    with _OPEN_LOCK:
        guard: DatabasePathGuard | None = _open_qualified_database(path)
        connection: sqlcipher3.Connection | None = None
        try:
            assert guard is not None
            guard.revalidate()  # immediately before the pathname reopen
            connection = sqlcipher3.connect(
                os.fspath(guard.path),
                isolation_level=None,
                check_same_thread=False,
                flags=SQLCIPHER_OPEN_FLAGS,
                factory=QualifiedSQLCipherConnection,
            )
            if not isinstance(connection, QualifiedSQLCipherConnection):
                raise RuntimeError("SQLCipher connection guard unavailable")
            connection._bind_path_guard(guard)
            guard = None
            connection.revalidate_storage_path()  # after connect, before key
            # This must remain the first SQL statement issued on the connection.
            connection.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
            _initialization_checkpoint("key_validation")
            connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
            _initialization_checkpoint("keyed_read")
            version = connection.execute("PRAGMA cipher_version").fetchone()
            if version is None or not version[0]:
                raise RuntimeError("SQLCipher support is unavailable")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            if connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                raise RuntimeError("SQLCipher WAL mode is unavailable")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("ROLLBACK")
            _initialization_checkpoint("wal_activation")
            assert connection._path_guard is not None
            connection._path_guard.qualify_materialized_sidecars()
            _initialization_checkpoint("sidecar_metadata")
            connection.revalidate_storage_path()  # after keyed read/WAL setup
            listed = connection.execute("PRAGMA database_list").fetchall()
            assert connection._path_guard is not None
            expected = os.fspath(connection._path_guard.path)
            if [row[2] for row in listed if row[1] == "main"] != [expected]:
                raise PermissionError("unsafe database path")
            integrity_errors = connection.execute("PRAGMA cipher_integrity_check").fetchall()
            if integrity_errors:
                raise RuntimeError("SQLCipher integrity check failed")
            _initialization_checkpoint("integrity")
            connection._path_guard.publish_locked()
            return connection
        except BaseException as initialization_error:
            if connection is not None:
                try:
                    if isinstance(connection, QualifiedSQLCipherConnection):
                        connection._close_after_initialization_failure_locked()
                    else:
                        connection.close()
                except BaseException as close_error:
                    raise SQLCipherCleanupError(
                        connection,
                        initialization_error,
                        close_error,
                        guard,
                    ) from close_error
            if guard is not None:
                guard.rollback_connect_failure_locked()
            raise
