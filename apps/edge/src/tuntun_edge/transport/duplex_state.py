from __future__ import annotations

import asyncio
import errno
import os
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, Protocol, TypeVar
from uuid import UUID

from tuntun_contracts.base import JCS_MAX_SAFE_INTEGER
from tuntun_contracts.reachy_wire import Direction, FrameKind, FramePurpose

EDGE_DUPLEX_ROOT: Final = Path("/private/var/lib/tuntun/reachy")
EDGE_DUPLEX_DB: Final = EDGE_DUPLEX_ROOT / "duplex-state.sqlite3"
_SCHEMA_VERSION: Final = 1
_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_DB_OPEN_FLAGS: Final = os.O_RDWR | _CLOEXEC | _NOFOLLOW
_DB_CREATE_FLAGS: Final = os.O_RDWR | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW
_DIR_OPEN_FLAGS: Final = os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW
_PURPOSES: Final[frozenset[str]] = frozenset(
    (
        "reachy.command.v1",
        "reachy.health.v1",
        "reachy.stop_all.v1",
        "reachy.camera_grant.v1",
        "reachy.event.v1",
        "reachy.media_control.v1",
    )
)
_KINDS: Final[frozenset[str]] = frozenset(("request", "response", "event"))
_DIRECTIONS: Final[frozenset[str]] = frozenset(("edge_to_core", "core_to_edge"))
_PENDING_CORRELATION_LIMIT: Final = 256
_TERMINAL_CORRELATION_RETENTION_LIMIT: Final = 4_096
_EDGE_INTEGRITY_CHECK_WRITE_INTERVAL: Final = 256
_ResultT = TypeVar("_ResultT")

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS edge_duplex_sequences(
    direction TEXT PRIMARY KEY CHECK(direction IN ('edge_to_core','core_to_edge')),
    last_sequence INTEGER NOT NULL CHECK(
        typeof(last_sequence)='integer'
        AND last_sequence BETWEEN 0 AND 9007199254740991
    )
);
CREATE TABLE IF NOT EXISTS edge_duplex_correlations(
    correlation_id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    request_direction TEXT NOT NULL CHECK(request_direction IN ('edge_to_core','core_to_edge')),
    state TEXT NOT NULL CHECK(state IN ('pending','completed','abandoned')),
    first_sequence INTEGER NOT NULL,
    last_sequence INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(typeof(first_sequence)='integer'),
    CHECK(typeof(last_sequence)='integer'),
    CHECK(first_sequence BETWEEN 1 AND 9007199254740991),
    CHECK(last_sequence BETWEEN first_sequence AND 9007199254740991)
);
"""


class Clock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    nlink: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _FileIdentity:
        return cls(
            value.st_dev,
            value.st_ino,
            stat.S_IMODE(value.st_mode),
            value.st_uid,
            value.st_nlink,
        )

    def same_file(self, value: os.stat_result) -> bool:
        return (self.device, self.inode) == (value.st_dev, value.st_ino)


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _DirectoryIdentity:
        return cls(value.st_dev, value.st_ino)

    def same_directory(self, value: os.stat_result) -> bool:
        return (self.device, self.inode) == (value.st_dev, value.st_ino)


class EdgeDuplexState:
    """Owner-only durable edge control state.

    The edge persists only edge-to-core transmit sequence, core-to-edge receive
    sequence, and correlation lifecycle rows. Payload bytes never enter this DB.
    """

    def __init__(
        self,
        path: Path = EDGE_DUPLEX_DB,
        clock: Clock | None = None,
        *,
        trusted_root: Path | None = None,
        expected_uid: int | None = None,
    ) -> None:
        self._clock = _require_clock(clock)
        self._path = _absolute_lexical_path(path)
        self._root = _absolute_lexical_path(trusted_root or self._path.parent)
        if self._path.parent != self._root:
            raise PermissionError("edge duplex trusted path mismatch")
        self._expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self._lock = asyncio.Lock()
        self._writes_since_integrity_check = 0
        self._ensure_root()
        root_fd = self._open_root_fd()
        try:
            self._file_identity = self._open_or_create_database(root_fd)
            self._root_identity = _DirectoryIdentity.from_stat(os.fstat(root_fd))
        finally:
            os.close(root_fd)
        self._initialize()

    async def reserve_outbound(
        self,
        correlation_id: UUID,
        purpose: FramePurpose,
        kind: FrameKind,
    ) -> int:
        _require_exact_uuid(correlation_id, "correlation_id")
        _require_purpose(purpose)
        _require_kind(kind)
        now = self._now()

        def reserve(db: sqlite3.Connection) -> int:
            previous = self._last_sequence(db, "edge_to_core")
            sequence = previous + 1
            _require_sequence_bounds(sequence)
            cursor = db.execute(
                "INSERT INTO edge_duplex_sequences(direction,last_sequence) "
                "VALUES('edge_to_core',?) "
                "ON CONFLICT(direction) DO UPDATE SET last_sequence=excluded.last_sequence "
                "WHERE last_sequence=?",
                (sequence, previous),
            )
            if cursor.rowcount != 1:
                raise PermissionError("sequence_allocation_conflict")
            self._advance_correlation(
                db,
                correlation_id,
                purpose,
                kind,
                "edge_to_core",
                sequence,
                now,
            )
            return sequence

        return await self._write(reserve)

    async def reserve_event_envelope_sequence(
        self,
        correlation_id: UUID,
        purpose: FramePurpose = "reachy.event.v1",
    ) -> int:
        return await self.reserve_outbound(correlation_id, purpose, "event")

    async def accept_inbound(
        self,
        sequence: int,
        correlation_id: UUID,
        purpose: FramePurpose,
        kind: FrameKind,
    ) -> None:
        _require_sequence(sequence)
        _require_exact_uuid(correlation_id, "correlation_id")
        _require_purpose(purpose)
        _require_kind(kind)
        now = self._now()

        def accept(db: sqlite3.Connection) -> None:
            previous = self._last_sequence(db, "core_to_edge")
            if sequence <= previous:
                raise PermissionError("replayed_sequence_or_correlation")
            if sequence != previous + 1:
                raise PermissionError("sequence_gap")
            cursor = db.execute(
                "INSERT INTO edge_duplex_sequences(direction,last_sequence) "
                "VALUES('core_to_edge',?) "
                "ON CONFLICT(direction) DO UPDATE SET last_sequence=excluded.last_sequence "
                "WHERE last_sequence=?",
                (sequence, previous),
            )
            if cursor.rowcount != 1:
                raise PermissionError("replayed_sequence_or_correlation")
            self._advance_correlation(
                db,
                correlation_id,
                purpose,
                kind,
                "core_to_edge",
                sequence,
                now,
            )

        await self._write(accept)

    async def accept_response(
        self,
        correlation_id: UUID,
        purpose: FramePurpose,
        payload: bytes,
    ) -> None:
        _require_exact_uuid(correlation_id, "correlation_id")
        _require_purpose(purpose)
        _require_payload_bytes(payload)

        def accept(db: sqlite3.Connection) -> None:
            row = db.execute(
                "SELECT 1 FROM edge_duplex_correlations "
                "WHERE correlation_id=? AND purpose=? "
                "AND request_direction='edge_to_core' AND state='pending'",
                (str(correlation_id), purpose),
            ).fetchone()
            if row is None:
                raise PermissionError("correlation_not_pending")

        await self._write(accept)

    async def complete(self, correlation_id: UUID) -> None:
        await self._terminal(correlation_id, "completed")

    async def abandon_correlation(self, correlation_id: UUID, reason: str) -> None:
        _require_reason(reason)
        await self._terminal(correlation_id, "abandoned")

    async def abandon_connection(self, reason: str) -> None:
        _require_reason(reason)
        now = self._now()

        def abandon(db: sqlite3.Connection) -> None:
            db.execute(
                "UPDATE edge_duplex_correlations SET state='abandoned',updated_at=? "
                "WHERE state='pending'",
                (now,),
            )

        await self._write(abandon)

    async def pending_for_replay(self) -> tuple[()]:
        return ()

    async def _terminal(
        self,
        correlation_id: UUID,
        state: Literal["completed", "abandoned"],
    ) -> None:
        _require_exact_uuid(correlation_id, "correlation_id")
        now = self._now()

        def finish(db: sqlite3.Connection) -> None:
            cursor = db.execute(
                "UPDATE edge_duplex_correlations SET state=?,updated_at=? "
                "WHERE correlation_id=? AND state='pending'",
                (state, now, str(correlation_id)),
            )
            if cursor.rowcount != 1:
                raise PermissionError("correlation_not_pending")

        await self._write(finish)

    def _advance_correlation(
        self,
        db: sqlite3.Connection,
        correlation_id: UUID,
        purpose: FramePurpose,
        kind: FrameKind,
        direction: Direction,
        sequence: int,
        now: str,
    ) -> None:
        row = db.execute(
            "SELECT purpose,request_direction,state FROM edge_duplex_correlations "
            "WHERE correlation_id=?",
            (str(correlation_id),),
        ).fetchone()
        if kind in {"request", "event"}:
            if row is not None:
                raise PermissionError("replayed_sequence_or_correlation")
            pending = db.execute(
                "SELECT COUNT(*) FROM edge_duplex_correlations WHERE state='pending'"
            ).fetchone()
            if pending is None or type(pending[0]) is not int:
                raise PermissionError("edge_duplex_store_corrupt")
            if pending[0] >= _PENDING_CORRELATION_LIMIT:
                raise PermissionError("pending_correlation_limit")
            db.execute(
                "INSERT INTO edge_duplex_correlations("
                "correlation_id,purpose,request_direction,state,"
                "first_sequence,last_sequence,created_at,updated_at"
                ") VALUES(?,?,?,?,?,?,?,?)",
                (str(correlation_id), purpose, direction, "pending", sequence, sequence, now, now),
            )
            return
        if kind != "response":
            raise ValueError("unsupported control frame kind")
        opposite = _opposite_direction(direction)
        if row is None or tuple(row) != (purpose, opposite, "pending"):
            raise PermissionError("correlation_not_pending")
        cursor = db.execute(
            "UPDATE edge_duplex_correlations SET last_sequence=?,updated_at=? "
            "WHERE correlation_id=? AND state='pending'",
            (sequence, now, str(correlation_id)),
        )
        if cursor.rowcount != 1:
            raise PermissionError("correlation_not_pending")

    async def _write(self, operation: Callable[[sqlite3.Connection], _ResultT]) -> _ResultT:
        async with self._lock:
            return await asyncio.to_thread(self._transaction, operation)

    def _transaction(self, operation: Callable[[sqlite3.Connection], _ResultT]) -> _ResultT:
        self._validate_store_identity()
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            value = operation(db)
            self._prune_terminal_correlations(db)
            next_writes_since_integrity_check = self._writes_since_integrity_check + 1
            run_integrity_check = (
                next_writes_since_integrity_check >= _EDGE_INTEGRITY_CHECK_WRITE_INTERVAL
            )
            if run_integrity_check:
                self._verify_integrity(db)
            db.commit()
            self._writes_since_integrity_check = (
                0 if run_integrity_check else next_writes_since_integrity_check
            )
            self._fsync_database()
            return value
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self) -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            for statement in _SCHEMA.strip().split(";"):
                if statement.strip():
                    db.execute(statement)
            db.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            self._verify_integrity(db)
            db.commit()
            self._fsync_database()
            self._fsync_root()
        except sqlite3.DatabaseError as error:
            db.rollback()
            raise PermissionError("edge_duplex_store_corrupt") from error
        finally:
            db.close()

    def _connect(self) -> sqlite3.Connection:
        pre_connect_identity = self._current_store_identity()
        try:
            db = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
        except sqlite3.DatabaseError as error:
            raise PermissionError("edge_duplex_store_corrupt") from error
        try:
            post_connect_identity = self._current_store_identity()
            if post_connect_identity != pre_connect_identity:
                raise PermissionError("edge_duplex_store_replaced")
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            return db
        except sqlite3.DatabaseError as error:
            db.close()
            raise PermissionError("edge_duplex_store_corrupt") from error
        except BaseException:
            db.close()
            raise

    def _prune_terminal_correlations(self, db: sqlite3.Connection) -> None:
        db.execute(
            "DELETE FROM edge_duplex_correlations "
            "WHERE rowid IN ("
            "SELECT rowid FROM edge_duplex_correlations "
            "WHERE state IN ('completed','abandoned') "
            "ORDER BY updated_at DESC,last_sequence DESC,correlation_id DESC "
            "LIMIT -1 OFFSET ?"
            ")",
            (_TERMINAL_CORRELATION_RETENTION_LIMIT,),
        )

    @staticmethod
    def _verify_integrity(db: sqlite3.Connection) -> None:
        try:
            integrity = db.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.DatabaseError as error:
            raise PermissionError("edge_duplex_store_corrupt") from error
        if integrity is None or integrity[0] != "ok":
            raise PermissionError("edge_duplex_store_corrupt")

    def _last_sequence(self, db: sqlite3.Connection, direction: Direction) -> int:
        _require_direction(direction)
        row = db.execute(
            "SELECT last_sequence FROM edge_duplex_sequences WHERE direction=?",
            (direction,),
        ).fetchone()
        if row is None:
            return 0
        return _bounded_sequence(row[0])

    def _ensure_root(self) -> None:
        try:
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise PermissionError("edge duplex trusted path invalid") from error
        identity = self._root.lstat()
        if not stat.S_ISDIR(identity.st_mode):
            raise PermissionError("edge duplex trusted path invalid")
        if stat.S_IMODE(identity.st_mode) != 0o700 or identity.st_uid != self._expected_uid:
            raise PermissionError("edge_duplex_parent_ownership_or_mode")

    def _open_root_fd(self) -> int:
        try:
            descriptor = os.open(self._root, _DIR_OPEN_FLAGS)
        except OSError as error:
            raise PermissionError("edge duplex trusted path invalid") from error
        try:
            identity = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(identity.st_mode)
                or stat.S_IMODE(identity.st_mode) != 0o700
                or identity.st_uid != self._expected_uid
            ):
                raise PermissionError("edge_duplex_parent_ownership_or_mode")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_or_create_database(self, root_fd: int) -> _FileIdentity:
        try:
            descriptor = os.open(self._path.name, _DB_OPEN_FLAGS, dir_fd=root_fd)
        except FileNotFoundError:
            descriptor = os.open(self._path.name, _DB_CREATE_FLAGS, 0o600, dir_fd=root_fd)
            try:
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                self._fsync_root_fd(root_fd)
            except BaseException:
                os.close(descriptor)
                raise
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                raise PermissionError("edge duplex trusted path invalid") from error
            raise
        try:
            opened = os.fstat(descriptor)
            named = os.stat(self._path.name, dir_fd=root_fd, follow_symlinks=False)
            identity = _FileIdentity.from_stat(opened)
            if (
                not identity.same_file(named)
                or not stat.S_ISREG(opened.st_mode)
                or identity.mode != 0o600
                or identity.uid != self._expected_uid
                or identity.nlink != 1
            ):
                raise PermissionError("edge_duplex_store_ownership_or_mode")
            return identity
        finally:
            os.close(descriptor)

    def _validate_store_identity(self) -> None:
        self._current_store_identity()

    def _current_store_identity(self) -> _FileIdentity:
        root_fd = self._open_root_fd()
        try:
            root_identity = os.fstat(root_fd)
            if not self._root_identity.same_directory(root_identity):
                raise PermissionError("edge_duplex_parent_replaced")
            opened = os.stat(self._path.name, dir_fd=root_fd, follow_symlinks=False)
            identity = _FileIdentity.from_stat(opened)
            if (
                not self._file_identity.same_file(opened)
                or not stat.S_ISREG(opened.st_mode)
                or identity.mode != 0o600
                or identity.uid != self._expected_uid
                or identity.nlink != 1
            ):
                raise PermissionError("edge_duplex_store_replaced")
            return identity
        finally:
            os.close(root_fd)

    def _fsync_database(self) -> None:
        root_fd = self._open_root_fd()
        try:
            descriptor = os.open(self._path.name, _DB_OPEN_FLAGS, dir_fd=root_fd)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            os.close(root_fd)

    def _fsync_root(self) -> None:
        root_fd = self._open_root_fd()
        try:
            self._fsync_root_fd(root_fd)
        finally:
            os.close(root_fd)

    @staticmethod
    def _fsync_root_fd(root_fd: int) -> None:
        os.fsync(root_fd)

    def _now(self) -> str:
        value = self._clock.now()
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise TypeError("stored timestamp must be timezone-aware")
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _absolute_lexical_path(path: Path) -> Path:
    raw = os.fspath(path)
    if type(raw) is not str or not raw or "\x00" in raw or not raw.startswith(os.sep):
        raise PermissionError("edge duplex trusted path invalid")
    if raw.startswith(os.sep * 2):
        raise PermissionError("edge duplex trusted path invalid")
    components = Path(raw).parts
    if any(component in {".", ".."} for component in components):
        raise PermissionError("edge duplex trusted path invalid")
    return Path(raw)


def _require_clock(clock: Clock | None) -> Clock:
    if clock is None or not callable(getattr(clock, "now", None)):
        raise TypeError("edge duplex clock required")
    return clock


def _require_direction(value: str) -> None:
    if type(value) is not str or value not in _DIRECTIONS:
        raise ValueError("unsupported control frame direction")


def _require_purpose(value: str) -> None:
    if type(value) is not str or value not in _PURPOSES:
        raise ValueError("unsupported control frame purpose")


def _require_kind(value: str) -> None:
    if type(value) is not str or value not in _KINDS:
        raise ValueError("unsupported control frame kind")


def _require_sequence(value: int) -> None:
    if type(value) is not int:
        raise TypeError("sequence must be an exact integer")
    _require_sequence_bounds(value)
    if value < 1:
        raise ValueError("sequence must be positive")


def _require_sequence_bounds(value: int) -> None:
    if not 0 <= value <= JCS_MAX_SAFE_INTEGER:
        raise ValueError("sequence outside JCS safe integer domain")


def _bounded_sequence(value: object) -> int:
    if type(value) is not int:
        raise ValueError("stored sequence must be an integer")
    _require_sequence_bounds(value)
    return value


def _require_exact_uuid(value: UUID, label: str) -> None:
    if type(value) is not UUID:
        raise TypeError(f"{label} must be an exact UUID")


def _require_reason(value: str) -> None:
    if type(value) is not str or not 1 <= len(value.encode("utf-8")) <= 128:
        raise ValueError("duplex terminal reason invalid")


def _require_payload_bytes(value: bytes) -> None:
    if type(value) is not bytes:
        raise TypeError("control response payload must be bytes")


def _opposite_direction(direction: Direction) -> Direction:
    if direction == "edge_to_core":
        return "core_to_edge"
    if direction == "core_to_edge":
        return "edge_to_core"
    raise ValueError("unsupported control frame direction")


__all__ = ("EDGE_DUPLEX_DB", "EDGE_DUPLEX_ROOT", "EdgeDuplexState")
