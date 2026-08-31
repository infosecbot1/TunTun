from __future__ import annotations

from collections.abc import Callable, Mapping
from time import sleep
from types import TracebackType
from typing import Any, Literal

from sqlalchemy import Engine
from sqlalchemy.engine import Connection, CursorResult
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import Executable

_BUSY_RETRY_DELAYS = (0.025, 0.050, 0.100)
_CLEANUP_NOTE = "additional unit-of-work cleanup failure"
_SQLITE_PRIMARY_RESULT_MASK = 0xFF
_SQLITE_BUSY_OR_LOCKED = frozenset((5, 6))


def _record_cleanup_failure(
    primary: BaseException,
    action: str,
    cleanup_error: BaseException,
) -> None:
    primary.add_note(f"{_CLEANUP_NOTE} ({action}): {type(cleanup_error).__name__}: {cleanup_error}")


def _is_busy_error(error: OperationalError) -> bool:
    sqlite_errorcode = getattr(error.orig, "sqlite_errorcode", None)
    if type(sqlite_errorcode) is int and sqlite_errorcode >= 0:
        primary_result = sqlite_errorcode & _SQLITE_PRIMARY_RESULT_MASK
        return primary_result in _SQLITE_BUSY_OR_LOCKED
    message = str(error.orig).strip().casefold()
    return any(
        message == prefix or message.startswith(f"{prefix}:")
        for prefix in (
            "database is locked",
            "database table is locked",
            "database schema is locked",
        )
    )


class UnitOfWork:
    def __init__(
        self,
        engine: Engine,
        sleeper: Callable[[float], None] = sleep,
    ) -> None:
        self.engine = engine
        self.sleeper = sleeper
        self.connection: Connection | None = None
        self._finished = False
        self._entered = False
        self._begun = False
        self._closed = False

    def __enter__(self) -> UnitOfWork:
        if self._closed:
            raise RuntimeError("unit of work is closed")
        if self._entered:
            raise RuntimeError("unit of work cannot be reused")
        self._entered = True
        try:
            self.connection = self.engine.connect()
        except BaseException:
            self._closed = True
            raise
        try:
            for attempt in range(len(_BUSY_RETRY_DELAYS) + 1):
                try:
                    self.connection.exec_driver_sql("BEGIN IMMEDIATE")
                    self._begun = True
                    return self
                except OperationalError as error:
                    if not _is_busy_error(error) or attempt == len(_BUSY_RETRY_DELAYS):
                        raise
                    self.sleeper(_BUSY_RETRY_DELAYS[attempt])
            raise AssertionError("unreachable")
        except BaseException as error:
            try:
                self.connection.close()
            except BaseException as close_error:
                _record_cleanup_failure(error, "close", close_error)
            else:
                self._closed = True
            raise

    def _active_connection(self) -> Connection:
        if (
            self.connection is None
            or not self._entered
            or not self._begun
            or self._finished
            or self._closed
        ):
            raise RuntimeError("unit of work is not active")
        return self.connection

    @property
    def active(self) -> bool:
        return (
            self.connection is not None
            and self._entered
            and self._begun
            and not self._finished
            and not self._closed
        )

    @property
    def closed(self) -> bool:
        return self._closed

    def execute(
        self,
        statement: Executable,
        parameters: Mapping[str, object] | None = None,
    ) -> CursorResult[Any]:
        return self._active_connection().execute(statement, parameters or {})

    def exec_driver_sql(
        self,
        statement: str,
        parameters: tuple[object, ...] | Mapping[str, object] = (),
    ) -> CursorResult[Any]:
        return self._active_connection().exec_driver_sql(statement, parameters)

    def commit(self) -> None:
        self._active_connection().commit()
        self._finished = True

    def rollback(self) -> None:
        connection = self._active_connection()
        connection.rollback()
        self._finished = True

    def _terminate(self, primary: BaseException | None) -> BaseException | None:
        if self.connection is None:
            self._closed = True
            return primary
        if self._begun and not self._finished:
            try:
                self.rollback()
            except BaseException as rollback_error:
                if primary is None:
                    primary = rollback_error
                else:
                    _record_cleanup_failure(primary, "rollback", rollback_error)
        if not self._closed:
            try:
                self.connection.close()
            except BaseException as close_error:
                if primary is None:
                    primary = close_error
                else:
                    _record_cleanup_failure(primary, "close", close_error)
            else:
                self._closed = True
        return primary

    def close(self) -> None:
        """Abort if needed and retry terminal close without dropping ownership."""

        if self._closed:
            return
        primary = self._terminate(None)
        if primary is not None:
            raise primary

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        del exc_type, traceback
        primary = self._terminate(exc)
        if primary is not None and primary is not exc:
            raise primary
        return False
