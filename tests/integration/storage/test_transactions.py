from __future__ import annotations

import ast
import inspect
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError
from tuntun_core.adapters.sqlcipher.connection import open_sqlcipher
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork
from tuntun_core.services.transactions import mutation_scope, protocols
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol

HOUSEHOLD_INSERT = text(
    "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) "
    "VALUES(:id,:label,'Asia/Singapore',:now)"
)


def _household(identifier: str) -> dict[str, object]:
    return {
        "id": identifier,
        "label": b"ciphertext",
        "now": "2026-08-27T01:02:03.000004Z",
    }


def _household_count(engine: object) -> int:
    with engine.connect() as connection:  # type: ignore[attr-defined]
        return int(connection.execute(text("SELECT count(*) FROM households")).scalar_one())


def test_context_rolls_back_without_explicit_commit(migrated_database: object) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    with UnitOfWork(engine) as uow:
        uow.execute(
            HOUSEHOLD_INSERT,
            _household("00000000-0000-0000-0000-000000000601"),
        )

    assert _household_count(engine) == 0


def test_exception_rolls_back_without_explicit_commit(migrated_database: object) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    try:
        with UnitOfWork(engine) as uow:
            uow.execute(
                HOUSEHOLD_INSERT,
                _household("00000000-0000-0000-0000-000000000602"),
            )
            raise RuntimeError("kill-point")
    except RuntimeError as error:
        assert str(error) == "kill-point"

    assert _household_count(engine) == 0


def test_explicit_commit_persists(migrated_database: object) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    with UnitOfWork(engine) as uow:
        uow.execute(
            HOUSEHOLD_INSERT,
            _household("00000000-0000-0000-0000-000000000603"),
        )
        uow.commit()

    assert _household_count(engine) == 1


def test_adapter_structurally_satisfies_service_protocol(migrated_database: object) -> None:
    uow = UnitOfWork(migrated_database.engine)  # type: ignore[attr-defined]
    assert isinstance(uow, UnitOfWorkProtocol)


def test_service_protocol_has_no_adapter_dependency() -> None:
    imported: set[str] = set()
    for module in (protocols, mutation_scope):
        tree = ast.parse(inspect.getsource(module))
        imported.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        imported.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
    assert not any(name.startswith("tuntun_core.adapters") for name in imported)


def test_read_connection_does_not_implicitly_take_writer_slot(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    with engine.connect() as reader:
        assert reader.execute(text("SELECT count(*) FROM households")).scalar_one() == 0
        with UnitOfWork(engine) as writer:
            writer.execute(
                HOUSEHOLD_INSERT,
                _household("00000000-0000-0000-0000-000000000604"),
            )
            writer.rollback()

    assert _household_count(engine) == 0


class _CodedDbApiError(RuntimeError):
    def __init__(self, message: str, sqlite_errorcode: int) -> None:
        super().__init__(message)
        self.sqlite_errorcode = sqlite_errorcode


def _operational_error(
    message: str,
    *,
    sqlite_errorcode: int | None = None,
) -> OperationalError:
    original = (
        RuntimeError(message)
        if sqlite_errorcode is None
        else _CodedDbApiError(message, sqlite_errorcode)
    )
    return OperationalError("BEGIN IMMEDIATE", (), original)


class _ScriptedConnection:
    def __init__(
        self,
        begin_outcomes: list[OperationalError | None],
        *,
        commit_error: BaseException | None = None,
        rollback_outcomes: list[BaseException | None] | None = None,
        close_outcomes: list[BaseException | None] | None = None,
    ) -> None:
        self._begin_outcomes = begin_outcomes
        self._commit_error = commit_error
        self._rollback_outcomes = rollback_outcomes or []
        self._close_outcomes = close_outcomes or []
        self.begin_count = 0
        self.commit_count = 0
        self.rollback_count = 0
        self.close_count = 0
        self.closed = False

    def exec_driver_sql(
        self,
        statement: str,
        parameters: tuple[object, ...] | Mapping[str, object] = (),
    ) -> object:
        del parameters
        assert statement == "BEGIN IMMEDIATE"
        self.begin_count += 1
        outcome = self._begin_outcomes.pop(0)
        if outcome is not None:
            raise outcome
        return object()

    def execute(self, statement: object, parameters: Mapping[str, object]) -> object:
        del statement, parameters
        return object()

    def commit(self) -> None:
        self.commit_count += 1
        if self._commit_error is not None:
            raise self._commit_error

    def rollback(self) -> None:
        self.rollback_count += 1
        if self._rollback_outcomes:
            outcome = self._rollback_outcomes.pop(0)
            if outcome is not None:
                raise outcome

    def close(self) -> None:
        self.close_count += 1
        if self._close_outcomes:
            outcome = self._close_outcomes.pop(0)
            if outcome is not None:
                raise outcome
        self.closed = True


class _ScriptedEngine:
    def __init__(self, connection: _ScriptedConnection) -> None:
        self.connection = connection
        self.connect_count = 0

    def connect(self) -> _ScriptedConnection:
        self.connect_count += 1
        return self.connection


def _scripted_uow(
    connection: _ScriptedConnection,
    sleeper: Callable[[float], None] = lambda _delay: None,
) -> tuple[UnitOfWork, _ScriptedEngine]:
    engine = _ScriptedEngine(connection)
    return UnitOfWork(cast(Engine, engine), sleeper=sleeper), engine


def test_busy_begin_retries_same_owned_connection_with_bounded_delays() -> None:
    delays: list[float] = []
    connection = _ScriptedConnection(
        [
            _operational_error("database is locked"),
            _operational_error("database table is locked"),
            _operational_error("database is locked"),
            None,
        ]
    )
    uow, engine = _scripted_uow(connection, delays.append)

    with uow:
        uow.rollback()

    assert engine.connect_count == 1
    assert connection.begin_count == 4
    assert delays == [0.025, 0.050, 0.100]
    assert connection.close_count == 1


def test_non_busy_begin_error_is_not_retried_and_connection_is_closed() -> None:
    failure = _operational_error("synthetic disk I/O error")
    connection = _ScriptedConnection([failure])
    uow, engine = _scripted_uow(connection)

    with pytest.raises(OperationalError) as raised:
        uow.__enter__()

    assert raised.value is failure
    assert engine.connect_count == 1
    assert connection.begin_count == 1
    assert connection.close_count == 1


def test_non_busy_message_containing_locked_is_not_misclassified() -> None:
    failure = _operational_error("database is not locked")
    connection = _ScriptedConnection([failure])
    delays: list[float] = []
    uow, _ = _scripted_uow(connection, delays.append)

    with pytest.raises(OperationalError) as raised:
        uow.__enter__()

    assert raised.value is failure
    assert connection.begin_count == 1
    assert delays == []
    assert connection.closed


@pytest.mark.parametrize("sqlite_errorcode", (5, 6, 261, 262, 517, 518, 773))
def test_sqlite_busy_and_locked_primary_or_extended_codes_are_retried(
    sqlite_errorcode: int,
) -> None:
    delays: list[float] = []
    connection = _ScriptedConnection(
        [_operational_error("driver-specific busy text", sqlite_errorcode=sqlite_errorcode), None]
    )
    uow, _ = _scripted_uow(connection, delays.append)

    with uow:
        uow.rollback()

    assert connection.begin_count == 2
    assert delays == [0.025]
    assert connection.closed


def test_non_busy_sqlite_code_overrides_a_misleading_locked_message() -> None:
    failure = _operational_error("database is locked", sqlite_errorcode=10)
    connection = _ScriptedConnection([failure])
    delays: list[float] = []
    uow, _ = _scripted_uow(connection, delays.append)

    with pytest.raises(OperationalError) as raised:
        uow.__enter__()

    assert raised.value is failure
    assert connection.begin_count == 1
    assert delays == []
    assert connection.closed


def test_actual_sqlcipher_busy_error_shape_is_classified_by_result_code(
    tmp_path: Path,
) -> None:
    path = tmp_path / "busy-shape.db"
    key = bytes(range(32))
    first = open_sqlcipher(path, key)
    second = open_sqlcipher(path, key)
    try:
        first.execute("CREATE TABLE busy_probe(value INTEGER)")
        first.commit()
        second.execute("PRAGMA busy_timeout=0")
        first.execute("BEGIN IMMEDIATE")
        with pytest.raises(Exception) as raised:
            second.execute("BEGIN IMMEDIATE")
        original = raised.value
        assert getattr(original, "sqlite_errorcode", None) == 5
        assert getattr(original, "sqlite_errorname", None) == "SQLITE_BUSY"
    finally:
        first.rollback()
        first.close()
        second.close()

    failure = OperationalError("BEGIN IMMEDIATE", (), original)
    delays: list[float] = []
    connection = _ScriptedConnection([failure, None])
    uow, _ = _scripted_uow(connection, delays.append)
    with uow:
        uow.rollback()

    assert connection.begin_count == 2
    assert delays == [0.025]


def test_retry_sleeper_failure_retains_connection_until_close_retry() -> None:
    sleep_error = RuntimeError("synthetic sleeper failure")
    close_error = RuntimeError("synthetic close failure")
    connection = _ScriptedConnection(
        [_operational_error("database is locked")],
        close_outcomes=[close_error, None],
    )

    def fail_sleep(delay: float) -> None:
        assert delay == 0.025
        raise sleep_error

    uow, _ = _scripted_uow(connection, fail_sleep)
    with pytest.raises(RuntimeError) as raised:
        uow.__enter__()

    assert raised.value is sleep_error
    assert any("close failure" in note for note in getattr(raised.value, "__notes__", ()))
    assert not connection.closed
    uow.close()
    assert connection.closed


def test_exhausted_busy_error_survives_a_secondary_close_failure() -> None:
    failures = [_operational_error("database is locked") for _ in range(4)]
    terminal_failure = failures[-1]
    close_error = RuntimeError("synthetic close failure")
    connection = _ScriptedConnection(failures, close_outcomes=[close_error, None])
    uow, _ = _scripted_uow(connection)

    with pytest.raises(OperationalError) as raised:
        uow.__enter__()

    assert raised.value is terminal_failure
    assert connection.begin_count == 4
    assert connection.close_count == 1
    assert not connection.closed
    assert any("close failure" in note for note in getattr(raised.value, "__notes__", ()))
    uow.close()
    assert connection.closed
    assert connection.close_count == 2


def test_body_error_survives_rollback_and_close_failures() -> None:
    rollback_error = RuntimeError("synthetic rollback failure")
    close_error = RuntimeError("synthetic close failure")
    connection = _ScriptedConnection(
        [None],
        rollback_outcomes=[rollback_error, None],
        close_outcomes=[close_error, None],
    )
    uow, _ = _scripted_uow(connection)
    body_error = ValueError("body remains primary")

    with pytest.raises(ValueError) as raised, uow:
        raise body_error

    assert raised.value is body_error
    notes = getattr(raised.value, "__notes__", ())
    assert any("rollback failure" in note for note in notes)
    assert any("close failure" in note for note in notes)
    assert connection.rollback_count == 1
    assert connection.close_count == 1
    assert not connection.closed
    uow.close()
    assert connection.rollback_count == 2
    assert connection.close_count == 2
    assert connection.closed


def test_commit_error_survives_exit_cleanup_failures() -> None:
    commit_error = RuntimeError("synthetic commit failure")
    connection = _ScriptedConnection(
        [None],
        commit_error=commit_error,
        rollback_outcomes=[RuntimeError("synthetic rollback failure"), None],
        close_outcomes=[RuntimeError("synthetic close failure"), None],
    )
    uow, _ = _scripted_uow(connection)

    with pytest.raises(RuntimeError) as raised, uow:
        uow.commit()

    assert raised.value is commit_error
    notes = getattr(raised.value, "__notes__", ())
    assert any("rollback failure" in note for note in notes)
    assert any("close failure" in note for note in notes)
    assert connection.commit_count == 1
    assert connection.rollback_count == 1
    assert connection.close_count == 1
    assert not connection.closed
    uow.close()
    assert connection.closed


def test_begin_failure_retains_connection_until_retry_close_succeeds() -> None:
    begin_error = _operational_error("synthetic disk I/O error")
    close_error = RuntimeError("synthetic close failure")
    connection = _ScriptedConnection(
        [begin_error],
        close_outcomes=[close_error, None],
    )
    uow, _ = _scripted_uow(connection)

    with pytest.raises(OperationalError) as raised:
        uow.__enter__()

    assert raised.value is begin_error
    assert not connection.closed
    with pytest.raises(RuntimeError, match="not active"):
        uow.exec_driver_sql("SELECT 1")
    uow.close()
    assert connection.closed


def test_post_commit_close_failure_retains_retryable_connection_ownership() -> None:
    close_error = RuntimeError("synthetic close failure")
    connection = _ScriptedConnection([None], close_outcomes=[close_error, None])
    uow, _ = _scripted_uow(connection)

    with pytest.raises(RuntimeError) as raised, uow:
        uow.commit()

    assert raised.value is close_error
    assert connection.commit_count == 1
    assert not connection.closed
    uow.close()
    assert connection.closed
    assert connection.commit_count == 1


def test_unit_of_work_instance_cannot_be_entered_twice() -> None:
    connection = _ScriptedConnection([None])
    uow, engine = _scripted_uow(connection)

    with uow:
        with pytest.raises(RuntimeError, match="cannot be reused"):
            uow.__enter__()
        uow.rollback()

    assert engine.connect_count == 1


def test_close_before_enter_permanently_rejects_later_entry() -> None:
    connection = _ScriptedConnection([None])
    uow, engine = _scripted_uow(connection)

    uow.close()
    uow.close()
    with pytest.raises(RuntimeError, match="closed"):
        uow.__enter__()

    assert engine.connect_count == 0
    assert connection.begin_count == 0
