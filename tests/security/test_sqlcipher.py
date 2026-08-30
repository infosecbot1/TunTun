import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event, Thread

import pytest
from sqlcipher3 import dbapi2 as sqlcipher3
from tuntun_core.adapters.sqlcipher import connection as connection_module
from tuntun_core.adapters.sqlcipher.connection import (
    SQLCIPHER_OPEN_FLAGS,
    SQLITE_OPEN_NOFOLLOW,
    QualifiedSQLCipherConnection,
    open_sqlcipher,
    qualified_database_identity,
)
from tuntun_core.adapters.sqlcipher.probe import probe_storage
from tuntun_core.cli import main as cli_module
from tuntun_core.cli.commands import storage_probe as storage_probe_command
from typer.testing import CliRunner

KEY = bytes(range(32))
WRONG = bytes(reversed(range(32)))


def _database_path(tmp_path: Path, name: str = "foundation.db") -> Path:
    # pytest owns this root; canonicalize only its trusted Darwin /var alias.
    root = Path(os.path.realpath(tmp_path))
    private = root / "private"
    private.mkdir(mode=0o700, exist_ok=True)
    return private / name


@pytest.fixture
def short_database_root() -> Iterator[Path]:
    # Darwin limits AF_UNIX names to roughly 104 bytes. Resolve the trusted
    # /tmp alias so the production no-symlink walk still sees the real path.
    root = Path(os.path.realpath(tempfile.mkdtemp(prefix="tt-sql-", dir="/tmp")))
    root.chmod(0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root)


def _regular(path: Path, data: bytes = b"") -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def _exclusive_empty_main(path: Path) -> None:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        opened = os.fstat(fd)
        assert stat.S_ISREG(opened.st_mode)
        assert stat.S_IMODE(opened.st_mode) == 0o600
    finally:
        os.close(fd)
    assert os.stat(path, follow_symlinks=False).st_size == 0
    for suffix in ("-wal", "-shm"):
        with pytest.raises(FileNotFoundError):
            os.stat(os.fspath(path) + suffix, follow_symlinks=False)


def _identity(path: Path) -> tuple[int, int]:
    value = os.stat(path, follow_symlinks=False)
    return value.st_dev, value.st_ino


LOCK_CONTENDER = r"""\
import os,sys
from sqlcipher3 import dbapi2 as sqlcipher3
SQLITE_OPEN_NOFOLLOW=0x01000000
flags=(sqlcipher3.SQLITE_OPEN_READWRITE|sqlcipher3.SQLITE_OPEN_FULLMUTEX|
       sqlcipher3.SQLITE_OPEN_PRIVATECACHE|SQLITE_OPEN_NOFOLLOW)
db=sqlcipher3.connect(sys.argv[1],isolation_level=None,flags=flags)
db.execute(f"PRAGMA key = \"x'{sys.argv[2]}'\"")
db.execute("PRAGMA busy_timeout=250")
try:
    db.execute("BEGIN IMMEDIATE")
    db.execute("INSERT INTO lock_probe VALUES (2)")
    db.execute("COMMIT")
except sqlcipher3.OperationalError:
    db.close(); raise SystemExit(75)
db.close()
"""

OPEN_LIFECYCLE_PROBE = r"""\
import sys
from pathlib import Path
from tuntun_core.adapters.sqlcipher import connection as module
path=Path(sys.argv[1]); key=bytes.fromhex(sys.argv[2]); checkpoint=sys.argv[3]
if checkpoint!="success":
    def injected(name):
        if name==checkpoint: raise RuntimeError(f"injected {name}")
    module._initialization_checkpoint=injected
try:
    db=module.open_sqlcipher(path,key)
except RuntimeError as error:
    if checkpoint=="success": raise
    if str(error)!=f"injected {checkpoint}": raise
    if module._registry_snapshot(path) is not None: raise SystemExit(21)
else:
    if checkpoint!="success": raise SystemExit(22)
    db.close()
    if module._registry_snapshot(path) is not None: raise SystemExit(23)
"""


def _contend(path: Path, expected_returncode: int) -> None:
    result = subprocess.run(
        [sys.executable, "-c", LOCK_CONTENDER, os.fspath(path), KEY.hex()],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == expected_returncode, (result.stdout, result.stderr)


@pytest.mark.parametrize(
    "checkpoint",
    (
        "success",
        "key_validation",
        "keyed_read",
        "wal_activation",
        "sidecar_metadata",
        "integrity",
    ),
)
def test_open_and_cleanup_lock_ownership_never_deadlocks(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    path = _database_path(tmp_path, f"lifecycle-{checkpoint}.db")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            OPEN_LIFECYCLE_PROBE,
            os.fspath(path),
            KEY.hex(),
            checkpoint,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.parametrize(
    "path",
    (Path("."), Path("private") / ".." / "database.db", Path("bad\x00name.db")),
)
def test_database_path_rejects_dot_dotdot_and_nul(path: Path) -> None:
    with pytest.raises(PermissionError, match="unsafe database path"):
        open_sqlcipher(path, KEY)


@pytest.mark.parametrize(
    "key",
    (b"", bytes(31), bytes(33), bytearray(32), memoryview(bytes(32)), "x" * 32),
)
def test_database_key_must_be_exactly_32_immutable_bytes(key: object) -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        open_sqlcipher(Path("database.db"), key)  # type: ignore[arg-type]


def test_key_first_database_is_encrypted_and_wrong_key_fails(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    sentinel = b"foundation-private-sentinel"
    db = open_sqlcipher(path, KEY)
    db.execute("CREATE TABLE marker(value BLOB NOT NULL)")
    db.execute("INSERT INTO marker VALUES (?)", (sentinel,))
    db.commit()
    db.close()
    assert sentinel not in path.read_bytes()
    assert not path.read_bytes().startswith(b"SQLite format 3\x00")
    with pytest.raises(sqlcipher3.DatabaseError):
        open_sqlcipher(path, WRONG)
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(path).execute("SELECT name FROM sqlite_master").fetchall()


def test_connection_enables_integrity_foreign_keys_and_secure_delete(tmp_path: Path) -> None:
    db = open_sqlcipher(_database_path(tmp_path, "settings.db"), KEY)
    assert db.execute("PRAGMA cipher_version").fetchone()[0]
    assert db.execute("PRAGMA cipher_integrity_check").fetchall() == []
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert db.execute("PRAGMA secure_delete").fetchone()[0] == 1
    db.close()


def test_cipher_integrity_error_fails_closed_and_rolls_back_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path, "integrity-error.db")
    original_execute = QualifiedSQLCipherConnection.execute

    class IntegrityErrors:
        @staticmethod
        def fetchall() -> list[tuple[str]]:
            return [("synthetic integrity error",)]

    def injecting_execute(self, statement, *args, **kwargs):
        if statement == "PRAGMA cipher_integrity_check":
            return IntegrityErrors()
        return original_execute(self, statement, *args, **kwargs)

    monkeypatch.setattr(
        QualifiedSQLCipherConnection,
        "execute",
        injecting_execute,
    )

    with pytest.raises(RuntimeError, match="SQLCipher integrity check failed"):
        open_sqlcipher(path, KEY)
    assert connection_module._registry_snapshot(path) is None


def test_connect_uses_normal_path_exact_flags_and_key_is_first_sql(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path)
    calls = []
    statements = []
    original_connect = connection_module.sqlcipher3.connect
    original_execute = QualifiedSQLCipherConnection.execute

    def recording_connect(database, *args, **kwargs):
        calls.append((database, dict(kwargs)))
        return original_connect(database, *args, **kwargs)

    def recording_execute(self, statement, *args, **kwargs):
        statements.append(str(statement))
        return original_execute(self, statement, *args, **kwargs)

    monkeypatch.setattr(connection_module.sqlcipher3, "connect", recording_connect)
    monkeypatch.setattr(QualifiedSQLCipherConnection, "execute", recording_execute)
    db = open_sqlcipher(path, KEY)
    db.close()
    database, kwargs = calls[0]
    assert database == os.fspath(path)
    assert not database.startswith("/dev/fd/")
    assert kwargs["flags"] == SQLCIPHER_OPEN_FLAGS
    assert kwargs["factory"] is QualifiedSQLCipherConnection
    assert "uri" not in kwargs and "vfs" not in kwargs
    assert SQLCIPHER_OPEN_FLAGS & sqlcipher3.SQLITE_OPEN_CREATE == 0
    assert SQLCIPHER_OPEN_FLAGS & SQLITE_OPEN_NOFOLLOW
    assert statements[0] == f"PRAGMA key = \"x'{KEY.hex()}'\""


@pytest.mark.parametrize("component", ("ancestor", "leaf"))
def test_pinned_driver_enforces_nofollow_on_each_target_platform(
    tmp_path: Path,
    component: str,
) -> None:
    real = _database_path(tmp_path, "real.db")
    db = open_sqlcipher(real, KEY)
    db.close()
    if component == "leaf":
        candidate = real.with_name("alias.db")
        candidate.symlink_to(real)
    else:
        alias = real.parent.with_name("alias-parent")
        alias.symlink_to(real.parent, target_is_directory=True)
        candidate = alias / real.name
    with pytest.raises(sqlcipher3.OperationalError):
        sqlcipher3.connect(os.fspath(candidate), flags=SQLCIPHER_OPEN_FLAGS)


@pytest.mark.parametrize(
    "mutation",
    (
        "symlink",
        "fifo",
        "socket",
        "directory",
        "mode_0640",
        "mode_0400",
        "wrong_owner",
        "hard_link",
        "device_mismatch",
    ),
)
def test_database_entry_is_regular_owned_private_single_link_and_same_device(
    tmp_path: Path,
    short_database_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    path = _database_path(tmp_path)
    cleanup = None
    if mutation == "symlink":
        target = path.with_name("target.db")
        _regular(target)
        path.symlink_to(target)
    elif mutation == "fifo":
        os.mkfifo(path, 0o600)
    elif mutation == "socket":
        path = short_database_root / "foundation.db"
        cleanup = socket.socket(socket.AF_UNIX)
        cleanup.bind(os.fspath(path))
    elif mutation == "directory":
        path.mkdir(mode=0o700)
    else:
        _regular(path)
        if mutation.startswith("mode_"):
            path.chmod(int(mutation.removeprefix("mode_"), 8))
        elif mutation == "hard_link":
            os.link(path, path.with_name("second-link.db"))
        elif mutation == "wrong_owner":
            original = connection_module._reported_owner
            monkeypatch.setattr(
                connection_module,
                "_reported_owner",
                lambda name, value: (
                    value.st_uid + 1 if name == path.name else original(name, value)
                ),
            )
        elif mutation == "device_mismatch":
            original = connection_module._reported_device
            monkeypatch.setattr(
                connection_module,
                "_reported_device",
                lambda name, value: (
                    value.st_dev + 1 if name == path.name else original(name, value)
                ),
            )
    try:
        with pytest.raises(PermissionError, match="unsafe database path"):
            open_sqlcipher(path, KEY)
    finally:
        if cleanup is not None:
            cleanup.close()


def test_every_ancestor_and_final_symlink_is_rejected(tmp_path: Path) -> None:
    root = Path(os.path.realpath(tmp_path))
    target = root / "target"
    target.mkdir(mode=0o700)
    alias = root / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(PermissionError, match="unsafe database path"):
        open_sqlcipher(alias / "database.db", KEY)
    private = root / "private"
    private.mkdir(mode=0o700)
    real = private / "real.db"
    _regular(real)
    (private / "database.db").symlink_to(real)
    with pytest.raises(PermissionError, match="unsafe database path"):
        open_sqlcipher(private / "database.db", KEY)


@pytest.mark.parametrize("replacement", ("database", "parent"))
def test_one_way_replacement_during_connect_fails_and_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
) -> None:
    path = _database_path(tmp_path)
    parent = path.parent
    captured = []
    original_connect = connection_module.sqlcipher3.connect
    original_open = connection_module._open_qualified_database

    def recording_open(value):
        guard = original_open(value)
        captured.append(guard.parent.fd)
        return guard

    def replacing_connect(*args, **kwargs):
        if replacement == "database":
            path.rename(parent / "qualified-original.db")
            _regular(path)
        else:
            parent.rename(parent.with_name("qualified-original-parent"))
            parent.mkdir(mode=0o700)
            _regular(path)
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(connection_module, "_open_qualified_database", recording_open)
    monkeypatch.setattr(connection_module.sqlcipher3, "connect", replacing_connect)
    with pytest.raises(PermissionError, match="unsafe database path"):
        open_sqlcipher(path, KEY)
    assert captured
    for fd in captured:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert connection_module._registry_snapshot(path) is None


@pytest.mark.parametrize("suffix", ("-wal", "-shm"))
@pytest.mark.parametrize(
    "mutation",
    (
        "symlink",
        "fifo",
        "socket",
        "directory",
        "mode_0640",
        "mode_0400",
        "wrong_owner",
        "hard_link",
        "device_mismatch",
    ),
)
def test_preexisting_sidecars_are_qualified_before_sqlite_touches_them(
    tmp_path: Path,
    short_database_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    mutation: str,
) -> None:
    path = _database_path(tmp_path)
    cleanup = None
    if mutation == "socket":
        path = short_database_root / "foundation.db"
    _exclusive_empty_main(path)
    sidecar = Path(os.fspath(path) + suffix)
    if mutation == "symlink":
        target = sidecar.with_name(sidecar.name + "-target")
        _regular(target)
        sidecar.symlink_to(target)
    elif mutation == "fifo":
        os.mkfifo(sidecar, 0o600)
    elif mutation == "socket":
        cleanup = socket.socket(socket.AF_UNIX)
        cleanup.bind(os.fspath(sidecar))
    elif mutation == "directory":
        sidecar.mkdir(mode=0o700)
    else:
        _regular(sidecar)
        if mutation.startswith("mode_"):
            sidecar.chmod(int(mutation.removeprefix("mode_"), 8))
        elif mutation == "hard_link":
            os.link(sidecar, sidecar.with_name(sidecar.name + "-link"))
        elif mutation == "wrong_owner":
            original = connection_module._reported_owner
            monkeypatch.setattr(
                connection_module,
                "_reported_owner",
                lambda name, value: (
                    value.st_uid + 1 if name == sidecar.name else original(name, value)
                ),
            )
        elif mutation == "device_mismatch":
            original = connection_module._reported_device
            monkeypatch.setattr(
                connection_module,
                "_reported_device",
                lambda name, value: (
                    value.st_dev + 1 if name == sidecar.name else original(name, value)
                ),
            )
    try:
        created = os.stat(sidecar, follow_symlinks=False)
        assert {
            "symlink": stat.S_ISLNK,
            "fifo": stat.S_ISFIFO,
            "socket": stat.S_ISSOCK,
            "directory": stat.S_ISDIR,
        }.get(mutation, stat.S_ISREG)(created.st_mode)
        if mutation.startswith("mode_"):
            assert stat.S_IMODE(created.st_mode) == int(mutation.removeprefix("mode_"), 8)
        if mutation == "hard_link":
            assert created.st_nlink == 2
        with pytest.raises(PermissionError, match="unsafe database path"):
            open_sqlcipher(path, KEY)
        assert connection_module._registry_snapshot(path) is None
    finally:
        if cleanup is not None:
            cleanup.close()


def test_creation_only_fd_closes_before_reservation_and_sqlcipher_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path)
    events = []
    original_close = connection_module.os.close
    original_connect = connection_module.sqlcipher3.connect

    def recording_close(fd):
        opened = os.fstat(fd)
        try:
            named = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            named = None
        if named is not None and (opened.st_dev, opened.st_ino) == (
            named.st_dev,
            named.st_ino,
        ):
            state = connection_module._ACTIVE_DATABASES.get(path)
            events.append(
                (
                    "creation-close",
                    None if state is None else (state.active, state.initializing),
                )
            )
        return original_close(fd)

    def recording_connect(*args, **kwargs):
        state = connection_module._ACTIVE_DATABASES[path]
        events.append(("connect", (state.active, state.initializing)))
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(connection_module.os, "close", recording_close)
    monkeypatch.setattr(connection_module.sqlcipher3, "connect", recording_connect)
    db = open_sqlcipher(path, KEY)
    db.close()
    assert [name for name, _ in events[:2]] == ["creation-close", "connect"]
    assert events[0][1] is None
    assert events[1][1] == (0, 1)


def test_materialized_sidecars_are_metadata_identities_and_only_parent_fd_is_retained(
    tmp_path: Path,
) -> None:
    path = _database_path(tmp_path)
    db = open_sqlcipher(path, KEY)
    parent_fd = db.guarded_parent_descriptor()
    opened_parent = os.fstat(parent_fd)
    assert stat.S_ISDIR(opened_parent.st_mode)
    main_identity, sidecar_identities = db.storage_identities()
    assert (main_identity.device, main_identity.inode) == _identity(path)
    assert {suffix for suffix, _ in sidecar_identities} == {"-wal", "-shm"}
    for suffix in ("-wal", "-shm"):
        value = os.stat(os.fspath(path) + suffix, follow_symlinks=False)
        assert stat.S_ISREG(value.st_mode)
        assert stat.S_IMODE(value.st_mode) == 0o600
        assert value.st_uid == os.geteuid()
        assert value.st_nlink == 1
        assert value.st_dev == os.lstat(path.parent).st_dev
    db.close()
    with pytest.raises(OSError):
        os.fstat(parent_fd)
    assert connection_module._registry_snapshot(path) is None


def test_second_connection_never_adapter_opens_or_closes_main_or_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path)
    first = open_sqlcipher(path, KEY)
    protected = {
        _identity(path),
        *(_identity(Path(os.fspath(path) + suffix)) for suffix in ("-wal", "-shm")),
    }
    events = []
    original_open = connection_module.os.open
    original_close = connection_module.os.close

    def _identity_from_fd(fd):
        value = os.fstat(fd)
        return value.st_dev, value.st_ino

    def recording_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        events.append(("open", _identity_from_fd(fd)))
        return fd

    def recording_close(fd):
        events.append(("close", _identity_from_fd(fd)))
        return original_close(fd)

    monkeypatch.setattr(connection_module.os, "open", recording_open)
    monkeypatch.setattr(connection_module.os, "close", recording_close)
    second = open_sqlcipher(path, KEY)
    assert second.storage_identities() == first.storage_identities()
    second.close()
    assert not [event for event in events if event[1] in protected]
    assert connection_module._registry_snapshot(path).active == 1
    assert first.execute("SELECT 1").fetchone() == (1,)
    first.close()


def test_successful_close_orders_sqlcipher_then_registry_then_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path)
    db = open_sqlcipher(path, KEY)
    events = []
    original_base = QualifiedSQLCipherConnection._close_sqlcipher_base
    original_release = connection_module._release_reservation_after_close
    original_parent = connection_module.DatabasePathGuard._close_parent_after_release

    def base(connection):
        events.append("sqlcipher")
        return original_base(connection)

    def release(reservation):
        events.append("registry")
        return original_release(reservation)

    def parent(guard):
        events.append("parent")
        return original_parent(guard)

    monkeypatch.setattr(QualifiedSQLCipherConnection, "_close_sqlcipher_base", base)
    monkeypatch.setattr(connection_module, "_release_reservation_after_close", release)
    monkeypatch.setattr(connection_module.DatabasePathGuard, "_close_parent_after_release", parent)
    db.close()
    assert events == ["sqlcipher", "registry", "parent"]


@pytest.mark.parametrize(
    "checkpoint",
    (
        "key_validation",
        "keyed_read",
        "wal_activation",
        "sidecar_metadata",
        "integrity",
    ),
)
def test_initialization_failure_closes_before_rollback_and_preserves_healthy_peer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint: str,
) -> None:
    path = _database_path(tmp_path)
    healthy = open_sqlcipher(path, KEY)
    before = connection_module._registry_snapshot(path)
    events = []
    original_base = QualifiedSQLCipherConnection._close_sqlcipher_base
    original_rollback = connection_module._rollback_reservation_after_close
    original_parent = connection_module.DatabasePathGuard._close_parent_after_release

    def fail_at(name):
        if name == checkpoint:
            raise RuntimeError(f"injected {checkpoint}")

    def base(connection):
        events.append("sqlcipher")
        return original_base(connection)

    def rollback(reservation):
        events.append("registry")
        return original_rollback(reservation)

    def parent(guard):
        events.append("parent")
        return original_parent(guard)

    monkeypatch.setattr(connection_module, "_initialization_checkpoint", fail_at)
    monkeypatch.setattr(QualifiedSQLCipherConnection, "_close_sqlcipher_base", base)
    monkeypatch.setattr(connection_module, "_rollback_reservation_after_close", rollback)
    monkeypatch.setattr(connection_module.DatabasePathGuard, "_close_parent_after_release", parent)
    with pytest.raises(RuntimeError, match=f"injected {checkpoint}"):
        open_sqlcipher(path, KEY)
    assert events == ["sqlcipher", "registry", "parent"]
    after = connection_module._registry_snapshot(path)
    assert (
        (after.active, after.initializing)
        == (
            before.active,
            before.initializing,
        )
        == (1, 0)
    )
    assert healthy.execute("SELECT 1").fetchone() == (1,)
    healthy.close()


def test_initialization_close_failure_retains_initializing_lease_until_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path)
    healthy = open_sqlcipher(path, KEY)
    original = QualifiedSQLCipherConnection._close_sqlcipher_base
    failed = False

    def fail_checkpoint(name):
        if name == "key_validation":
            raise RuntimeError("injected initialization failure")

    def fail_first_cleanup(connection):
        nonlocal failed
        if not failed:
            failed = True
            raise RuntimeError("injected initialization close failure")
        return original(connection)

    monkeypatch.setattr(connection_module, "_initialization_checkpoint", fail_checkpoint)
    monkeypatch.setattr(QualifiedSQLCipherConnection, "_close_sqlcipher_base", fail_first_cleanup)
    with pytest.raises(connection_module.SQLCipherCleanupError) as captured:
        open_sqlcipher(path, KEY)
    failed_connection = captured.value.connection
    parent_fd = failed_connection.guarded_parent_descriptor()
    state = connection_module._registry_snapshot(path)
    assert (state.active, state.initializing, state.failed_closes) == (1, 1, 1)
    assert os.fstat(parent_fd)
    with pytest.raises(RuntimeError, match="prior SQLCipher close failed"):
        open_sqlcipher(path, KEY)
    failed_connection.close()
    with pytest.raises(OSError):
        os.fstat(parent_fd)
    state = connection_module._registry_snapshot(path)
    assert (state.active, state.initializing, state.failed_closes) == (1, 0, 0)
    assert healthy.execute("SELECT 1").fetchone() == (1,)
    healthy.close()


def test_sqlcipher_close_failure_retains_lease_parent_and_blocks_new_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path)
    db = open_sqlcipher(path, KEY)
    parent_fd = db.guarded_parent_descriptor()
    original = QualifiedSQLCipherConnection._close_sqlcipher_base
    failed = False

    def fail_once(connection):
        nonlocal failed
        if connection is db and not failed:
            failed = True
            raise RuntimeError("injected SQLCipher close failure")
        return original(connection)

    monkeypatch.setattr(QualifiedSQLCipherConnection, "_close_sqlcipher_base", fail_once)
    with pytest.raises(RuntimeError, match="injected SQLCipher close failure"):
        db.close()
    state = connection_module._registry_snapshot(path)
    assert (state.active, state.initializing, state.failed_closes) == (1, 0, 1)
    assert os.fstat(parent_fd)
    assert db.guarded_parent_descriptor() == parent_fd
    with pytest.raises(RuntimeError, match="prior SQLCipher close failed"):
        open_sqlcipher(path, KEY)
    db.close()
    with pytest.raises(OSError):
        os.fstat(parent_fd)
    reopened = open_sqlcipher(path, KEY)
    reopened.close()


def test_close_failure_mark_is_atomic_with_respect_to_new_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path)
    db = open_sqlcipher(path, KEY)
    entered = Event()
    allow_failure = Event()
    open_done = Event()
    close_errors = []
    open_errors = []
    returned = []
    original = QualifiedSQLCipherConnection._close_sqlcipher_base
    failed_once = False

    def paused_failure(connection):
        nonlocal failed_once
        if connection is db and not failed_once:
            failed_once = True
            entered.set()
            assert allow_failure.wait(5)
            raise RuntimeError("injected paused close failure")
        return original(connection)

    def close_worker():
        try:
            db.close()
        except BaseException as error:
            close_errors.append(error)

    def open_worker():
        try:
            returned.append(open_sqlcipher(path, KEY))
        except BaseException as error:
            open_errors.append(error)
        finally:
            open_done.set()

    monkeypatch.setattr(QualifiedSQLCipherConnection, "_close_sqlcipher_base", paused_failure)
    closer = Thread(target=close_worker)
    closer.start()
    assert entered.wait(5)
    opener = Thread(target=open_worker)
    opener.start()
    assert not open_done.wait(0.2)
    allow_failure.set()
    closer.join(5)
    opener.join(5)
    assert not closer.is_alive()
    assert not opener.is_alive()
    assert len(close_errors) == 1
    assert "paused close failure" in str(close_errors[0])
    assert not returned
    assert len(open_errors) == 1
    assert "prior SQLCipher close failed" in str(open_errors[0])
    db.close()


@pytest.mark.parametrize("replacement", ("database", "parent"))
def test_live_connection_revalidation_rejects_named_entry_drift(
    tmp_path: Path,
    replacement: str,
) -> None:
    path = _database_path(tmp_path)
    db = open_sqlcipher(path, KEY)
    parent = path.parent
    if replacement == "database":
        original = parent / "open-original.db"
        path.rename(original)
        _regular(path, original.read_bytes())
    else:
        original_parent = parent.with_name("open-original-parent")
        parent.rename(original_parent)
        parent.mkdir(mode=0o700)
        _regular(path, (original_parent / path.name).read_bytes())
    with pytest.raises(PermissionError, match="unsafe database path"):
        db.revalidate_storage_path()
    db.close()


def test_live_database_identity_cannot_be_reopened_through_renamed_parent(
    tmp_path: Path,
) -> None:
    path = _database_path(tmp_path)
    db = open_sqlcipher(path, KEY)
    moved_parent = path.parent.with_name("moved-private")
    path.parent.rename(moved_parent)
    alias_path = moved_parent / path.name
    alias = None
    try:
        with pytest.raises(PermissionError, match="unsafe database path"):
            qualified_database_identity(alias_path)
        with pytest.raises(PermissionError, match="unsafe database path"):
            alias = open_sqlcipher(alias_path, KEY)
        state = connection_module._registry_snapshot(path)
        assert (state.active, state.initializing, state.failed_closes) == (1, 0, 0)
        assert connection_module._registry_snapshot(alias_path) is None
    finally:
        if alias is not None:
            alias.close()
        db.close()


def test_failed_close_blocks_same_inode_reopen_through_renamed_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path)
    db = open_sqlcipher(path, KEY)
    moved_parent = path.parent.with_name("moved-private")
    path.parent.rename(moved_parent)
    alias_path = moved_parent / path.name
    original_close = QualifiedSQLCipherConnection._close_sqlcipher_base
    failed = False

    def fail_once(connection):
        nonlocal failed
        if connection is db and not failed:
            failed = True
            raise RuntimeError("injected SQLCipher close failure")
        return original_close(connection)

    monkeypatch.setattr(QualifiedSQLCipherConnection, "_close_sqlcipher_base", fail_once)
    with pytest.raises(RuntimeError, match="injected SQLCipher close failure"):
        db.close()
    alias = None
    try:
        with pytest.raises(RuntimeError, match="prior SQLCipher close failed"):
            qualified_database_identity(alias_path)
        with pytest.raises(RuntimeError, match="prior SQLCipher close failed"):
            alias = open_sqlcipher(alias_path, KEY)
        state = connection_module._registry_snapshot(path)
        assert (state.active, state.initializing, state.failed_closes) == (1, 0, 1)
        assert connection_module._registry_snapshot(alias_path) is None
    finally:
        if alias is not None:
            alias.close()
        db.close()


def test_two_connections_share_canonical_wal_and_complete_concurrent_writes(
    tmp_path: Path,
) -> None:
    path = _database_path(tmp_path)
    first = open_sqlcipher(path, KEY)
    second = open_sqlcipher(path, KEY)
    first.execute("CREATE TABLE concurrent_writes(value INTEGER NOT NULL)")

    def write(connection, value):
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO concurrent_writes VALUES (?)", (value,))
        connection.execute("COMMIT")

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda item: write(*item), ((first, 1), (second, 2))))
    expected = os.fspath(path)
    assert first.execute("PRAGMA database_list").fetchone()[2] == expected
    assert second.execute("PRAGMA database_list").fetchone()[2] == expected
    assert Path(expected + "-wal").is_file()
    assert Path(expected + "-shm").is_file()
    assert first.execute("SELECT count(*) FROM concurrent_writes").fetchone()[0] == 2
    first.close()
    second.close()


def test_closing_peer_does_not_cancel_holder_lock_for_subprocess(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    holder = open_sqlcipher(path, KEY)
    peer = open_sqlcipher(path, KEY)
    holder.execute("CREATE TABLE lock_probe(value INTEGER NOT NULL)")
    holder.execute("BEGIN IMMEDIATE")
    holder.execute("INSERT INTO lock_probe VALUES (1)")
    peer.close()
    _contend(path, 75)
    holder.execute("COMMIT")
    _contend(path, 0)
    assert holder.execute("SELECT count(*) FROM lock_probe").fetchone()[0] == 2
    holder.close()


def test_legitimate_close_and_reopen_never_assumes_sidecar_deletion(
    tmp_path: Path,
) -> None:
    path = _database_path(tmp_path)
    db = open_sqlcipher(path, KEY)
    db.execute("CREATE TABLE reopen_probe(value INTEGER NOT NULL)")
    db.execute("INSERT INTO reopen_probe VALUES (1)")
    db.close()
    for suffix in ("-wal", "-shm"):
        try:
            surviving = os.stat(os.fspath(path) + suffix, follow_symlinks=False)
        except FileNotFoundError:
            continue
        assert stat.S_ISREG(surviving.st_mode)
        assert stat.S_IMODE(surviving.st_mode) == 0o600
    reopened = open_sqlcipher(path, KEY)
    assert reopened.execute("SELECT value FROM reopen_probe").fetchone() == (1,)
    for suffix in ("-wal", "-shm"):
        current = os.stat(os.fspath(path) + suffix, follow_symlinks=False)
        assert stat.S_ISREG(current.st_mode)
        assert stat.S_IMODE(current.st_mode) == 0o600
    reopened.close()


def test_probe_is_sanitized_and_records_driver_runtime(tmp_path: Path) -> None:
    value = probe_storage(_database_path(tmp_path), KEY).as_dict()
    encoded = json.dumps(value)
    assert set(value) == {
        "operating_system",
        "architecture",
        "python",
        "driver",
        "sqlite",
        "cipher",
        "open_flags",
        "integrity_ok",
        "mode",
    }
    assert value["driver"] == "sqlcipher3==0.6.2"
    assert value["sqlite"] == sqlcipher3.sqlite_version
    assert value["cipher"]
    assert value["open_flags"] == SQLCIPHER_OPEN_FLAGS
    assert value["integrity_ok"] is True
    assert value["mode"] == "0o600"
    assert "path" not in value and "key" not in value
    assert os.fspath(tmp_path) not in encoded
    assert KEY.hex() not in encoded


def test_storage_probe_cli_reads_database_key_and_emits_only_sorted_probe_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path, "do-not-emit-this-name.db")
    public_probe = {
        "operating_system": "test-os",
        "architecture": "test-arch",
        "python": "3.12.test",
        "driver": "sqlcipher3==0.6.2",
        "sqlite": "test-sqlite",
        "cipher": "test-cipher",
        "open_flags": 123,
        "integrity_ok": True,
        "mode": "0o600",
    }
    calls: list[tuple[object, ...]] = []

    class FakeProvider:
        def get(self, service: str, account: str) -> bytes:
            calls.append(("get", service, account))
            return KEY

    class FakeProbe:
        def as_dict(self) -> dict[str, object]:
            return public_probe

    def fake_probe(candidate: Path, key: bytes) -> FakeProbe:
        calls.append(("probe", candidate, key))
        return FakeProbe()

    monkeypatch.setattr(storage_probe_command, "MacOSKeychainSecretProvider", FakeProvider)
    monkeypatch.setattr(storage_probe_command, "probe_storage", fake_probe)

    result = CliRunner().invoke(
        cli_module.app,
        ["storage", "probe", "--path", os.fspath(path), "--json"],
    )

    assert result.exit_code == 0, result.output
    assert result.stdout == json.dumps(public_probe, sort_keys=True) + "\n"
    assert calls == [
        ("get", "tuntun.database", "root-v1"),
        ("probe", path, KEY),
    ]
    assert os.fspath(path) not in result.stdout
    assert KEY.hex() not in result.stdout


def test_storage_probe_cli_missing_key_fails_before_storage_and_emits_no_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path, "must-not-be-opened.db")
    probe_called = False

    class MissingProvider:
        def get(self, service: str, account: str) -> bytes:
            assert (service, account) == ("tuntun.database", "root-v1")
            raise RuntimeError("missing secret")

    def unexpected_probe(candidate: Path, key: bytes) -> object:
        nonlocal probe_called
        del candidate, key
        probe_called = True
        raise AssertionError("storage must not open without the database key")

    monkeypatch.setattr(
        storage_probe_command,
        "MacOSKeychainSecretProvider",
        MissingProvider,
    )
    monkeypatch.setattr(storage_probe_command, "probe_storage", unexpected_probe)

    result = CliRunner().invoke(
        cli_module.app,
        ["storage", "probe", "--path", os.fspath(path), "--json"],
    )

    assert result.exit_code == 1
    assert isinstance(result.exception, RuntimeError)
    assert str(result.exception) == "missing secret"
    assert not probe_called
    assert os.fspath(path) not in result.stdout
    assert KEY.hex() not in result.stdout
