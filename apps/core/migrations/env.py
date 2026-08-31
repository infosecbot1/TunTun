from __future__ import annotations

from pathlib import Path

from alembic import context
from sqlalchemy.engine import Connection
from tuntun_core.adapters.sqlcipher.connection import QualifiedSQLCipherConnection
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine
from tuntun_core.adapters.sqlcipher.models import metadata

config = context.config


def _run_on_connection(connection: Connection) -> None:
    driver_connection = connection.connection.driver_connection
    if not isinstance(driver_connection, QualifiedSQLCipherConnection):
        raise RuntimeError("migration connection is not qualified SQLCipher")
    transaction = connection.get_transaction()
    owns_transaction = transaction is None
    if transaction is None:
        transaction = connection.begin()
    try:
        if not driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        context.configure(
            connection=connection,
            target_metadata=metadata,
            transaction_per_migration=True,
            transactional_ddl=True,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        if owns_transaction:
            transaction.commit()
    except BaseException:
        if owns_transaction and transaction.is_active:
            transaction.rollback()
        raise


def run_migrations_online() -> None:
    path = config.attributes.get("sqlcipher_path")
    key = config.attributes.get("sqlcipher_key")
    if not isinstance(path, Path) or type(key) is not bytes or len(key) != 32:
        raise RuntimeError("SQLCipher path and key are required")

    supplied_connection = config.attributes.get("sqlalchemy_connection")
    if supplied_connection is not None:
        if not isinstance(supplied_connection, Connection):
            raise RuntimeError("invalid supplied SQLAlchemy migration connection")
        driver_connection = supplied_connection.connection.driver_connection
        if not isinstance(driver_connection, QualifiedSQLCipherConnection):
            raise RuntimeError("supplied migration connection is not qualified SQLCipher")
        driver_connection.revalidate_storage_path()
        database_paths = [
            row[2] for row in driver_connection.execute("PRAGMA database_list") if row[1] == "main"
        ]
        if database_paths != [str(path)]:
            raise RuntimeError("supplied migration connection path does not match")
        _run_on_connection(supplied_connection)
        return

    engine = create_sqlcipher_engine(path, key)
    try:
        with engine.connect() as connection:
            _run_on_connection(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline/plaintext migration mode is forbidden")

run_migrations_online()
