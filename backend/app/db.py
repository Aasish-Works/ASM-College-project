from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings


def _sqlite_connect_args(database_url: str) -> dict[str, object]:
    if database_url.startswith("sqlite"):
        return {"check_same_thread": False, "timeout": 30}
    return {}


engine: Engine = create_engine(
    settings.database_url,
    connect_args=_sqlite_connect_args(settings.database_url),
    future=True,
)


if settings.database_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def _column_sql_type(column) -> str:
    column_type = column.type
    if isinstance(column_type, Integer):
        return "INTEGER"
    if isinstance(column_type, Float):
        return "FLOAT"
    if isinstance(column_type, Boolean):
        return "BOOLEAN"
    if isinstance(column_type, DateTime):
        return "DATETIME"
    if isinstance(column_type, String):
        return "TEXT"
    if isinstance(column_type, Text):
        return "TEXT"
    return "TEXT"


def _column_default_sql(column) -> str:
    default = getattr(column, "default", None)
    if default is None or not getattr(default, "is_scalar", False):
        return ""
    value = default.arg
    if isinstance(value, bool):
        return f" DEFAULT {1 if value else 0}"
    if isinstance(value, (int, float)):
        return f" DEFAULT {value}"
    if value is None:
        return ""
    escaped = str(value).replace("'", "''")
    return f" DEFAULT '{escaped}'"


def ensure_sqlite_schema() -> None:
    if not settings.database_url.startswith("sqlite"):
        return

    inspector = inspect(engine)
    with engine.begin() as connection:
        for table_name, table in Base.metadata.tables.items():
            if not inspector.has_table(table_name):
                continue
            existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
            for column in table.columns:
                if column.name in existing_columns:
                    continue
                ddl = f"ALTER TABLE {table_name} ADD COLUMN {column.name} {_column_sql_type(column)}{_column_default_sql(column)}"
                connection.execute(text(ddl))


def ensure_sqlite_data_defaults() -> None:
    if not settings.database_url.startswith("sqlite"):
        return

    statements = [
        "UPDATE scan_results SET payload='{}' WHERE payload IS NULL OR TRIM(payload) = ''",
        "UPDATE scan_results SET artifact_json='{}' WHERE artifact_json IS NULL OR TRIM(artifact_json) = ''",
        "UPDATE scan_jobs SET current_stage = NULL WHERE current_stage = ''",
        "UPDATE scan_jobs SET status_message = NULL WHERE status_message = ''",
    ]
    with engine.begin() as connection:
        for statement in statements:
            try:
                connection.execute(text(statement))
            except Exception:
                continue


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_sqlite_schema()
    ensure_sqlite_data_defaults()


def get_db() -> Iterator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
