"""PostgreSQL connection helpers using pg8000 (pure Python)."""
import os
from contextlib import contextmanager
from typing import Iterator

import pg8000.native


def _conn_kwargs() -> dict:
    """Parse DATABASE_URL. Supports postgresql://host/dbname only."""
    url = os.getenv("DATABASE_URL", "postgresql://localhost/gateway_db")
    if "://" not in url:
        raise RuntimeError("DATABASE_URL must start with postgresql://")
    without_scheme = url.split("://", 1)[1]
    if "/" not in without_scheme:
        raise RuntimeError("DATABASE_URL must include a database name")
    host_part, dbname = without_scheme.split("/", 1)
    host = host_part or "localhost"

    # Priority: PGUSER env var → current OS user (whoami) → error
    user = os.getenv("PGUSER")
    if not user:
        user = os.getenv("USER")

    if not user:
        raise RuntimeError("Cannot determine PostgreSQL user. Set PGUSER in .env")

    return {"user": user, "host": host, "database": dbname}


@contextmanager
def get_conn() -> Iterator[pg8000.native.Connection]:
    conn = pg8000.native.Connection(**(_conn_kwargs()))
    try:
        yield conn
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
"""


def init_schema() -> None:
    """Create tables and indexes if they don't exist."""
    with get_conn() as conn:
        for statement in SCHEMA.split(";"):
            stmt = statement.strip()
            if stmt:
                conn.run(stmt)
