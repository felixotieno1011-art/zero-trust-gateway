"""PostgreSQL connection helpers using pg8000 (pure Python)."""
import os
from contextlib import contextmanager
from typing import Iterator
from urllib.parse import urlparse

import pg8000.native


def _conn_kwargs() -> dict:
    url = os.getenv("DATABASE_URL", "postgresql://localhost/gateway_db")
    parsed = urlparse(url)
    if parsed.scheme not in ("postgresql", "postgres"):
        raise RuntimeError("DATABASE_URL must use postgresql:// or postgres://")

    kwargs = {
        "user": parsed.username or os.getenv("PGUSER") or os.getenv("USER", "postgres"),
        "host": parsed.hostname or "localhost",
        "database": (parsed.path or "/gateway_db").lstrip("/"),
    }
    if parsed.port:
        kwargs["port"] = parsed.port
    if parsed.password:
        kwargs["password"] = parsed.password
    return kwargs


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
    with get_conn() as conn:
        for statement in SCHEMA.split(";"):
            stmt = statement.strip()
            if stmt:
                conn.run(stmt)


# ---------------------------------------------------------------------------
# Refresh token operations
# ---------------------------------------------------------------------------

def store_refresh_token(conn, user_id: int, token: str, expires_at) -> None:
    conn.run(
        "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (:uid, :tok, :exp)",
        uid=user_id,
        tok=token,
        exp=expires_at,
    )


def find_refresh_token(conn, token: str):
    """Return (id, user_id, expires_at) or None."""
    rows = conn.run(
        "SELECT id, user_id, expires_at FROM refresh_tokens WHERE token = :tok",
        tok=token,
    )
    return rows[0] if rows else None


def revoke_refresh_token(conn, token: str) -> int:
    """Delete a refresh token. Returns number of rows affected."""
    rows = conn.run(
        "DELETE FROM refresh_tokens WHERE token = :tok RETURNING id",
        tok=token,
    )
    return len(rows)


def revoke_all_user_tokens(conn, user_id: int) -> int:
    """Revoke every refresh token for a user."""
    rows = conn.run(
        "DELETE FROM refresh_tokens WHERE user_id = :uid RETURNING id",
        uid=user_id,
    )
    return len(rows)
