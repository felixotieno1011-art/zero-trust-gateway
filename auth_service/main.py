"""Authentication service: register, login, JWT issuance, /me.

Starlette app (not FastAPI) to avoid the pydantic-core Rust build
requirement on Termux aarch64 + Python 3.14.

Uses bcrypt directly (not passlib) because passlib 1.7.4 is incompatible
with bcrypt 4.1+ due to the removed bcrypt.__about__ attribute.
"""
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import bcrypt
from dotenv import load_dotenv
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from auth_service.db import get_conn, init_schema
from auth_service.jwt_utils import create_token, load_secret, verify_token
from auth_service.schemas import ValidationError, validate_login, validate_register

load_dotenv()

BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))
ACCESS_EXPIRE_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))


def hash_password(password: str) -> str:
    """Hash a password with bcrypt. Truncates to 72 bytes (bcrypt limit)."""
    pw_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash. Returns False on any error."""
    try:
        pw_bytes = password.encode("utf-8")[:72]
        return bcrypt.checkpw(pw_bytes, password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def _json_error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def register(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        data = validate_register(body)
    except ValidationError as exc:
        return _json_error(str(exc), 400)
    except Exception:
        return _json_error("invalid JSON body", 400)

    try:
        password_hash = hash_password(data["password"])
    except Exception as exc:
        return _json_error(f"hash error: {exc}", 500)

    try:
        with get_conn() as conn:
            existing = conn.run("SELECT id FROM users WHERE email = :email", email=data["email"])
            if existing:
                return _json_error("email already registered", 409)
            rows = conn.run(
                "INSERT INTO users (email, password_hash) VALUES (:email, :ph) RETURNING id, email",
                email=data["email"],
                ph=password_hash,
            )
    except Exception as exc:
        return _json_error(f"database error: {exc}", 500)

    user_id, email = rows[0]
    return JSONResponse({"id": user_id, "email": email}, status_code=201)


async def login(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        data = validate_login(body)
    except ValidationError as exc:
        return _json_error(str(exc), 400)
    except Exception:
        return _json_error("invalid JSON body", 400)

    try:
        with get_conn() as conn:
            rows = conn.run(
                "SELECT id, email, password_hash FROM users WHERE email = :email",
                email=data["email"],
            )
    except Exception as exc:
        return _json_error(f"database error: {exc}", 500)

    if not rows:
        return _json_error("invalid credentials", 401)

    user_id, email, password_hash = rows[0]

    if not verify_password(data["password"], password_hash):
        return _json_error("invalid credentials", 401)

    secret = load_secret()
    access_token = create_token(
        {"sub": str(user_id), "email": email, "type": "access"},
        secret,
        expires_in_seconds=ACCESS_EXPIRE_MIN * 60,
    )
    refresh_token = create_token(
        {"sub": str(user_id), "type": "refresh"},
        secret,
        expires_in_seconds=REFRESH_EXPIRE_DAYS * 86400,
    )

    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRE_DAYS)

    try:
        with get_conn() as conn:
            conn.run(
                "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (:uid, :tok, :exp)",
                uid=user_id,
                tok=refresh_token,
                exp=expires_at,
            )
    except Exception as exc:
        return _json_error(f"database error: {exc}", 500)

    return JSONResponse({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_EXPIRE_MIN * 60,
    })


async def me(request: Request) -> JSONResponse:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return _json_error("missing bearer token", 401)

    token = auth.split(" ", 1)[1].strip()

    try:
        payload = verify_token(token, load_secret())
    except ValueError as exc:
        return _json_error(str(exc), 401)
    except RuntimeError as exc:
        return _json_error(f"server misconfigured: {exc}", 500)

    if payload.get("type") != "access":
        return _json_error("invalid token type", 401)

    return JSONResponse({
        "id": int(payload["sub"]),
        "email": payload.get("email"),
    })


@asynccontextmanager
async def lifespan(app: Starlette):
    """Run schema migration on startup, cleanup on shutdown."""
    init_schema()
    yield


app = Starlette(
    routes=[
        Route("/health", health, methods=["GET"]),
        Route("/register", register, methods=["POST"]),
        Route("/login", login, methods=["POST"]),
        Route("/me", me, methods=["GET"]),
    ],
    lifespan=lifespan,
)
