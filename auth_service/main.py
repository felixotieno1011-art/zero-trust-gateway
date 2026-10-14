"""Authentication service: register, login, refresh, logout, /me."""
import os
from contextlib import asynccontextmanager
from datetime import datetime

import bcrypt
from dotenv import load_dotenv
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from auth_service.db import (
    find_refresh_token,
    get_conn,
    init_schema,
    revoke_refresh_token,
    store_refresh_token,
)
from auth_service.jwt_utils import load_secret, verify_token
from auth_service.schemas import ValidationError, validate_login, validate_register
from auth_service.tokens import (
    access_expire_seconds,
    make_access_token,
    make_refresh_token,
    refresh_expiry_datetime,
)

load_dotenv()

BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))


def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        pw_bytes = password.encode("utf-8")[:72]
        return bcrypt.checkpw(pw_bytes, password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def _json_error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _issue_tokens(conn, user_id: int, email: str) -> dict:
    """Issue a fresh access + refresh pair and store the refresh in DB."""
    access = make_access_token(user_id, email)
    refresh = make_refresh_token(user_id)
    store_refresh_token(conn, user_id, refresh, refresh_expiry_datetime())
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": access_expire_seconds(),
    }


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def register(request: Request) -> JSONResponse:
    try:
        data = validate_register(await request.json())
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
            if conn.run("SELECT id FROM users WHERE email = :email", email=data["email"]):
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
        data = validate_login(await request.json())
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

    try:
        with get_conn() as conn:
            tokens = _issue_tokens(conn, user_id, email)
    except Exception as exc:
        return _json_error(f"database error: {exc}", 500)

    return JSONResponse(tokens)


async def refresh(request: Request) -> JSONResponse:
    """Exchange a refresh token for a new access + refresh pair (rotation).

    The old refresh token is deleted (revoked) so it cannot be reused.
    """
    try:
        body = await request.json()
    except Exception:
        return _json_error("invalid JSON body", 400)

    if not isinstance(body, dict):
        return _json_error("body must be a JSON object", 400)

    token = body.get("refresh_token")
    if not isinstance(token, str) or not token:
        return _json_error("refresh_token required", 400)

    try:
        payload = verify_token(token, load_secret())
    except ValueError as exc:
        return _json_error(str(exc), 401)
    except RuntimeError as exc:
        return _json_error(f"server misconfigured: {exc}", 500)

    if payload.get("type") != "refresh":
        return _json_error("invalid token type", 401)

    try:
        with get_conn() as conn:
            stored = find_refresh_token(conn, token)
            if not stored:
                return _json_error("refresh token revoked or unknown", 401)

            _stored_id, user_id, expires_at = stored

            # Guard against expired DB rows
            if expires_at and expires_at < datetime.now(expires_at.tzinfo):
                revoke_refresh_token(conn, token)
                return _json_error("refresh token expired", 401)

            # Fetch user email for the new access token
            user_rows = conn.run("SELECT email FROM users WHERE id = :uid", uid=user_id)
            if not user_rows:
                revoke_refresh_token(conn, token)
                return _json_error("user no longer exists", 401)
            email = user_rows[0][0]

            # Rotation: delete old, insert new
            revoke_refresh_token(conn, token)
            tokens = _issue_tokens(conn, user_id, email)
    except Exception as exc:
        return _json_error(f"database error: {exc}", 500)

    return JSONResponse(tokens)


async def logout(request: Request) -> JSONResponse:
    """Revoke a refresh token. Access tokens remain valid until they expire."""
    try:
        body = await request.json()
    except Exception:
        return _json_error("invalid JSON body", 400)

    if not isinstance(body, dict):
        return _json_error("body must be a JSON object", 400)

    token = body.get("refresh_token")
    if not isinstance(token, str) or not token:
        return _json_error("refresh_token required", 400)

    try:
        with get_conn() as conn:
            deleted = revoke_refresh_token(conn, token)
    except Exception as exc:
        return _json_error(f"database error: {exc}", 500)

    if deleted == 0:
        return _json_error("refresh token not found", 404)

    return JSONResponse({"status": "logged out"}, status_code=200)


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

    return JSONResponse({"id": int(payload["sub"]), "email": payload.get("email")})


@asynccontextmanager
async def lifespan(app: Starlette):
    init_schema()
    yield


app = Starlette(
    routes=[
        Route("/health", health, methods=["GET"]),
        Route("/register", register, methods=["POST"]),
        Route("/login", login, methods=["POST"]),
        Route("/refresh", refresh, methods=["POST"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/me", me, methods=["GET"]),
    ],
    lifespan=lifespan,
)
