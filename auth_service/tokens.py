"""Token creation and verification helpers."""
import os
import secrets
from datetime import datetime, timedelta, timezone

from auth_service.jwt_utils import create_token, load_secret, verify_token


def access_expire_seconds() -> int:
    return int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")) * 60


def refresh_expire_seconds() -> int:
    return int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")) * 86400


def _new_jti() -> str:
    """Generate a unique token ID. Prevents same-second collisions."""
    return secrets.token_urlsafe(16)


def make_access_token(user_id: int, email: str) -> str:
    return create_token(
        {
            "sub": str(user_id),
            "email": email,
            "type": "access",
            "jti": _new_jti(),
        },
        load_secret(),
        expires_in_seconds=access_expire_seconds(),
    )


def make_refresh_token(user_id: int) -> str:
    return create_token(
        {
            "sub": str(user_id),
            "type": "refresh",
            "jti": _new_jti(),
        },
        load_secret(),
        expires_in_seconds=refresh_expire_seconds(),
    )


def decode_token(token: str) -> dict:
    """Verify and decode. Raises ValueError on any failure."""
    return verify_token(token, load_secret())


def refresh_expiry_datetime() -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=refresh_expire_seconds())
