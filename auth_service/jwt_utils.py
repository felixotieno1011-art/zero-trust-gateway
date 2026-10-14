"""Minimal JWT implementation using only Python stdlib.

Implements HS256 JWT signing and verification. No external dependencies.
This is intentionally simple and auditable.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(message: bytes, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()


def create_token(payload: dict[str, Any], secret: str, expires_in_seconds: int) -> str:
    """Create a signed HS256 JWT."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    body = {**payload, "iat": now, "exp": now + expires_in_seconds}

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    body_b64 = _b64url_encode(json.dumps(body, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{body_b64}".encode("ascii")
    signature = _sign(signing_input, secret)
    signature_b64 = _b64url_encode(signature)

    return f"{header_b64}.{body_b64}.{signature_b64}"


def verify_token(token: str, secret: str) -> dict[str, Any]:
    """Verify an HS256 JWT. Raises ValueError on any failure."""
    if not isinstance(token, str):
        raise ValueError("token must be a string")

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")

    header_b64, body_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{body_b64}".encode("ascii")
    expected_sig = _sign(signing_input, secret)

    try:
        provided_sig = _b64url_decode(signature_b64)
    except Exception as exc:
        raise ValueError("bad signature encoding") from exc

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ValueError("invalid signature")

    try:
        payload = json.loads(_b64url_decode(body_b64))
    except Exception as exc:
        raise ValueError("bad payload encoding") from exc

    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    if "exp" not in payload:
        raise ValueError("missing exp claim")

    try:
        if int(payload["exp"]) < int(time.time()):
            raise ValueError("token expired")
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid exp claim") from exc

    return payload


def load_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret or len(secret) < 32:
        raise RuntimeError("JWT_SECRET must be set and at least 32 characters long")
    return secret
