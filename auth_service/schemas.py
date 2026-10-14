"""Manual request validation (no pydantic)."""
import re
from typing import Any

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ValidationError(Exception):
    """Raised when a request body fails validation."""


def validate_register(body: Any) -> dict[str, str]:
    if not isinstance(body, dict):
        raise ValidationError("body must be a JSON object")
    email = body.get("email")
    password = body.get("password")

    if not isinstance(email, str) or not EMAIL_RE.match(email):
        raise ValidationError("invalid email")
    if not isinstance(password, str) or len(password) < 8:
        raise ValidationError("password must be at least 8 characters")

    return {"email": email.lower().strip(), "password": password}


def validate_login(body: Any) -> dict[str, str]:
    if not isinstance(body, dict):
        raise ValidationError("body must be a JSON object")
    email = body.get("email")
    password = body.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        raise ValidationError("email and password required")

    return {"email": email.lower().strip(), "password": password}
