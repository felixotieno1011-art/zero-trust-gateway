"""JWT verification middleware for the gateway.

Public paths bypass verification. Everything else requires a valid
Bearer token. Verified identity is passed to upstream services via
X-User-Id and X-User-Email headers.

Special case: /me is proxied to the auth service, which itself parses
the Authorization header. For those paths we preserve the header.
"""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth_service.jwt_utils import verify_token, load_secret


PUBLIC_PATHS = {
    "/health",
    "/auth/register",
    "/auth/login",
    "/auth/refresh",
    "/auth/logout",   # revokes a refresh token — no access token required
}

PASSTHROUGH_AUTH_PATHS = {
    "/me",
}


def _is_public(path: str) -> bool:
    return path in PUBLIC_PATHS


def _preserves_auth_header(path: str) -> bool:
    return path in PASSTHROUGH_AUTH_PATHS


class JWTAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if _is_public(path):
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return JSONResponse({"error": "missing bearer token"}, status_code=401)

        token = auth_header.split(" ", 1)[1].strip()

        try:
            payload = verify_token(token, load_secret())
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        except RuntimeError as exc:
            return JSONResponse({"error": f"server misconfigured: {exc}"}, status_code=500)

        if payload.get("type") != "access":
            return JSONResponse({"error": "invalid token type"}, status_code=401)

        user_id = str(payload["sub"])
        user_email = payload.get("email", "")

        request.state.user_id = user_id
        request.state.user_email = user_email

        keep_auth = _preserves_auth_header(path)

        new_headers = []
        for name, value in request.scope["headers"]:
            lname = name.lower()
            if not keep_auth and lname == b"authorization":
                continue
            if lname in (b"x-user-id", b"x-user-email"):
                continue
            new_headers.append((name, value))

        new_headers.append((b"x-user-id", user_id.encode()))
        new_headers.append((b"x-user-email", user_email.encode()))

        request.scope["headers"] = new_headers

        if hasattr(request, "_headers"):
            delattr(request, "_headers")

        return await call_next(request)
