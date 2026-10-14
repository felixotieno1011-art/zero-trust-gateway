"""Zero-Trust Gateway: reverse proxy with JWT auth and WAF.

Middleware order (outermost first, as executed per request):
  1. WAFMiddleware       — blocks SQLi/XSS payloads
  2. JWTAuthMiddleware   — verifies JWT on protected routes
  3. proxy to backend
"""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from gateway.middleware.auth import JWTAuthMiddleware
from gateway.middleware.waf import WAFMiddleware


AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://127.0.0.1:8001")
MOCK_A_URL = os.getenv("MOCK_A_URL", "http://127.0.0.1:9001")
MOCK_B_URL = os.getenv("MOCK_B_URL", "http://127.0.0.1:9002")


async def _proxy(request: Request, target_base: str, path: str) -> JSONResponse:
    url = f"{target_base.rstrip('/')}/{path.lstrip('/')}"
    if request.url.query:
        url += f"?{request.url.query}"

    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }

    body = await request.body() if request.method in ("POST", "PUT", "PATCH") else None

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.request(
                request.method, url,
                headers=forward_headers,
                content=body,
            )
        except httpx.RequestError as exc:
            return JSONResponse({"error": f"upstream unreachable: {exc}"}, status_code=502)

    try:
        payload = resp.json()
    except Exception:
        payload = {"raw": resp.text}

    return JSONResponse(payload, status_code=resp.status_code)


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "gateway"})


async def auth_route(request: Request) -> JSONResponse:
    path = request.path_params.get("path", "")
    return await _proxy(request, AUTH_SERVICE_URL, path)


async def me_route(request: Request) -> JSONResponse:
    return await _proxy(request, AUTH_SERVICE_URL, "me")


async def service_a_route(request: Request) -> JSONResponse:
    path = request.path_params.get("path", "")
    return await _proxy(request, MOCK_A_URL, path)


async def service_b_route(request: Request) -> JSONResponse:
    path = request.path_params.get("path", "")
    return await _proxy(request, MOCK_B_URL, path)


routes = [
    Route("/health", health, methods=["GET"]),
    Route("/auth/{path:path}", auth_route, methods=["GET", "POST", "PUT", "PATCH"]),
    Route("/me", me_route, methods=["GET"]),
    Route("/api/a/{path:path}", service_a_route, methods=["GET", "POST", "PUT", "PATCH"]),
    Route("/api/b/{path:path}", service_b_route, methods=["GET", "POST", "PUT", "PATCH"]),
]

app = Starlette(routes=routes)

# Order: JWTAuth added first (innermost), WAF added second (outermost).
# WAF runs first on every request — blocks payloads before auth even evaluates.
app.add_middleware(JWTAuthMiddleware)
app.add_middleware(WAFMiddleware)
