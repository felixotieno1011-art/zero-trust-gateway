"""Mock backend service A."""
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

SERVICE_NAME = "mock-service-a"


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"service": SERVICE_NAME, "status": "ok"})


async def hello(request: Request) -> JSONResponse:
    user_id = request.headers.get("x-user-id", "anonymous")
    user_email = request.headers.get("x-user-email", "unknown")
    return JSONResponse({
        "service": SERVICE_NAME,
        "message": f"hello from {SERVICE_NAME}",
        "seen_user_id": user_id,
        "seen_user_email": user_email,
        "path": str(request.url.path),
    })


async def echo(request: Request) -> JSONResponse:
    body = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()
    return JSONResponse({
        "service": SERVICE_NAME,
        "method": request.method,
        "query": dict(request.query_params),
        "body": body.decode("utf-8", errors="replace") if body else None,
    })


app = Starlette(routes=[
    Route("/health", health, methods=["GET"]),
    Route("/hello", hello, methods=["GET"]),
    Route("/echo", echo, methods=["GET", "POST", "PUT", "PATCH"]),
])
