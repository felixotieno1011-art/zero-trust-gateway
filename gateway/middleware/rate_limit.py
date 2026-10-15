"""Redis sliding-window rate limiter for the gateway.

Three independent buckets per request:
- per-IP:         default 100 requests / 60s
- per-user:       300 requests / 60s (only after JWT verified)
- per-endpoint:   overrides for sensitive paths (e.g. login: 5/min)

Uses Redis sorted sets: each request adds a member with score=now.
Before counting, we remove entries older than the window. Remaining
count is compared to the limit.

Sliding window avoids the fixed-window boundary problem where a client
can do 2x the limit by timing requests around the reset boundary.
"""
import os
import secrets
import time
from pathlib import Path

import redis
from dotenv import load_dotenv
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_WINDOW_SECONDS = 60

# (limit, window_seconds) per bucket type
IP_LIMIT = (int(os.getenv("RATE_LIMIT_IP_PER_MIN", "100")), DEFAULT_WINDOW_SECONDS)
USER_LIMIT = (int(os.getenv("RATE_LIMIT_USER_PER_MIN", "300")), DEFAULT_WINDOW_SECONDS)

# Endpoint-specific overrides (path prefix -> (limit, window))
ENDPOINT_LIMITS = {
    "/auth/login": (5, 60),
    "/auth/refresh": (10, 60),
    "/auth/register": (5, 60),
    "/auth/logout": (10, 60),
}

PUBLIC_PATHS = {
    "/health",
}


# ---------------------------------------------------------------------------
# Redis client (lazy singleton)
# ---------------------------------------------------------------------------

_redis_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        _redis_client = redis.Redis.from_url(url, decode_responses=True)
    return _redis_client


def reset_redis_client() -> None:
    """For tests: drop the cached client so a new one is created."""
    global _redis_client
    _redis_client = None


# ---------------------------------------------------------------------------
# Core algorithm
# ---------------------------------------------------------------------------

def check_and_record(key: str, limit: int, window_seconds: int) -> tuple[bool, int, int]:
    """Sliding-window check.

    Returns (allowed, remaining, reset_seconds).
    On Redis failure: fails open (allowed=True) so the gateway stays up.
    """
    try:
        r = get_redis()
        now = time.time()
        cutoff = now - window_seconds

        # Unique member: now + random suffix so same-millisecond requests don't collide
        member = f"{now}:{secrets.token_hex(4)}"

        # Pipeline for atomicity at the app level (not strict across replicas,
        # but sufficient for single-instance gateway; use Lua for multi-instance)
        pipe = r.pipeline()
        pipe.zremrangebyscore(key, 0, cutoff)
        pipe.zadd(key, {member: now})
        pipe.zcard(key)
        pipe.expire(key, window_seconds + 1)
        results = pipe.execute()

        count = results[2]  # after zremrangebyscore + zadd

        if count > limit:
            # Over the limit — roll back by removing our own entry
            r.zrem(key, member)
            remaining = 0
            allowed = False
        else:
            remaining = max(0, limit - count)
            allowed = True

        return allowed, remaining, window_seconds
    except redis.RedisError:
        # Fail open — a broken limiter shouldn't take the gateway down
        return True, limit, window_seconds


def _client_ip(request: Request) -> str:
    """Best-effort client IP. Prefer X-Forwarded-For's first entry (when
    behind a trusted proxy) but fall back to the socket peer."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _endpoint_limit(path: str) -> tuple[int, int] | None:
    for prefix, cfg in ENDPOINT_LIMITS.items():
        if path.startswith(prefix):
            return cfg
    return None


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path in PUBLIC_PATHS:
            return await call_next(request)

        headers_to_add: dict[str, str] = {}
        blocked = False
        retry_after = 0

        # 1. Endpoint-specific limit (strictest, checked first)
        ep = _endpoint_limit(path)
        if ep:
            limit, window = ep
            key = f"rl:endpoint:{path}:{_client_ip(request)}"
            allowed, remaining, reset = check_and_record(key, limit, window)
            if not allowed:
                blocked = True
                retry_after = reset
                headers_to_add.update({
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset),
                    "X-RateLimit-Scope": "endpoint",
                })
            else:
                headers_to_add.update({
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(reset),
                    "X-RateLimit-Scope": "endpoint",
                })

        # 2. Per-IP limit (if not already blocked)
        if not blocked:
            limit, window = IP_LIMIT
            key = f"rl:ip:{_client_ip(request)}"
            allowed, remaining, reset = check_and_record(key, limit, window)
            if not allowed:
                blocked = True
                retry_after = reset
                headers_to_add.update({
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset),
                    "X-RateLimit-Scope": "ip",
                })
            elif "X-RateLimit-Limit" not in headers_to_add:
                # Endpoint limit took the headers; otherwise show IP headers
                headers_to_add.update({
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(reset),
                    "X-RateLimit-Scope": "ip",
                })

        # 3. Per-user limit (only if auth middleware ran and set state)
        #    Note: rate_limit runs BEFORE auth in our chain, so user identity
        #    isn't available yet. We check `request.state` defensively in
        #    case middleware order changes.
        user_id = getattr(request.state, "user_id", None)
        if not blocked and user_id:
            limit, window = USER_LIMIT
            key = f"rl:user:{user_id}"
            allowed, remaining, reset = check_and_record(key, limit, window)
            if not allowed:
                blocked = True
                retry_after = reset
                headers_to_add.update({
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset),
                    "X-RateLimit-Scope": "user",
                })

        if blocked:
            return JSONResponse(
                {"error": "rate limit exceeded"},
                status_code=429,
                headers={**headers_to_add, "Retry-After": str(retry_after)},
            )

        response = await call_next(request)
        for k, v in headers_to_add.items():
            response.headers[k] = v
        return response
