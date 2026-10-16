# Architecture

Zero-Trust Identity & API Security Gateway.

## System Diagram

    Client  -->  Gateway (port 8080)  -->  Auth Service (8001)
                                       -->  Mock A (9001)
                                       -->  Mock B (9002)

    Auth Service  -->  PostgreSQL (5432)
    Auth Service  -->  Redis (6379)
    Gateway       -->  Redis (6379)

## Networks

- edge-net (public):  gateway only
- app-net  (internal): gateway + auth + mocks
- data-net (internal): auth + postgres + redis

Only the gateway publishes a host port. Databases are unreachable
from the host and from the internet.

## Middleware Chain

Every request passes through, in order:

1. Rate limit  ->  429 if over limit
2. WAF         ->  403 if malicious
3. JWT auth    ->  401 if invalid token
4. Proxy       ->  forward to backend

## Identity Injection

The gateway verifies the JWT, strips the Authorization header, and
injects X-User-Id and X-User-Email from the token payload before
forwarding. Backends trust only these headers because they are
network-isolated from everything except the gateway.

## Token Lifecycle

- Register:  bcrypt hash, stored in users table
- Login:     bcrypt verify, issue access (15 min) + refresh (7 days)
- Refresh:   rotate; old refresh token deleted, new pair issued
- Logout:    delete refresh token

## Directory Layout

    auth_service/     Authentication + JWT issuance
    gateway/          Reverse proxy + middleware
    mock_service_a/   Demo backend
    mock_service_b/   Demo backend
    tests/            69 pytest tests
    docs/             This file + api.md
    SECURITY.md       Threat model
    docker-compose.yml
    Dockerfile.service

## Design Decisions

**Starlette over FastAPI:** FastAPI needs pydantic-core, which requires
a Rust toolchain. Termux's Rust target triple (aarch64-unknown-linux-android)
is not supported by rustup. Starlette is the same ASGI framework FastAPI
is built on, minus pydantic.

**Custom JWT:** python-jose and PyJWT pull in C/Rust extensions.
HS256 only needs stdlib hmac + hashlib.

**Redis sorted sets for rate limiting:** fixed-window counters allow
2x bursts at boundaries. Sliding windows don't.

**Three Docker networks:** A gateway that doesn't isolate backends is
defense-in-depth theater. internal:true blocks host routing.

**Fail-open rate limiting:** if Redis dies, we allow requests. Rate
limiting is protection, not a gate.
