
[![CI](https://github.com/felixotieno1011-art/zero-trust-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/felixotieno1011-art/zero-trust-gateway/actions/workflows/ci.yml)
[![Security Scan](https://github.com/felixotieno1011-art/zero-trust-gateway/actions/workflows/security.yml/badge.svg)](https://github.com/felixotieno1011-art/zero-trust-gateway/actions/workflows/security.yml)
![Tests](https://img.shields.io/badge/tests-69%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)


# Zero-Trust Identity & API Security Gateway

A reverse proxy that secures backend microservices with JWT authentication, a custom Web Application Firewall (WAF), and Redis-backed rate limiting.

## What is this?

A security gateway that sits between the internet and your backend services.
Every incoming request passes through it before reaching anything internal.

The gateway does four things on every request:

1. **Rate limits** — blocks clients sending too many requests
2. **Filters malicious payloads** — blocks SQL injection and XSS attacks
3. **Verifies identity** — checks a JWT token to know who the caller is
4. **Forwards clean requests** — passes authenticated traffic to backend services

Backends never see the internet directly. They only see requests the gateway
has already approved, with a verified user identity attached.

---

## What problem does it solve?

Without a gateway, every backend service has to handle its own authentication,
rate limiting, and input validation. That's a lot of duplicated code, and any
service that forgets one of those gets compromised.

With a gateway:

| Client sends... | What happens |
|---|---|
| 500 login attempts per minute | Rate limiter returns `429 Too Many Requests` |
| `' OR '1'='1` in a query string | WAF returns `403 request blocked by WAF` |
| No JWT token | Auth middleware returns `401 missing bearer token` |
| A valid JWT | Gateway verifies it, injects user identity, forwards to backend |
| A stolen refresh token reused after rotation | `401 refresh token revoked or unknown` |

---

## Quick start

### Prerequisites

- Docker and Docker Compose (v2)
- Or: Python 3.12+, PostgreSQL, and Redis running locally

### Run the full stack with Docker

```bash
# 1. Clone the repo
git clone https://github.com/felixotieno1011-art/zero-trust-gateway.git
cd zero-trust-gateway

# 2. Create a .env with a JWT secret (must be 32+ chars)
cat > .env << 'EOF'
JWT_SECRET=change-me-to-a-random-48-char-string
POSTGRES_PASSWORD=gateway_dev_password
EOF

# 3. Start everything
docker compose up -d

# 4. Wait ~10 seconds, then check
curl http://localhost:8080/health
## Why Starlette instead of FastAPI

Built and tested on Termux (Android, aarch64, Python 3.14). FastAPI's dependency on `pydantic-core` (Rust) cannot be built on this target because `rustup` does not support `aarch64-unknown-linux-android`. Starlette provides the same async framework primitives without Rust dependencies.

## Stack

- **Starlette** — async web framework
- **Custom JWT** — HS256 implementation using Python stdlib (`hmac`, `hashlib`)
- **PostgreSQL** — user store, connected via `pg8000` (pure-Python driver)
- **Redis** — rate limiting and session cache
- **bcrypt** — password hashing via `passlib`
- **Docker Compose** — network isolation (edge / app / data)
- **GitHub Actions** — CI validation

## Roadmap

- [x] Repo + project structure
- [x] Auth service (register, login, JWT, /me)
- [x] Gateway reverse proxy
- [x] WAF module (SQLi/XSS detection)
- [x] Redis rate limiting
- [x] Docker Compose stack
- [x] GitHub Actions CI
- [x] Tests (69 passing)
- [ ] Deployment

## Local Development

```bash
uv pip install starlette uvicorn passlib redis pg8000 python-multipart email-validator pytest httpx
uvicorn auth_service.main:app --host 127.0.0.1 --port 8001 --reload

## Progress Log

### Day 1 — Auth Service ✅
- [x] Starlette app with lifespan schema init
- [x] Custom HS256 JWT (stdlib only)
- [x] bcrypt password hashing (direct, no passlib)
- [x] PostgreSQL users + refresh_tokens tables
- [x] Endpoints: /health, /register, /login, /me
- [x] 8 attack tests verified (401/400/409 as appropriate)

### Day 2 — Coming Next
- [ ] POST /refresh (token rotation)
- [ ] POST /logout (token revocation)
- [ ] Pytest suite with HTTP tests

### Day 2 — Token Lifecycle + Tests ✅
- [x] POST /refresh with token rotation
- [x] POST /logout with token revocation
- [x] jti added to prevent same-second collision
- [x] 21 pytest tests, all passing
- [x] Test DB with session-scoped fixtures
- [x] Uvicorn subprocess management in tests

### Day 3 — Reverse Proxy Gateway ✅
- [x] Starlette reverse proxy on port 8080
- [x] JWT verification middleware
- [x] Two mock backends (mock-service-a, mock-service-b)
- [x] Identity injection via X-User-Id / X-User-Email headers
- [x] Header spoofing prevention (strips incoming X-User-* headers)
- [x] Authorization stripping (backends never see raw JWTs)
- [x] 14 gateway tests, 35 total, all passing

### Day 4 — WAF (Web Application Firewall) ✅
- [x] Pattern-based SQLi detection (10 rules)
- [x] Pattern-based XSS detection (8 rules)
- [x] Score-based blocking (weight 2 = auto-block, weight 1 = corroborated)
- [x] Inspects query string + JSON body + raw body
- [x] Double URL-decode to catch encoding evasion
- [x] WAF runs before auth (blocks attacks without a valid token)
- [x] X-WAF-Blocked response header names the triggering rules
- [x] 19 new tests, 54 total, all passing

### Day 4 — WAF + Lifecycle Fixes ✅
- [x] WAF middleware with 10 SQLi + 8 XSS rules
- [x] Score-based detection, double URL-decode
- [x] WAF runs before auth (blocks without a valid token)
- [x] 19 WAF tests + 4 new gateway lifecycle tests
- [x] Fixed /auth/logout missing from gateway PUBLIC_PATHS
- [x] requirements.txt + sync-deps.sh for reproducible env recovery
- [x] 58 total tests passing

### Day 5 — Redis Rate Limiting ✅
- [x] Sliding-window rate limiter (Redis sorted sets)
- [x] Per-IP (100/min), per-user (300/min), per-endpoint limits
- [x] Stricter auth endpoint limits (login/register 5/min)
- [x] X-RateLimit-* headers on every non-public response
- [x] 429 responses include Retry-After
- [x] Fails open on Redis errors
- [x] 11 new tests, 69 total passing

### Day 6 — Docker Compose + Network Isolation + CI ✅
- [x] Multi-container stack via docker-compose.yml
- [x] Network isolation: edge-net (public), app-net + data-net (internal)
- [x] Non-root user in containers, health checks on every service
- [x] Databases never exposed to host
- [x] GitHub Actions CI: test job (69 tests) + docker job (end-to-end smoke test)
- [x] Fixed cross-environment issues: psql over TCP, DATABASE_URL urlparse,
      bcrypt in requirements.txt, python3 in docker job
- [x] Both CI jobs green

### Day 7 — Security Scans in CI ✅
- [x] pip-audit: dependency CVE scanning
- [x] gitleaks: secret scanning across full git history
- [x] bandit: Python static analysis (medium+ severity)
- [x] Weekly scheduled run to catch newly-disclosed CVEs
- [x] All 5 CI jobs green (test, docker, pip-audit, gitleaks, bandit)


## Documentation

- [SECURITY.md](SECURITY.md) — threat model, attack scenarios, mitigations
- [docs/architecture.md](docs/architecture.md) — system diagrams, design decisions
- [docs/api.md](docs/api.md) — full endpoint reference
