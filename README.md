# Zero-Trust Identity & API Security Gateway

A reverse proxy that secures backend microservices with JWT authentication, a custom Web Application Firewall (WAF), and Redis-backed rate limiting.

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
- [ ] Auth service (register, login, JWT, /me)
- [ ] Gateway reverse proxy
- [ ] WAF module (SQLi/XSS detection)
- [ ] Redis rate limiting
- [ ] Docker Compose stack
- [ ] GitHub Actions CI
- [ ] Tests
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
