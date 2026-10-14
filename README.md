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
