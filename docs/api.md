# API Reference

All endpoints are exposed through the gateway at http://localhost:8080.
Backend services are never called directly.

## Authentication

Protected endpoints require an `Authorization: Bearer <access_token>` header.
Obtain a token via `POST /auth/login` or `POST /auth/refresh`.

Access tokens expire in 15 minutes.

## Endpoints

### GET /health

Gateway health check. Public. Not rate-limited.

Response 200:
    {"status": "ok", "service": "gateway"}

---

### POST /auth/register

Create a new user account. Rate limit: 5/min per IP.

Request body:
    {"email": "user@example.com", "password": "at-least-8-chars"}

Response 201:
    {"id": 1, "email": "user@example.com"}

Errors:
- 400 invalid JSON, invalid email, or password too short
- 409 email already registered
- 403 WAF blocked a malicious payload
- 429 rate limit exceeded

---

### POST /auth/login

Authenticate and issue tokens. Rate limit: 5/min per IP.

Request body:
    {"email": "user@example.com", "password": "at-least-8-chars"}

Response 200:
    {"access_token": "...", "refresh_token": "...", "token_type": "bearer", "expires_in": 900}

Errors:
- 400 invalid JSON or missing fields
- 401 invalid credentials
- 429 rate limit exceeded

---

### POST /auth/refresh

Exchange a refresh token for a new access + refresh pair.
The old refresh token is revoked on use (rotation).
Rate limit: 10/min per IP.

Request body:
    {"refresh_token": "..."}

Response 200: new token pair

Errors:
- 400 missing refresh_token
- 401 invalid, expired, or already-revoked token
- 429 rate limit exceeded

---

### POST /auth/logout

Revoke a refresh token. Rate limit: 10/min per IP.

Request body:
    {"refresh_token": "..."}

Response 200:
    {"status": "logged out"}

Errors:
- 400 missing refresh_token
- 404 token not found

---

### GET /me

Return the authenticated user's identity. Protected.

Request headers:
    Authorization: Bearer <access_token>

Response 200:
    {"id": 1, "email": "user@example.com"}

Errors:
- 401 missing, malformed, tampered, or expired token
- 401 a refresh token was supplied instead of an access token

---

### GET /api/a/hello and GET /api/b/hello

Demo backends. Protected.

The gateway verifies the JWT, strips the Authorization header, and injects
X-User-Id / X-User-Email before forwarding.

Response 200:
    {"service": "mock-service-a", "message": "hello from mock-service-a",
     "seen_user_id": "1", "seen_user_email": "user@example.com",
     "path": "/hello"}

The seen_user_* fields prove the gateway performed identity injection.

---

## Response Headers

Non-public responses include:

    X-RateLimit-Limit: 100
    X-RateLimit-Remaining: 97
    X-RateLimit-Reset: 60
    X-RateLimit-Scope: ip

When blocked by the WAF:

    X-WAF-Blocked: sqli_or_true,sqli_quote

When rate-limited:

    HTTP/1.1 429 Too Many Requests
    Retry-After: 42

---

## Error Format

All errors return JSON:

    {"error": "<human-readable message>"}

WAF blocks include a reason field naming the triggering rules.

---

## Testing with curl

    # Register
    curl -X POST http://localhost:8080/auth/register \
      -H "Content-Type: application/json" \
      -d '{"email":"demo@example.com","password":"testpassword123"}'

    # Login and save token
    TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
      -H "Content-Type: application/json" \
      -d '{"email":"demo@example.com","password":"testpassword123"}' \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

    # Protected backend
    curl http://localhost:8080/api/a/hello \
      -H "Authorization: Bearer $TOKEN"

    # SQLi payload - blocked by WAF
    curl "http://localhost:8080/api/a/echo?id=1'%20OR%20'1'='1" \
      -H "Authorization: Bearer $TOKEN"
