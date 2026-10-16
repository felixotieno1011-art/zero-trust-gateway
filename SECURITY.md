# Security Policy

## Overview

The Zero-Trust Identity & API Security Gateway is a reverse proxy that sits in
front of backend microservices and enforces authentication, request filtering,
and rate limiting **before** any traffic reaches internal services.

This document describes the security model, the threats we defend against, the
mitigations we implement, and the known limitations of the design.

---

## Scope

### In scope

- The gateway (`gateway/`)
- The authentication service (`auth_service/`)
- The interaction between them and the mock backends
- Container and network isolation (Docker Compose)
- Build and deployment pipeline (GitHub Actions)

### Out of scope

- The mock services (`mock_service_a/`, `mock_service_b/`) — these exist only as
  demonstration targets and contain no business logic.
- The underlying host OS, Docker daemon, or cloud provider.
- Any third-party software in `requirements.txt` beyond version pinning.

---

## Assets

What this system is designed to protect:

| Asset | Where it lives | Why it matters |
|---|---|---|
| User credentials | `users.password_hash` (bcrypt) | Compromise allows account takeover |
| Access tokens (JWT) | Client-held, short-lived (15 min) | Grants API access while valid |
| Refresh tokens | `refresh_tokens.token` (DB) | Grants ability to issue new access tokens |
| JWT signing key | `JWT_SECRET` env var | Compromise allows forging any token |
| Backend service integrity | Internal networks only | Bypassing the gateway defeats all controls |
| Audit trail | (not yet implemented, see *Known Limitations*) | Needed for incident investigation |

---

## Trust Boundaries

Data crosses trust boundaries at these points. Each is a control point.


Boundary crossings:

1. **Client → Gateway** — untrusted input. Enforced: rate limits, WAF, JWT verification, body size limits.
2. **Gateway → Auth service** — trusted, gateway-authenticated. Enforced: gateway is the only route in (network isolation).
3. **Gateway → Backend services** — trusted. The gateway strips the `Authorization` header and injects verified identity as `X-User-Id` and `X-User-Email`.
4. **Auth service → Database / Redis** — trusted, isolated on `data-net` (no host exposure, no external routing).

---

## Attack Scenarios and Mitigations

### 1. Credential stuffing / brute force login

**Attack:** Attacker submits many `(email, password)` combinations.

**Mitigation:**
- Login endpoint rate-limited to 5 requests/min per IP (`gateway/middleware/rate_limit.py`).
- Passwords compared using bcrypt with configurable rounds (`BCRYPT_ROUNDS`, default 12).
- Invalid credentials return the same generic error regardless of whether the email exists.

**Residual risk:** Distributed attacks from many IPs are not fully mitigated by
per-IP limits alone. Future work: account lockout, CAPTCHA, or third-party
bot detection.

### 2. SQL injection

**Attack:** Attacker embeds SQL metacharacters in query strings, JSON bodies,
or headers to manipulate backend database queries.

**Mitigation:**
- WAF middleware inspects URL, query string, and JSON body for 10 known SQLi
  patterns (UNION SELECT, OR 1=1, DROP TABLE, stacked statements, time-based
  delays, `information_schema` access, comment markers).
- Score-based detection: strong single patterns block immediately (weight 2);
  weak patterns require corroboration (weight 1, threshold 2).
- Double URL-decoding detects common evasion (`%2527` → `'`).
- The auth service uses parameterized queries everywhere (`conn.run(sql, **params)`),
  so even if a payload slips past the WAF, it cannot alter SQL structure.

**Residual risk:** WAF is pattern-based and can be bypassed with novel encodings
or obfuscation. The parameterized-query layer is the true defense.

### 3. Cross-site scripting (XSS)

**Attack:** Attacker submits script content in request bodies that ends up
rendered by a downstream client.

**Mitigation:**
- WAF detects `<script>`, `javascript:` URIs, `onerror=`/`onload=` handlers,
  `<iframe>`, `<svg onload>`, and `document.cookie` access.
- Body inspection walks every string value inside JSON.

**Residual risk:** This project has no HTML-rendering frontend, so XSS impact
in the current demo is limited. The WAF exists as defense-in-depth for any
future frontend.

### 4. Malicious request flooding

**Attack:** Attacker sends thousands of requests to exhaust resources.

**Mitigation:**
- Rate limiter uses Redis sorted-set sliding windows (not fixed windows).
- Three independent buckets per request: per-IP, per-user (after JWT verified),
  and per-endpoint.
- Stricter endpoint limits on `/auth/login` (5/min), `/auth/refresh` (10/min),
  `/auth/register` (5/min).
- Returns `429` with `Retry-After` header.

**Residual risk:** The rate limiter **fails open** if Redis is unreachable. This
is a deliberate trade-off (availability over strict limiting). In a
higher-security deployment, change this to fail-closed.

### 5. Token theft / replay

**Attack:** Attacker steals a valid JWT (access or refresh) and reuses it.

**Mitigation:**
- Access tokens expire in 15 minutes.
- Refresh tokens **rotate on every use**: the old token is deleted from the
  database before a new one is issued.
- Reusing a rotated-out refresh token returns `401` with
  `refresh token revoked or unknown`.
- `jti` (unique token ID) is embedded in every refresh token so tokens issued
  in the same second are still distinguishable.

**Residual risk:** Reuse detection currently returns `401` but does **not**
alert or revoke the entire session for that user. This is the top candidate
for the next security improvement (see *Roadmap*).

### 6. Header spoofing

**Attack:** Client sends `X-User-Id: 99999` directly to the gateway hoping the
backend will trust it.

**Mitigation:**
- The gateway **strips** any incoming `X-User-Id` and `X-User-Email` headers
  before injecting the values derived from the verified JWT.
- The `Authorization` header is stripped before forwarding to backends, so
  backends cannot accidentally accept a raw token.
- Backends trust only the gateway-injected headers because the network is
  isolated — only the gateway can reach them.

### 7. Network exposure of internal services

**Attack:** Direct access to the database or a backend service, bypassing the
gateway's controls.

**Mitigation:**
- Docker Compose defines three networks:
  - `edge-net` — public (gateway only)
  - `app-net` — internal (gateway + backends; Docker `internal: true`)
  - `data-net` — internal (auth service + Postgres + Redis; `internal: true`)
- Only `gateway` publishes a host port (`8080`).
- Postgres and Redis have no host ports — reachable only by services on
  `data-net`.
- Containers run as a non-root user (`appuser`, uid 1000).

---

## Known Limitations

These are intentionally **not** solved in the current version. Documented here
so reviewers know they are known, not missed.

1. **No security event audit log.** Attacks are blocked but not recorded in a
   queryable form. Planned: `security_events` table.
2. **No reuse-detection alerting.** Token reuse returns 401 but does not
   revoke the session or notify.
3. **`X-Forwarded-For` is trusted.** The rate limiter uses the first XFF entry.
   Behind an untrusted proxy, this can be spoofed. Production deployments
   should only trust XFF from known upstream proxies.
4. **No RBAC.** Any valid access token grants access to any endpoint.
5. **No account lockout.** Repeated failed logins are rate-limited but do not
   lock the account.
6. **No password complexity requirements beyond length ≥ 8.**
7. **No HTTPS termination.** TLS is expected to be handled by the deployment
   layer (reverse proxy, load balancer, or platform-managed ingress).
8. **Rate limiter fails open** on Redis errors (see #4 above).

---

## Security Testing in CI

Every push runs three additional security jobs:

- **pip-audit** — checks `requirements.txt` for known CVEs; fails the build if
  a vulnerability is found.
- **gitleaks** — scans the full git history for leaked secrets (API keys,
  JWTs, passwords).
- **bandit** — Python static analysis for common security anti-patterns
  (medium severity and above).

Plus the test suite (69 tests), which includes attack scenarios: malformed
tokens, tampered signatures, token-type confusion, WAF bypass attempts,
and rate-limit enforcement.

---

## Reporting a Vulnerability

If you believe you've found a security issue, please open a private security
advisory on GitHub rather than a public issue:

1. Navigate to the repository's **Security** tab
2. Click **Report a vulnerability**
3. Provide reproduction steps and impact assessment

Please do not publicly disclose until a fix has been released.

---

## Roadmap (Security-Focused)

Ranked by expected security value:

1. **Security event audit logging** — every failed login, WAF block, rate
   limit hit, and token reuse written to `security_events` with a
   `GET /admin/events` endpoint.
2. **Refresh token reuse detection** — reuse of a rotated token revokes the
   entire session and emits an alert event.
3. **Role-based access control (RBAC)** — `roles` and `user_roles` tables,
   `require_role()` middleware, deny-by-default.
4. **Request body size limits** — reject bodies over N KB with `413`.
5. **Admin-only audit log viewer** — simple read-only UI or JSON endpoint.

---

## Credits and License

See `LICENSE` for the license under which this code is distributed.

WAF rule patterns are inspired by the OWASP ModSecurity Core Rule Set.
JWT implementation follows RFC 7519 with HS256.
