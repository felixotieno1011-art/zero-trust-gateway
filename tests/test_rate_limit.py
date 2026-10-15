"""Rate limiter tests: per-IP, per-endpoint, and header behaviour."""
import redis
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register_and_login(gateway_client, email="rl-user@example.com", password="testpassword123"):
    gateway_client.post("/auth/register", json={"email": email, "password": password})
    r = gateway_client.post("/auth/login", json={"email": email, "password": password})
    return r.json()["access_token"]


# ---------------------------------------------------------------------------
# Login endpoint limit (5/min)
# ---------------------------------------------------------------------------

def test_login_limit_blocks_sixth_attempt(gateway_client):
    """The login endpoint should allow 5 requests per minute, then 429."""
    for i in range(5):
        r = gateway_client.post("/auth/login", json={"email": "x@example.com", "password": "wrong"})
        assert r.status_code == 401, f"attempt {i+1} should be 401, got {r.status_code}"

    r = gateway_client.post("/auth/login", json={"email": "x@example.com", "password": "wrong"})
    assert r.status_code == 429
    assert r.json()["error"] == "rate limit exceeded"


def test_login_429_includes_retry_after(gateway_client):
    for _ in range(5):
        gateway_client.post("/auth/login", json={"email": "x@example.com", "password": "wrong"})

    r = gateway_client.post("/auth/login", json={"email": "x@example.com", "password": "wrong"})
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    assert int(r.headers["Retry-After"]) > 0


def test_login_429_includes_ratelimit_headers(gateway_client):
    for _ in range(5):
        gateway_client.post("/auth/login", json={"email": "x@example.com", "password": "wrong"})

    r = gateway_client.post("/auth/login", json={"email": "x@example.com", "password": "wrong"})
    assert r.status_code == 429
    assert r.headers["X-RateLimit-Limit"] == "5"
    assert r.headers["X-RateLimit-Remaining"] == "0"
    assert r.headers["X-RateLimit-Scope"] == "endpoint"


# ---------------------------------------------------------------------------
# Register endpoint limit (5/min)
# ---------------------------------------------------------------------------

def test_register_limit(gateway_client):
    """Register also has a 5/min limit."""
    for i in range(5):
        r = gateway_client.post(
            "/auth/register",
            json={"email": f"new{i}@example.com", "password": "testpassword123"},
        )
        assert r.status_code == 201

    r = gateway_client.post(
        "/auth/register",
        json={"email": "new99@example.com", "password": "testpassword123"},
    )
    assert r.status_code == 429


# ---------------------------------------------------------------------------
# Public paths are exempt
# ---------------------------------------------------------------------------

def test_health_not_rate_limited(gateway_client):
    """Public /health should not consume rate-limit budget."""
    for _ in range(50):
        r = gateway_client.get("/health")
        assert r.status_code == 200
    # No X-RateLimit-* headers on public paths
    assert "X-RateLimit-Limit" not in r.headers


# ---------------------------------------------------------------------------
# Headers on successful non-public requests
# ---------------------------------------------------------------------------

def test_successful_request_includes_ratelimit_headers(gateway_client):
    token = _register_and_login(gateway_client)
    r = gateway_client.get("/api/a/hello", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert "X-RateLimit-Limit" in r.headers
    assert "X-RateLimit-Remaining" in r.headers
    assert "X-RateLimit-Reset" in r.headers


def test_remaining_decrements_across_requests(gateway_client):
    token = _register_and_login(gateway_client)
    r1 = gateway_client.get("/api/a/hello", headers={"Authorization": f"Bearer {token}"})
    r2 = gateway_client.get("/api/a/hello", headers={"Authorization": f"Bearer {token}"})
    r3 = gateway_client.get("/api/a/hello", headers={"Authorization": f"Bearer {token}"})

    rem1 = int(r1.headers["X-RateLimit-Remaining"])
    rem2 = int(r2.headers["X-RateLimit-Remaining"])
    rem3 = int(r3.headers["X-RateLimit-Remaining"])

    assert rem1 > rem2 > rem3, f"remaining should decrease: {rem1}, {rem2}, {rem3}"


# ---------------------------------------------------------------------------
# Separate buckets by IP header
# ---------------------------------------------------------------------------

def test_different_ips_have_separate_buckets(gateway_client):
    """Two different X-Forwarded-For IPs shouldn't share a bucket."""
    # IP A sends 5 requests (login limit)
    for _ in range(5):
        gateway_client.post(
            "/auth/login",
            json={"email": "x@example.com", "password": "wrong"},
            headers={"X-Forwarded-For": "10.0.0.1"},
        )
    # IP A is now blocked
    r_a = gateway_client.post(
        "/auth/login",
        json={"email": "x@example.com", "password": "wrong"},
        headers={"X-Forwarded-For": "10.0.0.1"},
    )
    assert r_a.status_code == 429

    # IP B should still work (fresh bucket)
    r_b = gateway_client.post(
        "/auth/login",
        json={"email": "x@example.com", "password": "wrong"},
        headers={"X-Forwarded-For": "10.0.0.2"},
    )
    assert r_b.status_code == 401, "IP B should not be affected by IP A's limit"


# ---------------------------------------------------------------------------
# Different endpoints have separate buckets
# ---------------------------------------------------------------------------

def test_login_and_register_have_separate_buckets(gateway_client):
    """Hitting the login limit shouldn't affect register."""
    for _ in range(5):
        gateway_client.post(
            "/auth/login",
            json={"email": "x@example.com", "password": "wrong"},
        )
    # login is now exhausted; register should still work
    r = gateway_client.post(
        "/auth/register",
        json={"email": "fresh@example.com", "password": "testpassword123"},
    )
    assert r.status_code == 201


# ---------------------------------------------------------------------------
# 429 body shape
# ---------------------------------------------------------------------------

def test_429_response_body_structure(gateway_client):
    for _ in range(5):
        gateway_client.post("/auth/login", json={"email": "x@example.com", "password": "wrong"})

    r = gateway_client.post("/auth/login", json={"email": "x@example.com", "password": "wrong"})
    assert r.status_code == 429
    body = r.json()
    assert body["error"] == "rate limit exceeded"


# ---------------------------------------------------------------------------
# WAF still runs even after rate-limit exhaustion
# ---------------------------------------------------------------------------

def test_waf_runs_after_rate_limit_not_exhausted(gateway_client):
    """A clean request still passes through WAF+auth — the limiter didn't break anything."""
    token = _register_and_login(gateway_client)
    r = gateway_client.get(
        "/api/a/hello",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
