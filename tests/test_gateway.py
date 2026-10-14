"""Tests for the zero-trust gateway: auth enforcement, routing, header injection."""
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_user(gateway_client, email="user@example.com", password="testpassword123"):
    return gateway_client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )


def login(gateway_client, email="user@example.com", password="testpassword123"):
    return gateway_client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )


def get_token(gateway_client, email="user@example.com", password="testpassword123"):
    create_user(gateway_client, email, password)
    r = login(gateway_client, email, password)
    return r.json()["access_token"]


# ---------------------------------------------------------------------------
# Gateway health
# ---------------------------------------------------------------------------

def test_gateway_health(gateway_client):
    r = gateway_client.get("/health")
    assert r.status_code == 200
    assert r.json()["service"] == "gateway"


# ---------------------------------------------------------------------------
# Public auth routes through gateway
# ---------------------------------------------------------------------------

def test_register_through_gateway(gateway_client):
    r = create_user(gateway_client)
    assert r.status_code == 201
    assert r.json()["email"] == "user@example.com"


def test_login_through_gateway(gateway_client):
    create_user(gateway_client)
    r = login(gateway_client)
    assert r.status_code == 200
    assert "access_token" in r.json()


# ---------------------------------------------------------------------------
# Zero-trust enforcement: unauthenticated requests blocked
# ---------------------------------------------------------------------------

def test_backend_a_rejects_no_token(gateway_client):
    r = gateway_client.get("/api/a/hello")
    assert r.status_code == 401
    assert r.json()["error"] == "missing bearer token"


def test_backend_b_rejects_no_token(gateway_client):
    r = gateway_client.get("/api/b/hello")
    assert r.status_code == 401


def test_backend_a_rejects_garbage_token(gateway_client):
    r = gateway_client.get(
        "/api/a/hello",
        headers={"Authorization": "Bearer garbage.token.here"},
    )
    assert r.status_code == 401


def test_backend_a_rejects_tampered_token(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/hello",
        headers={"Authorization": f"Bearer {token}x"},
    )
    assert r.status_code == 401
    assert "signature" in r.json()["error"].lower()


def test_backend_a_rejects_refresh_token(gateway_client):
    """A refresh token must not be accepted as an access token."""
    create_user(gateway_client)
    refresh = login(gateway_client).json()["refresh_token"]
    r = gateway_client.get(
        "/api/a/hello",
        headers={"Authorization": f"Bearer {refresh}"},
    )
    assert r.status_code == 401
    assert r.json()["error"] == "invalid token type"


# ---------------------------------------------------------------------------
# Authenticated routing + identity injection
# ---------------------------------------------------------------------------

def test_backend_a_accepts_valid_token(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/hello",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "mock-service-a"
    assert body["seen_user_email"] == "user@example.com"
    assert body["seen_user_id"] == "1"


def test_backend_b_accepts_valid_token(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/b/hello",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["service"] == "mock-service-b"
    assert r.json()["seen_user_email"] == "user@example.com"


def test_gateway_injects_identity_and_strips_auth(gateway_client):
    """Backends should see X-User-* headers, NOT the Authorization header."""
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/hello",
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    # Backend saw the identity via headers
    assert body["seen_user_email"] == "user@example.com"
    assert body["seen_user_id"] == "1"


def test_gateway_strips_spoofed_identity_headers(gateway_client):
    """A client cannot impersonate another user via X-User-Id."""
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/hello",
        headers={
            "Authorization": f"Bearer {token}",
            "X-User-Id": "99999",
            "X-User-Email": "attacker@evil.com",
        },
    )
    body = r.json()
    # Middleware must override forged headers with the real ones from the JWT
    assert body["seen_user_id"] == "1"
    assert body["seen_user_email"] == "user@example.com"


# ---------------------------------------------------------------------------
# /me passthrough
# ---------------------------------------------------------------------------

def test_me_through_gateway(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["email"] == "user@example.com"


def test_me_requires_auth(gateway_client):
    r = gateway_client.get("/me")
    assert r.status_code == 401
