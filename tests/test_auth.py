"""HTTP tests for the auth service."""
import time


def register(client, email="user@example.com", password="testpassword123"):
    return client.post("/register", json={"email": email, "password": password})


def login(client, email="user@example.com", password="testpassword123"):
    return client.post("/login", json={"email": email, "password": password})


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

def test_register_success(client):
    r = register(client)
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "user@example.com"
    assert isinstance(body["id"], int)


def test_register_duplicate_email(client):
    register(client)
    r = register(client)
    assert r.status_code == 409
    assert r.json()["error"] == "email already registered"


def test_register_invalid_email(client):
    r = register(client, email="not-an-email")
    assert r.status_code == 400
    assert "email" in r.json()["error"].lower()


def test_register_weak_password(client):
    r = register(client, password="short")
    assert r.status_code == 400
    assert "8 characters" in r.json()["error"]


def test_register_normalizes_email_case(client):
    r = register(client, email="Mixed@Example.com")
    assert r.status_code == 201
    assert r.json()["email"] == "mixed@example.com"


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def test_login_success(client):
    register(client)
    r = login(client)
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0


def test_login_wrong_password(client):
    register(client)
    r = login(client, password="wrongpassword")
    assert r.status_code == 401
    assert r.json()["error"] == "invalid credentials"


def test_login_unknown_user(client):
    r = login(client, email="nobody@example.com")
    assert r.status_code == 401
    assert r.json()["error"] == "invalid credentials"


# ---------------------------------------------------------------------------
# /me
# ---------------------------------------------------------------------------

def test_me_with_valid_token(client):
    register(client)
    tokens = login(client).json()
    r = client.get("/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
    assert r.json()["email"] == "user@example.com"


def test_me_without_token(client):
    r = client.get("/me")
    assert r.status_code == 401
    assert r.json()["error"] == "missing bearer token"


def test_me_with_malformed_token(client):
    r = client.get("/me", headers={"Authorization": "Bearer garbage.token.here"})
    assert r.status_code == 401


def test_me_with_tampered_token(client):
    register(client)
    tokens = login(client).json()
    tampered = tokens["access_token"] + "x"
    r = client.get("/me", headers={"Authorization": f"Bearer {tampered}"})
    assert r.status_code == 401


def test_me_rejects_refresh_token(client):
    """A refresh token must not be accepted as an access token."""
    register(client)
    tokens = login(client).json()
    r = client.get("/me", headers={"Authorization": f"Bearer {tokens['refresh_token']}"})
    assert r.status_code == 401
    assert r.json()["error"] == "invalid token type"


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

def test_refresh_issues_new_tokens(client):
    register(client)
    tokens = login(client).json()
    r = client.post("/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    new = r.json()
    assert new["access_token"] != tokens["access_token"]
    assert new["refresh_token"] != tokens["refresh_token"]


def test_refresh_rotates_token(client):
    """Old refresh token must be rejected after use."""
    register(client)
    old_refresh = login(client).json()["refresh_token"]

    r1 = client.post("/refresh", json={"refresh_token": old_refresh})
    assert r1.status_code == 200

    # Reuse the old one
    r2 = client.post("/refresh", json={"refresh_token": old_refresh})
    assert r2.status_code == 401
    assert "revoked" in r2.json()["error"].lower()


def test_refresh_with_garbage(client):
    r = client.post("/refresh", json={"refresh_token": "garbage.token.here"})
    assert r.status_code == 401


def test_refresh_missing_field(client):
    r = client.post("/refresh", json={})
    assert r.status_code == 400
    assert "refresh_token" in r.json()["error"]


def test_refresh_rejects_access_token(client):
    """An access token must not be usable as a refresh token."""
    register(client)
    tokens = login(client).json()
    r = client.post("/refresh", json={"refresh_token": tokens["access_token"]})
    assert r.status_code == 401
    assert r.json()["error"] == "invalid token type"


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

def test_logout_revokes_token(client):
    register(client)
    refresh = login(client).json()["refresh_token"]

    r1 = client.post("/logout", json={"refresh_token": refresh})
    assert r1.status_code == 200
    assert r1.json()["status"] == "logged out"

    # Token must no longer work
    r2 = client.post("/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 401


def test_logout_unknown_token(client):
    r = client.post("/logout", json={"refresh_token": "a.b.c"})
    assert r.status_code == 404
