"""WAF middleware tests: SQLi/XSS detection and blocking."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_token(gateway_client, email="waf-user@example.com", password="testpassword123"):
    gateway_client.post("/auth/register", json={"email": email, "password": password})
    r = gateway_client.post("/auth/login", json={"email": email, "password": password})
    return r.json()["access_token"]


def assert_blocked(response, expected_rule_fragment=None):
    """Assert the WAF blocked the request."""
    assert response.status_code == 403, f"expected 403, got {response.status_code}: {response.text}"
    body = response.json()
    assert body["error"] == "request blocked by WAF"
    assert "reason" in body
    assert "X-WAF-Blocked" in response.headers
    if expected_rule_fragment:
        assert expected_rule_fragment in body["reason"], (
            f"expected '{expected_rule_fragment}' in reason '{body['reason']}'"
        )


# ---------------------------------------------------------------------------
# Baseline: clean requests pass
# ---------------------------------------------------------------------------

def test_clean_request_passes(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get("/api/a/hello", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_clean_query_param_passes(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?id=42&name=alice",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200


def test_clean_json_body_passes(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.post(
        "/api/a/echo",
        headers={"Authorization": f"Bearer {token}"},
        json={"search": "hello world", "count": 5},
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

def test_sqli_or_true_in_query(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?id=1' OR '1'='1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r, "sqli_or_true")


def test_sqli_or_1_equals_1(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?filter=name=admin OR 1=1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r, "sqli_always_true")


def test_sqli_union_select(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?q=1 UNION SELECT password FROM users",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r)


def test_sqli_in_json_body(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.post(
        "/api/a/echo",
        headers={"Authorization": f"Bearer {token}"},
        json={"search": "1 OR 1=1"},
    )
    assert_blocked(r, "sqli_always_true")


def test_sqli_drop_table(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?q=x; DROP TABLE users",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r, "sqli_drop")


def test_sqli_information_schema(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?q=SELECT * FROM information_schema.tables",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r, "sqli_information_schema")


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

def test_xss_script_tag_in_query(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?name=<script>alert(1)</script>",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r, "xss_script_tag")


def test_xss_javascript_uri(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?url=javascript:alert(1)",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r, "xss_javascript_uri")


def test_xss_onerror_handler(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        '/api/a/echo?img=<img src=x onerror="alert(1)">',
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r)


def test_xss_in_json_body(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.post(
        "/api/a/echo",
        headers={"Authorization": f"Bearer {token}"},
        json={"comment": "<script>alert(document.cookie)</script>"},
    )
    assert_blocked(r, "xss_script_tag")


def test_xss_iframe(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?html=<iframe src=evil.com></iframe>",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r, "xss_iframe")


# ---------------------------------------------------------------------------
# WAF runs before auth — attack blocked even without a token
# ---------------------------------------------------------------------------

def test_waf_blocks_attack_without_token(gateway_client):
    """WAF is the outermost middleware. Attacks must be rejected even
    when no JWT is present — the request never reaches auth logic."""
    r = gateway_client.get("/api/a/echo?id=1' OR '1'='1")
    assert_blocked(r, "sqli_or_true")


def test_waf_blocks_xss_without_token(gateway_client):
    r = gateway_client.get("/api/a/echo?name=<script>alert(1)</script>")
    assert_blocked(r, "xss_script_tag")


# ---------------------------------------------------------------------------
# Attack surface coverage: public endpoints are also protected
# ---------------------------------------------------------------------------

def test_waf_blocks_attack_on_public_endpoint(gateway_client):
    """Even /auth/login is behind the WAF — SQLi in the email field
    is blocked before it reaches the auth service."""
    r = gateway_client.post(
        "/auth/login",
        json={"email": "admin' OR '1'='1", "password": "x"},
    )
    assert_blocked(r)


# ---------------------------------------------------------------------------
# URL-encoding evasion
# ---------------------------------------------------------------------------

def test_waf_detects_url_encoded_sqli(gateway_client):
    """Double-encoded payloads must still be caught."""
    token = get_token(gateway_client)
    # %2527 decodes to %27 (single quote) after a second decode
    r = gateway_client.get(
        "/api/a/echo?id=1%2527%2520OR%2520%25271%2527%253D%25271",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_blocked(r)


# ---------------------------------------------------------------------------
# Response headers
# ---------------------------------------------------------------------------

def test_waf_response_includes_blocked_rule_header(gateway_client):
    token = get_token(gateway_client)
    r = gateway_client.get(
        "/api/a/echo?q=<script>alert(1)</script>",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403
    assert r.headers["X-WAF-Blocked"]  # non-empty
    # The header names the exact rule that fired
    assert "xss" in r.headers["X-WAF-Blocked"].lower()
