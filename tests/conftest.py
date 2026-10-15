"""Pytest fixtures: test DB, all 4 services, test clients."""
import os
import subprocess
import time
from pathlib import Path

import pytest
import httpx


TEST_DB = "gateway_test_db"
ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"

PORTS = {
    "auth": 8101,
    "mock_a": 9101,
    "mock_b": 9102,
    "gateway": 8180,
}


def _psql(sql: str, db: str = "postgres") -> str:
    result = subprocess.run(
        ["psql", "-d", db, "-tAc", sql],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _load_env() -> dict:
    env = os.environ.copy()
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    _psql(f'DROP DATABASE IF EXISTS "{TEST_DB}";')
    _psql(f'CREATE DATABASE "{TEST_DB}";')
    os.environ["DATABASE_URL"] = f"postgresql://localhost/{TEST_DB}"
    yield
    _psql(f'DROP DATABASE IF EXISTS "{TEST_DB}";')


def _start(app_path: str, port: int, env: dict) -> subprocess.Popen:
    log_path = ROOT / f".pytest_service_{port}.log"
    log_file = open(log_path, "w")
    proc = subprocess.Popen(
        ["uvicorn", app_path, "--host", "127.0.0.1", "--port", str(port)],
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        cwd=str(ROOT),
    )
    proc._log_file = log_file  # keep reference so it isn't garbage-collected
    proc._log_path = log_path
    return proc


def _wait_healthy(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=0.5)
            if r.status_code == 200:
                return True
        except Exception:
            time.sleep(0.2)
    return False


@pytest.fixture(scope="session")
def services(setup_test_db):
    """Start all four services on test ports."""
    env = _load_env()
    env["DATABASE_URL"] = f"postgresql://localhost/{TEST_DB}"
    # Wire the gateway to the test ports
    env["AUTH_SERVICE_URL"] = f"http://127.0.0.1:{PORTS['auth']}"
    env["MOCK_A_URL"] = f"http://127.0.0.1:{PORTS['mock_a']}"
    env["MOCK_B_URL"] = f"http://127.0.0.1:{PORTS['mock_b']}"

    procs = []
    try:
        procs.append(_start("auth_service.main:app", PORTS["auth"], env))
        procs.append(_start("mock_service_a.main:app", PORTS["mock_a"], env))
        procs.append(_start("mock_service_b.main:app", PORTS["mock_b"], env))
        procs.append(_start("gateway.main:app", PORTS["gateway"], env))

        for name, port in [("auth", PORTS["auth"]),
                           ("mock_a", PORTS["mock_a"]),
                           ("mock_b", PORTS["mock_b"]),
                           ("gateway", PORTS["gateway"])]:
            if not _wait_healthy(f"http://127.0.0.1:{port}/health"):
                # Print log for debugging
                log_file = ROOT / f".pytest_service_{port}.log"
                log_content = log_file.read_text() if log_file.exists() else "(no log)"
                raise RuntimeError(
                    f"{name} service did not become healthy on port {port}\n"
                    f"--- last 40 lines of {log_file.name} ---\n"
                    f"{chr(10).join(log_content.splitlines()[-40:])}"
                )

        yield {
            "auth": f"http://127.0.0.1:{PORTS['auth']}",
            "mock_a": f"http://127.0.0.1:{PORTS['mock_a']}",
            "mock_b": f"http://127.0.0.1:{PORTS['mock_b']}",
            "gateway": f"http://127.0.0.1:{PORTS['gateway']}",
        }
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()


@pytest.fixture
def auth_client(services):
    with httpx.Client(base_url=services["auth"], timeout=5.0) as c:
        yield c


@pytest.fixture
def gateway_client(services):
    with httpx.Client(base_url=services["gateway"], timeout=5.0) as c:
        yield c


@pytest.fixture(autouse=True)
def clean_tables(setup_test_db):
    """Wipe users and refresh_tokens before each test.

    The tables may not exist on the very first test run (they're created
    by the auth service's lifespan on startup). Guard with to_regclass.
    """
    try:
        _psql(
            """
            DO $$
            BEGIN
                IF to_regclass('public.users') IS NOT NULL THEN
                    TRUNCATE refresh_tokens, users RESTART IDENTITY CASCADE;
                END IF;
            END $$;
            """,
            db=TEST_DB,
        )
    except RuntimeError:
        # Schema not ready yet — first test will initialize it
        pass
    yield


# ---------------------------------------------------------------------------
# Backward compatibility: test_auth.py uses `client` for the auth service
# ---------------------------------------------------------------------------

@pytest.fixture
def client(auth_client):
    """Alias for auth_client, used by test_auth.py."""
    yield auth_client


# ---------------------------------------------------------------------------
# Global rate-limit cleanup: flush Redis before every test
# ---------------------------------------------------------------------------

import redis as _redis


@pytest.fixture(autouse=True)
def flush_redis_counters():
    """Wipe rate-limit keys before and after every test.

    Without this, requests counted in one test leak into the next,
    causing spurious 429 responses.
    """
    def _flush():
        try:
            r = _redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)
            r.flushdb()
        except _redis.RedisError:
            pass

    _flush()
    yield
    _flush()
