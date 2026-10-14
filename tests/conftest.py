"""Pytest fixtures: test DB, test client, clean state per session."""
import os
import subprocess
import time

import pytest
import httpx


TEST_DB = "gateway_test_db"
TEST_PORT = 8002


def _psql(sql: str, db: str = "postgres") -> str:
    """Run a psql command against a specific DB. Returns stdout."""
    result = subprocess.run(
        ["psql", "-d", db, "-tAc", sql],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()}")
    return result.stdout.strip()


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create a fresh test database for the whole test session."""
    _psql(f'DROP DATABASE IF EXISTS "{TEST_DB}";')
    _psql(f'CREATE DATABASE "{TEST_DB}";')

    os.environ["DATABASE_URL"] = f"postgresql://localhost/{TEST_DB}"

    yield

    _psql(f'DROP DATABASE IF EXISTS "{TEST_DB}";')


@pytest.fixture(scope="session")
def app_server(setup_test_db):
    """Start uvicorn on a test port and wait for it to be ready."""
    env = os.environ.copy()
    env["DATABASE_URL"] = f"postgresql://localhost/{TEST_DB}"

    # Ensure JWT_SECRET is present — load from project .env if missing
    if "JWT_SECRET" not in env:
        env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
        with open(env_file) as f:
            for line in f:
                if line.startswith("JWT_SECRET="):
                    env["JWT_SECRET"] = line.strip().split("=", 1)[1]
                    break

    proc = subprocess.Popen(
        ["uvicorn", "auth_service.main:app",
         "--host", "127.0.0.1", "--port", str(TEST_PORT)],
        env=env,
        stdout=subprocess.DEVNULL,   # <-- critical fix: don't fill pipe buffer
        stderr=subprocess.DEVNULL,
    )

    # Wait for server to accept connections
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError(f"Test server exited early with code {proc.returncode}")
        try:
            r = httpx.get(f"http://127.0.0.1:{TEST_PORT}/health", timeout=0.5)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.2)
    else:
        proc.terminate()
        proc.wait(timeout=5)
        raise RuntimeError("Test server did not start in 12 seconds")

    yield f"http://127.0.0.1:{TEST_PORT}"

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture
def client(app_server):
    """HTTP client for the test server."""
    with httpx.Client(base_url=app_server, timeout=5.0) as c:
        yield c


@pytest.fixture(autouse=True)
def clean_tables(setup_test_db):
    """Wipe users and refresh_tokens before each test."""
    _psql("TRUNCATE refresh_tokens, users RESTART IDENTITY CASCADE;", db=TEST_DB)
    yield
