"""Pytest fixtures: test DB, all services, HTTP clients."""
import os
import subprocess
import time
from pathlib import Path

import httpx
import pytest


TEST_DB = "gateway_test_db"
ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"

PORTS = {
    "auth": 8101,
    "mock_a": 9101,
    "mock_b": 9102,
    "gateway": 8180,
}


# ---------------------------------------------------------------------------
# psql helper — always TCP, works on Termux, CI, and Docker
# ---------------------------------------------------------------------------

def _psql(sql: str, db: str = "postgres") -> str:
    """Run psql against a specific DB and return stdout.

    Tries TCP first (which is what CI and Docker need) and falls back
    to the local socket (which is what Termux uses). This makes the
    fixture work in all three environments without config.

    Order of preference for the DB user:
      1. PGUSER env var (CI, Docker)
      2. Current OS user (Termux default)
      3. "postgres"
    """
    host = os.getenv("PGHOST", "localhost")
    password = os.getenv("PGPASSWORD", "postgres")
    user_candidates = []
    if os.getenv("PGUSER"):
        user_candidates.append(os.getenv("PGUSER"))
    try:
        import getpass
        user_candidates.append(getpass.getuser())
    except Exception:
        pass
    user_candidates.append("postgres")

    # Deduplicate while preserving order
    seen = set()
    users = [u for u in user_candidates if not (u in seen or seen.add(u))]

    last_error = ""
    for user in users:
        for extra_args in (["-h", host], []):  # TCP first, then socket
            cmd = ["psql", "-U", user, *extra_args, "-d", db, "-tAc", sql]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "PGPASSWORD": password},
            )
            if result.returncode == 0:
                return result.stdout.strip()
            last_error = result.stderr.strip()

    raise RuntimeError(f"psql failed: {last_error}")


# ---------------------------------------------------------------------------
# Env loading
# ---------------------------------------------------------------------------

def _load_env() -> dict:
    """Return a copy of os.environ with .env values merged in."""
    env = os.environ.copy()
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


# ---------------------------------------------------------------------------
# Session-scoped: test DB
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    _psql(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE);')
    _psql(f'CREATE DATABASE "{TEST_DB}";')

    # Point the app at the test DB. Reuse the connection params that
    # _psql() succeeded with so the subprocess-spawned services connect
    # the same way the test runner does.
    #
    # Priority:
    #   1. PGUSER/PGPASSWORD/PGHOST env vars (CI, Docker)
    #   2. Fallback to bare localhost URL (Termux socket auth)
    user = os.getenv("PGUSER")
    password = os.getenv("PGPASSWORD")
    host = os.getenv("PGHOST", "localhost")

    if user and password:
        os.environ["DATABASE_URL"] = (
            f"postgresql://{user}:{password}@{host}:5432/{TEST_DB}"
        )
    else:
        # Termux default: socket auth, no password in URL
        os.environ["DATABASE_URL"] = f"postgresql://localhost/{TEST_DB}"

    yield
    _psql(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE);')


# ---------------------------------------------------------------------------
# Session-scoped: all four services
# ---------------------------------------------------------------------------

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
    proc._log_file = log_file  # type: ignore[attr-defined]
    proc._log_path = log_path  # type: ignore[attr-defined]
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
    env = _load_env()
    env["DATABASE_URL"] = os.environ["DATABASE_URL"]
    env["AUTH_SERVICE_URL"] = f"http://127.0.0.1:{PORTS['auth']}"
    env["MOCK_A_URL"] = f"http://127.0.0.1:{PORTS['mock_a']}"
    env["MOCK_B_URL"] = f"http://127.0.0.1:{PORTS['mock_b']}"

    procs = []
    try:
        procs.append(_start("auth_service.main:app", PORTS["auth"], env))
        procs.append(_start("mock_service_a.main:app", PORTS["mock_a"], env))
        procs.append(_start("mock_service_b.main:app", PORTS["mock_b"], env))
        procs.append(_start("gateway.main:app", PORTS["gateway"], env))

        for name, port in [
            ("auth", PORTS["auth"]),
            ("mock_a", PORTS["mock_a"]),
            ("mock_b", PORTS["mock_b"]),
            ("gateway", PORTS["gateway"]),
        ]:
            if not _wait_healthy(f"http://127.0.0.1:{port}/health"):
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


@pytest.fixture
def client(auth_client):
    """Alias for test_auth.py."""
    yield auth_client


# ---------------------------------------------------------------------------
# Per-test: clean tables + flush Redis
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_tables(setup_test_db):
    """Truncate users + refresh_tokens before each test.

    Tables may not exist on the very first test; guard with to_regclass.
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
        pass
    yield


@pytest.fixture(autouse=True)
def flush_redis_counters():
    """Flush rate-limit keys before and after each test."""
    import redis as _redis

    def _flush():
        try:
            r = _redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)
            r.flushdb()
        except _redis.RedisError:
            pass

    _flush()
    yield
    _flush()
