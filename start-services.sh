#!/data/data/com.termux/files/usr/bin/bash
# Start Postgres and Redis for local development
set -e

echo "Starting PostgreSQL..."
pg_ctl -D "$PREFIX/var/lib/postgresql" -l "$PREFIX/var/lib/postgresql/logfile" start 2>/dev/null || echo "  (already running)"

echo "Starting Redis..."
redis-server --daemonize yes 2>/dev/null || true

sleep 1

echo ""
echo "=== Status ==="
psql gateway_db -tc "SELECT 'Postgres OK: ' || current_database();" 2>&1
redis-cli ping 2>&1 | sed 's/^/Redis: /'
