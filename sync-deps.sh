#!/data/data/com.termux/files/usr/bin/bash
# Reinstall project dependencies into the venv from requirements.txt.
# Use this if tests fail with ModuleNotFoundError.
set -e

cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "No .venv found. Creating one..."
  uv venv --system-site-packages .venv
fi

source .venv/bin/activate
echo "Installing dependencies..."
uv pip install -r requirements.txt

echo ""
echo "=== Verify ==="
python -c "import starlette, uvicorn, passlib, redis, pg8000, httpx, pytest, dotenv; print('all imports OK ✅')"
