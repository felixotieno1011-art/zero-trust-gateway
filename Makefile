.PHONY: run test lint clean

run:
uvicorn auth_service.main:app --host 127.0.0.1 --port 8001 --reload

test:
pytest -v

lint:
python -m compileall auth-service gateway

clean:
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete
