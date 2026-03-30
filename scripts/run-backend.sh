#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
PYTHON="$BACKEND/.venv/bin/python"
HOST="${1:-0.0.0.0}"
PORT="${2:-8000}"

if [[ ! -x "$PYTHON" ]]; then
  echo "Missing backend virtual environment at backend/.venv. Create it first with: python3 -m venv backend/.venv" >&2
  exit 1
fi

cd "$BACKEND"
exec "$PYTHON" -m uvicorn app.main:app --reload --host "$HOST" --port "$PORT"
