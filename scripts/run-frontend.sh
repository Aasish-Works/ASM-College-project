#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND="$ROOT/frontend"
PORT="${1:-5173}"

cd "$FRONTEND"
exec python3 -m http.server "$PORT"
