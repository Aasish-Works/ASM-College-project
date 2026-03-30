#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATABASE="$ROOT/backend/asm.db"

if [[ -f "$DATABASE" ]]; then
  rm -f "$DATABASE"
  echo "Removed $DATABASE"
else
  echo "No database file found at $DATABASE"
fi

echo "Start the backend again to recreate a clean database."
