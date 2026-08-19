#!/bin/sh
set -eu

PORT="${PORT:-8000}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

printf 'Serving kernel study app from %s (cache disabled)\n' "$ROOT"
printf 'Open http://localhost:%s/app/\n' "$PORT"

exec python3 "$ROOT/serve.py" "$PORT" "$ROOT"
