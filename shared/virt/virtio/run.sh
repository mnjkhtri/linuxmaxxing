#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

make -C "$SCRIPT_DIR" clean all
cd "$SCRIPT_DIR"
exec ./build/vmm
