#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(dirname "$(realpath "$0")")
"$ROOT_DIR/build.sh"
x86_64-linux-gnu-gcc -O2 -Wall -static -o "$ROOT_DIR/shared/_work/fork_25_processes" "$ROOT_DIR/shared/_work/fork_25_processes.c"
x86_64-linux-gnu-gcc -O2 -Wall -static -pthread -o "$ROOT_DIR/shared/_work/exercise_memory_management" "$ROOT_DIR/shared/_work/exercise_memory_management.c"
