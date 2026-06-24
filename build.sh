#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(dirname "$(realpath "$0")")
SOURCE_DIR="$ROOT_DIR/linux"
BUILD_DIR="$ROOT_DIR/build-x86"
JOBS=${JOBS:-$(nproc)}

mkdir -p "$BUILD_DIR"

if command -v ccache >/dev/null 2>&1; then
  export CCACHE_BASEDIR="$ROOT_DIR"
  export CCACHE_NOHASHDIR=true
  CC=${CC:-"ccache gcc"}
else
  CC=${CC:-gcc}
fi

if [[ ! -f "$BUILD_DIR/.config" ]]; then
  make -C "$SOURCE_DIR" O="$BUILD_DIR" defconfig
fi

make -C "$SOURCE_DIR" O="$BUILD_DIR" olddefconfig
make -C "$SOURCE_DIR" O="$BUILD_DIR" CC="$CC" -j"$JOBS" "$@"
