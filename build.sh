#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(dirname "$(realpath "$0")")
SOURCE_DIR="$ROOT_DIR/linux"
BUILD_DIR="$ROOT_DIR/build"
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

"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable FUNCTION_TRACER
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable DYNAMIC_FTRACE
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable FUNCTION_GRAPH_TRACER
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable FTRACE_SYSCALLS
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable BPF
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable BPF_SYSCALL
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable BPF_JIT
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable BPF_EVENTS
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable KPROBES
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable KPROBES_ON_FTRACE
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable PERF_EVENTS
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable KALLSYMS
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable KALLSYMS_ALL
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --disable DEBUG_INFO_NONE
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable DEBUG_INFO_DWARF4
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable DEBUG_INFO_BTF
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable FPROBE

make -C "$SOURCE_DIR" O="$BUILD_DIR" olddefconfig
make -C "$SOURCE_DIR" O="$BUILD_DIR" CC="$CC" -j"$JOBS" "$@"
