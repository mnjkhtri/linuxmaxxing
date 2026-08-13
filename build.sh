#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(dirname "$(realpath "$0")")
SOURCE_DIR="$ROOT_DIR/linux"
BUILD_DIR="$ROOT_DIR/build"
if [[ -z ${JOBS:-} ]]; then
  AVAILABLE_JOBS=$(nproc)
  JOBS=$((AVAILABLE_JOBS > 1 ? AVAILABLE_JOBS / 2 : 1))
fi

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

# Tracefs/ftrace events used by the visualizers.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable FUNCTION_TRACER              # ftrace function-entry plumbing.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable DYNAMIC_FTRACE               # Runtime patching for low-overhead ftrace.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable FTRACE_SYSCALLS              # Syscall tracepoints in tracefs.

# eBPF loading and attachment paths used by shared/memory and shared/scheduler.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable BPF_SYSCALL                  # bpf() syscall for loading programs/maps.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable BPF_JIT                      # JIT eBPF for practical runtime cost.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable BPF_EVENTS                   # Attach eBPF to perf/trace events.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable FPROBE                       # fprobe/fentry-style instrumentation support.

# Type metadata for CO-RE BPF.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --disable DEBUG_INFO_NONE             # Defconfig chooses no debug info.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT # Minimal DWARF source for pahole.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable DEBUG_INFO_BTF               # BTF type info for CO-RE eBPF.

# Memory-management experiments.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable MEMCG                        # cgroup-v2 memory stats and swap accounting.

# Transparent huge page behavior controlled by the workload with madvise().
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable TRANSPARENT_HUGEPAGE         # Anonymous/file THP behavior.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --enable TRANSPARENT_HUGEPAGE_MADVISE # THP only when explicitly requested.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --disable TRANSPARENT_HUGEPAGE_ALWAYS # Avoid unrelated automatic THP noise.
"$SOURCE_DIR/scripts/config" --file "$BUILD_DIR/.config" --disable TRANSPARENT_HUGEPAGE_NEVER  # Keep THP available for MADV_HUGEPAGE.

make -C "$SOURCE_DIR" O="$BUILD_DIR" olddefconfig
make -C "$SOURCE_DIR" O="$BUILD_DIR" CC="$CC" -j"$JOBS" "$@"
