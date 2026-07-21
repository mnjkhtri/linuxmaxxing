#!/usr/bin/env bash
set -euo pipefail

mkdir -p /mnt/host/_captures
/mnt/host/ebpf/cfs_tree/cfs_tree > /mnt/host/_captures/ebpf-cfs_tree-rbtree.ndjson &
tracer=$!
cleanup() {
  kill -INT "$tracer" 2>/dev/null || true
  wait "$tracer" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
sleep 1
/mnt/host/_work/fork_25_processes
cleanup
trap - EXIT INT TERM
