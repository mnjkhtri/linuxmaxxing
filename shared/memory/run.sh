#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# CAPTURE MODEL
#
# One workload_mm run feeds all three capture artifacts:
#
#   memory.eBPF.ndjson   eBPF phase-boundary MM snapshots (source=ebpf)
#   memory-Phases.ndjson workload phase/meta/result records (source=workload)
#   memory-Trace.txt     raw tracefs MM event activity
#
# Both structured observers and the private tracefs instance are active before
# the workload starts, and all timestamps come from CLOCK_MONOTONIC.
# Each eBPF snapshot carries event_info.phase_seq, which is the authoritative
# link to the matching workload phase record; the frontend never guesses by time.
# tracefs stays a separate raw source used for time-correlated activity.
#
# This runner follows the scheduler reference pattern:
#   - private tracefs instance (never touches the global one)
#   - one machine-readable readiness line (LX_READY) gates the workload
#   - observer stdout is NDJSON only; diagnostics live on stderr
#   - structured cleanup on every exit path
# =============================================================================

# Run this inside the guest as root after `make -C shared/memory` on the host.

WORKLOAD=${MM_WORKLOAD:-/mnt/host/memory/workload_mm}
OBSERVER=${MM_OBSERVER:-/mnt/host/memory/build/mm}
CAPTURE_DIR=${MM_CAPTURE_DIR:-/mnt/host/_captures}
NDJSON_FILE="$CAPTURE_DIR/memory.eBPF.ndjson"
PHASES_FILE="$CAPTURE_DIR/memory-Phases.ndjson"
TRACE_FILE="$CAPTURE_DIR/memory-Trace.txt"

TRACEFS=/sys/kernel/tracing
INSTANCE_NAME=linuxmaxxing-memory
INSTANCE="$TRACEFS/instances/$INSTANCE_NAME"

# Memory spans many optional MM tracepoint categories whose availability varies by kernel.
# process VAS:
MM_EVENTS=(mmap/vm_unmapped_area mmap/exit_mmap exceptions/page_fault_user mmap_lock/mmap_lock_released tlb/tlb_flush
# page cache: faults
filemap/mm_filemap_fault filemap/mm_filemap_get_pages filemap/mm_filemap_map_pages filemap/mm_filemap_add_to_page_cache filemap/mm_filemap_delete_from_page_cache
# page cache: writeback
writeback/writeback_dirty_folio writeback/writeback_start writeback/wbc_writepage writeback/writeback_pages_written writeback/writeback_single_inode_start writeback/writeback_single_inode
# lru lifecycle
pagemap/mm_lru_insertion pagemap/mm_lru_activate
# buddy
kmem/rss_stat kmem/mm_page_alloc kmem/mm_setup_per_zone_wmarks kmem/mm_page_alloc_zone_locked kmem/mm_page_alloc_extfrag kmem/mm_page_free kmem/mm_page_free_batched kmem/mm_page_pcpu_drain
# slub/kmalloc
kmem/kmem_cache_alloc kmem/kmem_cache_free kmem/kmalloc kmem/kfree
# THP/khugepaged
huge_memory/mm_khugepaged_scan_pmd huge_memory/mm_collapse_huge_page_isolate huge_memory/mm_collapse_huge_page_swapin huge_memory/mm_collapse_huge_page huge_memory/mm_khugepaged_scan_file huge_memory/mm_khugepaged_collapse_file huge_memory/mm_khugepaged_scan
# reclaim
vmscan/mm_vmscan_direct_reclaim_begin vmscan/mm_vmscan_direct_reclaim_end vmscan/mm_vmscan_wakeup_kswapd vmscan/mm_vmscan_kswapd_wake vmscan/mm_vmscan_kswapd_sleep vmscan/mm_vmscan_balance_pgdat_begin vmscan/mm_vmscan_balance_pgdat_end vmscan/mm_vmscan_lru_isolate vmscan/mm_vmscan_lru_shrink_active vmscan/mm_vmscan_lru_shrink_inactive vmscan/mm_vmscan_write_folio vmscan/mm_vmscan_reclaim_pages
# shrinkers
vmscan/mm_shrink_slab_start vmscan/mm_shrink_slab_end
# NUMA migration
migrate/mm_migrate_pages_start migrate/mm_migrate_pages
# compaction
compaction/mm_compaction_begin compaction/mm_compaction_isolate_migratepages compaction/mm_compaction_isolate_freepages compaction/mm_compaction_migratepages compaction/mm_compaction_end compaction/mm_compaction_wakeup_kcompactd compaction/mm_compaction_kcompactd_wake compaction/mm_compaction_kcompactd_sleep compaction/mm_compaction_deferred compaction/mm_compaction_defer_compaction compaction/mm_compaction_defer_reset
# OOM
oom/reclaim_retry_zone oom/compact_retry oom/mark_victim oom/wake_reaper oom/start_task_reaping oom/finish_task_reaping oom/skip_task_reaping
# percpu allocator
percpu/percpu_alloc_percpu percpu/percpu_alloc_percpu_fail percpu/percpu_free_percpu percpu/percpu_create_chunk percpu/percpu_destroy_chunk)

SKIPPED_EVENTS=()
OBSERVER_PID=
OBSERVER_LOG=
WORKLOAD_STATUS=0
OBSERVER_STATUS=0

log()
{
	printf 'memory: %s\n' "$*" >&2
}

fail()
{
	log "error: $*"
	exit 1
}

# -----------------------------------------------------------------------------
# preflight: root, binaries, and a clean capture directory.
# -----------------------------------------------------------------------------
preflight()
{
	if [[ $(id -u) -ne 0 ]]; then
		fail "run this inside the guest as root"
	fi
	if [[ ! -x "$WORKLOAD" ]]; then
		fail "missing workload binary $WORKLOAD; run make -C shared/memory first"
	fi
	if [[ ! -x "$OBSERVER" ]]; then
		fail "missing eBPF observer $OBSERVER; run make -C shared/memory first"
	fi
	mkdir -p "$CAPTURE_DIR"
	: > "$NDJSON_FILE"
	: > "$PHASES_FILE"
	: > "$TRACE_FILE"
	log "capture directory: $CAPTURE_DIR"
}

# -----------------------------------------------------------------------------
# ensure_swap: the swap-backed pageout phases need active swap.
# The guest keeps /dev/vdb enabled for repeated runs, so cleanup never disables it.
# -----------------------------------------------------------------------------
ensure_swap()
{
	if awk 'NR > 1 { found = 1 } END { exit !found }' /proc/swaps; then
		log "active swap present"
		return
	fi
	if [[ ! -b /dev/vdb ]]; then
		fail "no swap and /dev/vdb swap disk is missing; boot the guest with boot.sh"
	fi
	swapon /dev/vdb
	if ! awk 'NR > 1 { found = 1 } END { exit !found }' /proc/swaps; then
		fail "swap activation failed"
	fi
	log "swap activated"
}

# -----------------------------------------------------------------------------
# setup_trace: a private tracefs instance on the mono clock with the MM event set.
# Events whose absence should not invalidate the experiment are enabled as optional.
# -----------------------------------------------------------------------------
setup_trace()
{
	mountpoint -q /proc || mount -t proc proc /proc
	mountpoint -q /sys || mount -t sysfs sysfs /sys
	mountpoint -q "$TRACEFS" || mount -t tracefs tracefs "$TRACEFS" 2>/dev/null || true
	[[ -d "$TRACEFS/events" ]] || fail "tracefs not available at $TRACEFS"

	if [[ -d "$INSTANCE" ]]; then
		echo 0 > "$INSTANCE/tracing_on" 2>/dev/null || true
		rmdir "$INSTANCE" 2>/dev/null || rm -rf "$INSTANCE" 2>/dev/null || true
	fi
	mkdir "$INSTANCE" || fail "cannot create tracefs instance $INSTANCE_NAME"

	echo 0 > "$INSTANCE/tracing_on"
	echo > "$INSTANCE/trace"
	# The trace_clock file lists every available clock and marks the selected one with brackets, e.g. "local [mono] global counter".
	# Test that mono is the selected clock after writing it.
	if ! echo mono > "$INSTANCE/trace_clock" 2>/dev/null || ! grep -q '\[mono\]' "$INSTANCE/trace_clock"; then
		fail "monotonic trace clock cannot be configured on instance $INSTANCE_NAME"
	fi
	# kmem/page events are noisy, so the private instance gets a large per-CPU buffer.
	if [[ -w "$INSTANCE/buffer_size_kb" ]]; then
		echo 65536 > "$INSTANCE/buffer_size_kb" 2>/dev/null || true
	fi

	for event in "${MM_EVENTS[@]}"; do
		enable_optional_event "$event"
	done
	if (( ${#SKIPPED_EVENTS[@]} > 0 )); then
		log "skipped unavailable trace events: ${SKIPPED_EVENTS[*]}"
	fi
	log "private tracefs instance ready: $INSTANCE (clock=mono)"
}

# -----------------------------------------------------------------------------
# enable_optional_event: enable a Memory-selected tracepoint when present.
# Unavailable events are reported, never silently hidden, and never fatal.
# -----------------------------------------------------------------------------
enable_optional_event()
{
	local event=$1
	local control="$INSTANCE/events/$event/enable"

	if [[ -e $control ]]; then
		echo 1 > "$control"
	else
		SKIPPED_EVENTS+=("$event")
	fi
}

# -----------------------------------------------------------------------------
# start_observer: the observer writes NDJSON to stdout and protocol lines to a temporary stderr log.
# Never mix the two streams.
# -----------------------------------------------------------------------------
start_observer()
{
	OBSERVER_LOG=$(mktemp /tmp/memory-mm.XXXXXX)
	: > "$NDJSON_FILE"
	"$OBSERVER" > "$NDJSON_FILE" 2> "$OBSERVER_LOG" &
	OBSERVER_PID=$!
	log "observer started (pid $OBSERVER_PID)"
}

# -----------------------------------------------------------------------------
# wait_for_observer: block until LX_READY or the observer dies.
# -----------------------------------------------------------------------------
wait_for_observer()
{
	for _ in $(seq 1 100); do
		if grep -q '^LX_READY' "$OBSERVER_LOG" 2>/dev/null; then
			log "observer ready"
			return 0
		fi
		if ! kill -0 "$OBSERVER_PID" 2>/dev/null; then
			cat "$OBSERVER_LOG" >&2
			fail "eBPF observer exited before LX_READY"
		fi
		sleep 0.1
	done
	cat "$OBSERVER_LOG" >&2
	fail "timed out waiting for LX_READY"
}

# -----------------------------------------------------------------------------
# run_workload: only now may tracing be enabled; both observers are live.
# The workload stdout is the canonical workload source file; its exit status is preserved.
# -----------------------------------------------------------------------------
run_workload()
{
	echo 1 > "$INSTANCE/tracing_on"
	log "tracing enabled; starting workload"
	: > "$PHASES_FILE"
	"$WORKLOAD" > "$PHASES_FILE" || WORKLOAD_STATUS=$?
	echo 0 > "$INSTANCE/tracing_on"
	log "tracing disabled; workload exit status $WORKLOAD_STATUS"
}

# -----------------------------------------------------------------------------
# stop_capture: SIGINT the observer, wait for its clean LX_DONE, then copy the private instance trace.
# -----------------------------------------------------------------------------
stop_capture()
{
	if [[ -n ${OBSERVER_PID} ]] && kill -0 "$OBSERVER_PID" 2>/dev/null; then
		kill -INT "$OBSERVER_PID" 2>/dev/null || true
		wait "$OBSERVER_PID" || OBSERVER_STATUS=$?
		OBSERVER_PID=
	fi
	cat "$INSTANCE/trace" > "$TRACE_FILE"
	log "captured $(wc -l < "$TRACE_FILE") trace lines"
}

# -----------------------------------------------------------------------------
# validate_capture: semantic checks on all three artifacts.
# The python pass verifies that every snapshot's phase_seq matches a workload
# phase and that both time sequences are monotonic.
# -----------------------------------------------------------------------------
validate_capture()
{
	if ! sed -n '1p' "$NDJSON_FILE" | grep -q '"kind":"meta"'; then
		fail "eBPF output has no metadata record on the first line"
	fi
	if ! grep -q '"kind":"snapshot"' "$NDJSON_FILE"; then
		fail "eBPF output has no snapshots"
	fi
	if ! grep -q '"event_info".*"phase_seq"' "$NDJSON_FILE"; then
		fail "eBPF snapshots carry no event_info.phase_seq"
	fi
	if ! grep -q '"kind":"phase"' "$PHASES_FILE"; then
		fail "workload produced no phase records"
	fi
	if ! grep -q 'mm_' "$TRACE_FILE"; then
		fail "tracefs capture has no MM events"
	fi

	local phase_count snapshot_count
	phase_count=$(grep -c '"kind":"phase"' "$PHASES_FILE" || true)
	snapshot_count=$(grep -c '"kind":"snapshot"' "$NDJSON_FILE" || true)
	if (( snapshot_count != phase_count )); then
		fail "snapshot count $snapshot_count does not match phase count $phase_count"
	fi

	if command -v python3 >/dev/null 2>&1; then
		python3 - "$NDJSON_FILE" "$PHASES_FILE" <<'PY' || fail "phase/snapshot association check failed"
import json
import sys

def load(path):
    records = []
    with open(path, 'r', encoding='utf-8') as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records

ndjson, phases = sys.argv[1], sys.argv[2]
snapshots = [r for r in load(ndjson) if r.get('kind') == 'snapshot']
phases = [r for r in load(phases) if r.get('kind') == 'phase']
snapshot_seqs = [r['event_info']['phase_seq'] for r in snapshots]
phase_seqs = [r['seq'] for r in phases]
assert snapshot_seqs == phase_seqs, 'snapshot phase_seq does not match phase sequence'
assert snapshot_seqs == sorted(snapshot_seqs), 'snapshot phase_seq is not monotonic'
assert [r['time_ns'] for r in snapshots] == sorted(r['time_ns'] for r in snapshots), 'snapshot time_ns is not monotonic'
assert [r['time_ns'] for r in phases] == sorted(r['time_ns'] for r in phases), 'phase time_ns is not monotonic'
print('memory: phase->snapshot association complete: %d phases, %d snapshots' % (len(phases), len(snapshots)))
PY
	fi
	log "captures validated"
}

# -----------------------------------------------------------------------------
# cleanup: restore everything on normal exit, SIGINT, SIGTERM, or any failure.
# -----------------------------------------------------------------------------
cleanup()
{
	local status=$?

	trap - EXIT HUP INT TERM
	set +e

	if [[ -n ${OBSERVER_PID:-} ]] && kill -0 "$OBSERVER_PID" 2>/dev/null; then
		kill -INT "$OBSERVER_PID" 2>/dev/null
		wait "$OBSERVER_PID" 2>/dev/null
		OBSERVER_PID=
	fi
	if [[ -n ${INSTANCE:-} && -d "$INSTANCE" ]]; then
		echo 0 > "$INSTANCE/tracing_on" 2>/dev/null
		for event in "${MM_EVENTS[@]:-}"; do
			[[ -e "$INSTANCE/events/$event/enable" ]] && echo 0 > "$INSTANCE/events/$event/enable" 2>/dev/null
		done
		rmdir "$INSTANCE" 2>/dev/null || rm -rf "$INSTANCE" 2>/dev/null
	fi
	[[ -n ${OBSERVER_LOG:-} ]] && rm -f "$OBSERVER_LOG" 2>/dev/null

	exit "$status"
}
trap cleanup EXIT HUP INT TERM

preflight
ensure_swap
setup_trace
start_observer
wait_for_observer
run_workload
stop_capture
validate_capture

if (( WORKLOAD_STATUS != 0 )); then
	log "workload failed with status $WORKLOAD_STATUS"
	exit "$WORKLOAD_STATUS"
fi
if (( OBSERVER_STATUS != 0 )); then
	log "observer exited with status $OBSERVER_STATUS"
	exit "$OBSERVER_STATUS"
fi

log "done"
