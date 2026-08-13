#!/usr/bin/env bash
set -euo pipefail

if ! awk 'NR > 1 { found = 1 } END { exit !found }' /proc/swaps; then
	if [[ ! -b /dev/vdb ]]; then
		echo "mm trace: /dev/vdb swap disk is missing; boot the guest with boot.sh" >&2
		exit 1
	fi
	swapon /dev/vdb
fi

if ! awk 'NR > 1 { found = 1 } END { exit !found }' /proc/swaps; then
	echo "mm trace: swap activation failed" >&2
	exit 1
fi

echo "mm trace: active swap"
cat /proc/swaps

cd /sys/kernel/tracing
echo 0 > tracing_on
# tracefs allocates this much ring-buffer space per CPU; kmem/page events are noisy.
if [[ -w buffer_size_kb ]]; then
	echo 65536 > buffer_size_kb || true
	echo "mm trace: tracefs buffer_size_kb=$(cat buffer_size_kb) per CPU" >&2
fi
echo 0 > events/enable
echo > set_event
echo > trace
if [[ -w trace_clock ]]; then
	echo mono > trace_clock || true
fi

enable_event()
{
	local event=$1
	local control="events/$event/enable"

	if [[ -e $control ]]; then
		echo 1 > "$control"
	else
		echo "mm trace: skipping unavailable $event" >&2
	fi
}

# process VAS:
enable_event mmap/vm_unmapped_area
enable_event mmap/exit_mmap
enable_event exceptions/page_fault_user
enable_event mmap_lock/mmap_lock_released
enable_event tlb/tlb_flush

# page cache: faults
enable_event filemap/mm_filemap_fault
enable_event filemap/mm_filemap_get_pages
enable_event filemap/mm_filemap_map_pages
enable_event filemap/mm_filemap_add_to_page_cache
enable_event filemap/mm_filemap_delete_from_page_cache

# page cache: writeback
enable_event writeback/writeback_dirty_folio
enable_event writeback/writeback_start
enable_event writeback/wbc_writepage
enable_event writeback/writeback_pages_written
enable_event writeback/writeback_single_inode_start
enable_event writeback/writeback_single_inode

# swap: no swap tracepoints

# lru lifecycle:
enable_event pagemap/mm_lru_insertion
enable_event pagemap/mm_lru_activate

# Buddy:
enable_event kmem/rss_stat
enable_event kmem/mm_page_alloc
enable_event kmem/mm_setup_per_zone_wmarks
enable_event kmem/mm_page_alloc_zone_locked
enable_event kmem/mm_page_alloc_extfrag
enable_event kmem/mm_page_free
enable_event kmem/mm_page_free_batched
enable_event kmem/mm_page_pcpu_drain

# SLUB/kmalloc:
enable_event kmem/kmem_cache_alloc
enable_event kmem/kmem_cache_free
enable_event kmem/kmalloc
enable_event kmem/kfree

# THP/khugepaged:
enable_event huge_memory/mm_khugepaged_scan_pmd
enable_event huge_memory/mm_collapse_huge_page_isolate
enable_event huge_memory/mm_collapse_huge_page_swapin
enable_event huge_memory/mm_collapse_huge_page
enable_event huge_memory/mm_khugepaged_scan_file
enable_event huge_memory/mm_khugepaged_collapse_file
enable_event huge_memory/mm_khugepaged_scan

# reclaim:
enable_event vmscan/mm_vmscan_direct_reclaim_begin
enable_event vmscan/mm_vmscan_direct_reclaim_end
enable_event vmscan/mm_vmscan_wakeup_kswapd
enable_event vmscan/mm_vmscan_kswapd_wake
enable_event vmscan/mm_vmscan_kswapd_sleep
enable_event vmscan/mm_vmscan_balance_pgdat_begin
enable_event vmscan/mm_vmscan_balance_pgdat_end
enable_event vmscan/mm_vmscan_lru_isolate
enable_event vmscan/mm_vmscan_lru_shrink_active
enable_event vmscan/mm_vmscan_lru_shrink_inactive
enable_event vmscan/mm_vmscan_write_folio
enable_event vmscan/mm_vmscan_reclaim_pages

# shrinkers:
enable_event vmscan/mm_shrink_slab_start
enable_event vmscan/mm_shrink_slab_end

# NUMA migration:
enable_event migrate/mm_migrate_pages_start
enable_event migrate/mm_migrate_pages

# compaction:
enable_event compaction/mm_compaction_begin
enable_event compaction/mm_compaction_isolate_migratepages
enable_event compaction/mm_compaction_isolate_freepages
enable_event compaction/mm_compaction_migratepages
enable_event compaction/mm_compaction_end
enable_event compaction/mm_compaction_wakeup_kcompactd
enable_event compaction/mm_compaction_kcompactd_wake
enable_event compaction/mm_compaction_kcompactd_sleep
enable_event compaction/mm_compaction_deferred
enable_event compaction/mm_compaction_defer_compaction
enable_event compaction/mm_compaction_defer_reset

# OOM:
enable_event oom/reclaim_retry_zone
enable_event oom/compact_retry
enable_event oom/mark_victim
enable_event oom/wake_reaper
enable_event oom/start_task_reaping
enable_event oom/finish_task_reaping
enable_event oom/skip_task_reaping

# percpu allocator:
enable_event percpu/percpu_alloc_percpu
enable_event percpu/percpu_alloc_percpu_fail
enable_event percpu/percpu_free_percpu
enable_event percpu/percpu_create_chunk
enable_event percpu/percpu_destroy_chunk

mkdir -p /mnt/host/_captures
capture_file=/mnt/host/_captures/memory-observer.ndjson
trace_file=/mnt/host/_captures/memory-trace.txt
: > "$capture_file"
: > "$trace_file"
observer_output=$(mktemp /tmp/mm-run.XXXXXX)
workload_file=$(mktemp /tmp/mm-workload.XXXXXX)
observer_pid=
observer_status=0

stop_observer()
{
	if [[ -n ${observer_pid:-} ]]; then
		kill -INT "$observer_pid" 2>/dev/null || true
		wait "$observer_pid" || observer_status=$?
		observer_pid=
	fi
}

cleanup()
{
	stop_observer
	rm -f "$workload_file" "$observer_output"
}

/mnt/host/memory/build/mm 2> "$observer_output" &
observer_pid=$!
trap cleanup EXIT INT TERM

observer_ready=0
for _ in $(seq 1 100); do
	if grep -q "capturing phase-boundary VMA snapshots" "$observer_output"; then
		observer_ready=1
		break
	fi
	if ! kill -0 "$observer_pid" 2>/dev/null; then
		stop_observer
		echo "mm eBPF observer failed before workload start" >&2
		cat "$observer_output" >&2
		exit "${observer_status:-1}"
	fi
	sleep 0.1
done
if ((observer_ready == 0)); then
	stop_observer
	echo "mm eBPF observer did not become ready before workload start" >&2
	cat "$observer_output" >&2
	exit 1
fi

echo 1 > tracing_on
workload_status=0
/mnt/host/memory/workload_mm > "$workload_file" || workload_status=$?
stop_observer
cat "$workload_file" >> "$capture_file"
python3 - "$workload_file" "$capture_file" <<'PY'
import json
import sys

phase_file, capture_file = sys.argv[1], sys.argv[2]

def records(path):
    with open(path, 'r', encoding='utf-8') as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

phases = [r for r in records(phase_file) if r.get('type') == 'phase']
snapshots = [r for r in records(capture_file) if r.get('type') == 'mm_snapshot']
snapshot_index = 0

print('mm trace: phase snapshot coverage')
for phase in phases:
    phase_time = int(phase.get('time_ns', 0))
    while snapshot_index < len(snapshots) and int(snapshots[snapshot_index].get('time_ns', 0)) < phase_time:
        snapshot_index += 1
    if snapshot_index < len(snapshots):
        snapshot = snapshots[snapshot_index]
        print('mm trace: captured phase: {name} | snapshot_time={time} map_count={maps} vmas={vmas}'.format(
            name=phase.get('name', '<unnamed>'),
            time=snapshot.get('time_ns', '?'),
            maps=snapshot.get('map_count', '?'),
            vmas=snapshot.get('vma_count', '?')))
        snapshot_index += 1
    else:
        print('mm trace: MISSING snapshot for phase: {name}'.format(name=phase.get('name', '<unnamed>')))
PY
if ! grep -q "\"type\":\"mm_snapshot\"" "$capture_file"; then
	echo "mm eBPF observer produced no mm_snapshot records" >&2
	cat "$observer_output" >&2
	exit 1
fi
echo 0 > tracing_on
cat trace > "$trace_file"
rm -f "$workload_file" "$observer_output"
trap - EXIT INT TERM
echo 0 > events/enable
echo > trace
if ((workload_status != 0)); then
	exit "$workload_status"
fi
exit "$observer_status"
