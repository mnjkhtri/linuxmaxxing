#!/usr/bin/env bash
set -euo pipefail

# boot.sh attaches a dedicated swap disk as /dev/vdb. Activate it here as a
# fallback in case the guest's systemd version ignores systemd.swap-extra=.
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
# tracefs allocates this much ring-buffer space per CPU.
echo 65536 > buffer_size_kb
echo 0 > events/enable
echo > set_event
echo > trace

# Keep the script portable across kernel configurations. Optional tracepoints
# are skipped rather than aborting the entire capture.
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

# Virtual address selection, faults, and address-space teardown.
enable_event mmap/vm_unmapped_area
enable_event mmap/exit_mmap
enable_event exceptions/page_fault_user

# File-backed faults, page-cache lookup, residency, writeback, and eviction.
enable_event filemap/mm_filemap_fault
enable_event filemap/mm_filemap_get_pages
enable_event filemap/mm_filemap_map_pages
enable_event filemap/mm_filemap_add_to_page_cache
enable_event filemap/mm_filemap_delete_from_page_cache
enable_event writeback/writeback_dirty_folio
enable_event writeback/writeback_start
enable_event writeback/wbc_writepage
enable_event writeback/writeback_pages_written
enable_event writeback/writeback_single_inode_start
enable_event writeback/writeback_single_inode

# kmem accounting plus SLUB and kmalloc object lifetimes.
enable_event kmem/rss_stat
enable_event kmem/kmem_cache_alloc
enable_event kmem/kmem_cache_free
enable_event kmem/kmalloc
enable_event kmem/kfree

# Page allocation, PCP movement, buddy fallback, and fragmentation.
enable_event kmem/mm_page_alloc
enable_event kmem/mm_page_alloc_zone_locked
enable_event kmem/mm_page_alloc_extfrag
enable_event kmem/mm_page_pcpu_drain
enable_event kmem/mm_page_free
enable_event kmem/mm_page_free_batched

echo 1 > tracing_on
workload_status=0
/mnt/host/_work/build/exercise_memory_management || workload_status=$?
# Freeze the ring buffer before copying it so the capture cannot change mid-read.
echo 0 > tracing_on
mkdir -p /mnt/host/_captures
cat trace > /mnt/host/_captures/tracing-mm-memory.txt
echo 0 > events/enable
echo > trace
exit "$workload_status"
