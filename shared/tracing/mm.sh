#!/usr/bin/env bash
set -euo pipefail
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

# Pressure response: reclaim, compaction, migration, and THP collapse. These
# remain quiet during ordinary phases and become valuable under pressure.
enable_event vmscan/mm_vmscan_direct_reclaim_begin
enable_event vmscan/mm_vmscan_direct_reclaim_end
enable_event vmscan/mm_vmscan_kswapd_wake
enable_event vmscan/mm_vmscan_kswapd_sleep
enable_event vmscan/mm_vmscan_balance_pgdat_begin
enable_event vmscan/mm_vmscan_balance_pgdat_end
enable_event vmscan/mm_vmscan_lru_isolate
enable_event vmscan/mm_vmscan_lru_shrink_active
enable_event vmscan/mm_vmscan_lru_shrink_inactive
enable_event vmscan/mm_vmscan_write_folio
enable_event vmscan/mm_vmscan_reclaim_pages
enable_event compaction/mm_compaction_begin
enable_event compaction/mm_compaction_isolate_migratepages
enable_event compaction/mm_compaction_isolate_freepages
enable_event compaction/mm_compaction_migratepages
enable_event compaction/mm_compaction_end
enable_event migrate/mm_migrate_pages_start
enable_event migrate/mm_migrate_pages
enable_event huge_memory/mm_khugepaged_scan_pmd
enable_event huge_memory/mm_collapse_huge_page
enable_event huge_memory/mm_collapse_huge_page_isolate
enable_event huge_memory/mm_collapse_huge_page_swapin
echo 1 > tracing_on
/mnt/host/_work/build/exercise_memory_management
# Freeze the ring buffer before copying it so the capture cannot change mid-read.
echo 0 > tracing_on
mkdir -p /mnt/host/_captures
cat trace > /mnt/host/_captures/tracing-mm-memory.txt
echo 0 > events/enable
echo > trace
