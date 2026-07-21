#!/usr/bin/env bash
set -euo pipefail
cd /sys/kernel/tracing
echo 0 > tracing_on
# tracefs allocates this much ring-buffer space per CPU. The VM has one CPU.
echo 65536 > buffer_size_kb
echo 0 > events/enable
echo > set_event
echo > trace
echo 1 > events/kmem/mm_page_alloc/enable
echo 1 > events/kmem/mm_page_free/enable
echo 1 > events/kmem/mm_page_free_batched/enable
echo 1 > events/mmap/exit_mmap/enable
echo 1 > events/filemap/mm_filemap_add_to_page_cache/enable
echo 1 > events/filemap/mm_filemap_delete_from_page_cache/enable
echo 1 > events/vmscan/mm_vmscan_lru_isolate/enable
echo 1 > events/vmscan/mm_vmscan_lru_shrink_inactive/enable
echo 1 > events/vmscan/mm_vmscan_write_folio/enable
echo 1 > events/writeback/writeback_dirty_folio/enable
echo 1 > events/writeback/writeback_start/enable
echo 1 > events/writeback/wbc_writepage/enable
echo 1 > events/kmem/kmem_cache_alloc/enable
echo 1 > events/kmem/kmem_cache_free/enable
echo 1 > events/kmem/kmalloc/enable
echo 1 > events/kmem/kfree/enable
echo 1 > tracing_on
/mnt/host/_work/exercise_memory_management
# Freeze the ring buffer before copying it so the capture cannot change mid-read.
echo 0 > tracing_on
mkdir -p /mnt/host/_captures
cat trace > /mnt/host/_captures/tracing-mm-memory.txt
echo 0 > events/kmem/mm_page_alloc/enable
echo 0 > events/kmem/mm_page_free/enable
echo 0 > events/kmem/mm_page_free_batched/enable
echo 0 > events/mmap/exit_mmap/enable
echo 0 > events/filemap/mm_filemap_add_to_page_cache/enable
echo 0 > events/filemap/mm_filemap_delete_from_page_cache/enable
echo 0 > events/vmscan/mm_vmscan_lru_isolate/enable
echo 0 > events/vmscan/mm_vmscan_lru_shrink_inactive/enable
echo 0 > events/vmscan/mm_vmscan_write_folio/enable
echo 0 > events/writeback/writeback_dirty_folio/enable
echo 0 > events/writeback/writeback_start/enable
echo 0 > events/writeback/wbc_writepage/enable
echo 0 > events/kmem/kmem_cache_alloc/enable
echo 0 > events/kmem/kmem_cache_free/enable
echo 0 > events/kmem/kmalloc/enable
echo 0 > events/kmem/kfree/enable
echo > trace
