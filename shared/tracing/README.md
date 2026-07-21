# Kernel Tracing Studies


Hook points are built-in tracepoints captured from tracefs.

### Hook Reference

Process lifecycle tracepoints:

| Tracepoint | Purpose |
|---|---|
| `sched:sched_process_fork` | Child task created. |
| `sched:sched_wakeup_new` | New child is woken and queued. |
| `sched:sched_switch` | CPU switches between tasks. |
| `sched:sched_process_exit` | Task exits. |
| `sched:sched_process_wait` | Parent waits for a child. |
| `sched:sched_process_free` | Task struct is freed. |

Memory tracepoints:

| Tracepoint | Purpose |
|---|---|
| `kmem:mm_page_alloc` | Page allocated. |
| `kmem:mm_page_free` | Page freed. |
| `kmem:mm_page_free_batched` | Page freed through batched free path. |
| `mmap:vm_unmapped_area` | Virtual address-space search completed. |
| `mmap:exit_mmap` | Process address space teardown. |
| `mmap_lock:mmap_lock_start_locking` | mmap lock acquisition started. |
| `mmap_lock:mmap_lock_released` | mmap lock released. |
| `mmap_lock:mmap_lock_acquire_returned` | mmap lock acquisition returned. |
| `filemap:mm_filemap_add_to_page_cache` | Folio added to page cache. |
| `filemap:mm_filemap_delete_from_page_cache` | Folio removed from page cache. |
| `vmscan:mm_vmscan_lru_isolate` | Folios isolated from LRU for reclaim. |
| `vmscan:mm_vmscan_lru_shrink_inactive` | Inactive LRU reclaim scanned/reclaimed folios. |
| `vmscan:mm_vmscan_write_folio` | Reclaim wrote a folio. |
| `writeback:writeback_dirty_folio` | Folio dirtied for writeback. |
| `writeback:writeback_start` | Writeback work started. |
| `writeback:wbc_writepage` | Writeback submitted a page through writepage control. |
| `kmem:kmem_cache_alloc` | Object allocated from a slab cache. |
| `kmem:kmem_cache_free` | Object freed back to a slab cache. |
| `kmem:kmalloc` | Generic kmalloc allocation. |
| `kmem:kfree` | Generic kfree release. |

### Core

The process and scheduler workload lives in `shared/_work/`. Inside QEMU, run [`core.sh`](core.sh) to enable the lifecycle tracepoints, run the workload, write `shared/_captures/tracing-core-lifecycle.txt`, and disable tracing.

### MM

The memory workload lives in `shared/_work/`. Inside QEMU, run [`mm.sh`](mm.sh) to enable the memory tracepoints, run the workload, write `shared/_captures/tracing-mm-memory.txt`, and disable tracing.

The script reserves a 64 MiB tracefs ring buffer per CPU before capture and stops tracing before reading `trace`. In the capture header, equal `entries-in-buffer/entries-written` values confirm that no records were overwritten.
