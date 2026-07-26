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
| `kmem:mm_page_alloc_zone_locked` | Allocation reached the zone/PCP refill path. |
| `kmem:mm_page_pcpu_drain` | A page moved from a per-CPU list toward the buddy allocator. |
| `kmem:mm_page_alloc_extfrag` | Allocation fell back across migratetypes and exposed fragmentation. |
| `kmem:rss_stat` | Per-mm anonymous, file, shmem, and swap footprint changed. |
| `mmap:vm_unmapped_area` | Virtual address-space search completed. |
| `mmap:exit_mmap` | Process address space teardown. |
| `exceptions:page_fault_user` | Userspace access faulted at a virtual address. |
| `filemap:mm_filemap_add_to_page_cache` | Folio added to page cache. |
| `filemap:mm_filemap_delete_from_page_cache` | Folio removed from page cache. |
| `filemap:mm_filemap_fault` | A file-backed VMA faulted at a file offset. |
| `filemap:mm_filemap_get_pages` | Filemap requested a range of cached pages. |
| `filemap:mm_filemap_map_pages` | A range of cached folios was mapped into page tables. |
| `writeback:writeback_dirty_folio` | Folio dirtied for writeback. |
| `writeback:writeback_start` | Writeback work started. |
| `writeback:wbc_writepage` | Writeback submitted a page through writepage control. |
| `writeback:writeback_pages_written` | Writeback completion reported the number of pages written. |
| `writeback:writeback_single_inode_start` | Inode writeback started. |
| `writeback:writeback_single_inode` | Inode writeback completed. |
| `kmem:kmem_cache_alloc` | Object allocated from a slab cache. |
| `kmem:kmem_cache_free` | Object freed back to a slab cache. |
| `kmem:kmalloc` | Generic kmalloc allocation. |
| `kmem:kfree` | Generic kfree release. |

### Core

The process and scheduler workload lives in `shared/_work/`. Inside QEMU, run [`/mnt/host/tracing/run.sh`](run.sh) to enable the lifecycle tracepoints, run the workload, write `shared/_captures/tracing-core-lifecycle.txt`, and disable tracing.

### MM

The [memory observer](../mm/README.md) lives in `shared/mm/`. Inside QEMU, run [`/mnt/host/mm/run.sh`](../mm/run.sh) to run the prebuilt workload and write phase plus eBPF VMA snapshots to `shared/_captures/mm.ndjson`.
