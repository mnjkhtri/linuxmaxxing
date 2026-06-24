# Hooks

Hooks are temporary instrumentation points added to Linux subsystem code paths. Each hook emits a single-line `pr_info()` record with a stable prefix so captures can be split by concept.

## kernel

Core hooks are compiled only in core study mode. Lifecycle records use the `LIFE` prefix, and CFS runqueue records use the `CFS` prefix. `boot.sh` uses `loglevel=4`, so these records are captured from `dmesg` instead of printed on the serial console.

| Prefix | File | Function | Purpose |
|---|---|---|---|
| `LIFE` | `kernel/fork.c` | `kernel_clone()` | Child task created. |
| `LIFE` | `kernel/sched/core.c` | `sched_fork()` | Child scheduler state initialized. |
| `LIFE` | `kernel/sched/core.c` | `wake_up_new_task()` | Child first queued to run. |
| `LIFE` | `kernel/exit.c` | `do_exit()` | Task begins final exit path. |
| `LIFE` | `kernel/exit.c` | `exit_notify()` | Task becomes visible as zombie. |
| `LIFE` | `kernel/exit.c` | `release_task()` | Dead task is reaped. |
| `LIFE` | `kernel/sched/core.c` | `do_task_dead()` | Exiting task schedules away permanently. |
| `CFS` | `kernel/sched/fair.c` | `__enqueue_entity()` | CFS entity enters RB tree. |
| `CFS` | `kernel/sched/fair.c` | `__dequeue_entity()` | CFS entity leaves RB tree. |

Only `__enqueue_entity()` and `__dequeue_entity()` are hooked for CFS because these are the two operations that mutate the RB tree. They only log sched entities for tasks whose `comm` starts with `workld`, which is what `shared/workloads/core/workload.c` names its children.

## mm

MM hooks are compiled only in MM study mode and use single-line `pr_info()` records. Page allocator records use the `ALLOC` prefix, slab records use the `SLAB` prefix, and user address-space records use the `ADDR` prefix.

| Prefix | File | Function | Purpose |
|---|---|---|---|
| `ALLOC` | `mm/mempolicy.c` | `alloc_pages()` | Page allocation requested. |
| `ALLOC` | `mm/page_alloc.c` | `__free_pages()` | Page free requested. |
| `SLAB` | `mm/slab_common.c` | `kmem_cache_create()` | Slab cache created. |
| `SLAB` | `mm/slab_common.c` | `kmem_cache_destroy()` | Slab cache destroy requested. |
| `ADDR` | `kernel/fork.c` | `mm_init()` | Address-space descriptor initialized. |
| `ADDR` | `kernel/fork.c` | `copy_mm()` | Child address space copied or shared. |
| `ADDR` | `kernel/exit.c` | `exit_mm()` | Task detaches from address space. |
| `ADDR` | `mm/mmap.c` | `do_mmap()` | User mapping created. |
| `ADDR` | `mm/mmap.c` | `do_munmap()` | User mapping removed. |

## fs

FS hooks are compiled in VFS study mode and use single-line `pr_info()` records with object-specific prefixes so captures can be split cleanly by file. These hooks sit in VFS code paths because that is where Linux creates superblock, inode, and dentry objects. Superblock records use `SUPER`; inode records use `INODE`; dentry/name-cache records use `DENTRY`.

Run `shared/workloads/vfs/run.sh` in the guest to exercise these paths. The same script is used for the block study so both layers receive a consistent I/O workload.

| Prefix | File | Function | Purpose |
|---|---|---|---|
| `SUPER` | `fs/super.c` | `alloc_super()` | Superblock allocated. |
| `INODE` | `fs/inode.c` | `alloc_inode()` | Inode allocated. |
| `DENTRY` | `fs/dcache.c` | `__d_alloc()` | Dentry allocated. |

## block

Block hooks are compiled in VFS study mode and use single-line `pr_info()` records with the `BLOCK` prefix.

Run `shared/workloads/vfs/run.sh` in the guest to drive file I/O through the filesystem and into the block layer.

| Prefix | File | Function | Purpose |
|---|---|---|---|
| `BLOCK` | `block/blk-mq.c` | `blk_mq_init_queue_data()` | blk-mq queue initialized. |
| `BLOCK` | `block/blk-core.c` | `submit_bio()` | BIO submitted. |
| `BLOCK` | `block/blk-mq.c` | `blk_mq_bio_to_request()` | BIO becomes request. |
| `BLOCK` | `block/blk-mq.c` | `blk_mq_start_request()` | Request issued. |
| `BLOCK` | `block/blk-mq.c` | `blk_mq_end_request()` | Request completed. |
| `BLOCK` | `block/bio.c` | `bio_endio()` | BIO completed. |
