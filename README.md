# kernel-oops

Build and run a custom Linux kernel in QEMU.

## Layout

```text
app/        Static visualization frontend.
shared/workloads/  Guest programs and scripts that trigger study hooks.
  core/          Process and scheduler workload.
  mm/            Memory-management workload.
  vfs/run.sh     Shared filesystem and block-I/O workload.
shared/modules/     Out-of-tree study modules.
shared/miscdriver/ Misc character driver.
shared/pci/        QEMU EDU PCI driver.
shared/_captures/  Flat generated capture files, prefixed by producer.
vm/         QEMU disk images, overlays, and cloud-init seed files.
linux/      Linux source tree.
build/  Out-of-tree kernel build output.
```

## Dependencies

Install the kernel build tools, QEMU, cloud-image utilities, and `ccache` for faster rebuilds.

```bash
sudo apt update
sudo apt install -y \
  build-essential bc bison flex libssl-dev libelf-dev dwarves \
  qemu-system-x86 qemu-utils cloud-image-utils ccache
```

## Kernel Source

`linux/` is a Git submodule pointing at upstream Linux. Build output stays separate in `build/`.

```bash
git submodule update --init --depth 1 linux
mkdir -p build shared vm
```

Move the kernel forward by updating the submodule checkout, then rebuild and rerun the eBPF/tracepoint captures:

```bash
cd linux
git fetch --depth 1 origin master
git checkout origin/master
cd ..
git add linux
```

## Configure And Build

Generate a default x86 config if needed, then build with the helper script. `build.sh` enables the tracing, eBPF, and BTF config needed by this project before running `olddefconfig`.

```bash
make -C linux O=../build defconfig
make -C linux O=../build oldconfig
./build.sh
```

## Rootfs

Use an Ubuntu cloud image as the guest disk and create a seed ISO for cloud-init data.

```bash
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img -O vm/ubuntu-24.04.qcow2
cloud-localds vm/seed.iso vm/user-data vm/meta-data
```

## Boot

`boot.sh` starts the custom kernel with a disposable overlay disk.

```bash
./boot.sh
```

It skips normal init and drops directly into `/bin/bash` for quick kernel-debug loops.
It keeps the console quiet with `quiet loglevel=4`, so the custom `pr_info()` study records stay in the kernel ring buffer instead of flooding the serial console. The boot script sets `log_buf_len=128M` because the custom hooks can generate enough printk traffic to wrap the default kernel log buffer quickly.

## Shared Folder

The boot script exposes host `shared/` to the guest with the 9p mount tag `hostshare`.

Inside QEMU:

```bash
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
```

## Kernel Hook Studies

Hook points are either built-in tracepoints captured from tracefs or the remaining custom CFS RB-tree `pr_info()` snapshots.

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

Scheduler custom CFS hooks:

| Prefix | File | Function | Purpose |
|---|---|---|---|
| `CFS` | `kernel/sched/fair.c` | `__enqueue_entity()` | CFS entity enters RB tree. |
| `CFS` | `kernel/sched/fair.c` | `__dequeue_entity()` | CFS entity leaves RB tree. |

Memory tracepoints:

| Tracepoint | Purpose |
|---|---|
| `kmem:mm_page_alloc` | Page allocated. |
| `kmem:mm_page_free` | Page freed. |
| `kmem:mm_page_free_batched` | Page freed through batched free path. |
| `mmap:vma_store` | VMA stored in the maple tree. |
| `mmap:exit_mmap` | Address space is torn down. |
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

VFS superblock tracepoints:

| Tracepoint | Purpose |
|---|---|
| `syscalls:sys_enter_mount` | Mount request entered the kernel. |
| `syscalls:sys_exit_mount` | Mount request returned to userspace. |

Study modes are mutually exclusive kernel config choices. Select one before building.

### None

```bash
./study-mode.sh none
./build.sh
```

### Core

The process and scheduler workload lives in `shared/workloads/core/`; captures use the `shared/_captures/core-*.txt` prefix.

```bash
./study-mode.sh core
./build.sh
x86_64-linux-gnu-gcc -O2 -Wall -static -o shared/workloads/core/workload shared/workloads/core/workload.c
```

Inside QEMU, capture process lifecycle tracepoints:

```bash
cd /sys/kernel/tracing
echo 0 > tracing_on
echo 0 > events/enable
echo > set_event
echo > trace
echo 1 > events/sched/sched_process_fork/enable
echo 1 > events/sched/sched_wakeup_new/enable
echo 1 > events/sched/sched_switch/enable
echo 1 > events/sched/sched_process_exit/enable
echo 1 > events/sched/sched_process_wait/enable
echo 1 > events/sched/sched_process_free/enable
echo 1 > tracing_on

/mnt/host/workloads/core/workload
mkdir -p /mnt/host/_captures
grep -E "sched_process_fork|sched_wakeup_new|sched_switch|sched_process_exit|sched_process_wait|sched_process_free" trace > /mnt/host/_captures/core-trace-lifecycle.txt

echo 0 > tracing_on
echo 0 > events/sched/sched_process_fork/enable
echo 0 > events/sched/sched_wakeup_new/enable
echo 0 > events/sched/sched_switch/enable
echo 0 > events/sched/sched_process_exit/enable
echo 0 > events/sched/sched_process_wait/enable
echo 0 > events/sched/sched_process_free/enable
echo > trace
```

### Scheduler

The scheduler RB-tree capture uses the same core workload and core study mode.

Inside QEMU, capture CFS scheduler RB-tree hooks:

```bash
dmesg | grep CFS > /mnt/host/_captures/core-hook-cfs-rbtree.txt
```

### MM

The memory workload lives in `shared/workloads/mm/`; captures use the `shared/_captures/mm-*.txt` prefix.

```bash
./study-mode.sh mm
./build.sh
x86_64-linux-gnu-gcc -O2 -Wall -static -pthread -o shared/workloads/mm/workload shared/workloads/mm/workload.c
```

Inside QEMU, capture memory tracepoints:

```bash
cd /sys/kernel/tracing
echo 0 > tracing_on
echo 0 > events/enable
echo > set_event
echo > trace
echo 1 > events/kmem/mm_page_alloc/enable
echo 1 > events/kmem/mm_page_free/enable
echo 1 > events/kmem/mm_page_free_batched/enable
echo 1 > events/mmap/vma_store/enable
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

/mnt/host/workloads/mm/workload
mkdir -p /mnt/host/_captures
cat trace > /mnt/host/_captures/mm-trace-memory.txt

echo 0 > tracing_on
echo 0 > events/kmem/mm_page_alloc/enable
echo 0 > events/kmem/mm_page_free/enable
echo 0 > events/kmem/mm_page_free_batched/enable
echo 0 > events/mmap/vma_store/enable
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
```

### VFS

The shared workload at `shared/workloads/vfs/run.sh` exercises filesystem mount activity for the superblock study.

```bash
./study-mode.sh vfs
./build.sh
```

Inside QEMU, capture superblock mount tracepoints:

```bash
cd /sys/kernel/tracing
echo 0 > tracing_on
echo 0 > events/enable
echo > set_event
echo > trace
echo 1 > events/syscalls/sys_enter_mount/enable
echo 1 > events/syscalls/sys_exit_mount/enable
echo 1 > tracing_on

sh /mnt/host/workloads/vfs/run.sh
mkdir -p /mnt/host/_captures
cat trace > /mnt/host/_captures/vfs-trace-super.txt

echo 0 > tracing_on
echo 0 > events/syscalls/sys_enter_mount/enable
echo 0 > events/syscalls/sys_exit_mount/enable
echo > trace
```

## External Modules

Module tools live in `shared/modules/`. Each module has its own source/build folder under `shared/modules/`; captures are stored as `shared/_captures/core-module-tasks.txt` and `shared/_captures/mm-module-allocators.txt`.

```bash
./study-mode.sh none
./build.sh
make -C shared/modules
```

Inside QEMU:

```bash
sh /mnt/host/modules/w.sh core
sh /mnt/host/modules/w.sh mm
mkdir -p /mnt/host/_captures
dmesg | grep KOOPS_CORE > /mnt/host/_captures/core-module-tasks.txt
dmesg | grep KOOPS_MM > /mnt/host/_captures/mm-module-allocators.txt
```

## Misc Driver

The simple misc character driver lives in `shared/miscdriver/` and creates `/dev/llkd_miscdrv`.

Build it against the custom kernel:

```bash
make -C shared/miscdriver
```

Inside QEMU, load and smoke-test it with:

```bash
sh /mnt/host/miscdriver/w.sh
```

Unload it explicitly when needed:

```bash
rmmod llkd_miscdrv
```

## PCI

Detailed driver architecture and userspace behavior are documented in
[`shared/pci/README.md`](shared/pci/README.md).
The QEMU EDU PCI driver lives in `shared/pci/`. `boot.sh` creates its matching `1234:11e8` device with `-device edu`.

Build the driver against the custom kernel:

```bash
make -C shared/pci
```

Inside QEMU, load it with the dedicated runner:

```bash
sh /mnt/host/pci/w.sh
```

The runner leaves `qedu` loaded so it remains bound while testing BARs, interrupts, and DMA. Unload it explicitly when needed:

```bash
rmmod qedu
```

## Quit QEMU

With `-nographic`:

| Action | Command |
|---|---|
| Quit QEMU | `Ctrl-a`, then `x` |
| Open QEMU monitor | `Ctrl-a`, then `c` |
| Quit from monitor | `quit` |

## App

The app visualizes text captures collected under `shared/`.

```text
app/
  index.html        Main shell with visualization tabs.
  theme.css         Shared theme tokens used by the shell.
  views/            Subsystem visualization pages.
    core.html       Core subsystem viewer for lifecycle and CFS captures.
    mm.html         Memory allocator and slab viewer.
    block.html      Block I/O BIO/request flow viewer.
    fs.html         Superblock, inode, and dentry viewer.
```

Start the web server from the repository root:

```bash
./run-app.sh
```

Open:

```text
http://localhost:8000/app/
```

If port `8000` is busy, use another port, for example `8001`.
