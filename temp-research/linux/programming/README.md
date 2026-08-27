# Linux Systems Programming Examples

Small C examples for learning Linux systems programming.

## Install

```bash
sudo apt update
sudo apt install build-essential manpages-dev
```

## The Linux File Stack

Three layers matter for most file operations.

### The VFS
The VFS gives Linux one common file interface.
* It stitches different filesystems into a single tree under `/`.
* It lets syscalls like `read()` and `write()` work through one interface.
* It manages caches such as the dcache and inode cache.

### The Filesystem
The filesystem driver does the actual work.
* Disk-backed filesystems like `ext4`, `xfs`, and `btrfs` manage stored data.
* Virtual filesystems like `procfs` and `sysfs` generate content on demand.

### The Inode
The inode is the kernel's internal record for a file object.
* It stores metadata like size, permissions, owner, and timestamps. It stores no filename.
* It also stores the coarse file type shown by the first character in `ls -l`:
  - `-` regular file type
  - `d` directory
  - `c` character device
  - `b` block device
  - `p` FIFO
  - `s` socket
  - `l` symlink

### The Page Cache
The page cache is the kernel's cache for file data.
* It holds file bytes in RAM.
* Reads often come from it, and writes often land there before later writeback.
* Because it is file-backed, the kernel can drop those pages and reload them later from the file.

---

## The `ls -ali` Logic

When you run `ls -ali`:

1. It opens the directory.
2. It reads directory entries and inode numbers.
3. It fetches metadata for each inode.
4. It prints the inode number and file type.

## See Them

```bash
ls -ali .
ls -ali /proc/cpuinfo
ls -ali /dev/sda
ls -ali /dev/null

mkfifo data/myfifo
ls -l data/myfifo

ln -sf 02-file-io.c data/demo_symlink
ls -l data/demo_symlink

strace ls -ali .
```

## Interesting Filesystems and Files

Interesting filesystems:

- `ext4` common disk filesystem
- `xfs` high-scale disk filesystem
- `btrfs` copy-on-write filesystem
- `tmpfs` RAM-backed filesystem
- `procfs` process and kernel state
- `sysfs` kernel and device state
- `devtmpfs` device nodes in `/dev`

To see the filesystems currently stitched into the namespace by VFS:

```bash
findmnt -t nosquashfs,notmpfs,nodevtmpfs
```

Interesting files:

- `/proc/cpuinfo` CPU details
- `/proc/meminfo` memory details
- `/proc/mounts` mounted filesystems
- `/proc/filesystems` supported filesystem types
- `/proc/self/status` current process status
- `/proc/self/fd` current process file descriptors
- `/proc/self/maps` current process memory mappings
- `/proc/self/smaps` detailed per-mapping memory stats
- `/sys/class` device classes
- `/sys/block` block devices
- `/dev/null` discard writes
- `/dev/zero` endless zero bytes
- `/dev/random` blocking random source
- `/dev/urandom` nonblocking random source
- `/dev/tty` current terminal

## Phase 0: Finding the Kernel

Before Linux mounts anything, the machine must first find the bootloader, then the kernel.

- firmware (`UEFI` or legacy `BIOS`) starts first
- `UEFI` usually reads a bootloader file from the EFI System Partition
- legacy `BIOS` starts from the disk boot sector path instead
- the bootloader (`GRUB`) has its own filesystem readers
- GRUB reads its config, finds the kernel and `initramfs`, loads them into RAM, and jumps to the kernel

Useful commands:

```bash
lsblk | grep -i efi
ls -lh /boot/vmlinuz* /boot/initrd*
```

## How Mounting Begins

At the very beginning, Linux has no usable disk-based `/` yet. Bootstrapping happens in stages:

- `rootfs` the kernel's built-in in-memory starting root
- `initramfs` a temporary RAM-based mini-system loaded by the bootloader
- real root mount the actual disk filesystem becomes `/`
- `/etc/fstab` mounts the remaining filesystems

Early on, the kernel brings up core infrastructure filesystems such as:

- `/proc`
- `/sys`
- `/dev`

How the kernel knows what to mount:

- kernel command line from the bootloader, often `root=UUID=...`
- `initramfs` logic and drivers to find the real root device
- `/etc/fstab` for the rest of the system mounts

Useful commands:

```bash
cat /proc/cmdline
cat /etc/fstab
```

Complete boot chain:

1. Firmware finds the bootloader.
2. GRUB finds the kernel and `initramfs`.
3. Kernel creates the early RAM-based root.
4. `initramfs` finds the real root device.
5. The real root filesystem becomes `/`.
6. The system reads `/etc/fstab` and mounts the rest.

## 02 Examples

```bash
gcc -Wall -Wextra -O2 02-file-io.c -o 02-file-io
./02-file-io
```

## 03 Examples

```bash
gcc -Wall -Wextra -O2 -pthread 03-buffered-io.c -o 03-buffered-io
./03-buffered-io
```

## 04 Examples

```bash
gcc -Wall -Wextra -O2 04-advanced-file-io.c -o 04-advanced-file-io
./04-advanced-file-io
```

## The Process Model

### The Hierarchy
* Every process except PID 1 is created by `fork()`
* Two structures: the process tree (parent-child links) and the job-control hierarchy (sessions and process groups)
* A shell puts a pipeline into one process group under one session
* Two CPU privilege levels: **kernel mode** (full access) and **user mode** (sandboxed). System calls cross between them.

### Bootstrapping to PID 1
* PID 0 (idle task) is hardcoded into the kernel — initializes the system, runs when nothing else is scheduled
* PID 1 is the first user-space process — kernel drops to user mode to start `init`. If it exits, the kernel panics.

`kernel → PID 1 → session manager → shell → your command`

### fork() and exec()
* `fork()` copies the parent's state — memory, file descriptors, signal handlers
* Pages are shared read-only (Copy-on-Write) and copied only on first write
* Parent and child share the same file description and offset
* `execve()` replaces the image — PID stays, address space is rebuilt
* ELF segments are mapped but not read from disk until the first page fault (demand paging)
* Dynamically linked binaries run `ld.so` first to resolve libraries before reaching `main()`

### Termination and Reaping
* `exit()` frees memory and files but leaves a zombie until the parent calls `wait()`
* If the parent dies first, the child is reparented to a subreaper


## 05 Examples

```bash
gcc -Wall -Wextra -O2 05-process-management.c -o 05-process-management
./05-process-management
```


## 06 Examples

```bash
gcc -Wall -Wextra -O2 06-advanced-process-management.c -o 06-advanced-process-management
./06-advanced-process-management
```

## 07 Examples

```bash
gcc -Wall -Wextra -O2 -pthread 07-threading.c -o 07-threading
./07-threading
```

## 08 Examples

```bash
gcc -Wall -Wextra -O2 08-file-directory-management.c -o 08-file-directory-management
./08-file-directory-management
```

## 09 Examples

```bash
gcc -Wall -Wextra -O2 09-memory-management.c -o 09-memory-management
./09-memory-management
```

## 10 Examples

```bash
gcc -Wall -Wextra -O2 10-signals.c -o 10-signals
./10-signals
```

## 11 Examples

```bash
gcc -Wall -Wextra -O2 11-time.c -o 11-time
./11-time
```
