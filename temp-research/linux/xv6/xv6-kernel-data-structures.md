# xv6-riscv Kernel Data Structures and ELF Sections

Scope: current working-tree source under `xv6-riscv/kernel/*.c` and `xv6-riscv/kernel/*.h`.

Section classification follows the requested source rules:

- `.bss`: uninitialized globals/statics, or explicit zero initializers such as `= 0`.
- `.data`: non-zero initialized globals/statics.
- `.rodata`: `const` globals and string literals.

Note: the existing optimized kernel ELF places some unmodified internal static lookup tables (`digits`, `states`, `syscalls`) in `.rodata` even though they are not declared `const`. They are listed under `.data` below because they are non-zero initialized objects under the requested rules.

## .bss section (zero-initialized)

| File | Scope | Name | Type | Approx. size | Description | Initialized by |
|---|---|---|---|---:|---|---|
| `start.c` | global | `stack0` | `char stack0[4096 * NCPU]` with `__attribute__((aligned(16)))` | `4096 * 8 = 32768` bytes | Per-CPU boot stacks used by `entry.S` before normal kernel scheduling. | none; linker/loader zeroes it |
| `main.c` | static global | `started` | `volatile static int` | 4 bytes | Boot synchronization flag; secondary harts spin until hart 0 finishes initialization. | `main()` sets it to 1 |
| `kalloc.c` | global | `kmem` | anonymous `struct { struct spinlock lock; struct run *freelist; }` | 32 bytes | Physical-page allocator state and free-list head. | `kinit()` |
| `vm.c` | global | `kernel_pagetable` | `pagetable_t` (`uint64 *`) | 8 bytes | Root of the shared kernel page table. | `kvminit()` |
| `proc.c` | global | `cpus` | `struct cpu cpus[NCPU]` | `8 * 128 = 1024` bytes | Per-CPU scheduler context, current process pointer, and interrupt nesting state. | none; runtime paths update fields |
| `proc.c` | global | `proc` | `struct proc proc[NPROC]` | `64 * 360 = 23040` bytes | Process table containing process locks, state, contexts, open files, cwd, and names. | `procinit()` |
| `proc.c` | global | `initproc` | `struct proc *` | 8 bytes | Pointer to the first process. | `userinit()` |
| `proc.c` | global | `pid_lock` | `struct spinlock` | 24 bytes | Protects `nextpid`. | `procinit()` |
| `proc.c` | global | `wait_lock` | `struct spinlock` | 24 bytes | Protects parent/child wait and wakeup coordination. | `procinit()` |
| `trap.c` | global | `tickslock` | `struct spinlock` | 24 bytes | Protects the timer tick counter. | `trapinit()` |
| `trap.c` | global | `ticks` | `uint` | 4 bytes | Timer tick count, incremented by clock interrupts. | none; incremented by `clockintr()` |
| `printf.c` | global | `panicking` | `volatile int` | 4 bytes | Suppresses printf locking once panic output begins. | none; set by `panic()` |
| `printf.c` | global | `panicked` | `volatile int` | 4 bytes | Freezes UART output from other CPUs after panic. | none; set by `panic()` |
| `printf.c` | static global | `pr` | anonymous `struct { struct spinlock lock; }` | 24 bytes | Serializes concurrent `printf()` output. | `printfinit()` |
| `uart.c` | static global | `tx_lock` | `struct spinlock` | 24 bytes | Protects UART transmit state. | `uartinit()` |
| `uart.c` | static global | `tx_busy` | `int` | 4 bytes | Tracks whether UART transmit is in progress. | none; used by `uartwrite()`/`uartintr()` |
| `uart.c` | static global | `tx_chan` | `int` | 4 bytes | Address used as UART transmit sleep channel. | none |
| `file.c` | global | `devsw` | `struct devsw devsw[NDEV]` | `10 * 16 = 160` bytes | Device major-number dispatch table for read/write functions. | `consoleinit()` fills `CONSOLE` |
| `file.c` | global | `ftable` | anonymous `struct { struct spinlock lock; struct file file[NFILE]; }` | `24 + 100 * 40 = 4024` bytes | System-wide open-file table. | `fileinit()` |
| `fs.c` | global | `sb` | `struct superblock` | 32 bytes | In-memory superblock for the single xv6 filesystem device. | `fsinit()` |
| `fs.c` | global | `itable` | anonymous `struct { struct spinlock lock; struct inode inode[NINODE]; }` | `24 + 50 * 136 = 6824` bytes | In-memory inode cache/table. | `iinit()` |
| `log.c` | global | `log` | `struct log` | 168 bytes | Filesystem transaction log state and in-memory log header. | `initlog()` |
| `bio.c` | global | `bcache` | anonymous `struct { struct spinlock lock; struct buf buf[NBUF]; struct buf head; }` | `24 + 31 * 1112 = 34496` bytes | Disk buffer cache and LRU list sentinel. | `binit()` |
| `console.c` | global | `cons` | anonymous `struct { struct spinlock lock; char buf[128]; uint r,w,e; }` | 168 bytes | Console input ring buffer and indices. | `consoleinit()` |
| `virtio_disk.c` | static global | `disk` | `static struct disk` | 320 bytes | Virtio block-device queue pointers, descriptor state, in-flight request info, headers, and lock. | `virtio_disk_init()` |

Header extern declarations that do not allocate storage: `proc.h` declares `extern struct cpu cpus[NCPU]`; `file.h` declares `extern struct devsw devsw[]`; `defs.h` declares `extern uint ticks` and `extern struct spinlock tickslock`.

## .data section (non-zero initialized)

| File | Scope | Name | Type | Initial value | Approx. size | Description |
|---|---|---|---|---|---:|---|
| `proc.c` | global | `nextpid` | `int` | `1` | 4 bytes | Next process ID allocated by `allocpid()`, protected by `pid_lock`. |
| `proc.c` | static local in `forkret()` | `first` | `static int` | `1` | 4 bytes | One-time guard for first process filesystem initialization and `/init` exec. |
| `printf.c` | static global | `digits` | `static char digits[]` | `"0123456789abcdef"` | 17 bytes | Digit lookup table for decimal/hex formatting. |
| `proc.c` | static local in `procdump()` | `states` | `static char *states[]` | process-state string pointers | `6 * 8 = 48` bytes | Maps `enum procstate` values to printable state names. |
| `syscall.c` | static global | `syscalls` | `static uint64 (*syscalls[])(void)` | designated syscall handler pointers | `22 * 8 = 176` bytes | Dispatch table from syscall number to `sys_*` implementation. |

## .rodata section (read-only)

| File | Name | Type | Description |
|---|---|---|---|
| all `kernel/*.c` | string literal pool | string literals | Panic messages, printf formats, lock names (`"kmem"`, `"proc"`, `"bcache"`, etc.), filesystem paths such as `"/"` and `"/init"`, and debug/status text. Not listed individually. |
| all `kernel/*.c` / `kernel/*.h` | const globals | none found | No file-scope `const` object definitions were found in the kernel C/header files. |

Relevant attribute annotations checked:

- `start.c`: `stack0` uses `__attribute__((aligned(16)))`, so it remains a `.bss` object with at least 16-byte alignment.
- `fs.h`: `struct dirent.name` uses `__attribute__((nonstring))`; this is a field annotation and creates no file-scope storage.
- `defs.h`: `printf` has a `format(printf, 1, 2)` function attribute; `panic` and `scheduler` are marked `noreturn`. These create no data objects.

## Linker symbols

| Name | Defined in | Points to |
|---|---|---|
| `etext` | `kernel/kernel.ld` via `PROVIDE(etext = .)` after `.text`/trampoline placement | First address after the kernel text/trampoline area; used by `vm.c` to map text read/execute and the remaining kernel/RAM read/write. Existing ELF: `0x80007000`. |
| `end` | `kernel/kernel.ld` via `PROVIDE(end = .)` after `.bss` | First address after the loaded kernel image; `kalloc.c` starts the free physical-page range here. Existing ELF: `0x800234c8`. |
| `trampoline` | label in `kernel/trampoline.S`, placed in `trampsec` by `kernel/kernel.ld` | Start of the trampoline page, mapped at `TRAMPOLINE` in user and kernel page tables. Existing ELF: `0x80006000`. |
| `uservec` | label in `kernel/trampoline.S` | User trap-entry code within the trampoline page; referenced by `trap.c`. Existing ELF: `0x80006000`. |
| `userret` | label in `kernel/trampoline.S` | User return path within the trampoline page; referenced by `proc.c` `forkret()`. Existing ELF: `0x8000609c`. |

## Dynamically allocated at boot (kalloc'd, lives in free memory above `end`)

`kinit()` does not call `kalloc()`. It calls `freerange(end, PHYSTOP)`, which page-aligns `end` upward and frees every 4096-byte page through `PHYSTOP` into `kmem.freelist`. The rows below are pages subsequently removed from that free list during boot.

| What | Allocated by | Size | Description |
|---|---|---:|---|
| Kernel page table pages | `kvminit()` -> `kvmmake()` -> `kalloc()`/`mappages()`/`walk()` | 102 pages = 417792 bytes | Root plus intermediate Sv39 page-table pages for UART, VIRTIO MMIO, PLIC, kernel text/data/RAM direct map, trampoline, and kernel-stack virtual mappings. |
| Per-process kernel stack backing pages | `kvmmake()` -> `proc_mapstacks()` | `NPROC * PGSIZE = 64 * 4096 = 262144` bytes | One physical stack page for each `proc[]` entry, mapped at `KSTACK(i)` with guard-page gaps. |
| Virtio queue pages | `virtio_disk_init()` | `3 * PGSIZE = 12288` bytes | DMA pages for `disk.desc`, `disk.avail`, and `disk.used`. |
| First process trapframe page | `userinit()` -> `allocproc()` | 1 page = 4096 bytes | Per-process trapframe page mapped at `TRAPFRAME` in the process page table. |
| First process initial user page table pages | `userinit()` -> `allocproc()` -> `proc_pagetable()` -> `uvmcreate()`/`mappages()` | 3 pages = 12288 bytes | Empty user root page table plus high-address page-table pages for `TRAMPOLINE` and `TRAPFRAME`; later replaced by the first `/init` exec. |
| First `/init` exec page table and user memory | `forkret()` -> `kexec("/init", ...)` -> `proc_pagetable()`/`uvmalloc()` | 9 pages = 36864 bytes allocated; then the old 3-page empty user page table is freed | Loads the built `_init` ELF: 5 new page-table pages and 4 user memory pages for two ELF pages plus guard and user stack pages. |

Other non-boot `kalloc()` sites found: `uvmalloc()` for process growth and exec loading, `uvmcopy()` for fork copies, `vmfault()` for lazy user pages, `pipealloc()` for a one-page pipe buffer, and `sys_exec()` for temporary one-page argument buffers that are freed after `kexec()`.

## Summary statistics

- Estimated `.bss` size: about 103216 bytes of named objects; existing ELF `.bss` is 103224 bytes including alignment padding.
- Estimated `.data` size by the requested rules: about 249 bytes of named objects, before alignment. Existing optimized ELF `.data` is 24 bytes because `digits`, `states`, and `syscalls` are emitted as read-only local objects.
- Number of spinlocks: 157 spinlock storage slots total; 156 are initialized during boot. This includes 76 direct spinlocks and 81 spinlocks embedded inside static sleeplocks; the extra uninitialized one is inside the `bcache.head` sentinel buffer.
- Number of sleeplocks: 81 sleeplock storage slots total; 80 are initialized during boot (`NBUF` buffer locks plus `NINODE` inode locks), with the `bcache.head` sentinel's sleeplock storage unused.
- Number of `kalloc()` calls during boot: 173 before entering the scheduler/first `forkret()` path. If the built-in first `kexec("/init", ...)` is counted as part of boot, the total calls rise to 182, after which 3 old initial user-page-table pages are freed.
