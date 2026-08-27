# XV6-RISCV Kernel Data Structures Analysis

Exhaustive survey of all global and static variable declarations across the xv6-riscv kernel.
Source: `/home/mike/Desktop/linux/xv6/xv6-riscv/kernel/`

---

## .bss section (zero-initialized)

Variables that are uninitialized or explicitly zero-initialized. The linker places these in `.bss` and the boot process zeroes the range before `main()` runs.

| File | Variable | Type | Static? | Size | Description | Init function |
|------|----------|------|---------|------|-------------|---------------|
| main.c | `started` | `volatile static int` | static | 4 B | Boot synchronization flag; hart 0 sets to 1 after init | self (set in main) |
| start.c | `stack0` | `char[4096*8]` `__attribute__((aligned(16)))` | global | 32 768 B | Boot kernel stacks, one 4 KB page per CPU (NCPU=8) | entry.S (sp set) |
| proc.c | `cpus[NCPU]` | `struct cpu[8]` | global | 8 × sizeof(struct cpu) ≈ 1 088 B | Per-CPU state (scheduler context, intena, noff, proc ptr) | scheduler() / mycpu() |
| proc.c | `proc[NPROC]` | `struct proc[64]` | global | 64 × sizeof(struct proc) ≈ 49 152 B | Process table | procinit() |
| proc.c | `initproc` | `struct proc *` | global | 8 B | Pointer to the init process | userinit() |
| proc.c | `nextpid` | `int` | global | 4 B | Next PID counter (starts at 1; stored as .data — see note) | procinit() |
| proc.c | `pid_lock` | `struct spinlock` | global | ≈ 32 B | Protects nextpid | procinit() |
| proc.c | `wait_lock` | `struct spinlock` | global | ≈ 32 B | Protects parent–child wait operations | procinit() |
| kalloc.c | `kmem` (anon struct) | `struct { struct spinlock lock; struct run *freelist; }` | global | ≈ 40 B | Kernel physical-page allocator state | kinit() |
| vm.c | `kernel_pagetable` | `pagetable_t` | global | 8 B | Pointer to the kernel's root page table | kvminit() |
| printf.c | `panicking` | `volatile int` | global | 4 B | Set to 1 while panic is in progress (suppresses re-entrant locks) | none |
| printf.c | `pr` (anon struct) | `struct { struct spinlock lock; int locking; }` | static | ≈ 24 B | Printf serialisation state | printfinit() |
| uart.c | `tx_lock` | `static struct spinlock` | static | ≈ 32 B | UART transmit-side lock | uartinit() |
| uart.c | `tx_buf[UART_TX_BUF_SIZE]` | `static char[32]` | static | 32 B | UART TX ring buffer | uartinit() |
| uart.c | `tx_w` | `static uint64` | static | 8 B | UART TX write index | uartinit() |
| uart.c | `tx_r` | `static uint64` | static | 8 B | UART TX read index | uartinit() |
| console.c | `cons` (anon struct) | `struct { struct spinlock lock; char buf[128]; uint r, w, e; }` | static | ≈ 152 B | Console input ring buffer + lock | consoleinit() |
| file.c | `devsw[NDEV]` | `struct devsw[10]` | global | 10 × sizeof(struct devsw) ≈ 80 B | Device switch table (read/write fn ptrs, zeroed = no device) | consoleinit() (fills slot 1) |
| file.c | `ftable` (anon struct) | `struct { struct spinlock lock; struct file file[NFILE]; }` | static | ≈ 8 + 100 × sizeof(struct file) ≈ 3 208 B | Global open-file table | fileinit() |
| bio.c | `bcache` (anon struct) | `struct { struct spinlock lock; struct buf buf[NBUF]; struct buf head; }` | static | ≈ 16 + 30 × sizeof(struct buf) ≈ 30 KB | Buffer cache (disk block cache) | binit() |
| fs.c | `sb` | `struct superblock` | global | sizeof(struct superblock) = 32 B | Cached copy of on-disk superblock | fsinit() |
| fs.c | `itable` (anon struct) | `struct { struct spinlock lock; struct inode inode[NINODE]; }` | static | ≈ 16 + 50 × sizeof(struct inode) ≈ 6 KB | In-memory inode table | iinit() |
| log.c | `log` | `struct log` | static | ≈ 120 B | Logging/journalling state (lock, lh, outstanding, committing) | initlog() |
| trap.c | `tickslock` | `struct spinlock` | global | ≈ 32 B | Protects the `ticks` counter | trapinit() |
| trap.c | `ticks` | `uint` | global | 4 B | Wall-clock tick counter (incremented by timer IRQ) | trapinit() (lock only); incremented in clockintr() |
| virtio_disk.c | `disk` (anon struct) | `struct { struct virtq_desc *desc; struct virtq_avail *avail; struct virtq_used *used; char free[NUM]; uint16 used_idx; struct { struct buf *b; char status; } info[NUM]; struct virtio_blk_req ops[NUM]; struct spinlock vdisk_lock; }` | static | ≈ 200 B (ptrs/indices; pages kalloc'd) | Virtio disk driver state | virtio_disk_init() |
| sleeplock.c | *(no file-scope vars)* | — | — | — | All state is inside `struct sleeplock` instances embedded elsewhere | — |
| spinlock.c | *(no file-scope vars)* | — | — | — | All state is inside `struct spinlock` instances embedded elsewhere | — |
| pipe.c | *(no file-scope vars)* | — | — | — | Pipe state is heap-allocated via kalloc() | pipealloc() |
| plic.c | *(no file-scope vars)* | — | — | — | PLIC access is all MMIO via macros | plicinit() |
| exec.c | *(no file-scope vars)* | — | — | — | — | — |
| string.c | *(no file-scope vars)* | — | — | — | Pure functions only | — |
| syscall.c | `syscalls[]` | `static uint64 (*syscalls[])(void)` | static | 22 × 8 B = 176 B | Syscall dispatch table (fn ptrs; zero slots = NULL) | none |
| sysfile.c | *(no file-scope vars)* | — | — | — | — | — |
| sysproc.c | *(no file-scope vars)* | — | — | — | — | — |

> **Note on `nextpid`**: Initialised to `1` in source (`int nextpid = 1`), so it actually lands in **.data**, not .bss. Listed again in the .data table below.

---

## .data section (non-zero initialized)

Variables with an explicit non-zero initializer. Stored in the `.data` segment and copied from the kernel ELF image at load time.

| File | Variable | Type | Static? | Initial value | Description |
|------|----------|------|---------|---------------|-------------|
| proc.c | `nextpid` | `int` | global | `1` | First PID issued will be 1 |
| printf.c | `digits` | `static char[]` | static | `"0123456789abcdef"` | Hex digit lookup for `printint`/`printptr` |
| syscall.c | `syscalls[]` non-NULL slots | `uint64 (*)(void)` fn ptrs | static | addresses of sys_* functions | Non-NULL entries in dispatch table (the table as a whole straddles .data/.bss) |

---

## .rodata section (read-only)

Constant data. The compiler typically emits `const` globals and string literals here.

| File | Variable | Type | Description |
|------|----------|------|-------------|
| *(all .c files)* | string literals | `const char[]` | Panic messages, `printf` format strings, lock names (`"proc"`, `"bcache"`, `"itable"`, etc.) — not individually listed |
| trap.c / proc.c / vm.c | *(none explicit)* | — | No `const` globals declared; lock-name string literals passed to `initlock()` end up here |

---

## Linker symbols

Symbols defined in `kernel/kernel.ld` (or assembly files) and declared `extern` in C code so the kernel can reference memory-layout boundaries.

| Name | Declared / used in | Points to / meaning |
|------|--------------------|---------------------|
| `end` | `kalloc.c` (`extern char end[]`) | First byte after all kernel BSS — start of free physical memory handed to `kinit()` |
| `etext` | `vm.c` (`extern char etext[]`) | First byte after the kernel `.text` section — used to set PTE_X boundary in `kvmmap` |
| `trampoline` | `proc.c`, `trap.c`, `vm.c` (`extern char trampoline[]`) | Start of the trampoline page (trampoline.S); mapped at `TRAMPOLINE` VA in every address space |
| `kernelvec` | `trap.c` (`extern void kernelvec()`) | Entry point for kernel-mode traps (kernelvec.S) |
| `uservec` | `trap.c`, `proc.c` (`extern char uservec[]`) | User-mode trap entry in trampoline page (trampoline.S) |
| `userret` | `trap.c`, `proc.c` (`extern char userret[]`) | Return-to-user code in trampoline page (trampoline.S) |
| `stack0` | `entry.S` references; `start.c` defines it | 32 KB statically-allocated boot stacks (one 4 KB page per hart) |

---

## Dynamically allocated at boot (kalloc'd, lives in free memory above `end`)

All `kalloc()` allocations return 4 096-byte pages from the free list that `kinit()` builds from `end` to `PHYSTOP`.

| What | Allocated by (function) | Size | Description |
|------|------------------------|------|-------------|
| Kernel page table root | `kvmmake()` ← `kvminit()` | 1 page = 4 096 B | Root PPN for the kernel's Sv39 page table |
| Kernel stack per process | `proc_mapstacks()` ← `kvmmake()` | 64 × 1 page = 256 KB | One guard-less stack page per `proc[]` slot (mapped at fixed VAs in kernel space) |
| Virtio descriptor ring (`disk.desc`) | `virtio_disk_init()` | 1 page = 4 096 B | `NUM` (8) `virtq_desc` structures |
| Virtio available ring (`disk.avail`) | `virtio_disk_init()` | 1 page = 4 096 B | `virtq_avail` with `NUM` ring entries |
| Virtio used ring (`disk.used`) | `virtio_disk_init()` | 1 page = 4 096 B | `virtq_used` with `NUM` ring entries |
| `initproc` trapframe | `allocproc()` ← `userinit()` | 1 page = 4 096 B | Trap frame for PID 1 (init) |
| `initproc` user page table | `proc_pagetable()` ← `userinit()` | 1 page + walk pages | Root PPN for init's user address space |
| `initproc` user memory (initcode) | `uvmalloc()` ← `userinit()` | 1 page = 4 096 B | First page of init's user address space (holds initcode binary) |
| *(runtime)* trapframe per forked proc | `allocproc()` | 1 page each | Trap frame for every subsequent process |
| *(runtime)* user page tables | `uvmcreate()` / `walk()` | variable | Page table nodes for user processes |
| *(runtime)* pipe buffers | `pipealloc()` | 1 page per pipe | `struct pipe` + 512-byte ring buffer, packed into one page |
| *(runtime)* user heap/stack pages | `uvmalloc()` ← `growproc()` / `exec()` | variable | Physical pages backing user virtual memory |

---

## Summary statistics

### Estimated total .bss size

| Contributor | Bytes |
|-------------|-------|
| `stack0` (start.c) | 32 768 |
| `proc[64]` (proc.c) | ~49 152 |
| `bcache` (bio.c) | ~30 720 |
| `itable` (fs.c) | ~6 144 |
| `ftable` (file.c) | ~3 208 |
| `cpus[8]` (proc.c) | ~1 088 |
| `cons` (console.c) | ~152 |
| `disk` (virtio_disk.c) | ~200 |
| `log` (log.c) | ~120 |
| `tx_buf` + indices (uart.c) | ~48 |
| `pr` (printf.c) | ~24 |
| `syscalls[]` null slots | ~32 |
| Miscellaneous spinlocks + small vars | ~300 |
| **Total** | **≈ 124 KB** |

### Estimated total .data size

| Contributor | Bytes |
|-------------|-------|
| `digits` (printf.c) | 17 |
| `nextpid` (proc.c) | 4 |
| Non-NULL `syscalls[]` fn ptrs | ~176 |
| **Total** | **≈ 200 B** |

### Number of spinlocks (`struct spinlock` instances)

| Location | Count |
|----------|-------|
| `proc[64].lock` | 64 |
| `bcache.buf[30]` — **sleeplock**, not spinlock | 0 here |
| `bcache.lock` | 1 |
| `itable.lock` | 1 |
| `itable.inode[50].lock` — **sleeplock** | 0 here |
| `ftable.lock` | 1 |
| `log.lock` | 1 |
| `kmem.lock` | 1 |
| `pid_lock` | 1 |
| `wait_lock` | 1 |
| `tickslock` | 1 |
| `cons.lock` | 1 |
| `tx_lock` (uart) | 1 |
| `pr.lock` (printf) | 1 |
| `disk.vdisk_lock` | 1 |
| **Total spinlocks** | **75** |

### Number of sleeplocks (`struct sleeplock` instances)

| Location | Count |
|----------|-------|
| `bcache.buf[30].lock` | 30 |
| `itable.inode[50].lock` | 50 |
| **Total sleeplocks** | **80** |

### Number of `kalloc()` calls during boot sequence

| Call site | Count |
|-----------|-------|
| `kvmmake()` — kernel page table root | 1 |
| `proc_mapstacks()` — 64 process kernel stacks | 64 |
| `virtio_disk_init()` — desc + avail + used rings | 3 |
| `userinit()` → `allocproc()` — PID 1 trapframe | 1 |
| `userinit()` → `proc_pagetable()` — PID 1 user PT root | 1 |
| `userinit()` → `uvmalloc()` — PID 1 initcode page | 1 |
| **Total boot-time `kalloc()` calls** | **71** |

> `kinit()` itself calls `kfree()` in a loop (not `kalloc()`), populating the free list from `end` to `PHYSTOP`.

---

## Key observations

1. **Process table dominates .bss**: `proc[64]` alone accounts for ~40% of static kernel data.
2. **Minimal .data**: Almost all global state is zero-initialized; only `nextpid`, the `digits` string, and the syscall dispatch table carry non-zero initial values.
3. **Encapsulation via anonymous structs**: `cons`, `pr`, `kmem`, `ftable`, `bcache`, `itable`, `log`, and `disk` each bundle their lock with their data in a file-local anonymous struct — a clean pattern for ownership.
4. **`stack0` is the largest single BSS object**: 32 KB of boot stacks declared with `__attribute__((aligned(16)))` in `start.c`.
5. **Virtio uses kalloc'd pages for rings**: The three virtqueue rings are heap-allocated (not statically declared), so their physical addresses can be handed to the device via MMIO.
6. **75 spinlocks, 80 sleeplocks**: Sleeplocks dominate per-resource; spinlocks dominate at the table/subsystem level.
7. **Linker symbols as memory-map anchors**: `end`, `etext`, and `trampoline` are the kernel's only interface to the linker script at runtime.
