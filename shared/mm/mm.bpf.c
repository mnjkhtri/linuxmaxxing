// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_VMAS 16
#define MAX_PAGES_PER_VMA 512
#define XA_CHUNK_MASK 0x3fULL
#define XA_CHUNK_SIZE 64
#define MAX_XARRAY_SCAN_SLOTS (XA_CHUNK_SIZE * XA_CHUNK_SIZE)
#define MAX_XARRAY_DEPTH 4
#define MAX_CACHE_ORDERS 10
#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PMD_SHIFT 21
#define PMD_SIZE (1ULL << PMD_SHIFT)
#define PUD_SHIFT 30
#define PUD_SIZE (1ULL << PUD_SHIFT)
#define PTR_MASK 0x1ffULL
#define PTE_ADDRESS_MASK 0x000ffffffffff000ULL
#define X86_PRESENT (1ULL << 0)
#define X86_LARGE (1ULL << 7)

extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym;
extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it, struct task_struct *task, __u64 address) __ksym;
extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym;

/* Resolved by the loader from /proc/kallsyms for this x86-64 guest. */
const volatile __u64 page_offset_base_address;

struct vma_record
{
    u64 start; /* VMA start address; positions the block in the virtual address-space view. */
    u64 end;   /* VMA end address; gives the VMA size and lower edge. */
    u64 flags; /* vm_flags; decoded into read/write/exec/shared permissions in the UI. */
    u64 pgoff; /* File page offset for file-backed VMAs. */

    u32 struct_file; /* Whether vm_file exists; separates file-backed from anon/special VMAs. */

    u64 mapping;     /* struct address_space pointer; target object for page-cache arrows. */
    u64 cache_pages; /* address_space->nrpages: total cached PAGE_SIZE units for the whole file. */

    u32 cache_folios;                            /* Folios found in address_space->i_pages. */
    u32 cache_clean_folios;                      /* Folios with neither PG_dirty nor PG_writeback. */
    u32 cache_dirty_folios;                      /* Folios with PG_dirty set. */
    u32 cache_writeback_folios;                  /* Folios with PG_writeback set. */
    u16 cache_order_folios[MAX_CACHE_ORDERS];    /* Folio count per order; pages per folio = 1 << order. */
    u16 cache_order_dirty[MAX_CACHE_ORDERS];     /* Dirty folios per order. */
    u16 cache_order_writeback[MAX_CACHE_ORDERS]; /* Writeback folios per order. */

    u64 inode;  /* Backing inode number; groups file VMAs that point to the same file. */
    u32 device; /* Superblock device id; disambiguates equal inode numbers. */

    char file_name[64]; /* Dentry name displayed inside file-backed VMA and address_space cards. */

    u32 pt_scanned_pages;              /* Number of valid entries in pt_states/pt_targets. */
    u8 pt_states[MAX_PAGES_PER_VMA];   /* Per-page state: none, PTE, swap, or huge mapping. */
    u16 pt_targets[MAX_PAGES_PER_VMA]; /* Compact PFN identity for COW/sharing comparison. */
};

struct mm_snapshot
{
    u64 timestamp_ns; /* Monotonic timestamp for ordering snapshots against PHASE records. */

    u64 pid_tgid;  /* Combined PID/TID; split by the loader for display. */
    u64 mm;        /* struct mm_struct pointer identifies the captured address space. */
    u64 mmap_base; /* mm->mmap_base; shown in the mm_struct summary card. */

    u64 total_vm;       /* Total mapped virtual pages from mm_struct accounting. */
    u64 data_vm;        /* Data virtual pages; kept for mm_struct completeness/debugging. */
    u64 exec_vm;        /* Executable virtual pages; kept for mm_struct completeness/debugging. */
    u64 stack_vm;       /* Stack virtual pages; kept for mm_struct completeness/debugging. */
    u64 pgtables_bytes; /* Page-table memory charged to this mm. */

    u32 map_count; /* Kernel mm->map_count; compared against captured vma_count. */
    u32 vma_count; /* Number of VMA records copied into this snapshot. */

    s64 anon_pages;   /* RSS anon counter; drives the ANON residency bar. */
    s64 file_pages;   /* RSS file counter; drives the FILE residency bar. */
    s64 shmem_pages;  /* RSS shmem counter; drives the SHMEM residency bar. */
    s64 swap_entries; /* RSS swap-entry counter; drives the SWAP residency bar. */

    char comm[16];                    /* Process name filter and displayed command. */
    struct vma_record vmas[MAX_VMAS]; /* Bounded VMA snapshot rendered by the HTML. */
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct mm_snapshot);
} scratch SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline bool is_memory_exercise(char comm[16])
{
    const char expected[16] = "exercise_memory";

#pragma unroll
    for (int i = 0; i < 15; i++)
        if (comm[i] != expected[i])
            return false;
    return true;
}

static __always_inline u64 read_u64(u64 address)
{
    u64 value = 0;

    if (address)
        bpf_probe_read_kernel(&value, sizeof(value), (const void *)address);
    return value;
}

#include "mm_xarray_walk.bpf.h"
#include "mm_page_walk.bpf.h"

SEC("uretprobe")
int snapshot_phase_return(struct pt_regs *context)
{
    (void)context;
    u32 zero = 0;
    struct mm_snapshot *event = bpf_map_lookup_elem(&scratch, &zero);
    if (!event)
        return 0;

    bpf_get_current_comm(event->comm, sizeof(event->comm));
    if (!is_memory_exercise(event->comm))
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;

    event->timestamp_ns = bpf_ktime_get_ns();

    event->pid_tgid = bpf_get_current_pid_tgid();
    event->mm = (u64)mm;
    event->mmap_base = BPF_CORE_READ(mm, mmap_base);

    event->total_vm = BPF_CORE_READ(mm, total_vm);
    event->data_vm = BPF_CORE_READ(mm, data_vm);
    event->exec_vm = BPF_CORE_READ(mm, exec_vm);
    event->stack_vm = BPF_CORE_READ(mm, stack_vm);
    event->pgtables_bytes = BPF_CORE_READ(mm, pgtables_bytes.counter);

    event->map_count = BPF_CORE_READ(mm, map_count);
    event->vma_count = 0;

    event->anon_pages = BPF_CORE_READ(&mm->rss_stat[MM_ANONPAGES], count);
    event->file_pages = BPF_CORE_READ(&mm->rss_stat[MM_FILEPAGES], count);
    event->shmem_pages = BPF_CORE_READ(&mm->rss_stat[MM_SHMEMPAGES], count);
    event->swap_entries = BPF_CORE_READ(&mm->rss_stat[MM_SWAPENTS], count);

    struct vm_area_struct *vma;
    bpf_for_each(task_vma, vma, task, 0)
    {
        if (event->vma_count >= MAX_VMAS)
        {
            break;
        }

        struct vma_record *record = &event->vmas[event->vma_count];

        record->start = BPF_CORE_READ(vma, vm_start);
        record->end = BPF_CORE_READ(vma, vm_end);
        record->flags = BPF_CORE_READ(vma, vm_flags);
        record->pgoff = BPF_CORE_READ(vma, vm_pgoff);

        struct file *file = BPF_CORE_READ(vma, vm_file);
        if (file)
        {
            record->struct_file = 1;

            struct address_space *mapping = BPF_CORE_READ(file, f_mapping);
            if (mapping)
            {
                record->mapping = (u64)mapping;
                record->cache_pages = BPF_CORE_READ(mapping, nrpages);
            }
            else
            {
                record->mapping = 0;
                record->cache_pages = 0;
            }

            struct inode *inode = BPF_CORE_READ(file, f_inode);
            if (inode)
            {
                record->inode = BPF_CORE_READ(inode, i_ino);
                record->device = BPF_CORE_READ(inode, i_sb, s_dev);
            }
            else
            {
                record->inode = record->device = 0;
            }

            record->file_name[0] = 0;
            struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
            if (dentry)
            {
                const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
                if (name)
                    bpf_probe_read_kernel_str(record->file_name, sizeof(record->file_name), name);
            }
        }
        else
        {
            record->struct_file = 0;
            record->inode = 0;
            record->device = 0;
            record->mapping = 0;
            record->cache_pages = 0;
            record->file_name[0] = 0;
        }

        record->cache_folios = 0;
        record->cache_clean_folios = 0;
        record->cache_dirty_folios = 0;
        record->cache_writeback_folios = 0;
#pragma unroll
        for (u32 order = 0; order < MAX_CACHE_ORDERS; order++)
        {
            record->cache_order_folios[order] = 0;
            record->cache_order_dirty[order] = 0;
            record->cache_order_writeback[order] = 0;
        }

        if (file && record->mapping)
        {
            u8 mapping_seen = 0;
#pragma unroll
            for (u32 previous = 0; previous < MAX_VMAS; previous++)
            {
                if (previous >= event->vma_count)
                    break;
                if (event->vmas[previous].mapping == record->mapping)
                    mapping_seen = 1;
            }

            if (!mapping_seen)
            {
                struct cache_walk cache = {
                    .mapping = (struct address_space *)record->mapping,
                    .vma_index = event->vma_count,
                };
                bpf_loop(MAX_XARRAY_SCAN_SLOTS, walk_xarray, &cache, 0);
            }
        }

        struct pt_walk walk = {
            .start = record->start,
            .end = record->end,
            .pgd = (u64)BPF_CORE_READ(mm, pgd),
            .page_offset_base = read_u64(page_offset_base_address),
            .vma_index = event->vma_count,
            .pages = (u32)((record->end - record->start) >> PAGE_SHIFT),
        };
        if (walk.pages > MAX_PAGES_PER_VMA)
        {
            walk.pages = MAX_PAGES_PER_VMA;
        }
        record->pt_scanned_pages = walk.pages;

        /* Bounded eBPF loop: sample each page-sized slot in this VMA. */
        bpf_loop(walk.pages, walk_page_table, &walk, 0);

        event->vma_count++;
    }

    bpf_ringbuf_output(&events, event, sizeof(*event), 0);
    return 0;
}
