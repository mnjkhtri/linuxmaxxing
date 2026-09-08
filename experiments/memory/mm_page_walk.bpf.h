/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LX_MM_PAGE_WALK_BPF_H
#define LX_MM_PAGE_WALK_BPF_H

/*
 * Best-effort x86-64, 4-level page-table sampler for visualization.
 *
 * This is intentionally not a correctness oracle: it does not take mmap_lock, page-table locks, RCU read locks, or mmu_notifier synchronization.
 * The workload is single-purpose and snapshots are taken at phase boundaries,
 * so the sampled PTE/PMD state is useful for teaching VMA -> page-table -> physical-target relationships, including COW and THP, without turning this exercise into a kernel page-table walker module.
 */

struct pt_walk
{
    u64 start;            /* First virtual address in this VMA. */
    u64 end;              /* Stop before this virtual address. */
    u64 pgd;              /* mm->pgd: root of this process page table. */
    u64 page_offset_base; /* Direct-map base for reading lower page-table pages. */
    u32 pages;            /* Page-sized slots to sample. */
    u32 vma_index;        /* Slot in mm_event.state.vmas. */
};

static __always_inline u64 next_table(u64 entry, u64 page_offset_base)
{
    /* Entries hold physical addresses; BPF reads them through the direct map. */
    return (entry & PTE_ADDRESS_MASK) + page_offset_base;
}

static __always_inline void set_page(struct mm_vma_record *vma, u32 index, u8 state, u64 target, u8 dirty)
{
    u32 page_index = index & (MAX_PAGES_PER_VMA - 1);

    if (!vma || page_index >= vma->pt_scanned_pages)
        return;
    vma->pt_states[page_index] = state;
    if (dirty)
        vma->pt_dirty[page_index >> 6] |= 1ULL << (page_index & 63);
    vma->pt_targets[page_index] = (u16)(target ^ (target >> 16) ^ (target >> 32)); /* Compact PFN identity for COW/sharing view. */
}

static long walk_page_table(u32 index, void *data)
{
    struct pt_walk *walk = data;
    u64 address = walk->start + (u64)index * PAGE_SIZE;
    u32 vma_index = walk->vma_index;

    if (index >= walk->pages || address >= walk->end || vma_index >= MAX_VMAS)
        return 1;

    /* Re-lookup keeps the map-value pointer verifier-safe inside bpf_loop. */
    u32 zero = 0;
    struct mm_event *event = bpf_map_lookup_elem(&scratch, &zero);
    if (!event)
        return 1;

    struct mm_vma_record *vma = &event->state.vmas[vma_index];
    u64 table = walk->pgd;

    /* PGD selects the top-level range containing this user address. */
    u64 entry = read_u64(table + ((address >> 39) & PTR_MASK) * sizeof(u64));

    if (!(entry & X86_PRESENT))
        goto none;
    /* PUD can either point down to PMD or be a huge mapping itself. */
    table = next_table(entry, walk->page_offset_base);
    entry = read_u64(table + ((address >> PUD_SHIFT) & PTR_MASK) * sizeof(u64));
    if (!(entry & X86_PRESENT))
        goto none;
    if (entry & X86_LARGE)
    {
        u64 target = ((entry & PTE_ADDRESS_MASK) >> PAGE_SHIFT) + ((address & (PUD_SIZE - 1)) >> PAGE_SHIFT);
        set_page(vma, index, MM_PAGE_HUGE_PUD, target, !!(entry & X86_DIRTY));
        return 0;
    }

    /* PMD can either point down to PTEs or be a THP-sized mapping. */
    table = next_table(entry, walk->page_offset_base);
    entry = read_u64(table + ((address >> PMD_SHIFT) & PTR_MASK) * sizeof(u64));
    if (!(entry & X86_PRESENT))
        goto none;
    if (entry & X86_LARGE)
    {
        u64 target = ((entry & PTE_ADDRESS_MASK) >> PAGE_SHIFT) + ((address & (PMD_SIZE - 1)) >> PAGE_SHIFT);
        set_page(vma, index, MM_PAGE_HUGE_PMD, target, !!(entry & X86_DIRTY));
        return 0;
    }

    /* PTE is the base-page leaf: present, swap, or absent. */
    table = next_table(entry, walk->page_offset_base);
    entry = read_u64(table + ((address >> PAGE_SHIFT) & PTR_MASK) * sizeof(u64));
    if (entry & X86_PRESENT)
    {
        set_page(vma, index, MM_PAGE_PTE, (entry & PTE_ADDRESS_MASK) >> PAGE_SHIFT, !!(entry & X86_DIRTY));
        return 0;
    }
    if (entry)
    {
        set_page(vma, index, MM_PAGE_SWAP, 0, 0);
        return 0;
    }

none:
    set_page(vma, index, MM_PAGE_NONE, 0, 0);
    return 0;
}

#endif
