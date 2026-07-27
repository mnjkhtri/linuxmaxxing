/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LX_MM_XARRAY_WALK_BPF_H
#define LX_MM_XARRAY_WALK_BPF_H

/*
 * Best-effort bounded XArray slot scan for page-cache accounting.
 *
 * nrpages says how many base pages are cached, but it does not tell us how
 * those pages are grouped into folios.  This scans XArray slots directly for
 * the small exercise mappings instead of assuming file indices are dense.
 */

static __always_inline bool xa_is_internal_entry(u64 entry)
{
    return (entry & 3) == 2;
}

static __always_inline bool xa_is_node_entry(u64 entry)
{
    return xa_is_internal_entry(entry) && entry > 4096;
}

static __always_inline bool xa_is_sibling_entry(u64 entry)
{
    return xa_is_internal_entry(entry) && entry < ((63ULL << 2) | 2);
}

static __always_inline u64 xa_to_node_address(u64 entry)
{
    return entry - 2;
}

struct cache_walk
{
    struct address_space *mapping;
    u32 vma_index;
};

static __always_inline void count_cache_folio(struct mm_snapshot *event, u32 vma_index, struct folio *folio)
{
    u64 flags = BPF_CORE_READ(folio, flags.f);
    u8 dirty = !!(flags & (1ULL << PG_dirty));
    u8 writeback = !!(flags & (1ULL << PG_writeback));
    u8 order = 0;

    if (flags & (1ULL << PG_head))
        order = BPF_CORE_READ(folio, _flags_1) & 0xff;
    if (order > MAX_CACHE_ORDERS - 1)
        order = MAX_CACHE_ORDERS - 1;

    u32 folio_pages = 1U << order;
    struct vma_record *record = &event->vmas[vma_index];

    record->cache_folios++;
    record->cache_order_folios[order]++;

    if (dirty)
    {
        record->cache_dirty_folios++;
        record->cache_order_dirty[order]++;
    }
    if (writeback)
    {
        record->cache_writeback_folios++;
        record->cache_order_writeback[order]++;
    }
    if (!dirty && !writeback)
    {
        record->cache_clean_folios++;
    }
}

static long walk_xarray(u32 slot, void *data)
{
    struct cache_walk *walk = data;
    u32 vma_index = walk->vma_index;
    struct address_space *mapping = walk->mapping;

    if (slot >= MAX_XARRAY_SCAN_SLOTS || vma_index >= MAX_VMAS || !mapping)
        return 1;

    u64 entry = (u64)BPF_CORE_READ(mapping, i_pages.xa_head);
    if (!entry || (entry & 1))
        return 0;

    if (xa_is_node_entry(entry))
    {
        struct xa_node *root = (struct xa_node *)xa_to_node_address(entry);
        u8 root_shift = BPF_CORE_READ(root, shift);

        if (root_shift == 0)
        {
            if (slot >= XA_CHUNK_SIZE)
                return 0;
            entry = (u64)BPF_CORE_READ(root, slots[slot]);
        }
        else if (root_shift == 6)
        {
            u32 root_slot = slot >> 6;
            u32 leaf_slot = slot & XA_CHUNK_MASK;
            if (root_slot >= XA_CHUNK_SIZE)
                return 0;

            entry = (u64)BPF_CORE_READ(root, slots[root_slot]);
            if (!entry || (entry & 1) || xa_is_sibling_entry(entry))
                return 0;
            if (xa_is_node_entry(entry))
            {
                struct xa_node *leaf = (struct xa_node *)xa_to_node_address(entry);
                entry = (u64)BPF_CORE_READ(leaf, slots[leaf_slot]);
            }
            else if (leaf_slot != 0)
            {
                return 0;
            }
        }
        else
        {
            /* Fallback: bounded point lookup for deeper sparse trees. */
#pragma unroll
            for (int depth = 0; depth < MAX_XARRAY_DEPTH; depth++)
            {
                if (!xa_is_node_entry(entry))
                    break;
                struct xa_node *node = (struct xa_node *)xa_to_node_address(entry);
                u8 shift = BPF_CORE_READ(node, shift);
                u64 offset = ((u64)slot >> shift) & XA_CHUNK_MASK;
                entry = (u64)BPF_CORE_READ(node, slots[offset]);
                if (xa_is_sibling_entry(entry))
                    return 0;
            }
        }
    }
    else if (slot != 0)
    {
        return 0;
    }

    if (!entry || (entry & 1) || xa_is_internal_entry(entry) || xa_is_sibling_entry(entry))
        return 0;

    u32 zero = 0;
    struct mm_snapshot *event = bpf_map_lookup_elem(&scratch, &zero);
    if (!event)
        return 1;

    count_cache_folio(event, vma_index, (struct folio *)entry);
    return 0;
}

#endif
