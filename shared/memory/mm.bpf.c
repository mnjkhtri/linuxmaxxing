// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "mm_event.h"

char LICENSE[] SEC("license") = "GPL";

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PMD_SHIFT 21
#define PMD_SIZE (1ULL << PMD_SHIFT)
#define PUD_SHIFT 30
#define PUD_SIZE (1ULL << PUD_SHIFT)
#define PTR_MASK 0x1ffULL
#define PTE_ADDRESS_MASK 0x000ffffffffff000ULL
#define X86_PRESENT (1ULL << 0)
#define X86_DIRTY (1ULL << 6)
#define X86_LARGE (1ULL << 7)

extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym;
extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it, struct task_struct *task, __u64 address) __ksym;
extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym;

/* Resolved by the loader from /proc/kallsyms for this x86-64 guest. */
const volatile __u64 page_offset_base_address;

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mm_event);
} scratch SEC(".maps");

/* Temporary state shared by the matching entry and return probes, keyed by pid_tgid. */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u32);
} active_args SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline bool is_memory_workload(char comm[16])
{
	const char expected[16] = "workload_mm";

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

/*
 * Entry probe: record the workload phase sequence argument keyed by pid_tgid.
 * The uretprobe cannot read the call arguments, so the phase identity travels through this map.
 * It deliberately emits no event because the post-phase MM state has not been captured yet.
 */
SEC("uprobe")
int phase_boundary_entry(struct pt_regs *context)
{
	char comm[16];

	bpf_get_current_comm(comm, sizeof(comm));
	if (!is_memory_workload(comm))
		return 0;

	u32 phase_seq = (u32)PT_REGS_PARM1(context);
	u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&active_args, &id, &phase_seq, BPF_ANY);
	return 0;
}

/*
 * Return probe: capture the post-boundary MM state and emit exactly one event per phase boundary.
 * The workload calls phase_boundary() after publishing the completed phase, so the snapshot
 * represents the MM state produced by that phase, identified by event_info.phase_seq.
 */
SEC("uretprobe")
int snapshot_phase_return(struct pt_regs *context)
{
	(void)context;
	u32 zero = 0;
	struct mm_event *event = bpf_map_lookup_elem(&scratch, &zero);
	if (!event)
		return 0;

	bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
	if (!is_memory_workload(event->context.comm))
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 *phase_seq = bpf_map_lookup_elem(&active_args, &id);
	event->event_info.phase_seq = phase_seq ? *phase_seq : 0;
	event->context.pid = (u32)(id >> 32);
	event->context.tid = (u32)id;
	event->context.cpu = bpf_get_smp_processor_id();

	struct task_struct *task = bpf_get_current_task_btf();
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;

	event->time_ns = bpf_ktime_get_ns();

	event->state.mm = (u64)mm;
	event->state.mmap_base = BPF_CORE_READ(mm, mmap_base);

	event->state.total_vm = BPF_CORE_READ(mm, total_vm);
	event->state.data_vm = BPF_CORE_READ(mm, data_vm);
	event->state.exec_vm = BPF_CORE_READ(mm, exec_vm);
	event->state.stack_vm = BPF_CORE_READ(mm, stack_vm);
	event->state.pgtables_bytes = BPF_CORE_READ(mm, pgtables_bytes.counter);

	event->state.map_count = BPF_CORE_READ(mm, map_count);
	event->state.vma_count = 0;

	event->state.anon_pages = BPF_CORE_READ(&mm->rss_stat[MM_ANONPAGES], count);
	event->state.file_pages = BPF_CORE_READ(&mm->rss_stat[MM_FILEPAGES], count);
	event->state.shmem_pages = BPF_CORE_READ(&mm->rss_stat[MM_SHMEMPAGES], count);
	event->state.swap_entries = BPF_CORE_READ(&mm->rss_stat[MM_SWAPENTS], count);

	struct vm_area_struct *vma;
	bpf_for_each(task_vma, vma, task, 0)
	{
		if (event->state.vma_count >= MAX_VMAS)
		{
			break;
		}

		struct mm_vma_record *record = &event->state.vmas[event->state.vma_count];

		record->start = BPF_CORE_READ(vma, vm_start);
		record->end = BPF_CORE_READ(vma, vm_end);
		record->flags = BPF_CORE_READ(vma, vm_flags);
		record->pgoff = BPF_CORE_READ(vma, vm_pgoff);

		struct file *file = BPF_CORE_READ(vma, vm_file);
		if (file)
		{
			record->struct_file = 1;

			/* Inode identity: lets the UI group file-backed VMAs by backing file. */
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

			/* Dentry name: short human-readable label for the VMA and address_space card. */
			record->file_name[0] = 0;
			struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
			if (dentry)
			{
				const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
				if (name)
					bpf_probe_read_kernel_str(record->file_name, sizeof(record->file_name), name);
			}

			/* Page-cache object: f_mapping is the address_space whose XArray owns cached folios. */
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

			record->cache_folios = 0;
			record->cache_clean_folios = 0;
			record->cache_dirty_folios = 0;
			record->cache_writeback_folios = 0;
			record->cache_lru_folios = 0;
			record->cache_active_folios = 0;
			record->cache_referenced_folios = 0;
			record->cache_workingset_folios = 0;
			record->cache_unevictable_folios = 0;
#pragma unroll
			for (u32 order = 0; order < MAX_CACHE_ORDERS; order++)
			{
				record->cache_order_folios[order] = 0;
				record->cache_order_dirty[order] = 0;
			}

			if (mapping)
			{
				/* Walk each address_space once; multiple VMAs may point at the same file cache. */
				u8 mapping_seen = 0;
#pragma unroll
				for (u32 previous = 0; previous < MAX_VMAS; previous++)
				{
					if (previous >= event->state.vma_count)
						break;
					if (event->state.vmas[previous].mapping == record->mapping)
						mapping_seen = 1;
				}

				if (!mapping_seen)
				{
					struct cache_walk cache = {
						.mapping = mapping,
						.vma_index = event->state.vma_count,
					};
					bpf_loop(MAX_XARRAY_SCAN_SLOTS, walk_xarray, &cache, 0);
				}
			}
		}
		else
		{
			record->struct_file = 0;
			record->inode = 0;
			record->device = 0;
			record->file_name[0] = 0;

			record->mapping = 0;
			record->cache_pages = 0;
			record->cache_folios = 0;
			record->cache_clean_folios = 0;
			record->cache_dirty_folios = 0;
			record->cache_writeback_folios = 0;
			record->cache_lru_folios = 0;
			record->cache_active_folios = 0;
			record->cache_referenced_folios = 0;
			record->cache_workingset_folios = 0;
			record->cache_unevictable_folios = 0;
#pragma unroll
			for (u32 order = 0; order < MAX_CACHE_ORDERS; order++)
			{
				record->cache_order_folios[order] = 0;
				record->cache_order_dirty[order] = 0;
			}
		}

		/* Anonymous reverse-map object; MAP_PRIVATE file VMAs can get one after COW. */
		struct anon_vma *anon_vma = BPF_CORE_READ(vma, anon_vma);
		if (anon_vma)
		{
			record->anon_vma = (u64)anon_vma;
			record->anon_vma_root = (u64)BPF_CORE_READ(anon_vma, root);
			record->anon_vma_parent = (u64)BPF_CORE_READ(anon_vma, parent);
		}
		else
		{
			record->anon_vma = 0;
			record->anon_vma_root = 0;
			record->anon_vma_parent = 0;
		}

		struct pt_walk walk = {
			.start = record->start,
			.end = record->end,
			.pgd = (u64)BPF_CORE_READ(mm, pgd),
			.page_offset_base = read_u64(page_offset_base_address),
			.vma_index = event->state.vma_count,
			.pages = (u32)((record->end - record->start) >> PAGE_SHIFT),
		};
		if (walk.pages > MAX_PAGES_PER_VMA)
		{
			walk.pages = MAX_PAGES_PER_VMA;
		}
		record->pt_scanned_pages = walk.pages;
#pragma unroll
		for (u32 word = 0; word < PT_DIRTY_WORDS; word++)
			record->pt_dirty[word] = 0;

		/* Bounded eBPF loop: sample each page-sized slot in this VMA. */
		bpf_loop(walk.pages, walk_page_table, &walk, 0);

		event->state.vma_count++;
	}

	bpf_map_delete_elem(&active_args, &id);
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}
