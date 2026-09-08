/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ring-buffer ABI shared between the BPF side (mm.bpf.c) and the userspace loader (mm.c).
 * This is the binary format only: the loader serializes it into the canonical NDJSON envelope.
 *
 * One post-phase-boundary MM snapshot, grouped into three semantic facts:
 *
 *   time_ns    CLOCK_MONOTONIC (bpf_ktime_get_ns()), comparable with the tracefs instance clock (mono)
 *   event_info which completed workload phase produced this snapshot
 *   context    where and as whom the probe executed (the workload task, not the captured mm)
 *   state      the observed mm_struct / RSS / VMA / page-cache / page-table state after the boundary
 *
 * The header intentionally contains no JSON vocabulary and no JSON representation choices.
 * Pointers are raw u64 here; the loader converts them into "0x..."/null for the public schema.
 * It must compile in both BPF (-target bpf) and normal userspace builds.
 */
#ifndef MM_EVENT_H
#define MM_EVENT_H

/* Bounded-observation limits: they define the ABI and the public capture metadata. */
#define MAX_VMAS 16
#define MAX_PAGES_PER_VMA 512
#define PT_DIRTY_WORDS ((MAX_PAGES_PER_VMA + 63) / 64)
#define MAX_XARRAY_SCAN_SLOTS 4096
#define MAX_XARRAY_DEPTH 4
#define MAX_CACHE_ORDERS 10

/* Page-table leaf states observed by the bounded walker; also the ABI encoding of pt_states. */
enum mm_page_state
{
	MM_PAGE_NONE = 0,	  /* VMA exists, but this virtual page has no page-table entry. */
	MM_PAGE_PTE = 1,	  /* Present base-page PTE points at a physical page. */
	MM_PAGE_SWAP = 2,	  /* Non-present entry carries swap metadata. */
	MM_PAGE_HUGE_PMD = 3, /* PMD is the leaf for a 2 MiB mapping; this is the practical THP case. */
	MM_PAGE_HUGE_PUD = 4, /* PUD is the leaf for a valid but less common 1 GiB mapping. */
};

/* One bounded VMA observation; it legitimately aggregates several kinds of MM state. */
struct mm_vma_record
{
	unsigned long long start; /* VMA start address; positions the block in the virtual address-space view. */
	unsigned long long end;	  /* VMA end address; gives the VMA size and lower edge. */
	unsigned long long flags; /* vm_flags; decoded into read/write/exec/shared permissions in the UI. */
	unsigned long long pgoff; /* File page offset for file-backed VMAs. */

	unsigned int struct_file;			/* Whether vm_file exists; separates file-backed from anon/special VMAs. */
	unsigned long long anon_vma;		/* vma->anon_vma for anonymous reverse-map/COW lineage visualization. */
	unsigned long long anon_vma_root;	/* anon_vma->root pointer, when anon_vma exists. */
	unsigned long long anon_vma_parent; /* anon_vma->parent pointer, when anon_vma exists. */

	unsigned long long inode; /* Backing inode number; groups file VMAs that point to the same file. */
	unsigned int device;	  /* Superblock device id; disambiguates equal inode numbers. */
	char file_name[64];		  /* Dentry name displayed inside file-backed VMA and address_space cards. */

	unsigned long long mapping;		/* struct address_space pointer; target object for page-cache arrows. */
	unsigned long long cache_pages; /* address_space->nrpages: total cached PAGE_SIZE units for the whole file. */

	unsigned int cache_folios;							 /* Folios found in address_space->i_pages. */
	unsigned short cache_order_folios[MAX_CACHE_ORDERS]; /* Folio count per order; pages per folio = 1 << order. */
	unsigned short cache_order_dirty[MAX_CACHE_ORDERS];	 /* Dirty folios per order. */

	unsigned int cache_clean_folios;	   /* Folios with neither PG_dirty nor PG_writeback. */
	unsigned int cache_dirty_folios;	   /* Folios with PG_dirty set. */
	unsigned int cache_writeback_folios;   /* Folios with PG_writeback set. */
	unsigned int cache_lru_folios;		   /* Folios with PG_lru set. */
	unsigned int cache_active_folios;	   /* Folios with PG_active set. */
	unsigned int cache_referenced_folios;  /* Folios with PG_referenced set. */
	unsigned int cache_workingset_folios;  /* Folios with PG_workingset set. */
	unsigned int cache_unevictable_folios; /* Folios with PG_unevictable set. */

	unsigned int pt_scanned_pages;				  /* Number of valid entries in pt_states/pt_targets. */
	unsigned char pt_states[MAX_PAGES_PER_VMA];	  /* Per-page state: MM_PAGE_NONE/PTE/SWAP/huge mapping. */
	unsigned long long pt_dirty[PT_DIRTY_WORDS];  /* Compact dirty bitmap from mapped PTE/PMD/PUD leaves. */
	unsigned short pt_targets[MAX_PAGES_PER_VMA]; /* Compact PFN identity for COW/sharing comparison. */
};

/* What the snapshot represents: the workload phase that just completed at the boundary. */
struct mm_event_info
{
	unsigned int phase_seq; /* Sequence of the workload phase whose boundary produced this snapshot. */
};

/* Where and as whom the probe executed; the workload task, which may not own the observed mm. */
struct mm_context
{
	unsigned int pid; /* TGID of the probing task. */
	unsigned int tid; /* TID of the probing task. */
	unsigned int cpu; /* CPU on which the probe callback executed. */
	char comm[16];	  /* Task name of the probing task. */
};

/* The actual memory subsystem state observed after the phase boundary. */
struct mm_state
{
	unsigned long long mm;		  /* struct mm_struct pointer identifies the captured address space. */
	unsigned long long mmap_base; /* mm->mmap_base; shown in the mm_struct summary card. */

	unsigned long long total_vm;	   /* Total mapped virtual pages from mm_struct accounting. */
	unsigned long long data_vm;		   /* Data virtual pages; kept for mm_struct completeness/debugging. */
	unsigned long long exec_vm;		   /* Executable virtual pages; kept for mm_struct completeness/debugging. */
	unsigned long long stack_vm;	   /* Stack virtual pages; kept for mm_struct completeness/debugging. */
	unsigned long long pgtables_bytes; /* Page-table memory charged to this mm. */

	unsigned int map_count; /* Kernel mm->map_count; compared against captured vma_count. */
	unsigned int vma_count; /* Number of VMA records copied into this snapshot. */

	long long anon_pages;	/* RSS anon counter; drives the ANON residency bar. */
	long long file_pages;	/* RSS file counter; drives the FILE residency bar. */
	long long shmem_pages;	/* RSS shmem counter; drives the SHMEM residency bar. */
	long long swap_entries; /* RSS swap-entry counter; drives the SWAP residency bar. */

	struct mm_vma_record vmas[MAX_VMAS]; /* Bounded VMA snapshot rendered by the frontend. */
};

struct mm_event
{
	unsigned long long time_ns;
	struct mm_event_info event_info;
	struct mm_context context;
	struct mm_state state;
};

#endif /* MM_EVENT_H */
