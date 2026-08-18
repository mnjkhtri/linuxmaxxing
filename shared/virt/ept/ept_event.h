/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ring-buffer ABI shared between the BPF side (ept.bpf.c) and the userspace loader (ept.c).
 * This is the binary format only: the loader serializes it into the canonical NDJSON envelope.
 *
 * One KVM boundary snapshot, grouped into three semantic facts:
 *
 *   time_ns    CLOCK_MONOTONIC (bpf_ktime_get_ns()), comparable with the tracefs instance clock (mono)
 *   event_info which KVM boundary produced this snapshot
 *   context    where and as whom the probe executed (the VMM thread)
 *   state      the observed EPT root and per-GFN walk after that boundary
 *
 * The header intentionally contains no JSON vocabulary and no JSON representation choices.
 * Events are integers here, pointers are raw u64 here, and present/mmio flags are 0/1 here.
 * The loader converts those into readable names, "0x..."/null, and booleans for the public schema.
 * It must compile in both BPF (-target bpf) and normal userspace builds.
 */
#ifndef EPT_EVENT_H
#define EPT_EVENT_H

/* Bounded-observation limits: they define the ABI and the public capture metadata. */
#define EPT_LEVELS 4
#define SLOT0_GFN_SAMPLES 16
#define HUGE_GFN_SAMPLES 1
#define MAX_GFN_SAMPLES (SLOT0_GFN_SAMPLES + HUGE_GFN_SAMPLES)
#define HUGE_GFN_BASE 512

/* The KVM boundary that produced this snapshot; the loader owns the readable names. */
enum ept_event_type
{
	EPT_EVENT_KVM_ENTRY = 0,
	EPT_EVENT_KVM_EXIT = 1,
	EPT_EVENT_KVM_USERSPACE_EXIT = 2,
	EPT_EVENT_KVM_UNMAP_HVA_RANGE = 3,
	EPT_EVENT_KVM_MMU_SPTE_REQUESTED = 4,
	EPT_EVENT_KVM_MMU_SET_SPTE = 5,
	EPT_EVENT_KVM_FLUSH_REMOTE_TLBS = 6,
};

/* One EPT/TDP page-table entry observed on the way to a sampled GFN. */
struct ept_entry_record
{
	unsigned long long spte;	  /* Raw SPTE read from this level. */
	unsigned long long table_hpa; /* Host physical address of the EPT table page holding this entry. */
	unsigned short index;		  /* 9-bit slot selected by the GPA for this level. */
	unsigned char level;		  /* EPT level: 4=PML4, 3=PDPT, 2=PD, 1=PT. */
	unsigned char present;		  /* Hardware-usable EPT entry after excluding KVM's MMIO marker. */
	unsigned char mmio;			  /* KVM software MMIO SPTE; present but not a GPA-to-HPA mapping. */
	unsigned char leaf;			  /* This entry maps memory instead of pointing to a lower table. */
	unsigned char readable;		  /* EPT read permission. */
	unsigned char writable;		  /* EPT write permission. */
	unsigned char executable;	  /* EPT execute permission. */
	unsigned char accessed;		  /* Hardware EPT accessed state when EPT A/D is enabled. */
	unsigned char dirty;		  /* Hardware EPT dirty state when EPT A/D is enabled. */
};

/* One sampled guest frame number with its complete bounded EPT walk. */
struct ept_guest_gfn
{
	unsigned long long gfn;		 /* Guest frame number being sampled. */
	unsigned long long gva;		 /* Guest virtual address; equals GPA while guest paging is off. */
	unsigned long long gpa;		 /* Guest physical address: gfn << PAGE_SHIFT. */
	unsigned long long leaf_pfn; /* Host PFN from the leaf SPTE when mapped. */
	unsigned char ept_mapped;	 /* Whether the walk reached a real RAM leaf mapping. */
	unsigned char ept_mmio;		 /* Whether the walk reached KVM's non-mapping MMIO marker. */
	unsigned char leaf_level;	 /* Level that provided the RAM leaf; 1 means normal 4 KiB page. */

	struct ept_entry_record entries[EPT_LEVELS]; /* Per-level EPT walk, GPA-indexed. */
};

/* Which KVM boundary this snapshot belongs to. */
struct ept_event_info
{
	unsigned int event; /* enum ept_event_type. */
};

/* Where and as whom the probe executed: the VMM thread driving the vCPU. */
struct ept_context
{
	unsigned int pid; /* TGID of the probing task. */
	unsigned int tid; /* TID of the probing task. */
	unsigned int cpu; /* CPU on which the probe callback executed. */
	char comm[16];	  /* Task name of the probing task. */
};

/* The KVM EPT state observed after the boundary. */
struct ept_state
{
	unsigned long long vcpu;	 /* struct kvm_vcpu pointer that owns this snapshot. */
	unsigned long long kvm;		 /* Owning struct kvm pointer for this vCPU. */
	unsigned long long mmu;		 /* vcpu->arch.mmu, KVM's software MMU/EPT state object. */
	unsigned long long root_hpa; /* Host physical address of the EPT root page. */
	unsigned long long root_pgd; /* KVM root PGD/GPA metadata, useful for comparing kernel versions. */

	struct ept_guest_gfn gfns[MAX_GFN_SAMPLES]; /* Bounded GFN sample window. */
};

struct ept_event
{
	unsigned long long time_ns;
	struct ept_event_info event_info;
	struct ept_context context;
	struct ept_state state;
};

#endif /* EPT_EVENT_H */
