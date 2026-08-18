// SPDX-License-Identifier: GPL-2.0
/*
 * MM tab mental model:
 *
 *   for each captured VMA
 *     take at most the first 512 pages from that VMA
 *     for each sampled virtual page
 *       start at mm->pgd
 *       walk the process page table
 *       record what that page currently is
 *
 * EPT version in this file:
 *
 *   hook the same KVM tracepoints shown in the VIRT UI
 *   at each selected KVM execution, MMU, or invalidation boundary
 *     sample GFN 0-15 plus the command-4 access in the huge-page range
 *     convert GFN to GPA
 *     start at KVM's EPT root HPA from kvm_vcpu->arch.mmu
 *     walk the EPT/TDP page table
 *     record what host physical page, if any, backs that guest frame
 *
 * The difference is both address space and detail level.
 * The MM tab walks PGD/PUD/PMD/PTE internally, but records only the leaf result in pt_states[]/pt_targets[].
 * This EPT observer records the full per-level EPT walk plus the final leaf result because the table structure is the lesson here.
 * This toy guest currently has paging off, so GVA == GPA.
 *
 * Every callback emits one struct ept_event record.
 * The record is grouped into event_info, context, and state.
 * event_info names which KVM boundary fired, context describes the VMM thread the probe ran as, and state holds the EPT walk.
 * The shared ABI in ept_event.h owns the layout.
 * This file only fills that ABI and never decides JSON shape.
 */

#include "vmlinux.h"
#include "kvm_types.h" /* Generated only when KVM structs live in module BTF instead of vmlinux BTF. */
#include <bpf/bpf_core_read.h>
#include "kvm_compat.h" /* Generated because KVM root fields differ across kernels. */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ept_event.h"

char LICENSE[] SEC("license") = "GPL";

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PTR_MASK 0x1ffULL
#define SPTE_ADDRESS_MASK 0x000ffffffffff000ULL
#define EPT_READ (1ULL << 0)
#define EPT_WRITE (1ULL << 1)
#define EPT_EXEC (1ULL << 2)
#define EPT_LARGE (1ULL << 7)
#define EPT_ACCESSED (1ULL << 8)
#define EPT_DIRTY (1ULL << 9)
#define EPT_SUPPRESS_VE (1ULL << 63)
#define EPT_MMIO_MASK (EPT_READ | EPT_WRITE | EPT_EXEC | EPT_SUPPRESS_VE)
#define EPT_MMIO_VALUE (EPT_WRITE | EPT_EXEC)

/* Userspace resolves page_offset_base so BPF can read EPT pages through the kernel direct map. */
const volatile __u64 page_offset_base_address;

/* Per-CPU scratch avoids putting a large snapshot on the tiny BPF stack. */
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ept_event);
} scratch SEC(".maps");

/* The loader drains this ring buffer and writes one NDJSON record per snapshot. */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Host-MM callbacks do not expose vcpu, so remember the VMM thread's last vCPU. */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct kvm_vcpu *);
} current_vcpu SEC(".maps");

/* Keep the capture focused on our toy VMM process, not every KVM user on the host. */
static __always_inline int is_vmm_comm(char comm[16])
{
	const char expected[4] = "vmm";

#pragma unroll
	for (int i = 0; i < 3; i++)
		if (comm[i] != expected[i])
			return 0;
	return comm[3] == '\0';
}

static __always_inline __u64 read_u64(__u64 address)
{
	__u64 value = 0;

	if (address)
		bpf_probe_read_kernel(&value, sizeof(value), (const void *)address);
	return value;
}

static __always_inline __u64 hpa_to_direct_map(__u64 hpa)
{
	/* EPT entries store HPAs; BPF reads the backing page through the host kernel direct map. */
	return (hpa & SPTE_ADDRESS_MASK) + read_u64(page_offset_base_address);
}

static __always_inline __u16 ept_index(__u64 gpa, __u8 level)
{
	if (level == 4)
		return (gpa >> 39) & PTR_MASK;
	if (level == 3)
		return (gpa >> 30) & PTR_MASK;
	if (level == 2)
		return (gpa >> 21) & PTR_MASK;
	return (gpa >> 12) & PTR_MASK;
}

static __always_inline __u64 ept_leaf_pfn(__u64 spte, __u64 gpa, __u8 level)
{
	__u64 base_pfn = (spte & SPTE_ADDRESS_MASK) >> PAGE_SHIFT;
	__u64 offset_pages = 0;

	/* A large EPT leaf maps 2 MiB at level 2 or 1 GiB at level 3. */
	if (level > 1)
	{
		__u8 offset_bits = PAGE_SHIFT + (9 * (level - 1));
		offset_pages = (gpa & ((1ULL << offset_bits) - 1)) >> PAGE_SHIFT;
	}
	return base_pfn + offset_pages;
}

static __always_inline __u64 sampled_gfn(__u32 slot)
{
	/* Keep the low-GFN view dense, then walk the GFN that faults in the huge range. */
	if (slot < SLOT0_GFN_SAMPLES)
		return slot;
	return HUGE_GFN_BASE;
}

/* Walk one sampled guest frame number through KVM's EPT/TDP page table. */
static __always_inline void walk_gfn(struct ept_event *event, __u32 slot, __u64 root_hpa)
{
	struct ept_guest_gfn *record = &event->state.gfns[slot];
	__u64 gfn = sampled_gfn(slot);
	__u64 gpa = gfn << PAGE_SHIFT;
	__u64 table_hpa = root_hpa;
	__u64 table = (root_hpa && root_hpa != ~0ULL) ? hpa_to_direct_map(root_hpa) : 0;

	record->gfn = gfn;

	/* This toy guest has paging off, so guest virtual address equals guest physical address for now. */
	record->gva = gpa;
	record->gpa = gpa;

	record->ept_mapped = 0;
	record->ept_mmio = 0;
	record->leaf_level = 0;
	record->leaf_pfn = 0;

#pragma unroll
	for (__u32 i = 0; i < EPT_LEVELS; i++)
	{
		__u8 level = EPT_LEVELS - i;
		__u16 index = ept_index(gpa, level);
		struct ept_entry_record *entry = &record->entries[i];
		/* Each level is a 512-entry SPTE page, indexed by the GPA bits for that level. */
		__u64 spte = table ? read_u64(table + ((__u64)index * sizeof(__u64))) : 0;

		entry->spte = spte;
		entry->table_hpa = table_hpa & SPTE_ADDRESS_MASK;
		entry->index = index;
		entry->level = level;

		/* Intel KVM encodes emulated MMIO as the invalid EPT permission pattern W=1, X=1, R=0 so hardware exits instead of translating it. */
		/* KVM/userspace handles that exit; passed-through device MMIO can instead use a real EPT mapping and will not match this marker. */
		entry->mmio = spte && (spte & EPT_MMIO_MASK) == EPT_MMIO_VALUE;
		entry->present = !entry->mmio && (spte & (EPT_READ | EPT_WRITE | EPT_EXEC)) != 0;
		entry->readable = !!(spte & EPT_READ);
		entry->writable = !!(spte & EPT_WRITE);
		entry->executable = !!(spte & EPT_EXEC);
		entry->accessed = !!(spte & EPT_ACCESSED);
		entry->dirty = !!(spte & EPT_DIRTY);
		entry->leaf = 0;

		if (entry->mmio)
		{
			record->ept_mmio = 1;
			table_hpa = 0;
			table = 0;
			continue;
		}

		if (!entry->present)
		{
			table_hpa = 0;
			table = 0;
			continue;
		}

		/* Level 1 is a normal 4 KiB leaf; EPT_LARGE means a higher-level huge mapping is the leaf. */
		if (level == 1 || (spte & EPT_LARGE))
		{
			entry->leaf = 1;
			record->ept_mapped = 1;
			record->leaf_level = level;
			record->leaf_pfn = ept_leaf_pfn(spte, gpa, level);
			table_hpa = 0;
			table = 0;
			continue;
		}

		table_hpa = spte & SPTE_ADDRESS_MASK;
		table = hpa_to_direct_map(table_hpa);
	}
}

/* Snapshot vCPU MM/EPT state from the same KVM tracepoint events that the UI displays. */
static __always_inline int snapshot_vcpu_mm(struct kvm_vcpu *vcpu, enum ept_event_type event_type)
{
	__u32 zero = 0;
	struct ept_event *event = bpf_map_lookup_elem(&scratch, &zero);
	if (!event || !vcpu)
		return 0;

	bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
	if (!is_vmm_comm(event->context.comm))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&current_vcpu, &pid_tgid, &vcpu, BPF_ANY);

	/* vcpu->arch.mmu is KVM's software MMU object; for this VM it owns the EPT root HPA. */
	struct kvm_mmu *mmu = BPF_CORE_READ(vcpu, arch.mmu);
	__u64 root_hpa = mmu ? READ_KVM_MMU_ROOT_HPA(mmu) : 0;
	__u64 root_pgd = mmu ? READ_KVM_MMU_ROOT_PGD(mmu) : 0;

	event->time_ns = bpf_ktime_get_ns();
	event->event_info.event = (unsigned int)event_type;
	event->context.pid = (unsigned int)(pid_tgid >> 32);
	event->context.tid = (unsigned int)pid_tgid;
	event->context.cpu = bpf_get_smp_processor_id();

	event->state.vcpu = (__u64)vcpu;
	event->state.kvm = (__u64)BPF_CORE_READ(vcpu, kvm);
	event->state.mmu = (__u64)mmu;
	event->state.root_hpa = root_hpa;
	event->state.root_pgd = root_pgd;

#pragma unroll
	for (__u32 i = 0; i < MAX_GFN_SAMPLES; i++)
		walk_gfn(event, i, root_hpa);

	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

SEC("raw_tp/kvm_entry")
int kvm_entry_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)ctx->args[0];
	return snapshot_vcpu_mm(vcpu, EPT_EVENT_KVM_ENTRY);
}

SEC("tp/kvm/kvm_exit")
int kvm_exit_snapshot(void *ctx)
{
	(void)ctx;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

	if (!vcpu)
		return 0;
	return snapshot_vcpu_mm(*vcpu, EPT_EVENT_KVM_EXIT);
}

SEC("tp/kvm/kvm_userspace_exit")
int kvm_userspace_exit_snapshot(void *ctx)
{
	(void)ctx;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);
	if (!vcpu)
		return 0;
	return snapshot_vcpu_mm(*vcpu, EPT_EVENT_KVM_USERSPACE_EXIT);
}

SEC("tp/kvm/kvm_unmap_hva_range")
int kvm_unmap_hva_range_snapshot(void *ctx)
{
	(void)ctx;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

	if (!vcpu)
		return 0;
	return snapshot_vcpu_mm(*vcpu, EPT_EVENT_KVM_UNMAP_HVA_RANGE);
}

SEC("tp/kvmmmu/kvm_mmu_spte_requested")
int kvm_mmu_spte_requested_snapshot(void *ctx)
{
	(void)ctx;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);
	if (!vcpu)
		return 0;
	return snapshot_vcpu_mm(*vcpu, EPT_EVENT_KVM_MMU_SPTE_REQUESTED);
}

SEC("tp/kvmmmu/kvm_mmu_set_spte")
int kvm_mmu_set_spte_snapshot(void *ctx)
{
	(void)ctx;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

	if (!vcpu)
		return 0;
	return snapshot_vcpu_mm(*vcpu, EPT_EVENT_KVM_MMU_SET_SPTE);
}

SEC("kprobe/kvm_flush_remote_tlbs")
int kvm_flush_remote_tlbs_snapshot(void *ctx)
{
	(void)ctx;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

	if (!vcpu)
		return 0;
	return snapshot_vcpu_mm(*vcpu, EPT_EVENT_KVM_FLUSH_REMOTE_TLBS);
}
