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
 *     sample GFN 0-15 plus 8 pages spread evenly across the 2 MiB huge slot 1 window
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
 * Optional typed sections carry paired VMM requests/returns; state carries the EPT walk when a vCPU association exists.
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

struct control_args
{
	__u64 started_ns;
	__u64 operation_id;
	__u8 command;
};

struct memslot_args
{
	__u64 started_ns;
	__u64 operation_id;
	__u64 guest_phys_addr;
	__u64 userspace_addr;
	__u64 size;
	__u32 slot;
	__u32 flags;
	__u8 control_command;
	int vm_fd;
};

struct ioctl_args
{
	__u64 started_ns;
	__u64 call_id;
	__u64 request;
	__u64 argument;
	int fd;
};

struct madvise_args
{
	__u64 started_ns;
	__u64 call_id;
	__u64 start;
	__u64 length;
	int advice;
};

struct mmap_args
{
	__u64 started_ns;
	__u64 call_id;
	__u64 requested_addr;
	__u64 length;
	__u64 offset;
	int prot;
	int flags;
	int fd;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct control_args);
} active_control SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct memslot_args);
} active_memslot SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct ioctl_args);
} active_ioctl SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct madvise_args);
} active_madvise SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct mmap_args);
} active_mmap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} operation_counters SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} ioctl_counters SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} madvise_counters SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} mmap_counters SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u8);
} experiment_tasks SEC(".maps");

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

static __always_inline int experiment_started(__u64 key)
{
	return bpf_map_lookup_elem(&experiment_tasks, &key) != NULL;
}

SEC("uprobe/build/vmm:main")
int BPF_UPROBE(observe_vmm_main)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u8 active = 1;

	bpf_map_update_elem(&experiment_tasks, &key, &active, BPF_ANY);
	return 0;
}

static __always_inline struct ept_event *new_event(enum ept_event_type event_type)
{
	__u32 zero = 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ept_event *event = bpf_map_lookup_elem(&scratch, &zero);

	if (!event)
		return NULL;
	/* Scratch persists across callbacks; reset each optional section's public validity state. */
	event->control.present = 0;
	event->control.completed = 0;
	event->control.result = 0;
	event->control.duration_ns = 0;
	event->memslot.present = 0;
	event->memslot.completed = 0;
	event->memslot.result = 0;
	event->memslot.duration_ns = 0;
	event->ioctl.present = 0;
	event->ioctl.completed = 0;
	event->ioctl.result = 0;
	event->ioctl.duration_ns = 0;
	event->madvise.present = 0;
	event->madvise.completed = 0;
	event->madvise.result = 0;
	event->madvise.duration_ns = 0;
	event->mmap.present = 0;
	event->mmap.completed = 0;
	event->mmap.result = 0;
	event->mmap.duration_ns = 0;
	event->disposition.present = 0;
	event->disposition.result = 0;
	event->state.present = 0;
	bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
	if (!is_vmm_comm(event->context.comm))
		return NULL;
	event->time_ns = bpf_ktime_get_ns();
	event->event_info.event = event_type;
	event->context.pid = pid_tgid >> 32;
	event->context.tid = (__u32)pid_tgid;
	event->context.cpu = bpf_get_smp_processor_id();
	return event;
}

static __always_inline __u64 next_operation_id(__u64 key)
{
	__u64 next = 1;
	__u64 *last = bpf_map_lookup_elem(&operation_counters, &key);

	if (last)
		next = *last + 1;
	bpf_map_update_elem(&operation_counters, &key, &next, BPF_ANY);
	return next;
}

static __always_inline void emit_event(struct ept_event *event)
{
	if (event)
		bpf_ringbuf_output(&events, event, sizeof(*event), 0);
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
	/* Keep the low-GFN view dense, then walk 8 pages spread evenly across the 2 MiB huge window. */
	/* The samples fall on GFN HUGE_GFN_BASE + stride*k, so they cover the slot 1 range end to end. */
	if (slot < SLOT0_GFN_SAMPLES)
		return slot;
	return HUGE_GFN_BASE + (__u64)(slot - SLOT0_GFN_SAMPLES) * HUGE_GFN_STRIDE;
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

/* Sample the current EPT root and bounded walks into an already initialized event. */
static __always_inline void sample_vcpu_state(struct ept_event *event, struct kvm_vcpu *vcpu)
{
	if (!event || !vcpu)
		return;
	struct kvm_mmu *mmu = BPF_CORE_READ(vcpu, arch.mmu);
	__u64 root_hpa = mmu ? READ_KVM_MMU_ROOT_HPA(mmu) : 0;
	__u64 root_pgd = mmu ? READ_KVM_MMU_ROOT_PGD(mmu) : 0;

	event->state.present = 1;
	event->state.vcpu = (__u64)vcpu;
	event->state.kvm = (__u64)BPF_CORE_READ(vcpu, kvm);
	event->state.mmu = (__u64)mmu;
	event->state.root_hpa = root_hpa;
	event->state.root_pgd = root_pgd;
#pragma unroll
	for (__u32 i = 0; i < MAX_GFN_SAMPLES; i++)
		walk_gfn(event, i, root_hpa);
}

static __always_inline void sample_current_state(struct ept_event *event)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &key);

	if (vcpu)
		sample_vcpu_state(event, *vcpu);
}

static __always_inline int snapshot_current_mm(enum ept_event_type event_type)
{
	struct ept_event *event = new_event(event_type);

	if (!event)
		return 0;
	sample_current_state(event);
	emit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int observe_ioctl_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 next = 1;
	__u64 *last;
	struct ept_event *event;
	struct ioctl_args args = {};

	if (!experiment_started(key))
		return 0;
	last = bpf_map_lookup_elem(&ioctl_counters, &key);
	event = new_event(EPT_EVENT_SYS_ENTER_IOCTL);
	if (!event)
		return 0;
	if (last)
		next = *last + 1;
	args.started_ns = event->time_ns;
	args.call_id = next;
	args.fd = (int)ctx->args[0];
	args.request = ctx->args[1];
	args.argument = ctx->args[2];
	bpf_map_update_elem(&ioctl_counters, &key, &next, BPF_ANY);
	bpf_map_update_elem(&active_ioctl, &key, &args, BPF_ANY);
	event->ioctl.present = 1;
	event->ioctl.fd = args.fd;
	event->ioctl.request = args.request;
	event->ioctl.argument = args.argument;
	event->ioctl.call_id = args.call_id;
	sample_current_state(event);
	emit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int observe_ioctl_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct ioctl_args *args = bpf_map_lookup_elem(&active_ioctl, &key);
	struct ept_event *event;

	if (!args)
		return 0;
	event = new_event(EPT_EVENT_SYS_EXIT_IOCTL);
	if (event)
	{
		event->ioctl.present = 1;
		event->ioctl.completed = 1;
		event->ioctl.fd = args->fd;
		event->ioctl.request = args->request;
		event->ioctl.argument = args->argument;
		event->ioctl.call_id = args->call_id;
		event->ioctl.result = ctx->ret;
		event->ioctl.duration_ns = event->time_ns - args->started_ns;
		sample_current_state(event);
		emit_event(event);
	}
	bpf_map_delete_elem(&active_ioctl, &key);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_madvise")
int observe_madvise_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 next = 1;
	__u64 *last;
	struct ept_event *event;
	struct madvise_args args = {};

	if (!experiment_started(key))
		return 0;
	last = bpf_map_lookup_elem(&madvise_counters, &key);
	event = new_event(EPT_EVENT_SYS_ENTER_MADVISE);
	if (!event)
		return 0;
	if (last)
		next = *last + 1;
	args.started_ns = event->time_ns;
	args.call_id = next;
	args.start = ctx->args[0];
	args.length = ctx->args[1];
	args.advice = (int)ctx->args[2];
	bpf_map_update_elem(&madvise_counters, &key, &next, BPF_ANY);
	bpf_map_update_elem(&active_madvise, &key, &args, BPF_ANY);
	event->madvise.present = 1;
	event->madvise.start = args.start;
	event->madvise.length = args.length;
	event->madvise.advice = args.advice;
	event->madvise.call_id = args.call_id;
	sample_current_state(event);
	emit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_madvise")
int observe_madvise_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct madvise_args *args = bpf_map_lookup_elem(&active_madvise, &key);
	struct ept_event *event;

	if (!args)
		return 0;
	event = new_event(EPT_EVENT_SYS_EXIT_MADVISE);
	if (event)
	{
		event->madvise.present = 1;
		event->madvise.completed = 1;
		event->madvise.start = args->start;
		event->madvise.length = args->length;
		event->madvise.advice = args->advice;
		event->madvise.call_id = args->call_id;
		event->madvise.result = ctx->ret;
		event->madvise.duration_ns = event->time_ns - args->started_ns;
		sample_current_state(event);
		emit_event(event);
	}
	bpf_map_delete_elem(&active_madvise, &key);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int observe_mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 next = 1;
	__u64 *last;
	struct ept_event *event;
	struct mmap_args args = {};

	if (!experiment_started(key))
		return 0;
	last = bpf_map_lookup_elem(&mmap_counters, &key);
	event = new_event(EPT_EVENT_SYS_ENTER_MMAP);
	if (!event)
		return 0;
	if (last)
		next = *last + 1;
	args.started_ns = event->time_ns;
	args.call_id = next;
	args.requested_addr = ctx->args[0];
	args.length = ctx->args[1];
	args.prot = (int)ctx->args[2];
	args.flags = (int)ctx->args[3];
	args.fd = (int)ctx->args[4];
	args.offset = ctx->args[5];
	bpf_map_update_elem(&mmap_counters, &key, &next, BPF_ANY);
	bpf_map_update_elem(&active_mmap, &key, &args, BPF_ANY);
	event->mmap.present = 1;
	event->mmap.requested_addr = args.requested_addr;
	event->mmap.length = args.length;
	event->mmap.prot = args.prot;
	event->mmap.flags = args.flags;
	event->mmap.fd = args.fd;
	event->mmap.offset = args.offset;
	event->mmap.call_id = args.call_id;
	sample_current_state(event);
	emit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int observe_mmap_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct mmap_args *args = bpf_map_lookup_elem(&active_mmap, &key);
	struct ept_event *event;

	if (!args)
		return 0;
	event = new_event(EPT_EVENT_SYS_EXIT_MMAP);
	if (event)
	{
		event->mmap.present = 1;
		event->mmap.completed = 1;
		event->mmap.requested_addr = args->requested_addr;
		event->mmap.length = args->length;
		event->mmap.prot = args->prot;
		event->mmap.flags = args->flags;
		event->mmap.fd = args->fd;
		event->mmap.offset = args->offset;
		event->mmap.call_id = args->call_id;
		event->mmap.result = ctx->ret;
		event->mmap.duration_ns = event->time_ns - args->started_ns;
		sample_current_state(event);
		emit_event(event);
	}
	bpf_map_delete_elem(&active_mmap, &key);
	return 0;
}

/* Optional: distinguish exits handled inside KVM from exits returned by KVM_RUN. */
SEC("kretprobe/vmx_handle_exit")
int BPF_KRETPROBE(observe_vmx_handle_exit_return, int result)
{
	struct ept_event *event = new_event(EPT_EVENT_VMX_HANDLE_EXIT_RETURN);

	if (!event)
		return 0;
	event->disposition.present = 1;
	event->disposition.result = result;
	sample_current_state(event);
	emit_event(event);
	return 0;
}

/* Snapshot vCPU MM/EPT state from the same KVM tracepoint events that the UI displays. */
static __always_inline int snapshot_vcpu_mm(struct kvm_vcpu *vcpu, enum ept_event_type event_type)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct ept_event *event = new_event(event_type);

	if (!event || !vcpu)
		return 0;
	bpf_map_update_elem(&current_vcpu, &key, &vcpu, BPF_ANY);
	sample_vcpu_state(event, vcpu);
	emit_event(event);
	return 0;
}

SEC("uprobe/build/vmm:handle_control_command")
int BPF_UPROBE(observe_control_begin, void *context, __u8 command)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct ept_event *event = new_event(EPT_EVENT_CONTROL_BEGIN);
	struct control_args args = {};

	(void)context;
	if (!event)
		return 0;
	args.started_ns = event->time_ns;
	args.operation_id = next_operation_id(key);
	args.command = command;
	bpf_map_update_elem(&active_control, &key, &args, BPF_ANY);
	event->control.present = 1;
	event->control.command = command;
	event->control.operation_id = args.operation_id;
	sample_current_state(event);
	emit_event(event);
	return 0;
}

SEC("uretprobe/build/vmm:handle_control_command")
int BPF_URETPROBE(observe_control_end, int result)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct control_args *args = bpf_map_lookup_elem(&active_control, &key);
	struct ept_event *event;

	if (!args)
		return 0;
	event = new_event(EPT_EVENT_CONTROL_END);
	if (event)
	{
		event->control.present = 1;
		event->control.completed = 1;
		event->control.command = args->command;
		event->control.result = result;
		event->control.operation_id = args->operation_id;
		event->control.duration_ns = event->time_ns - args->started_ns;
		sample_current_state(event);
		emit_event(event);
	}
	bpf_map_delete_elem(&active_control, &key);
	return 0;
}

SEC("uprobe/build/vmm:set_memory_region")
int BPF_UPROBE(observe_memslot_begin, int vm_fd, __u32 slot, __u64 guest_phys_addr, void *memory, __u64 size, __u32 flags)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct control_args *control = bpf_map_lookup_elem(&active_control, &key);
	struct ept_event *event = new_event(EPT_EVENT_MEMSLOT_BEGIN);
	struct memslot_args args = {};

	if (!event)
		return 0;
	args.started_ns = event->time_ns;
	args.operation_id = next_operation_id(key);
	args.vm_fd = vm_fd;
	args.slot = slot;
	args.flags = flags;
	args.guest_phys_addr = guest_phys_addr;
	args.userspace_addr = (__u64)memory;
	args.size = size;
	args.control_command = control ? control->command : 0;
	bpf_map_update_elem(&active_memslot, &key, &args, BPF_ANY);
	event->memslot.present = 1;
	event->memslot.vm_fd = vm_fd;
	event->memslot.slot = slot;
	event->memslot.flags = flags;
	event->memslot.guest_phys_addr = guest_phys_addr;
	event->memslot.userspace_addr = (__u64)memory;
	event->memslot.size = size;
	event->memslot.control_command = args.control_command;
	event->memslot.operation_id = args.operation_id;
	sample_current_state(event);
	emit_event(event);
	return 0;
}

SEC("uretprobe/build/vmm:set_memory_region")
int BPF_URETPROBE(observe_memslot_end, int result)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct memslot_args *args = bpf_map_lookup_elem(&active_memslot, &key);
	struct ept_event *event;

	if (!args)
		return 0;
	event = new_event(EPT_EVENT_MEMSLOT_END);
	if (event)
	{
		event->memslot.present = 1;
		event->memslot.completed = 1;
		event->memslot.vm_fd = args->vm_fd;
		event->memslot.result = result;
		event->memslot.slot = args->slot;
		event->memslot.flags = args->flags;
		event->memslot.guest_phys_addr = args->guest_phys_addr;
		event->memslot.userspace_addr = args->userspace_addr;
		event->memslot.size = args->size;
		event->memslot.control_command = args->control_command;
		event->memslot.operation_id = args->operation_id;
		event->memslot.duration_ns = event->time_ns - args->started_ns;
		sample_current_state(event);
		emit_event(event);
	}
	bpf_map_delete_elem(&active_memslot, &key);
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

SEC("tp/kvm/kvm_page_fault")
int kvm_page_fault_snapshot(void *ctx)
{
	(void)ctx;
	return snapshot_current_mm(EPT_EVENT_KVM_PAGE_FAULT);
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

SEC("tp/kvmmmu/kvm_mmu_split_huge_page")
int kvm_mmu_split_huge_page_snapshot(void *ctx)
{
	(void)ctx;
	return snapshot_current_mm(EPT_EVENT_KVM_MMU_SPLIT_HUGE_PAGE);
}

SEC("tp/kvmmmu/mark_mmio_spte")
int mark_mmio_spte_snapshot(void *ctx)
{
	(void)ctx;
	return snapshot_current_mm(EPT_EVENT_MARK_MMIO_SPTE);
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
