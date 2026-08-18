// SPDX-License-Identifier: GPL-2.0
/*
 * Interrupt-virtualization observer.
 *
 * This observer snapshots KVM interrupt-controller state at the events the UI renders.
 * Each record carries event metadata plus a best-effort snapshot of the controller state.
 * The controller snapshot covers the IOAPIC redirection entry for the device GSI and the LAPIC IRR/ISR bit for the device vector.
 *
 * Main teaching chain:
 *
 *   kvm_ioapic_set_irq    (IOAPIC RTE reached for the GSI line)
 *     -> kvm_apic_accept_irq  (LAPIC accepts and sets IRR)
 *       -> kvm_inj_virq       (vector selected for injection)
 *         -> guest runs ISR
 *           -> guest EOI write -> kvm_eoi (ISR cleared)
 *
 * The kvm_entry tracepoint records the vmm thread to its vcpu in the pid_tgid association map.
 * Later callbacks recover the vcpu from that map.
 * Every callback derives the vcpu's lapic through the KVM BTF relationship and samples IRR/ISR from it.
 * The kvm_ioapic_set_irq tracepoint samples its RTE bits from its first argument.
 *
 * The argument order was verified on CloudLab kernel 6.8 from /sys/kernel/tracing/events/kvm/<event>/format.
 * Only kvm_entry and kvm_exit expose the vcpu directly; the remaining intercepts recover it from the map.
 * On this kernel kvm_inj_virq and kvm_eoi never fire for this guest, so only the events above appear in the capture.
 * The lapic derivation and the IRR/ISR reads are gated by the BTF readers the Makefile confirms.
 * Until a kernel exposes a reader, the affected fields stay zero and the UI shows them as "not sampled" -- never fake.
 *
 * The shared ABI in io_event.h owns the record layout.
 * The layout is grouped into event_info / context / state.
 * This file only fills that ABI and never decides JSON shape.
 *
 * Every tracepoint fills one shared ring buffer.
 * The event type rides in the record itself, so the loader needs no separate event tag.
 */
#include "vmlinux.h"
#include "kvm_types.h"	/* Generated CO-RE KVM structs when KVM is a module. */
#include "kvm_compat.h" /* Generated to bridge the layout differences handled by the readers below. */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "io_event.h"

char LICENSE[] SEC("license") = "GPL";

/* Per-CPU scratch avoids putting a large snapshot on the tiny BPF stack. */
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct vio_event);
} scratch SEC(".maps");

/* The loader drains this ring buffer and writes one NDJSON record per snapshot. */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Remember the VMM thread to its vcpu association so callbacks without a vcpu argument can recover it. */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct kvm_vcpu *);
} current_vcpu SEC(".maps");

/* Keep the capture focused on our toy VMM process. */
static __always_inline int is_vmm_comm(char comm[16])
{
	const char expected[4] = "vmm";

#pragma unroll
	for (int i = 0; i < 3; i++)
		if (comm[i] != expected[i])
			return 0;
	return comm[3] == '\0';
}

/* Remember the VMM thread to its vcpu association at entry so arg-less callbacks can recover it. */
static __always_inline void remember_vcpu(struct kvm_vcpu *vcpu)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&current_vcpu, &pid_tgid, &vcpu, BPF_ANY);
}

/* Recover the VMM thread's vcpu from the association map established at entry. */
static __always_inline struct kvm_vcpu *vcpu_from_map(void)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

	return vcpu ? *vcpu : NULL;
}

/* Fixed metadata for a snapshot taken from the owning vcpu. */
static __always_inline void snapshot_base(struct vio_event *event, struct kvm_vcpu *vcpu)
{
	unsigned char *bytes = (unsigned char *)event;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	/* Clear the shared scratch so stale fields from another event type never leak into this record. */
	/* Every callback then populates only the facts it actually observed for its boundary. */
#pragma unroll
	for (unsigned int i = 0; i < sizeof(*event); i++)
		bytes[i] = 0;

	bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
	if (!is_vmm_comm(event->context.comm))
		return;
	event->time_ns = bpf_ktime_get_ns();
	event->context.pid = (unsigned int)(pid_tgid >> 32);
	event->context.tid = (unsigned int)pid_tgid;
	event->context.cpu = bpf_get_smp_processor_id();
	event->state.vcpu = (__u64)vcpu;
	event->state.kvm = (__u64)BPF_CORE_READ(vcpu, kvm);
}

/* Best-effort read of one DEVICE_VECTOR bit in a LAPIC IRR/ISR field. */
static __always_inline __u8 lapic_pending_bit(const struct kvm_lapic *apic, __u32 base)
{
	const __u32 *regs = READ_KVM_LAPIC_REGS(apic);
	__u32 word = (base >> 2) + (DEVICE_VECTOR >> 5) * 4; /* The 32 vectors of a bank occupy four u32 slots. */
	__u32 bit = 1u << (DEVICE_VECTOR & 31);
	__u32 value = 0;

	if (!regs)
		return 0;
	bpf_probe_read_kernel(&value, sizeof(value), &regs[word]);
	return !!(value & bit);
}

/* Sample the LAPIC IRR/ISR bits through the vcpu's own lapic relationship. */
static __always_inline void sample_lapic(struct vio_event *event, struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu ? BPF_CORE_READ(vcpu, arch.apic) : NULL;

	event->state.apic = (__u64)apic;
	if (apic)
	{
		event->state.controller.irr = lapic_pending_bit(apic, 0x200u); /* The 0x200 offset is the LAPIC IRR base. */
		event->state.controller.isr = lapic_pending_bit(apic, 0x100u); /* The 0x100 offset is the LAPIC ISR base. */
	}
}

/* Emit one record into the shared ring buffer, sampling controller state. */
static __always_inline int emit_boundary(enum io_event_type event_type, struct kvm_vcpu *vcpu)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)event_type;
	sample_lapic(event, vcpu);
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

/* kvm_entry exposes the vcpu as its first raw-tracepoint argument and seeds the association map. */
SEC("raw_tp/kvm_entry")
int kvm_entry_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)ctx->args[0];

	remember_vcpu(vcpu);
	return emit_boundary(IO_EVENT_KVM_ENTRY, vcpu);
}

/* kvm_exit exposes the vcpu as its first raw-tracepoint argument. */
SEC("raw_tp/kvm_exit")
int kvm_exit_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_EXIT, (struct kvm_vcpu *)ctx->args[0]);
}

/* kvm_userspace_exit carries only a reason and errno, so the vcpu comes from the association map. */
SEC("raw_tp/kvm_userspace_exit")
int kvm_userspace_exit_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_USERSPACE_EXIT, vcpu_from_map());
}

/* kvm_apic_accept_irq carries only apicid/delivery/vector, so the vcpu comes from the association map. */
SEC("raw_tp/kvm_apic_accept_irq")
int kvm_apic_accept_irq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_APIC_ACCEPT_IRQ, vcpu_from_map());
}

/* kvm_inj_virq carries only a vector, so the vcpu comes from the association map. */
SEC("raw_tp/kvm_inj_virq")
int kvm_inj_virq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_INJ_VIRQ, vcpu_from_map());
}

/* kvm_ioapic_set_irq carries the RTE bits in its first argument, and the vcpu comes from the map. */
SEC("raw_tp/kvm_ioapic_set_irq")
int kvm_ioapic_set_irq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)IO_EVENT_KVM_IOAPIC_SET_IRQ;
	sample_lapic(event, vcpu);
	event->state.controller.rte = ctx->args[0];
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

/* kvm_eoi carries a vector with the vcpu from the association map. */
SEC("raw_tp/kvm_eoi")
int kvm_eoi_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_EOI, vcpu_from_map());
}

/* kvm_apic carries register access details without any controller pointer, so the vcpu comes from the map. */
SEC("raw_tp/kvm_apic")
int kvm_apic_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_APIC, vcpu_from_map());
}

/* The uprobe below samples the VMM's real virtual-DMA entry point through its normal ABI arguments. */
SEC("uprobe/build/vmm:device_dma_transfer")
int BPF_UPROBE(device_dma_transfer, void *dev, uint8_t *guest_mem_base, uint64_t guest_mem_size, uint32_t dir, uint64_t gpa, uint32_t len)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();

	/* The first parameter is the device object, and the backing facts are run constants. */
	(void)dev;
	(void)guest_mem_base;
	(void)guest_mem_size;
	(void)len;

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)IO_EVENT_DEVICE_DMA_TRANSFER;
	sample_lapic(event, vcpu);
	event->state.dma.gpa = gpa;
	event->state.dma.dir = dir;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}
