// SPDX-License-Identifier: GPL-2.0
/*
 * Interrupt-virtualization observer.
 *
 * Snapshots KVM interrupt-controller state at the same events the UI
 * renders, mirroring the EPT observer's philosophy: each record carries event
 * metadata plus a best-effort snapshot of the relevant controller state
 * (IOAPIC RTE for the device GSI, LAPIC IRR/ISR bit for the device vector).
 *
 * Main teaching chain:
 *
 *   kvm_ioapic_set_irq    (IOAPIC RTE -> GSI line)
 *     -> kvm_apic_accept_irq  (LAPIC accepts: IRR set)
 *       -> kvm_inj_virq       (vector selected for injection)
 *         -> guest runs ISR
 *           -> guest EOI write -> kvm_eoi (ISR cleared)
 *
 * Association: raw_tp/kvm_entry records vmm-thread -> vcpu in a pid_tgid map;
 * later callbacks recover the vcpu from it, except when the tracepoint already
 * hands us a stronger pointer (lapic / ioapic), which we prefer.
 *
 * VERIFY ON CLOUDLAB: raw-tracepoint argument order and the KVM internal layout
 * used by the IRR/ISR/RTE reads must be confirmed against the target kernel's
 * source, /sys/kernel/tracing/events/kvm/<event>/format, and module BTF.  The
 * Makefile generates kvm_types.h / kvm_compat.h from that BTF (EPT pattern) and
 * defines READ_KVM_LAPIC_REGS / READ_KVM_IOAPIC_RTE.  Until those reads are
 * confirmed, the controller-state fields stay zero and the UI shows them as
 * "not sampled" -- never fake.
 *
 * The shared ABI in io_event.h owns the record layout, grouped into
 * event_info / context / state.  This file only fills that ABI and never
 * decides JSON shape.
 *
 * Every tracepoint fills one shared ring buffer, and the event type rides in
 * the record itself.  The loader therefore needs no separate event tag.
 */
#include "vmlinux.h"
#include "kvm_types.h"	/* Generated CO-RE KVM structs when KVM is a module. */
#include "kvm_compat.h" /* Generated: layout differences + the readers below. */
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

/* Fixed metadata for a snapshot taken from the owning vcpu. */
static __always_inline void snapshot_base(struct vio_event *event, struct kvm_vcpu *vcpu)
{
	__u64 pid_tgid;

	bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
	if (!is_vmm_comm(event->context.comm))
		return;
	pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&current_vcpu, &pid_tgid, &vcpu, BPF_ANY);
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

/* Emit one record into the shared ring buffer, sampling controller state. */
static __always_inline int emit_boundary(enum io_event_type event_type, struct kvm_vcpu *vcpu, const struct kvm_lapic *lapic, const struct kvm_ioapic *ioapic)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)event_type;
	event->state.apic = (__u64)lapic;
	event->state.ioapic = (__u64)ioapic;

	/* Controller state is surfaced only when the target exposes the readers. */
	if (ioapic && READ_KVM_IOAPIC_RTE_AVAILABLE)
		event->state.controller.rte = READ_KVM_IOAPIC_RTE(ioapic, DEVICE_GSI);
	if (lapic)
	{
		event->state.controller.irr = lapic_pending_bit(lapic, 0x200u); /* LAPIC IRR base */
		event->state.controller.isr = lapic_pending_bit(lapic, 0x100u); /* LAPIC ISR base */
	}

	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

/* The events below expose the vcpu directly as their first raw-tracepoint argument. */

SEC("raw_tp/kvm_entry")
int kvm_entry_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_ENTRY, (struct kvm_vcpu *)ctx->args[0], NULL, NULL);
}

SEC("raw_tp/kvm_exit")
int kvm_exit_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_EXIT, (struct kvm_vcpu *)ctx->args[0], NULL, NULL);
}

SEC("raw_tp/kvm_userspace_exit")
int kvm_userspace_exit_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_USERSPACE_EXIT, (struct kvm_vcpu *)ctx->args[0], NULL, NULL);
}

SEC("raw_tp/kvm_apic_accept_irq")
int kvm_apic_accept_irq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_APIC_ACCEPT_IRQ, (struct kvm_vcpu *)ctx->args[0], NULL, NULL);
}

SEC("raw_tp/kvm_inj_virq")
int kvm_inj_virq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_INJ_VIRQ, (struct kvm_vcpu *)ctx->args[0], NULL, NULL);
}

/* kvm_ioapic_set_irq exposes the ioapic directly but needs the vcpu from the association map. */
SEC("raw_tp/kvm_ioapic_set_irq")
int kvm_ioapic_set_irq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	struct kvm_ioapic *ioapic = (struct kvm_ioapic *)ctx->args[0];
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

	if (!vcpu || !ioapic)
		return 0;
	return emit_boundary(IO_EVENT_KVM_IOAPIC_SET_IRQ, *vcpu, NULL, ioapic);
}

/* kvm_eoi and kvm_apic expose the lapic directly but need the vcpu from the association map. */
SEC("raw_tp/kvm_eoi")
int kvm_eoi_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	struct kvm_lapic *apic = (struct kvm_lapic *)ctx->args[0];
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

	if (!vcpu || !apic)
		return 0;
	return emit_boundary(IO_EVENT_KVM_EOI, *vcpu, apic, NULL);
}

SEC("raw_tp/kvm_apic")
int kvm_apic_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	struct kvm_lapic *apic = (struct kvm_lapic *)ctx->args[0];
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

	if (!vcpu || !apic)
		return 0;
	return emit_boundary(IO_EVENT_KVM_APIC, *vcpu, apic, NULL);
}

/* The uprobe below samples the VMM's real virtual-DMA entry point through its normal ABI arguments. */
SEC("uprobe/build/vmm:device_dma_transfer")
int BPF_UPROBE(device_dma_transfer, uint8_t *guest_mem_base, uint64_t guest_mem_size, uint32_t dir, uint64_t gpa, uint32_t len)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);

	/* The backing base, backing size, and transfer length are run constants that live in the meta record. */
	(void)guest_mem_base;
	(void)guest_mem_size;
	(void)len;

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, *vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)IO_EVENT_DEVICE_DMA_TRANSFER;
	event->state.dma.gpa = gpa;
	event->state.dma.dir = dir;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}
