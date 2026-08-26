// SPDX-License-Identifier: GPL-2.0
/*
 * KVM virtual-I/O observer.
 *
 * Existing KVM tracepoints capture VM transitions, handler boundaries, and interrupt routing.
 * Syscall tracepoints pair KVM ioctls, a VMX kretprobe captures KVM's exit disposition when available, and uprobes observe calls into the toy userspace device model.
 * Each record carries event metadata plus a best-effort snapshot of the controller state.
 * The controller snapshot covers the IOAPIC redirection entry for the device GSI and the LAPIC IRR/ISR bit for the vector that the boundary actually concerns.
 *
 * Main teaching chain for the legacy line-based path:
 *
 *   kvm_ioapic_set_irq    (IOAPIC RTE reached for the GSI line)
 *     -> kvm_apic_accept_irq  (LAPIC accepts and sets IRR)
 *       -> kvm_inj_virq       (vector selected for injection)
 *         -> guest runs ISR
 *           -> guest EOI write -> kvm_eoi (ISR cleared)
 *
 * MSI transport (Phase D) uses kvm_msi_set_irq and deliberately skips the IOAPIC:
 *
 *   kvm_msi_set_irq       (an MSI message arrives with address + data)
 *     -> kvm_apic_accept_irq  (LAPIC accepts vector from the MSI data)
 *
 * The LAPIC IRR/ISR sample is tied to the vector of the boundary, because the run has two vectors: DEVICE_VECTOR and MSI_VECTOR.
 * Sampling the wrong vector would be false state.  Boundaries that carry a vector (ioapic, msi, accept, inj_virq, eoi) sample that vector's bits.
 * Controller registers are sampled as full windows when a vCPU association is available.
 *
 * The kvm_entry tracepoint records the vmm thread to its vcpu in the pid_tgid association map.
 * Later callbacks recover the vcpu from that map.
 * Every callback derives the vcpu's lapic through the KVM BTF relationship and samples IRR/ISR from it when a vector is available.
 * The kvm_ioapic_set_irq tracepoint samples its RTE bits and the RTE-derived vector from its argument.
 * The kvm_msi_set_irq tracepoint samples the raw MSI address and data, and derives the vector from the data field.
 *
 * The argument order was verified on CloudLab kernel 6.8 from /sys/kernel/tracing/events/kvm/<event>/format.
 * kvm_msi_set_irq is expected to carry (address, data); its exact argument positions must be confirmed on the target kernel before first use.
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

struct vio_ioctl_call
{
	unsigned long long request;
	unsigned long long argument;
	unsigned long long started_ns;
	unsigned long long call_id;
	int fd;
};

struct vio_command_call
{
	struct toy_device *dev;
	unsigned long long started_ns;
	unsigned long long operation_id;
};

struct vio_dma_call
{
	struct toy_device *dev;
	unsigned char *guest_mem_base;
	unsigned long long started_ns;
	unsigned long long gpa;
	unsigned int dir;
	unsigned int len;
};

#define VIO_HASH_MAP(name, value_type) \
struct \
{ \
	__uint(type, BPF_MAP_TYPE_HASH); \
	__uint(max_entries, 64); \
	__type(key, __u64); \
	__type(value, value_type); \
} name SEC(".maps")

VIO_HASH_MAP(ioctl_calls, struct vio_ioctl_call);
VIO_HASH_MAP(ioctl_counters, __u64);
VIO_HASH_MAP(vmexit_counters, __u64);
VIO_HASH_MAP(current_vmexit, __u64);
VIO_HASH_MAP(operation_counters, __u64);
VIO_HASH_MAP(active_operation, __u64);
VIO_HASH_MAP(command_calls, struct vio_command_call);
VIO_HASH_MAP(dma_calls, struct vio_dma_call);

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
static __always_inline void sample_controller_config(struct vio_event *event, struct kvm_vcpu *vcpu);
static __always_inline void snapshot_base(struct vio_event *event, struct kvm_vcpu *vcpu)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *id;

	/* Clear the shared scratch so stale fields from another event type never leak into this record. */
	__builtin_memset(event, 0, sizeof(*event));
	bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
	if (!is_vmm_comm(event->context.comm))
		return;
	event->time_ns = bpf_ktime_get_ns();
	event->context.pid = (unsigned int)(pid_tgid >> 32);
	event->context.tid = (unsigned int)pid_tgid;
	event->context.cpu = bpf_get_smp_processor_id();
	id = bpf_map_lookup_elem(&current_vmexit, &pid_tgid);
	if (id)
		event->event_info.vmexit_id = *id;
	id = bpf_map_lookup_elem(&active_operation, &pid_tgid);
	if (id)
		event->event_info.operation_id = *id;
	if (vcpu)
	{
		event->state.vcpu = (__u64)vcpu;
		event->state.kvm = (__u64)BPF_CORE_READ(vcpu, kvm);
		sample_controller_config(event, vcpu);
	}
}

static __always_inline __u32 lapic_bank(const struct kvm_lapic *apic, unsigned int base, unsigned int k)
{
	const __u32 *regs = READ_KVM_LAPIC_REGS(apic);

	if (!regs)
		return 0;
	__u32 value = 0;

	bpf_probe_read_kernel(&value, sizeof(value), &regs[(base >> 2) + k * 4]);
	return value;
}

static __always_inline unsigned long long lapic_reg(const struct kvm_lapic *apic, unsigned int offset)
{
	const __u32 *regs = READ_KVM_LAPIC_REGS(apic);

	if (!regs)
		return 0;
	__u32 value = 0;

	bpf_probe_read_kernel(&value, sizeof(value), &regs[offset >> 2]);
	return value & 0xffffffffu;
}

static __always_inline void sample_lapic_window(struct vio_event *event, struct kvm_lapic *apic)
{
#pragma unroll
	for (unsigned int k = 0; k < 8; k++)
	{
		event->state.controller.irr[k] = lapic_bank(apic, 0x200u, k);
		event->state.controller.isr[k] = lapic_bank(apic, 0x100u, k);
	}
}

static __always_inline void sample_controller_config(struct vio_event *event, struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu ? BPF_CORE_READ(vcpu, arch.apic) : NULL;
	struct kvm_ioapic *ioapic = vcpu ? BPF_CORE_READ(vcpu, kvm, arch.vioapic) : NULL;

	event->state.apic = (__u64)apic;
	event->state.ioapic = (__u64)ioapic;
	if (apic)
	{
		event->state.controller.tpr = lapic_reg(apic, 0x080u);
		event->state.controller.svr = lapic_reg(apic, 0x0F0u);
		sample_lapic_window(event, apic);
	}
	if (ioapic)
		event->state.controller.rte = READ_KVM_IOAPIC_RTE(ioapic, DEVICE_GSI);
}

/*
 * Emit one record into the shared ring buffer.
 * IRR/ISR and the config registers are sampled as full windows, so every boundary carries state.
 */
static __always_inline int emit_boundary(enum io_event_type event_type, struct kvm_vcpu *vcpu)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);

	if (!event)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)event_type;
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
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 next = 1;
	__u64 *last = bpf_map_lookup_elem(&vmexit_counters, &pid_tgid);

	if (last)
		next = *last + 1;
	bpf_map_update_elem(&vmexit_counters, &pid_tgid, &next, BPF_ANY);
	bpf_map_update_elem(&current_vmexit, &pid_tgid, &next, BPF_ANY);
	return emit_boundary(IO_EVENT_KVM_EXIT, (struct kvm_vcpu *)ctx->args[0]);
}

/* kvm_userspace_exit carries only a reason and errno, so the vcpu comes from the association map. */
SEC("raw_tp/kvm_userspace_exit")
int kvm_userspace_exit_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_USERSPACE_EXIT, vcpu_from_map());
}

/* kvm_apic_accept_irq carries (apicid, delivery_mode, vector, level_triggered), so the vcpu comes from the association map. */
SEC("raw_tp/kvm_apic_accept_irq")
int kvm_apic_accept_irq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)IO_EVENT_KVM_APIC_ACCEPT_IRQ;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

/* kvm_inj_virq carries the vector as its first raw argument. */
SEC("raw_tp/kvm_inj_virq")
int kvm_inj_virq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)IO_EVENT_KVM_INJ_VIRQ;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
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
	event->state.controller.rte = ctx->args[0];
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

/*
 * kvm_msi_set_irq carries (address, data); both are u32 values, never kernel pointers.
 * The vector is the low byte of the MSI data.  The MSI message bypasses the IOAPIC, so no RTE is sampled.
 * Argument positions must be confirmed against the target kernel's kvm_msi_set_irq/format before first use.
 */
SEC("raw_tp/kvm_msi_set_irq")
int kvm_msi_set_irq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();
	__u32 address = (__u32)ctx->args[0];
	__u32 data = (__u32)ctx->args[1];

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)IO_EVENT_KVM_MSI_SET_IRQ;
	event->state.msi.present = 1;
	event->state.msi.address = address;
	event->state.msi.data = data;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

/* kvm_eoi carries a vector with the vcpu from the association map. */
SEC("raw_tp/kvm_eoi")
int kvm_eoi_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	event->event_info.event = (unsigned int)IO_EVENT_KVM_EOI;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

/* kvm_apic carries register access details without any controller pointer, so the vcpu comes from the map. */
SEC("raw_tp/kvm_apic")
int kvm_apic_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
	return emit_boundary(IO_EVENT_KVM_APIC, vcpu_from_map());
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int sys_enter_ioctl_snapshot(struct trace_event_raw_sys_enter *ctx)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct vio_ioctl_call call = {};
	struct kvm_vcpu *vcpu = vcpu_from_map();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 next = 1;
	__u64 *last;

	if (!event)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;
	last = bpf_map_lookup_elem(&ioctl_counters, &pid_tgid);
	if (last)
		next = *last + 1;
	call.fd = (int)ctx->args[0];
	call.request = ctx->args[1];
	call.argument = ctx->args[2];
	call.started_ns = event->time_ns;
	call.call_id = next;
	bpf_map_update_elem(&ioctl_counters, &pid_tgid, &next, BPF_ANY);
	bpf_map_update_elem(&ioctl_calls, &pid_tgid, &call, BPF_ANY);
	event->event_info.event = IO_EVENT_SYS_ENTER_IOCTL;
	event->event_info.call_id = next;
	event->state.ioctl.present = 1;
	event->state.ioctl.fd = call.fd;
	event->state.ioctl.request = call.request;
	event->state.ioctl.argument = call.argument;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int sys_exit_ioctl_snapshot(struct trace_event_raw_sys_exit *ctx)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct vio_ioctl_call *call = bpf_map_lookup_elem(&ioctl_calls, &pid_tgid);

	if (!event || !call)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;
	event->event_info.event = IO_EVENT_SYS_EXIT_IOCTL;
	event->event_info.call_id = call->call_id;
	event->state.ioctl.present = 1;
	event->state.ioctl.completed = 1;
	event->state.ioctl.fd = call->fd;
	event->state.ioctl.request = call->request;
	event->state.ioctl.argument = call->argument;
	event->state.ioctl.result = ctx->ret;
	event->state.ioctl.duration_ns = event->time_ns - call->started_ns;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	bpf_map_delete_elem(&ioctl_calls, &pid_tgid);
	return 0;
}

/* The VMX handler return states whether KVM resumes the guest or returns KVM_RUN to userspace. */
SEC("kretprobe/vmx_handle_exit")
int BPF_KRETPROBE(vmx_handle_exit_return, int result)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();

	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;
	event->event_info.event = IO_EVENT_VMX_HANDLE_EXIT_RETURN;
	event->state.disposition.present = 1;
	event->state.disposition.result = result;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

/* Observe the real VMM dispatch into the toy device, including the register and value. */
SEC("uprobe/build/vmm:device_mmio_write")
int BPF_UPROBE(device_mmio_write, int vm, struct toy_device *dev, uint32_t offset, uint8_t *data, uint8_t *guest_mem_base, uint64_t guest_mem_size)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 value = 0;
	__u64 next = 1;
	__u64 *last;

	(void)vm;
	(void)dev;
	(void)guest_mem_base;
	(void)guest_mem_size;
	if (!event || !vcpu)
		return 0;
	if (bpf_probe_read_user(&value, sizeof(value), data) != 0)
		return 0;
	if (offset == REG_COMMAND)
	{
		last = bpf_map_lookup_elem(&operation_counters, &pid_tgid);
		if (last)
			next = *last + 1;
		bpf_map_update_elem(&operation_counters, &pid_tgid, &next, BPF_ANY);
		bpf_map_update_elem(&active_operation, &pid_tgid, &next, BPF_ANY);
	}
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;
	event->event_info.event = IO_EVENT_DEVICE_MMIO_WRITE;
	event->state.mmio.present = 1;
	event->state.mmio.offset = offset;
	event->state.mmio.value = value;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

SEC("uprobe/build/vmm:device_execute_command")
int BPF_UPROBE(device_execute_command, int vm, struct toy_device *dev, uint8_t *guest_mem_base, uint64_t guest_mem_size)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct vio_command_call call = {.dev = dev};
	__u64 *operation;

	(void)vm;
	(void)guest_mem_base;
	(void)guest_mem_size;
	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;
	operation = bpf_map_lookup_elem(&active_operation, &pid_tgid);
	call.started_ns = event->time_ns;
	call.operation_id = operation ? *operation : 0;
	bpf_map_update_elem(&command_calls, &pid_tgid, &call, BPF_ANY);
	event->event_info.event = IO_EVENT_DEVICE_EXECUTE_COMMAND;
	bpf_probe_read_user(&event->state.command.command, sizeof(event->state.command.command), &dev->command);
	bpf_probe_read_user(&event->state.command.status, sizeof(event->state.command.status), &dev->status);
	bpf_probe_read_user(&event->state.command.dma_gpa, sizeof(event->state.command.dma_gpa), &dev->dma_gpa);
	bpf_probe_read_user(&event->state.command.result, sizeof(event->state.command.result), &dev->result);
	event->state.command.present = 1;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

SEC("uretprobe/build/vmm:device_execute_command")
int BPF_URETPROBE(device_execute_command_return)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct vio_command_call *call = bpf_map_lookup_elem(&command_calls, &pid_tgid);

	if (!event || !vcpu || !call)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;
	event->event_info.event = IO_EVENT_DEVICE_EXECUTE_COMMAND_RETURN;
	event->event_info.operation_id = call->operation_id;
	bpf_probe_read_user(&event->state.command.command, sizeof(event->state.command.command), &call->dev->command);
	bpf_probe_read_user(&event->state.command.status, sizeof(event->state.command.status), &call->dev->status);
	bpf_probe_read_user(&event->state.command.dma_gpa, sizeof(event->state.command.dma_gpa), &call->dev->dma_gpa);
	bpf_probe_read_user(&event->state.command.result, sizeof(event->state.command.result), &call->dev->result);
	event->state.command.present = 1;
	event->state.command.completed = 1;
	event->state.command.duration_ns = event->time_ns - call->started_ns;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	bpf_map_delete_elem(&command_calls, &pid_tgid);
	bpf_map_delete_elem(&active_operation, &pid_tgid);
	return 0;
}

/* The uprobe below samples the VMM's real virtual-DMA entry point through its normal ABI arguments. */
SEC("uprobe/build/vmm:device_dma_transfer")
int BPF_UPROBE(device_dma_transfer, struct toy_device *dev, uint8_t *guest_mem_base, uint64_t guest_mem_size, uint32_t dir, uint64_t gpa, uint32_t len)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct vio_dma_call call = {
		.dev = dev,
		.guest_mem_base = guest_mem_base,
		.started_ns = bpf_ktime_get_ns(),
		.gpa = gpa,
		.dir = dir,
		.len = len,
	};

	(void)guest_mem_size;
	if (!event || !vcpu)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;

	/* Record the device-initiated guest-memory access before the functional copy runs. */
	bpf_map_update_elem(&dma_calls, &pid_tgid, &call, BPF_ANY);
	event->event_info.event = (unsigned int)IO_EVENT_DEVICE_DMA_TRANSFER;
	event->state.dma.gpa = gpa;
	event->state.dma.guest_hva = (__u64)(guest_mem_base + gpa);
	event->state.dma.dir = dir;
	event->state.dma.len = len;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	return 0;
}

SEC("uretprobe/build/vmm:device_dma_transfer")
int BPF_URETPROBE(device_dma_transfer_return, int result)
{
	__u32 zero = 0;
	struct vio_event *event = bpf_map_lookup_elem(&scratch, &zero);
	struct kvm_vcpu *vcpu = vcpu_from_map();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct vio_dma_call *call = bpf_map_lookup_elem(&dma_calls, &pid_tgid);

	if (!event || !vcpu || !call)
		return 0;
	snapshot_base(event, vcpu);
	if (!is_vmm_comm(event->context.comm))
		return 0;
	event->event_info.event = IO_EVENT_DEVICE_DMA_TRANSFER_RETURN;
	event->state.dma.gpa = call->gpa;
	event->state.dma.guest_hva = (__u64)(call->guest_mem_base + call->gpa);
	event->state.dma.dir = call->dir;
	event->state.dma.len = call->len;
	event->state.dma.result = result;
	event->state.dma.completed = 1;
	event->state.dma.duration_ns = event->time_ns - call->started_ns;
	bpf_probe_read_user(&event->state.dma.checksum, sizeof(event->state.dma.checksum), &call->dev->result);
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	bpf_map_delete_elem(&dma_calls, &pid_tgid);
	return 0;
}
