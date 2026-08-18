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
 */

#include "vmlinux.h"
#include "kvm_types.h"  /* Generated CO-RE KVM structs when KVM is a module. */
#include "kvm_compat.h" /* Generated: layout differences + the readers below. */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define DEVICE_VECTOR 0x40
#define DEVICE_GSI    4

/* One event -> one ring-buffer record, drained by io.c as NDJSON. */
struct irq_snapshot
{
    __u64 timestamp_ns;
    __u64 pid_tgid;
    __u64 vcpu;    /* struct kvm_vcpu * that owns this event */
    __u64 kvm;     /* owning struct kvm * */
    __u64 apic;    /* struct kvm_lapic *, when this tracepoint exposes one */
    __u64 ioapic;  /* struct kvm_ioapic *, when this tracepoint exposes one */
    char   comm[16];

    /* Controller state for DEVICE_VECTOR / DEVICE_GSI, best-effort. */
    __u32 rte_low;  /* IOAPIC redirection entry low 32 bits for DEVICE_GSI */
    __u32 rte_high; /* IOAPIC redirection entry high 32 bits for DEVICE_GSI */
    __u8  irr;      /* LAPIC IRR bit for DEVICE_VECTOR */
    __u8  isr;      /* LAPIC ISR bit for DEVICE_VECTOR */

    /* Upfrobed virtual-DMA operation (reliable, from real ABI args). */
    __u64 dma_guest_base; /* host userspace base backing the guest GPA */
    __u64 dma_gpa;        /* guest physical address targeted */
    __u32 dma_len;        /* transfer length (fixed DMA_XFER_SIZE) */
    __u32 dma_dir;        /* CMD_DMA_TO_DEVICE / CMD_DMA_FROM_DEVICE */
};

/* Per-CPU scratch avoids a large snapshot on the tiny BPF stack. */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct irq_snapshot);
} scratch SEC(".maps");

/*
 * One ring buffer per event.  With a shared buffer the record is anonymous and
 * we could only tell which tracepoint fired via a bookkeeping tag; instead the
 * loader (io.c) tags each buffer's name, so the record itself stays clean.
 */
#define IO_RINGBUF(name)                                   \
    struct                                                 \
    {                                                      \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                \
        __uint(max_entries, 1 << 20);                      \
    } name SEC(".maps")

IO_RINGBUF(events_entry);
IO_RINGBUF(events_exit);
IO_RINGBUF(events_userspace_exit);
IO_RINGBUF(events_ioapic_set_irq);
IO_RINGBUF(events_apic_accept_irq);
IO_RINGBUF(events_inj_virq);
IO_RINGBUF(events_eoi);
IO_RINGBUF(events_apic);
IO_RINGBUF(events_dma);

/* vmm thread -> its vcpu, so callbacks without a vcpu arg can recover it. */
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
static __always_inline void snapshot_base(struct irq_snapshot *s, struct kvm_vcpu *vcpu)
{
    s->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(s->comm, sizeof(s->comm));
    if (!is_vmm_comm(s->comm))
        return;
    s->pid_tgid = bpf_get_current_pid_tgid();
    s->vcpu = (__u64)vcpu;
    s->kvm = (__u64)BPF_CORE_READ(vcpu, kvm);
}

/* Best-effort read of one DEVICE_VECTOR bit in a LAPIC IRR/ISR field. */
static __always_inline __u8 lapic_pending_bit(const struct kvm_lapic *apic, __u32 base)
{
    const __u32 *regs = READ_KVM_LAPIC_REGS(apic);
    __u32 word = (base >> 2) + (DEVICE_VECTOR >> 5) * 4; /* 32 vectors occupy 4 u32 slots */
    __u32 bit = 1u << (DEVICE_VECTOR & 31);
    __u32 value = 0;

    if (!regs)
        return 0;
    bpf_probe_read_kernel(&value, sizeof(value), &regs[word]);
    return !!(value & bit);
}

/* Emit one record into a per-event ring buffer, sampling controller state. */
static __always_inline int emit_boundary(void *rb, struct kvm_vcpu *vcpu, const struct kvm_lapic *lapic, const struct kvm_ioapic *ioapic)
{
    __u32 zero = 0;
    struct irq_snapshot *s = bpf_map_lookup_elem(&scratch, &zero);

    if (!s || !vcpu)
        return 0;
    snapshot_base(s, vcpu);
    if (!is_vmm_comm(s->comm))
        return 0;

    s->apic = (__u64)lapic;
    s->ioapic = (__u64)ioapic;

    /* Controller state is surfaced only when the target exposes the readers. */
    if (ioapic && READ_KVM_IOAPIC_RTE_AVAILABLE) {
        __u64 rte = READ_KVM_IOAPIC_RTE(ioapic, DEVICE_GSI);

        s->rte_low = (__u32)rte;
        s->rte_high = (__u32)(rte >> 32);
    }
    if (lapic) {
        s->irr = lapic_pending_bit(lapic, 0x200u); /* LAPIC IRR base */
        s->isr = lapic_pending_bit(lapic, 0x100u); /* LAPIC ISR base */
    }

    bpf_ringbuf_output(rb, s, sizeof(*s), 0);
    return 0;
}

/* ---- events that expose the vcpu directly ---- */

SEC("raw_tp/kvm_entry")
int kvm_entry_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
    struct kvm_vcpu *vcpu = (struct kvm_vcpu *)ctx->args[0];
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if (vcpu)
        bpf_map_update_elem(&current_vcpu, &pid_tgid, &vcpu, BPF_ANY);
    return emit_boundary(&events_entry, vcpu, NULL, NULL);
}

SEC("raw_tp/kvm_exit")
int kvm_exit_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
    return emit_boundary(&events_exit, (struct kvm_vcpu *)ctx->args[0], NULL, NULL);
}

SEC("raw_tp/kvm_userspace_exit")
int kvm_userspace_exit_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
    return emit_boundary(&events_userspace_exit, (struct kvm_vcpu *)ctx->args[0], NULL, NULL);
}

SEC("raw_tp/kvm_apic_accept_irq")
int kvm_apic_accept_irq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
    return emit_boundary(&events_apic_accept_irq, (struct kvm_vcpu *)ctx->args[0], NULL, NULL);
}

SEC("raw_tp/kvm_inj_virq")
int kvm_inj_virq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
    return emit_boundary(&events_inj_virq, (struct kvm_vcpu *)ctx->args[0], NULL, NULL);
}

/* ---- kvm_ioapic_set_irq exposes the ioapic directly ---- */
SEC("raw_tp/kvm_ioapic_set_irq")
int kvm_ioapic_set_irq_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
    struct kvm_ioapic *ioapic = (struct kvm_ioapic *)ctx->args[0];
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

    if (!vcpu || !ioapic)
        return 0;
    return emit_boundary(&events_ioapic_set_irq, *vcpu, NULL, ioapic);
}

/* ---- kvm_eoi / kvm_apic expose the lapic directly ---- */
SEC("raw_tp/kvm_eoi")
int kvm_eoi_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
    struct kvm_lapic *apic = (struct kvm_lapic *)ctx->args[0];
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

    if (!vcpu || !apic)
        return 0;
    return emit_boundary(&events_eoi, *vcpu, apic, NULL);
}

SEC("raw_tp/kvm_apic")
int kvm_apic_snapshot(struct bpf_raw_tracepoint_args *ctx)
{
    struct kvm_lapic *apic = (struct kvm_lapic *)ctx->args[0];
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);

    if (!vcpu || !apic)
        return 0;
    return emit_boundary(&events_apic, *vcpu, apic, NULL);
}

/* ---- uprobe on the VMM's real virtual-DMA entry point ---- */
SEC("uprobe/device_dma_transfer")
int BPF_UPROBE(device_dma_transfer, uint8_t *guest_mem_base, uint64_t guest_mem_size, uint32_t dir, uint64_t gpa, uint32_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct kvm_vcpu **vcpu = bpf_map_lookup_elem(&current_vcpu, &pid_tgid);
    __u32 zero = 0;
    struct irq_snapshot *s = bpf_map_lookup_elem(&scratch, &zero);

    if (!s || !vcpu)
        return 0;
    snapshot_base(s, *vcpu);
    if (!is_vmm_comm(s->comm))
        return 0;

    s->dma_guest_base = (__u64)guest_mem_base;
    s->dma_gpa = gpa;
    s->dma_len = len;
    s->dma_dir = dir;
    bpf_ringbuf_output(&events_dma, s, sizeof(*s), 0);
    return 0;
}
