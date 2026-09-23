/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "observer_bpf.h"
#include <bpf/bpf_tracing.h>

#include "vtd_event.h"

/* These x86 ioctl values are resolved from the target UAPI headers. */
#define VFIO_IOMMU_MAP_DMA 0x3b71
#define VFIO_IOMMU_UNMAP_DMA 0x3b72
#define VFIO_DEVICE_SET_IRQS 0x3b6e
#define KVM_SET_USER_MEMORY_REGION 0x4020ae46
#define KVM_SET_USER_MEMORY_REGION2 0x40a0ae49

char LICENSE[] SEC("license") = "GPL";

struct vfio_dma_map_request {
    __u32 argsz;
    __u32 flags;
    __u64 vaddr;
    __u64 iova;
    __u64 size;
};

struct vfio_dma_unmap_request {
    __u32 argsz;
    __u32 flags;
    __u64 iova;
    __u64 size;
};

struct vfio_irq_set_request {
    __u32 argsz;
    __u32 flags;
    __u32 index;
    __u32 start;
    __u32 count;
};

struct kvm_memory_region_request {
    __u32 slot;
    __u32 flags;
    __u64 guest_phys_addr;
    __u64 memory_size;
    __u64 userspace_addr;
};

struct trace_event_raw_iommu_map {
    __u8 common[8];
    __u64 iova;
    __u64 paddr;
    __u64 size;
};

struct trace_event_raw_iommu_unmap {
    __u8 common[8];
    __u64 iova;
    __u64 size;
    __u64 unmapped_size;
};

struct trace_event_raw_iommu_attach_device_to_domain {
    __u8 common[8];
    __u32 device_loc;
};

struct active_operation {
    __u32 operation;
    __u32 fd;
    __u32 flags;
    __u32 argsz;
    __u32 slot;
    __u32 sample_status;
    __u64 command;
    __u64 request_id;
    __u64 user_argument;
    __u64 hva;
    __u64 gpa;
    __u64 iova;
    __u64 size;
    __u32 irq_index;
    __u32 irq_start;
    __u32 irq_count;
};

/* Host probes share this record while a kernel call crosses entry and return. */
struct host_pending {
    __u32 virq;
    __u32 irq;
    __u32 irq_count;
    __u64 message;
    __u64 domain_address;
    __u64 iommu_address;
    __u32 iommu_id;
    __u32 qi_count;
    __u32 qi_options;
    __u64 descriptor_0;
    __u64 descriptor_1;
};

/* Guest DMA and IRQ probes share one short-lived execution record. */
struct guest_pending {
    __u32 direction;
    __u32 irq;
    __u64 size;
    __u64 episode_id;
    __u32 phase;
    char action[VTD_ACTION_NAME_LEN];
};

struct guest_control {
    __u64 episode_counter;
    __u64 once;
    __u32 phase;
    __u32 active;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct active_operation);
} active_operations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, struct host_pending);
} host_pending_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct guest_pending);
} guest_pending_states SEC(".maps");

const volatile char target_interface[VTD_COMM_LEN];

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} request_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct guest_control);
} guest_control SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int current_process_is_qemu(void)
{
    char comm[VTD_COMM_LEN] = {};

    bpf_get_current_comm(comm, sizeof(comm));
    return comm[0] == 'q' && comm[1] == 'e' && comm[2] == 'm' && comm[3] == 'u';
}

static __always_inline __u64 next_request_id(void)
{
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&request_counter, &key);

    if (!counter)
        return bpf_ktime_get_ns();
    return __sync_fetch_and_add(counter, 1) + 1;
}

static __always_inline void count_drop(void)
{
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&dropped_events, &key);

    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline __u32 current_guest_phase(void);

static __always_inline struct vtd_event *reserve_event(unsigned int kind)
{
    struct vtd_event *event;
    __u64 pid_tgid;

    if (!current_process_is_qemu())
        return 0;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    event->time_ns = bpf_ktime_get_ns();
    event->event_info.kind = kind;
    event->state.guest_phase = current_guest_phase();
    event->context.pid = pid_tgid >> 32;
    event->context.tid = (__u32)pid_tgid;
    event->context.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
    return event;
}

static __always_inline struct vtd_event *reserve_unfiltered_event(unsigned int kind)
{
    struct vtd_event *event;
    __u64 pid_tgid;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    event->time_ns = bpf_ktime_get_ns();
    event->event_info.kind = kind;
    event->state.guest_phase = current_guest_phase();
    event->context.pid = pid_tgid >> 32;
    event->context.tid = (__u32)pid_tgid;
    event->context.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
    return event;
}

static __always_inline int claim_guest_once(unsigned int bit)
{
    __u32 key = 0;
    __u64 mask = 1ULL << bit;
    struct guest_control *control = bpf_map_lookup_elem(&guest_control, &key);

    if (!control)
        return 0;
    return !(__sync_fetch_and_or(&control->once, mask) & mask);
}

static __always_inline int guest_loopback_is_active(void)
{
    __u32 key = 0;
    struct guest_control *control = bpf_map_lookup_elem(&guest_control, &key);

    return control && control->active;
}

static __always_inline int guest_irq_name_matches(const char *name)
{
#pragma unroll
    for (int index = 0; index < VTD_COMM_LEN; index++) {
        if (!target_interface[index])
            return index > 0;
        if (name[index] != target_interface[index])
            return 0;
    }
    return 1;
}

static __always_inline __u32 current_guest_phase(void)
{
    __u32 key = 0;
    struct guest_control *control = bpf_map_lookup_elem(&guest_control, &key);

    return control ? control->phase : VTD_GUEST_PHASE_NONE;
}

static __always_inline void set_guest_phase(__u32 phase)
{
    __u32 key = 0;

    struct guest_control *control = bpf_map_lookup_elem(&guest_control, &key);

    if (control)
        control->phase = phase;
}

static __always_inline __u64 next_guest_episode(void)
{
    __u32 key = 0;
    struct guest_control *control = bpf_map_lookup_elem(&guest_control, &key);

    return control ? __sync_fetch_and_add(&control->episode_counter, 1) + 1 : bpf_ktime_get_ns();
}

static __always_inline void copy_guest_episode(struct vtd_event *event, const struct guest_pending *state)
{
    event->state.episode_id = state->episode_id;
    event->state.guest_phase = state->phase;
    event->state.irq = state->irq;
    __builtin_memcpy(event->state.action, state->action, sizeof(event->state.action));
}

static __always_inline void copy_operation(struct vtd_event *event, const struct active_operation *operation)
{
    event->event_info.operation = operation->operation;
    event->event_info.fd = operation->fd;
    event->event_info.flags = operation->flags;
    event->event_info.argsz = operation->argsz;
    event->event_info.slot = operation->slot;
    event->event_info.command = operation->command;
    event->event_info.request_id = operation->request_id;
    event->event_info.sample_status = operation->sample_status;
    event->state.user_argument = operation->user_argument;
    event->state.hva = operation->hva;
    event->state.gpa = operation->gpa;
    event->state.iova = operation->iova;
    event->state.size = operation->size;
    event->state.irq_index = operation->irq_index;
    event->state.irq_start = operation->irq_start;
    event->state.irq_count = operation->irq_count;
}

static __always_inline int is_tracked_ioctl(__u64 command)
{
    return command == VFIO_IOMMU_MAP_DMA || command == VFIO_IOMMU_UNMAP_DMA || command == VFIO_DEVICE_SET_IRQS ||
        command == KVM_SET_USER_MEMORY_REGION || command == KVM_SET_USER_MEMORY_REGION2;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int enter_ioctl(struct trace_event_raw_sys_enter *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation operation = {};
    struct vfio_dma_map_request map_request = {};
    struct vfio_dma_unmap_request unmap_request = {};
    struct vfio_irq_set_request irq_request = {};
    struct kvm_memory_region_request memory_request = {};
    struct vtd_event *event;

    /* Pair selected QEMU KVM/VFIO ioctls with their return and nested IOMMU events. */
    if (!current_process_is_qemu() || !is_tracked_ioctl(context->args[1]))
        return 0;
    operation.fd = context->args[0];
    operation.command = context->args[1];
    operation.user_argument = context->args[2];
    operation.request_id = next_request_id();
    if (operation.command == VFIO_IOMMU_MAP_DMA) {
        operation.operation = VTD_OP_VFIO_MAP;
        if (bpf_probe_read_user(&map_request, sizeof(map_request), (void *)operation.user_argument)) {
            operation.sample_status = VTD_SAMPLE_READ_FAILED;
        } else {
            operation.argsz = map_request.argsz;
            operation.flags = map_request.flags;
            operation.hva = map_request.vaddr;
            operation.iova = map_request.iova;
            operation.size = map_request.size;
            if (map_request.argsz < sizeof(map_request))
                operation.sample_status = VTD_SAMPLE_INVALID_ARGUMENT;
        }
    } else if (operation.command == VFIO_IOMMU_UNMAP_DMA) {
        operation.operation = VTD_OP_VFIO_UNMAP;
        if (bpf_probe_read_user(&unmap_request, sizeof(unmap_request), (void *)operation.user_argument)) {
            operation.sample_status = VTD_SAMPLE_READ_FAILED;
        } else {
            operation.argsz = unmap_request.argsz;
            operation.flags = unmap_request.flags;
            operation.iova = unmap_request.iova;
            operation.size = unmap_request.size;
            if (unmap_request.argsz < sizeof(unmap_request))
                operation.sample_status = VTD_SAMPLE_INVALID_ARGUMENT;
        }
    } else if (operation.command == VFIO_DEVICE_SET_IRQS) {
        operation.operation = VTD_OP_VFIO_IRQ_SET;
        if (bpf_probe_read_user(&irq_request, sizeof(irq_request), (void *)operation.user_argument)) {
            operation.sample_status = VTD_SAMPLE_READ_FAILED;
        } else {
            operation.argsz = irq_request.argsz;
            operation.flags = irq_request.flags;
            operation.irq_index = irq_request.index;
            operation.irq_start = irq_request.start;
            operation.irq_count = irq_request.count;
            if (irq_request.argsz < sizeof(irq_request))
                operation.sample_status = VTD_SAMPLE_INVALID_ARGUMENT;
        }
    } else {
        operation.operation = VTD_OP_KVM_MEMORY_REGION;
        if (bpf_probe_read_user(&memory_request, sizeof(memory_request), (void *)operation.user_argument)) {
            operation.sample_status = VTD_SAMPLE_READ_FAILED;
        } else {
            operation.flags = memory_request.flags;
            operation.slot = memory_request.slot;
            operation.gpa = memory_request.guest_phys_addr;
            operation.hva = memory_request.userspace_addr;
            operation.size = memory_request.memory_size;
        }
    }
    lab_map_update(&active_operations, &key, &operation, BPF_ANY);

    event = reserve_event(VTD_EVENT_IOCTL_ENTER);
    if (!event)
        return 0;
    copy_operation(event, &operation);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int exit_ioctl(struct trace_event_raw_sys_exit *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vfio_dma_unmap_request returned_unmap = {};
    struct vtd_event *event;

    if (!operation)
        return 0;
    event = reserve_event(VTD_EVENT_IOCTL_EXIT);
    if (event) {
        copy_operation(event, operation);
        event->event_info.result = context->ret;
        if (operation->operation == VTD_OP_VFIO_UNMAP && !context->ret &&
            !bpf_probe_read_user(&returned_unmap, sizeof(returned_unmap), (void *)operation->user_argument))
            event->state.returned_size = returned_unmap.size;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&active_operations, &key);
    return 0;
}

SEC("tracepoint/iommu/map")
int iommu_map(struct trace_event_raw_iommu_map *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    /* Keep only leaf installs made during this thread's active VFIO map request. */
    if (!operation || operation->operation != VTD_OP_VFIO_MAP || operation->sample_status != VTD_SAMPLE_COMPLETE)
        return 0;
    if (context->iova < operation->iova || context->size > operation->size ||
        context->iova - operation->iova > operation->size - context->size)
        return 0;
    event = reserve_event(VTD_EVENT_IOMMU_MAP);
    if (!event)
        return 0;
    copy_operation(event, operation);
    event->state.iova = context->iova;
    event->state.hpa = context->paddr;
    event->state.size = context->size;
    event->state.parent_iova = operation->iova;
    event->state.parent_size = operation->size;
    event->event_info.correlated = 1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/iommu/unmap")
int iommu_unmap(struct trace_event_raw_iommu_unmap *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    if (!operation || operation->operation != VTD_OP_VFIO_UNMAP || operation->sample_status != VTD_SAMPLE_COMPLETE)
        return 0;
    if (!(operation->flags & 2) && (context->iova < operation->iova || context->size > operation->size ||
        context->iova - operation->iova > operation->size - context->size))
        return 0;
    event = reserve_event(VTD_EVENT_IOMMU_UNMAP);
    if (!event)
        return 0;
    copy_operation(event, operation);
    event->state.iova = context->iova;
    event->state.size = context->size;
    event->state.returned_size = context->unmapped_size;
    event->state.parent_iova = operation->iova;
    event->state.parent_size = operation->size;
    event->event_info.correlated = 1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/iommu/attach_device_to_domain")
int attach_device(struct trace_event_raw_iommu_attach_device_to_domain *context)
{
    struct vtd_event *event = reserve_event(VTD_EVENT_DEVICE_ATTACH);
    __u32 offset;

    if (!event)
        return 0;
    offset = context->device_loc & 0xffff;
    bpf_probe_read_str(event->state.device, sizeof(event->state.device), (void *)context + offset);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/domain_attach_iommu")
int BPF_KPROBE(host_domain_attach_enter, struct dmar_domain *domain, struct intel_iommu *iommu)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct host_pending active = {};
    struct vtd_event *event;

    if (!current_process_is_qemu())
        return 0;
    active.domain_address = (__u64)domain;
    active.iommu_address = (__u64)iommu;
    active.iommu_id = BPF_CORE_READ(iommu, seq_id);
    lab_map_update(&host_pending_states, &key, &active, BPF_ANY);
    event = reserve_event(VTD_EVENT_DOMAIN_ATTACH_ENTER);
    if (!event)
        return 0;
    event->state.domain_address = active.domain_address;
    event->state.iommu_address = active.iommu_address;
    event->state.iommu_id = active.iommu_id;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/domain_attach_iommu")
int BPF_KRETPROBE(host_domain_attach_exit, long result)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct host_pending *active = bpf_map_lookup_elem(&host_pending_states, &key);
    struct vtd_event *event;

    if (!active)
        return 0;
    event = reserve_event(VTD_EVENT_DOMAIN_ATTACH_EXIT);
    if (event) {
        event->event_info.result = result;
        event->state.domain_address = active->domain_address;
        event->state.iommu_address = active->iommu_address;
        event->state.iommu_id = active->iommu_id;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&host_pending_states, &key);
    return 0;
}

SEC("kprobe/qi_submit_sync")
int BPF_KPROBE(host_qi_submit, struct intel_iommu *iommu, struct qi_desc *descriptors, unsigned int count, unsigned long options)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct host_pending active = {};
    struct qi_desc descriptor = {};
    struct vtd_event *event;

    if (!operation || (operation->operation != VTD_OP_VFIO_MAP && operation->operation != VTD_OP_VFIO_UNMAP))
        return 0;
    active.qi_count = count;
    active.qi_options = options;
    active.iommu_address = (__u64)iommu;
    active.iommu_id = BPF_CORE_READ(iommu, seq_id);
    if (count && !bpf_probe_read_kernel(&descriptor, sizeof(descriptor), descriptors)) {
        active.descriptor_0 = descriptor.qw0;
        active.descriptor_1 = descriptor.qw1;
    }
    lab_map_update(&host_pending_states, &key, &active, BPF_ANY);
    event = reserve_event(VTD_EVENT_QI_SUBMIT);
    if (!event)
        return 0;
    copy_operation(event, operation);
    event->event_info.correlated = 1;
    event->state.iommu_address = (__u64)iommu;
    event->state.iommu_id = BPF_CORE_READ(iommu, seq_id);
    event->state.qi_count = active.qi_count;
    event->state.qi_options = active.qi_options;
    event->state.qi_descriptor_0 = active.descriptor_0;
    event->state.qi_descriptor_1 = active.descriptor_1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/qi_submit_sync")
int BPF_KRETPROBE(host_qi_complete, long result)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct host_pending *active = bpf_map_lookup_elem(&host_pending_states, &key);
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    if (!active || !operation)
        return 0;
    event = reserve_event(VTD_EVENT_QI_COMPLETE);
    if (event) {
        copy_operation(event, operation);
        event->event_info.correlated = 1;
        event->event_info.result = result;
        event->state.iommu_address = active->iommu_address;
        event->state.iommu_id = active->iommu_id;
        event->state.qi_count = active->qi_count;
        event->state.qi_options = active->qi_options;
        event->state.qi_descriptor_0 = active->descriptor_0;
        event->state.qi_descriptor_1 = active->descriptor_1;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&host_pending_states, &key);
    return 0;
}

SEC("kprobe/intel_irq_remapping_activate")
int BPF_KPROBE(host_irte_activate, void *domain, struct irq_data *irq_data, bool reserve)
{
    struct vtd_event *event;

    (void)domain;
    if (!current_process_is_qemu())
        return 0;
    event = reserve_event(VTD_EVENT_IRTE_ACTIVATE);
    if (!event)
        return 0;
    event->state.irq = BPF_CORE_READ(irq_data, irq);
    event->event_info.flags = reserve;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/intel_ir_compose_msi_msg")
int BPF_KPROBE(host_ir_msi_entry, struct irq_data *irq_data, struct msi_msg *message)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct host_pending compose = {};

    if (!current_process_is_qemu())
        return 0;
    compose.message = (__u64)message;
    compose.irq = BPF_CORE_READ(irq_data, irq);
    lab_map_update(&host_pending_states, &key, &compose, BPF_ANY);
    return 0;
}

SEC("kretprobe/intel_ir_compose_msi_msg")
int BPF_KRETPROBE(host_ir_msi_exit)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct host_pending *compose = bpf_map_lookup_elem(&host_pending_states, &key);
    struct msi_msg message = {};
    struct vtd_event *event;

    if (!compose)
        return 0;
    if (!bpf_probe_read_kernel(&message, sizeof(message), (void *)compose->message)) {
        event = reserve_event(VTD_EVENT_IR_MSI_MESSAGE);
        if (event) {
            event->state.irq = compose->irq;
            event->state.interrupt_address = ((__u64)message.address_hi << 32) | message.address_lo;
            event->state.interrupt_data = message.data;
            bpf_ringbuf_submit(event, 0);
        }
    }
    bpf_map_delete_elem(&host_pending_states, &key);
    return 0;
}

SEC("tracepoint/kvm/kvm_pi_irte_update")
int host_kvm_pi_irte_update(struct trace_event_raw_kvm_pi_irte_update *context)
{
    struct vtd_event *event;

    event = reserve_event(VTD_EVENT_KVM_PI_IRTE_UPDATE);
    if (!event)
        return 0;
    event->state.irq = context->host_irq;
    event->state.vcpu_id = context->vcpu_id;
    event->state.gsi = context->gsi;
    event->state.vector = context->gvec;
    event->state.pi_desc_address = context->pi_desc_addr;
    event->state.posted = context->set;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/ixgbe_run_loopback_test")
int BPF_KPROBE(guest_run_entry)
{
    __u32 key = 0;
    struct guest_control *control = bpf_map_lookup_elem(&guest_control, &key);
    struct vtd_event *event;

    if (control)
        control->active = 1;
    set_guest_phase(VTD_GUEST_PHASE_LOOPBACK_RUN);
    if (!claim_guest_once(0))
        return 0;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_RUN_ENTRY);
    if (event)
        bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/ixgbe_run_loopback_test")
int BPF_KRETPROBE(guest_run_exit, long result)
{
    __u32 key = 0;
    struct guest_control *control = bpf_map_lookup_elem(&guest_control, &key);
    struct vtd_event *event;

    if (control)
        control->active = 0;
    if (!claim_guest_once(1))
        return 0;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_RUN_EXIT);
    if (!event)
        return 0;
    event->event_info.result = result;
    bpf_ringbuf_submit(event, 0);
    set_guest_phase(VTD_GUEST_PHASE_NONE);
    return 0;
}

SEC("kprobe/dma_map_page_attrs")
int BPF_KPROBE(guest_dma_map_entry, void *device, void *page, unsigned long offset, unsigned long size, unsigned int direction, unsigned long attrs)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct guest_pending call = {};
    struct vtd_event *event;

    (void)device;
    (void)page;
    (void)offset;
    (void)attrs;
    /* Sample the guest driver's DMA API call during loopback, not device DMA traffic. */
    if (!guest_loopback_is_active() || !claim_guest_once(2))
        return 0;
    call.size = size;
    call.direction = direction;
    lab_map_update(&guest_pending_states, &key, &call, BPF_ANY);
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_DMA_MAP_ENTRY);
    if (!event)
        return 0;
    event->state.data_length = size;
    event->state.dma_direction = direction;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/dma_map_page_attrs")
int BPF_KRETPROBE(guest_dma_map_exit, unsigned long long dma_address)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct guest_pending *call = bpf_map_lookup_elem(&guest_pending_states, &key);
    struct vtd_event *event;

    if (!call)
        return 0;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_DMA_MAP_EXIT);
    if (event) {
        event->state.dma_address = dma_address;
        event->state.data_length = call->size;
        event->state.dma_direction = call->direction;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&guest_pending_states, &key);
    return 0;
}

SEC("tracepoint/irq/irq_handler_entry")
int guest_irq_entry(struct trace_event_raw_irq_handler_entry *context)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u64 key = ((__u64)cpu << 32) | (__u32)context->irq;
    struct guest_pending state = {};
    struct vtd_event *event;
    __u32 offset;

    offset = context->__data_loc_name & 0xffff;
    bpf_probe_read_str(state.action, sizeof(state.action), (void *)context + offset);
    if (!guest_irq_name_matches(state.action))
        return 0;
    state.episode_id = next_guest_episode();
    state.phase = current_guest_phase();
    state.irq = context->irq;
    lab_map_update(&guest_pending_states, &key, &state, BPF_ANY);
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_IRQ_ENTRY);
    if (event) {
        copy_guest_episode(event, &state);
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int guest_irq_exit(struct trace_event_raw_irq_handler_exit *context)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u64 key = ((__u64)cpu << 32) | (__u32)context->irq;
    struct guest_pending *state = bpf_map_lookup_elem(&guest_pending_states, &key);
    struct vtd_event *event;

    if (!state)
        return 0;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_IRQ_EXIT);
    if (event) {
        event->event_info.result = context->ret;
        copy_guest_episode(event, state);
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&guest_pending_states, &key);
    return 0;
}
