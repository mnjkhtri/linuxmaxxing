/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "vtd_event.h"

/* These x86 ioctl values are resolved from the target UAPI headers. */
#define VFIO_IOMMU_MAP_DMA 0x3b71
#define VFIO_IOMMU_UNMAP_DMA 0x3b72
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

struct trace_event_raw_kvm_msi_set_irq {
    __u8 common[8];
    __u64 address;
    __u64 data;
};

struct trace_event_raw_kvm_apic_accept_irq {
    __u8 common[8];
    __u32 apic_id;
    __u16 delivery_mode;
    __u16 trigger_mode;
    __u8 vector;
};

struct trace_event_raw_kvm_mmio {
    __u8 common[8];
    __u32 access_type;
    __u32 length;
    __u64 gpa;
    __u64 value;
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
};

struct guest_path_state {
    __u32 capture_tx;
    __u32 capture_clean;
};

struct guest_dma_call {
    __u64 size;
    __u32 direction;
    __u32 capture;
};

struct guest_irq_state {
    char action[VTD_ACTION_NAME_LEN];
};

const volatile char target_interface[VTD_COMM_LEN];

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct active_operation);
} active_operations SEC(".maps");

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
    __type(value, __u32);
} runtime_gate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} runtime_event_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u32);
} active_irq_chains SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, struct guest_path_state);
} guest_paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, struct guest_dma_call);
} guest_dma_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct guest_irq_state);
} guest_active_irqs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} guest_once SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} guest_loopback_active SEC(".maps");

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
    event->context.pid = pid_tgid >> 32;
    event->context.tid = (__u32)pid_tgid;
    bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
    return event;
}

static __always_inline int runtime_is_enabled(void)
{
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&runtime_gate, &key);

    return enabled && *enabled;
}

static __always_inline int allow_runtime_event(unsigned int kind)
{
    __u32 key = kind;
    __u64 *count;

    if (!runtime_is_enabled() || key >= 64)
        return 0;
    count = bpf_map_lookup_elem(&runtime_event_counts, &key);
    if (!count)
        return 0;
    return __sync_fetch_and_add(count, 1) < 128;
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
    event->context.pid = pid_tgid >> 32;
    event->context.tid = (__u32)pid_tgid;
    bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
    return event;
}

static __always_inline struct vtd_event *reserve_runtime_event(unsigned int kind)
{
    if (!allow_runtime_event(kind))
        return 0;
    return reserve_unfiltered_event(kind);
}

static __always_inline int claim_guest_once(unsigned int bit)
{
    __u32 key = 0;
    __u64 mask = 1ULL << bit;
    __u64 *seen = bpf_map_lookup_elem(&guest_once, &key);

    if (!seen)
        return 0;
    return !(__sync_fetch_and_or(seen, mask) & mask);
}

static __always_inline int guest_loopback_is_active(void)
{
    __u32 key = 0;
    __u32 *active = bpf_map_lookup_elem(&guest_loopback_active, &key);

    return active && *active;
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
}

static __always_inline int is_tracked_ioctl(__u64 command)
{
    return command == VFIO_IOMMU_MAP_DMA || command == VFIO_IOMMU_UNMAP_DMA ||
        command == KVM_SET_USER_MEMORY_REGION || command == KVM_SET_USER_MEMORY_REGION2;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int enter_ioctl(struct trace_event_raw_sys_enter *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation operation = {};
    struct vfio_dma_map_request map_request = {};
    struct vfio_dma_unmap_request unmap_request = {};
    struct kvm_memory_region_request memory_request = {};
    struct vtd_event *event;

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
    bpf_map_update_elem(&active_operations, &key, &operation, BPF_ANY);

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

SEC("kprobe/vfio_iommu_type1_map_dma")
int BPF_KPROBE(vfio_map_enter, void *iommu, unsigned long argument)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    (void)iommu;
    if (!operation || operation->operation != VTD_OP_VFIO_MAP || argument != operation->user_argument)
        return 0;
    event = reserve_event(VTD_EVENT_VFIO_MAP_ENTER);
    if (!event)
        return 0;
    copy_operation(event, operation);
    event->event_info.correlated = 1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/vfio_iommu_type1_map_dma")
int BPF_KRETPROBE(vfio_map_exit, long result)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    if (!operation || operation->operation != VTD_OP_VFIO_MAP)
        return 0;
    event = reserve_event(VTD_EVENT_VFIO_MAP_EXIT);
    if (!event)
        return 0;
    copy_operation(event, operation);
    event->event_info.correlated = 1;
    event->event_info.result = result;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/vfio_pin_pages_remote")
int BPF_KPROBE(vfio_pin_enter, void *dma, unsigned long vaddr, unsigned long page_count)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    (void)dma;
    if (!operation || operation->operation != VTD_OP_VFIO_MAP)
        return 0;
    event = reserve_event(VTD_EVENT_PAGE_PIN_ENTER);
    if (!event)
        return 0;
    copy_operation(event, operation);
    event->state.hva = vaddr;
    event->state.page_count = page_count;
    event->event_info.correlated = 1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/vfio_pin_pages_remote")
int BPF_KRETPROBE(vfio_pin_exit, long result)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    if (!operation || operation->operation != VTD_OP_VFIO_MAP)
        return 0;
    event = reserve_event(VTD_EVENT_PAGE_PIN_EXIT);
    if (!event)
        return 0;
    copy_operation(event, operation);
    event->event_info.correlated = 1;
    event->event_info.result = result;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/vfio_unpin_pages_remote")
int BPF_KPROBE(vfio_unpin_enter, void *dma, __u64 iova, unsigned long pfn, unsigned long page_count)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    (void)dma;
    (void)pfn;
    if (!operation || operation->operation != VTD_OP_VFIO_UNMAP)
        return 0;
    event = reserve_event(VTD_EVENT_PAGE_UNPIN_ENTER);
    if (!event)
        return 0;
    copy_operation(event, operation);
    event->state.iova = iova;
    event->state.page_count = page_count;
    event->event_info.correlated = 1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/vfio_unpin_pages_remote")
int BPF_KRETPROBE(vfio_unpin_exit, long result)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_operation *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    if (!operation || operation->operation != VTD_OP_VFIO_UNMAP)
        return 0;
    event = reserve_event(VTD_EVENT_PAGE_UNPIN_EXIT);
    if (!event)
        return 0;
    copy_operation(event, operation);
    event->event_info.correlated = 1;
    event->event_info.result = result;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int begin_vfio_irq(unsigned int kind, int irq)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct vtd_event *event;

    if (!runtime_is_enabled())
        return 0;
    bpf_map_update_elem(&active_irq_chains, &key, &kind, BPF_ANY);
    event = reserve_runtime_event(kind);
    if (!event)
        return 0;
    event->state.irq = irq;
    event->event_info.correlated = 1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int finish_vfio_irq(unsigned int kind, long result)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 *active = bpf_map_lookup_elem(&active_irq_chains, &key);
    struct vtd_event *event;

    if (!active || *active != kind - 1)
        return 0;
    event = reserve_runtime_event(kind);
    if (event) {
        event->event_info.result = result;
        event->event_info.correlated = 1;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&active_irq_chains, &key);
    return 0;
}

SEC("kprobe/vfio_msihandler")
int BPF_KPROBE(host_vfio_msi_entry, int irq, void *argument)
{
    (void)argument;
    return begin_vfio_irq(VTD_EVENT_VFIO_MSI_ENTRY, irq);
}

SEC("kretprobe/vfio_msihandler")
int BPF_KRETPROBE(host_vfio_msi_exit, long result)
{
    return finish_vfio_irq(VTD_EVENT_VFIO_MSI_EXIT, result);
}

SEC("kprobe/vfio_intx_handler")
int BPF_KPROBE(host_vfio_intx_entry, int irq, void *argument)
{
    (void)argument;
    return begin_vfio_irq(VTD_EVENT_VFIO_INTX_ENTRY, irq);
}

SEC("kretprobe/vfio_intx_handler")
int BPF_KRETPROBE(host_vfio_intx_exit, long result)
{
    return finish_vfio_irq(VTD_EVENT_VFIO_INTX_EXIT, result);
}

SEC("kprobe/irqfd_wakeup")
int BPF_KPROBE(host_irqfd_wakeup)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 *active = bpf_map_lookup_elem(&active_irq_chains, &key);
    struct vtd_event *event;

    if (!active)
        return 0;
    event = reserve_runtime_event(VTD_EVENT_IRQFD_WAKEUP);
    if (!event)
        return 0;
    event->event_info.correlated = 1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/kvm/kvm_msi_set_irq")
int host_kvm_msi_route(struct trace_event_raw_kvm_msi_set_irq *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 *active = bpf_map_lookup_elem(&active_irq_chains, &key);
    struct vtd_event *event;

    if (!active)
        return 0;
    event = reserve_runtime_event(VTD_EVENT_KVM_MSI_ROUTE);
    if (!event)
        return 0;
    event->event_info.correlated = 1;
    event->state.interrupt_address = context->address;
    event->state.interrupt_data = context->data;
    event->state.vector = context->data & 0xff;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/kvm/kvm_apic_accept_irq")
int host_kvm_apic_accept(struct trace_event_raw_kvm_apic_accept_irq *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 *active = bpf_map_lookup_elem(&active_irq_chains, &key);
    struct vtd_event *event;

    if (!active)
        return 0;
    event = reserve_runtime_event(VTD_EVENT_KVM_APIC_ACCEPT);
    if (!event)
        return 0;
    event->event_info.correlated = 1;
    event->state.apic_id = context->apic_id;
    event->state.vector = context->vector;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/kvm/kvm_mmio")
int host_kvm_mmio(struct trace_event_raw_kvm_mmio *context)
{
    struct vtd_event *event;

    if (!current_process_is_qemu())
        return 0;
    event = reserve_runtime_event(VTD_EVENT_KVM_MMIO);
    if (!event)
        return 0;
    event->state.gpa = context->gpa;
    event->state.mmio_length = context->length;
    event->state.mmio_type = context->access_type;
    event->state.mmio_value = context->value;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/ixgbe_run_loopback_test")
int BPF_KPROBE(guest_run_entry)
{
    __u32 key = 0;
    __u32 enabled = 1;
    struct vtd_event *event;

    bpf_map_update_elem(&guest_loopback_active, &key, &enabled, BPF_ANY);
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
    __u32 disabled = 0;
    struct vtd_event *event;

    bpf_map_update_elem(&guest_loopback_active, &key, &disabled, BPF_ANY);
    if (!claim_guest_once(1))
        return 0;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_RUN_EXIT);
    if (!event)
        return 0;
    event->event_info.result = result;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/ixgbe_xmit_frame_ring")
int BPF_KPROBE(guest_xmit_entry, struct sk_buff *skb, void *adapter, void *ring)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct guest_path_state path = {};
    struct vtd_event *event;

    (void)adapter;
    (void)ring;
    if (!guest_loopback_is_active())
        return 0;
    path.capture_tx = claim_guest_once(2);
    bpf_map_update_elem(&guest_paths, &key, &path, BPF_ANY);
    if (!path.capture_tx)
        return 0;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_XMIT_ENTRY);
    if (!event)
        return 0;
    event->state.data_length = BPF_CORE_READ(skb, len);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/dma_map_page_attrs")
int BPF_KPROBE(guest_dma_map_entry, void *device, void *page, unsigned long offset, unsigned long size, unsigned int direction, unsigned long attrs)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct guest_path_state *path = bpf_map_lookup_elem(&guest_paths, &key);
    struct guest_dma_call call = {};
    struct vtd_event *event;

    (void)device;
    (void)page;
    (void)offset;
    (void)attrs;
    if (!path || !path->capture_tx || !claim_guest_once(3))
        return 0;
    call.size = size;
    call.direction = direction;
    call.capture = 1;
    bpf_map_update_elem(&guest_dma_calls, &key, &call, BPF_ANY);
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
    struct guest_dma_call *call = bpf_map_lookup_elem(&guest_dma_calls, &key);
    struct vtd_event *event;

    if (!call || !call->capture)
        return 0;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_DMA_MAP_EXIT);
    if (event) {
        event->state.dma_address = dma_address;
        event->state.data_length = call->size;
        event->state.dma_direction = call->direction;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&guest_dma_calls, &key);
    return 0;
}

SEC("kretprobe/ixgbe_xmit_frame_ring")
int BPF_KRETPROBE(guest_xmit_exit, long result)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct guest_path_state *path = bpf_map_lookup_elem(&guest_paths, &key);
    struct vtd_event *event;

    if (path && path->capture_tx) {
        event = reserve_unfiltered_event(VTD_EVENT_GUEST_XMIT_EXIT);
        if (event) {
            event->event_info.result = result;
            bpf_ringbuf_submit(event, 0);
        }
    }
    bpf_map_delete_elem(&guest_paths, &key);
    return 0;
}

SEC("kprobe/ixgbe_clean_test_rings")
int BPF_KPROBE(guest_clean_entry)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct guest_path_state path = {};
    struct vtd_event *event;

    path.capture_clean = claim_guest_once(4);
    bpf_map_update_elem(&guest_paths, &key, &path, BPF_ANY);
    if (!path.capture_clean)
        return 0;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_CLEAN_ENTRY);
    if (event)
        bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int emit_guest_dma_boundary(unsigned int kind, unsigned long long dma_address, unsigned long size, unsigned int direction, unsigned int once_bit)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct guest_path_state *path = bpf_map_lookup_elem(&guest_paths, &key);
    struct vtd_event *event;

    if (!path || !path->capture_clean || !claim_guest_once(once_bit))
        return 0;
    event = reserve_unfiltered_event(kind);
    if (!event)
        return 0;
    event->state.dma_address = dma_address;
    event->state.data_length = size;
    event->state.dma_direction = direction;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/dma_unmap_page_attrs")
int BPF_KPROBE(guest_dma_unmap, void *device, unsigned long long dma_address, unsigned long size, unsigned int direction, unsigned long attrs)
{
    (void)device;
    (void)attrs;
    return emit_guest_dma_boundary(VTD_EVENT_GUEST_DMA_UNMAP, dma_address, size, direction, 5);
}

SEC("kprobe/dma_sync_single_for_cpu")
int BPF_KPROBE(guest_dma_sync_cpu, void *device, unsigned long long dma_address, unsigned long size, unsigned int direction)
{
    (void)device;
    return emit_guest_dma_boundary(VTD_EVENT_GUEST_DMA_SYNC_CPU, dma_address, size, direction, 6);
}

SEC("kprobe/dma_sync_single_for_device")
int BPF_KPROBE(guest_dma_sync_device, void *device, unsigned long long dma_address, unsigned long size, unsigned int direction)
{
    (void)device;
    return emit_guest_dma_boundary(VTD_EVENT_GUEST_DMA_SYNC_DEVICE, dma_address, size, direction, 7);
}

SEC("kretprobe/ixgbe_clean_test_rings")
int BPF_KRETPROBE(guest_clean_exit, long result)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct guest_path_state *path = bpf_map_lookup_elem(&guest_paths, &key);
    struct vtd_event *event;

    if (path && path->capture_clean) {
        event = reserve_unfiltered_event(VTD_EVENT_GUEST_CLEAN_EXIT);
        if (event) {
            event->event_info.result = result;
            event->state.count = result;
            bpf_ringbuf_submit(event, 0);
        }
    }
    bpf_map_delete_elem(&guest_paths, &key);
    return 0;
}

SEC("tracepoint/irq/irq_handler_entry")
int guest_irq_entry(struct trace_event_raw_irq_handler_entry *context)
{
    struct guest_irq_state state = {};
    struct vtd_event *event;
    __u64 key;
    __u32 offset;

    offset = context->__data_loc_name & 0xffff;
    bpf_probe_read_str(state.action, sizeof(state.action), (void *)context + offset);
    if (!guest_irq_name_matches(state.action))
        return 0;
    key = ((__u64)bpf_get_smp_processor_id() << 32) | (__u32)context->irq;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_IRQ_ENTRY);
    if (!event)
        return 0;
    event->state.irq = context->irq;
    __builtin_memcpy(event->state.action, state.action, sizeof(state.action));
    bpf_ringbuf_submit(event, 0);
    bpf_map_update_elem(&guest_active_irqs, &key, &state, BPF_ANY);
    return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int guest_irq_exit(struct trace_event_raw_irq_handler_exit *context)
{
    __u64 key = ((__u64)bpf_get_smp_processor_id() << 32) | (__u32)context->irq;
    struct guest_irq_state *state = bpf_map_lookup_elem(&guest_active_irqs, &key);
    struct vtd_event *event;

    if (!state)
        return 0;
    event = reserve_unfiltered_event(VTD_EVENT_GUEST_IRQ_EXIT);
    if (event) {
        event->event_info.result = context->ret;
        event->state.irq = context->irq;
        __builtin_memcpy(event->state.action, state->action, sizeof(event->state.action));
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&guest_active_irqs, &key);
    return 0;
}
