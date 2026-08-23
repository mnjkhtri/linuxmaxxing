/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "vtd_event.h"

/* These values were resolved from the target kernel's linux/vfio.h. */
#define VFIO_IOMMU_MAP_DMA 0x3b71
#define VFIO_IOMMU_UNMAP_DMA 0x3b72

char LICENSE[] SEC("license") = "GPL";

struct dma_map {
    __u32 argsz;
    __u32 flags;
    __u64 vaddr;
    __u64 iova;
    __u64 size;
};

struct dma_unmap {
    __u32 argsz;
    __u32 flags;
    __u64 iova;
    __u64 size;
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

struct active_ioctl {
    __u32 operation;
    __u32 fd;
    __u64 command;
    __u64 hva;
    __u64 iova;
    __u64 size;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u64);
    __type(value, struct active_ioctl);
} active_operations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int current_process_is_qemu(void)
{
    char comm[16] = {};

    bpf_get_current_comm(comm, sizeof(comm));
    return comm[0] == 'q' && comm[1] == 'e' && comm[2] == 'm' && comm[3] == 'u';
}

static __always_inline struct vtd_event *reserve_event(unsigned int kind)
{
    struct vtd_event *event;
    __u64 pid_tgid;

    if (!current_process_is_qemu())
        return 0;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    event->time_ns = bpf_ktime_get_ns();
    event->event_info.kind = kind;
    event->context.pid = pid_tgid >> 32;
    event->context.tid = (__u32)pid_tgid;
    return event;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int enter_ioctl(struct trace_event_raw_sys_enter *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_ioctl operation = {};
    struct dma_map map_request = {};
    struct dma_unmap unmap_request = {};
    struct vtd_event *event;

    if (!current_process_is_qemu())
        return 0;
    if (context->args[1] != VFIO_IOMMU_MAP_DMA && context->args[1] != VFIO_IOMMU_UNMAP_DMA)
        return 0;
    operation.operation = context->args[1] == VFIO_IOMMU_MAP_DMA ? VTD_OP_MAP : VTD_OP_UNMAP;
    operation.fd = context->args[0];
    operation.command = context->args[1];
    if (operation.operation == VTD_OP_MAP) {
        if (bpf_probe_read_user(&map_request, sizeof(map_request), (void *)context->args[2]))
            return 0;
        operation.hva = map_request.vaddr;
        operation.iova = map_request.iova;
        operation.size = map_request.size;
        operation.flags = map_request.flags;
    } else {
        if (bpf_probe_read_user(&unmap_request, sizeof(unmap_request), (void *)context->args[2]))
            return 0;
        operation.iova = unmap_request.iova;
        operation.size = unmap_request.size;
        operation.flags = unmap_request.flags;
    }
    bpf_map_update_elem(&active_operations, &key, &operation, BPF_ANY);

    event = reserve_event(VTD_EVENT_IOCTL_ENTER);
    if (!event)
        return 0;
    event->event_info.operation = operation.operation;
    event->event_info.fd = operation.fd;
    event->event_info.command = operation.command;
    event->state.hva = operation.hva;
    event->state.iova = operation.iova;
    event->state.size = operation.size;
    event->event_info.flags = operation.flags;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int exit_ioctl(struct trace_event_raw_sys_exit *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_ioctl *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    if (!operation)
        return 0;
    event = reserve_event(VTD_EVENT_IOCTL_EXIT);
    if (event) {
        event->event_info.operation = operation->operation;
        event->event_info.fd = operation->fd;
        event->event_info.command = operation->command;
        event->state.iova = operation->iova;
        event->state.size = operation->size;
        event->event_info.result = context->ret;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&active_operations, &key);
    return 0;
}

SEC("tracepoint/iommu/map")
int iommu_map(struct trace_event_raw_iommu_map *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct active_ioctl *operation = bpf_map_lookup_elem(&active_operations, &key);
    struct vtd_event *event;

    if (!operation || operation->operation != VTD_OP_MAP)
        return 0;
    if (context->iova < operation->iova || context->iova + context->size > operation->iova + operation->size)
        return 0;
    event = reserve_event(VTD_EVENT_IOMMU_MAP);
    if (!event)
        return 0;
    event->event_info.operation = VTD_OP_MAP;
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
    struct vtd_event *event = reserve_event(VTD_EVENT_IOMMU_UNMAP);

    if (!event)
        return 0;
    event->event_info.operation = VTD_OP_UNMAP;
    event->state.iova = context->iova;
    event->state.size = context->size;
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
