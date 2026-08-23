/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "json_writer.h"
#include "vtd.skel.h"
#include "vtd_event.h"

static volatile sig_atomic_t stop_requested;
static unsigned int record_count;

static void on_signal(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static const char *event_name(const struct vtd_event *event)
{
    if (event->event_info.kind == VTD_EVENT_IOCTL_ENTER)
        return event->event_info.operation == VTD_OP_MAP ? "vfio_dma_map_enter" : "vfio_dma_unmap_enter";
    if (event->event_info.kind == VTD_EVENT_IOCTL_EXIT)
        return event->event_info.operation == VTD_OP_MAP ? "vfio_dma_map_exit" : "vfio_dma_unmap_exit";
    if (event->event_info.kind == VTD_EVENT_IOMMU_MAP)
        return "iommu_map";
    if (event->event_info.kind == VTD_EVENT_IOMMU_UNMAP)
        return "iommu_unmap";
    return "iommu_device_attach";
}

static const char *event_hook(const struct vtd_event *event)
{
    if (event->event_info.kind == VTD_EVENT_IOMMU_MAP)
        return "iommu:map";
    if (event->event_info.kind == VTD_EVENT_IOMMU_UNMAP)
        return "iommu:unmap";
    if (event->event_info.kind == VTD_EVENT_DEVICE_ATTACH)
        return "iommu:attach_device_to_domain";
    return event->event_info.kind == VTD_EVENT_IOCTL_EXIT ? "syscalls:sys_exit_ioctl" : "syscalls:sys_enter_ioctl";
}

static int emit_record(void *ctx, void *data, size_t size)
{
    struct json_writer writer;
    const struct vtd_event *event = data;

    (void)ctx;
    if (size != sizeof(*event))
        return 0;

    json_writer_init(&writer, stdout);
    json_object_begin(&writer);
    json_u32(&writer, "schema_version", 2);
    json_string(&writer, "experiment", "virt-vtd");
    json_string(&writer, "kind", event_name(event));
    json_string(&writer, "source", "ebpf");
    json_u32(&writer, "seq", ++record_count);
    json_u64(&writer, "time_ns", event->time_ns);

    json_object_begin_field(&writer, "event_info");
    json_string(&writer, "hook", event_hook(event));
    json_bool(&writer, "correlated", event->event_info.correlated);
    json_hex(&writer, "command", event->event_info.command);
    json_hex(&writer, "hva", event->state.hva);
    json_hex(&writer, "iova", event->state.iova);
    json_hex(&writer, "hpa", event->state.hpa);
    json_hex(&writer, "size", event->state.size);
    json_hex(&writer, "parent_iova", event->state.parent_iova);
    json_hex(&writer, "parent_size", event->state.parent_size);
    json_u32(&writer, "flags", event->event_info.flags);
    json_i64(&writer, "result", event->event_info.result);
    json_string(&writer, "device", event->state.device);
    json_object_end(&writer);

    json_object_begin_field(&writer, "context");
    json_u32(&writer, "pid", event->context.pid);
    json_u32(&writer, "tid", event->context.tid);
    json_object_end(&writer);

    json_object_begin_field(&writer, "state");
    json_object_end(&writer);
    json_object_end(&writer);
    json_newline(&writer);
    fflush(stdout);
    return 0;
}

int main(void)
{
    struct vtd_bpf *skeleton;
    struct ring_buffer *ring_buffer;
    struct bpf_link *links[5] = {};
    int poll_result = 0;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skeleton = vtd_bpf__open_and_load();
    if (!skeleton) {
        fprintf(stderr, "vtd observer: open/load failed\n");
        return 1;
    }

    links[0] = bpf_program__attach(skeleton->progs.enter_ioctl);
    links[1] = bpf_program__attach(skeleton->progs.exit_ioctl);
    links[2] = bpf_program__attach(skeleton->progs.iommu_map);
    links[3] = bpf_program__attach(skeleton->progs.iommu_unmap);
    links[4] = bpf_program__attach(skeleton->progs.attach_device);
    for (size_t index = 0; index < 5; index++) {
        if (!links[index]) {
            fprintf(stderr, "vtd observer: attach failed\n");
            return 1;
        }
    }

    ring_buffer = ring_buffer__new(bpf_map__fd(skeleton->maps.events), emit_record, NULL, NULL);
    if (!ring_buffer)
        return 1;

    fprintf(stderr, "LX_READY experiment=virt-vtd observer=vtd\n");
    while (!stop_requested) {
        poll_result = ring_buffer__poll(ring_buffer, 250);
        if (poll_result < 0 && poll_result != -EINTR)
            break;
    }

    ring_buffer__free(ring_buffer);
    for (size_t index = 0; index < 5; index++)
        bpf_link__destroy(links[index]);
    vtd_bpf__destroy(skeleton);
    fprintf(stderr, "LX_DONE experiment=virt-vtd observer=vtd records=%u\n", record_count);
    return poll_result < 0 ? 1 : 0;
}
