/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "json_writer.h"
#include "observer_runtime.h"
#include "vtd.skel.h"
#include "vtd_event.h"

#define MAX_LINKS 48

enum capture_mode { CAPTURE_HOST, CAPTURE_GUEST };

struct capture_features {
    bool irte_activate;
    bool ir_msi_entry, ir_msi_exit, kvm_pi_irte_update;
    bool domain_attach_enter, domain_attach_exit;
    bool qi_submit, qi_complete;
    bool guest_run_entry, guest_run_exit;
    bool guest_dma_map_entry, guest_dma_map_exit;
    bool guest_irq_entry, guest_irq_exit;
};

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t gate_request = -1;
static unsigned int sequence, event_count, short_record_count;
static enum capture_mode current_mode = CAPTURE_HOST;
static const char *guest_interface = "";
static const char *guest_driver = "ixgbe";
static char guest_run_name[64];
static char guest_run_hook[80];

static void on_signal(int signal_number)
{
    if (signal_number == SIGUSR1) gate_request = 1;
    else if (signal_number == SIGUSR2) gate_request = 0;
    else stop_requested = 1;
}

static uint64_t monotonic_time_ns(void)
{
    struct timespec now = {};
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static uint64_t realtime_time_ns(void)
{
    struct timespec now = {};
    if (clock_gettime(CLOCK_REALTIME, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static const char *operation_name(unsigned int operation)
{
    switch (operation) {
    case VTD_OP_VFIO_MAP: return "vfio_dma_map";
    case VTD_OP_VFIO_UNMAP: return "vfio_dma_unmap";
    case VTD_OP_KVM_MEMORY_REGION: return "kvm_memory_region";
    case VTD_OP_VFIO_IRQ_SET: return "vfio_irq_set";
    default: return "none";
    }
}

static const char *sample_status_name(unsigned int status)
{
    switch (status) {
    case VTD_SAMPLE_READ_FAILED: return "read_failed";
    case VTD_SAMPLE_INVALID_ARGUMENT: return "invalid_argument";
    default: return "complete";
    }
}

static const char *guest_phase_name(unsigned int phase)
{
    return phase == VTD_GUEST_PHASE_LOOPBACK_RUN ? "loopback_run" : "none";
}

static bool is_mapping_event(unsigned int kind)
{
    switch (kind) {
    case VTD_EVENT_IOCTL_ENTER: case VTD_EVENT_IOMMU_MAP:
    case VTD_EVENT_IOMMU_UNMAP: case VTD_EVENT_DEVICE_ATTACH:
    case VTD_EVENT_IOCTL_EXIT: return true;
    default: return false;
    }
}

static bool is_interrupt_event(unsigned int kind)
{
    switch (kind) {
    case VTD_EVENT_IRTE_ACTIVATE:
    case VTD_EVENT_IR_MSI_MESSAGE: case VTD_EVENT_KVM_PI_IRTE_UPDATE:
    case VTD_EVENT_GUEST_IRQ_ENTRY: case VTD_EVENT_GUEST_IRQ_EXIT: return true;
    default: return false;
    }
}

static bool is_iommu_event(unsigned int kind)
{
    switch (kind) {
    case VTD_EVENT_DOMAIN_ATTACH_ENTER: case VTD_EVENT_DOMAIN_ATTACH_EXIT:
    case VTD_EVENT_QI_SUBMIT: case VTD_EVENT_QI_COMPLETE: return true;
    default: return false;
    }
}

static bool is_guest_event(unsigned int kind)
{
    switch (kind) {
    case VTD_EVENT_GUEST_RUN_ENTRY: case VTD_EVENT_GUEST_RUN_EXIT:
    case VTD_EVENT_GUEST_DMA_MAP_ENTRY: case VTD_EVENT_GUEST_DMA_MAP_EXIT:
    case VTD_EVENT_GUEST_IRQ_ENTRY: case VTD_EVENT_GUEST_IRQ_EXIT: return true;
    default: return false;
    }
}

static const char *event_name(const struct vtd_event *event)
{
    switch (event->event_info.kind) {
    case VTD_EVENT_IOCTL_ENTER:
        if (event->event_info.operation == VTD_OP_KVM_MEMORY_REGION) return "kvm_memory_region_enter";
        if (event->event_info.operation == VTD_OP_VFIO_IRQ_SET) return "vfio_irq_set_enter";
        return event->event_info.operation == VTD_OP_VFIO_MAP ? "vfio_dma_map_enter" : "vfio_dma_unmap_enter";
    case VTD_EVENT_IOCTL_EXIT:
        if (event->event_info.operation == VTD_OP_KVM_MEMORY_REGION) return "kvm_memory_region_exit";
        if (event->event_info.operation == VTD_OP_VFIO_IRQ_SET) return "vfio_irq_set_exit";
        return event->event_info.operation == VTD_OP_VFIO_MAP ? "vfio_dma_map_exit" : "vfio_dma_unmap_exit";
    case VTD_EVENT_IOMMU_MAP: return "iommu_map";
    case VTD_EVENT_IOMMU_UNMAP: return "iommu_unmap";
    case VTD_EVENT_DEVICE_ATTACH: return "iommu_device_attach";
    case VTD_EVENT_IRTE_ACTIVATE: return "irte_activate";
    case VTD_EVENT_IR_MSI_MESSAGE: return "interrupt_remap_msi_message";
    case VTD_EVENT_KVM_PI_IRTE_UPDATE: return "kvm_pi_irte_update";
    case VTD_EVENT_DOMAIN_ATTACH_ENTER: return "iommu_domain_attach_enter";
    case VTD_EVENT_DOMAIN_ATTACH_EXIT: return "iommu_domain_attach_exit";
    case VTD_EVENT_QI_SUBMIT: return "iommu_qi_submit";
    case VTD_EVENT_QI_COMPLETE: return "iommu_qi_complete";
    case VTD_EVENT_GUEST_RUN_ENTRY:
        snprintf(guest_run_name, sizeof(guest_run_name), "guest_nic_run_loopback_entry");
        return guest_run_name;
    case VTD_EVENT_GUEST_RUN_EXIT:
        snprintf(guest_run_name, sizeof(guest_run_name), "guest_nic_run_loopback_exit");
        return guest_run_name;
    case VTD_EVENT_GUEST_DMA_MAP_ENTRY: return "guest_dma_map_entry";
    case VTD_EVENT_GUEST_DMA_MAP_EXIT: return "guest_dma_map_exit";
    case VTD_EVENT_GUEST_IRQ_ENTRY: return "guest_irq_handler_entry";
    case VTD_EVENT_GUEST_IRQ_EXIT: return "guest_irq_handler_exit";
    default: return "unknown";
    }
}

static const char *event_hook(const struct vtd_event *event)
{
    switch (event->event_info.kind) {
    case VTD_EVENT_IOMMU_MAP: return "tracepoint/iommu/map";
    case VTD_EVENT_IOMMU_UNMAP: return "tracepoint/iommu/unmap";
    case VTD_EVENT_DEVICE_ATTACH: return "tracepoint/iommu/attach_device_to_domain";
    case VTD_EVENT_IRTE_ACTIVATE: return "kprobe:intel_irq_remapping_activate";
    case VTD_EVENT_IR_MSI_MESSAGE: return "kretprobe:intel_ir_compose_msi_msg";
    case VTD_EVENT_KVM_PI_IRTE_UPDATE: return "tracepoint/kvm/kvm_pi_irte_update";
    case VTD_EVENT_DOMAIN_ATTACH_ENTER: return "kprobe:domain_attach_iommu";
    case VTD_EVENT_DOMAIN_ATTACH_EXIT: return "kretprobe:domain_attach_iommu";
    case VTD_EVENT_QI_SUBMIT: return "kprobe:qi_submit_sync";
    case VTD_EVENT_QI_COMPLETE: return "kretprobe:qi_submit_sync";
    case VTD_EVENT_GUEST_RUN_ENTRY:
        snprintf(guest_run_hook, sizeof(guest_run_hook), "kprobe:%s_run_loopback_test", guest_driver);
        return guest_run_hook;
    case VTD_EVENT_GUEST_RUN_EXIT:
        snprintf(guest_run_hook, sizeof(guest_run_hook), "kretprobe:%s_run_loopback_test", guest_driver);
        return guest_run_hook;
    case VTD_EVENT_GUEST_DMA_MAP_ENTRY: return "kprobe:dma_map_page_attrs";
    case VTD_EVENT_GUEST_DMA_MAP_EXIT: return "kretprobe:dma_map_page_attrs";
    case VTD_EVENT_GUEST_IRQ_ENTRY: return "tracepoint/irq/irq_handler_entry";
    case VTD_EVENT_GUEST_IRQ_EXIT: return "tracepoint/irq/irq_handler_exit";
    default: return event->event_info.kind == VTD_EVENT_IOCTL_EXIT ? "tracepoint/syscalls/sys_exit_ioctl" : "tracepoint/syscalls/sys_enter_ioctl";
    }
}

static void begin_record(struct json_writer *writer, const char *kind, const char *source, uint64_t time_ns)
{
    json_object_begin(writer);
    json_string(writer, "experiment", "virt-vtd");
    json_string(writer, "kind", kind);
    json_string(writer, "source", source);
    json_u32(writer, "seq", ++sequence);
    json_u64(writer, "time_ns", time_ns);
    json_string(writer, "clock", "monotonic");
}

static void emit_empty_context(struct json_writer *writer)
{
    json_object_begin_field(writer, "context");
    json_null(writer, "pid"); json_null(writer, "tid");
    json_null(writer, "cpu"); json_null(writer, "comm");
    json_object_end(writer);
}

static int emit_meta(const struct capture_features *f)
{
    uint64_t now = monotonic_time_ns();
    struct json_writer writer;
    json_writer_init(&writer, stdout);
    begin_record(&writer, "capture_meta", "observer", now);
    json_object_begin_field(&writer, "event_info");
    json_string(&writer, "observer", current_mode == CAPTURE_HOST ? "host-ebpf" : "guest-ebpf");
    json_string(&writer, "filter", current_mode == CAPTURE_HOST ? "qemu-control" : guest_interface);
    json_object_end(&writer);
    emit_empty_context(&writer);
    json_object_begin_field(&writer, "state");
    json_object_begin_field(&writer, "clock_anchor");
    json_u64(&writer, "monotonic_ns", now); json_u64(&writer, "realtime_ns", realtime_time_ns());
    json_object_end(&writer);
    json_object_begin_field(&writer, "hooks");
    json_bool(&writer, "syscall_ioctl", current_mode == CAPTURE_HOST);
    json_bool(&writer, "iommu_map", current_mode == CAPTURE_HOST); json_bool(&writer, "iommu_unmap", current_mode == CAPTURE_HOST);
    json_bool(&writer, "iommu_device_attach", current_mode == CAPTURE_HOST);
    json_bool(&writer, "vfio_type1_map_enter", false); json_bool(&writer, "vfio_type1_map_exit", false);
    json_bool(&writer, "page_pin_enter", false); json_bool(&writer, "page_pin_exit", false);
    json_bool(&writer, "page_unpin_enter", false); json_bool(&writer, "page_unpin_exit", false);
    json_bool(&writer, "vfio_msi", false); json_bool(&writer, "vfio_intx", false); json_bool(&writer, "irqfd_wakeup", false);
    json_bool(&writer, "kvm_msi_route", false); json_bool(&writer, "kvm_apic_accept", false); json_bool(&writer, "kvm_mmio", false);
    json_bool(&writer, "irte_activate", f->irte_activate);
    json_bool(&writer, "ir_msi_entry", f->ir_msi_entry); json_bool(&writer, "ir_msi_exit", f->ir_msi_exit);
    json_bool(&writer, "kvm_pi_irte_update", f->kvm_pi_irte_update); json_bool(&writer, "iommu_fault", false);
    json_bool(&writer, "domain_attach_enter", f->domain_attach_enter); json_bool(&writer, "domain_attach_exit", f->domain_attach_exit);
    json_bool(&writer, "qi_submit", f->qi_submit); json_bool(&writer, "qi_complete", f->qi_complete);
    json_bool(&writer, "pi_sync_enter", false); json_bool(&writer, "pi_sync_exit", false); json_bool(&writer, "pi_wakeup", false);
    json_bool(&writer, "pi_wakeup_exit", false); json_bool(&writer, "pi_vcpu_wake_up", false); json_bool(&writer, "pi_wakeup_vector", false);
    json_bool(&writer, "guest_run_entry", f->guest_run_entry); json_bool(&writer, "guest_run_exit", f->guest_run_exit);
    json_bool(&writer, "guest_xmit_entry", false); json_bool(&writer, "guest_xmit_exit", false);
    json_bool(&writer, "guest_dma_map_entry", f->guest_dma_map_entry); json_bool(&writer, "guest_dma_map_exit", f->guest_dma_map_exit);
    json_bool(&writer, "guest_clean_entry", false); json_bool(&writer, "guest_clean_exit", false);
    json_bool(&writer, "guest_dma_unmap", false); json_bool(&writer, "guest_dma_sync_cpu", false); json_bool(&writer, "guest_dma_sync_device", false);
    json_bool(&writer, "guest_irq_entry", f->guest_irq_entry); json_bool(&writer, "guest_irq_exit", f->guest_irq_exit);
    json_bool(&writer, "guest_netdev_open", false); json_bool(&writer, "guest_netdev_close", false);
    json_bool(&writer, "guest_diag_entry", false); json_bool(&writer, "guest_diag_exit", false);
    json_bool(&writer, "guest_intr_test_entry", false); json_bool(&writer, "guest_intr_test_exit", false);
    json_bool(&writer, "guest_loopback_entry", false); json_bool(&writer, "guest_loopback_exit", false);
    json_bool(&writer, "guest_softirq_raise", false); json_bool(&writer, "guest_softirq_entry", false);
    json_bool(&writer, "guest_napi_poll", false); json_bool(&writer, "guest_softirq_exit", false);
    json_object_end(&writer); json_object_end(&writer); json_object_end(&writer);
    json_newline(&writer); fflush(stdout);
    return json_writer_ok(&writer) ? 0 : -EIO;
}

static int emit_gate_marker(unsigned int enabled)
{
    /* Gate signals timestamp the workload interval; they do not detach BPF links. */
    struct json_writer writer;
    uint64_t now = monotonic_time_ns();
    json_writer_init(&writer, stdout);
    begin_record(&writer, enabled ? "workload_begin" : "workload_end", "observer", now);
    json_object_begin_field(&writer, "event_info"); json_string(&writer, "boundary", enabled ? "begin" : "end"); json_object_end(&writer);
    emit_empty_context(&writer);
    json_object_begin_field(&writer, "state");
    json_object_begin_field(&writer, "clock_anchor");
    json_u64(&writer, "monotonic_ns", now); json_u64(&writer, "realtime_ns", realtime_time_ns());
    json_object_end(&writer); json_object_end(&writer);
    json_object_end(&writer); json_newline(&writer); fflush(stdout);
    if (!json_writer_ok(&writer)) return -EIO;
    event_count++;
    return 0;
}

static int emit_record(void *ctx, void *data, size_t size)
{
    const struct vtd_event *event = data;
    struct json_writer writer;
    (void)ctx;
    if (size < sizeof(*event)) { short_record_count++; return 0; }
    json_writer_init(&writer, stdout);
    begin_record(&writer, event_name(event), current_mode == CAPTURE_HOST ? "host-ebpf" : "guest-ebpf", event->time_ns);
    json_object_begin_field(&writer, "event_info");
    json_string(&writer, "hook", event_hook(event)); json_string(&writer, "operation", operation_name(event->event_info.operation));
    json_u64(&writer, "request_id", event->event_info.request_id); json_bool(&writer, "correlated", event->event_info.correlated);
    json_string(&writer, "sample_status", sample_status_name(event->event_info.sample_status)); json_u32(&writer, "fd", event->event_info.fd);
    json_hex(&writer, "command", event->event_info.command); json_u32(&writer, "argsz", event->event_info.argsz);
    json_u32(&writer, "flags", event->event_info.flags); json_u32(&writer, "slot", event->event_info.slot);
    json_i64(&writer, "result", event->event_info.result); json_object_end(&writer);
    json_object_begin_field(&writer, "context");
    json_u32(&writer, "pid", event->context.pid); json_u32(&writer, "tid", event->context.tid); json_u32(&writer, "cpu", event->context.cpu);
    json_string_n(&writer, "comm", event->context.comm, sizeof(event->context.comm)); json_object_end(&writer);
    json_object_begin_field(&writer, "state");
    if (is_mapping_event(event->event_info.kind) && event->event_info.operation != VTD_OP_VFIO_IRQ_SET) {
        json_object_begin_field(&writer, "address_space");
        json_hex(&writer, "hva", event->state.hva); json_hex(&writer, "gpa", event->state.gpa); json_hex(&writer, "iova", event->state.iova);
        json_hex(&writer, "hpa", event->state.hpa); json_hex(&writer, "size", event->state.size); json_hex(&writer, "returned_size", event->state.returned_size);
        json_hex(&writer, "parent_iova", event->state.parent_iova); json_hex(&writer, "parent_size", event->state.parent_size); json_u64(&writer, "page_count", event->state.page_count);
        json_object_end(&writer); json_string_n(&writer, "device", event->state.device, sizeof(event->state.device));
    }
    if (event->event_info.kind == VTD_EVENT_GUEST_DMA_MAP_ENTRY || event->event_info.kind == VTD_EVENT_GUEST_DMA_MAP_EXIT) {
        json_object_begin_field(&writer, "dma"); json_hex(&writer, "address", event->state.dma_address); json_u64(&writer, "length", event->state.data_length);
        json_u32(&writer, "direction", event->state.dma_direction); json_u32(&writer, "completed_descriptors", event->state.count); json_object_end(&writer);
    }
    if (is_interrupt_event(event->event_info.kind) || event->event_info.operation == VTD_OP_VFIO_IRQ_SET) {
        json_object_begin_field(&writer, "interrupt"); json_u32(&writer, "irq", event->state.irq); json_u32(&writer, "vector", event->state.vector); json_u32(&writer, "apic_id", event->state.apic_id);
        json_hex(&writer, "address", event->state.interrupt_address); json_hex(&writer, "data", event->state.interrupt_data);
        json_string_n(&writer, "action", event->state.action, sizeof(event->state.action)); json_u32(&writer, "index", event->state.irq_index);
        json_u32(&writer, "start", event->state.irq_start); json_u32(&writer, "count", event->state.irq_count); json_u32(&writer, "irte_index", event->state.irte_index);
        json_u32(&writer, "gsi", event->state.gsi); json_u32(&writer, "vcpu_id", event->state.vcpu_id); json_bool(&writer, "posted", event->state.posted);
        json_hex(&writer, "pi_desc_address", event->state.pi_desc_address); json_object_end(&writer);
    }
    if (is_iommu_event(event->event_info.kind)) {
        json_object_begin_field(&writer, "iommu"); json_hex(&writer, "domain", event->state.domain_address); json_hex(&writer, "unit", event->state.iommu_address);
        json_u32(&writer, "unit_id", event->state.iommu_id); json_hex(&writer, "iova", event->state.iova); json_hex(&writer, "size", event->state.size);
        json_bool(&writer, "invalidation_hint", event->state.invalidation_hint); json_bool(&writer, "mapping_invalidation", event->state.invalidation_map);
        json_u32(&writer, "qi_count", event->state.qi_count); json_u32(&writer, "qi_options", event->state.qi_options);
        json_hex(&writer, "qi_descriptor_0", event->state.qi_descriptor_0); json_hex(&writer, "qi_descriptor_1", event->state.qi_descriptor_1); json_object_end(&writer);
    }
    if (is_guest_event(event->event_info.kind)) {
        json_object_begin_field(&writer, "execution"); json_u64(&writer, "episode_id", event->state.episode_id);
        json_string(&writer, "phase", guest_phase_name(event->state.guest_phase));
        if (event->event_info.kind == VTD_EVENT_GUEST_IRQ_ENTRY || event->event_info.kind == VTD_EVENT_GUEST_IRQ_EXIT) {
            json_u32(&writer, "irq", event->state.irq); json_string_n(&writer, "action", event->state.action, sizeof(event->state.action));
        }
        json_object_end(&writer);
    }
    json_object_end(&writer); json_object_end(&writer); json_newline(&writer); fflush(stdout);
    if (!json_writer_ok(&writer)) return -EIO;
    event_count++;
    return 0;
}

static int emit_summary(uint64_t dropped)
{
    struct json_writer writer;
    json_writer_init(&writer, stdout);
    begin_record(&writer, "capture_summary", "observer", monotonic_time_ns());
    json_object_begin_field(&writer, "event_info"); json_string(&writer, "observer", current_mode == CAPTURE_HOST ? "host-ebpf" : "guest-ebpf"); json_object_end(&writer);
    emit_empty_context(&writer);
    json_object_begin_field(&writer, "state"); json_u32(&writer, "events", event_count); json_u64(&writer, "ringbuf_dropped", dropped); json_u32(&writer, "short_records", short_record_count); json_object_end(&writer);
    json_object_end(&writer); json_newline(&writer); fflush(stdout);
    return json_writer_ok(&writer) ? 0 : -EIO;
}

static struct bpf_link *attach_required(struct bpf_program *program)
{
    struct bpf_link *link = bpf_program__attach(program);
    return libbpf_get_error(link) ? NULL : link;
}

static struct bpf_link *attach_optional(struct bpf_program *program, bool ret, const char *symbol, bool *available)
{
    struct bpf_link *link = bpf_program__attach_kprobe(program, ret, symbol);
    if (libbpf_get_error(link)) { *available = false; return NULL; }
    *available = true;
    return link;
}

static struct bpf_link *attach_optional_program(struct bpf_program *program, bool *available)
{
    struct bpf_link *link = bpf_program__attach(program);
    if (libbpf_get_error(link)) { *available = false; return NULL; }
    *available = true;
    return link;
}

static int attach_host_programs(struct vtd_bpf *s, struct bpf_link **links, unsigned int *count, struct capture_features *f)
{
    unsigned int first = *count;
    links[(*count)++] = attach_required(s->progs.enter_ioctl); links[(*count)++] = attach_required(s->progs.exit_ioctl);
    links[(*count)++] = attach_required(s->progs.iommu_map); links[(*count)++] = attach_required(s->progs.iommu_unmap); links[(*count)++] = attach_required(s->progs.attach_device);
    for (unsigned int i = first; i < *count; i++) if (!links[i]) return -ENOENT;
    links[(*count)++] = attach_optional(s->progs.host_irte_activate, false, "intel_irq_remapping_activate", &f->irte_activate);
    links[(*count)++] = attach_optional(s->progs.host_ir_msi_entry, false, "intel_ir_compose_msi_msg", &f->ir_msi_entry);
    links[(*count)++] = attach_optional(s->progs.host_ir_msi_exit, true, "intel_ir_compose_msi_msg", &f->ir_msi_exit);
    links[(*count)++] = attach_optional_program(s->progs.host_kvm_pi_irte_update, &f->kvm_pi_irte_update);
    links[(*count)++] = attach_optional(s->progs.host_domain_attach_enter, false, "domain_attach_iommu", &f->domain_attach_enter);
    links[(*count)++] = attach_optional(s->progs.host_domain_attach_exit, true, "domain_attach_iommu", &f->domain_attach_exit);
    links[(*count)++] = attach_optional(s->progs.host_qi_submit, false, "qi_submit_sync", &f->qi_submit);
    links[(*count)++] = attach_optional(s->progs.host_qi_complete, true, "qi_submit_sync", &f->qi_complete);
    return 0;
}

static int attach_guest_programs(struct vtd_bpf *s, struct bpf_link **links, unsigned int *count, struct capture_features *f)
{
    const char *symbol = !strcmp(guest_driver, "igb") ? "igb_run_loopback_test" : "ixgbe_run_loopback_test";
    links[(*count)++] = attach_optional(s->progs.guest_run_entry, false, symbol, &f->guest_run_entry);
    links[(*count)++] = attach_optional(s->progs.guest_run_exit, true, symbol, &f->guest_run_exit);
    links[(*count)++] = attach_optional(s->progs.guest_dma_map_entry, false, "dma_map_page_attrs", &f->guest_dma_map_entry);
    links[(*count)++] = attach_optional(s->progs.guest_dma_map_exit, true, "dma_map_page_attrs", &f->guest_dma_map_exit);
    links[(*count)++] = attach_optional_program(s->progs.guest_irq_entry, &f->guest_irq_entry);
    links[(*count)++] = attach_optional_program(s->progs.guest_irq_exit, &f->guest_irq_exit);
    return f->guest_run_entry && f->guest_run_exit && f->guest_dma_map_entry && f->guest_dma_map_exit && f->guest_irq_entry && f->guest_irq_exit ? 0 : -ENOENT;
}

int main(int argc, char **argv)
{
    struct capture_features features = {};
    struct vtd_bpf *skeleton = NULL;
    struct ring_buffer *ring_buffer = NULL;
    struct bpf_link *links[MAX_LINKS] = {};
    unsigned int link_count = 0;
    uint64_t dropped = 0;
    uint32_t map_key = 0;
    int poll_result = 0, status = 1;

    if (argc == 4 && !strcmp(argv[1], "--guest")) {
        current_mode = CAPTURE_GUEST;
        guest_interface = argv[2];
        guest_driver = argv[3];
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [--guest interface driver]\n", argv[0]);
        return 2;
    }
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal); signal(SIGUSR1, on_signal); signal(SIGUSR2, on_signal);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    skeleton = vtd_bpf__open();
    if (skeleton && current_mode == CAPTURE_GUEST)
        snprintf(skeleton->rodata->target_interface, sizeof(skeleton->rodata->target_interface), "%s", guest_interface);
    if (!skeleton || vtd_bpf__load(skeleton)) goto cleanup;
    if ((current_mode == CAPTURE_HOST && attach_host_programs(skeleton, links, &link_count, &features)) ||
        (current_mode == CAPTURE_GUEST && attach_guest_programs(skeleton, links, &link_count, &features))) goto cleanup;
    ring_buffer = ring_buffer__new(bpf_map__fd(skeleton->maps.events), emit_record, NULL, NULL);
    if (!ring_buffer || emit_meta(&features)) goto cleanup;
    lab_control("LX_READY experiment=virt-vtd observer=%s clock=monotonic\n", current_mode == CAPTURE_HOST ? "host" : "guest");
    while (!stop_requested) {
        poll_result = ring_buffer__poll(ring_buffer, 250);
        if (poll_result < 0 && poll_result != -EINTR) break;
        if (gate_request >= 0) {
            uint32_t enabled = gate_request;
            if (emit_gate_marker(enabled)) goto cleanup;
            lab_control("LX_GATE enabled=%u\n", enabled); gate_request = -1;
        }
    }
    for (unsigned int i = 0; i < link_count; i++) { bpf_link__destroy(links[i]); links[i] = NULL; }
    stop_requested = 1;
    if (lab_poll(ring_buffer, &stop_requested) < 0) goto cleanup;
    if (bpf_map_lookup_elem(bpf_map__fd(skeleton->maps.dropped_events), &map_key, &dropped)) goto cleanup;
    if (emit_summary(dropped)) goto cleanup;
    status = (poll_result < 0 && poll_result != -EINTR) || dropped || short_record_count;
    if (lab_health(dropped, skeleton->bss->lab_failures + short_record_count)) status = 1;
cleanup:
    ring_buffer__free(ring_buffer);
    for (unsigned int i = 0; i < link_count; i++) bpf_link__destroy(links[i]);
    vtd_bpf__destroy(skeleton);
    lab_control("LX_DONE experiment=virt-vtd observer=%s events=%u dropped=%llu short=%u\n", current_mode == CAPTURE_HOST ? "host" : "guest", event_count, (unsigned long long)dropped, short_record_count);
    return status;
}
