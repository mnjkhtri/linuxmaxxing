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
#include "vtd.skel.h"
#include "vtd_event.h"

#define VTD_SCHEMA_VERSION 8
#define MAX_LINKS 96

enum capture_mode {
    CAPTURE_HOST,
    CAPTURE_GUEST,
};

struct capture_features {
    bool vfio_type1_map_enter;
    bool vfio_type1_map_exit;
    bool page_pin_enter;
    bool page_pin_exit;
    bool page_unpin_enter;
    bool page_unpin_exit;
    bool vfio_msi;
    bool vfio_intx;
    bool irqfd_wakeup;
    bool kvm_msi_route;
    bool kvm_apic_accept;
    bool kvm_mmio;
    bool irte_alloc_enter;
    bool irte_index;
    bool irte_alloc_exit;
    bool irte_activate;
    bool ir_msi_entry;
    bool ir_msi_exit;
    bool kvm_pi_irte_update;
    bool iommu_fault;
    bool domain_attach_enter;
    bool domain_attach_exit;
    bool iotlb_invalidate;
    bool qi_submit;
    bool qi_complete;
    bool pi_sync_enter;
    bool pi_sync_exit;
    bool pi_wakeup;
    bool pi_wakeup_exit;
    bool pi_vcpu_wake_up;
    bool pi_wakeup_vector;
    bool guest_run_entry;
    bool guest_run_exit;
    bool guest_xmit_entry;
    bool guest_xmit_exit;
    bool guest_dma_map_entry;
    bool guest_dma_map_exit;
    bool guest_clean_entry;
    bool guest_clean_exit;
    bool guest_dma_unmap;
    bool guest_dma_sync_cpu;
    bool guest_dma_sync_device;
    bool guest_irq_entry;
    bool guest_irq_exit;
    bool guest_netdev_open;
    bool guest_netdev_close;
    bool guest_diag_entry;
    bool guest_diag_exit;
    bool guest_intr_test_entry;
    bool guest_intr_test_exit;
    bool guest_loopback_entry;
    bool guest_loopback_exit;
    bool guest_softirq_raise;
    bool guest_softirq_entry;
    bool guest_napi_poll;
    bool guest_softirq_exit;
};

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t gate_request = -1;
static unsigned int sequence;
static unsigned int event_count;
static unsigned int short_record_count;
static enum capture_mode current_mode = CAPTURE_HOST;
static const char *guest_interface = "";

static void on_signal(int signal_number)
{
    if (signal_number == SIGUSR1)
        gate_request = 1;
    else if (signal_number == SIGUSR2)
        gate_request = 0;
    else
        stop_requested = 1;
}

static uint64_t monotonic_time_ns(void)
{
    struct timespec now = {};

    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static uint64_t realtime_time_ns(void)
{
    struct timespec now = {};

    if (clock_gettime(CLOCK_REALTIME, &now))
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static const char *operation_name(unsigned int operation)
{
    if (operation == VTD_OP_VFIO_MAP)
        return "vfio_dma_map";
    if (operation == VTD_OP_VFIO_UNMAP)
        return "vfio_dma_unmap";
    if (operation == VTD_OP_KVM_MEMORY_REGION)
        return "kvm_memory_region";
    if (operation == VTD_OP_VFIO_IRQ_SET)
        return "vfio_irq_set";
    return "none";
}

static const char *sample_status_name(unsigned int status)
{
    if (status == VTD_SAMPLE_READ_FAILED)
        return "read_failed";
    if (status == VTD_SAMPLE_INVALID_ARGUMENT)
        return "invalid_argument";
    return "complete";
}

static const char *guest_phase_name(unsigned int phase)
{
    switch (phase) {
    case VTD_GUEST_PHASE_INTERFACE_START:
        return "interface_start";
    case VTD_GUEST_PHASE_OFFLINE_DIAG:
        return "offline_diag";
    case VTD_GUEST_PHASE_INTR_TEST:
        return "intr_test";
    case VTD_GUEST_PHASE_LOOPBACK_SETUP:
        return "loopback_setup";
    case VTD_GUEST_PHASE_LOOPBACK_RUN:
        return "loopback_run";
    case VTD_GUEST_PHASE_INTERFACE_RESTORE:
        return "interface_restore";
    default:
        return "none";
    }
}

static const char *softirq_name(unsigned int vector)
{
    static const char *const names[] = {"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU"};

    return vector < sizeof(names) / sizeof(names[0]) ? names[vector] : "UNKNOWN";
}

static bool is_guest_execution_event(unsigned int kind)
{
    return (kind >= VTD_EVENT_GUEST_RUN_ENTRY && kind <= VTD_EVENT_GUEST_NETDEV_CLOSE) ||
        (kind >= VTD_EVENT_GUEST_DIAG_ENTRY && kind <= VTD_EVENT_GUEST_SOFTIRQ_EXIT);
}

static const char *event_name(const struct vtd_event *event)
{
    switch (event->event_info.kind) {
    case VTD_EVENT_IOCTL_ENTER:
        if (event->event_info.operation == VTD_OP_KVM_MEMORY_REGION)
            return "kvm_memory_region_enter";
        if (event->event_info.operation == VTD_OP_VFIO_IRQ_SET)
            return "vfio_irq_set_enter";
        return event->event_info.operation == VTD_OP_VFIO_MAP ? "vfio_dma_map_enter" : "vfio_dma_unmap_enter";
    case VTD_EVENT_IOCTL_EXIT:
        if (event->event_info.operation == VTD_OP_KVM_MEMORY_REGION)
            return "kvm_memory_region_exit";
        if (event->event_info.operation == VTD_OP_VFIO_IRQ_SET)
            return "vfio_irq_set_exit";
        return event->event_info.operation == VTD_OP_VFIO_MAP ? "vfio_dma_map_exit" : "vfio_dma_unmap_exit";
    case VTD_EVENT_IOMMU_MAP:
        return "iommu_map";
    case VTD_EVENT_IOMMU_UNMAP:
        return "iommu_unmap";
    case VTD_EVENT_DEVICE_ATTACH:
        return "iommu_device_attach";
    case VTD_EVENT_VFIO_MAP_ENTER:
        return "vfio_type1_map_enter";
    case VTD_EVENT_VFIO_MAP_EXIT:
        return "vfio_type1_map_exit";
    case VTD_EVENT_PAGE_PIN_ENTER:
        return "vfio_page_pin_enter";
    case VTD_EVENT_PAGE_PIN_EXIT:
        return "vfio_page_pin_exit";
    case VTD_EVENT_PAGE_UNPIN_ENTER:
        return "vfio_page_unpin_enter";
    case VTD_EVENT_PAGE_UNPIN_EXIT:
        return "vfio_page_unpin_exit";
    case VTD_EVENT_VFIO_MSI_ENTRY:
        return "vfio_msi_handler_entry";
    case VTD_EVENT_VFIO_MSI_EXIT:
        return "vfio_msi_handler_exit";
    case VTD_EVENT_VFIO_INTX_ENTRY:
        return "vfio_intx_handler_entry";
    case VTD_EVENT_VFIO_INTX_EXIT:
        return "vfio_intx_handler_exit";
    case VTD_EVENT_IRQFD_WAKEUP:
        return "kvm_irqfd_wakeup";
    case VTD_EVENT_KVM_MSI_ROUTE:
        return "kvm_msi_route";
    case VTD_EVENT_KVM_APIC_ACCEPT:
        return "kvm_apic_accept_irq";
    case VTD_EVENT_KVM_MMIO:
        return "kvm_mmio";
    case VTD_EVENT_IRTE_ALLOC:
        return "irte_alloc";
    case VTD_EVENT_IRTE_ACTIVATE:
        return "irte_activate";
    case VTD_EVENT_IR_MSI_MESSAGE:
        return "interrupt_remap_msi_message";
    case VTD_EVENT_KVM_PI_IRTE_UPDATE:
        return "kvm_pi_irte_update";
    case VTD_EVENT_GUEST_RUN_ENTRY:
        return "guest_ixgbe_run_loopback_entry";
    case VTD_EVENT_GUEST_RUN_EXIT:
        return "guest_ixgbe_run_loopback_exit";
    case VTD_EVENT_GUEST_XMIT_ENTRY:
        return "guest_ixgbe_xmit_entry";
    case VTD_EVENT_GUEST_DMA_MAP_ENTRY:
        return "guest_dma_map_entry";
    case VTD_EVENT_GUEST_DMA_MAP_EXIT:
        return "guest_dma_map_exit";
    case VTD_EVENT_GUEST_XMIT_EXIT:
        return "guest_ixgbe_xmit_exit";
    case VTD_EVENT_GUEST_CLEAN_ENTRY:
        return "guest_ixgbe_clean_entry";
    case VTD_EVENT_GUEST_DMA_UNMAP:
        return "guest_dma_unmap";
    case VTD_EVENT_GUEST_DMA_SYNC_CPU:
        return "guest_dma_sync_for_cpu";
    case VTD_EVENT_GUEST_DMA_SYNC_DEVICE:
        return "guest_dma_sync_for_device";
    case VTD_EVENT_GUEST_CLEAN_EXIT:
        return "guest_ixgbe_clean_exit";
    case VTD_EVENT_GUEST_IRQ_ENTRY:
        return "guest_irq_handler_entry";
    case VTD_EVENT_GUEST_IRQ_EXIT:
        return "guest_irq_handler_exit";
    case VTD_EVENT_GUEST_NETDEV_OPEN:
        return "guest_ixgbe_open";
    case VTD_EVENT_GUEST_NETDEV_CLOSE:
        return "guest_ixgbe_close";
    case VTD_EVENT_GUEST_DIAG_ENTRY:
        return "guest_ixgbe_diag_entry";
    case VTD_EVENT_GUEST_DIAG_EXIT:
        return "guest_ixgbe_diag_exit";
    case VTD_EVENT_GUEST_INTR_TEST_ENTRY:
        return "guest_ixgbe_intr_test_entry";
    case VTD_EVENT_GUEST_INTR_TEST_EXIT:
        return "guest_ixgbe_intr_test_exit";
    case VTD_EVENT_GUEST_LOOPBACK_ENTRY:
        return "guest_ixgbe_loopback_test_entry";
    case VTD_EVENT_GUEST_LOOPBACK_EXIT:
        return "guest_ixgbe_loopback_test_exit";
    case VTD_EVENT_GUEST_SOFTIRQ_RAISE:
        return "guest_softirq_raise";
    case VTD_EVENT_GUEST_SOFTIRQ_ENTRY:
        return "guest_softirq_entry";
    case VTD_EVENT_GUEST_NAPI_POLL:
        return "guest_napi_poll";
    case VTD_EVENT_GUEST_SOFTIRQ_EXIT:
        return "guest_softirq_exit";
    case VTD_EVENT_IOMMU_FAULT:
        return "iommu_page_fault";
    case VTD_EVENT_DOMAIN_ATTACH_ENTER:
        return "iommu_domain_attach_enter";
    case VTD_EVENT_DOMAIN_ATTACH_EXIT:
        return "iommu_domain_attach_exit";
    case VTD_EVENT_IOTLB_INVALIDATE:
        return "iommu_iotlb_invalidate";
    case VTD_EVENT_QI_SUBMIT:
        return "iommu_qi_submit";
    case VTD_EVENT_QI_COMPLETE:
        return "iommu_qi_complete";
    case VTD_EVENT_PI_SYNC_EXIT:
        return "kvm_pi_sync_pir_to_irr_exit";
    case VTD_EVENT_PI_WAKEUP:
        return "kvm_pi_wakeup";
    case VTD_EVENT_PI_WAKEUP_VECTOR:
        return "kvm_pi_wakeup_vector";
    default:
        return "unknown";
    }
}

static const char *event_hook(const struct vtd_event *event)
{
    switch (event->event_info.kind) {
    case VTD_EVENT_IOMMU_MAP:
        return "iommu:map";
    case VTD_EVENT_IOMMU_UNMAP:
        return "iommu:unmap";
    case VTD_EVENT_DEVICE_ATTACH:
        return "iommu:attach_device_to_domain";
    case VTD_EVENT_VFIO_MAP_ENTER:
        return "kprobe:vfio_iommu_type1_map_dma";
    case VTD_EVENT_VFIO_MAP_EXIT:
        return "kretprobe:vfio_iommu_type1_map_dma";
    case VTD_EVENT_PAGE_PIN_ENTER:
        return "kprobe:vfio_pin_pages_remote";
    case VTD_EVENT_PAGE_PIN_EXIT:
        return "kretprobe:vfio_pin_pages_remote";
    case VTD_EVENT_PAGE_UNPIN_ENTER:
        return "kprobe:vfio_unpin_pages_remote";
    case VTD_EVENT_PAGE_UNPIN_EXIT:
        return "kretprobe:vfio_unpin_pages_remote";
    case VTD_EVENT_VFIO_MSI_ENTRY:
        return "kprobe:vfio_msihandler";
    case VTD_EVENT_VFIO_MSI_EXIT:
        return "kretprobe:vfio_msihandler";
    case VTD_EVENT_VFIO_INTX_ENTRY:
        return "kprobe:vfio_intx_handler";
    case VTD_EVENT_VFIO_INTX_EXIT:
        return "kretprobe:vfio_intx_handler";
    case VTD_EVENT_IRQFD_WAKEUP:
        return "kprobe:irqfd_wakeup";
    case VTD_EVENT_KVM_MSI_ROUTE:
        return "kvm:kvm_msi_set_irq";
    case VTD_EVENT_KVM_APIC_ACCEPT:
        return "kvm:kvm_apic_accept_irq";
    case VTD_EVENT_KVM_MMIO:
        return "kvm:kvm_mmio";
    case VTD_EVENT_IRTE_ALLOC:
        return "kretprobe:alloc_irte";
    case VTD_EVENT_IRTE_ACTIVATE:
        return "kprobe:intel_irq_remapping_activate";
    case VTD_EVENT_IR_MSI_MESSAGE:
        return "kretprobe:intel_ir_compose_msi_msg";
    case VTD_EVENT_KVM_PI_IRTE_UPDATE:
        return "kvm:kvm_pi_irte_update";
    case VTD_EVENT_GUEST_RUN_ENTRY:
        return "kprobe:ixgbe_run_loopback_test";
    case VTD_EVENT_GUEST_RUN_EXIT:
        return "kretprobe:ixgbe_run_loopback_test";
    case VTD_EVENT_GUEST_XMIT_ENTRY:
        return "kprobe:ixgbe_xmit_frame_ring";
    case VTD_EVENT_GUEST_DMA_MAP_ENTRY:
        return "kprobe:dma_map_page_attrs";
    case VTD_EVENT_GUEST_DMA_MAP_EXIT:
        return "kretprobe:dma_map_page_attrs";
    case VTD_EVENT_GUEST_XMIT_EXIT:
        return "kretprobe:ixgbe_xmit_frame_ring";
    case VTD_EVENT_GUEST_CLEAN_ENTRY:
        return "kprobe:ixgbe_clean_test_rings";
    case VTD_EVENT_GUEST_DMA_UNMAP:
        return "kprobe:dma_unmap_page_attrs";
    case VTD_EVENT_GUEST_DMA_SYNC_CPU:
        return "kprobe:dma_sync_single_for_cpu";
    case VTD_EVENT_GUEST_DMA_SYNC_DEVICE:
        return "kprobe:dma_sync_single_for_device";
    case VTD_EVENT_GUEST_CLEAN_EXIT:
        return "kretprobe:ixgbe_clean_test_rings";
    case VTD_EVENT_GUEST_IRQ_ENTRY:
        return "irq:irq_handler_entry";
    case VTD_EVENT_GUEST_IRQ_EXIT:
        return "irq:irq_handler_exit";
    case VTD_EVENT_GUEST_NETDEV_OPEN:
        return "kprobe:ixgbe_open";
    case VTD_EVENT_GUEST_NETDEV_CLOSE:
        return "kprobe:ixgbe_close";
    case VTD_EVENT_GUEST_DIAG_ENTRY:
        return "kprobe:ixgbe_diag_test";
    case VTD_EVENT_GUEST_DIAG_EXIT:
        return "kretprobe:ixgbe_diag_test";
    case VTD_EVENT_GUEST_INTR_TEST_ENTRY:
        return "kprobe:ixgbe_intr_test";
    case VTD_EVENT_GUEST_INTR_TEST_EXIT:
        return "kretprobe:ixgbe_intr_test";
    case VTD_EVENT_GUEST_LOOPBACK_ENTRY:
        return "kprobe:ixgbe_loopback_test";
    case VTD_EVENT_GUEST_LOOPBACK_EXIT:
        return "kretprobe:ixgbe_loopback_test";
    case VTD_EVENT_GUEST_SOFTIRQ_RAISE:
        return "irq:softirq_raise";
    case VTD_EVENT_GUEST_SOFTIRQ_ENTRY:
        return "irq:softirq_entry";
    case VTD_EVENT_GUEST_NAPI_POLL:
        return "napi:napi_poll";
    case VTD_EVENT_GUEST_SOFTIRQ_EXIT:
        return "irq:softirq_exit";
    case VTD_EVENT_IOMMU_FAULT:
        return "iommu:io_page_fault";
    case VTD_EVENT_DOMAIN_ATTACH_ENTER:
        return "kprobe:domain_attach_iommu";
    case VTD_EVENT_DOMAIN_ATTACH_EXIT:
        return "kretprobe:domain_attach_iommu";
    case VTD_EVENT_IOTLB_INVALIDATE:
        return "kprobe:iommu_flush_iotlb_psi";
    case VTD_EVENT_QI_SUBMIT:
        return "kprobe:qi_submit_sync";
    case VTD_EVENT_QI_COMPLETE:
        return "kretprobe:qi_submit_sync";
    case VTD_EVENT_PI_SYNC_EXIT:
        return "kretprobe:vmx_sync_pir_to_irr";
    case VTD_EVENT_PI_WAKEUP:
        return "kretprobe:pi_wakeup_handler";
    case VTD_EVENT_PI_WAKEUP_VECTOR:
        return "kprobe:sysvec_kvm_posted_intr_wakeup_ipi";
    default:
        return event->event_info.kind == VTD_EVENT_IOCTL_EXIT ? "syscalls:sys_exit_ioctl" : "syscalls:sys_enter_ioctl";
    }
}

static void begin_record(struct json_writer *writer, const char *kind, const char *source, uint64_t time_ns)
{
    json_object_begin(writer);
    json_u32(writer, "schema_version", VTD_SCHEMA_VERSION);
    json_string(writer, "experiment", "virt-vtd");
    json_string(writer, "kind", kind);
    json_string(writer, "source", source);
    json_u32(writer, "seq", ++sequence);
    json_u64(writer, "time_ns", time_ns);
    json_string(writer, "clock", "monotonic");
}

static int emit_meta(const struct capture_features *features)
{
    struct json_writer writer;
    uint64_t monotonic_ns = monotonic_time_ns();

    json_writer_init(&writer, stdout);
    begin_record(&writer, "capture_meta", "observer", monotonic_ns);
    json_object_begin_field(&writer, "event_info");
    json_string(&writer, "observer", current_mode == CAPTURE_HOST ? "host-ebpf" : "guest-ebpf");
    json_string(&writer, "filter", current_mode == CAPTURE_HOST ? "qemu-control + gated-vfio-irq-chain" : guest_interface);
    json_object_end(&writer);
    json_object_begin_field(&writer, "context");
    json_null(&writer, "pid");
    json_null(&writer, "tid");
    json_null(&writer, "cpu");
    json_null(&writer, "comm");
    json_object_end(&writer);
    json_object_begin_field(&writer, "state");
    json_object_begin_field(&writer, "clock_anchor");
    json_u64(&writer, "monotonic_ns", monotonic_ns);
    json_u64(&writer, "realtime_ns", realtime_time_ns());
    json_object_end(&writer);
    json_object_begin_field(&writer, "hooks");
    json_bool(&writer, "syscall_ioctl", current_mode == CAPTURE_HOST);
    json_bool(&writer, "iommu_map", current_mode == CAPTURE_HOST);
    json_bool(&writer, "iommu_unmap", current_mode == CAPTURE_HOST);
    json_bool(&writer, "iommu_device_attach", current_mode == CAPTURE_HOST);
    json_bool(&writer, "vfio_type1_map_enter", features->vfio_type1_map_enter);
    json_bool(&writer, "vfio_type1_map_exit", features->vfio_type1_map_exit);
    json_bool(&writer, "page_pin_enter", features->page_pin_enter);
    json_bool(&writer, "page_pin_exit", features->page_pin_exit);
    json_bool(&writer, "page_unpin_enter", features->page_unpin_enter);
    json_bool(&writer, "page_unpin_exit", features->page_unpin_exit);
    json_bool(&writer, "vfio_msi", features->vfio_msi);
    json_bool(&writer, "vfio_intx", features->vfio_intx);
    json_bool(&writer, "irqfd_wakeup", features->irqfd_wakeup);
    json_bool(&writer, "kvm_msi_route", features->kvm_msi_route);
    json_bool(&writer, "kvm_apic_accept", features->kvm_apic_accept);
    json_bool(&writer, "kvm_mmio", features->kvm_mmio);
    json_bool(&writer, "irte_alloc_enter", features->irte_alloc_enter);
    json_bool(&writer, "irte_index", features->irte_index);
    json_bool(&writer, "irte_alloc_exit", features->irte_alloc_exit);
    json_bool(&writer, "irte_activate", features->irte_activate);
    json_bool(&writer, "ir_msi_entry", features->ir_msi_entry);
    json_bool(&writer, "ir_msi_exit", features->ir_msi_exit);
    json_bool(&writer, "kvm_pi_irte_update", features->kvm_pi_irte_update);
    json_bool(&writer, "iommu_fault", features->iommu_fault);
    json_bool(&writer, "domain_attach_enter", features->domain_attach_enter);
    json_bool(&writer, "domain_attach_exit", features->domain_attach_exit);
    json_bool(&writer, "iotlb_invalidate", features->iotlb_invalidate);
    json_bool(&writer, "qi_submit", features->qi_submit);
    json_bool(&writer, "qi_complete", features->qi_complete);
    json_bool(&writer, "pi_sync_enter", features->pi_sync_enter);
    json_bool(&writer, "pi_sync_exit", features->pi_sync_exit);
    json_bool(&writer, "pi_wakeup", features->pi_wakeup);
    json_bool(&writer, "pi_wakeup_exit", features->pi_wakeup_exit);
    json_bool(&writer, "pi_vcpu_wake_up", features->pi_vcpu_wake_up);
    json_bool(&writer, "pi_wakeup_vector", features->pi_wakeup_vector);
    json_bool(&writer, "guest_run_entry", features->guest_run_entry);
    json_bool(&writer, "guest_run_exit", features->guest_run_exit);
    json_bool(&writer, "guest_xmit_entry", features->guest_xmit_entry);
    json_bool(&writer, "guest_xmit_exit", features->guest_xmit_exit);
    json_bool(&writer, "guest_dma_map_entry", features->guest_dma_map_entry);
    json_bool(&writer, "guest_dma_map_exit", features->guest_dma_map_exit);
    json_bool(&writer, "guest_clean_entry", features->guest_clean_entry);
    json_bool(&writer, "guest_clean_exit", features->guest_clean_exit);
    json_bool(&writer, "guest_dma_unmap", features->guest_dma_unmap);
    json_bool(&writer, "guest_dma_sync_cpu", features->guest_dma_sync_cpu);
    json_bool(&writer, "guest_dma_sync_device", features->guest_dma_sync_device);
    json_bool(&writer, "guest_irq_entry", features->guest_irq_entry);
    json_bool(&writer, "guest_irq_exit", features->guest_irq_exit);
    json_bool(&writer, "guest_netdev_open", features->guest_netdev_open);
    json_bool(&writer, "guest_netdev_close", features->guest_netdev_close);
    json_bool(&writer, "guest_diag_entry", features->guest_diag_entry);
    json_bool(&writer, "guest_diag_exit", features->guest_diag_exit);
    json_bool(&writer, "guest_intr_test_entry", features->guest_intr_test_entry);
    json_bool(&writer, "guest_intr_test_exit", features->guest_intr_test_exit);
    json_bool(&writer, "guest_loopback_entry", features->guest_loopback_entry);
    json_bool(&writer, "guest_loopback_exit", features->guest_loopback_exit);
    json_bool(&writer, "guest_softirq_raise", features->guest_softirq_raise);
    json_bool(&writer, "guest_softirq_entry", features->guest_softirq_entry);
    json_bool(&writer, "guest_napi_poll", features->guest_napi_poll);
    json_bool(&writer, "guest_softirq_exit", features->guest_softirq_exit);
    json_object_end(&writer);
    json_object_end(&writer);
    json_object_end(&writer);
    json_newline(&writer);
    fflush(stdout);
    return json_writer_ok(&writer) ? 0 : -EIO;
}

static int emit_gate_marker(unsigned int enabled)
{
    struct json_writer writer;
    uint64_t monotonic_ns = monotonic_time_ns();

    json_writer_init(&writer, stdout);
    begin_record(&writer, enabled ? "workload_begin" : "workload_end", "observer", monotonic_ns);
    json_object_begin_field(&writer, "event_info");
    json_string(&writer, "boundary", enabled ? "begin" : "end");
    json_object_end(&writer);
    json_object_begin_field(&writer, "context");
    json_null(&writer, "pid");
    json_null(&writer, "tid");
    json_null(&writer, "cpu");
    json_null(&writer, "comm");
    json_object_end(&writer);
    json_object_begin_field(&writer, "state");
    json_object_begin_field(&writer, "clock_anchor");
    json_u64(&writer, "monotonic_ns", monotonic_ns);
    json_u64(&writer, "realtime_ns", realtime_time_ns());
    json_object_end(&writer);
    json_object_end(&writer);
    json_object_end(&writer);
    json_newline(&writer);
    fflush(stdout);
    if (!json_writer_ok(&writer))
        return -EIO;
    event_count++;
    return 0;
}

static int emit_record(void *ctx, void *data, size_t size)
{
    struct json_writer writer;
    const struct vtd_event *event = data;

    (void)ctx;
    if (size < sizeof(*event)) {
        short_record_count++;
        return 0;
    }

    json_writer_init(&writer, stdout);
    begin_record(&writer, event_name(event), current_mode == CAPTURE_HOST ? "host-ebpf" : "guest-ebpf", event->time_ns);
    json_object_begin_field(&writer, "event_info");
    json_string(&writer, "hook", event_hook(event));
    json_string(&writer, "operation", operation_name(event->event_info.operation));
    json_u64(&writer, "request_id", event->event_info.request_id);
    json_bool(&writer, "correlated", event->event_info.correlated);
    json_string(&writer, "sample_status", sample_status_name(event->event_info.sample_status));
    json_u32(&writer, "fd", event->event_info.fd);
    json_hex(&writer, "command", event->event_info.command);
    json_u32(&writer, "argsz", event->event_info.argsz);
    json_u32(&writer, "flags", event->event_info.flags);
    json_u32(&writer, "slot", event->event_info.slot);
    json_i64(&writer, "result", event->event_info.result);
    json_object_end(&writer);

    json_object_begin_field(&writer, "context");
    json_u32(&writer, "pid", event->context.pid);
    json_u32(&writer, "tid", event->context.tid);
    json_u32(&writer, "cpu", event->context.cpu);
    json_string_n(&writer, "comm", event->context.comm, sizeof(event->context.comm));
    json_object_end(&writer);

    json_object_begin_field(&writer, "state");
    if (event->event_info.kind <= VTD_EVENT_PAGE_UNPIN_EXIT && event->event_info.operation != VTD_OP_VFIO_IRQ_SET) {
        json_object_begin_field(&writer, "address_space");
        json_hex(&writer, "hva", event->state.hva);
        json_hex(&writer, "gpa", event->state.gpa);
        json_hex(&writer, "iova", event->state.iova);
        json_hex(&writer, "hpa", event->state.hpa);
        json_hex(&writer, "size", event->state.size);
        json_hex(&writer, "returned_size", event->state.returned_size);
        json_hex(&writer, "parent_iova", event->state.parent_iova);
        json_hex(&writer, "parent_size", event->state.parent_size);
        json_u64(&writer, "page_count", event->state.page_count);
        json_object_end(&writer);
        json_string_n(&writer, "device", event->state.device, sizeof(event->state.device));
    }
    if (event->event_info.kind >= VTD_EVENT_GUEST_XMIT_ENTRY && event->event_info.kind <= VTD_EVENT_GUEST_CLEAN_EXIT) {
        json_object_begin_field(&writer, "dma");
        json_hex(&writer, "address", event->state.dma_address);
        json_u64(&writer, "length", event->state.data_length);
        json_u32(&writer, "direction", event->state.dma_direction);
        json_u32(&writer, "completed_descriptors", event->state.count);
        json_object_end(&writer);
    }
    if ((event->event_info.kind >= VTD_EVENT_VFIO_MSI_ENTRY && event->event_info.kind <= VTD_EVENT_KVM_APIC_ACCEPT) ||
        (event->event_info.kind >= VTD_EVENT_IRTE_ALLOC && event->event_info.kind <= VTD_EVENT_KVM_PI_IRTE_UPDATE) ||
        (event->event_info.kind >= VTD_EVENT_PI_SYNC_EXIT && event->event_info.kind <= VTD_EVENT_PI_WAKEUP_VECTOR) ||
        event->event_info.operation == VTD_OP_VFIO_IRQ_SET || event->event_info.kind == VTD_EVENT_GUEST_IRQ_ENTRY || event->event_info.kind == VTD_EVENT_GUEST_IRQ_EXIT) {
        json_object_begin_field(&writer, "interrupt");
        json_u32(&writer, "irq", event->state.irq);
        json_u32(&writer, "vector", event->state.vector);
        json_u32(&writer, "apic_id", event->state.apic_id);
        json_hex(&writer, "address", event->state.interrupt_address);
        json_hex(&writer, "data", event->state.interrupt_data);
        json_string_n(&writer, "action", event->state.action, sizeof(event->state.action));
        json_u32(&writer, "index", event->state.irq_index);
        json_u32(&writer, "start", event->state.irq_start);
        json_u32(&writer, "count", event->state.irq_count);
        json_u32(&writer, "irte_index", event->state.irte_index);
        json_u32(&writer, "gsi", event->state.gsi);
        json_u32(&writer, "vcpu_id", event->state.vcpu_id);
        json_bool(&writer, "posted", event->state.posted);
        json_hex(&writer, "pi_desc_address", event->state.pi_desc_address);
        if (event->event_info.kind == VTD_EVENT_PI_WAKEUP)
            json_u32(&writer, "wakeup_count", event->state.wakeup_count);
        json_object_end(&writer);
    }
    if (event->event_info.kind == VTD_EVENT_IOMMU_FAULT) {
        json_object_begin_field(&writer, "fault");
        json_string_n(&writer, "device", event->state.device, sizeof(event->state.device));
        json_string_n(&writer, "driver", event->state.driver, sizeof(event->state.driver));
        json_hex(&writer, "iova", event->state.iova);
        json_u32(&writer, "flags", event->event_info.flags);
        json_object_end(&writer);
    }
    if (event->event_info.kind >= VTD_EVENT_DOMAIN_ATTACH_ENTER && event->event_info.kind <= VTD_EVENT_QI_COMPLETE) {
        json_object_begin_field(&writer, "iommu");
        json_hex(&writer, "domain", event->state.domain_address);
        json_hex(&writer, "unit", event->state.iommu_address);
        json_u32(&writer, "unit_id", event->state.iommu_id);
        json_hex(&writer, "iova", event->state.iova);
        json_hex(&writer, "size", event->state.size);
        json_bool(&writer, "invalidation_hint", event->state.invalidation_hint);
        json_bool(&writer, "mapping_invalidation", event->state.invalidation_map);
        json_u32(&writer, "qi_count", event->state.qi_count);
        json_u32(&writer, "qi_options", event->state.qi_options);
        json_hex(&writer, "qi_descriptor_0", event->state.qi_descriptor_0);
        json_hex(&writer, "qi_descriptor_1", event->state.qi_descriptor_1);
        json_object_end(&writer);
    }
    if (event->event_info.kind == VTD_EVENT_KVM_MMIO) {
        json_object_begin_field(&writer, "mmio");
        json_hex(&writer, "gpa", event->state.gpa);
        json_hex(&writer, "value", event->state.mmio_value);
        json_u32(&writer, "length", event->state.mmio_length);
        json_u32(&writer, "type", event->state.mmio_type);
        json_object_end(&writer);
    }
    if (is_guest_execution_event(event->event_info.kind)) {
        json_object_begin_field(&writer, "execution");
        json_u64(&writer, "episode_id", event->state.episode_id);
        json_string(&writer, "phase", guest_phase_name(event->state.guest_phase));
        if (event->event_info.kind == VTD_EVENT_GUEST_IRQ_ENTRY || event->event_info.kind == VTD_EVENT_GUEST_IRQ_EXIT ||
            (event->event_info.kind >= VTD_EVENT_GUEST_SOFTIRQ_RAISE && event->event_info.kind <= VTD_EVENT_GUEST_SOFTIRQ_EXIT)) {
            json_u32(&writer, "irq", event->state.irq);
            json_string_n(&writer, "action", event->state.action, sizeof(event->state.action));
        }
        if (event->event_info.kind >= VTD_EVENT_GUEST_SOFTIRQ_RAISE && event->event_info.kind <= VTD_EVENT_GUEST_SOFTIRQ_EXIT) {
            json_u32(&writer, "softirq_vector", event->state.softirq_vector);
            json_string(&writer, "softirq", softirq_name(event->state.softirq_vector));
        }
        if (event->event_info.kind == VTD_EVENT_GUEST_NAPI_POLL) {
            json_u32(&writer, "napi_work", event->state.napi_work);
            json_u32(&writer, "napi_budget", event->state.napi_budget);
            json_string_n(&writer, "device", event->state.device, sizeof(event->state.device));
        }
        json_object_end(&writer);
    }
    json_object_end(&writer);
    json_object_end(&writer);
    json_newline(&writer);
    fflush(stdout);
    if (!json_writer_ok(&writer))
        return -EIO;
    event_count++;
    return 0;
}

static int emit_summary(uint64_t dropped)
{
    struct json_writer writer;

    json_writer_init(&writer, stdout);
    begin_record(&writer, "capture_summary", "observer", monotonic_time_ns());
    json_object_begin_field(&writer, "event_info");
    json_string(&writer, "observer", current_mode == CAPTURE_HOST ? "host-ebpf" : "guest-ebpf");
    json_object_end(&writer);
    json_object_begin_field(&writer, "context");
    json_null(&writer, "pid");
    json_null(&writer, "tid");
    json_null(&writer, "cpu");
    json_null(&writer, "comm");
    json_object_end(&writer);
    json_object_begin_field(&writer, "state");
    json_u32(&writer, "events", event_count);
    json_u64(&writer, "ringbuf_dropped", dropped);
    json_u32(&writer, "short_records", short_record_count);
    json_object_end(&writer);
    json_object_end(&writer);
    json_newline(&writer);
    fflush(stdout);
    return json_writer_ok(&writer) ? 0 : -EIO;
}

static struct bpf_link *attach_required(struct bpf_program *program)
{
    struct bpf_link *link = bpf_program__attach(program);

    if (libbpf_get_error(link))
        return NULL;
    return link;
}

static struct bpf_link *attach_optional(struct bpf_program *program, bool return_probe, const char *symbol, bool *available)
{
    struct bpf_link *link = bpf_program__attach_kprobe(program, return_probe, symbol);

    if (libbpf_get_error(link)) {
        *available = false;
        return NULL;
    }
    *available = true;
    return link;
}

static struct bpf_link *attach_optional_program(struct bpf_program *program, bool *available)
{
    struct bpf_link *link = bpf_program__attach(program);

    if (libbpf_get_error(link)) {
        *available = false;
        return NULL;
    }
    *available = true;
    return link;
}

static struct bpf_link *attach_optional_symbol_pair(struct bpf_program *program, bool return_probe, const char *primary, const char *fallback, bool *available)
{
    struct bpf_link *link = bpf_program__attach_kprobe(program, return_probe, primary);

    if (libbpf_get_error(link) && fallback)
        link = bpf_program__attach_kprobe(program, return_probe, fallback);
    if (libbpf_get_error(link)) {
        *available = false;
        return NULL;
    }
    *available = true;
    return link;
}

static int attach_host_programs(struct vtd_bpf *skeleton, struct bpf_link **links, unsigned int *link_count, struct capture_features *features)
{
    unsigned int required_start = *link_count;

    links[(*link_count)++] = attach_required(skeleton->progs.enter_ioctl);
    links[(*link_count)++] = attach_required(skeleton->progs.exit_ioctl);
    links[(*link_count)++] = attach_required(skeleton->progs.iommu_map);
    links[(*link_count)++] = attach_required(skeleton->progs.iommu_unmap);
    links[(*link_count)++] = attach_required(skeleton->progs.attach_device);
    for (unsigned int index = required_start; index < *link_count; index++) {
        if (!links[index])
            return -ENOENT;
    }
    links[(*link_count)++] = attach_optional(skeleton->progs.vfio_map_enter, false, "vfio_iommu_type1_map_dma", &features->vfio_type1_map_enter);
    links[(*link_count)++] = attach_optional(skeleton->progs.vfio_map_exit, true, "vfio_iommu_type1_map_dma", &features->vfio_type1_map_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.vfio_pin_enter, false, "vfio_pin_pages_remote", &features->page_pin_enter);
    links[(*link_count)++] = attach_optional(skeleton->progs.vfio_pin_exit, true, "vfio_pin_pages_remote", &features->page_pin_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.vfio_unpin_enter, false, "vfio_unpin_pages_remote", &features->page_unpin_enter);
    links[(*link_count)++] = attach_optional(skeleton->progs.vfio_unpin_exit, true, "vfio_unpin_pages_remote", &features->page_unpin_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_vfio_msi_entry, false, "vfio_msihandler", &features->vfio_msi);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_vfio_msi_exit, true, "vfio_msihandler", &features->vfio_msi);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_vfio_intx_entry, false, "vfio_intx_handler", &features->vfio_intx);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_vfio_intx_exit, true, "vfio_intx_handler", &features->vfio_intx);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_irqfd_wakeup, false, "irqfd_wakeup", &features->irqfd_wakeup);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.host_kvm_msi_route, &features->kvm_msi_route);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.host_kvm_apic_accept, &features->kvm_apic_accept);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.host_kvm_mmio, &features->kvm_mmio);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_irte_alloc_enter, false, "intel_irq_remapping_alloc", &features->irte_alloc_enter);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_alloc_irte_exit, true, "alloc_irte", &features->irte_index);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_irte_alloc_exit, true, "intel_irq_remapping_alloc", &features->irte_alloc_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_irte_activate, false, "intel_irq_remapping_activate", &features->irte_activate);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_ir_msi_entry, false, "intel_ir_compose_msi_msg", &features->ir_msi_entry);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_ir_msi_exit, true, "intel_ir_compose_msi_msg", &features->ir_msi_exit);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.host_kvm_pi_irte_update, &features->kvm_pi_irte_update);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.iommu_fault, &features->iommu_fault);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_domain_attach_enter, false, "domain_attach_iommu", &features->domain_attach_enter);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_domain_attach_exit, true, "domain_attach_iommu", &features->domain_attach_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_iotlb_invalidate, false, "iommu_flush_iotlb_psi", &features->iotlb_invalidate);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_qi_submit, false, "qi_submit_sync", &features->qi_submit);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_qi_complete, true, "qi_submit_sync", &features->qi_complete);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_pi_sync_enter, false, "vmx_sync_pir_to_irr", &features->pi_sync_enter);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_pi_sync_exit, true, "vmx_sync_pir_to_irr", &features->pi_sync_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_pi_wakeup, false, "pi_wakeup_handler", &features->pi_wakeup);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_pi_vcpu_wake_up, false, "kvm_vcpu_wake_up", &features->pi_vcpu_wake_up);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_pi_wakeup_exit, true, "pi_wakeup_handler", &features->pi_wakeup_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.host_pi_wakeup_vector, false, "sysvec_kvm_posted_intr_wakeup_ipi", &features->pi_wakeup_vector);
    return 0;
}

static int attach_guest_programs(struct vtd_bpf *skeleton, struct bpf_link **links, unsigned int *link_count, struct capture_features *features)
{
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_diag_entry, false, "ixgbe_diag_test", &features->guest_diag_entry);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_diag_exit, true, "ixgbe_diag_test", &features->guest_diag_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_intr_test_entry, false, "ixgbe_intr_test", &features->guest_intr_test_entry);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_intr_test_exit, true, "ixgbe_intr_test", &features->guest_intr_test_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_loopback_entry, false, "ixgbe_loopback_test", &features->guest_loopback_entry);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_loopback_exit, true, "ixgbe_loopback_test", &features->guest_loopback_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_run_entry, false, "ixgbe_run_loopback_test", &features->guest_run_entry);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_run_exit, true, "ixgbe_run_loopback_test", &features->guest_run_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_xmit_entry, false, "ixgbe_xmit_frame_ring", &features->guest_xmit_entry);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_xmit_exit, true, "ixgbe_xmit_frame_ring", &features->guest_xmit_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_dma_map_entry, false, "dma_map_page_attrs", &features->guest_dma_map_entry);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_dma_map_exit, true, "dma_map_page_attrs", &features->guest_dma_map_exit);
    links[(*link_count)++] = attach_optional_symbol_pair(skeleton->progs.guest_clean_entry, false, "ixgbe_clean_test_rings.constprop.0", "ixgbe_clean_test_rings", &features->guest_clean_entry);
    links[(*link_count)++] = attach_optional_symbol_pair(skeleton->progs.guest_clean_exit, true, "ixgbe_clean_test_rings.constprop.0", "ixgbe_clean_test_rings", &features->guest_clean_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_dma_unmap, false, "dma_unmap_page_attrs", &features->guest_dma_unmap);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_dma_sync_cpu, false, "dma_sync_single_for_cpu", &features->guest_dma_sync_cpu);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_dma_sync_device, false, "dma_sync_single_for_device", &features->guest_dma_sync_device);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.guest_irq_entry, &features->guest_irq_entry);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.guest_irq_exit, &features->guest_irq_exit);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.guest_softirq_raise, &features->guest_softirq_raise);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.guest_softirq_entry, &features->guest_softirq_entry);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.guest_napi_poll, &features->guest_napi_poll);
    links[(*link_count)++] = attach_optional_program(skeleton->progs.guest_softirq_exit, &features->guest_softirq_exit);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_netdev_open, false, "ixgbe_open", &features->guest_netdev_open);
    links[(*link_count)++] = attach_optional(skeleton->progs.guest_netdev_close, false, "ixgbe_close", &features->guest_netdev_close);
    if (!features->guest_run_entry || !features->guest_run_exit || !features->guest_xmit_entry || !features->guest_xmit_exit || !features->guest_dma_map_entry || !features->guest_dma_map_exit || !features->guest_clean_entry || !features->guest_clean_exit || !features->guest_irq_entry || !features->guest_irq_exit || !features->guest_diag_entry || !features->guest_diag_exit || !features->guest_intr_test_entry || !features->guest_intr_test_exit || !features->guest_loopback_entry || !features->guest_loopback_exit || !features->guest_softirq_raise || !features->guest_softirq_entry || !features->guest_napi_poll || !features->guest_softirq_exit)
        return -ENOENT;
    return 0;
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
    int poll_result = 0;
    int status = 1;

    if (argc == 3 && !strcmp(argv[1], "--guest")) {
        current_mode = CAPTURE_GUEST;
        guest_interface = argv[2];
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [--guest interface]\n", argv[0]);
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_signal);
    signal(SIGUSR2, on_signal);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skeleton = vtd_bpf__open();
    if (skeleton && current_mode == CAPTURE_GUEST)
        snprintf(skeleton->rodata->target_interface, sizeof(skeleton->rodata->target_interface), "%s", guest_interface);
    if (!skeleton || vtd_bpf__load(skeleton)) {
        vtd_bpf__destroy(skeleton);
        skeleton = NULL;
    }
    if (!skeleton) {
        fprintf(stderr, "vtd observer: open/load failed\n");
        goto cleanup;
    }

    if ((current_mode == CAPTURE_HOST && attach_host_programs(skeleton, links, &link_count, &features)) ||
        (current_mode == CAPTURE_GUEST && attach_guest_programs(skeleton, links, &link_count, &features))) {
        fprintf(stderr, "vtd observer: required %s hooks unavailable\n", current_mode == CAPTURE_HOST ? "host" : "guest");
        goto cleanup;
    }

    ring_buffer = ring_buffer__new(bpf_map__fd(skeleton->maps.events), emit_record, NULL, NULL);
    if (!ring_buffer) {
        fprintf(stderr, "vtd observer: ring buffer creation failed\n");
        goto cleanup;
    }
    if (emit_meta(&features))
        goto cleanup;

    fprintf(stderr, "LX_READY experiment=virt-vtd observer=%s clock=monotonic\n", current_mode == CAPTURE_HOST ? "host" : "guest");
    while (!stop_requested) {
        poll_result = ring_buffer__poll(ring_buffer, 250);
        if (poll_result < 0 && poll_result != -EINTR)
            break;
        if (gate_request >= 0) {
            uint32_t enabled = gate_request;

            if (current_mode == CAPTURE_HOST && bpf_map_update_elem(bpf_map__fd(skeleton->maps.runtime_gate), &map_key, &enabled, BPF_ANY))
                break;
            if (emit_gate_marker(enabled))
                break;
            fprintf(stderr, "LX_GATE enabled=%u\n", enabled);
            fflush(stderr);
            gate_request = -1;
        }
    }
    bpf_map_lookup_elem(bpf_map__fd(skeleton->maps.dropped_events), &map_key, &dropped);
    if (emit_summary(dropped))
        goto cleanup;
    status = poll_result < 0 && poll_result != -EINTR;

cleanup:
    ring_buffer__free(ring_buffer);
    for (unsigned int index = 0; index < link_count; index++)
        bpf_link__destroy(links[index]);
    vtd_bpf__destroy(skeleton);
    fprintf(stderr, "LX_DONE experiment=virt-vtd observer=%s events=%u dropped=%llu short=%u\n", current_mode == CAPTURE_HOST ? "host" : "guest", event_count, (unsigned long long)dropped, short_record_count);
    return status;
}
