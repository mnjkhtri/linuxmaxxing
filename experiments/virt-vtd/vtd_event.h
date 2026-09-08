/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VTD_EVENT_H
#define VTD_EVENT_H

#define VTD_COMM_LEN 16
#define VTD_DEVICE_NAME_LEN 64
#define VTD_ACTION_NAME_LEN 64

enum vtd_operation {
    VTD_OP_NONE,
    VTD_OP_VFIO_MAP,
    VTD_OP_VFIO_UNMAP,
    VTD_OP_KVM_MEMORY_REGION,
    VTD_OP_VFIO_IRQ_SET,
};

enum vtd_event_kind {
    VTD_EVENT_IOCTL_ENTER,
    VTD_EVENT_IOMMU_MAP,
    VTD_EVENT_IOMMU_UNMAP,
    VTD_EVENT_DEVICE_ATTACH,
    VTD_EVENT_IOCTL_EXIT,
    VTD_EVENT_VFIO_MAP_ENTER,
    VTD_EVENT_VFIO_MAP_EXIT,
    VTD_EVENT_PAGE_PIN_ENTER,
    VTD_EVENT_PAGE_PIN_EXIT,
    VTD_EVENT_PAGE_UNPIN_ENTER,
    VTD_EVENT_PAGE_UNPIN_EXIT,
    VTD_EVENT_VFIO_MSI_ENTRY,
    VTD_EVENT_VFIO_MSI_EXIT,
    VTD_EVENT_VFIO_INTX_ENTRY,
    VTD_EVENT_VFIO_INTX_EXIT,
    VTD_EVENT_IRQFD_WAKEUP,
    VTD_EVENT_KVM_MSI_ROUTE,
    VTD_EVENT_KVM_APIC_ACCEPT,
    VTD_EVENT_KVM_MMIO,
    VTD_EVENT_IRTE_ALLOC,
    VTD_EVENT_IRTE_ACTIVATE,
    VTD_EVENT_IR_MSI_MESSAGE,
    VTD_EVENT_KVM_PI_IRTE_UPDATE,
    VTD_EVENT_GUEST_RUN_ENTRY,
    VTD_EVENT_GUEST_RUN_EXIT,
    VTD_EVENT_GUEST_XMIT_ENTRY,
    VTD_EVENT_GUEST_DMA_MAP_ENTRY,
    VTD_EVENT_GUEST_DMA_MAP_EXIT,
    VTD_EVENT_GUEST_XMIT_EXIT,
    VTD_EVENT_GUEST_CLEAN_ENTRY,
    VTD_EVENT_GUEST_DMA_UNMAP,
    VTD_EVENT_GUEST_DMA_SYNC_CPU,
    VTD_EVENT_GUEST_DMA_SYNC_DEVICE,
    VTD_EVENT_GUEST_CLEAN_EXIT,
    VTD_EVENT_GUEST_IRQ_ENTRY,
    VTD_EVENT_GUEST_IRQ_EXIT,
    VTD_EVENT_GUEST_NETDEV_OPEN,
    VTD_EVENT_GUEST_NETDEV_CLOSE,
    VTD_EVENT_IOMMU_FAULT,
    VTD_EVENT_DOMAIN_ATTACH_ENTER,
    VTD_EVENT_DOMAIN_ATTACH_EXIT,
    VTD_EVENT_IOTLB_INVALIDATE,
    VTD_EVENT_QI_SUBMIT,
    VTD_EVENT_QI_COMPLETE,
    VTD_EVENT_PI_SYNC_EXIT,
    VTD_EVENT_PI_WAKEUP,
    VTD_EVENT_PI_WAKEUP_VECTOR,
    VTD_EVENT_GUEST_DIAG_ENTRY,
    VTD_EVENT_GUEST_DIAG_EXIT,
    VTD_EVENT_GUEST_INTR_TEST_ENTRY,
    VTD_EVENT_GUEST_INTR_TEST_EXIT,
    VTD_EVENT_GUEST_LOOPBACK_ENTRY,
    VTD_EVENT_GUEST_LOOPBACK_EXIT,
    VTD_EVENT_GUEST_SOFTIRQ_RAISE,
    VTD_EVENT_GUEST_SOFTIRQ_ENTRY,
    VTD_EVENT_GUEST_NAPI_POLL,
    VTD_EVENT_GUEST_SOFTIRQ_EXIT,
};

enum vtd_guest_phase {
    VTD_GUEST_PHASE_NONE,
    VTD_GUEST_PHASE_INTERFACE_START,
    VTD_GUEST_PHASE_OFFLINE_DIAG,
    VTD_GUEST_PHASE_INTR_TEST,
    VTD_GUEST_PHASE_LOOPBACK_SETUP,
    VTD_GUEST_PHASE_LOOPBACK_RUN,
    VTD_GUEST_PHASE_INTERFACE_RESTORE,
};

enum vtd_sample_status {
    VTD_SAMPLE_COMPLETE,
    VTD_SAMPLE_READ_FAILED,
    VTD_SAMPLE_INVALID_ARGUMENT,
};

/* Event information identifies the observed syscall, function, or IOMMU boundary. */
struct vtd_event_info {
    unsigned int kind;
    unsigned int operation;
    unsigned int fd;
    unsigned int flags;
    unsigned int argsz;
    unsigned int slot;
    unsigned long long command;
    unsigned long long request_id;
    long long result;
    unsigned char correlated;
    unsigned char sample_status;
    unsigned char reserved[6];
};

/* Context identifies the host task executing the observed boundary. */
struct vtd_context {
    unsigned int pid;
    unsigned int tid;
    unsigned int cpu;
    unsigned int reserved;
    char comm[VTD_COMM_LEN];
};

/* State contains the address-space facts sampled at that boundary. */
struct vtd_state {
    unsigned long long hva;
    unsigned long long gpa;
    unsigned long long iova;
    unsigned long long hpa;
    unsigned long long size;
    unsigned long long returned_size;
    unsigned long long parent_iova;
    unsigned long long parent_size;
    unsigned long long page_count;
    unsigned long long user_argument;
    unsigned long long dma_address;
    unsigned long long data_length;
    unsigned long long interrupt_address;
    unsigned long long interrupt_data;
    unsigned long long mmio_value;
    unsigned int dma_direction;
    unsigned int irq;
    unsigned int vector;
    unsigned int apic_id;
    unsigned int count;
    unsigned int mmio_length;
    unsigned int mmio_type;
    unsigned int irq_index;
    unsigned int irq_start;
    unsigned int irq_count;
    unsigned int irte_index;
    unsigned int gsi;
    unsigned int vcpu_id;
    unsigned int posted;
    unsigned long long pi_desc_address;
    unsigned long long domain_address;
    unsigned long long iommu_address;
    unsigned long long qi_descriptor_0;
    unsigned long long qi_descriptor_1;
    unsigned int iommu_id;
    unsigned int qi_count;
    unsigned int qi_options;
    unsigned int invalidation_hint;
    unsigned int invalidation_map;
    unsigned long long episode_id;
    unsigned int guest_phase;
    unsigned int softirq_vector;
    unsigned int napi_work;
    unsigned int napi_budget;
    unsigned int wakeup_count;
    char device[VTD_DEVICE_NAME_LEN];
    char driver[VTD_DEVICE_NAME_LEN];
    char action[VTD_ACTION_NAME_LEN];
};

struct vtd_event {
    unsigned long long time_ns;
    struct vtd_event_info event_info;
    struct vtd_context context;
    struct vtd_state state;
};

#endif
