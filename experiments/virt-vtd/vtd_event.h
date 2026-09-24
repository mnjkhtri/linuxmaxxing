/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VTD_EVENT_H
#define VTD_EVENT_H

/* Small shared ABI: one event, one conceptual VT-d boundary. */
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
    VTD_EVENT_IRTE_ACTIVATE,
	VTD_EVENT_IR_MSI_MESSAGE,
	VTD_EVENT_KVM_PI_IRTE_UPDATE,
	VTD_EVENT_DOMAIN_ATTACH_ENTER,
	VTD_EVENT_DOMAIN_ATTACH_EXIT,
	VTD_EVENT_QI_SUBMIT,
	VTD_EVENT_QI_COMPLETE,
	VTD_EVENT_GUEST_RUN_ENTRY,
	VTD_EVENT_GUEST_RUN_EXIT,
	VTD_EVENT_GUEST_DMA_MAP_ENTRY,
	VTD_EVENT_GUEST_DMA_MAP_EXIT,
	VTD_EVENT_GUEST_IRQ_ENTRY,
	VTD_EVENT_GUEST_IRQ_EXIT,
};

enum vtd_guest_phase {
	VTD_GUEST_PHASE_NONE,
	VTD_GUEST_PHASE_LOOPBACK_RUN,
};

enum vtd_sample_status {
	VTD_SAMPLE_COMPLETE,
	VTD_SAMPLE_READ_FAILED,
	VTD_SAMPLE_INVALID_ARGUMENT,
};

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
	unsigned char sample_status;
	unsigned char reserved[7];
};

struct vtd_context {
	unsigned int pid;
	unsigned int tid;
	unsigned int cpu;
	unsigned int reserved;
	char comm[VTD_COMM_LEN];
};

/* Fields are grouped by the four teaching paths, not by kernel subsystem. */
struct vtd_state {
	/* VFIO/IOMMU address-space mapping. */
	unsigned long long hva;
	unsigned long long gpa;
	unsigned long long iova;
	unsigned long long hpa;
	unsigned long long size;
	unsigned long long returned_size;
	unsigned long long parent_iova;
	unsigned long long parent_size;
	unsigned int irq_index;
	unsigned int irq_start;

	/* Interrupt remapping and posted-interrupt routing. */
	unsigned long long interrupt_address;
	unsigned long long interrupt_data;
	unsigned long long pi_desc_address;
	unsigned int irq;
	unsigned int vector;
	unsigned int vcpu_id;
	unsigned int irq_count;
	unsigned int irte_index;
	unsigned int gsi;
	unsigned int posted;

	/* IOMMU invalidation queue. */
	unsigned long long domain_address;
	unsigned long long iommu_address;
	unsigned long long qi_descriptor_0;
	unsigned long long qi_descriptor_1;
	unsigned int iommu_id;
	unsigned int qi_count;
	unsigned int qi_options;
	unsigned int invalidation_hint;
	unsigned int invalidation_map;

	/* Guest DMA and interrupt execution. */
	unsigned long long dma_address;
	unsigned long long data_length;
	unsigned int dma_direction;
	unsigned long long episode_id;
	unsigned int guest_phase;
	char device[VTD_DEVICE_NAME_LEN];
	char action[VTD_ACTION_NAME_LEN];
};

struct vtd_event {
	unsigned long long time_ns;
	struct vtd_event_info event_info;
	struct vtd_context context;
	struct vtd_state state;
};

#endif
