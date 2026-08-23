/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VTD_EVENT_H
#define VTD_EVENT_H

#define VTD_DEVICE_NAME_LEN 64

enum vtd_operation {
    VTD_OP_NONE,
    VTD_OP_MAP,
    VTD_OP_UNMAP,
};

enum vtd_event_kind {
    VTD_EVENT_IOCTL_ENTER,
    VTD_EVENT_IOMMU_MAP,
    VTD_EVENT_IOMMU_UNMAP,
    VTD_EVENT_DEVICE_ATTACH,
    VTD_EVENT_IOCTL_EXIT,
};

/* Event information identifies the observed syscall or IOMMU boundary. */
struct vtd_event_info {
    unsigned int kind;
    unsigned int operation;
    unsigned int fd;
    unsigned int flags;
    unsigned long long command;
    long long result;
    unsigned char correlated;
    unsigned char reserved[7];
};

/* Context identifies the host task executing the observed boundary. */
struct vtd_context {
    unsigned int pid;
    unsigned int tid;
};

/* State contains the address-space facts sampled at that boundary. */
struct vtd_state {
    unsigned long long hva;
    unsigned long long iova;
    unsigned long long hpa;
    unsigned long long size;
    unsigned long long parent_iova;
    unsigned long long parent_size;
    char device[VTD_DEVICE_NAME_LEN];
};

struct vtd_event {
    unsigned long long time_ns;
    struct vtd_event_info event_info;
    struct vtd_context context;
    struct vtd_state state;
};

#endif
