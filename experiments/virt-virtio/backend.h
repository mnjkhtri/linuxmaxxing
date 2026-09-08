/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VIRTIO_BACKEND_H
#define VIRTIO_BACKEND_H

#include <stdatomic.h>
#include <stdint.h>

#include "virtio.h"

/* Every address in this structure remains a guest physical address. */
struct virtio_queue
{
	uint32_t size;           /* QueueSize is the number of descriptor-table entries. */
	uint32_t ready;          /* QueueReady says that this queue's three memory areas are configured. */
	uint16_t last_avail_idx; /* The backend has consumed every available entry before this index. */
	uint64_t desc_addr;      /* QueueDesc is the descriptor-table GPA. */
	uint64_t driver_addr;    /* QueueDriver is the available-ring GPA. */
	uint64_t device_addr;    /* QueueDevice is the used-ring GPA. */
};

struct virtio_mmio_device
{
	uint32_t device_features_sel; /* DeviceFeaturesSel chooses the offered 32-bit feature word. */
	uint32_t driver_features_sel; /* DriverFeaturesSel chooses the accepted 32-bit feature word. */
	uint32_t driver_features[2];  /* The controlled guest negotiates only feature words zero and one. */
	uint32_t status;              /* Status records the modern virtio initialization handshake. */
	uint32_t interrupt_status;    /* Bit zero records a used-buffer notification until InterruptACK clears it. */
	uint32_t queue_sel;           /* QueueSel identifies which queue the following queue registers address. */
	struct virtio_queue queue;    /* Virtio-rng exposes exactly one split virtqueue in this experiment. */
};

struct virtio_backend
{
	struct virtio_mmio_device *dev; /* Both notification directions share the same device state. */
	uint8_t *guest_mem;             /* The backend translates validated queue GPAs through this host mapping. */
	int kick_fd;                    /* kick_fd carries guest-to-backend QueueNotify wakeups. */
	int call_fd;                    /* call_fd carries backend-to-guest completion wakeups. */
	atomic_bool stop;               /* Shutdown wakes the worker without creating a guest-kick observation. */
	uint64_t guest_kicks;           /* This counts KVM_IOEVENTFD wakeups caused by the guest. */
	uint64_t guest_calls;           /* This counts completion signals written for KVM_IRQFD. */
	int result;                     /* The worker preserves backend failure for the VMM thread. */
};

int process_queue(struct virtio_mmio_device *dev, uint8_t *guest_mem);
int process_ioeventfd_kick(struct virtio_mmio_device *dev, uint8_t *guest_mem, struct virtio_backend *backend, uint64_t eventfd_count);
int signal_irqfd_completion(struct virtio_mmio_device *dev, uint8_t *guest_mem, struct virtio_backend *backend, uint64_t call_count);
void *virtio_backend_worker(void *opaque);

#endif
