/* SPDX-License-Identifier: BSD-3-Clause */
/* Checkpoint 4 contract for one modern virtio-mmio entropy device with level-triggered completion notification. */
#ifndef VIRTIO_EXPERIMENT_H
#define VIRTIO_EXPERIMENT_H

/* The device occupies an MMIO window outside the guest's 128 KiB RAM slot. */
#define VIRTIO_MMIO_BASE 0x10000000
#define VIRTIO_MMIO_WINDOW_SIZE 0x00000200

/* These are the only modern virtio-mmio registers implemented through Checkpoint 4. */
#define VIRTIO_MMIO_MAGIC_VALUE 0x000
#define VIRTIO_MMIO_VERSION 0x004
#define VIRTIO_MMIO_DEVICE_ID 0x008
#define VIRTIO_MMIO_VENDOR_ID 0x00c
#define VIRTIO_MMIO_DEVICE_FEATURES 0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014
#define VIRTIO_MMIO_DRIVER_FEATURES 0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024
#define VIRTIO_MMIO_QUEUE_SEL 0x030
#define VIRTIO_MMIO_QUEUE_SIZE_MAX 0x034
#define VIRTIO_MMIO_QUEUE_SIZE 0x038
#define VIRTIO_MMIO_QUEUE_READY 0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY 0x050
#define VIRTIO_MMIO_INTERRUPT_STATUS 0x060
#define VIRTIO_MMIO_INTERRUPT_ACK 0x064
#define VIRTIO_MMIO_STATUS 0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW 0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084
#define VIRTIO_MMIO_QUEUE_DRIVER_LOW 0x090
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH 0x094
#define VIRTIO_MMIO_QUEUE_DEVICE_LOW 0x0a0
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH 0x0a4

/* These values identify a modern virtio entropy device to the guest. */
#define VIRTIO_MAGIC_VALUE 0x74726976
#define VIRTIO_VERSION_MODERN 2
#define VIRTIO_DEVICE_ID_ENTROPY 4
/* Stable, non-zero ID reserved locally for the kernel-oops experiment. */
#define VIRTIO_EXPERIMENT_VENDOR_ID 0x4b4f4f50

/* Virtio exposes the 64-bit feature space as two 32-bit words selected through MMIO. */
#define VIRTIO_F_VERSION_1 32
#define VIRTIO_VERSION_1_WORD 1
#define VIRTIO_VERSION_1_WORD_MASK 0x00000001

/* The driver builds device status cumulatively and may clear it only by writing zero. */
#define VIRTIO_STATUS_ACKNOWLEDGE 0x01
#define VIRTIO_STATUS_DRIVER 0x02
#define VIRTIO_STATUS_DRIVER_OK 0x04
#define VIRTIO_STATUS_FEATURES_OK 0x08
#define VIRTIO_STATUS_FAILED 0x80
#define VIRTIO_STATUS_CHECKPOINT1 (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK)
#define VIRTIO_STATUS_CHECKPOINT2 (VIRTIO_STATUS_CHECKPOINT1 | VIRTIO_STATUS_DRIVER_OK)

#define VIRTIO_MMIO_INT_VRING (1U << 0)
#define VIRTIO_GSI 4
#define VIRTIO_VECTOR 0x40

/* The one split virtqueue uses three dedicated guest pages and one fixed entropy output buffer. */
#define VIRTQ_INDEX 0
#define VIRTQ_SIZE 8
#define DESC_GPA 0x00004000
#define AVAIL_GPA 0x00005000
#define USED_GPA 0x00006000
#define RNG_BUFFER_GPA 0x00007000
#define VIRTQ_PAGE_SIZE 0x00001000
#define VIRTQ_DESC_BYTES (VIRTQ_SIZE * 16)
#define VIRTQ_AVAIL_BYTES (6 + 2 * VIRTQ_SIZE)
#define VIRTQ_USED_BYTES (6 + 8 * VIRTQ_SIZE)
#define RNG_REQUEST_LEN 32
#define VIRTIO_IRQ_WAIT_LIMIT 1000000

#define VIRTQ_DESC_F_NEXT 1
#define VIRTQ_DESC_F_WRITE 2
#define VIRTQ_DESC_F_INDIRECT 4

/* These offsets let guest.S show every descriptor and ring store directly. */
#define VIRTQ_DESC_ADDR_OFFSET 0
#define VIRTQ_DESC_LEN_OFFSET 8
#define VIRTQ_DESC_FLAGS_OFFSET 12
#define VIRTQ_DESC_NEXT_OFFSET 14
#define VIRTQ_AVAIL_FLAGS_OFFSET 0
#define VIRTQ_AVAIL_IDX_OFFSET 2
#define VIRTQ_AVAIL_RING_OFFSET 4
#define VIRTQ_USED_IDX_OFFSET 2
#define VIRTQ_USED_RING_OFFSET 4
#define VIRTQ_USED_ELEM_ID_OFFSET 0
#define VIRTQ_USED_ELEM_LEN_OFFSET 4

/* These ports provide an explicit test result because an unexpected HLT is treated as failure. */
#define VIRTIO_TEST_SUCCESS_PORT 0x82
#define VIRTIO_TEST_FAILURE_PORT 0x83

/* Guest code stays below 0x1000, and the stack begins well above that reserved code region. */
#define VIRTIO_GUEST_MEM_SIZE 0x00020000
#define VIRTIO_GUEST_STACK_TOP 0x00003000
#define VIRTIO_GUEST_CODE_LIMIT 0x00001000
#define VIRTIO_IDT_GPA 0x00001000
#define VIRTIO_IRQ_COUNT_GPA 0x00002000
#define VIRTIO_IRQ_STATUS_GPA 0x00002004

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>

/* Each descriptor identifies one guest buffer, and the request still uses only direct writable descriptor zero. */
struct virtq_desc
{
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};

/* QueueDriver points to this available-ring area, and used_event is present even though EVENT_IDX is not negotiated. */
struct virtq_avail
{
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[VIRTQ_SIZE];
	uint16_t used_event;
} __attribute__((packed));

struct virtq_used_elem
{
	uint32_t id;
	uint32_t len;
};

/* QueueDevice points to this used-ring area, and avail_event is present even though EVENT_IDX is not negotiated. */
struct virtq_used
{
	uint16_t flags;
	uint16_t idx;
	struct virtq_used_elem ring[VIRTQ_SIZE];
	uint16_t avail_event;
} __attribute__((packed));

_Static_assert(sizeof(struct virtq_desc) == 16, "each virtq descriptor must be sixteen bytes");
_Static_assert(sizeof(struct virtq_desc) * VIRTQ_SIZE == VIRTQ_DESC_BYTES, "virtq descriptor table size must match the split-ring layout");
_Static_assert(sizeof(struct virtq_avail) == VIRTQ_AVAIL_BYTES, "virtq available ring size must match the split-ring layout");
_Static_assert(sizeof(struct virtq_used_elem) == 8, "virtq used element must be eight bytes");
_Static_assert(sizeof(struct virtq_used) == VIRTQ_USED_BYTES, "virtq used ring size must match the split-ring layout");
_Static_assert(offsetof(struct virtq_desc, addr) == VIRTQ_DESC_ADDR_OFFSET, "guest descriptor address offset must match the C layout");
_Static_assert(offsetof(struct virtq_desc, len) == VIRTQ_DESC_LEN_OFFSET, "guest descriptor length offset must match the C layout");
_Static_assert(offsetof(struct virtq_desc, flags) == VIRTQ_DESC_FLAGS_OFFSET, "guest descriptor flags offset must match the C layout");
_Static_assert(offsetof(struct virtq_desc, next) == VIRTQ_DESC_NEXT_OFFSET, "guest descriptor next offset must match the C layout");
_Static_assert(offsetof(struct virtq_avail, idx) == VIRTQ_AVAIL_IDX_OFFSET, "guest available index offset must match the C layout");
_Static_assert(offsetof(struct virtq_avail, ring) == VIRTQ_AVAIL_RING_OFFSET, "guest available ring offset must match the C layout");
_Static_assert(offsetof(struct virtq_used, idx) == VIRTQ_USED_IDX_OFFSET, "guest used index offset must match the C layout");
_Static_assert(offsetof(struct virtq_used, ring) == VIRTQ_USED_RING_OFFSET, "guest used ring offset must match the C layout");
_Static_assert(offsetof(struct virtq_used_elem, id) == VIRTQ_USED_ELEM_ID_OFFSET, "guest used-element ID offset must match the C layout");
_Static_assert(offsetof(struct virtq_used_elem, len) == VIRTQ_USED_ELEM_LEN_OFFSET, "guest used-element length offset must match the C layout");
#endif

#endif /* VIRTIO_EXPERIMENT_H */
