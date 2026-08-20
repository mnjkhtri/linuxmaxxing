#ifndef VIRTIO_EXPERIMENT_H
#define VIRTIO_EXPERIMENT_H

/* Virtio-mmio transport */
#define VIRTIO_MMIO_BASE 0x10000000
#define VIRTIO_MMIO_SIZE 0x1000

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
#define VIRTIO_MMIO_STATUS 0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW 0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084
#define VIRTIO_MMIO_QUEUE_DRIVER_LOW 0x090
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH 0x094
#define VIRTIO_MMIO_QUEUE_DEVICE_LOW 0x0a0
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH 0x0a4

/* Device identity, status, and features */
#define VIRTIO_MAGIC_VALUE 0x74726976
#define VIRTIO_VERSION_MODERN 2
#define VIRTIO_DEVICE_ID_ENTROPY 4
#define VIRTIO_EXPERIMENT_VENDOR_ID 0x4f4f5053

#define VIRTIO_VERSION_1_WORD 1
#define VIRTIO_VERSION_1_WORD_MASK 1

#define VIRTIO_STATUS_ACKNOWLEDGE 0x01
#define VIRTIO_STATUS_DRIVER 0x02
#define VIRTIO_STATUS_DRIVER_OK 0x04
#define VIRTIO_STATUS_FEATURES_OK 0x08
#define VIRTIO_STATUS_FEATURES_READY 0x0b
#define VIRTIO_STATUS_DRIVER_READY 0x0f

/* Guest memory layout */
#define VIRTIO_GUEST_MEM_SIZE 0x20000
#define VIRTIO_GUEST_CODE_LIMIT 0x1000
#define VIRTIO_GUEST_STACK_TOP 0x3000
#define DESC_GPA 0x4000
#define AVAIL_GPA 0x5000
#define USED_GPA 0x6000
#define RNG_BUFFER_GPA 0x7000
#define VIRTQ_PAGE_SIZE 0x1000
#define RNG_REQUEST_LEN 32
#define VIRTIO_POLL_LIMIT 1000000

#define VIRTIO_TEST_SUCCESS_PORT 0x82
#define VIRTIO_TEST_FAILURE_PORT 0x83

/* Split virtqueue */
#define VIRTQ_INDEX 0
#define VIRTQ_SIZE 8
#define VIRTQ_DESC_F_WRITE 2

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

#define VIRTQ_DESC_BYTES (VIRTQ_SIZE * 16)
#define VIRTQ_AVAIL_BYTES (4 + VIRTQ_SIZE * 2)
#define VIRTQ_USED_BYTES (4 + VIRTQ_SIZE * 8)

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>

/* Each descriptor names one guest-memory buffer and states whether the device may write it. */
struct virtq_desc
{
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};

/* The driver publishes descriptor heads through ring[] and then advances idx. */
struct virtq_avail
{
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[VIRTQ_SIZE];
};

struct virtq_used_elem
{
	uint32_t id;
	uint32_t len;
};

/* The device publishes completed descriptor heads through ring[] and then advances idx. */
struct virtq_used
{
	uint16_t flags;
	uint16_t idx;
	struct virtq_used_elem ring[VIRTQ_SIZE];
};

_Static_assert(sizeof(struct virtq_desc) == 16, "virtq_desc must match the split-ring ABI");
_Static_assert(sizeof(struct virtq_avail) == VIRTQ_AVAIL_BYTES, "virtq_avail must match the negotiated layout");
_Static_assert(sizeof(struct virtq_used_elem) == 8, "virtq_used_elem must match the split-ring ABI");
_Static_assert(sizeof(struct virtq_used) == VIRTQ_USED_BYTES, "virtq_used must match the negotiated layout");
_Static_assert(offsetof(struct virtq_avail, ring) == VIRTQ_AVAIL_RING_OFFSET, "assembly avail offset must match C");
_Static_assert(offsetof(struct virtq_used, ring) == VIRTQ_USED_RING_OFFSET, "assembly used offset must match C");
#endif

#endif
