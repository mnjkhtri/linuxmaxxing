// SPDX-License-Identifier: GPL-2.0
/* Checkpoint 4 VMM for one modern virtio-mmio entropy device. */
/* Discovery, one split virtqueue request, and one level-triggered completion notification exist here. */
/* Every register access is an intentional KVM_EXIT_MMIO. */
/* QueueNotify remains a doorbell, while the used ring remains the authoritative completion state. */
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>

#include "virtio.h"

/* This is the device's knowledge of queue zero, and every address remains a guest physical address. */
struct virtio_queue
{
	uint32_t size; /* QueueSize is the number of descriptor-table entries selected by the guest. */
	uint32_t ready; /* QueueReady marks this specific queue configuration as active. */
	uint16_t last_avail_idx; /* The backend consumes available entries from this monotonically wrapping position. */
	uint64_t desc_addr; /* QueueDesc points to the split-ring descriptor table. */
	uint64_t driver_addr; /* QueueDriver points to the split-ring available ring. */
	uint64_t device_addr; /* QueueDevice points to the split-ring used ring. */
};

struct virtio_mmio_device
{
	uint32_t device_features_sel; /* This selects the 32-bit device feature word returned by DeviceFeatures. */
	uint32_t driver_features_sel; /* This selects the 32-bit driver feature word changed by DriverFeatures. */
	uint32_t driver_features[2]; /* These words preserve exactly what the guest accepted during negotiation. */
	uint32_t status; /* This is the cumulative virtio device status visible to the guest. */
	uint32_t queue_sel; /* QueueSel chooses which queue the MMIO queue registers describe. */
	uint32_t interrupt_status; /* Bit zero reports a used-buffer notification until the guest acknowledges it. */
	uint32_t irq_asserted; /* This mirrors the level currently driven on the fixed platform GSI. */
	struct virtio_queue queue; /* Virtio-rng has exactly one request queue at queue index zero. */
};

/* Register names keep protocol-error diagnostics readable without introducing a logging framework. */
static const char *register_name(uint32_t offset)
{
	switch (offset)
	{
	case VIRTIO_MMIO_MAGIC_VALUE:
		return "MagicValue";
	case VIRTIO_MMIO_VERSION:
		return "Version";
	case VIRTIO_MMIO_DEVICE_ID:
		return "DeviceID";
	case VIRTIO_MMIO_VENDOR_ID:
		return "VendorID";
	case VIRTIO_MMIO_DEVICE_FEATURES:
		return "DeviceFeatures";
	case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
		return "DeviceFeaturesSel";
	case VIRTIO_MMIO_DRIVER_FEATURES:
		return "DriverFeatures";
	case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
		return "DriverFeaturesSel";
	case VIRTIO_MMIO_QUEUE_SEL:
		return "QueueSel";
	case VIRTIO_MMIO_QUEUE_SIZE_MAX:
		return "QueueSizeMax";
	case VIRTIO_MMIO_QUEUE_SIZE:
		return "QueueSize";
	case VIRTIO_MMIO_QUEUE_READY:
		return "QueueReady";
	case VIRTIO_MMIO_QUEUE_NOTIFY:
		return "QueueNotify";
	case VIRTIO_MMIO_INTERRUPT_STATUS:
		return "InterruptStatus";
	case VIRTIO_MMIO_INTERRUPT_ACK:
		return "InterruptACK";
	case VIRTIO_MMIO_STATUS:
		return "Status";
	case VIRTIO_MMIO_QUEUE_DESC_LOW:
		return "QueueDescLow";
	case VIRTIO_MMIO_QUEUE_DESC_HIGH:
		return "QueueDescHigh";
	case VIRTIO_MMIO_QUEUE_DRIVER_LOW:
		return "QueueDriverLow";
	case VIRTIO_MMIO_QUEUE_DRIVER_HIGH:
		return "QueueDriverHigh";
	case VIRTIO_MMIO_QUEUE_DEVICE_LOW:
		return "QueueDeviceLow";
	case VIRTIO_MMIO_QUEUE_DEVICE_HIGH:
		return "QueueDeviceHigh";
	default:
		return NULL;
	}
}

/* Readable registers provide device identity, offered features, queue capabilities, readiness, and status. */
static int read_register(struct virtio_mmio_device *dev, uint32_t offset, uint32_t *value)
{
	switch (offset)
	{
	case VIRTIO_MMIO_MAGIC_VALUE:
		*value = VIRTIO_MAGIC_VALUE;
		break;
	case VIRTIO_MMIO_VERSION:
		*value = VIRTIO_VERSION_MODERN;
		break;
	case VIRTIO_MMIO_DEVICE_ID:
		*value = VIRTIO_DEVICE_ID_ENTROPY;
		break;
	case VIRTIO_MMIO_VENDOR_ID:
		*value = VIRTIO_EXPERIMENT_VENDOR_ID;
		break;
	case VIRTIO_MMIO_DEVICE_FEATURES:
		/* Selector one contains VERSION_1, while selector zero and unsupported words contain no features. */
		*value = dev->device_features_sel == VIRTIO_VERSION_1_WORD ? VIRTIO_VERSION_1_WORD_MASK : 0;
		fprintf(stderr, "virtio: DeviceFeatures[%u] = 0x%08x\n", dev->device_features_sel, *value);
		return 0;
	case VIRTIO_MMIO_STATUS:
		*value = dev->status;
		fprintf(stderr, "virtio: read Status -> 0x%02x\n", *value);
		return 0;
	case VIRTIO_MMIO_QUEUE_SIZE_MAX:
		*value = dev->queue_sel == VIRTQ_INDEX ? VIRTQ_SIZE : 0;
		fprintf(stderr, "virtio: QueueSizeMax[%u] -> %u\n", dev->queue_sel, *value);
		return 0;
	case VIRTIO_MMIO_QUEUE_READY:
		*value = dev->queue_sel == VIRTQ_INDEX ? dev->queue.ready : 0;
		fprintf(stderr, "virtio: QueueReady[%u] -> %u\n", dev->queue_sel, *value);
		return 0;
	case VIRTIO_MMIO_INTERRUPT_STATUS:
		*value = dev->interrupt_status;
		fprintf(stderr, "virtio: read InterruptStatus -> 0x%02x\n", *value);
		return 0;
	case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
	case VIRTIO_MMIO_DRIVER_FEATURES:
	case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
	case VIRTIO_MMIO_QUEUE_SEL:
	case VIRTIO_MMIO_QUEUE_SIZE:
	case VIRTIO_MMIO_QUEUE_DESC_LOW:
	case VIRTIO_MMIO_QUEUE_DESC_HIGH:
	case VIRTIO_MMIO_QUEUE_DRIVER_LOW:
	case VIRTIO_MMIO_QUEUE_DRIVER_HIGH:
	case VIRTIO_MMIO_QUEUE_DEVICE_LOW:
	case VIRTIO_MMIO_QUEUE_DEVICE_HIGH:
	case VIRTIO_MMIO_QUEUE_NOTIFY:
	case VIRTIO_MMIO_INTERRUPT_ACK:
		fprintf(stderr, "virtio-mmio: read from write-only %s\n", register_name(offset));
		return -1;
	default:
		fprintf(stderr, "virtio-mmio: read from unimplemented offset 0x%03x\n", offset);
		return -1;
	}

	fprintf(stderr, "virtio-mmio: read %s -> 0x%08x\n", register_name(offset), *value);
	return 0;
}

/* KVM_IRQ_LINE drives the fixed platform GSI as persistent level state rather than an edge pulse. */
static int set_irq_level(int vm, struct virtio_mmio_device *dev, uint32_t asserted)
{
	struct kvm_irq_level level = {.irq = VIRTIO_GSI, .level = asserted};

	if (dev->irq_asserted == asserted)
		return 0;
	if (ioctl(vm, KVM_IRQ_LINE, &level) < 0)
	{
		perror(asserted ? "KVM_IRQ_LINE assert" : "KVM_IRQ_LINE deassert");
		return -1;
	}
	dev->irq_asserted = asserted;
	fprintf(stderr, "virtio: GSI %u %s\n", VIRTIO_GSI, asserted ? "asserted" : "deasserted");
	return 0;
}

/* QueueNotify enters this one explicit virtio-rng backend after the transport has validated the doorbell. */
static int process_queue(int vm, struct virtio_mmio_device *dev, uint8_t *guest_mem)
{
	struct virtq_desc *desc;
	struct virtq_avail *avail;
	struct virtq_used *used;
	uint16_t *avail_idx_ptr;
	uint16_t *used_idx_ptr;
	uint16_t avail_idx;
	uint16_t pending;

	if (!dev->queue.ready || dev->queue.size != VIRTQ_SIZE)
	{
		fprintf(stderr, "virtio-rng: queue zero is not ready\n");
		return -1;
	}
	if ((dev->queue.desc_addr & 15) || dev->queue.desc_addr > VIRTIO_GUEST_MEM_SIZE || VIRTQ_DESC_BYTES > VIRTIO_GUEST_MEM_SIZE - dev->queue.desc_addr)
	{
		fprintf(stderr, "virtio-rng: invalid descriptor-table GPA 0x%016llx\n", (unsigned long long)dev->queue.desc_addr);
		return -1;
	}
	if ((dev->queue.driver_addr & 1) || dev->queue.driver_addr > VIRTIO_GUEST_MEM_SIZE || VIRTQ_AVAIL_BYTES > VIRTIO_GUEST_MEM_SIZE - dev->queue.driver_addr)
	{
		fprintf(stderr, "virtio-rng: invalid available-ring GPA 0x%016llx\n", (unsigned long long)dev->queue.driver_addr);
		return -1;
	}
	if ((dev->queue.device_addr & 3) || dev->queue.device_addr > VIRTIO_GUEST_MEM_SIZE || VIRTQ_USED_BYTES > VIRTIO_GUEST_MEM_SIZE - dev->queue.device_addr)
	{
		fprintf(stderr, "virtio-rng: invalid used-ring GPA 0x%016llx\n", (unsigned long long)dev->queue.device_addr);
		return -1;
	}

	/* GPA bounds and alignment are valid before these guest_mem plus GPA translations occur. */
	desc = (struct virtq_desc *)(guest_mem + (size_t)dev->queue.desc_addr);
	avail = (struct virtq_avail *)(guest_mem + (size_t)dev->queue.driver_addr);
	used = (struct virtq_used *)(guest_mem + (size_t)dev->queue.device_addr);
	avail_idx_ptr = (uint16_t *)(guest_mem + (size_t)dev->queue.driver_addr + VIRTQ_AVAIL_IDX_OFFSET);
	used_idx_ptr = (uint16_t *)(guest_mem + (size_t)dev->queue.device_addr + VIRTQ_USED_IDX_OFFSET);

	avail_idx = *avail_idx_ptr;
	/* The acquire fence keeps descriptor and ring reads after the guest's avail.idx publication. */
	atomic_thread_fence(memory_order_acquire);
	pending = (uint16_t)(avail_idx - dev->queue.last_avail_idx);
	if (pending > VIRTQ_SIZE)
	{
		fprintf(stderr, "virtio-rng: avail ring overrun with %u pending entries\n", (unsigned int)pending);
		return -1;
	}
	fprintf(stderr, "virtio: avail.idx=%u last_avail_idx=%u\n", (unsigned int)avail_idx, (unsigned int)dev->queue.last_avail_idx);

	while (dev->queue.last_avail_idx != avail_idx)
	{
		struct virtq_desc request;
		uint16_t avail_slot = dev->queue.last_avail_idx % VIRTQ_SIZE;
		uint16_t head = avail->ring[avail_slot];
		uint16_t old_used_idx;
		uint16_t used_slot;
		uint32_t old_interrupt_status;
		uint8_t *buffer;
		size_t filled = 0;

		fprintf(stderr, "virtio: consume avail[%u] -> desc %u\n", (unsigned int)avail_slot, (unsigned int)head);
		if (head >= dev->queue.size)
		{
			fprintf(stderr, "virtio-rng: invalid descriptor index %u\n", (unsigned int)head);
			return -1;
		}
		request = desc[head];
		fprintf(stderr, "virtio: desc[%u] addr=0x%016llx len=%u flags=0x%04x\n", (unsigned int)head, (unsigned long long)request.addr, request.len, (unsigned int)request.flags);
		if (request.flags != VIRTQ_DESC_F_WRITE)
		{
			fprintf(stderr, "virtio-rng: descriptor must be one direct writable buffer\n");
			return -1;
		}
		if (request.len == 0 || request.addr > VIRTIO_GUEST_MEM_SIZE || request.len > VIRTIO_GUEST_MEM_SIZE - request.addr)
		{
			fprintf(stderr, "virtio-rng: invalid writable buffer GPA 0x%016llx length %u\n", (unsigned long long)request.addr, request.len);
			return -1;
		}

		/* The descriptor buffer becomes an HVA only after its complete GPA range has been validated. */
		buffer = guest_mem + (size_t)request.addr;
		while (filled < request.len)
		{
			ssize_t bytes = getrandom(buffer + filled, request.len - filled, 0);

			if (bytes < 0 && errno == EINTR)
				continue;
			if (bytes <= 0)
			{
				if (bytes < 0)
					perror("getrandom");
				else
					fprintf(stderr, "getrandom returned zero bytes\n");
				return -1;
			}
			filled += (size_t)bytes;
		}
		fprintf(stderr, "virtio-rng: wrote %u bytes to GPA 0x%llx\n", request.len, (unsigned long long)request.addr);

		old_used_idx = *used_idx_ptr;
		used_slot = old_used_idx % VIRTQ_SIZE;
		used->ring[used_slot].id = head;
		used->ring[used_slot].len = request.len;
		fprintf(stderr, "virtio: used[%u] id=%u len=%u\n", (unsigned int)used_slot, (unsigned int)head, request.len);
		/* The release fence publishes random bytes and the used element before used.idx transfers ownership back. */
		atomic_thread_fence(memory_order_release);
		*used_idx_ptr = (uint16_t)(old_used_idx + 1);
		fprintf(stderr, "virtio: used.idx %u -> %u\n", (unsigned int)old_used_idx, (unsigned int)(uint16_t)(old_used_idx + 1));
		dev->queue.last_avail_idx++;

		/* Completion is already authoritative in the used ring before the interrupt becomes visible. */
		old_interrupt_status = dev->interrupt_status;
		dev->interrupt_status |= VIRTIO_MMIO_INT_VRING;
		fprintf(stderr, "virtio: InterruptStatus 0x%02x -> 0x%02x\n", old_interrupt_status, dev->interrupt_status);
		if (set_irq_level(vm, dev, 1) < 0)
			return -1;
	}

	return 0;
}

/* Writable registers select feature words, record accepted features, or advance device status. */
static int write_register(int vm, struct virtio_mmio_device *dev, uint8_t *guest_mem, uint32_t offset, uint32_t value)
{
	switch (offset)
	{
	case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
		dev->device_features_sel = value;
		fprintf(stderr, "virtio: DeviceFeaturesSel = %u\n", value);
		return 0;
	case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
		if (dev->status & VIRTIO_STATUS_FEATURES_OK)
		{
			fprintf(stderr, "virtio: DriverFeaturesSel changed after FEATURES_OK\n");
			return -1;
		}
		dev->driver_features_sel = value;
		fprintf(stderr, "virtio: DriverFeaturesSel = %u\n", value);
		return 0;
	case VIRTIO_MMIO_DRIVER_FEATURES:
		if (dev->status & VIRTIO_STATUS_FEATURES_OK)
		{
			fprintf(stderr, "virtio: DriverFeatures changed after FEATURES_OK\n");
			return -1;
		}
		if (dev->driver_features_sel >= 2)
		{
			fprintf(stderr, "virtio: DriverFeatures word %u is unsupported\n", dev->driver_features_sel);
			return -1;
		}
		dev->driver_features[dev->driver_features_sel] = value;
		fprintf(stderr, "virtio: DriverFeatures[%u] = 0x%08x\n", dev->driver_features_sel, value);
		return 0;
	case VIRTIO_MMIO_QUEUE_SEL:
		dev->queue_sel = value;
		fprintf(stderr, "virtio: QueueSel = %u\n", value);
		return 0;
	case VIRTIO_MMIO_QUEUE_SIZE:
		if (dev->queue_sel != VIRTQ_INDEX)
		{
			fprintf(stderr, "virtio: QueueSize write for unsupported queue %u\n", dev->queue_sel);
			return -1;
		}
		if (dev->queue.ready)
		{
			fprintf(stderr, "virtio: QueueSize cannot change while queue zero is ready\n");
			return -1;
		}
		if (value != VIRTQ_SIZE)
		{
			fprintf(stderr, "virtio: QueueSize[0] must be %u, not %u\n", VIRTQ_SIZE, value);
			return -1;
		}
		dev->queue.size = value;
		fprintf(stderr, "virtio: QueueSize[0] = %u\n", value);
		return 0;
	case VIRTIO_MMIO_QUEUE_DESC_LOW:
		if (dev->queue_sel != VIRTQ_INDEX || dev->queue.ready)
		{
			fprintf(stderr, "virtio: QueueDescLow requires inactive queue zero\n");
			return -1;
		}
		dev->queue.desc_addr = (dev->queue.desc_addr & 0xffffffff00000000ULL) | value;
		return 0;
	case VIRTIO_MMIO_QUEUE_DESC_HIGH:
		if (dev->queue_sel != VIRTQ_INDEX || dev->queue.ready)
		{
			fprintf(stderr, "virtio: QueueDescHigh requires inactive queue zero\n");
			return -1;
		}
		dev->queue.desc_addr = (dev->queue.desc_addr & 0x00000000ffffffffULL) | ((uint64_t)value << 32);
		fprintf(stderr, "virtio: QueueDesc = 0x%016llx\n", (unsigned long long)dev->queue.desc_addr);
		return 0;
	case VIRTIO_MMIO_QUEUE_DRIVER_LOW:
		if (dev->queue_sel != VIRTQ_INDEX || dev->queue.ready)
		{
			fprintf(stderr, "virtio: QueueDriverLow requires inactive queue zero\n");
			return -1;
		}
		dev->queue.driver_addr = (dev->queue.driver_addr & 0xffffffff00000000ULL) | value;
		return 0;
	case VIRTIO_MMIO_QUEUE_DRIVER_HIGH:
		if (dev->queue_sel != VIRTQ_INDEX || dev->queue.ready)
		{
			fprintf(stderr, "virtio: QueueDriverHigh requires inactive queue zero\n");
			return -1;
		}
		dev->queue.driver_addr = (dev->queue.driver_addr & 0x00000000ffffffffULL) | ((uint64_t)value << 32);
		fprintf(stderr, "virtio: QueueDriver = 0x%016llx\n", (unsigned long long)dev->queue.driver_addr);
		return 0;
	case VIRTIO_MMIO_QUEUE_DEVICE_LOW:
		if (dev->queue_sel != VIRTQ_INDEX || dev->queue.ready)
		{
			fprintf(stderr, "virtio: QueueDeviceLow requires inactive queue zero\n");
			return -1;
		}
		dev->queue.device_addr = (dev->queue.device_addr & 0xffffffff00000000ULL) | value;
		return 0;
	case VIRTIO_MMIO_QUEUE_DEVICE_HIGH:
		if (dev->queue_sel != VIRTQ_INDEX || dev->queue.ready)
		{
			fprintf(stderr, "virtio: QueueDeviceHigh requires inactive queue zero\n");
			return -1;
		}
		dev->queue.device_addr = (dev->queue.device_addr & 0x00000000ffffffffULL) | ((uint64_t)value << 32);
		fprintf(stderr, "virtio: QueueDevice = 0x%016llx\n", (unsigned long long)dev->queue.device_addr);
		return 0;
	case VIRTIO_MMIO_QUEUE_READY:
	{
		int desc_valid;
		int driver_valid;
		int device_valid;
		int ranges_disjoint;

		if (dev->queue_sel != VIRTQ_INDEX)
		{
			fprintf(stderr, "virtio: QueueReady write for unsupported queue %u\n", dev->queue_sel);
			return -1;
		}
		if (value > 1)
		{
			fprintf(stderr, "virtio: QueueReady accepts only zero or one\n");
			return -1;
		}
		if (value == 0)
		{
			dev->queue.ready = 0;
			fprintf(stderr, "virtio: QueueReady[0] = 0\n");
			return 0;
		}

		/* QueueReady means this queue's size and three guest physical memory areas are fully configured. */
		desc_valid = !(dev->queue.desc_addr & 15) && dev->queue.desc_addr <= VIRTIO_GUEST_MEM_SIZE && VIRTQ_DESC_BYTES <= VIRTIO_GUEST_MEM_SIZE - dev->queue.desc_addr;
		driver_valid = !(dev->queue.driver_addr & 1) && dev->queue.driver_addr <= VIRTIO_GUEST_MEM_SIZE && VIRTQ_AVAIL_BYTES <= VIRTIO_GUEST_MEM_SIZE - dev->queue.driver_addr;
		device_valid = !(dev->queue.device_addr & 3) && dev->queue.device_addr <= VIRTIO_GUEST_MEM_SIZE && VIRTQ_USED_BYTES <= VIRTIO_GUEST_MEM_SIZE - dev->queue.device_addr;
		ranges_disjoint = dev->queue.desc_addr + VIRTQ_DESC_BYTES <= dev->queue.driver_addr || dev->queue.driver_addr + VIRTQ_AVAIL_BYTES <= dev->queue.desc_addr;
		ranges_disjoint = ranges_disjoint && (dev->queue.desc_addr + VIRTQ_DESC_BYTES <= dev->queue.device_addr || dev->queue.device_addr + VIRTQ_USED_BYTES <= dev->queue.desc_addr);
		ranges_disjoint = ranges_disjoint && (dev->queue.driver_addr + VIRTQ_AVAIL_BYTES <= dev->queue.device_addr || dev->queue.device_addr + VIRTQ_USED_BYTES <= dev->queue.driver_addr);
		if (dev->queue.size != VIRTQ_SIZE || !desc_valid || !driver_valid || !device_valid || !ranges_disjoint)
		{
			fprintf(stderr, "virtio: QueueReady rejected size=%u desc=0x%016llx driver=0x%016llx device=0x%016llx\n", dev->queue.size, (unsigned long long)dev->queue.desc_addr, (unsigned long long)dev->queue.driver_addr, (unsigned long long)dev->queue.device_addr);
			return -1;
		}
		dev->queue.ready = 1;
		fprintf(stderr, "virtio: QueueReady[0] = 1\n");
		return 0;
	}
	case VIRTIO_MMIO_QUEUE_NOTIFY:
		fprintf(stderr, "virtio: QueueNotify queue=%u\n", value);
		if (value != VIRTQ_INDEX)
		{
			fprintf(stderr, "virtio: QueueNotify for unsupported queue %u\n", value);
			return -1;
		}
		if ((dev->status & (VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK)) != (VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK) || dev->queue.ready != 1)
		{
			fprintf(stderr, "virtio: QueueNotify requires FEATURES_OK, DRIVER_OK, and ready queue zero\n");
			return -1;
		}
		return process_queue(vm, dev, guest_mem);
	case VIRTIO_MMIO_INTERRUPT_ACK:
	{
		uint32_t old = dev->interrupt_status;

		if (value & ~VIRTIO_MMIO_INT_VRING)
		{
			fprintf(stderr, "virtio: InterruptACK contains unsupported bits 0x%08x\n", value & ~VIRTIO_MMIO_INT_VRING);
			return -1;
		}
		fprintf(stderr, "virtio: InterruptACK = 0x%02x\n", value);
		dev->interrupt_status &= ~value;
		fprintf(stderr, "virtio: InterruptStatus 0x%02x -> 0x%02x\n", old, dev->interrupt_status);
		if (dev->interrupt_status == 0 && set_irq_level(vm, dev, 0) < 0)
			return -1;
		return 0;
	}
	case VIRTIO_MMIO_STATUS:
	{
		const uint32_t supported = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_FAILED;
		uint32_t old = dev->status;
		uint32_t accepted = value;

		/* Status bits accumulate until reset, while FEATURES_OK remains set only after exact feature validation. */
		if (value == 0)
		{
			if (set_irq_level(vm, dev, 0) < 0)
				return -1;
			dev->status = 0;
			dev->device_features_sel = 0;
			dev->driver_features_sel = 0;
			dev->driver_features[0] = 0;
			dev->driver_features[1] = 0;
			dev->queue_sel = 0;
			dev->queue.size = 0;
			dev->queue.ready = 0;
			dev->queue.last_avail_idx = 0;
			dev->queue.desc_addr = 0;
			dev->queue.driver_addr = 0;
			dev->queue.device_addr = 0;
			dev->interrupt_status = 0;
			fprintf(stderr, "virtio: status 0x%02x -> 0x00 (reset)\n", old);
			return 0;
		}
		if (value & ~supported)
		{
			fprintf(stderr, "virtio: unsupported status bits 0x%08x\n", value & ~supported);
			return -1;
		}
		if ((value & old) != old)
		{
			fprintf(stderr, "virtio: status bits may only be cleared by reset\n");
			return -1;
		}
		if ((value & VIRTIO_STATUS_DRIVER) && !(value & VIRTIO_STATUS_ACKNOWLEDGE))
		{
			fprintf(stderr, "virtio: DRIVER requires ACKNOWLEDGE\n");
			return -1;
		}
		if ((value & VIRTIO_STATUS_FEATURES_OK) && (value & (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER)) != (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER))
		{
			fprintf(stderr, "virtio: FEATURES_OK requires ACKNOWLEDGE | DRIVER\n");
			return -1;
		}
		if (value & VIRTIO_STATUS_DRIVER_OK)
		{
			int desc_valid = !(dev->queue.desc_addr & 15) && dev->queue.desc_addr <= VIRTIO_GUEST_MEM_SIZE && VIRTQ_DESC_BYTES <= VIRTIO_GUEST_MEM_SIZE - dev->queue.desc_addr;
			int driver_valid = !(dev->queue.driver_addr & 1) && dev->queue.driver_addr <= VIRTIO_GUEST_MEM_SIZE && VIRTQ_AVAIL_BYTES <= VIRTIO_GUEST_MEM_SIZE - dev->queue.driver_addr;
			int device_valid = !(dev->queue.device_addr & 3) && dev->queue.device_addr <= VIRTIO_GUEST_MEM_SIZE && VIRTQ_USED_BYTES <= VIRTIO_GUEST_MEM_SIZE - dev->queue.device_addr;
			int ranges_disjoint = dev->queue.desc_addr + VIRTQ_DESC_BYTES <= dev->queue.driver_addr || dev->queue.driver_addr + VIRTQ_AVAIL_BYTES <= dev->queue.desc_addr;

			ranges_disjoint = ranges_disjoint && (dev->queue.desc_addr + VIRTQ_DESC_BYTES <= dev->queue.device_addr || dev->queue.device_addr + VIRTQ_USED_BYTES <= dev->queue.desc_addr);
			ranges_disjoint = ranges_disjoint && (dev->queue.driver_addr + VIRTQ_AVAIL_BYTES <= dev->queue.device_addr || dev->queue.device_addr + VIRTQ_USED_BYTES <= dev->queue.driver_addr);
			/* DRIVER_OK means feature negotiation is complete and queue zero is ready for device operation. */
			if (!(old & VIRTIO_STATUS_FEATURES_OK) || dev->queue.size != VIRTQ_SIZE || dev->queue.ready != 1 || !desc_valid || !driver_valid || !device_valid || !ranges_disjoint)
			{
				fprintf(stderr, "virtio: DRIVER_OK requires accepted features and a valid ready queue\n");
				return -1;
			}
		}
		if ((value & VIRTIO_STATUS_FEATURES_OK) && !(old & VIRTIO_STATUS_FEATURES_OK))
		{
			/* Virtio requires the device to clear FEATURES_OK when it cannot accept the driver's feature set. */
			if (dev->driver_features[0] != 0 || dev->driver_features[1] != VIRTIO_VERSION_1_WORD_MASK)
			{
				accepted &= ~VIRTIO_STATUS_FEATURES_OK;
				fprintf(stderr, "virtio: FEATURES_OK rejected (driver words 0x%08x 0x%08x)\n", dev->driver_features[0], dev->driver_features[1]);
			}
			else
				fprintf(stderr, "virtio: FEATURES_OK accepted\n");
		}
		dev->status = accepted;
		fprintf(stderr, "virtio: status 0x%02x -> 0x%02x\n", old, dev->status);
		return 0;
	}
	case VIRTIO_MMIO_MAGIC_VALUE:
	case VIRTIO_MMIO_VERSION:
	case VIRTIO_MMIO_DEVICE_ID:
	case VIRTIO_MMIO_VENDOR_ID:
	case VIRTIO_MMIO_DEVICE_FEATURES:
	case VIRTIO_MMIO_QUEUE_SIZE_MAX:
	case VIRTIO_MMIO_INTERRUPT_STATUS:
		fprintf(stderr, "virtio-mmio: write to read-only %s\n", register_name(offset));
		return -1;
	default:
		fprintf(stderr, "virtio-mmio: write to unimplemented offset 0x%03x\n", offset);
		return -1;
	}
}

/* Each guest register access arrives here as one KVM_EXIT_MMIO that must be a little-endian aligned 32-bit operation. */
static int handle_mmio(int vm, struct virtio_mmio_device *dev, uint8_t *guest_mem, struct kvm_run *run)
{
	uint64_t address = run->mmio.phys_addr;
	uint32_t offset;
	uint32_t value;

	if (address < VIRTIO_MMIO_BASE || address > (uint64_t)VIRTIO_MMIO_BASE + VIRTIO_MMIO_WINDOW_SIZE - 4)
	{
		fprintf(stderr, "virtio-mmio: access outside window at 0x%llx\n", (unsigned long long)address);
		return -1;
	}
	if (run->mmio.len != 4)
	{
		fprintf(stderr, "virtio-mmio: invalid access length %u\n", run->mmio.len);
		return -1;
	}
	if (address & 3)
	{
		fprintf(stderr, "virtio-mmio: unaligned access at 0x%llx\n", (unsigned long long)address);
		return -1;
	}

	offset = (uint32_t)(address - VIRTIO_MMIO_BASE);
	if (run->mmio.is_write)
	{
		/* KVM places the guest's little-endian write value in the MMIO exit data buffer. */
		memcpy(&value, run->mmio.data, sizeof(value));
		return write_register(vm, dev, guest_mem, offset, value);
	}
	if (read_register(dev, offset, &value) < 0)
		return -1;
	/* The VMM completes an MMIO read by copying the register value into KVM's exit data buffer. */
	memcpy(run->mmio.data, &value, sizeof(value));
	return 0;
}

/* One KVM memory slot maps guest physical addresses 0 through 0x1ffff onto this userspace allocation. */
static int set_memory_region(int vm, uint8_t *memory)
{
	/* KVM translates a guest physical address by adding its slot offset to userspace_addr. */
	struct kvm_userspace_memory_region region = {
		.slot = 0, /* This experiment needs only one contiguous guest RAM slot. */
		.guest_phys_addr = 0, /* Guest RAM begins at guest physical address zero. */
		.memory_size = VIRTIO_GUEST_MEM_SIZE, /* The slot covers the complete 128 KiB guest RAM model. */
		.userspace_addr = (uint64_t)memory, /* This is the host virtual address backing guest RAM. */
	};

	return ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region);
}

int main(void)
{
	struct virtio_mmio_device dev = {0}; /* Zero initialization matches the virtio device's reset state. */
	uint8_t *guest_mem;
	struct kvm_run *run;
	struct kvm_sregs sregs;
	struct virtq_desc *desc;
	struct virtq_avail *avail;
	struct virtq_used *used;
	uint32_t *irq_count;
	uint32_t *observed_interrupt_status;
	size_t guest_size;
	int kvm, vm, vcpu, run_size;
	int success = 0;

	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm < 0)
	{
		perror("open /dev/kvm");
		return 1;
	}
	if (ioctl(kvm, KVM_GET_API_VERSION, 0) != 12)
	{
		fprintf(stderr, "unexpected KVM API version\n");
		return 1;
	}
	vm = ioctl(kvm, KVM_CREATE_VM, 0);
	if (vm < 0)
	{
		perror("KVM_CREATE_VM");
		return 1;
	}
	/* The in-kernel PIC, IOAPIC, and per-vCPU LAPIC deliver the fixed virtio platform interrupt. */
	if (ioctl(vm, KVM_CREATE_IRQCHIP, 0) < 0)
	{
		perror("KVM_CREATE_IRQCHIP");
		return 1;
	}

	/* Anonymous host memory supplies the HVA backing for the guest's single GPA range. */
	guest_mem = mmap(NULL, VIRTIO_GUEST_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (guest_mem == MAP_FAILED)
	{
		perror("mmap guest memory");
		return 1;
	}

	FILE *guest = fopen("build/guest.bin", "rb");
	if (!guest)
	{
		perror("fopen build/guest.bin");
		return 1;
	}
	guest_size = fread(guest_mem, 1, VIRTIO_GUEST_MEM_SIZE, guest);
	if (ferror(guest))
	{
		perror("fread build/guest.bin");
		return 1;
	}
	if (guest_size > VIRTIO_GUEST_CODE_LIMIT)
	{
		fprintf(stderr, "guest image exceeds reserved code region\n");
		return 1;
	}
	if (fgetc(guest) != EOF)
	{
		fprintf(stderr, "guest image exceeds guest RAM\n");
		return 1;
	}
	fclose(guest);

	if (set_memory_region(vm, guest_mem) < 0)
	{
		perror("KVM_SET_USER_MEMORY_REGION");
		return 1;
	}
	vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
	if (vcpu < 0)
	{
		perror("KVM_CREATE_VCPU");
		return 1;
	}
	run_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (run_size < 0)
	{
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return 1;
	}
	run = mmap(NULL, (size_t)run_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
	if (run == MAP_FAILED)
	{
		perror("mmap kvm_run");
		return 1;
	}

	/* The VMM starts the vCPU in real mode at address zero, and guest.S performs the protected-mode transition. */
	if (ioctl(vcpu, KVM_GET_SREGS, &sregs) < 0)
	{
		perror("KVM_GET_SREGS");
		return 1;
	}
	sregs.cs.selector = 0;
	sregs.cs.base = 0;
	if (ioctl(vcpu, KVM_SET_SREGS, &sregs) < 0)
	{
		perror("KVM_SET_SREGS");
		return 1;
	}
	struct kvm_regs regs = {.rip = 0, .rflags = 0x2};
	if (ioctl(vcpu, KVM_SET_REGS, &regs) < 0)
	{
		perror("KVM_SET_REGS");
		return 1;
	}

	for (;;)
	{
		/* KVM_RUN returns whenever the guest needs userspace to handle an exit. */
		if (ioctl(vcpu, KVM_RUN, 0) < 0)
		{
			perror("KVM_RUN");
			return 1;
		}
		if (run->exit_reason == KVM_EXIT_MMIO)
		{
			if (handle_mmio(vm, &dev, guest_mem, run) < 0)
				return 1;
			continue;
		}
		if (run->exit_reason == KVM_EXIT_IO)
		{
			/* The guest uses one-byte output ports only to report an explicit test result. */
			uint8_t *data = (uint8_t *)run + run->io.data_offset;

			if (run->io.direction != KVM_EXIT_IO_OUT || run->io.size != 1 || run->io.count != 1)
			{
				fprintf(stderr, "unexpected completion-port access\n");
				return 1;
			}
			if (run->io.port == VIRTIO_TEST_FAILURE_PORT)
			{
				fprintf(stderr, "guest reported failure code %u\n", data[0]);
				return 1;
			}
			if (run->io.port != VIRTIO_TEST_SUCCESS_PORT)
			{
				fprintf(stderr, "unexpected guest I/O port 0x%x\n", run->io.port);
				return 1;
			}
			if (dev.status != VIRTIO_STATUS_CHECKPOINT2 || dev.driver_features[0] != 0 || dev.driver_features[1] != VIRTIO_VERSION_1_WORD_MASK || dev.interrupt_status != 0 || dev.irq_asserted != 0)
			{
				fprintf(stderr, "guest signaled success with invalid virtio state\n");
				return 1;
			}
			if (dev.queue_sel != VIRTQ_INDEX || dev.queue.size != VIRTQ_SIZE || dev.queue.ready != 1 || dev.queue.last_avail_idx != 1 || dev.queue.desc_addr != DESC_GPA || dev.queue.driver_addr != AVAIL_GPA || dev.queue.device_addr != USED_GPA)
			{
				fprintf(stderr, "guest signaled success with an unexpected queue configuration\n");
				return 1;
			}
			if (DESC_GPA > VIRTIO_GUEST_MEM_SIZE || VIRTQ_DESC_BYTES > VIRTIO_GUEST_MEM_SIZE - DESC_GPA || AVAIL_GPA > VIRTIO_GUEST_MEM_SIZE || VIRTQ_AVAIL_BYTES > VIRTIO_GUEST_MEM_SIZE - AVAIL_GPA || USED_GPA > VIRTIO_GUEST_MEM_SIZE || VIRTQ_USED_BYTES > VIRTIO_GUEST_MEM_SIZE - USED_GPA || RNG_BUFFER_GPA > VIRTIO_GUEST_MEM_SIZE || RNG_REQUEST_LEN > VIRTIO_GUEST_MEM_SIZE - RNG_BUFFER_GPA || VIRTIO_IRQ_COUNT_GPA > VIRTIO_GUEST_MEM_SIZE - sizeof(*irq_count) || VIRTIO_IRQ_STATUS_GPA > VIRTIO_GUEST_MEM_SIZE - sizeof(*observed_interrupt_status))
			{
				fprintf(stderr, "fixed queue or request range lies outside guest RAM\n");
				return 1;
			}
			/* Only after validating each GPA range may the VMM translate it to guest_mem plus GPA. */
			desc = (struct virtq_desc *)(guest_mem + DESC_GPA);
			avail = (struct virtq_avail *)(guest_mem + AVAIL_GPA);
			used = (struct virtq_used *)(guest_mem + USED_GPA);
			irq_count = (uint32_t *)(guest_mem + VIRTIO_IRQ_COUNT_GPA);
			observed_interrupt_status = (uint32_t *)(guest_mem + VIRTIO_IRQ_STATUS_GPA);
			if (desc[0].addr != RNG_BUFFER_GPA || desc[0].len != RNG_REQUEST_LEN || desc[0].flags != VIRTQ_DESC_F_WRITE || desc[0].next != 0)
			{
				fprintf(stderr, "descriptor zero does not match the one-buffer entropy request\n");
				return 1;
			}
			if (avail->flags != 0 || avail->idx != 1 || avail->ring[0] != 0 || used->idx != 1 || used->ring[0].id != 0 || used->ring[0].len != RNG_REQUEST_LEN)
			{
				fprintf(stderr, "shared rings do not contain the expected request and completion\n");
				return 1;
			}
			if (*irq_count != 1 || *observed_interrupt_status != VIRTIO_MMIO_INT_VRING)
			{
				fprintf(stderr, "guest did not service exactly one virtio completion interrupt\n");
				return 1;
			}
			success = 1;
			break;
		}
		if (run->exit_reason == KVM_EXIT_HLT)
		{
			fprintf(stderr, "guest halted without explicit success\n");
			return 1;
		}
		fprintf(stderr, "unexpected KVM exit reason: %u\n", run->exit_reason);
		return 1;
	}

	if (!success)
		return 1;
	fprintf(stderr, "virtio checkpoint 4: completion interrupt serviced, used.idx=%u irq_count=%u\n", (unsigned int)used->idx, *irq_count);
	fprintf(stderr, "virtio checkpoint 4: interrupt_status=0x%02x GSI=%s, used[0]={id=%u len=%u}\n", dev.interrupt_status, dev.irq_asserted ? "asserted" : "deasserted", used->ring[0].id, used->ring[0].len);
	return 0;
}
