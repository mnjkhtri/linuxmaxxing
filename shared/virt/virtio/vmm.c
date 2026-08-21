// SPDX-License-Identifier: GPL-2.0
/* This VMM exposes one modern virtio-mmio entropy device backed by one split virtqueue. */
/* The request lives in guest RAM, and QueueNotify is only the MMIO doorbell that asks the backend to inspect it. */
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include "backend.h"
#include "virtio.h"

/* read_register() is the complete readable side of this experiment's virtio-mmio transport. */
static int read_register(struct virtio_mmio_device *dev, uint32_t offset, uint32_t *value)
{
	switch (offset)
	{
	case VIRTIO_MMIO_MAGIC_VALUE:
		*value = VIRTIO_MAGIC_VALUE;
		return 0;
	case VIRTIO_MMIO_VERSION:
		*value = VIRTIO_VERSION_MODERN;
		return 0;
	case VIRTIO_MMIO_DEVICE_ID:
		*value = VIRTIO_DEVICE_ID_ENTROPY;
		return 0;
	case VIRTIO_MMIO_VENDOR_ID:
		*value = VIRTIO_EXPERIMENT_VENDOR_ID;
		return 0;
	case VIRTIO_MMIO_DEVICE_FEATURES:
		/* Word one bit zero is global feature bit 32, VIRTIO_F_VERSION_1. */
		*value = dev->device_features_sel == VIRTIO_F_VERSION_1_WORD ? VIRTIO_F_VERSION_1_MASK : 0;
		return 0;
	case VIRTIO_MMIO_STATUS:
		*value = dev->status;
		return 0;
	case VIRTIO_MMIO_QUEUE_SIZE_MAX:
		*value = dev->queue_sel == VIRTIO_RNG_QUEUE_INDEX ? VIRTQ_SIZE : 0;
		return 0;
	case VIRTIO_MMIO_QUEUE_READY:
		*value = dev->queue_sel == VIRTIO_RNG_QUEUE_INDEX ? dev->queue.ready : 0;
		return 0;
	case VIRTIO_MMIO_INTERRUPT_STATUS:
		*value = __atomic_load_n(&dev->interrupt_status, __ATOMIC_ACQUIRE);
		return 0;
	case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
	case VIRTIO_MMIO_DRIVER_FEATURES:
	case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
	case VIRTIO_MMIO_QUEUE_SEL:
	case VIRTIO_MMIO_QUEUE_SIZE:
	case VIRTIO_MMIO_QUEUE_NOTIFY:
	case VIRTIO_MMIO_INTERRUPT_ACK:
	case VIRTIO_MMIO_QUEUE_DESC_LOW:
	case VIRTIO_MMIO_QUEUE_DESC_HIGH:
	case VIRTIO_MMIO_QUEUE_DRIVER_LOW:
	case VIRTIO_MMIO_QUEUE_DRIVER_HIGH:
	case VIRTIO_MMIO_QUEUE_DEVICE_LOW:
	case VIRTIO_MMIO_QUEUE_DEVICE_HIGH:
		fprintf(stderr, "virtio-mmio: read from write-only register 0x%03x\n", offset);
		return -1;
	default:
		fprintf(stderr, "virtio-mmio: read from unimplemented offset 0x%03x\n", offset);
		return -1;
	}
}

/* write_register() is the complete writable side of this experiment's virtio-mmio transport. */
static int write_register(struct virtio_mmio_device *dev, uint8_t *guest_mem, uint32_t offset, uint32_t value)
{
	switch (offset)
	{
	case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
		dev->device_features_sel = value;
		return 0;
	case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
		if (dev->status & VIRTIO_STATUS_FEATURES_OK)
			return -1;
		dev->driver_features_sel = value;
		return 0;
	case VIRTIO_MMIO_DRIVER_FEATURES:
		if ((dev->status & VIRTIO_STATUS_FEATURES_OK) || dev->driver_features_sel >= 2)
			return -1;
		dev->driver_features[dev->driver_features_sel] = value;
		return 0;
	case VIRTIO_MMIO_QUEUE_SEL:
		dev->queue_sel = value;
		return 0;
	case VIRTIO_MMIO_QUEUE_SIZE:
		if (dev->queue_sel != VIRTIO_RNG_QUEUE_INDEX || dev->queue.ready || value != VIRTQ_SIZE)
			return -1;
		dev->queue.size = value;
		return 0;
	case VIRTIO_MMIO_QUEUE_DESC_LOW:
		if (dev->queue_sel != VIRTIO_RNG_QUEUE_INDEX || dev->queue.ready)
			return -1;
		dev->queue.desc_addr = (dev->queue.desc_addr & 0xffffffff00000000ULL) | value;
		return 0;
	case VIRTIO_MMIO_QUEUE_DESC_HIGH:
		if (dev->queue_sel != VIRTIO_RNG_QUEUE_INDEX || dev->queue.ready)
			return -1;
		dev->queue.desc_addr = (dev->queue.desc_addr & 0x00000000ffffffffULL) | ((uint64_t)value << 32);
		return 0;
	case VIRTIO_MMIO_QUEUE_DRIVER_LOW:
		if (dev->queue_sel != VIRTIO_RNG_QUEUE_INDEX || dev->queue.ready)
			return -1;
		dev->queue.driver_addr = (dev->queue.driver_addr & 0xffffffff00000000ULL) | value;
		return 0;
	case VIRTIO_MMIO_QUEUE_DRIVER_HIGH:
		if (dev->queue_sel != VIRTIO_RNG_QUEUE_INDEX || dev->queue.ready)
			return -1;
		dev->queue.driver_addr = (dev->queue.driver_addr & 0x00000000ffffffffULL) | ((uint64_t)value << 32);
		return 0;
	case VIRTIO_MMIO_QUEUE_DEVICE_LOW:
		if (dev->queue_sel != VIRTIO_RNG_QUEUE_INDEX || dev->queue.ready)
			return -1;
		dev->queue.device_addr = (dev->queue.device_addr & 0xffffffff00000000ULL) | value;
		return 0;
	case VIRTIO_MMIO_QUEUE_DEVICE_HIGH:
		if (dev->queue_sel != VIRTIO_RNG_QUEUE_INDEX || dev->queue.ready)
			return -1;
		dev->queue.device_addr = (dev->queue.device_addr & 0x00000000ffffffffULL) | ((uint64_t)value << 32);
		return 0;
	case VIRTIO_MMIO_QUEUE_READY:
		if (dev->queue_sel != VIRTIO_RNG_QUEUE_INDEX || value > 1)
			return -1;
		if (value == 0)
		{
			dev->queue.ready = 0;
			return 0;
		}
		/* This educational backend supports only its controlled guest's fixed layout; production backends validate arbitrary driver-provided queue memory. */
		if (dev->queue.size != VIRTQ_SIZE || dev->queue.desc_addr != VIRTQ_DESC_GPA || dev->queue.driver_addr != VIRTQ_AVAIL_GPA || dev->queue.device_addr != VIRTQ_USED_GPA)
		{
			fprintf(stderr, "virtio B: fixed queue layout rejected\n");
			return -1;
		}
		dev->queue.ready = 1;
		return 0;
	case VIRTIO_MMIO_QUEUE_NOTIFY:
		if (value != VIRTIO_RNG_QUEUE_INDEX || dev->status != VIRTIO_STATUS_OPERATIONAL || !dev->queue.ready)
		{
			fprintf(stderr, "virtio C: QueueNotify requires operational queue zero\n");
			return -1;
		}
		return process_queue(dev, guest_mem);
	case VIRTIO_MMIO_INTERRUPT_ACK:
		if (value & ~VIRTIO_MMIO_INT_VRING)
		{
			fprintf(stderr, "virtio D: unsupported InterruptACK bits 0x%08x\n", value);
			return -1;
		}
		__atomic_fetch_and(&dev->interrupt_status, ~value, __ATOMIC_RELEASE);
		return 0;
	case VIRTIO_MMIO_STATUS:
	{
		const uint32_t supported = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK;
		uint32_t old = dev->status;
		uint32_t accepted = value;

		if (value == 0)
		{
			dev->status = 0;
			dev->device_features_sel = 0;
			dev->driver_features_sel = 0;
			dev->driver_features[0] = 0;
			dev->driver_features[1] = 0;
			__atomic_store_n(&dev->interrupt_status, 0, __ATOMIC_RELEASE);
			dev->queue_sel = 0;
			dev->queue.size = 0;
			dev->queue.ready = 0;
			dev->queue.last_avail_idx = 0;
			dev->queue.desc_addr = 0;
			dev->queue.driver_addr = 0;
			dev->queue.device_addr = 0;
			return 0;
		}
		if ((value & ~supported) || (value & old) != old)
		{
			fprintf(stderr, "virtio A: invalid non-monotonic status value 0x%02x\n", value);
			return -1;
		}
		if ((value & VIRTIO_STATUS_FEATURES_OK) && !(old & VIRTIO_STATUS_FEATURES_OK))
		{
			if ((value & (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER)) != (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) || dev->driver_features[0] != 0 || dev->driver_features[1] != VIRTIO_F_VERSION_1_MASK)
			{
				accepted &= ~VIRTIO_STATUS_FEATURES_OK;
				fprintf(stderr, "virtio A: FEATURES_OK rejected\n");
			}
			else
				fprintf(stderr, "virtio A: device=virtio-rng version=2 VERSION_1 negotiated\n");
		}
		if ((value & VIRTIO_STATUS_DRIVER_OK) && !(old & VIRTIO_STATUS_DRIVER_OK))
		{
			if (!(old & VIRTIO_STATUS_FEATURES_OK) || !dev->queue.ready || dev->queue.size != VIRTQ_SIZE || dev->queue.desc_addr != VIRTQ_DESC_GPA || dev->queue.driver_addr != VIRTQ_AVAIL_GPA || dev->queue.device_addr != VIRTQ_USED_GPA)
			{
				fprintf(stderr, "virtio B: DRIVER_OK requires the fixed ready queue\n");
				return -1;
			}
			fprintf(stderr, "virtio B:\n");
			fprintf(stderr, "  queue 0 ready size=8 desc=0x4000 avail=0x5000 used=0x6000\n");
			fprintf(stderr, "  status=DRIVER_OK\n");
		}
		dev->status = accepted;
		return 0;
	}
	case VIRTIO_MMIO_MAGIC_VALUE:
	case VIRTIO_MMIO_VERSION:
	case VIRTIO_MMIO_DEVICE_ID:
	case VIRTIO_MMIO_VENDOR_ID:
	case VIRTIO_MMIO_DEVICE_FEATURES:
	case VIRTIO_MMIO_QUEUE_SIZE_MAX:
	case VIRTIO_MMIO_INTERRUPT_STATUS:
		fprintf(stderr, "virtio-mmio: write to read-only register 0x%03x\n", offset);
		return -1;
	default:
		fprintf(stderr, "virtio-mmio: write to unimplemented offset 0x%03x\n", offset);
		return -1;
	}
}

/* do_mmio() handles accesses returned to userspace; the Phase-D QueueNotify is intercepted by ioeventfd and never reaches this function. */
static int do_mmio(struct virtio_mmio_device *dev, uint8_t *guest_mem, struct kvm_run *run)
{
	uint64_t address = run->mmio.phys_addr;
	uint32_t offset;
	uint32_t value;

	if (address < VIRTIO_MMIO_BASE || address > (uint64_t)VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE - 4 || run->mmio.len != 4 || (address & 3))
	{
		fprintf(stderr, "virtio-mmio: invalid access address=0x%llx length=%u\n", (unsigned long long)address, run->mmio.len);
		return -1;
	}

	offset = (uint32_t)(address - VIRTIO_MMIO_BASE);
	if (run->mmio.is_write)
	{
		memcpy(&value, run->mmio.data, sizeof(value));
		return write_register(dev, guest_mem, offset, value);
	}
	if (read_register(dev, offset, &value) < 0)
		return -1;
	memcpy(run->mmio.data, &value, sizeof(value));
	return 0;
}

/* One KVM memory slot maps GPA 0 through 0x1ffff onto one userspace allocation. */
static int set_memory_region(int vm, uint8_t *memory)
{
	struct kvm_userspace_memory_region region = {
		.slot = 0,
		.guest_phys_addr = 0,
		.memory_size = VIRTIO_GUEST_MEM_SIZE,
		.userspace_addr = (uint64_t)memory,
	};

	return ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region);
}

int main(void)
{
	struct virtio_mmio_device dev = {0};
	struct kvm_sregs sregs;
	struct kvm_regs regs = {.rip = 0, .rflags = 0x2};
	struct kvm_run *run;
	struct virtq_desc *desc;
	struct virtq_avail *avail;
	struct virtq_used *used;
	struct virtio_backend backend = {.kick_fd = -1, .call_fd = -1};
	struct kvm_ioeventfd ioevent = {0};
	struct kvm_irqfd irqevent = {0};
	pthread_t backend_thread;
	uint8_t *guest_mem;
	size_t guest_size;
	unsigned int queue_notify_exits = 0;
	int ioeventfd_registered = 0;
	int irqfd_registered = 0;
	int worker_started = 0;
	int run_result = 1;
	int kvm;
	int vm;
	int vcpu;
	int run_size;

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
	if (ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IOEVENTFD) <= 0)
	{
		fprintf(stderr, "KVM_CAP_IOEVENTFD is unavailable\n");
		return 1;
	}
	if (ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IRQCHIP) <= 0 || ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IRQFD) <= 0 || ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IRQ_ROUTING) <= 0)
	{
		fprintf(stderr, "KVM irqchip, irqfd, or IRQ routing support is unavailable\n");
		return 1;
	}
	vm = ioctl(kvm, KVM_CREATE_VM, 0);
	if (vm < 0)
	{
		perror("KVM_CREATE_VM");
		return 1;
	}
	if (ioctl(vm, KVM_CREATE_IRQCHIP, 0) < 0)
	{
		perror("KVM_CREATE_IRQCHIP");
		return 1;
	}
	{
		struct
		{
			struct kvm_irq_routing routing;
			struct kvm_irq_routing_entry entry;
		} route = {0};

		/* The backend's call eventfd reaches the guest through one fixed master-PIC IRQ5 route. */
		route.routing.nr = 1;
		route.entry.gsi = VIRTIO_IRQ_GSI;
		route.entry.type = KVM_IRQ_ROUTING_IRQCHIP;
		route.entry.u.irqchip.irqchip = KVM_IRQCHIP_PIC_MASTER;
		route.entry.u.irqchip.pin = VIRTIO_IRQ_GSI;
		if (ioctl(vm, KVM_SET_GSI_ROUTING, &route) < 0)
		{
			perror("KVM_SET_GSI_ROUTING");
			return 1;
		}
	}

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
	if (ferror(guest) || guest_size > VIRTIO_GUEST_CODE_LIMIT || fgetc(guest) != EOF)
	{
		fprintf(stderr, "guest image does not fit its reserved code region\n");
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

	/* The vCPU starts in real mode at GPA zero, and guest.S performs the protected-mode transition. */
	if (ioctl(vcpu, KVM_GET_SREGS, &sregs) < 0)
	{
		perror("KVM_GET_SREGS");
		return 1;
	}
	sregs.cs.selector = 0;
	sregs.cs.base = 0;
	if (ioctl(vcpu, KVM_SET_SREGS, &sregs) < 0 || ioctl(vcpu, KVM_SET_REGS, &regs) < 0)
	{
		perror("initialize vCPU registers");
		return 1;
	}

	for (;;)
	{
		if (ioctl(vcpu, KVM_RUN, 0) < 0)
		{
			perror("KVM_RUN");
			break;
		}
		if (run->exit_reason == KVM_EXIT_MMIO)
		{
			if (run->mmio.is_write && run->mmio.phys_addr == VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY)
			{
				queue_notify_exits++;
				if (ioeventfd_registered)
				{
					fprintf(stderr, "virtio D: QueueNotify unexpectedly reached userspace MMIO\n");
					break;
				}
			}
			if (do_mmio(&dev, guest_mem, run) < 0)
				break;
			if (queue_notify_exits == 2 && !ioeventfd_registered)
			{
				struct virtq_avail *phase_c_avail = (struct virtq_avail *)(guest_mem + VIRTQ_AVAIL_GPA);
				struct virtq_used *phase_c_used = (struct virtq_used *)(guest_mem + VIRTQ_USED_GPA);

				if (phase_c_avail->idx != VIRTIO_RNG_REQUEST_COUNT || phase_c_used->idx != VIRTIO_RNG_REQUEST_COUNT || dev.queue.last_avail_idx != VIRTIO_RNG_REQUEST_COUNT)
				{
					fprintf(stderr, "virtio D: refusing ioeventfd before Phase C completes\n");
					break;
				}
				backend.dev = &dev;
				backend.guest_mem = guest_mem;
				backend.kick_fd = eventfd(0, EFD_CLOEXEC);
				if (backend.kick_fd < 0)
				{
					perror("eventfd");
					break;
				}
				backend.call_fd = eventfd(0, EFD_CLOEXEC);
				if (backend.call_fd < 0)
				{
					perror("eventfd call_fd");
					break;
				}
				atomic_init(&backend.stop, false);
				ioevent.datamatch = VIRTIO_RNG_QUEUE_INDEX;
				ioevent.addr = VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY;
				ioevent.len = 4;
				ioevent.fd = backend.kick_fd;
				ioevent.flags = KVM_IOEVENTFD_FLAG_DATAMATCH;
				if (ioctl(vm, KVM_IOEVENTFD, &ioevent) < 0)
				{
					perror("KVM_IOEVENTFD");
					close(backend.kick_fd);
					backend.kick_fd = -1;
					break;
				}
				ioeventfd_registered = 1;
				irqevent.fd = backend.call_fd;
				irqevent.gsi = VIRTIO_IRQ_GSI;
				/* Plain irqfd drives one edge-routed PIC input for this controlled one-shot completion, so no resamplefd is needed. */
				if (ioctl(vm, KVM_IRQFD, &irqevent) < 0)
				{
					perror("KVM_IRQFD");
					break;
				}
				irqfd_registered = 1;
				if (pthread_create(&backend_thread, NULL, virtio_backend_worker, &backend) != 0)
				{
					fprintf(stderr, "pthread_create failed\n");
					break;
				}
				worker_started = 1;
				fprintf(stderr, "virtio D: accelerated notification\n");
				fprintf(stderr, "  KVM_IOEVENTFD addr=0x%llx len=%u datamatch=%llu\n", (unsigned long long)ioevent.addr, ioevent.len, (unsigned long long)ioevent.datamatch);
				fprintf(stderr, "  KVM_IRQFD call_fd -> GSI %u -> master PIC IRQ%u\n", VIRTIO_IRQ_GSI, VIRTIO_IRQ_GSI);
				fprintf(stderr, "  userspace backend worker ready\n");
			}
			continue;
		}
		if (run->exit_reason == KVM_EXIT_IO)
		{
			uint8_t *data = (uint8_t *)run + run->io.data_offset;

			if (run->io.direction != KVM_EXIT_IO_OUT || run->io.size != 1 || run->io.count != 1)
			{
				fprintf(stderr, "unexpected completion-port access\n");
				break;
			}
			if (run->io.port == VIRTIO_TEST_FAILURE_PORT)
			{
				fprintf(stderr, "guest reported failure code %u\n", data[0]);
				break;
			}
			if (run->io.port != VIRTIO_TEST_SUCCESS_PORT)
			{
				fprintf(stderr, "unexpected guest I/O port 0x%x\n", run->io.port);
				break;
			}
			run_result = 0;
			break;
		}
		if (run->exit_reason == KVM_EXIT_HLT)
			fprintf(stderr, "guest halted without explicit success\n");
		else
			fprintf(stderr, "unexpected KVM exit reason %u\n", run->exit_reason);
		break;
	}

	if (ioeventfd_registered)
	{
		struct kvm_ioeventfd deassign = ioevent;

		deassign.flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
		if (ioctl(vm, KVM_IOEVENTFD, &deassign) < 0)
		{
			perror("KVM_IOEVENTFD deassign");
			run_result = 1;
		}
	}
	if (irqfd_registered)
	{
		struct kvm_irqfd deassign = irqevent;

		deassign.flags = KVM_IRQFD_FLAG_DEASSIGN;
		if (ioctl(vm, KVM_IRQFD, &deassign) < 0)
		{
			perror("KVM_IRQFD deassign");
			run_result = 1;
		}
	}
	if (worker_started)
	{
		uint64_t wake = 1;
		ssize_t bytes;

		atomic_store_explicit(&backend.stop, true, memory_order_release);
		do
			bytes = write(backend.kick_fd, &wake, sizeof(wake));
		while (bytes < 0 && errno == EINTR);
		if (bytes != sizeof(wake))
		{
			perror("wake ioeventfd worker");
			run_result = 1;
		}
		if (pthread_join(backend_thread, NULL) != 0)
		{
			fprintf(stderr, "pthread_join failed\n");
			run_result = 1;
		}
	}
	if (backend.kick_fd >= 0)
		close(backend.kick_fd);
	if (backend.call_fd >= 0)
		close(backend.call_fd);
	if (run_result || backend.result < 0)
		return 1;

	desc = (struct virtq_desc *)(guest_mem + VIRTQ_DESC_GPA);
	avail = (struct virtq_avail *)(guest_mem + VIRTQ_AVAIL_GPA);
	used = (struct virtq_used *)(guest_mem + VIRTQ_USED_GPA);
	if (dev.status != VIRTIO_STATUS_OPERATIONAL || dev.driver_features[0] != 0 || dev.driver_features[1] != VIRTIO_F_VERSION_1_MASK)
	{
		fprintf(stderr, "guest signaled success with invalid feature or status state\n");
		return 1;
	}
	/* Device-side state must still describe the one live virtio-rng queue. */
	if (dev.queue_sel != VIRTIO_RNG_QUEUE_INDEX || dev.queue.size != VIRTQ_SIZE || !dev.queue.ready)
	{
		fprintf(stderr, "guest signaled success with invalid queue selection, size, or readiness\n");
		return 1;
	}
	if (dev.queue.desc_addr != VIRTQ_DESC_GPA || dev.queue.driver_addr != VIRTQ_AVAIL_GPA || dev.queue.device_addr != VIRTQ_USED_GPA)
	{
		fprintf(stderr, "guest signaled success with invalid queue addresses\n");
		return 1;
	}
	if (dev.queue.last_avail_idx != VIRTIO_TOTAL_REQUEST_COUNT)
	{
		fprintf(stderr, "guest signaled success before the backend consumed all available entries\n");
		return 1;
	}

	/* Shared guest RAM must contain six published and completed requests in queue order. */
	for (uint32_t index = 0; index < VIRTIO_TOTAL_REQUEST_COUNT; index++)
	{
		uint64_t expected_buffer = VIRTIO_RNG_BUFFER_GPA + (uint64_t)index * VIRTIO_RNG_BUFFER_STRIDE;

		if (desc[index].addr != expected_buffer || desc[index].len != VIRTIO_RNG_REQUEST_LEN || desc[index].flags != VIRTQ_DESC_F_WRITE || desc[index].next != 0)
		{
			fprintf(stderr, "guest signaled success with invalid descriptor %u\n", index);
			return 1;
		}
		if (avail->ring[index] != index)
		{
			fprintf(stderr, "guest signaled success with invalid available-ring slot %u\n", index);
			return 1;
		}
		if (used->ring[index].id != index || used->ring[index].len != VIRTIO_RNG_REQUEST_LEN)
		{
			fprintf(stderr, "guest signaled success with invalid used-ring slot %u\n", index);
			return 1;
		}
	}
	if (avail->idx != VIRTIO_TOTAL_REQUEST_COUNT || used->idx != VIRTIO_TOTAL_REQUEST_COUNT)
	{
		fprintf(stderr, "guest signaled success with invalid published queue indices\n");
		return 1;
	}
	if (queue_notify_exits != 2)
	{
		fprintf(stderr, "guest signaled success without exactly two QueueNotify exits\n");
		return 1;
	}
	if (backend.guest_kicks != 1)
	{
		fprintf(stderr, "guest signaled success without exactly one ioeventfd kick\n");
		return 1;
	}
	if (backend.guest_calls != 1 || __atomic_load_n(&dev.interrupt_status, __ATOMIC_ACQUIRE) != 0)
	{
		fprintf(stderr, "guest did not receive and acknowledge exactly one irqfd completion\n");
		return 1;
	}

	fprintf(stderr, "  first request: one request / one QueueNotify\n");
	fprintf(stderr, "  four-request batch: four requests / one QueueNotify\n");
	fprintf(stderr, "virtio D:\n");
	fprintf(stderr, "  guest handled irqfd completion and validated used.idx=%u\n", used->idx);
	fprintf(stderr, "  success\n\n");
	fprintf(stderr, "data path:\n");
	fprintf(stderr, "  total requests = %u\n", VIRTIO_TOTAL_REQUEST_COUNT);
	fprintf(stderr, "  guest QueueNotify writes = %u\n", queue_notify_exits + (unsigned int)backend.guest_kicks);
	fprintf(stderr, "  request-description MMIO exits = 0\n");
	fprintf(stderr, "  QueueNotify userspace MMIO exits = %u\n", queue_notify_exits);
	fprintf(stderr, "  ioeventfd kicks = %llu\n", (unsigned long long)backend.guest_kicks);
	fprintf(stderr, "  irqfd completion signals = %llu\n", (unsigned long long)backend.guest_calls);
	fprintf(stderr, "  Phase C completion = polling\n");
	fprintf(stderr, "  Phase D completion = interrupt\n");
	return 0;
}
