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
#include <sys/random.h>
#include <unistd.h>

#include "virtio.h"

/* Every address in this structure remains a guest physical address. */
struct virtio_queue
{
	uint32_t size;          /* QueueSize is the number of descriptor-table entries. */
	uint32_t ready;         /* QueueReady says that this queue's three memory areas are configured. */
	uint16_t last_avail_idx; /* The backend has consumed every available entry before this index. */
	uint64_t desc_addr;     /* QueueDesc is the descriptor-table GPA. */
	uint64_t driver_addr;   /* QueueDriver is the available-ring GPA. */
	uint64_t device_addr;   /* QueueDevice is the used-ring GPA. */
};

struct virtio_mmio_device
{
	uint32_t device_features_sel; /* DeviceFeaturesSel chooses the offered 32-bit feature word. */
	uint32_t driver_features_sel; /* DriverFeaturesSel chooses the accepted 32-bit feature word. */
	uint32_t driver_features[2];  /* The controlled guest negotiates only feature words zero and one. */
	uint32_t status;              /* Status records the modern virtio initialization handshake. */
	uint32_t queue_sel;           /* QueueSel identifies which queue the following queue registers address. */
	struct virtio_queue queue;    /* Virtio-rng exposes exactly one split virtqueue in this experiment. */
};

struct ioeventfd_backend
{
	struct virtio_mmio_device *dev; /* Both notification paths share the same device state. */
	uint8_t *guest_mem;             /* The worker translates queue GPAs through this KVM memory-slot mapping. */
	int kick_fd;                    /* KVM increments this eventfd when QueueNotify writes zero. */
	atomic_bool stop;               /* Shutdown wakes the worker without creating a guest-kick observation. */
	uint64_t guest_kicks;           /* This counts eventfd wakes caused by the registered guest doorbell. */
	int result;                     /* The worker preserves backend failure for the main thread. */
};

/* process_queue() is the virtio-rng backend, separate from the MMIO register interface below. */
static int process_queue(struct virtio_mmio_device *dev, uint8_t *guest_mem)
{
	struct virtq_desc *desc;
	struct virtq_avail *avail;
	struct virtq_used *used;
	struct virtq_desc request;
	uint16_t avail_idx;
	uint16_t pending;
	uint16_t slot;
	uint16_t head;
	uint16_t old_used_idx;
	uint64_t expected_buffer;
	uint8_t *buffer;

	if (!dev->queue.ready || dev->queue.size != VIRTQ_SIZE)
	{
		fprintf(stderr, "virtqueue backend: notification reached an unconfigured queue\n");
		return -1;
	}

	/* These fixed, validated GPAs become VMM host virtual addresses only when the backend accesses guest RAM. */
	desc = (struct virtq_desc *)(guest_mem + dev->queue.desc_addr);
	avail = (struct virtq_avail *)(guest_mem + dev->queue.driver_addr);
	used = (struct virtq_used *)(guest_mem + dev->queue.device_addr);

	avail_idx = avail->idx;
	/* The acquire fence keeps ring and descriptor reads after observing the guest's avail.idx publication. */
	atomic_thread_fence(memory_order_acquire);
	pending = (uint16_t)(avail_idx - dev->queue.last_avail_idx);
	if (pending == 0)
		return 0;
	if (pending > VIRTQ_SIZE)
	{
		fprintf(stderr, "virtqueue backend: available ring contains more entries than the queue can hold\n");
		return -1;
	}

	fprintf(stderr, "virtqueue backend: avail.idx=%u last_avail_idx=%u pending=%u\n", avail_idx, dev->queue.last_avail_idx, pending);
	while (dev->queue.last_avail_idx != avail_idx)
	{
		size_t filled = 0;

		slot = dev->queue.last_avail_idx % VIRTQ_SIZE;
		head = avail->ring[slot];
		if (head >= VIRTQ_SIZE)
		{
			fprintf(stderr, "virtqueue backend: avail[%u] names descriptor %u outside the table\n", slot, head);
			return -1;
		}
		request = desc[head];
		expected_buffer = VIRTIO_RNG_BUFFER_GPA + (uint64_t)head * VIRTIO_RNG_BUFFER_STRIDE;
		if (request.addr != expected_buffer || request.len != VIRTIO_RNG_REQUEST_LEN || request.flags != VIRTQ_DESC_F_WRITE || request.next != 0)
		{
			fprintf(stderr, "virtqueue backend: descriptor %u is not the expected direct writable entropy buffer\n", head);
			return -1;
		}

		/* A descriptor address is an untrusted GPA rather than a host pointer, so its complete range is checked before translation. */
		if (request.addr > VIRTIO_GUEST_MEM_SIZE || request.len > VIRTIO_GUEST_MEM_SIZE - request.addr)
		{
			fprintf(stderr, "virtqueue backend: descriptor %u buffer lies outside guest RAM\n", head);
			return -1;
		}
		buffer = guest_mem + request.addr;
		fprintf(stderr, "  avail[%u] -> desc[%u] -> GPA 0x%llx\n", slot, head, (unsigned long long)request.addr);
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

		old_used_idx = used->idx;
		slot = old_used_idx % VIRTQ_SIZE;
		used->ring[slot].id = head;
		used->ring[slot].len = request.len;
		/* The release fence publishes the entropy and used element before used.idx returns ownership to the guest. */
		atomic_thread_fence(memory_order_release);
		used->idx = (uint16_t)(old_used_idx + 1);
		dev->queue.last_avail_idx++;
		fprintf(stderr, "  used[%u] { id=%u len=%u } used.idx=%u\n", slot, head, request.len, used->idx);
	}
	return 0;
}

/* This stable boundary exposes an ioeventfd wake before the shared virtqueue backend consumes it. */
__attribute__((noinline)) static int process_ioeventfd_kick(struct virtio_mmio_device *dev, uint8_t *guest_mem, uint64_t eventfd_count)
{
	if (eventfd_count != 1)
	{
		fprintf(stderr, "virtio D: unexpected ioeventfd wake count=%llu\n", (unsigned long long)eventfd_count);
		return -1;
	}
	fprintf(stderr, "virtio D:\n");
	fprintf(stderr, "  ioeventfd wake count=%llu\n", (unsigned long long)eventfd_count);
	return process_queue(dev, guest_mem);
}

static void *ioeventfd_worker(void *opaque)
{
	struct ioeventfd_backend *backend = opaque;
	uint64_t count;
	ssize_t bytes;

	for (;;)
	{
		do
			bytes = read(backend->kick_fd, &count, sizeof(count));
		while (bytes < 0 && errno == EINTR);
		if (bytes != sizeof(count))
		{
			if (bytes < 0)
				perror("read ioeventfd");
			else
				fprintf(stderr, "virtio D: short ioeventfd read\n");
			backend->result = -1;
			return NULL;
		}
		if (atomic_load_explicit(&backend->stop, memory_order_acquire))
			return NULL;
		backend->guest_kicks += count;
		backend->result = process_ioeventfd_kick(backend->dev, backend->guest_mem, count);
		if (backend->result < 0)
			return NULL;
	}
}

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
	case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
	case VIRTIO_MMIO_DRIVER_FEATURES:
	case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
	case VIRTIO_MMIO_QUEUE_SEL:
	case VIRTIO_MMIO_QUEUE_SIZE:
	case VIRTIO_MMIO_QUEUE_NOTIFY:
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
	struct ioeventfd_backend backend = {.kick_fd = -1};
	struct kvm_ioeventfd ioevent = {0};
	pthread_t backend_thread;
	uint8_t *guest_mem;
	size_t guest_size;
	unsigned int queue_notify_exits = 0;
	int ioeventfd_registered = 0;
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
	vm = ioctl(kvm, KVM_CREATE_VM, 0);
	if (vm < 0)
	{
		perror("KVM_CREATE_VM");
		return 1;
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
				if (pthread_create(&backend_thread, NULL, ioeventfd_worker, &backend) != 0)
				{
					fprintf(stderr, "pthread_create failed\n");
					break;
				}
				worker_started = 1;
				fprintf(stderr, "virtio D:\n");
				fprintf(stderr, "  KVM_IOEVENTFD addr=0x%llx len=%u datamatch=%llu\n", (unsigned long long)ioevent.addr, ioevent.len, (unsigned long long)ioevent.datamatch);
				fprintf(stderr, "  backend worker ready\n");
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

	fprintf(stderr, "  first request: one request / one QueueNotify\n");
	fprintf(stderr, "  four-request batch: four requests / one QueueNotify\n");
	fprintf(stderr, "virtio D:\n");
	fprintf(stderr, "  guest observed completion used.idx=%u\n", used->idx);
	fprintf(stderr, "  success\n\n");
	fprintf(stderr, "data path:\n");
	fprintf(stderr, "  total requests = %u\n", VIRTIO_TOTAL_REQUEST_COUNT);
	fprintf(stderr, "  guest QueueNotify writes = %u\n", queue_notify_exits + (unsigned int)backend.guest_kicks);
	fprintf(stderr, "  request-description MMIO exits = 0\n");
	fprintf(stderr, "  QueueNotify userspace MMIO exits = %u\n", queue_notify_exits);
	fprintf(stderr, "  ioeventfd kicks = %llu\n", (unsigned long long)backend.guest_kicks);
	fprintf(stderr, "  completion polling MMIO exits = 0\n");
	return 0;
}
