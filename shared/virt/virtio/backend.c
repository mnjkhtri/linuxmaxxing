// SPDX-License-Identifier: GPL-2.0
/* Userspace virtio-rng backend. */
/* vmm.c owns virtualization and transport/control-plane wiring; this file services the shared virtqueue. */
/* Linux vhost applies a similar separation but places supported backend work in the host kernel. */
/* This experiment is not vhost. */
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/random.h>
#include <unistd.h>

#include "backend.h"

/* process_queue() consumes every newly published descriptor and publishes each completion through the used ring. */
__attribute__((noinline)) int process_queue(struct virtio_mmio_device *dev, uint8_t *guest_mem)
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

	/* These fixed, validated GPAs become host virtual addresses only when the backend accesses guest RAM. */
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

/* This stable boundary observes the call eventfd after used state and InterruptStatus have been published. */
__attribute__((noinline)) int signal_irqfd_completion(struct virtio_mmio_device *dev, uint8_t *guest_mem, struct virtio_backend *backend, uint64_t call_count)
{
	ssize_t bytes;

	(void)dev;
	(void)guest_mem;
	do
		bytes = write(backend->call_fd, &call_count, sizeof(call_count));
	while (bytes < 0 && errno == EINTR);
	if (bytes != sizeof(call_count))
	{
		if (bytes < 0)
			perror("write call_fd");
		else
			fprintf(stderr, "virtio D: short call_fd write\n");
		return -1;
	}
	backend->guest_calls += call_count;
	fprintf(stderr, "  irqfd completion signal count=%llu GSI=%u\n", (unsigned long long)call_count, VIRTIO_IRQ_GSI);
	return 0;
}

/* This stable boundary exposes an ioeventfd wake before the shared virtqueue backend consumes it. */
__attribute__((noinline)) int process_ioeventfd_kick(struct virtio_mmio_device *dev, uint8_t *guest_mem, struct virtio_backend *backend, uint64_t eventfd_count)
{
	struct virtq_used *used = (struct virtq_used *)(guest_mem + VIRTQ_USED_GPA);

	if (eventfd_count != 1)
	{
		fprintf(stderr, "virtio D: unexpected ioeventfd wake count=%llu\n", (unsigned long long)eventfd_count);
		return -1;
	}
	fprintf(stderr, "virtio D:\n");
	fprintf(stderr, "  ioeventfd wake count=%llu\n", (unsigned long long)eventfd_count);
	if (process_queue(dev, guest_mem) < 0)
		return -1;
	if (dev->queue.last_avail_idx != VIRTIO_TOTAL_REQUEST_COUNT || used->idx != VIRTIO_TOTAL_REQUEST_COUNT)
	{
		fprintf(stderr, "virtio D: backend completion state is incomplete\n");
		return -1;
	}
	/* InterruptStatus is published only after process_queue() has published the complete used-ring state. */
	atomic_thread_fence(memory_order_release);
	__atomic_fetch_or(&dev->interrupt_status, VIRTIO_MMIO_INT_VRING, __ATOMIC_RELEASE);
	return signal_irqfd_completion(dev, guest_mem, backend, 1);
}

void *virtio_backend_worker(void *opaque)
{
	struct virtio_backend *backend = opaque;
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
				perror("read kick_fd");
			else
				fprintf(stderr, "virtio D: short kick_fd read\n");
			backend->result = -1;
			return NULL;
		}
		if (atomic_load_explicit(&backend->stop, memory_order_acquire))
			return NULL;
		backend->guest_kicks += count;
		backend->result = process_ioeventfd_kick(backend->dev, backend->guest_mem, backend, count);
		if (backend->result < 0)
			return NULL;
	}
}
