// SPDX-License-Identifier: GPL-2.0
/* Uprobes observe the virtio-mmio transport and the userspace virtio-rng backend without adding guest exits. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "virtio_event.h"

#define __ASSEMBLER__
#include "virtio.h"
#undef __ASSEMBLER__

char LICENSE[] SEC("license") = "GPL";

/* These structures mirror the small VMM-private state read through bpf_probe_read_user(). */
struct observed_virtio_queue
{
	__u32 size;
	__u32 ready;
	__u16 last_avail_idx;
	__u16 reserved16;
	__u32 reserved32;
	__u64 desc_addr;
	__u64 driver_addr;
	__u64 device_addr;
};

struct observed_virtio_device
{
	__u32 device_features_sel;
	__u32 driver_features_sel;
	__u32 driver_features[2];
	__u32 status;
	__u32 queue_sel;
	struct observed_virtio_queue queue;
};

/* kvm_run is a stable userspace ABI; its exit union starts at byte 32 and MMIO uses this member layout. */
struct observed_kvm_run
{
	__u8 prefix[32];
	struct
	{
		__u64 phys_addr;
		__u8 data[8];
		__u32 len;
		__u8 is_write;
	} mmio;
};

struct observed_virtq_desc
{
	__u64 addr;
	__u32 len;
	__u16 flags;
	__u16 next;
};

struct observed_virtq_avail
{
	__u16 flags;
	__u16 idx;
	__u16 ring[VIRTQ_SIZE];
};

struct observed_virtq_used_elem
{
	__u32 id;
	__u32 len;
};

struct observed_virtq_used
{
	__u16 flags;
	__u16 idx;
	struct observed_virtq_used_elem ring[VIRTQ_SIZE];
};

struct process_args
{
	__u64 dev;
	__u64 guest_mem;
};

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct virtio_event);
} scratch SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct process_args);
} active_process SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int is_vmm_comm(char comm[16])
{
	const char expected[4] = "vmm";

#pragma unroll
	for (int i = 0; i < 3; i++)
		if (comm[i] != expected[i])
			return 0;
	return comm[3] == '\0';
}

static __always_inline struct virtio_event *new_event(unsigned int event_type)
{
	__u32 zero = 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct virtio_event *event = bpf_map_lookup_elem(&scratch, &zero);

	if (!event)
		return NULL;
	__builtin_memset(event, 0, sizeof(*event));
	bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
	if (!is_vmm_comm(event->context.comm))
		return NULL;
	event->time_ns = bpf_ktime_get_ns();
	event->event_info.event = event_type;
	event->context.pid = pid_tgid >> 32;
	event->context.tid = (__u32)pid_tgid;
	event->context.cpu = bpf_get_smp_processor_id();
	return event;
}

static __always_inline int sample_device(struct virtio_event *event, const void *dev_ptr)
{
	struct observed_virtio_device dev = {};

	if (!dev_ptr || bpf_probe_read_user(&dev, sizeof(dev), dev_ptr) != 0)
		return -1;
	event->state.device.present = 1;
	event->state.device.status = dev.status;
	event->state.device.device_features_sel = dev.device_features_sel;
	event->state.device.driver_features_sel = dev.driver_features_sel;
	event->state.device.driver_features[0] = dev.driver_features[0];
	event->state.device.driver_features[1] = dev.driver_features[1];
	event->state.device.queue_sel = dev.queue_sel;
	event->state.queue.present = 1;
	event->state.queue.size = dev.queue.size;
	event->state.queue.ready = dev.queue.ready;
	event->state.queue.last_avail_idx = dev.queue.last_avail_idx;
	event->state.queue.desc_addr = dev.queue.desc_addr;
	event->state.queue.driver_addr = dev.queue.driver_addr;
	event->state.queue.device_addr = dev.queue.device_addr;
	return 0;
}

/* Queue memory is sampled only after the device state names the controlled guest's fixed queue layout. */
static __always_inline void sample_queue_memory(struct virtio_event *event, const void *guest_mem)
{
	struct observed_virtq_desc desc = {};
	struct observed_virtq_avail avail = {};
	struct observed_virtq_used used = {};

	if (!guest_mem || !event->state.queue.present || event->state.queue.desc_addr != DESC_GPA || event->state.queue.driver_addr != AVAIL_GPA || event->state.queue.device_addr != USED_GPA)
		return;
	if (bpf_probe_read_user(&desc, sizeof(desc), guest_mem + DESC_GPA) == 0)
	{
		event->state.descriptor.present = 1;
		event->state.descriptor.addr = desc.addr;
		event->state.descriptor.len = desc.len;
		event->state.descriptor.flags = desc.flags;
		event->state.descriptor.next = desc.next;
	}
	if (bpf_probe_read_user(&avail, sizeof(avail), guest_mem + AVAIL_GPA) == 0)
	{
		event->state.avail.present = 1;
		event->state.avail.flags = avail.flags;
		event->state.avail.idx = avail.idx;
		event->state.avail.ring0 = avail.ring[0];
	}
	if (bpf_probe_read_user(&used, sizeof(used), guest_mem + USED_GPA) == 0)
	{
		event->state.used.present = 1;
		event->state.used.flags = used.flags;
		event->state.used.idx = used.idx;
		event->state.used.ring0_id = used.ring[0].id;
		event->state.used.ring0_len = used.ring[0].len;
	}
}

static __always_inline void sample_buffer_preview(struct virtio_event *event, const void *guest_mem)
{
	if (!guest_mem)
		return;
	if (bpf_probe_read_user(event->state.buffer_preview.bytes, VIRTIO_BUFFER_PREVIEW_BYTES, guest_mem + RNG_BUFFER_GPA) == 0)
	{
		event->state.buffer_preview.present = 1;
		event->state.buffer_preview.length = VIRTIO_BUFFER_PREVIEW_BYTES;
	}
}

static __always_inline void emit_event(struct virtio_event *event)
{
	if (event)
		bpf_ringbuf_output(&events, event, sizeof(*event), 0);
}

SEC("uprobe/build/vmm:handle_mmio")
int BPF_UPROBE(observe_handle_mmio, void *dev, void *guest_mem, struct observed_kvm_run *run)
{
	struct observed_kvm_run observed = {};
	struct virtio_event *event = new_event(VIRTIO_EVENT_MMIO);

	if (!event || !run || bpf_probe_read_user(&observed, sizeof(observed), run) != 0)
		return 0;
	event->event_info.mmio_present = 1;
	event->event_info.mmio_address = observed.mmio.phys_addr;
	event->event_info.mmio_offset = (__u32)(observed.mmio.phys_addr - VIRTIO_MMIO_BASE);
	event->event_info.mmio_length = observed.mmio.len;
	event->event_info.mmio_is_write = observed.mmio.is_write != 0;
	if (observed.mmio.is_write)
	{
		event->event_info.mmio_value_present = 1;
		__builtin_memcpy(&event->event_info.mmio_value, observed.mmio.data, sizeof(event->event_info.mmio_value));
	}
	sample_device(event, dev);
	sample_queue_memory(event, guest_mem);
	emit_event(event);
	return 0;
}

SEC("uprobe/build/vmm:process_queue")
int BPF_UPROBE(observe_process_queue_begin, void *dev, void *guest_mem)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct process_args args = {.dev = (__u64)dev, .guest_mem = (__u64)guest_mem};
	struct virtio_event *event = new_event(VIRTIO_EVENT_QUEUE_BACKEND_BEGIN);

	bpf_map_update_elem(&active_process, &key, &args, BPF_ANY);
	if (!event)
		return 0;
	sample_device(event, dev);
	sample_queue_memory(event, guest_mem);
	emit_event(event);
	return 0;
}

SEC("uretprobe/build/vmm:process_queue")
int BPF_URETPROBE(observe_process_queue_end, int result)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct process_args *args = bpf_map_lookup_elem(&active_process, &key);
	struct virtio_event *event = new_event(VIRTIO_EVENT_QUEUE_BACKEND_END);

	if (event)
	{
		event->event_info.return_present = 1;
		event->event_info.return_value = result;
		if (args)
		{
			sample_device(event, (const void *)args->dev);
			sample_queue_memory(event, (const void *)args->guest_mem);
			if (result == 0)
				sample_buffer_preview(event, (const void *)args->guest_mem);
		}
		emit_event(event);
	}
	/* Every return deletes the saved arguments so a later call cannot inherit stale pointers. */
	bpf_map_delete_elem(&active_process, &key);
	return 0;
}
