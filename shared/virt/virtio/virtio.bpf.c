// SPDX-License-Identifier: GPL-2.0
/* Uprobes observe the virtio-mmio transport and the userspace virtio-rng backend without adding guest exits. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define __ASSEMBLER__
#include "virtio.h"
#undef __ASSEMBLER__
#include "virtio_event.h"

#if VIRTIO_EVENT_QUEUE_SLOTS != VIRTQ_SIZE
#error "The observer ABI must match the experiment queue size."
#endif

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
	__u32 interrupt_status;
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
	__u64 started_ns;
	__u64 operation_id;
};

struct mmio_args
{
	__u64 dev;
	__u64 guest_mem;
	__u64 run;
	__u64 started_ns;
	__u64 operation_id;
};

struct helper_args
{
	__u64 dev;
	__u64 guest_mem;
	__u64 started_ns;
	__u64 operation_id;
	__u64 count;
};

struct ioctl_call
{
	__u64 request;
	__u64 argument;
	__u64 started_ns;
	__u64 call_id;
	int fd;
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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct mmio_args);
} active_mmio SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct helper_args);
} active_ioeventfd SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct helper_args);
} active_irqfd SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct ioctl_call);
} active_ioctl SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} ioctl_counters SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} operation_counters SEC(".maps");

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
	event->state.device.interrupt_status = dev.interrupt_status;
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
	struct observed_virtq_desc desc[VIRTQ_SIZE] = {};
	struct observed_virtq_avail avail = {};
	struct observed_virtq_used used = {};

	if (!guest_mem || !event->state.queue.present || event->state.queue.desc_addr != VIRTQ_DESC_GPA || event->state.queue.driver_addr != VIRTQ_AVAIL_GPA || event->state.queue.device_addr != VIRTQ_USED_GPA)
		return;
	if (bpf_probe_read_user(&desc, sizeof(desc), guest_mem + VIRTQ_DESC_GPA) == 0)
	{
		event->state.descriptor.present = 1;
#pragma unroll
		for (int i = 0; i < VIRTQ_SIZE; i++)
		{
			event->state.descriptor.entries[i].addr = desc[i].addr;
			event->state.descriptor.entries[i].len = desc[i].len;
			event->state.descriptor.entries[i].flags = desc[i].flags;
			event->state.descriptor.entries[i].next = desc[i].next;
		}
	}
	if (bpf_probe_read_user(&avail, sizeof(avail), guest_mem + VIRTQ_AVAIL_GPA) == 0)
	{
		event->state.avail.present = 1;
		event->state.avail.flags = avail.flags;
		event->state.avail.idx = avail.idx;
#pragma unroll
		for (int i = 0; i < VIRTQ_SIZE; i++)
			event->state.avail.ring[i] = avail.ring[i];
	}
	if (bpf_probe_read_user(&used, sizeof(used), guest_mem + VIRTQ_USED_GPA) == 0)
	{
		event->state.used.present = 1;
		event->state.used.flags = used.flags;
		event->state.used.idx = used.idx;
#pragma unroll
		for (int i = 0; i < VIRTQ_SIZE; i++)
		{
			event->state.used.ring[i].id = used.ring[i].id;
			event->state.used.ring[i].len = used.ring[i].len;
		}
	}
}

static __always_inline void sample_buffer_preview(struct virtio_event *event, const void *guest_mem)
{
	if (!guest_mem)
		return;
	if (bpf_probe_read_user(event->state.buffer_preview.bytes, VIRTIO_BUFFER_PREVIEW_BYTES, guest_mem + VIRTIO_RNG_BUFFER_GPA) == 0)
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

static __always_inline __u64 next_operation_id(__u64 key)
{
	__u64 next = 1;
	__u64 *last = bpf_map_lookup_elem(&operation_counters, &key);

	if (last)
		next = *last + 1;
	bpf_map_update_elem(&operation_counters, &key, &next, BPF_ANY);
	return next;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int observe_ioctl_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 next = 1;
	__u64 *last;
	struct ioctl_call call = {};
	struct virtio_event *event = new_event(VIRTIO_EVENT_SYS_ENTER_IOCTL);

	if (!event)
		return 0;
	last = bpf_map_lookup_elem(&ioctl_counters, &key);
	if (last)
		next = *last + 1;
	call.fd = (int)ctx->args[0];
	call.request = ctx->args[1];
	call.argument = ctx->args[2];
	call.started_ns = event->time_ns;
	call.call_id = next;
	bpf_map_update_elem(&ioctl_counters, &key, &next, BPF_ANY);
	bpf_map_update_elem(&active_ioctl, &key, &call, BPF_ANY);
	event->event_info.call_id = next;
	event->state.ioctl.present = 1;
	event->state.ioctl.fd = call.fd;
	event->state.ioctl.request = call.request;
	event->state.ioctl.argument = call.argument;
	emit_event(event);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int observe_ioctl_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct ioctl_call *call = bpf_map_lookup_elem(&active_ioctl, &key);
	struct virtio_event *event;

	if (!call)
		return 0;
	event = new_event(VIRTIO_EVENT_SYS_EXIT_IOCTL);
	if (event)
	{
		event->event_info.call_id = call->call_id;
		event->state.ioctl.present = 1;
		event->state.ioctl.completed = 1;
		event->state.ioctl.fd = call->fd;
		event->state.ioctl.request = call->request;
		event->state.ioctl.argument = call->argument;
		event->state.ioctl.result = ctx->ret;
		event->state.ioctl.duration_ns = event->time_ns - call->started_ns;
		emit_event(event);
	}
	bpf_map_delete_elem(&active_ioctl, &key);
	return 0;
}

/* This optional kretprobe records whether KVM resumes the guest or returns KVM_RUN to userspace. */
SEC("kretprobe/vmx_handle_exit")
int BPF_KRETPROBE(observe_vmx_handle_exit_return, int result)
{
	struct virtio_event *event = new_event(VIRTIO_EVENT_VMX_HANDLE_EXIT_RETURN);

	if (!event)
		return 0;
	event->state.disposition.present = 1;
	event->state.disposition.result = result;
	emit_event(event);
	return 0;
}

SEC("uprobe/build/vmm:do_mmio")
int BPF_UPROBE(observe_do_mmio, void *dev, void *guest_mem, struct observed_kvm_run *run)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct observed_kvm_run observed = {};
	struct mmio_args args = {.dev = (__u64)dev, .guest_mem = (__u64)guest_mem, .run = (__u64)run};
	struct virtio_event *event = new_event(VIRTIO_EVENT_MMIO);

	if (!event || !run || bpf_probe_read_user(&observed, sizeof(observed), run) != 0)
		return 0;
	args.started_ns = event->time_ns;
	args.operation_id = next_operation_id(key);
	bpf_map_update_elem(&active_mmio, &key, &args, BPF_ANY);
	event->event_info.operation_id = args.operation_id;
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

SEC("uretprobe/build/vmm:do_mmio")
int BPF_URETPROBE(observe_do_mmio_end, int result)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct mmio_args *args = bpf_map_lookup_elem(&active_mmio, &key);
	struct observed_kvm_run observed = {};
	struct virtio_event *event;

	if (!args)
		return 0;
	event = new_event(VIRTIO_EVENT_MMIO_RETURN);
	if (event && bpf_probe_read_user(&observed, sizeof(observed), (const void *)args->run) == 0)
	{
		event->event_info.operation_id = args->operation_id;
		event->event_info.duration_ns = event->time_ns - args->started_ns;
		event->event_info.mmio_present = 1;
		event->event_info.mmio_address = observed.mmio.phys_addr;
		event->event_info.mmio_offset = (__u32)(observed.mmio.phys_addr - VIRTIO_MMIO_BASE);
		event->event_info.mmio_length = observed.mmio.len;
		event->event_info.mmio_is_write = observed.mmio.is_write != 0;
		event->event_info.mmio_value_present = 1;
		__builtin_memcpy(&event->event_info.mmio_value, observed.mmio.data, sizeof(event->event_info.mmio_value));
		event->event_info.return_present = 1;
		event->event_info.return_value = result;
		sample_device(event, (const void *)args->dev);
		sample_queue_memory(event, (const void *)args->guest_mem);
		emit_event(event);
	}
	bpf_map_delete_elem(&active_mmio, &key);
	return 0;
}

SEC("uprobe/build/vmm:process_queue")
int BPF_UPROBE(observe_process_queue_begin, void *dev, void *guest_mem)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct process_args args = {.dev = (__u64)dev, .guest_mem = (__u64)guest_mem};
	struct virtio_event *event = new_event(VIRTIO_EVENT_QUEUE_BACKEND_BEGIN);

	if (!event)
		return 0;
	args.started_ns = event->time_ns;
	args.operation_id = next_operation_id(key);
	bpf_map_update_elem(&active_process, &key, &args, BPF_ANY);
	event->event_info.operation_id = args.operation_id;
	sample_device(event, dev);
	sample_queue_memory(event, guest_mem);
	emit_event(event);
	return 0;
}

SEC("uprobe/build/vmm:process_ioeventfd_kick")
int BPF_UPROBE(observe_ioeventfd_kick, void *dev, void *guest_mem, void *backend, __u64 eventfd_count)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct helper_args args = {.dev = (__u64)dev, .guest_mem = (__u64)guest_mem, .count = eventfd_count};
	struct virtio_event *event = new_event(VIRTIO_EVENT_IOEVENTFD_KICK);

	(void)backend;
	if (!event)
		return 0;
	args.started_ns = event->time_ns;
	args.operation_id = next_operation_id(key);
	bpf_map_update_elem(&active_ioeventfd, &key, &args, BPF_ANY);
	event->event_info.operation_id = args.operation_id;
	event->event_info.ioeventfd_present = 1;
	event->event_info.ioeventfd_count = eventfd_count;
	sample_device(event, dev);
	sample_queue_memory(event, guest_mem);
	emit_event(event);
	return 0;
}

SEC("uretprobe/build/vmm:process_ioeventfd_kick")
int BPF_URETPROBE(observe_ioeventfd_kick_end, int result)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct helper_args *args = bpf_map_lookup_elem(&active_ioeventfd, &key);
	struct virtio_event *event;

	if (!args)
		return 0;
	event = new_event(VIRTIO_EVENT_IOEVENTFD_KICK_RETURN);
	if (event)
	{
		event->event_info.operation_id = args->operation_id;
		event->event_info.duration_ns = event->time_ns - args->started_ns;
		event->event_info.return_present = 1;
		event->event_info.return_value = result;
		event->event_info.ioeventfd_present = 1;
		event->event_info.ioeventfd_count = args->count;
		sample_device(event, (const void *)args->dev);
		sample_queue_memory(event, (const void *)args->guest_mem);
		emit_event(event);
	}
	bpf_map_delete_elem(&active_ioeventfd, &key);
	return 0;
}

SEC("uprobe/build/vmm:signal_irqfd_completion")
int BPF_UPROBE(observe_irqfd_signal, void *dev, void *guest_mem, void *backend, __u64 call_count)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct helper_args args = {.dev = (__u64)dev, .guest_mem = (__u64)guest_mem, .count = call_count};
	struct virtio_event *event = new_event(VIRTIO_EVENT_IRQFD_SIGNAL);

	(void)backend;
	if (!event)
		return 0;
	args.started_ns = event->time_ns;
	args.operation_id = next_operation_id(key);
	bpf_map_update_elem(&active_irqfd, &key, &args, BPF_ANY);
	event->event_info.operation_id = args.operation_id;
	event->event_info.irqfd_present = 1;
	event->event_info.irqfd_count = call_count;
	sample_device(event, dev);
	sample_queue_memory(event, guest_mem);
	emit_event(event);
	return 0;
}

SEC("uretprobe/build/vmm:signal_irqfd_completion")
int BPF_URETPROBE(observe_irqfd_signal_end, int result)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct helper_args *args = bpf_map_lookup_elem(&active_irqfd, &key);
	struct virtio_event *event;

	if (!args)
		return 0;
	event = new_event(VIRTIO_EVENT_IRQFD_SIGNAL_RETURN);
	if (event)
	{
		event->event_info.operation_id = args->operation_id;
		event->event_info.duration_ns = event->time_ns - args->started_ns;
		event->event_info.return_present = 1;
		event->event_info.return_value = result;
		event->event_info.irqfd_present = 1;
		event->event_info.irqfd_count = args->count;
		sample_device(event, (const void *)args->dev);
		sample_queue_memory(event, (const void *)args->guest_mem);
		emit_event(event);
	}
	bpf_map_delete_elem(&active_irqfd, &key);
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
			event->event_info.operation_id = args->operation_id;
			event->event_info.duration_ns = event->time_ns - args->started_ns;
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
