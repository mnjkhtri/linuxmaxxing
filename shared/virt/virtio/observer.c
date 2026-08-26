// SPDX-License-Identifier: GPL-2.0
/* The loader owns public JSON representation; stdout is NDJSON and stderr is lifecycle/diagnostics only. */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <bpf/libbpf.h>

#include "json_writer.h"
#include "virtio.h"
#include "virtio_event.h"
#include "virtio.skel.h"

static unsigned int record_count;
static unsigned int seq_counter;
static bool vmx_disposition_available;
static volatile sig_atomic_t exiting;

static void on_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

static const char *event_name(unsigned int event)
{
	switch (event)
	{
	case VIRTIO_EVENT_MMIO:
		return "virtio_mmio";
	case VIRTIO_EVENT_QUEUE_BACKEND_BEGIN:
		return "queue_backend_begin";
	case VIRTIO_EVENT_QUEUE_BACKEND_END:
		return "queue_backend_end";
	case VIRTIO_EVENT_IOEVENTFD_KICK:
		return "ioeventfd_kick";
	case VIRTIO_EVENT_IRQFD_SIGNAL:
		return "irqfd_signal";
	case VIRTIO_EVENT_SYS_ENTER_IOCTL:
		return "sys_enter_ioctl";
	case VIRTIO_EVENT_SYS_EXIT_IOCTL:
		return "sys_exit_ioctl";
	case VIRTIO_EVENT_VMX_HANDLE_EXIT_RETURN:
		return "vmx_handle_exit_return";
	case VIRTIO_EVENT_MMIO_RETURN:
		return "virtio_mmio_return";
	case VIRTIO_EVENT_IOEVENTFD_KICK_RETURN:
		return "ioeventfd_kick_return";
	case VIRTIO_EVENT_IRQFD_SIGNAL_RETURN:
		return "irqfd_signal_return";
	default:
		return "unknown";
	}
}

static const char *ioctl_request_name(unsigned long long request)
{
	switch (request)
	{
	case KVM_GET_API_VERSION: return "KVM_GET_API_VERSION";
	case KVM_CHECK_EXTENSION: return "KVM_CHECK_EXTENSION";
	case KVM_CREATE_VM: return "KVM_CREATE_VM";
	case KVM_CREATE_IRQCHIP: return "KVM_CREATE_IRQCHIP";
	case KVM_SET_USER_MEMORY_REGION: return "KVM_SET_USER_MEMORY_REGION";
	case KVM_CREATE_VCPU: return "KVM_CREATE_VCPU";
	case KVM_GET_VCPU_MMAP_SIZE: return "KVM_GET_VCPU_MMAP_SIZE";
	case KVM_GET_SREGS: return "KVM_GET_SREGS";
	case KVM_SET_SREGS: return "KVM_SET_SREGS";
	case KVM_SET_REGS: return "KVM_SET_REGS";
	case KVM_SET_GSI_ROUTING: return "KVM_SET_GSI_ROUTING";
	case KVM_IOEVENTFD: return "KVM_IOEVENTFD";
	case KVM_IRQFD: return "KVM_IRQFD";
	case KVM_RUN: return "KVM_RUN";
	default: return "UNKNOWN_IOCTL";
	}
}

static const char *exit_disposition_name(int result)
{
	if (result > 0) return "resume guest";
	if (result == 0) return "return userspace";
	return "error";
}

static bool kallsyms_has_symbol(const char *wanted)
{
	FILE *stream = fopen("/proc/kallsyms", "r");
	char line[512];
	char symbol[256];
	bool found = false;

	if (!stream) return false;
	while (fgets(line, sizeof(line), stream))
	{
		if (sscanf(line, "%*s %*c %255s", symbol) == 1 && strcmp(symbol, wanted) == 0)
		{
			found = true;
			break;
		}
	}
	fclose(stream);
	return found;
}

static const char *register_name(unsigned int offset)
{
	switch (offset)
	{
	case VIRTIO_MMIO_MAGIC_VALUE: return "MagicValue";
	case VIRTIO_MMIO_VERSION: return "Version";
	case VIRTIO_MMIO_DEVICE_ID: return "DeviceID";
	case VIRTIO_MMIO_VENDOR_ID: return "VendorID";
	case VIRTIO_MMIO_DEVICE_FEATURES: return "DeviceFeatures";
	case VIRTIO_MMIO_DEVICE_FEATURES_SEL: return "DeviceFeaturesSel";
	case VIRTIO_MMIO_DRIVER_FEATURES: return "DriverFeatures";
	case VIRTIO_MMIO_DRIVER_FEATURES_SEL: return "DriverFeaturesSel";
	case VIRTIO_MMIO_QUEUE_SEL: return "QueueSel";
	case VIRTIO_MMIO_QUEUE_SIZE_MAX: return "QueueSizeMax";
	case VIRTIO_MMIO_QUEUE_SIZE: return "QueueSize";
	case VIRTIO_MMIO_QUEUE_READY: return "QueueReady";
	case VIRTIO_MMIO_QUEUE_NOTIFY: return "QueueNotify";
	case VIRTIO_MMIO_INTERRUPT_STATUS: return "InterruptStatus";
	case VIRTIO_MMIO_INTERRUPT_ACK: return "InterruptACK";
	case VIRTIO_MMIO_STATUS: return "Status";
	case VIRTIO_MMIO_QUEUE_DESC_LOW: return "QueueDescLow";
	case VIRTIO_MMIO_QUEUE_DESC_HIGH: return "QueueDescHigh";
	case VIRTIO_MMIO_QUEUE_DRIVER_LOW: return "QueueDriverLow";
	case VIRTIO_MMIO_QUEUE_DRIVER_HIGH: return "QueueDriverHigh";
	case VIRTIO_MMIO_QUEUE_DEVICE_LOW: return "QueueDeviceLow";
	case VIRTIO_MMIO_QUEUE_DEVICE_HIGH: return "QueueDeviceHigh";
	default: return "unknown";
	}
}

static int is_queue_configuration_register(unsigned int offset)
{
	switch (offset)
	{
	case VIRTIO_MMIO_QUEUE_SEL:
	case VIRTIO_MMIO_QUEUE_SIZE_MAX:
	case VIRTIO_MMIO_QUEUE_SIZE:
	case VIRTIO_MMIO_QUEUE_READY:
	case VIRTIO_MMIO_QUEUE_DESC_LOW:
	case VIRTIO_MMIO_QUEUE_DESC_HIGH:
	case VIRTIO_MMIO_QUEUE_DRIVER_LOW:
	case VIRTIO_MMIO_QUEUE_DRIVER_HIGH:
	case VIRTIO_MMIO_QUEUE_DEVICE_LOW:
	case VIRTIO_MMIO_QUEUE_DEVICE_HIGH:
		return 1;
	default:
		return 0;
	}
}

static const char *phase_name(const struct virtio_event *event)
{
	unsigned int offset = event->event_info.mmio_offset;

	if (event->event_info.event == VIRTIO_EVENT_IOEVENTFD_KICK || event->event_info.event == VIRTIO_EVENT_IRQFD_SIGNAL || event->event_info.event == VIRTIO_EVENT_IOEVENTFD_KICK_RETURN || event->event_info.event == VIRTIO_EVENT_IRQFD_SIGNAL_RETURN)
		return "D";
	if (event->state.ioctl.present)
	{
		if (event->state.ioctl.request == KVM_IOEVENTFD || event->state.ioctl.request == KVM_IRQFD)
			return "D";
		return "A";
	}
	if (event->event_info.event == VIRTIO_EVENT_VMX_HANDLE_EXIT_RETURN)
		return "A"; /* The frontend aligns this kernel event to the nearest tracefs phase boundary. */
	if (event->event_info.event != VIRTIO_EVENT_MMIO && event->event_info.event != VIRTIO_EVENT_MMIO_RETURN)
	{
		if (event->state.avail.present && event->state.avail.idx == VIRTIO_TOTAL_REQUEST_COUNT)
			return "D";
		return "C";
	}
	if (offset == VIRTIO_MMIO_QUEUE_NOTIFY)
		return "C";
	if (offset == VIRTIO_MMIO_INTERRUPT_STATUS || offset == VIRTIO_MMIO_INTERRUPT_ACK)
		return "D";
	if (is_queue_configuration_register(offset))
		return "B";
	if (offset == VIRTIO_MMIO_STATUS && ((event->event_info.mmio_value_present && event->event_info.mmio_value == VIRTIO_STATUS_OPERATIONAL) || (event->state.queue.present && event->state.queue.ready)))
		return "B";
	return "A";
}

static void write_meta(struct json_writer *jw)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 6);
	json_string(jw, "experiment", "virt-virtio");
	json_string(jw, "kind", "meta");
	json_string(jw, "source", "ebpf");
	json_string(jw, "clock", "monotonic");
	json_hex(jw, "virtio_mmio_base", VIRTIO_MMIO_BASE);
	json_string(jw, "device", "virtio-rng");
	json_u32(jw, "virtio_version", VIRTIO_VERSION_MODERN);
	json_u32(jw, "queue_index", VIRTIO_RNG_QUEUE_INDEX);
	json_u32(jw, "queue_size", VIRTQ_SIZE);
	json_u32(jw, "guest_memory_slot", 0);
	json_hex(jw, "guest_memory_gpa", 0);
	json_hex(jw, "guest_memory_size", VIRTIO_GUEST_MEM_SIZE);
	json_hex(jw, "guest_code_gpa", VIRTIO_GUEST_CODE_GPA);
	json_hex(jw, "guest_code_size", VIRTIO_GUEST_CODE_LIMIT);
	json_hex(jw, "guest_idt_gpa", VIRTIO_GUEST_IDT_GPA);
	json_hex(jw, "guest_idt_size", VIRTIO_GUEST_IDT_SIZE);
	json_hex(jw, "guest_completion_flag_gpa", VIRTIO_GUEST_COMPLETION_GPA);
	json_hex(jw, "guest_stack_bottom", VIRTIO_GUEST_STACK_BOTTOM);
	json_hex(jw, "guest_stack_top", VIRTIO_GUEST_STACK_TOP);
	json_hex(jw, "queue_region_size", VIRTQ_PAGE_SIZE);
	json_hex(jw, "descriptor_gpa", VIRTQ_DESC_GPA);
	json_u32(jw, "descriptor_bytes", VIRTQ_DESC_BYTES);
	json_hex(jw, "avail_gpa", VIRTQ_AVAIL_GPA);
	json_u32(jw, "avail_bytes", VIRTQ_AVAIL_BYTES);
	json_hex(jw, "used_gpa", VIRTQ_USED_GPA);
	json_u32(jw, "used_bytes", VIRTQ_USED_BYTES);
	json_hex(jw, "rng_buffer_gpa", VIRTIO_RNG_BUFFER_GPA);
	json_hex(jw, "rng_buffer_stride", VIRTIO_RNG_BUFFER_STRIDE);
	json_u32(jw, "rng_request_length", VIRTIO_RNG_REQUEST_LEN);
	json_u32(jw, "phase_c_request_count", VIRTIO_RNG_REQUEST_COUNT);
	json_u32(jw, "total_request_count", VIRTIO_TOTAL_REQUEST_COUNT);
	json_string(jw, "negotiated_feature", "VIRTIO_F_VERSION_1");
	json_string(jw, "phase_c_request_notification", "KVM_EXIT_MMIO");
	json_string(jw, "phase_c_completion", "polling");
	json_string(jw, "phase_d_request_notification", "KVM_IOEVENTFD");
	json_string(jw, "phase_d_completion_notification", "KVM_IRQFD");
	json_hex(jw, "ioeventfd_address", VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY);
	json_u32(jw, "ioeventfd_length", 4);
	json_u32(jw, "ioeventfd_datamatch", VIRTIO_RNG_QUEUE_INDEX);
	json_u32(jw, "irqfd_gsi", VIRTIO_IRQ_GSI);
	json_string(jw, "backend_location", "userspace");
	json_bool(jw, "vmx_disposition_available", vmx_disposition_available);
	json_u32(jw, "structured_event_types", 11);
	json_object_end(jw);
	json_newline(jw);
}

static void write_event_info(struct json_writer *jw, const struct virtio_event *event)
{
	const struct virtio_event_info *info = &event->event_info;

	json_object_begin_field(jw, "event_info");
	json_u32(jw, "event", info->event);
	json_string(jw, "event_name", event_name(info->event));
	json_string(jw, "phase", phase_name(event));
	json_u64(jw, "call_id", info->call_id);
	json_u64(jw, "operation_id", info->operation_id);
	json_u64(jw, "duration_ns", info->duration_ns);
	json_object_begin_field(jw, "mmio");
	json_bool(jw, "present", info->mmio_present != 0);
	if (info->mmio_present)
	{
		json_hex(jw, "address", info->mmio_address);
		json_hex(jw, "offset", info->mmio_offset);
		json_string(jw, "register", register_name(info->mmio_offset));
		json_string(jw, "direction", info->mmio_is_write ? "write" : "read");
		json_u32(jw, "length", info->mmio_length);
		if (info->mmio_value_present)
			json_hex(jw, "value", info->mmio_value);
		else
			json_null(jw, "value");
	}
	else
	{
		json_null(jw, "address");
		json_null(jw, "offset");
		json_null(jw, "register");
		json_null(jw, "direction");
		json_null(jw, "length");
		json_null(jw, "value");
	}
	json_object_end(jw);
	json_object_begin_field(jw, "ioeventfd");
	json_bool(jw, "present", info->ioeventfd_present != 0);
	if (info->ioeventfd_present)
	{
		json_u64(jw, "count", info->ioeventfd_count);
		json_hex(jw, "address", VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY);
		json_u32(jw, "length", 4);
		json_u32(jw, "datamatch", VIRTIO_RNG_QUEUE_INDEX);
	}
	else
	{
		json_null(jw, "count");
		json_null(jw, "address");
		json_null(jw, "length");
		json_null(jw, "datamatch");
	}
	json_object_end(jw);
	json_object_begin_field(jw, "irqfd");
	json_bool(jw, "present", info->irqfd_present != 0);
	if (info->irqfd_present)
	{
		json_u64(jw, "count", info->irqfd_count);
		json_u32(jw, "gsi", VIRTIO_IRQ_GSI);
	}
	else
	{
		json_null(jw, "count");
		json_null(jw, "gsi");
	}
	json_object_end(jw);
	if (info->return_present)
		json_i64(jw, "return_value", info->return_value);
	else
		json_null(jw, "return_value");
	json_object_end(jw);
}

static void write_context(struct json_writer *jw, const struct virtio_context *context)
{
	json_object_begin_field(jw, "context");
	json_u32(jw, "pid", context->pid);
	json_u32(jw, "tid", context->tid);
	json_u32(jw, "cpu", context->cpu);
	json_string_n(jw, "comm", context->comm, sizeof(context->comm));
	json_object_end(jw);
}

static void write_device(struct json_writer *jw, const struct virtio_device_state *device)
{
	json_object_begin_field(jw, "device");
	json_bool(jw, "present", device->present != 0);
	if (device->present)
	{
		json_hex(jw, "status", device->status);
		json_hex(jw, "interrupt_status", device->interrupt_status);
		json_u32(jw, "device_features_sel", device->device_features_sel);
		json_u32(jw, "driver_features_sel", device->driver_features_sel);
		json_hex(jw, "driver_features_word0", device->driver_features[0]);
		json_hex(jw, "driver_features_word1", device->driver_features[1]);
		json_u32(jw, "queue_sel", device->queue_sel);
	}
	else
	{
		json_null(jw, "status");
		json_null(jw, "interrupt_status");
		json_null(jw, "device_features_sel");
		json_null(jw, "driver_features_sel");
		json_null(jw, "driver_features_word0");
		json_null(jw, "driver_features_word1");
		json_null(jw, "queue_sel");
	}
	json_object_end(jw);
}

static void write_queue(struct json_writer *jw, const struct virtio_queue_state *queue)
{
	json_object_begin_field(jw, "queue");
	json_bool(jw, "present", queue->present != 0);
	if (queue->present)
	{
		json_u32(jw, "size", queue->size);
		json_bool(jw, "ready", queue->ready != 0);
		json_u32(jw, "last_avail_idx", queue->last_avail_idx);
		json_hex(jw, "desc_gpa", queue->desc_addr);
		json_hex(jw, "driver_gpa", queue->driver_addr);
		json_hex(jw, "device_gpa", queue->device_addr);
	}
	else
	{
		json_null(jw, "size");
		json_null(jw, "ready");
		json_null(jw, "last_avail_idx");
		json_null(jw, "desc_gpa");
		json_null(jw, "driver_gpa");
		json_null(jw, "device_gpa");
	}
	json_object_end(jw);
}

static void write_descriptor(struct json_writer *jw, const struct virtio_descriptor_state *descriptor)
{
	json_object_begin_field(jw, "descriptor");
	json_bool(jw, "present", descriptor->present != 0);
	if (descriptor->present)
	{
		json_array_begin_field(jw, "entries");
		for (unsigned int i = 0; i < VIRTQ_SIZE; i++)
		{
			const struct virtio_descriptor_entry *entry = &descriptor->entries[i];

			json_object_begin(jw);
			json_u32(jw, "index", i);
			json_hex(jw, "addr", entry->addr);
			json_u32(jw, "len", entry->len);
			json_hex(jw, "flags", entry->flags);
			json_bool(jw, "device_writable", (entry->flags & VIRTQ_DESC_F_WRITE) != 0);
			json_u32(jw, "next", entry->next);
			json_object_end(jw);
		}
		json_array_end(jw);
	}
	else
		json_null(jw, "entries");
	json_object_end(jw);
}

static void write_avail(struct json_writer *jw, const struct virtio_avail_state *avail)
{
	json_object_begin_field(jw, "avail");
	json_bool(jw, "present", avail->present != 0);
	if (avail->present)
	{
		json_hex(jw, "flags", avail->flags);
		json_u32(jw, "idx", avail->idx);
		json_array_begin_field(jw, "ring");
		for (unsigned int i = 0; i < VIRTQ_SIZE; i++)
			json_u32_value(jw, avail->ring[i]);
		json_array_end(jw);
	}
	else
	{
		json_null(jw, "flags");
		json_null(jw, "idx");
		json_null(jw, "ring");
	}
	json_object_end(jw);
}

static void write_used(struct json_writer *jw, const struct virtio_used_state *used)
{
	json_object_begin_field(jw, "used");
	json_bool(jw, "present", used->present != 0);
	if (used->present)
	{
		json_hex(jw, "flags", used->flags);
		json_u32(jw, "idx", used->idx);
		json_array_begin_field(jw, "ring");
		for (unsigned int i = 0; i < VIRTQ_SIZE; i++)
		{
			json_object_begin(jw);
			json_u32(jw, "slot", i);
			json_u32(jw, "id", used->ring[i].id);
			json_u32(jw, "len", used->ring[i].len);
			json_object_end(jw);
		}
		json_array_end(jw);
	}
	else
	{
		json_null(jw, "flags");
		json_null(jw, "idx");
		json_null(jw, "ring");
	}
	json_object_end(jw);
}

static void write_buffer_preview(struct json_writer *jw, const struct virtio_buffer_preview *preview)
{
	json_object_begin_field(jw, "buffer_preview");
	json_bool(jw, "present", preview->present != 0);
	json_string(jw, "meaning", "raw_random_data");
	if (preview->present)
	{
		json_u32(jw, "length", preview->length);
		json_array_begin_field(jw, "bytes");
		for (unsigned int i = 0; i < preview->length && i < VIRTIO_BUFFER_PREVIEW_BYTES; i++)
			json_u32_value(jw, preview->bytes[i]);
		json_array_end(jw);
	}
	else
	{
		json_null(jw, "length");
		json_null(jw, "bytes");
	}
	json_object_end(jw);
}

static void write_ioctl(struct json_writer *jw, const struct virtio_ioctl_state *ioctl_state)
{
	json_object_begin_field(jw, "ioctl");
	json_bool(jw, "present", ioctl_state->present != 0);
	json_bool(jw, "completed", ioctl_state->completed != 0);
	if (ioctl_state->present)
	{
		json_u32(jw, "fd", (unsigned int)ioctl_state->fd);
		json_hex(jw, "request", ioctl_state->request);
		json_string(jw, "request_name", ioctl_request_name(ioctl_state->request));
		json_hex(jw, "argument", ioctl_state->argument);
		json_i64(jw, "result", ioctl_state->result);
		json_u64(jw, "duration_ns", ioctl_state->duration_ns);
	}
	json_object_end(jw);
}

static void write_disposition(struct json_writer *jw, const struct virtio_disposition_state *disposition)
{
	json_object_begin_field(jw, "disposition");
	json_bool(jw, "present", disposition->present != 0);
	if (disposition->present)
	{
		json_i64(jw, "result", disposition->result);
		json_string(jw, "meaning", exit_disposition_name(disposition->result));
	}
	json_object_end(jw);
}

static void write_state(struct json_writer *jw, const struct virtio_state *state)
{
	json_object_begin_field(jw, "state");
	write_device(jw, &state->device);
	write_queue(jw, &state->queue);
	write_descriptor(jw, &state->descriptor);
	write_avail(jw, &state->avail);
	write_used(jw, &state->used);
	write_buffer_preview(jw, &state->buffer_preview);
	write_ioctl(jw, &state->ioctl);
	write_disposition(jw, &state->disposition);
	json_object_end(jw);
}

static void write_snapshot(struct json_writer *jw, const struct virtio_event *event, unsigned int seq)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 6);
	json_string(jw, "experiment", "virt-virtio");
	json_string(jw, "kind", "snapshot");
	json_string(jw, "source", "ebpf");
	json_u32(jw, "seq", seq);
	json_u64(jw, "time_ns", event->time_ns);
	write_event_info(jw, event);
	write_context(jw, &event->context);
	write_state(jw, &event->state);
	json_object_end(jw);
	json_newline(jw);
}

static int handle_event(void *context, void *data, size_t length)
{
	const struct virtio_event *event = data;
	struct json_writer jw;

	(void)context;
	if (length < sizeof(*event))
		return 0;
	seq_counter++;
	record_count++;
	json_writer_init(&jw, stdout);
	write_snapshot(&jw, event, seq_counter);
	return json_writer_ok(&jw) ? 0 : -1;
}

int main(void)
{
	struct virtio_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	struct json_writer jw;
	int err = 0;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	setvbuf(stdout, NULL, _IOLBF, 0);

	skel = virtio_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "virtio: failed to open BPF skeleton\n");
		return 1;
	}
	vmx_disposition_available = kallsyms_has_symbol("vmx_handle_exit");
	if (!vmx_disposition_available)
	{
		bpf_program__set_autoload(skel->progs.observe_vmx_handle_exit_return, false);
		fprintf(stderr, "virtio: vmx_handle_exit unavailable; disposition probe disabled\n");
	}
	if (virtio_bpf__load(skel) != 0 || virtio_bpf__attach(skel) != 0)
	{
		fprintf(stderr, "virtio: failed to load or attach BPF programs\n");
		err = 1;
		goto out;
	}
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!ringbuf)
	{
		fprintf(stderr, "virtio: failed to create ring buffer: %d\n", -errno);
		err = 1;
		goto out;
	}

	json_writer_init(&jw, stdout);
	write_meta(&jw);
	fflush(stdout);
	fprintf(stderr, "LX_READY experiment=virt-virtio observer=virtio\n");
	while (!exiting)
	{
		err = ring_buffer__poll(ringbuf, 250);
		if (err == -EINTR)
			break;
		if (err < 0)
		{
			fprintf(stderr, "virtio: ring-buffer polling failed: %d\n", err);
			goto out;
		}
	}
	while (ring_buffer__consume(ringbuf) > 0)
		;
	err = 0;

out:
	ring_buffer__free(ringbuf);
	virtio_bpf__destroy(skel);
	if (err)
		return 1;
	fprintf(stderr, "LX_DONE experiment=virt-virtio observer=virtio records=%u\n", record_count);
	return 0;
}
