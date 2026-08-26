// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <bpf/libbpf.h>
#include "io_event.h"
#include "json_writer.h"
#include "io.skel.h"
#include "kvm_compat.h" /* Generated: READ_KVM_*_AVAILABLE run facts for the meta record. */

/*
 * libbpf loads and verifies io.bpf.o, attaches the KVM intercept programs and the VMM uprobe, and polls the ring buffer.
 * Each callback serializes one boundary snapshot as a single NDJSON record for the frontend.
 *
 * Stdout carries NDJSON only.
 * Stderr carries machine-readable lifecycle lines (LX_READY / LX_DONE) plus human diagnostics.
 * run.sh can therefore gate the workload on a successful attachment without parsing capture records.
 *
 * The binary event is grouped into event_info/context/state, and the public schema keeps that grouping.
 * event_info identifies the KVM boundary or device operation that produced the snapshot, and the BPF side stamps it.
 * state holds the interrupt-controller sample and the uprobed virtual-DMA operation.
 * Serialization is owned here.
 * schema_version, experiment, kind, source, and seq come from the loader.
 * Representation choices such as readable event names, "0x..."/null pointers, and booleans are normalized here.
 * Kernel pointers are identities used to connect objects in the visualization, never addresses to dereference.
 * Run-constant facts (reader availability, transfer size, and device identities) live in the meta record once.
 * Controller snapshots ride on each record only when the target's BTF exposes the readers, and zeros mean not sampled.
 */

static unsigned int record_count;
static unsigned int seq_counter;
static bool vmx_disposition_available;

static volatile sig_atomic_t exiting;

static void on_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

/* The public schema carries readable event names; the binary ABI carries only the integer. */
static const char *event_name(unsigned int event)
{
	switch (event)
	{
	case IO_EVENT_KVM_ENTRY:
		return "kvm_entry";
	case IO_EVENT_KVM_EXIT:
		return "kvm_exit";
	case IO_EVENT_KVM_USERSPACE_EXIT:
		return "kvm_userspace_exit";
	case IO_EVENT_KVM_IOAPIC_SET_IRQ:
		return "kvm_ioapic_set_irq";
	case IO_EVENT_KVM_APIC_ACCEPT_IRQ:
		return "kvm_apic_accept_irq";
	case IO_EVENT_KVM_INJ_VIRQ:
		return "kvm_inj_virq";
	case IO_EVENT_KVM_EOI:
		return "kvm_eoi";
	case IO_EVENT_KVM_APIC:
		return "kvm_apic";
	case IO_EVENT_DEVICE_DMA_TRANSFER:
		return "device_dma_transfer";
	case IO_EVENT_KVM_MSI_SET_IRQ:
		return "kvm_msi_set_irq";
	case IO_EVENT_SYS_ENTER_IOCTL:
		return "sys_enter_ioctl";
	case IO_EVENT_SYS_EXIT_IOCTL:
		return "sys_exit_ioctl";
	case IO_EVENT_VMX_HANDLE_EXIT_RETURN:
		return "vmx_handle_exit_return";
	case IO_EVENT_DEVICE_MMIO_WRITE:
		return "device_mmio_write";
	case IO_EVENT_DEVICE_EXECUTE_COMMAND:
		return "device_execute_command";
	case IO_EVENT_DEVICE_EXECUTE_COMMAND_RETURN:
		return "device_execute_command_return";
	case IO_EVENT_DEVICE_DMA_TRANSFER_RETURN:
		return "device_dma_transfer_return";
	default:
		return "unknown";
	}
}

static const char *ioctl_request_name(unsigned long long request)
{
	switch (request)
	{
	case KVM_GET_API_VERSION:
		return "KVM_GET_API_VERSION";
	case KVM_CHECK_EXTENSION:
		return "KVM_CHECK_EXTENSION";
	case KVM_CREATE_VM:
		return "KVM_CREATE_VM";
	case KVM_CREATE_IRQCHIP:
		return "KVM_CREATE_IRQCHIP";
	case KVM_SET_USER_MEMORY_REGION:
		return "KVM_SET_USER_MEMORY_REGION";
	case KVM_CREATE_VCPU:
		return "KVM_CREATE_VCPU";
	case KVM_GET_VCPU_MMAP_SIZE:
		return "KVM_GET_VCPU_MMAP_SIZE";
	case KVM_GET_SREGS:
		return "KVM_GET_SREGS";
	case KVM_SET_SREGS:
		return "KVM_SET_SREGS";
	case KVM_SET_REGS:
		return "KVM_SET_REGS";
	case KVM_RUN:
		return "KVM_RUN";
	case KVM_IRQ_LINE:
		return "KVM_IRQ_LINE";
	case KVM_SIGNAL_MSI:
		return "KVM_SIGNAL_MSI";
	default:
		return "UNKNOWN_IOCTL";
	}
}

static const char *device_command_name(unsigned int command)
{
	switch (command)
	{
	case CMD_IRQ_ONLY:
		return "CMD_IRQ_ONLY";
	case CMD_DMA_TO_DEVICE:
		return "CMD_DMA_TO_DEVICE";
	case CMD_DMA_FROM_DEVICE:
		return "CMD_DMA_FROM_DEVICE";
	case CMD_MSI_ONLY:
		return "CMD_MSI_ONLY";
	default:
		return "UNKNOWN_COMMAND";
	}
}

static const char *device_register_name(unsigned int offset)
{
	switch (offset)
	{
	case REG_COMMAND:
		return "REG_COMMAND";
	case REG_STATUS:
		return "REG_STATUS";
	case REG_DMA_GPA:
		return "REG_DMA_GPA";
	case REG_RESULT:
		return "REG_RESULT";
	case REG_IRQ_ACK:
		return "REG_IRQ_ACK";
	default:
		return "REG_BUFFER";
	}
}

static const char *exit_disposition_name(int result)
{
	if (result > 0)
		return "resume guest";
	if (result == 0)
		return "return userspace";
	return "error";
}

static bool kallsyms_has_symbol(const char *wanted)
{
	FILE *stream = fopen("/proc/kallsyms", "r");
	char line[512];
	char symbol[256];
	bool found = false;

	if (!stream)
		return false;
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

/* The public schema carries the DMA direction as a readable word; the ABI carries the command integer. */
static const char *dma_direction_name(unsigned int dir)
{
	switch (dir)
	{
	case CMD_DMA_TO_DEVICE:
		return "to_device";
	case CMD_DMA_FROM_DEVICE:
		return "from_device";
	default:
		return "unknown";
	}
}

/*
 * First NDJSON record.
 * The frontend recognizes kind=meta and does not treat it as a snapshot.
 * Static device facts live here once instead of on every record.
 */
static void write_meta(struct json_writer *jw)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 2);
	json_string(jw, "experiment", "virt-io");
	json_string(jw, "kind", "meta");
	json_string(jw, "source", "ebpf");
	json_string(jw, "clock", "monotonic");
	json_string(jw, "capture", "io_snapshot");
	json_u32(jw, "device_gsi", DEVICE_GSI);
	json_u32(jw, "device_vector", DEVICE_VECTOR);
	json_u32(jw, "msi_vector", MSI_VECTOR);
	json_u32(jw, "dma_xfer_size", DMA_XFER_SIZE);
	json_u32(jw, "device_buffer_size", DEVICE_BUFFER_SIZE);
	json_u32(jw, "events", IO_EVENT_COUNT);
	json_bool(jw, "ioapic_available", READ_KVM_IOAPIC_RTE_AVAILABLE != 0);
	json_bool(jw, "lapic_available", READ_KVM_LAPIC_REGS_AVAILABLE != 0);
	json_bool(jw, "vmx_disposition_available", vmx_disposition_available);
	json_object_end(jw);
	json_newline(jw);
}

static void write_event_info(struct json_writer *jw, const struct vio_event_info *event_info)
{
	json_object_begin_field(jw, "event_info");
	json_u32(jw, "event", event_info->event);
	json_string(jw, "event_name", event_name(event_info->event));
	json_u64(jw, "vmexit_id", event_info->vmexit_id);
	json_u64(jw, "operation_id", event_info->operation_id);
	json_u64(jw, "call_id", event_info->call_id);
	json_object_end(jw);
}

static void write_context(struct json_writer *jw, const struct vio_context *context)
{
	json_object_begin_field(jw, "context");
	json_u32(jw, "pid", context->pid);
	json_u32(jw, "tid", context->tid);
	json_u32(jw, "cpu", context->cpu);
	json_string_n(jw, "comm", context->comm, sizeof(context->comm));
	json_object_end(jw);
}

static void write_state(struct json_writer *jw, const struct vio_state *state)
{
	json_object_begin_field(jw, "state");
	json_ptr(jw, "vcpu", state->vcpu);
	json_ptr(jw, "kvm", state->kvm);
	json_ptr(jw, "apic", state->apic);
	json_ptr(jw, "ioapic", state->ioapic);
	json_object_begin_field(jw, "controller");
	json_hex(jw, "rte", state->controller.rte);
	json_hex(jw, "tpr", state->controller.tpr);
	json_hex(jw, "svr", state->controller.svr);
	json_object_begin_field(jw, "irr");
	for (unsigned int k = 0; k < 8; k++)
	{
		char key[4] = {'b', (char)('0' + k), '\0'};

		json_hex(jw, key, state->controller.irr[k]);
	}
	json_object_end(jw);
	json_object_begin_field(jw, "isr");
	for (unsigned int k = 0; k < 8; k++)
	{
		char key[4] = {'b', (char)('0' + k), '\0'};

		json_hex(jw, key, state->controller.isr[k]);
	}
	json_object_end(jw);
	json_object_end(jw);
	json_object_begin_field(jw, "msi");
	json_bool(jw, "present", state->msi.present != 0);
	if (state->msi.present)
	{
		/* Raw MSI message fields; the frontend decodes destination/delivery/trigger into readable words. */
		json_hex(jw, "address", state->msi.address);
		json_hex(jw, "data", state->msi.data);
		json_u32(jw, "vector", (unsigned int)(state->msi.data & 0xff));
		json_u32(jw, "destination", (unsigned int)((state->msi.address >> 12) & 0xff));
		json_bool(jw, "logical", (state->msi.address & (1u << 3)) != 0);
		json_bool(jw, "level_triggered", (state->msi.data & (1u << 15)) != 0);
		json_u32(jw, "delivery_mode", (unsigned int)((state->msi.data >> 8) & 0x7));
	}
	json_object_end(jw);
	json_object_begin_field(jw, "dma");
	json_bool(jw, "present", state->dma.len != 0);
	json_bool(jw, "completed", state->dma.completed != 0);
	json_hex(jw, "gpa", state->dma.gpa);
	json_ptr(jw, "guest_hva", state->dma.guest_hva);
	json_string(jw, "dir", dma_direction_name(state->dma.dir));
	json_u32(jw, "len", state->dma.len);
	json_i64(jw, "result", state->dma.result);
	json_u32(jw, "checksum", state->dma.checksum);
	json_u64(jw, "duration_ns", state->dma.duration_ns);
	json_object_end(jw);
	json_object_begin_field(jw, "ioctl");
	json_bool(jw, "present", state->ioctl.present != 0);
	json_bool(jw, "completed", state->ioctl.completed != 0);
	if (state->ioctl.present)
	{
		json_u32(jw, "fd", (unsigned int)state->ioctl.fd);
		json_hex(jw, "request", state->ioctl.request);
		json_string(jw, "request_name", ioctl_request_name(state->ioctl.request));
		json_hex(jw, "argument", state->ioctl.argument);
		json_i64(jw, "result", state->ioctl.result);
		json_u64(jw, "duration_ns", state->ioctl.duration_ns);
	}
	json_object_end(jw);
	json_object_begin_field(jw, "disposition");
	json_bool(jw, "present", state->disposition.present != 0);
	if (state->disposition.present)
	{
		json_i64(jw, "result", state->disposition.result);
		json_string(jw, "meaning", exit_disposition_name(state->disposition.result));
	}
	json_object_end(jw);
	json_object_begin_field(jw, "mmio");
	json_bool(jw, "present", state->mmio.present != 0);
	if (state->mmio.present)
	{
		json_u32(jw, "offset", state->mmio.offset);
		json_string(jw, "register", device_register_name(state->mmio.offset));
		json_hex(jw, "value", state->mmio.value);
	}
	json_object_end(jw);
	json_object_begin_field(jw, "command");
	json_bool(jw, "present", state->command.present != 0);
	json_bool(jw, "completed", state->command.completed != 0);
	if (state->command.present)
	{
		json_u32(jw, "command", state->command.command);
		json_string(jw, "command_name", device_command_name(state->command.command));
		json_hex(jw, "status", state->command.status);
		json_hex(jw, "dma_gpa", state->command.dma_gpa);
		json_u32(jw, "result", state->command.result);
		json_u64(jw, "duration_ns", state->command.duration_ns);
	}
	json_object_end(jw);
	json_object_end(jw);
}

static void write_snapshot(struct json_writer *jw, const struct vio_event *event, unsigned int seq)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 2);
	json_string(jw, "experiment", "virt-io");
	json_string(jw, "kind", "snapshot");
	json_string(jw, "source", "ebpf");
	json_u32(jw, "seq", seq);
	json_u64(jw, "time_ns", event->time_ns);
	write_event_info(jw, &event->event_info);
	write_context(jw, &event->context);
	write_state(jw, &event->state);
	json_object_end(jw);
	json_newline(jw);
}

/*
 * libbpf invokes this for every boundary snapshot emitted by the BPF program.
 * Rejecting a short record protects the byte-for-byte ABI shared with struct vio_event in io_event.h.
 * seq is assigned here in output order, and the ring-buffer callback preserves snapshot order.
 */
static int handle_event(void *context, void *data, size_t length)
{
	const struct vio_event *event = data;
	struct json_writer jw;

	(void)context;

	if (length < sizeof(*event))
		return 0;

	seq_counter++;
	record_count++;

	json_writer_init(&jw, stdout);
	write_snapshot(&jw, event, seq_counter);
	return 0;
}

int main(void)
{
	struct io_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	int err = 0;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* Stdout is NDJSON; line-buffer so records reach the capture promptly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	skel = io_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "io: failed to open IO BPF skeleton\n");
		return 1;
	}
	vmx_disposition_available = kallsyms_has_symbol("vmx_handle_exit");
	if (!vmx_disposition_available)
	{
		bpf_program__set_autoload(skel->progs.vmx_handle_exit_return, false);
		fprintf(stderr, "io: vmx_handle_exit unavailable; disposition probe disabled\n");
	}
	if (io_bpf__load(skel) != 0)
	{
		fprintf(stderr, "io: failed to load IO BPF skeleton\n");
		err = 1;
		goto out;
	}
	if (io_bpf__attach(skel) != 0)
	{
		fprintf(stderr, "io: failed to attach IO BPF programs\n");
		err = 1;
		goto out;
	}
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!ringbuf)
	{
		fprintf(stderr, "io: failed to create ring buffer: %d\n", -errno);
		err = 1;
		goto out;
	}

	/* Metadata first: static capture facts, not a snapshot. */
	struct json_writer jw;

	json_writer_init(&jw, stdout);
	write_meta(&jw);
	fflush(stdout);

	fprintf(stderr, "LX_READY experiment=virt-io observer=io\n");

	while (!exiting)
	{
		err = ring_buffer__poll(ringbuf, 250);
		if (err == -EINTR)
			break;
		if (err < 0)
			break;
	}
	while (ring_buffer__consume(ringbuf) > 0)
		;
	err = 0;

out:
	ring_buffer__free(ringbuf);
	io_bpf__destroy(skel);

	if (err)
		return 1;
	fprintf(stderr, "LX_DONE experiment=virt-io observer=io records=%u\n", record_count);
	return 0;
}
