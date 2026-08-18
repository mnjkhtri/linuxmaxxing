// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
	default:
		return "unknown";
	}
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
	json_u32(jw, "schema_version", 1);
	json_string(jw, "experiment", "virt-io");
	json_string(jw, "kind", "meta");
	json_string(jw, "source", "ebpf");
	json_string(jw, "clock", "monotonic");
	json_string(jw, "capture", "io_snapshot");
	json_u32(jw, "device_gsi", DEVICE_GSI);
	json_u32(jw, "device_vector", DEVICE_VECTOR);
	json_u32(jw, "dma_xfer_size", DMA_XFER_SIZE);
	json_u32(jw, "device_buffer_size", DEVICE_BUFFER_SIZE);
	json_u32(jw, "events", IO_EVENT_COUNT);
	json_bool(jw, "ioapic_available", READ_KVM_IOAPIC_RTE_AVAILABLE != 0);
	json_bool(jw, "lapic_available", READ_KVM_LAPIC_REGS_AVAILABLE != 0);
	json_object_end(jw);
	json_newline(jw);
}

static void write_event_info(struct json_writer *jw, const struct vio_event_info *event_info)
{
	json_object_begin_field(jw, "event_info");
	json_u32(jw, "event", event_info->event);
	json_string(jw, "event_name", event_name(event_info->event));
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
	json_bool(jw, "irr", state->controller.irr != 0);
	json_bool(jw, "isr", state->controller.isr != 0);
	json_object_end(jw);
	json_object_begin_field(jw, "dma");
	json_bool(jw, "present", state->dma.dir == CMD_DMA_TO_DEVICE || state->dma.dir == CMD_DMA_FROM_DEVICE);
	json_hex(jw, "gpa", state->dma.gpa);
	json_string(jw, "dir", dma_direction_name(state->dma.dir));
	json_object_end(jw);
	json_object_end(jw);
}

static void write_snapshot(struct json_writer *jw, const struct vio_event *event, unsigned int seq)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 1);
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
