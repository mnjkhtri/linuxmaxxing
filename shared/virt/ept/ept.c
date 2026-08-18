// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "ept_event.h"
#include "json_writer.h"
#include "ept.skel.h"

/*
 * libbpf loads and verifies ept.bpf.o, attaches the KVM boundary programs, and polls the ring buffer.
 * Each callback serializes one post-boundary EPT snapshot as a single NDJSON record for the frontend.
 *
 * Stdout carries NDJSON only.
 * Stderr carries machine-readable lifecycle lines (LX_READY / LX_DONE) plus human diagnostics.
 * run.sh can therefore gate the workload on a successful attachment without parsing capture records.
 *
 * The binary event is grouped into event_info/context/state, and the public schema keeps that grouping.
 * event_info identifies the KVM boundary that produced the snapshot; state holds the EPT walk.
 * Serialization is owned here.
 * schema_version, experiment, kind, source, and seq come from the loader.
 * Representation choices such as readable event names, "0x..."/null pointers, and booleans are normalized here.
 * Kernel pointers are identities used to connect objects in the visualization, never addresses to dereference.
 * The EPT walk is bounded and best-effort; the recorded limits live in the meta record.
 */

static unsigned int record_count;
static unsigned int seq_counter;

static volatile sig_atomic_t exiting;

static void on_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

static unsigned long long symbol_address(const char *path, const char *wanted)
{
	FILE *symbols = fopen(path, "r");

	if (!symbols)
		return 0;
	for (;;)
	{
		unsigned long long address;
		char type;
		char name[256];

		if (fscanf(symbols, "%llx %c %255s", &address, &type, name) != 3)
			break;
		if (strcmp(name, wanted) == 0)
		{
			fclose(symbols);
			return address;
		}
	}
	fclose(symbols);
	return 0;
}

/* The public schema carries readable event names; the binary ABI carries only the integer. */
static const char *event_name(unsigned int event)
{
	switch (event)
	{
	case EPT_EVENT_KVM_ENTRY:
		return "kvm_entry";
	case EPT_EVENT_KVM_EXIT:
		return "kvm_exit";
	case EPT_EVENT_KVM_USERSPACE_EXIT:
		return "kvm_userspace_exit";
	case EPT_EVENT_KVM_UNMAP_HVA_RANGE:
		return "kvm_unmap_hva_range";
	case EPT_EVENT_KVM_MMU_SPTE_REQUESTED:
		return "kvm_mmu_spte_requested";
	case EPT_EVENT_KVM_MMU_SET_SPTE:
		return "kvm_mmu_set_spte";
	case EPT_EVENT_KVM_FLUSH_REMOTE_TLBS:
		return "kvm_flush_remote_tlbs";
	default:
		return "unknown";
	}
}

/*
 * First NDJSON record.
 * The frontend recognizes kind=meta and does not treat it as a snapshot.
 * Static sampling limits live here once instead of on every record.
 */
static void write_meta(struct json_writer *jw)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 1);
	json_string(jw, "experiment", "virt-ept");
	json_string(jw, "kind", "meta");
	json_string(jw, "source", "ebpf");
	json_string(jw, "clock", "monotonic");
	json_string(jw, "capture", "ept_snapshot");
	json_u32(jw, "ept_levels", EPT_LEVELS);
	json_u32(jw, "slot0_gfn_samples", SLOT0_GFN_SAMPLES);
	json_u32(jw, "huge_gfn_samples", HUGE_GFN_SAMPLES);
	json_u32(jw, "max_gfn_samples", MAX_GFN_SAMPLES);
	json_u32(jw, "huge_gfn_base", HUGE_GFN_BASE);
	json_u32(jw, "huge_gfn_stride", HUGE_GFN_STRIDE);
	json_object_end(jw);
	json_newline(jw);
}

static void write_entry(struct json_writer *jw, const struct ept_entry_record *entry)
{
	json_object_begin(jw);
	json_u32(jw, "level", entry->level);
	json_hex(jw, "table_hpa", entry->table_hpa);
	json_u32(jw, "index", entry->index);
	json_hex(jw, "spte", entry->spte);
	json_bool(jw, "present", entry->present != 0);
	json_bool(jw, "mmio", entry->mmio != 0);
	json_bool(jw, "leaf", entry->leaf != 0);
	json_bool(jw, "r", entry->readable != 0);
	json_bool(jw, "w", entry->writable != 0);
	json_bool(jw, "x", entry->executable != 0);
	json_bool(jw, "a", entry->accessed != 0);
	json_bool(jw, "d", entry->dirty != 0);
	json_object_end(jw);
}

static void write_gfn(struct json_writer *jw, const struct ept_guest_gfn *gfn)
{
	json_object_begin(jw);
	json_u64(jw, "gfn", gfn->gfn);
	json_hex(jw, "gva", gfn->gva);
	json_hex(jw, "gpa", gfn->gpa);
	json_bool(jw, "ept_mapped", gfn->ept_mapped != 0);
	json_bool(jw, "ept_mmio", gfn->ept_mmio != 0);
	json_u32(jw, "leaf_level", gfn->leaf_level);
	json_hex(jw, "leaf_pfn", gfn->leaf_pfn);
	json_array_begin_field(jw, "entries");
	for (unsigned int i = 0; i < EPT_LEVELS; i++)
		write_entry(jw, &gfn->entries[i]);
	json_array_end(jw);
	json_object_end(jw);
}

static void write_state(struct json_writer *jw, const struct ept_state *state)
{
	json_object_begin_field(jw, "state");
	json_ptr(jw, "vcpu", state->vcpu);
	json_ptr(jw, "kvm", state->kvm);
	json_ptr(jw, "mmu", state->mmu);
	json_hex(jw, "root_hpa", state->root_hpa);
	json_hex(jw, "root_pgd", state->root_pgd);
	json_array_begin_field(jw, "gfns");
	for (unsigned int i = 0; i < MAX_GFN_SAMPLES; i++)
		write_gfn(jw, &state->gfns[i]);
	json_array_end(jw);
	json_object_end(jw);
}

static void write_context(struct json_writer *jw, const struct ept_context *context)
{
	json_object_begin_field(jw, "context");
	json_u32(jw, "pid", context->pid);
	json_u32(jw, "tid", context->tid);
	json_u32(jw, "cpu", context->cpu);
	json_string_n(jw, "comm", context->comm, sizeof(context->comm));
	json_object_end(jw);
}

static void write_event_info(struct json_writer *jw, const struct ept_event_info *event_info)
{
	json_object_begin_field(jw, "event_info");
	json_u32(jw, "event", event_info->event);
	json_string(jw, "event_name", event_name(event_info->event));
	json_object_end(jw);
}

static void write_snapshot(struct json_writer *jw, const struct ept_event *event, unsigned int seq)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 1);
	json_string(jw, "experiment", "virt-ept");
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
 * libbpf invokes this for every KVM boundary snapshot emitted by the BPF program.
 * Rejecting a short record protects the byte-for-byte ABI shared with struct ept_event in ept_event.h.
 * seq is assigned here in output order; the ring-buffer callback preserves snapshot order.
 */
static int handle_event(void *context, void *data, size_t length)
{
	const struct ept_event *event = data;
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
	struct ept_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	int err = 0;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* Stdout is NDJSON; line-buffer so records reach the capture promptly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	skel = ept_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "ept: failed to open EPT BPF skeleton\n");
		return 1;
	}
	unsigned long long page_offset_base = symbol_address("/proc/kallsyms", "page_offset_base");
	if (!page_offset_base)
	{
		fprintf(stderr, "ept: failed to resolve page_offset_base\n");
		err = 1;
		goto out;
	}
	skel->rodata->page_offset_base_address = page_offset_base;
	if (ept_bpf__load(skel) != 0)
	{
		fprintf(stderr, "ept: failed to load EPT BPF skeleton\n");
		err = 1;
		goto out;
	}
	if (ept_bpf__attach(skel) != 0)
	{
		fprintf(stderr, "ept: failed to attach EPT BPF programs\n");
		err = 1;
		goto out;
	}
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!ringbuf)
	{
		fprintf(stderr, "ept: failed to create ring buffer: %d\n", -errno);
		err = 1;
		goto out;
	}

	/* Metadata first: static capture facts, not a snapshot. */
	struct json_writer jw;

	json_writer_init(&jw, stdout);
	write_meta(&jw);
	fflush(stdout);

	fprintf(stderr, "LX_READY experiment=virt-ept observer=ept\n");

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
	ept_bpf__destroy(skel);

	if (err)
		return 1;
	fprintf(stderr, "LX_DONE experiment=virt-ept observer=ept records=%u\n", record_count);
	return 0;
}
