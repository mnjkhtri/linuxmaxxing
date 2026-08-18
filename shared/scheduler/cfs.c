// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "cfs_event.h"
#include "json_writer.h"
#include "cfs.skel.h"

/*
 * libbpf loads and verifies cfs.bpf.o, attaches its entry/return probes, and polls the ring buffer.
 * Each callback serializes one post-enqueue tree state as a single NDJSON record for scheduler.js.
 *
 * Stdout carries NDJSON only.
 * Stderr carries machine-readable lifecycle lines (LX_READY / LX_DONE) plus human diagnostics.
 * run.sh can therefore gate the workload on a successful attachment without parsing capture records.
 *
 * The binary event is grouped into event_info/context/state, but the public schema keeps its own layout.
 * In particular the enqueued entity facts travel from event.event_info into state.runqueue.enqueued_entity.
 * Serialization is owned here.
 * schema_version, experiment, kind, source, and seq come from the loader.
 * Representation choices such as "red"/"black", "0x..."/null, and true/false are normalized here.
 * Kernel pointers are identities used to connect nodes in the visualization, never addresses to dereference.
 */

static unsigned int record_count;
static unsigned int seq_counter;

static volatile sig_atomic_t exiting;

static void on_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

/*
 * First NDJSON record.
 * The frontend recognizes kind=meta and does not treat it as a playback frame.
 * Static facts live here once instead of on every record.
 */
static void write_meta(struct json_writer *jw)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 1);
	json_string(jw, "experiment", "scheduler");
	json_string(jw, "kind", "meta");
	json_string(jw, "source", "ebpf");
	json_string(jw, "clock", "monotonic");
	json_string(jw, "capture", "cfs_runqueue");
	json_u32(jw, "max_nodes", MAX_TREE_NODES);
	json_object_end(jw);
	json_newline(jw);
}

/*
 * The loader attaches exactly one probe contract, so the event_info facts are constants.
 * The enqueued entity belongs to the public runqueue shape and is written by write_state().
 */
static void write_event_info(struct json_writer *jw, const struct cfs_event_info *event_info)
{
	(void)event_info;
	json_string(jw, "name", "enqueue_entity");
	json_string(jw, "phase", "after");
	json_string(jw, "probe", "kretprobe/__enqueue_entity");
}

static void write_context(struct json_writer *jw, const struct cfs_context *context)
{
	json_u32(jw, "cpu", context->cpu);
	json_u32(jw, "pid", context->pid);
	json_u32(jw, "tid", context->tid);
	json_string_n(jw, "comm", context->comm, sizeof(context->comm));
}

static void write_node(struct json_writer *jw, const struct tree_node *node)
{
	json_object_begin(jw);
	json_ptr(jw, "address", node->node);
	json_ptr(jw, "left", node->left);
	json_ptr(jw, "right", node->right);
	json_string(jw, "color", node->color == CFS_RB_RED ? "red" : "black");
	json_string_n(jw, "comm", node->comm, sizeof(node->comm));
	json_object_end(jw);
}

static void write_state(struct json_writer *jw, const struct cfs_state *state, const struct cfs_event_info *event_info)
{
	json_object_begin_field(jw, "runqueue");
	json_ptr(jw, "address", state->cfs_rq);
	json_u32(jw, "nr_running", (uint32_t)state->nr_running);
	json_ptr(jw, "root", state->root);
	json_ptr(jw, "leftmost", state->leftmost);

	json_object_begin_field(jw, "enqueued_entity");
	json_ptr(jw, "address", event_info->enqueued_entity);
	json_ptr(jw, "rb_node", event_info->enqueued_rb_node);
	json_object_end(jw);

	json_u32(jw, "node_count", state->node_count);
	json_bool(jw, "truncated", state->truncated != 0);

	json_array_begin_field(jw, "nodes");
	for (unsigned int i = 0; i < state->node_count; i++)
		write_node(jw, &state->nodes[i]);
	json_array_end(jw);

	json_object_end(jw);
}

static void write_snapshot(struct json_writer *jw, const struct cfs_event *event, unsigned int seq)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 1);
	json_string(jw, "experiment", "scheduler");
	json_string(jw, "kind", "snapshot");
	json_string(jw, "source", "ebpf");
	json_u32(jw, "seq", seq);
	json_u64(jw, "time_ns", event->time_ns);

	json_object_begin_field(jw, "event_info");
	write_event_info(jw, &event->event_info);
	json_object_end(jw);

	json_object_begin_field(jw, "context");
	write_context(jw, &event->context);
	json_object_end(jw);

	json_object_begin_field(jw, "state");
	write_state(jw, &event->state, &event->event_info);
	json_object_end(jw);

	json_object_end(jw);
	json_newline(jw);
}

/*
 * libbpf invokes this after the kretprobe emits one event.
 * Rejecting a short record protects the byte-for-byte ABI shared with struct cfs_event in cfs_event.h.
 * seq is assigned here in output order; the ring-buffer callback preserves enqueue order.
 */
static int handle_event(void *ctx, void *data, size_t len)
{
	const struct cfs_event *event = data;
	struct json_writer jw;

	(void)ctx;

	if (len < sizeof(*event))
		return 0;

	seq_counter++;
	record_count++;

	json_writer_init(&jw, stdout);
	write_snapshot(&jw, event, seq_counter);
	return 0;
}

int main(void)
{
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* Stdout is NDJSON; line-buffer so records reach the capture promptly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	struct cfs_bpf *skel = cfs_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "cfs: failed to open/load BPF skeleton\n");
		return 1;
	}
	int err = cfs_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "cfs: failed to attach BPF programs: %d\n", err);
		cfs_bpf__destroy(skel);
		return 1;
	}
	struct ring_buffer *ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!ringbuf)
	{
		fprintf(stderr, "cfs: failed to create ring buffer: %d\n", -errno);
		cfs_bpf__destroy(skel);
		return 1;
	}

	/* Metadata first: static capture facts, not a playback frame. */
	struct json_writer jw;
	json_writer_init(&jw, stdout);
	write_meta(&jw);
	fflush(stdout);

	fprintf(stderr, "LX_READY experiment=scheduler observer=cfs\n");

	while (!exiting)
	{
		err = ring_buffer__poll(ringbuf, 250);
		if (err == -EINTR)
			break;
		if (err < 0)
			break;
	}
	ring_buffer__free(ringbuf);
	cfs_bpf__destroy(skel);

	fprintf(stderr, "LX_DONE experiment=scheduler observer=cfs records=%u\n", record_count);
	return 0;
}
