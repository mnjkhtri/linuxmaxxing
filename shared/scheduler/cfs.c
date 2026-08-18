// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "cfs_event.h"
#include "cfs.skel.h"

/*
 * libbpf loads and verifies cfs.bpf.o, attaches its entry/return probes, and polls the ring buffer.
 * Each callback serializes one post-enqueue tree state as a single NDJSON record for scheduler.js.
 *
 * Stdout carries NDJSON only.
 * Stderr carries machine-readable lifecycle lines (LX_READY / LX_DONE) plus human diagnostics.
 * run.sh can therefore gate the workload on a successful attachment without parsing capture records.
 *
 * Kernel pointers are printed as "0x..." strings.
 * They are identities used to connect nodes in the visualization, never addresses userspace should dereference.
 * Null pointers are emitted as JSON null.
 *
 * The binary event color (CFS_RB_RED/CFS_RB_BLACK) is normalized here to "red"/"black".
 * The frontend never sees the numeric value.
 */

static unsigned int record_count;
static unsigned int seq_counter;

static volatile sig_atomic_t exiting;

static void on_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

static void json_comma(int *first)
{
	if (*first)
	{
		*first = 0;
		return;
	}
	putchar(',');
}

static void json_string_value(const char *value, size_t max_len)
{
	putchar('"');
	for (size_t i = 0; i < max_len && value[i]; i++)
	{
		unsigned char c = value[i];

		if (c == '"' || c == '\\')
			printf("\\%c", c);
		else if (c < 0x20)
			printf("\\u%04x", c);
		else
			putchar(c);
	}
	putchar('"');
}

static void json_string(int *first, const char *name, const char *value, size_t max_len)
{
	json_comma(first);
	printf("\"%s\":", name);
	json_string_value(value, max_len);
}

static void json_uint(int *first, const char *name, unsigned int value)
{
	json_comma(first);
	printf("\"%s\":%u", name, value);
}

static void json_u64(int *first, const char *name, unsigned long long value)
{
	json_comma(first);
	printf("\"%s\":%llu", name, value);
}

static void json_bool(int *first, const char *name, int value)
{
	json_comma(first);
	printf("\"%s\":%s", name, value ? "true" : "false");
}

/* Kernel pointers: "0x..." when present, JSON null otherwise. */
static void json_hex_ptr(int *first, const char *name, unsigned long long value)
{
	json_comma(first);
	if (value)
		printf("\"%s\":\"0x%016llx\"", name, value);
	else
		printf("\"%s\":null", name);
}

static void print_node(const struct tree_node *node)
{
	int first = 1;

	putchar('{');
	json_hex_ptr(&first, "address", node->node);
	json_hex_ptr(&first, "left", node->left);
	json_hex_ptr(&first, "right", node->right);
	json_comma(&first);
	printf("\"color\":\"%s\"", node->color == CFS_RB_RED ? "red" : "black");
	json_string(&first, "comm", node->comm, 16);
	putchar('}');
}

/*
 * First NDJSON record.
 * The frontend recognizes kind=meta and does not treat it as a playback frame.
 * Static facts live here once instead of on every record.
 */
static void print_meta(void)
{
	int first = 1;

	putchar('{');
	json_uint(&first, "schema_version", 1);
	json_string(&first, "experiment", "scheduler", 32);
	json_string(&first, "kind", "meta", 16);
	json_string(&first, "source", "ebpf", 16);
	json_string(&first, "clock", "monotonic", 16);
	json_string(&first, "capture", "cfs_runqueue", 32);
	json_uint(&first, "max_nodes", MAX_TREE_NODES);
	puts("}");
}

/*
 * libbpf invokes this after the kretprobe emits one event.
 * Rejecting a short record protects the byte-for-byte ABI shared with struct cfs_event in cfs_event.h.
 * seq is assigned here in output order; the ring-buffer callback preserves enqueue order.
 */
static int handle_event(void *ctx, void *data, size_t len)
{
	const struct cfs_event *event = data;
	(void)ctx;

	if (len < sizeof(*event))
		return 0;

	seq_counter++;
	record_count++;

	int first = 1;
	putchar('{');
	json_uint(&first, "schema_version", 1);
	json_string(&first, "experiment", "scheduler", 32);
	json_string(&first, "kind", "snapshot", 16);
	json_string(&first, "source", "ebpf", 16);
	json_uint(&first, "seq", seq_counter);
	json_u64(&first, "time_ns", event->time_ns);

	json_comma(&first);
	printf("\"trigger\":{");
	int t = 1;
	json_string(&t, "name", "enqueue_entity", 32);
	json_string(&t, "phase", "after", 16);
	json_string(&t, "probe", "kretprobe/__enqueue_entity", 32);
	printf("}");

	json_comma(&first);
	printf("\"context\":{");
	int c = 1;
	json_uint(&c, "cpu", event->cpu);
	json_uint(&c, "pid", event->pid);
	json_uint(&c, "tid", event->tid);
	json_string(&c, "comm", event->comm, 16);
	printf("}");

	json_comma(&first);
	printf("\"state\":{\"runqueue\":{");
	int s = 1;
	json_hex_ptr(&s, "address", event->cfs_rq);
	json_uint(&s, "nr_running", event->nr_running);
	json_hex_ptr(&s, "root", event->root);
	json_hex_ptr(&s, "leftmost", event->leftmost);
	json_comma(&s);
	printf("\"enqueued_entity\":{");
	int e = 1;
	json_hex_ptr(&e, "address", event->se);
	json_hex_ptr(&e, "rb_node", event->run_node);
	printf("}");
	json_uint(&s, "node_count", event->node_count);
	json_bool(&s, "truncated", event->truncated);
	json_comma(&s);
	printf("\"nodes\":[");
	for (unsigned int i = 0; i < event->node_count; i++)
	{
		if (i)
			putchar(',');
		print_node(&event->nodes[i]);
	}
	puts("]}}}");
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
	print_meta();
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
