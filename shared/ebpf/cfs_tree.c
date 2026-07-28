// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "cfs_tree.skel.h"

#define MAX_TREE_NODES 31

/* Must match the BPF event byte-for-byte. */
struct tree_node
{
	unsigned long long node;
	unsigned long long left;
	unsigned long long right;
	unsigned int color;
	char comm[16];
};

struct context_event
{
	unsigned int tid;
	unsigned int cpu;
	unsigned long long cfs_rq;
	unsigned long long se;
	unsigned long long run_node;
	unsigned long long leftmost;
	unsigned int node_count;
	unsigned int truncated;
	struct tree_node nodes[MAX_TREE_NODES];
};

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

static void json_string_value(const char *value)
{
	putchar('"');
	for (size_t i = 0; i < 16 && value[i]; i++)
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

static void json_string(int *first, const char *name, const char *value)
{
	json_comma(first);
	printf("\"%s\":", name);
	json_string_value(value);
}

static void json_u32(int *first, const char *name, unsigned int value)
{
	json_comma(first);
	printf("\"%s\":%u", name, value);
}

static void json_hex(int *first, const char *name, unsigned long long value)
{
	json_comma(first);
	printf("\"%s\":\"%016llx\"", name, value);
}

static void print_node(const struct tree_node *node)
{
	int first = 1;

	putchar('{');
	json_hex(&first, "node", node->node);
	json_hex(&first, "left", node->left);
	json_hex(&first, "right", node->right);
	json_u32(&first, "color", node->color);
	json_string(&first, "comm", node->comm);
	putchar('}');
}

/* libbpf invokes this after the kretprobe emits one event. */
static int handle_event(void *ctx, void *data, size_t len)
{
	const struct context_event *event = data;
	(void)ctx;

	if (len < sizeof(*event))
		return 0;
	int first = 1;

	putchar('{');
	json_string(&first, "type", "event");
	json_string(&first, "op", "enqueue");
	json_u32(&first, "tid", event->tid);
	json_u32(&first, "cpu", event->cpu);
	json_hex(&first, "cfs_rq", event->cfs_rq);
	json_hex(&first, "se", event->se);
	json_hex(&first, "run_node", event->run_node);
	json_hex(&first, "leftmost", event->leftmost);
	json_u32(&first, "valid_nodes", event->node_count);
	json_u32(&first, "truncated", event->truncated);
	json_comma(&first);
	printf("\"nodes\":[");
	for (unsigned int i = 0; i < event->node_count; i++)
	{
		if (i)
			putchar(',');
		print_node(&event->nodes[i]);
	}
	puts("]}");
	return 0;
}

int main(void)
{
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	struct cfs_tree_bpf *skel = cfs_tree_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "failed to open/load BPF skeleton\n");
		return 1;
	}
	int err = cfs_tree_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		cfs_tree_bpf__destroy(skel);
		return 1;
	}
	struct ring_buffer *ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!ringbuf)
	{
		fprintf(stderr, "failed to create ring buffer: %d\n", -errno);
		cfs_tree_bpf__destroy(skel);
		return 1;
	}

	fprintf(stderr, "attached enqueue entry/return probes; press Ctrl-C to stop\n");
	while (!exiting)
	{
		err = ring_buffer__poll(ringbuf, 250);
		if (err == -EINTR)
			break;
		if (err < 0)
			break;
	}
	ring_buffer__free(ringbuf);
	cfs_tree_bpf__destroy(skel);
	return 0;
}
