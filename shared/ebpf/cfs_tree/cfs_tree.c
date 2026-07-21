// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "cfs_tree.skel.h"

/* Must match the BPF event byte-for-byte. */
struct tree_node {
	unsigned long long node;
	unsigned long long left;
	unsigned long long right;
	unsigned int color;
	char comm[16];
};

struct context_event {
	unsigned int tid;
	unsigned long long cfs_rq;
	unsigned long long se;
	unsigned long long leftmost;
	unsigned int node_count;
	unsigned int truncated;
	struct tree_node nodes[31];
};

static volatile sig_atomic_t exiting;

static void on_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

/* libbpf invokes this after the kretprobe emits one event. */
static int handle_event(void *ctx, void *data, size_t len)
{
	const struct context_event *event = data;
	(void)ctx;
	if (len < sizeof(*event))
		return 0;
	printf("{\"type\":\"event\",\"op\":\"enqueue\",\"tid\":%u,\"cfs_rq\":\"%016llx\",\"se\":\"%016llx\",\"leftmost\":\"%016llx\",\"valid_nodes\":%u,\"truncated\":%u,\"nodes\":[",
	       event->tid, event->cfs_rq, event->se, event->leftmost,
	       event->node_count, event->truncated);
	for (unsigned int i = 0; i < event->node_count; i++) {
		if (i)
			putchar(',');
		printf("{\"node\":\"%016llx\",\"left\":\"%016llx\",\"right\":\"%016llx\",\"color\":%u,\"comm\":\"%s\"}",
		       event->nodes[i].node, event->nodes[i].left,
		       event->nodes[i].right, event->nodes[i].color, event->nodes[i].comm);
	}
	puts("]}");
	return 0;
}

int main(void)
{
	struct cfs_tree_bpf *skel;
	struct ring_buffer *ringbuf;
	int err;
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	skel = cfs_tree_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load BPF skeleton\n");
		return 1;
	}
	err = cfs_tree_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		cfs_tree_bpf__destroy(skel);
		return 1;
	}
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "failed to create ring buffer: %d\n", -errno);
		cfs_tree_bpf__destroy(skel);
		return 1;
	}
	fprintf(stderr, "attached enqueue entry/return probes; press Ctrl-C to stop\n");
	while (!exiting) {
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
