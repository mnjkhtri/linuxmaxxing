// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/types.h>

#include <bpf/libbpf.h>

#include "cfs_tree.skel.h"

#define MAX_TREE_NODES 31

static volatile sig_atomic_t exiting;

struct cfs_node_event {
	unsigned long long node;
	unsigned long long left;
	unsigned long long right;
	unsigned long long se;
	unsigned int color;
	unsigned int _pad;
};

struct cfs_event {
	unsigned long long ts_ns;
	unsigned int cpu;
	unsigned int op;
	unsigned int node_count;
	unsigned int _pad;
	unsigned long long cfs_rq;
	unsigned long long root;
	unsigned long long leftmost;
	unsigned long long changed_node;
	unsigned int changed_pid;
	unsigned int truncated;
	char changed_comm[16];
	struct cfs_node_event nodes[MAX_TREE_NODES];
};

enum {
	OP_ENQUEUE = 1,
	OP_DEQUEUE = 2,
};

static void on_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct cfs_event *e = data;
	const char *op;
	unsigned int count;

	(void)ctx;

	if (len < sizeof(*e))
		return 0;

	op = e->op == OP_ENQUEUE ? "enqueue" :
	     e->op == OP_DEQUEUE ? "dequeue" : "unknown";
	count = e->node_count > MAX_TREE_NODES ? MAX_TREE_NODES : e->node_count;

	printf("{\"type\":\"event\",\"seq\":%llu,\"op\":\"%s\",\"cpu\":%u,\"cfs_rq\":\"%016llx\",\"root\":\"%016llx\",\"leftmost\":\"%016llx\",\"changed_node\":\"%016llx\",\"changed_pid\":%u,\"changed_comm\":\"%s\",\"truncated\":%s,\"nodes\":[",
	       e->ts_ns, op, e->cpu, e->cfs_rq, e->root, e->leftmost,
	       e->changed_node, e->changed_pid, e->changed_comm,
	       e->truncated ? "true" : "false");
	for (unsigned int i = 0; i < count; i++) {
		const struct cfs_node_event *n = &e->nodes[i];

		printf("%s{\"node\":\"%016llx\",\"left\":\"%016llx\",\"right\":\"%016llx\",\"se\":\"%016llx\",\"color\":\"%s\",\"changed\":%s,\"leftmost\":%s}",
		       i ? "," : "", n->node, n->left, n->right, n->se,
		       n->color ? "B" : "R",
		       n->node == e->changed_node ? "true" : "false",
		       n->node == e->leftmost ? "true" : "false");
	}
	printf("]}\n");
	return 0;
}

int main(void)
{
	struct cfs_tree_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	skel = cfs_tree_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

if (skel->rodata)
		memcpy(skel->rodata->target_comm, "workld", 7);

	err = cfs_tree_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = cfs_tree_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
	                      NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "failed to create ring buffer: %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "attached to __enqueue_entity/__dequeue_entity; press Ctrl-C to stop\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 250);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ring buffer poll failed: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	cfs_tree_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
