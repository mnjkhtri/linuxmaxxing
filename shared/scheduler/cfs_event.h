/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ring-buffer ABI shared between the BPF side (cfs.bpf.c) and the userspace loader (cfs.c).
 * This is the binary format only: the loader serializes it into the canonical NDJSON envelope.
 * The loader also normalizes representation details such as RB colors (0/1 here becomes "red"/"black" there).
 *
 * The header intentionally contains no JSON vocabulary.
 * It must compile in both BPF (-target bpf) and normal userspace builds.
 */
#ifndef CFS_EVENT_H
#define CFS_EVENT_H

#define MAX_TREE_NODES 31

/* Linux rbtree stores the color in the low bit of __rb_parent_color: 0 = red, 1 = black. */
#define CFS_RB_RED 0
#define CFS_RB_BLACK 1

struct tree_node
{
	unsigned long long node;
	unsigned long long left;
	unsigned long long right;
	unsigned int color; /* CFS_RB_RED or CFS_RB_BLACK */
	char comm[16];
};

/*
 * One post-__enqueue_entity snapshot.
 * Time is CLOCK_MONOTONIC (bpf_ktime_get_ns()), identical to the tracefs instance clock (mono).
 * The frontend can therefore compare time_ns directly with tracefs seconds * 1e9.
 *
 * pid/tid/comm describe the task context the probes ran in.
 * They are not necessarily the task represented by the enqueued sched_entity.
 */
struct cfs_event
{
	unsigned long long time_ns;
	unsigned int pid; /* tgid of the probing task */
	unsigned int tid; /* tid of the probing task */
	unsigned int cpu; /* CPU the probe ran on */
	char comm[16];    /* task name of the probing task */
	unsigned long long cfs_rq;
	unsigned long long se; /* enqueued sched_entity */
	unsigned long long run_node; /* enqueued se's embedded rb_node */
	unsigned long long nr_running;
	unsigned long long root; /* cfs_rq->tasks_timeline.rb_root.rb_node */
	unsigned long long leftmost; /* cfs_rq->tasks_timeline.rb_leftmost */
	unsigned int node_count;
	unsigned int truncated;
	struct tree_node nodes[MAX_TREE_NODES];
};

#endif /* CFS_EVENT_H */
