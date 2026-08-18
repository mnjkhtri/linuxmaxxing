/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ring-buffer ABI shared between the BPF side (cfs.bpf.c) and the userspace loader (cfs.c).
 * This is the binary format only: the loader serializes it into the canonical NDJSON envelope.
 *
 * One post-__enqueue_entity snapshot, grouped into three semantic facts:
 *
 *   time_ns    CLOCK_MONOTONIC (bpf_ktime_get_ns()), identical to the tracefs instance clock (mono)
 *   event_info what caused this snapshot (the entity being enqueued)
 *   context    where and as whom the probe executed, which is not necessarily the enqueued task
 *   state      the actual CFS runqueue state observed after insertion
 *
 * The header intentionally contains no JSON vocabulary and no JSON representation choices.
 * Colors are 0/1 here, pointers are raw u64 here, and truncated is an integer here.
 * The loader converts those into "red"/"black", "0x..."/null, and true/false for the public schema.
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

struct cfs_event_info
{
	unsigned long long enqueued_entity; /* the enqueued sched_entity */
	unsigned long long enqueued_rb_node; /* the enqueued entity's embedded rb_node */
};

struct cfs_context
{
	unsigned int cpu; /* CPU on which this probe callback executed */
	unsigned int pid; /* TGID of the probing task */
	unsigned int tid; /* TID of the probing task */
	char comm[16];    /* task name of the probing task */
};

struct cfs_state
{
	unsigned long long cfs_rq;
	unsigned long long nr_running;
	unsigned long long root; /* cfs_rq->tasks_timeline.rb_root.rb_node */
	unsigned long long leftmost; /* cfs_rq->tasks_timeline.rb_leftmost */
	unsigned int node_count;
	unsigned int truncated;
	struct tree_node nodes[MAX_TREE_NODES];
};

struct cfs_event
{
	unsigned long long time_ns;
	struct cfs_event_info event_info;
	struct cfs_context context;
	struct cfs_state state;
};

#endif /* CFS_EVENT_H */
