// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_TREE_NODES 31

/* This event proves that entry state reached the return probe. */
struct tree_node
{
	u64 node;
	u64 left;
	u64 right;
	u32 color;
	char comm[16];
};

struct context_event
{
	u32 tid;
	u64 cfs_rq;
	u64 se;
	u64 leftmost;
	u32 node_count;
	u32 truncated;
	struct tree_node nodes[MAX_TREE_NODES];
};

struct scratch_state
{
	struct context_event event;
	struct rb_node *traversal_worklist[MAX_TREE_NODES];
	u32 head;
	u32 tail;
};

static __always_inline void read_node_comm(struct rb_node *node, char *comm);

static __always_inline void fill_node(struct tree_node *dst, struct rb_node *node)
{
	dst->node = (u64)node;
	if (!node)
		return;
	dst->left = (u64)BPF_CORE_READ(node, rb_left);
	dst->right = (u64)BPF_CORE_READ(node, rb_right);
	dst->color = (u32)(BPF_CORE_READ(node, __rb_parent_color) & 1);
	read_node_comm(node, dst->comm);
}

/* Recover a task name from a task-level sched_entity; group entities may have no task. */
static __always_inline void read_node_comm(struct rb_node *node, char *comm)
{
	__builtin_memset(comm, 0, 16);
	if (!node)
		return;

	struct sched_entity *se = (struct sched_entity *)((char *)node - bpf_core_field_offset(struct sched_entity, run_node));
	struct task_struct *task = (struct task_struct *)((char *)se - bpf_core_field_offset(struct task_struct, se));
	long n = bpf_probe_read_kernel_str(comm, 16, task->comm);
	if (n < 0)
		comm[0] = 0;
}

/* Temporary state shared by the matching entry and return probes. */
struct saved_args
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *se;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct saved_args);
} active_args SEC(".maps");

/* Per-CPU temporary workspace: keeps large traversal state off the 512-byte BPF stack and prevents CPUs from sharing one mutable scratch value, so no scratch lock is needed. */
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct scratch_state);
} scratch SEC(".maps");

static long walk_one_node(u64 index, void *ctx)
{
	u32 *key = ctx;
	struct scratch_state *scratch_state_ptr = bpf_map_lookup_elem(&scratch, key);
	struct rb_node *node;
	struct context_event *event;

	if (!scratch_state_ptr || index >= MAX_TREE_NODES ||
		scratch_state_ptr->head >= MAX_TREE_NODES ||
		scratch_state_ptr->tail > MAX_TREE_NODES ||
		scratch_state_ptr->head >= scratch_state_ptr->tail ||
		!scratch_state_ptr->traversal_worklist[scratch_state_ptr->head])
		return 1;

	event = &scratch_state_ptr->event;
	node = scratch_state_ptr->traversal_worklist[scratch_state_ptr->head++];
	fill_node(&event->nodes[index], node);
	if (event->nodes[index].left)
	{
		if (scratch_state_ptr->tail < MAX_TREE_NODES)
			scratch_state_ptr->traversal_worklist[scratch_state_ptr->tail++] =
				(struct rb_node *)event->nodes[index].left;
		else
			event->truncated = 1;
	}
	if (event->nodes[index].right)
	{
		if (scratch_state_ptr->tail < MAX_TREE_NODES)
			scratch_state_ptr->traversal_worklist[scratch_state_ptr->tail++] =
				(struct rb_node *)event->nodes[index].right;
		else
			event->truncated = 1;
	}
	return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} events SEC(".maps");

/* Entry probe: save arguments only. It deliberately emits no event. */
SEC("kprobe/__enqueue_entity")
int BPF_KPROBE(kprobe_enqueue_entity)
{
	u64 id = bpf_get_current_pid_tgid();
	struct saved_args args = {
		.cfs_rq = (struct cfs_rq *)PT_REGS_PARM1(ctx),
		.se = (struct sched_entity *)PT_REGS_PARM2(ctx),
	};

	bpf_map_update_elem(&active_args, &id, &args, BPF_ANY);
	return 0;
}

/* Return probe: retrieve the saved pointers and emit them once. */
SEC("kretprobe/__enqueue_entity")
int BPF_KRETPROBE(kretprobe_enqueue_entity)
{
	u64 id = bpf_get_current_pid_tgid();
	struct saved_args *args = bpf_map_lookup_elem(&active_args, &id);
	if (!args)
		return 0;

	/* Copy the map value pointer first so CO-RE sees the kernel type directly. */
	struct cfs_rq *cfs_rq = args->cfs_rq;
	struct rb_node *root_node =
		BPF_CORE_READ(cfs_rq, tasks_timeline.rb_root.rb_node);
	u32 zero = 0;
	struct scratch_state *scratch_state_ptr = bpf_map_lookup_elem(&scratch, &zero);
	if (!scratch_state_ptr)
		return 0;

	struct context_event *event = &scratch_state_ptr->event;
	event->tid = (u32)id;
	event->cfs_rq = (u64)cfs_rq;
	event->se = (u64)args->se;
	event->leftmost = (u64)BPF_CORE_READ(cfs_rq, tasks_timeline.rb_leftmost);
	event->node_count = 0;
	event->truncated = 0;
	scratch_state_ptr->head = 0;
	scratch_state_ptr->tail = 1;
	scratch_state_ptr->traversal_worklist[0] = root_node;
	u32 traversal_key = 0;

	/* The helper provides a verifier-visible bound for the BFS. */
	bpf_loop(MAX_TREE_NODES, walk_one_node, &traversal_key, 0);
	event->node_count = scratch_state_ptr->head;
	if (scratch_state_ptr->head < scratch_state_ptr->tail)
		event->truncated = 1;
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	bpf_map_delete_elem(&active_args, &id);
	return 0;
}
