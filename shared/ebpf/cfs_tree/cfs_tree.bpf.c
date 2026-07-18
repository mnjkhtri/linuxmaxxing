// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

const volatile char target_comm[16];

#define MAX_TREE_NODES 31

struct saved_args {
	struct cfs_rq *cfs_rq;
	struct sched_entity *se;
};

struct cfs_node_event {
	u64 node;
	u64 left;
	u64 right;
	u64 se;
	u32 color;
	u32 _pad;
};

struct cfs_event {
	u64 ts_ns;
	u32 cpu;
	u32 op;
	u32 node_count;
	u32 _pad;
	u64 cfs_rq;
	u64 root;
	u64 leftmost;
	u64 changed_node;
	u32 changed_pid;
	u32 truncated;
	char changed_comm[16];
	struct cfs_node_event nodes[MAX_TREE_NODES];
};

struct walk_state {
	struct cfs_event event;
	u64 queue[MAX_TREE_NODES];
	u32 head;
	u32 tail;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct saved_args);
} cfs_active_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct walk_state);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

enum {
	PHASE_ENTRY = 0,
	PHASE_RETURN = 1,
};

enum {
	OP_ENQUEUE = 1,
	OP_DEQUEUE = 2,
};

static __always_inline struct task_struct *task_from_se(struct sched_entity *se)
{
	return (struct task_struct *)((char *)se -
		bpf_core_field_offset(struct task_struct, se));
}

static __always_inline void read_task_identity(struct sched_entity *se, u32 *pid,
					       char comm[16])
{
	struct task_struct *task = task_from_se(se);
	long n = bpf_probe_read_kernel_str(comm, 16, task->comm);
	*pid = BPF_CORE_READ(task, pid);
	if (n < 0) {
		*pid = 0;
		comm[0] = 0;
	}
}

static __always_inline int target_matches(char comm[16])
{
	#pragma unroll
	for (int i = 0; i < 6; i++)
		if (target_comm[i] && comm[i] != target_comm[i])
			return 0;
	return 1;
}

static __always_inline struct sched_entity *se_from_node(struct rb_node *node)
{
	return (struct sched_entity *)((char *)node -
		bpf_core_field_offset(struct sched_entity, run_node));
}

static __noinline void fill_node(struct cfs_node_event *dst,
				      struct rb_node *node)
{
	struct sched_entity *node_se;
	u64 parent_color;

	dst->node = (u64)node;
	dst->left = (u64)BPF_CORE_READ(node, rb_left);
	dst->right = (u64)BPF_CORE_READ(node, rb_right);
	parent_color = BPF_CORE_READ(node, __rb_parent_color);
	dst->color = parent_color & 1;
	node_se = se_from_node(node);
	dst->se = (u64)node_se;
}

static long walk_tree(u32 i, void *data)
{
	struct walk_state *state;
	struct cfs_event *e;
	u32 *zero = data;

	state = bpf_map_lookup_elem(&scratch, zero);
	if (!state)
		return 1;
	e = &state->event;
	struct rb_node *node;
	struct cfs_node_event *out;
	u32 head;
	u32 slot;
	u32 tail;

	slot = i & 31;
	head = state->head;
	tail = state->tail;
	if (slot >= MAX_TREE_NODES || head >= MAX_TREE_NODES ||
	    tail > MAX_TREE_NODES || head >= tail)
		return 1;

	state->head = head + 1;
	node = (struct rb_node *)state->queue[head & 31];
	if (!node)
		return 0;

	out = &e->nodes[slot];
	fill_node(out, node);
	e->node_count = slot + 1;

	tail = state->tail;
	if (out->left && tail < MAX_TREE_NODES) {
		state->queue[tail & 31] = out->left;
		state->tail = ++tail;
	}
	if (out->right && tail < MAX_TREE_NODES) {
		state->queue[tail & 31] = out->right;
		state->tail = tail + 1;
	}

	return 0;
}

static __always_inline void emit_event(u32 op, struct cfs_rq *cfs_rq,
				       struct sched_entity *se)
{
	struct walk_state *state;
	struct cfs_event *e;
	struct rb_node *root;
	u32 zero = 0;
	u32 changed_pid;
	char changed_comm[16];

	read_task_identity(se, &changed_pid, changed_comm);
	if (!target_matches(changed_comm))
		return;

	state = bpf_map_lookup_elem(&scratch, &zero);
	if (!state)
		return;
	e = &state->event;
	state->head = 0;
	state->tail = 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->cpu = bpf_get_smp_processor_id();
	e->op = op;
	e->node_count = 0;
	e->_pad = 0;
	e->cfs_rq = (u64)cfs_rq;
	e->root = 0;
	e->leftmost = (u64)BPF_CORE_READ(cfs_rq, tasks_timeline.rb_leftmost);
	e->changed_node = (u64)&se->run_node;
	e->changed_pid = changed_pid;
	e->truncated = 0;
	__builtin_memcpy(e->changed_comm, changed_comm, sizeof(e->changed_comm));

	root = BPF_CORE_READ(cfs_rq, tasks_timeline.rb_root.rb_node);
	e->root = (u64)root;
	if (!root) {
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
		return;
	}

	state->queue[0] = (u64)root;
	state->tail = 1;
	bpf_loop(MAX_TREE_NODES, walk_tree, &zero, 0);
	state = bpf_map_lookup_elem(&scratch, &zero);
	if (!state)
		return;
	e = &state->event;
	e->truncated = state->head < state->tail;

	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

static __always_inline int on_entry(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct saved_args args = {};

	args.cfs_rq = (struct cfs_rq *)PT_REGS_PARM1(ctx);
	args.se = (struct sched_entity *)PT_REGS_PARM2(ctx);
	bpf_map_update_elem(&cfs_active_args, &id, &args, BPF_ANY);
	return 0;
}

static __always_inline int on_return(u32 op)
{
	u64 id = bpf_get_current_pid_tgid();
	struct saved_args *args;

	args = bpf_map_lookup_elem(&cfs_active_args, &id);
	if (!args)
		return 0;

	emit_event(op, args->cfs_rq, args->se);
	bpf_map_delete_elem(&cfs_active_args, &id);
	return 0;
}

SEC("kprobe/__enqueue_entity")
int BPF_KPROBE(kprobe_enqueue_entity)
{
	return on_entry(ctx);
}

SEC("kretprobe/__enqueue_entity")
int BPF_KRETPROBE(kretprobe_enqueue_entity)
{
	return on_return(OP_ENQUEUE);
}

SEC("kprobe/__dequeue_entity")
int BPF_KPROBE(kprobe_dequeue_entity)
{
	return on_entry(ctx);
}

SEC("kretprobe/__dequeue_entity")
int BPF_KRETPROBE(kretprobe_dequeue_entity)
{
	return on_return(OP_DEQUEUE);
}
