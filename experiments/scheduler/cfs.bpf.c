// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "observer_bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "cfs_event.h"

char LICENSE[] SEC("license") = "GPL";

#define WORKLOAD_PREFIX "sched"
#define WORKLOAD_LAUNCHER "workload_fork"

/*
 * CFS keeps runnable scheduling entities in a red-black tree owned by each CPU's cfs_rq.
 * tasks_timeline.rb_root.rb_node is the root, while rb_leftmost caches the entity at the smallest ordering key.
 *
 * We observe __enqueue_entity twice: the kprobe saves its cfs_rq and sched_entity arguments, then the kretprobe reads the tree after insertion.
 * BTF describes these kernel types and CO-RE relocates their field offsets for the running kernel.
 * CO-RE adapts layouts; it does not make arbitrary kernel addresses safe, so every pointer still comes from a probe argument or a field reached from one.
 *
 * The emitted event carries the actual kernel-observed root and cached leftmost (captured directly, never reconstructed in userspace), the enqueued entity's rb_node, and a bounded BFS of the tree in cfs_event.
 */

/* Temporary state shared by the matching entry and return probes. */
struct saved_args
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *se;
};

struct scratch_state
{
	struct cfs_event event;
	struct rb_node *traversal_worklist[MAX_TREE_NODES];
	u32 head;
	u32 tail;
};

static __always_inline void read_node_comm(struct rb_node *node, char *comm);
static __always_inline int workload_name(char *comm);

static __always_inline struct task_struct *node_task(struct rb_node *node)
{
	struct sched_entity *se = (struct sched_entity *)((char *)node -
													  bpf_core_field_offset(struct sched_entity, run_node));
	return (struct task_struct *)((char *)se -
								  bpf_core_field_offset(struct task_struct, se));
}

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} capture_mode SEC(".maps");

static __always_inline void fill_node(struct tree_node *dst, struct rb_node *node)
{
	dst->node = (u64)node;
	if (!node)
		return;
	dst->left = (u64)BPF_CORE_READ(node, rb_left);
	dst->right = (u64)BPF_CORE_READ(node, rb_right);
	dst->color = (u32)(BPF_CORE_READ(node, __rb_parent_color) & 1);
	struct task_struct *task = node_task(node);
	dst->pid = BPF_CORE_READ(task, pid);
	read_node_comm(node, dst->comm);
}

/*
 * During the workload, scope snapshots to the launcher and schedNNN workers.
 * During the short post-workload drain, the userspace observer enables all task enqueues so the final per-CPU kernel activity remains visible.
 * Task-level entities embed struct task_struct at se - offsetof(task_struct, se), the same walk read_node_comm uses for tree nodes.
 * A group entity has no task behind that offset which we treat as not-a-workload-task, so such enqueues are safely skipped.
 */
static __always_inline int workload_entity(struct sched_entity *se)
{
	char comm[16] = {};
	u32 zero = 0;
	u32 *mode = bpf_map_lookup_elem(&capture_mode, &zero);
	struct task_struct *task =
		(struct task_struct *)((char *)se - bpf_core_field_offset(struct task_struct, se));
	long n = bpf_probe_read_kernel_str(comm, sizeof(comm), task->comm);
	if (n < 0)
		return 0;
	if (mode && *mode)
		return 1;
	return workload_name(comm);
}

static __always_inline int has_prefix(char *comm, const char *prefix, int length)
{
#pragma unroll
	for (int i = 0; i < length; i++)
		if (comm[i] != prefix[i])
			return 0;
	return 1;
}

static __always_inline int workload_name(char *comm)
{
	const char worker_prefix[] = WORKLOAD_PREFIX;
	const char launcher_name[] = WORKLOAD_LAUNCHER;

	return has_prefix(comm, worker_prefix, sizeof(worker_prefix) - 1) ||
		   has_prefix(comm, launcher_name, sizeof(launcher_name) - 1);
}

/* Recover a task name from a task-level sched_entity; group entities may have no task. */
static __always_inline void read_node_comm(struct rb_node *node, char *comm)
{
	__builtin_memset(comm, 0, 16);
	if (!node)
		return;

	struct task_struct *task = node_task(node);
	long n = bpf_probe_read_kernel_str(comm, 16, task->comm);
	if (n < 0)
		comm[0] = 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct saved_args);
} active_args SEC(".maps");

/* Per-CPU temporary workspace: keeps large traversal state off the 512-byte BPF stack and prevents CPUs from sharing one mutable scratch value. */
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct scratch_state);
} scratch SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/*
 * Breadth-first traversal uses an explicitly bounded bpf_loop callback.
 * The verifier needs the range checks immediately before every variable-index access.
 * If the 31-slot worklist fills while children remain, truncated is set so userspace never mistakes a partial tree for a complete one.
 */
static long walk_one_node(u64 index, void *ctx)
{
	u32 *key = ctx;
	struct scratch_state *scratch_state_ptr = bpf_map_lookup_elem(&scratch, key);

	if (!scratch_state_ptr || index >= MAX_TREE_NODES ||
		scratch_state_ptr->head >= MAX_TREE_NODES ||
		scratch_state_ptr->tail > MAX_TREE_NODES ||
		scratch_state_ptr->head >= scratch_state_ptr->tail ||
		!scratch_state_ptr->traversal_worklist[scratch_state_ptr->head])
		return 1;

	struct cfs_event *event = &scratch_state_ptr->event;
	struct rb_node *node = scratch_state_ptr->traversal_worklist[scratch_state_ptr->head++];
	fill_node(&event->state.nodes[index], node);
	if (event->state.nodes[index].left)
	{
		if (scratch_state_ptr->tail < MAX_TREE_NODES)
			scratch_state_ptr->traversal_worklist[scratch_state_ptr->tail++] =
				(struct rb_node *)event->state.nodes[index].left;
		else
			event->state.truncated = 1;
	}
	if (event->state.nodes[index].right)
	{
		if (scratch_state_ptr->tail < MAX_TREE_NODES)
			scratch_state_ptr->traversal_worklist[scratch_state_ptr->tail++] =
				(struct rb_node *)event->state.nodes[index].right;
		else
			event->state.truncated = 1;
	}
	return 0;
}

static __always_inline int emit_snapshot(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 zero = 0;
	struct scratch_state *scratch_state_ptr = bpf_map_lookup_elem(&scratch, &zero);
	if (!scratch_state_ptr)
		return 0;

	struct cfs_event *event = &scratch_state_ptr->event;
	event->time_ns = bpf_ktime_get_ns();
	event->context.pid = (u32)(id >> 32);
	event->context.tid = (u32)id;
	event->context.cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(event->context.comm, sizeof(event->context.comm));
	event->event_info.enqueued_entity = (u64)se;
	event->event_info.enqueued_rb_node =
		(u64)((char *)se + bpf_core_field_offset(struct sched_entity, run_node));
	event->state.cfs_rq = (u64)cfs_rq;
	event->state.nr_running = BPF_CORE_READ(cfs_rq, rq, nr_running);
	event->state.root = (u64)BPF_CORE_READ(cfs_rq, tasks_timeline.rb_root.rb_node);
	event->state.leftmost = (u64)BPF_CORE_READ(cfs_rq, tasks_timeline.rb_leftmost);
	event->state.node_count = 0;
	event->state.truncated = 0;
	scratch_state_ptr->head = 0;
	scratch_state_ptr->tail = 1;
	scratch_state_ptr->traversal_worklist[0] = BPF_CORE_READ(cfs_rq, tasks_timeline.rb_root.rb_node);
	u32 traversal_key = 0;
	bpf_loop(MAX_TREE_NODES, walk_one_node, &traversal_key, 0);
	event->state.node_count = scratch_state_ptr->head;
	if (scratch_state_ptr->head < scratch_state_ptr->tail)
		event->state.truncated = 1;
	lab_output(&events, event, sizeof(*event), 0);
	return 0;
}

/*
 * Entry probe: correlate arguments by pid_tgid.
 * It deliberately emits no event because __enqueue_entity has not finished changing the tree yet.
 */
SEC("kprobe/__enqueue_entity")
int BPF_KPROBE(kprobe_enqueue_entity)
{
	struct saved_args args = {
		.cfs_rq = (struct cfs_rq *)PT_REGS_PARM1(ctx),
		.se = (struct sched_entity *)PT_REGS_PARM2(ctx),
	};

	/* Keep the active_args map focused during the workload; drain mode is enabled by the userspace observer after workload completion. */
	if (!workload_entity(args.se))
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	lab_map_update(&active_args, &id, &args, BPF_ANY);
	return 0;
}

/* Return probe: read the post-enqueue tree, emit it once, then forget args. */
SEC("kretprobe/__enqueue_entity")
int BPF_KRETPROBE(kretprobe_enqueue_entity)
{
	u64 id = bpf_get_current_pid_tgid();
	struct saved_args *args = bpf_map_lookup_elem(&active_args, &id);
	if (!args)
		return 0;

	/* Copy the map value pointer first so CO-RE sees the kernel type directly. */
	emit_snapshot(args->cfs_rq, args->se);
	bpf_map_delete_elem(&active_args, &id);
	return 0;
}
