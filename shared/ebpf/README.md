# Visualizing the Linux CFS RB Tree with eBPF

The Completely Fair Scheduler keeps runnable scheduling entities in a red-black tree. Each CPU has a CFS run queue. Its `tasks_timeline` tree is ordered by virtual runtime; `rb_root.rb_node` identifies the root and `rb_leftmost` identifies the entity with the smallest ordering key.

This collector observes `__enqueue_entity` with dynamic libbpf kprobes and kretprobes. The entry probe saves the function arguments. The return probe runs after enqueue changes the tree, traverses the resulting tree, and emits one newline-delimited JSON record.

## Kernel Prerequisites

The rebuilt kernel must provide BTF and BPF kprobe/kretprobe support. Install the required host packages from the repository root README.

Generate type declarations from the exact kernel image being tested:

```bash
mkdir -p shared/ebpf
bpftool btf dump file build/vmlinux format c > shared/ebpf/vmlinux.h
```

`vmlinux.h` is generated from kernel BTF. It lets the BPF program name kernel types such as `struct cfs_rq`, `struct rb_node`, and `struct task_struct`. CO-RE relocations let libbpf adapt field accesses when loading the program.

## Build and Run

```bash
make -C shared/ebpf clean
make -C shared/ebpf
```

Inside QEMU:

```bash
/mnt/host/ebpf/run.sh
```

The attachment message is written to stderr. Event records are written to stdout.

## Probe Flow

On x86-64, `__enqueue_entity` receives a `struct cfs_rq *` and a `struct sched_entity *`. The entry kprobe obtains them with `PT_REGS_PARM1(ctx)` and `PT_REGS_PARM2(ctx)`.

The entry probe stores them in the `active_args` hash map under `bpf_get_current_pid_tgid()`. It emits no event because the function has not finished modifying the tree.

The kretprobe retrieves the saved arguments after the function returns. It reads the post-enqueue tree, publishes the event to the ring buffer, and deletes the saved map entry.

## BPF Storage

The maps are:

- `active_args`: a hash map for entry-to-return correlation;
- `scratch`: a one-entry per-CPU array containing the large event, traversal worklist, and counters;
- `events`: a ring buffer for completed event transport to userspace.

The BPF stack is limited to 512 bytes, so the 31-node snapshot cannot be stored there. Each CPU has a private scratch copy, preventing concurrent probes from overwriting one another without a scratch lock.

`bpf_ringbuf_output()` copies a completed event into `events`, and libbpf invokes the userspace callback when that record is available.

## Tree Snapshot

The return probe reads:

```text
cfs_rq->tasks_timeline.rb_root.rb_node
cfs_rq->tasks_timeline.rb_leftmost
```

Each node record contains:

- its RB-node address;
- its left child;
- its right child;
- its color;
- its task name when available.

The color is bit zero of `rb_node.__rb_parent_color`; the remaining bits contain parent-pointer information.

Traversal uses a bounded breadth-first worklist:

```c
bpf_loop(MAX_TREE_NODES, walk_one_node, &traversal_key, 0);
```

The callback processes one worklist entry, records its children, and appends non-null children. The current bound is 31 nodes. `valid_nodes` is the number of records captured. `truncated=1` means reachable work remained after the configured bound was reached.

The verifier requires explicit bounds before variable-index map access. An ordinary 31-iteration loop exceeded verifier state complexity, so `bpf_loop()` provides the explicit bound.

## Task Names

An RB node belongs to a `sched_entity` through `sched_entity.run_node`. The helper subtracts that BTF offset to recover the entity, then subtracts the BTF offset of `task_struct.se` to recover the containing task.

The task name is copied with:

```c
bpf_probe_read_kernel_str(comm, 16, task->comm);
```

The name is limited to 15 visible characters and a terminating byte. Group scheduling entities do not always correspond directly to a task, so their name may be empty.

## JSON Format

Userspace emits one object per line:

```json
{"type":"event","op":"enqueue","tid":123,"cpu":1,"cfs_rq":"ffff...","se":"ffff...","leftmost":"ffff...","valid_nodes":2,"truncated":0,"nodes":[{"node":"ffff...","left":"0","right":"ffff...","color":1,"comm":"sched000"}]}
```

Pointers are strings because they are kernel addresses. The BPF and userspace `context_event` definitions must have identical field order, types, and array sizes.

## Workload Used By This Collector

The scheduler workload used for CFS snapshots is `fork_25_processes`. It forks 25 children, lets the scheduler balance them across the available CPUs, names them `schedNNN`, and releases them together. Each event records the CPU that owns the affected `cfs_rq`. The collector does not filter by the workload names; they simply create repeatable scheduler activity.

Run it inside QEMU with the command in the Build and Run section.

## Troubleshooting

Common failures:

- invalid CO-RE relocation: copy the kernel pointer into a local typed pointer before using a CO-RE macro;
- stack-limit error: move large temporary objects into map storage;
- unbounded map access: add explicit bounds checks before indexing;
- `processed 1000001 insns`: reduce verifier branches or use bounded `bpf_loop()`;
- empty task name: the entity may be a scheduling group or the task read may have failed;
- empty event file: the loader may have failed before attachment or stdout may have been redirected elsewhere.

## How eBPF Works

An eBPF program is compiled by Clang into BPF bytecode and placed in an object file. A userspace loader submits that object to the kernel through the `bpf()` system call, normally through libbpf. The kernel verifies each program before it can run. If verification succeeds, libbpf creates the declared maps and attaches the program to its section, such as `kprobe/__enqueue_entity` or `kretprobe/__enqueue_entity`.

The scheduler remains ordinary kernel code. When it calls `__enqueue_entity`, the attached entry program receives a probe context. When the function returns, the return program runs. BPF programs cannot use libc, call arbitrary kernel functions, allocate arbitrary memory, or trust arbitrary addresses. They use BPF instructions, kernel-provided helpers, BTF-aware reads, and declared maps.

The two programs have separate jobs:

- the BPF program observes kernel state and produces fixed-size records;
- the userspace loader opens and attaches the object, polls the ring buffer, and serializes records as JSON;
- the browser consumes the captured JSON.

## BTF, CO-RE, and Kernel Memory

BTF means BPF Type Format. It describes kernel C types, fields, sizes, offsets, and enums. DWARF is general compiler debugging information; BTF is compact type metadata intended for kernel and BPF use. `vmlinux` is the kernel image. `vmlinux.h` is a generated C header derived from the BTF in that image.

CO-RE means Compile Once, Run Everywhere. When Clang compiles an expression such as:

```c
BPF_CORE_READ(cfs_rq, tasks_timeline.rb_leftmost)
```

libbpf records the intended type and field. At load time it consults the running kernel BTF and relocates the access to the actual field offset. CO-RE adapts layout; it does not make an arbitrary kernel address safe. The pointer must still be obtained through a valid probe argument or a previously read kernel field, and every access must be bounded and verifier-approved.

BPF probe-read helpers copy kernel bytes into BPF memory. A kernel pointer is not a userspace pointer and must never be dereferenced by the browser. The JSON output treats addresses as strings used to connect nodes, not as addresses that userspace should access.

## Dynamic Kprobes and Kretprobes

A kprobe runs at function entry. On x86-64, `PT_REGS_PARM1(ctx)` and `PT_REGS_PARM2(ctx)` expose the first two function arguments. For `__enqueue_entity`, these are the CFS run queue and the scheduling entity being inserted.

A kretprobe runs when the function returns. It is the correct point for a post-operation snapshot because the enqueue operation has finished changing the tree. The return context does not provide the original arguments in the same convenient form, so the entry probe stores them in `active_args`, keyed by `bpf_get_current_pid_tgid()`. The return probe looks them up, uses them, and deletes the entry.

The key is a 64-bit process-and-thread identifier. The upper 32 bits are the thread-group ID and the lower 32 bits are the thread ID. A kprobe and kretprobe pair must correlate this state carefully; stale entries would associate a return event with the wrong operation.

## BPF Helpers and Maps

Helpers are kernel-provided functions that BPF is allowed to call. This program uses helpers for current identity, map lookup/update/delete, kernel reads, ring-buffer output, and bounded looping. A helper is not a normal C function: its arguments and return values have types that the verifier understands.

A map is kernel-managed storage declared by the BPF program. The map type determines its access pattern and lifetime:

```text
active_args  hash map keyed by pid_tgid; persistent entry/return correlation
scratch      one-entry per-CPU array; large temporary traversal workspace
events       ring buffer; completed event transport to userspace
```

The scratch map is per-CPU because multiple BPF invocations can run concurrently on different CPUs. A shared mutable workspace would allow CPU 1 to overwrite CPU 0 while CPU 0 was still walking its tree. A per-CPU array gives each CPU a private copy without a scratch lock. This does not mean the data is CPU-specific; it is only storage isolation.

The scratch map is needed because the BPF stack is limited to 512 bytes. The 31-node event and 31-pointer worklist cannot fit there. Small counters can remain on the stack, while large arrays belong in map storage.

The ring buffer is a transport mechanism, not long-term state. `bpf_ringbuf_output()` copies the completed event into the ring buffer. libbpf invokes the userspace callback with a pointer to the copied record and its length. The callback must reject short records before interpreting them as `context_event`.

## The Verifier

The verifier is a static safety proof engine. It does not run the program against one workload and assume the rest is safe. It explores possible control-flow paths and tracks:

- pointer provenance and pointer types;
- scalar minimum and maximum ranges;
- initialized stack and map memory;
- helper argument contracts;
- loop bounds and callback behavior;
- whether a variable offset stays inside an object.

The 512-byte stack limit is a memory limit. A stack error means the local objects are too large. Moving the event and worklist into `scratch` solves that limit.

Verifier complexity is a separate limit. A loop may have a small numeric bound and still create too many possible states when it contains branches, CO-RE reads, and variable-index map accesses. The kernel may report:

```text
BPF program is too large
processed 1000001 insns
```

This usually describes verifier analysis work, not a literal million-instruction BPF object.

The callback checks `index`, `head`, and `tail` before indexing the worklist. The verifier needs those checks directly before the access. A programmer knowing that an index is small is not enough; the verifier needs a provable range in the current path.

## bpf_loop and Bounded Traversal

`bpf_loop()` provides a bounded callback loop:

```c
bpf_loop(iterations, callback, context, flags);
```

The callback receives the iteration index and the supplied context. Returning zero continues; returning a nonzero value stops early. In this collector, `MAX_TREE_NODES` is 31 and the callback processes one worklist item per iteration.

The callback context is a small stack-resident key containing zero. It selects the only entry in the per-CPU scratch array. The iteration index is supplied by `bpf_loop`; it is not the map key and must not be incremented by the program.

The worklist implements breadth-first traversal. The callback reads one node, records its links and color, and appends its children. If the worklist fills while a child still exists, `truncated` is set. A complete snapshot has `truncated=0`; a snapshot with `truncated=1` is only the captured prefix of the reachable tree.
