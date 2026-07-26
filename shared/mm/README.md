# Memory State and Trace Observer

This directory combines two independent sources of evidence:

- kernel-state snapshots, which will be the visualization's source of truth;
- trace and eBPF events, which explain transitions between snapshots.

The eBPF observer attaches a return uprobe to the workload's `phase()`
function. Each phase record is therefore followed immediately by a snapshot of
the current task's real `mm_struct` and complete VMA layout.

The phase is only the synchronization boundary. VMA ranges, permissions, file
identity, offsets, and MM accounting are read from kernel state rather than
reconstructed from workload events. Since the workload announces a phase
before performing its action, its snapshot describes the state at that phase's
start; the following phase's snapshot shows the action's resulting VMA state.

## Build

The build follows the existing `shared/ebpf` CO-RE pipeline:

```bash
make -C shared/mm
```

This generates `vmlinux.h` from `build/vmlinux`, compiles the BPF object,
generates a libbpf skeleton, and links the userspace loader.

## Run the Observer

As root inside QEMU:

```bash
/mnt/host/mm/run.sh
```

The runner starts the prebuilt observer and workload, stops the observer
immediately afterward, and writes phase and `mm_snapshot` records to the
single capture file `/mnt/host/_captures/mm.ndjson`.
