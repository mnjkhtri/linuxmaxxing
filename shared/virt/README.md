# KVM and EPT

One-shot checks for manually allocated CloudLab virtualization hosts.

CloudLab must already have your SSH public key configured.

Put the SSH target in `shared/virt/cloudlab`:

```bash
user@c220g5-xxxxxx.wisc.cloudlab.us
```

```bash
./shared/virt/verify.sh
```

Long-lived SSH session:

```bash
ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=120 "$(cat shared/virt/cloudlab)"
```

```bash
./shared/virt/run.sh
```

One CloudLab run executes the toy VMM once and writes both captures:

```text
shared/_captures/kvm-trace.txt
shared/_captures/ept.ndjson
```

The observer is intentionally Intel-only: it walks KVM's EPT tables and
recognizes Intel EPT permission and MMIO encodings. `verify.sh` rejects AMD
NPT hosts instead of presenting their entries as EPT.

`verify.sh` is a provisioning check, not a purely read-only probe. On a new
CloudLab node it can install build dependencies, load `kvm_intel`, mount
tracefs/debugfs, repair broken node hostname lookup, and repair DNS when package
installation cannot resolve the Ubuntu archive. It does not leave KVM
tracepoints enabled.

`run.sh` uses a private tracefs instance with the monotonic clock. The eBPF
hooks use KVM events only as sampling boundaries and emit pure EPT state
snapshots; the UI derives changes by comparing adjacent snapshots.

The guest keeps code in GFN 0, uses the last slot page (GFN 7) for data, and
leaves GFNs 1-6 untouched so their EPT states remain visually distinct. It
requests two synchronization exercises
through port `0xe9`:

1. The VMM calls `madvise(MADV_DONTNEED)` on that page. Linux emits an MMU
   notifier invalidation, KVM removes the EPT leaf, and the next guest store
   faults the page back in.
2. The VMM deletes slot 0 and recreates it over a different anonymous mapping.
   KVM drops the old slot's EPT mappings, then guest instruction and data
   accesses rebuild them against the replacement backing.

`kvm_unmap_hva_range` and `kvm_mmu_spte_requested` are sampling triggers
only; their event arguments are not stored in `vcpu_mm_snapshot`.
`ept.ndjson` contains pure EPT state, and the UI derives mapping changes by
comparing adjacent snapshots.

If transport is interrupted after a successful remote run, retrieve the
already-validated capture set without rerunning the guest:

```bash
VIRT_FETCH_ONLY=1 ./shared/virt/run.sh
```

MM sampling model:

```text
for each captured VMA
  take at most the first 512 pages from that VMA
  for each sampled virtual page
    start at mm->pgd
    walk the process page table
    record what that page currently is
```

EPT sampling model:

```text
sample GFN 0-15 densely
sample the command-4 access GFN in the huge-page range
for each sampled guest frame number
  convert GFN to GPA
  start at KVM's EPT root HPA from kvm_vcpu->arch.mmu
  walk the EPT/TDP page table
  record what host physical page, if any, backs that guest frame
```

MM walks process virtual pages from VMA ranges. EPT walks guest physical frames because EPT translates GPA to HPA. This toy guest currently has paging off, so GVA equals GPA.

EPT snapshots are best-effort observations. KVM can update SPTEs while BPF
walks them; the observer deliberately does not take KVM's MMU locks from a
tracepoint program.
