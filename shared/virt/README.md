# cloudlab

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

## 01-kvm

```bash
./shared/virt/01-kvm/run.sh
```

One CloudLab run executes the toy VMM once and writes both captures:

```text
shared/_captures/01-kvm-trace.txt
shared/_captures/ept.ndjson
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
take at most the first MAX_GFN_SAMPLES guest frames
for each sampled guest frame number
  convert GFN to GPA
  start at KVM's EPT root HPA from kvm_vcpu->arch.mmu
  walk the EPT/TDP page table
  record what host physical page, if any, backs that guest frame
```

MM walks process virtual pages from VMA ranges. EPT walks guest physical frames because EPT translates GPA to HPA. This toy guest currently has paging off, so GVA equals GPA.
