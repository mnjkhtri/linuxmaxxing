# HyperTurtle Reproduction Status Report

**Date:** March 26, 2026
**Paper:** "Accelerating Nested Virtualization with HyperTurtle" (USENIX ATC'25)
**Repo:** https://github.com/acsl-technion/hyperturtle
**Platform:** CloudLab — 2× c220g5 nodesA

---

## 1. Hardware Comparison
| Component | Paper (Table 6) | Our Setup |
|---|---|---|
| CPU | 2×Xeon Silver 4216 (16-core, 2.1GHz) | 2×Xeon Silver 4114 (10-core, 2.2GHz) |
| CPU Family | Skylake-SP | Skylake-SP (same family) |
| Physical Address Bits | 46-bit | 46-bit |
| RAM | 512 GiB | ~192 GiB |
| NIC | Nvidia MT27710 (ConnectX-4) | Intel X520/X540 |
| SMT | Off | Off ✅ |
| Cores/NUMA node | 16 | 10 (3 of 12 vCPUs cross NUMA boundary) |

---

## 2. Current System Configuration

### L0 (Bare-Metal Hypervisor)
| Component | Status |
|---|---|
| OS | Ubuntu 20.04.6 LTS ✅ |
| Kernel | 5.16.0+ (hyperturtle-linux) ✅ |
| Boot Params | `idle=poll nopti` ✅ |
| SMT Off, KVM nested=Y, ple_gap=0 | ✅ |
| vhost_net zero-copy TX | ✅ |
| Custom QEMU 7.2.0 | ✅ |
| libbpf v0.8.0, bpftool | ✅ |

### L0 Kernel Patches
- `bpf_probe_read_hyperupcall` helper (ID=180)
- QEMU null-check for `nc->info->type`
- `MAPS_DEV_OFFSET`: 5 → 1 in `kvm_host.h`
- Zombie fix 1: early hyperupcall disablement in `__kvm_set_memory_region`
- Zombie fix 2: eBPF circuit breaker for reserved-bits PTE
- All `bpf_printk` calls commented out in `ept_fault.bpf.c`

### L1 (Virtualized Hypervisor)
| Component | Status |
|---|---|
| OS | Ubuntu 20.04.6 LTS ✅ |
| Kernel | 5.16.0+ ✅ |
| Boot Params | `nopti console=ttyS0 idle=poll` ✅ |
| QEMU prealloc | on ✅ |
| vCPUs / RAM | 12 / 64 GiB ✅ |
| Kata Containers 3.2.0 | ✅ |
| Cloud-Hypervisor v33.0 | ✅ |
| Kata debug logging | OFF ✅ |
| CPU pinning | Fixed (`pin_vcpus.sh`) ✅ |

### L2 (Kata Container)
| Component | Status |
|---|---|
| VMM | Cloud-Hypervisor v33.0 ✅ |
| vCPUs / RAM | 1 / 2048 MiB ✅ |
| Kernel | 6.1.38 (Kata bundled) ✅ |

### Hyperupcall Infrastructure
| Component | Status |
|---|---|
| ept_fault.bpf.o | ✅ Built (printk removed, circuit breaker active) |
| ept_fault.guest | ✅ Registration, linking, shared maps all working |
| Network hyperupcalls | ❌ Not built |
| Tracing hyperupcall | ❌ Not built |

---

## 3. Experiment Landscape & Results

### 3.1 EPT Fault Latency Microbenchmark (Paper Fig 9a / Table 2)

**Method:** mmap 1GiB anonymous memory, touch each 4KiB page, measure per-fault latency via rdtsc.

| Config | Our Average | Paper Average | Our 99p | Paper 99p | Match? |
|---|---|---|---|---|---|
| L1 VM (non-nested) | **5.52µs** | 5.58µs | 10.69µs | 9.35µs | ✅ Excellent |
| L2 VM (nested baseline) | **30.35µs** | 28.39µs | 65.03µs | 49.13µs | ✅ Close |
| L2 VM + HT | **28.43µs** | ~5.5µs (expected) | 62.92µs | ~10µs | ❌ Not reproduced |
| Paper's speedup | — | **5.1×** | — | **5.3×** | — |
| Our speedup | **1.07×** (6.3%) | — | **1.03×** (3.2%) | — | — |

**Tail latency improvement is significant:**
| | Baseline Max | HT Max | Improvement |
|---|---|---|---|
| Our results | 12,556µs | 825µs | **15× better** |

**Hyperupcall counters during 1GiB benchmark (262,144 pages):**
- Attempts: 212,878 (81% of pages triggered hyperupcall)
- Success: 194,719 (74% handled on fast path, 93% of attempts)
- no_memslot failures: 486
- cant_remap failures: 385
- N_BLANKS warmup skips: 999

**Diagnosis:** The eBPF successfully handles 74% of all faults, but per-fault latency is not significantly reduced (~28µs vs ~30µs). The fast path avoids world switches to L1, but L0 still performs the full EPT0→2 fixup and nested VMCS manipulation after the eBPF returns. **We suspect L0 may still be executing the slow path after the eBPF succeeds** — investigation of the hook implementation is in progress.

### 3.2 Kata Container Startup (Paper Fig 10)

**Method:** Docker → Kata → Cloud-Hypervisor → L2 boot → web server → port responds via nc.

#### With `idle=poll` (current config, matches paper)

| Image | Baseline | HT-on | Δ |
|---|---|---|---|
| alpine | 2.66 | 2.90 | +9% |
| ubuntu | 2.68 | 2.71 | +1% |
| java | 2.66 | 2.77 | +4% |
| js | 2.67 | 2.79 | +4% |
| python | 2.68 | 2.75 | +3% |
| pd | 2.72 | 2.81 | +3% |
| **Average** | **2.68** | **2.79** | **+4% (slower)** |

5 runs per image. CoV < 3%. Zero zombies.

**Paper reports ~27% improvement. We see ~4% regression.**

#### Without `idle=poll` (earlier config)

| Image | Baseline | HT-on | Δ |
|---|---|---|---|
| alpine | 2.731 | 2.774 | +1.6% |
| ubuntu | 2.750 | 2.787 | +1.3% |
| java | 2.741 | 2.849 | +3.9% |
| js | 2.727 | 2.829 | +3.7% |
| python | 2.718 | 2.854 | +5.0% |
| pd | 2.754 | 2.808 | +2.0% |
| **Average** | **2.737** | **2.817** | **+2.9% (slower)** |

10 runs per image. CoV < 3%. Zero zombies.

### 3.3 VM-Exit Breakdown (One Baseline Container Boot, from L0 debugfs)

| Counter | Delta | % of exits |
|---|---|---|
| Total exits | 223,565 | 100% |
| pf_fixed (all EPT faults) | 40,653 | 18% |
| halt_exits | 17,763 | 8% |
| hypercalls | 3,677 | 2% |
| mmio_exits | 36 | ~0% |
| Other (IRQs, emulation) | ~161,436 | 72% |

Of the ~40K EPT faults, only ~4K are L2 faults handled by the hyperupcall. The rest are L1's own faults (containerd, Docker, Cloud-Hypervisor, virtiofsd, Kata shim).

### 3.4 Experiments Not Yet Run

| Benchmark | Paper Reference | Dependencies | Status |
|---|---|---|---|
| EPT Fault Latency | Fig 9a, Table 2 | ept_fault hyperupcall | 🔶 Run but not reproduced — investigating hook |
| Startup (4KiB) | Fig 10a | ept_fault hyperupcall | 🔶 Run, no improvement seen |
| Startup (2MiB) | Fig 10b | Launch L1 with `-b` flag | ❌ Not started |
| Redis/DeathStar Launch | Fig 11 | ept_fault hyperupcall | ❌ Not started |
| Network Latency/Throughput | Table 7 | Network hyperupcalls, 2nd node | ❌ Not started |
| Nginx Throughput | Fig 12a | Network hyperupcalls, ApacheBench | ❌ Not started |
| Redis Throughput | Fig 12b | Network hyperupcalls, memtier | ❌ Not started |
| Memcached Latency | Fig 13 | Network hyperupcalls, mutilate | ❌ Not started |
| Profiling Latency | Fig 9b | Tracing hyperupcall, GUPS | ❌ Not started |
| Profiling + Memcached | Fig 14 | Tracing + Network hyperupcalls | ❌ Not started |

---

## 4. Current Investigation: Why HT Fast Path Isn't Fast

### What works correctly
- Hyperupcall loads, links, creates 7 shared maps via PCI devices
- eBPF fires on L2 EPT faults (212K attempts in 1GiB benchmark)
- 74% of pages handled via fast path (194K successes)
- PFN cache works (cache_dirty = success count)
- Memslot data populated, QEMU_CR3 captured
- Zero reserved-bits errors, zero zombies
- Tail latency dramatically improved (max 12,556 → 825µs, 15×)

### What doesn't match the paper
- Average per-fault latency with HT (~28µs) is nearly the same as without (~30µs)
- Paper expects ~5.5µs (matching L1 non-nested performance)
- The eBPF writes EPT1→2 successfully, but L0's post-eBPF handling appears to still execute the full expensive path

### Active investigation
- **Searching for the eBPF hook point in L0's KVM code** — the hook isn't in standard MMU/nested code paths, kprobes list is empty, no SEC() annotations with hook functions. The eBPF is loaded via custom hypercalls (13=LOAD, 15=LINK) but the invocation mechanism is unclear.
- **Hypothesis:** L0 may be running the eBPF to populate EPT1→2, but then still going through the full 6-world-switch path (inject to L1, L1 handles, trap back) because it doesn't check the eBPF return value to short-circuit.
- **Next step:** Find where in L0's kernel the linked eBPF programs are invoked during EPT fault handling.

---

## 5. Bugs Found and Fixed

| # | Bug | Impact | Fix |
|---|---|---|---|
| 1 | MAPS_DEV_OFFSET=5 (should be 1) | Shared maps all NULL, hyperupcall non-functional | One-line change in `kvm_host.h` |
| 2 | Zombie Cloud-Hypervisor | Infinite EPT retry loop on VM teardown, ~70% CPU per zombie | Two-part: early disablement + eBPF circuit breaker |
| 3 | Kata `enable_debug=true` | +3.5s per container boot, masked all HT effects | Set to false in `configuration-clh.toml` |
| 4 | CPU pinning script broken | Non-vCPU threads sharing cores with vCPU threads | Rewrote `pin_vcpus.sh` |
| 5 | Dockerfile base image swaps | Build failures | Fixed image names and packages |
| 6 | `bpf_printk` in eBPF hot path | 3 uncommented debug prints firing ~262K times | Commented out, rebuilt |
| 7 | `idle=poll` missing in L1 | L1 VM EPT faults artificially fast (2.7µs vs 5.5µs), mismatched paper config | Added to grub.cfg directly |
| 8 | QEMU duplicate PCI object crash | QEMU aborts on hyperupcall reload without full restart | Must restart L1 QEMU between hyperupcall sessions |

---

## 6. Reproduction Roadmap

### Completed ✅
1. ✅ L0 → L1 → L2 stack fully operational (matching paper Table 6)
2. ✅ EPT fault hyperupcall infrastructure fully working
3. ✅ All kernel/config bugs fixed (MAPS_DEV_OFFSET, zombies, debug, pinning, printk)
4. ✅ Baseline EPT fault latency matches paper (L1: 5.52 vs 5.58µs, L2: 30.35 vs 28.39µs)
5. ✅ Container startup benchmarks collected (baseline and HT, with and without idle=poll)
6. ✅ VM-exit breakdown analysis completed

### In Progress
1. 🔶 **Investigating why HT fast path doesn't reduce average latency** — searching for eBPF hook invocation point in L0 KVM

### Next Steps (after hook investigation)
2. ⬜ Run startup benchmark with corrected HT (if hook issue found)
3. ⬜ Run 2MiB huge pages startup benchmark
4. ⬜ Redis + DeathStarBench launch benchmarks (Fig 11)

### Medium-Term
5. ⬜ Set up second node (netperf, iperf3, mutilate, wrk2)
6. ⬜ Build networking hyperupcalls
7. ⬜ Networking benchmarks (Table 7, Fig 12, Fig 13)
8. ⬜ Build profiling hyperupcall
9. ⬜ Profiling benchmarks (Fig 9b, Fig 14)

---

## 7. L1 Reboot Checklist

```bash
# 1. From L0 — launch L1
cd /work/hyperturtle
sudo bash launch_l1.sh -i /work/hyperturtle/ubuntu-l1.qcow2 -c 12 -m 64

# 2. From L0 — pin vCPUs (after L1 is up)
sudo bash /work/hyperturtle/pin_vcpus.sh

# 3. From L1 — mount shared fs
sudo mount -t 9p -o trans=virtio hostshare /home/ubuntu/shared_folder -o version=9p2000.L

# 4. From L1 — restore containerd config
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml > /dev/null
sudo tee -a /etc/containerd/config.toml <<'EOF'

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  privileged_without_host_devices = true
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata.options]
    ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-clh.toml"
EOF
sudo systemctl restart containerd

# 5. Verify
cat /proc/cmdline  # should show idle=poll nopti
grep "enable_debug" /opt/kata/share/defaults/kata-containers/configuration-clh.toml  # should show false
time sudo ctr run --runtime io.containerd.kata.v2 --rm docker.io/library/alpine:latest verify echo "OK"

# 6. IMPORTANT: Never reload ept_fault.guest without restarting L1 QEMU first
```

---

## 8. Key Files

### L0
| Item | Path |
|---|---|
| HyperTurtle repo | /work/hyperturtle/ |
| Custom kernel | /work/hyperturtle/hyperturtle-linux/ |
| Custom QEMU | /work/hyperturtle/hyperturtle-qemu/build/qemu-system-x86_64 |
| CPU pinning | /work/hyperturtle/pin_vcpus.sh |
| L1 launch script | /work/hyperturtle/launch_l1.sh |
| L1 disk image | /work/hyperturtle/ubuntu-l1.qcow2 |
| eBPF source | /work/hyperturtle/hyperupcalls/ept_fault/ept_fault.bpf.c |
| MAPS_DEV_OFFSET fix | hyperturtle-linux/include/linux/kvm_host.h:96 |
| Zombie fix (KVM) | hyperturtle-linux/virt/kvm/kvm_main.c |

### L1
| Item | Path |
|---|---|
| Shared folder | /home/ubuntu/shared_folder/ |
| Kata config | /opt/kata/share/defaults/kata-containers/configuration-clh.toml |
| Benchmark script | /home/ubuntu/shared_folder/benchmarks/startup.sh |
| EPT fault bench | /home/ubuntu/shared_folder/benchmarks/ept_fault_bench |
| Results | /home/ubuntu/shared_folder/benchmarks/results/ |

### Benchmark Result Files
| File | Description |
|---|---|
| `startup_ht_off_20260326_114345.csv` | Baseline, idle=poll, 5 runs × 6 images |
| `startup_ht_on_20260326_113928.csv` | HT-on, idle=poll, 5 runs × 6 images |
| `startup_ht_off_20260326_103558.csv` | Baseline, no idle=poll, 10 runs × 6 images |
| `startup_ht_on_20260326_102636.csv` | HT-on, no idle=poll, 10 runs × 6 images |
| `ept_fault_latencies_l1_vm_1024MiB.csv` | L1 microbenchmark (5.52µs avg) |
| `ept_fault_latencies_l2_baseline_1024MiB.csv` | L2 baseline microbenchmark |
| `ept_fault_latencies_l2_ht_noprintk_1024MiB.csv` | L2+HT microbenchmark (28.43µs avg) |
| `startup_ht_off_20260326_092841.csv` | DEPRECATED — debug was ON |
| `startup_ht_on_20260326_100033.csv` | DEPRECATED — debug was ON |
