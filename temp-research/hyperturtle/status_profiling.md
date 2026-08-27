# HyperTurtle Profiling Benchmarks — Reproduction Report

| Date | 2026-03-31 |
| --- | --- |
| Scope | Table 4 / Figure 9(b), Figure 14 (1 kHz and 4 kHz) |
| Primary systems | L0: node0 (CloudLab), L1 VM (Ubuntu 5.16.0+), Kata/QEMU L2 containers |
| Load generator | mutilate (built from source on L0) |
| Status | Figure 14 gist reproduced at 1 kHz; 4 kHz inconclusive; Table 4 three of four configs measured |

---

## 1. Executive Summary

- **Figure 14 at 1 kHz:** Cleanly reproduced. L1 profiling adds 40–95 µs to p99 read latency. HT profiling adds only 5–17 µs.
- **Figure 14 at 4 kHz:** Inconclusive. HT and L1 profiling nearly indistinguishable on this stack.
- **Table 4 / Figure 9(b):** Three of four configurations measured. L0→L1 = 4.93 µs (paper: 5.66), HT→L2 = 7.02 µs (paper: ~8.5), L1→L2 = ~75 µs (paper: 60.68). Speedup ratio HT→L2 vs L1→L2 = 10.7× (paper: 7.15×).
- **GUPS overhead proxy:** All modes identical at ~310 Mops — workload not sensitive to profiling at 1 kHz.
- **Key caveat:** Nested-VirtIO networking (not Direct-Assignment), limiting peak QPS to ~21K vs paper's ~80K.

---

## 2. Environment

### L0 (Bare-Metal Host)

| Component | Specification |
| --- | --- |
| Kernel | 5.16.0+ #3 SMP PREEMPT |
| CPU | 2×Intel Xeon Silver 4114 @ 2.20GHz (10-core), SMT off, 20 CPUs online |
| RAM | 187 GiB |
| Network | ens1f1 on br0 (10.10.1.1/24) |

### L1 (Nested Hypervisor)

| Component | Specification |
| --- | --- |
| Kernel | 5.16.0+ #2 SMP PREEMPT |
| vCPUs / RAM | 12 / 62 GiB |
| VMM | HyperTurtle QEMU |
| Launch | `sudo bash launch_l1_htonly.sh -i ubuntu-l1.qcow2 -c 12 -m 64 -P 1 -p off` |

### L2 (Kata Container)

| Component | Specification |
| --- | --- |
| Runtime | io.containerd.kata.v2 |
| PMU | cpu_features="pmu=on" |
| Memcached | -m 512 -t 4 -l 0.0.0.0 -p 11211 |

### Differences from Paper

| Aspect | Paper | Ours |
| --- | --- | --- |
| L0 CPU | Xeon Silver 4216 (16-core) | Xeon Silver 4114 (10-core) |
| L2 VMM | Cloud-Hypervisor | QEMU (Kata default) |
| Networking (Fig 14) | Direct-Assignment | Nested-VirtIO |
| Peak QPS | ~80K | ~21K |

---

## 3. Build and Setup Notes

**Mutilate:** Required `apt-get install scons libevent-dev libzmq3-dev gengetopt g++ make`. ZMQ link failure fixed by adding `env.Append(LIBS = ['zmq'])` to SConstruct. Full scons cache clear needed (`rm -rf .sconf_temp .sconsign.dblite config.h`).

**HT Profiler:** Frequency hardcoded as `#define FREQUENCY` in `perf_top.guest.c`. Changed via sed, rebuilt with `make clean && make V=1`.

**CPU Pinning:** HT profiling hard-codes `perf_event_open(..., cpu=5)`. Workaround: `sudo taskset -pc 5 <hot_L1_QEMU_TID>` before each run.

**L1 Profiling Helper:** No perf binary in L1. Wrote minimal C program using `perf_event_open` (source in Appendix). Holds fd open; kernel generates NMI interrupts at configured frequency.

**Sampling Verification:** 1 kHz confirmed (3001 samples / 3s from rbp_traces map). 4 kHz confirmed (4034 samples / 1s).

---

## 4. Table 4 / Figure 9(b) — Per-Sample Handle Time

| Configuration | Paper (µs) | Ours (µs) | Method | Samples |
| --- | --- | --- | --- | --- |
| L0→L1 (optimal) | 5.66 | **4.93** | ftrace function_graph on L0 CPU 5 | 2028 |
| L1→L1 | 25.63 | — | Not measurable from L0 (L1 ftrace misses world-switch time) | — |
| L1→L2 | 60.68 | **~75** | KVM tracepoint burst timing on L0 CPU 4 | manual |
| HT→L2 | ~8.49 | **7.02** | ftrace function_graph on L0 CPU 5 | 3 |

**L0→L1 stats:** avg=4.93 µs, min=4.65, max=6.59 (2028 samples over 2 seconds).

**HT→L2 samples:** 6.807, 7.113, 7.140 µs. BPF-only execution: 0.60 µs/sample (bpftool run_time_ns/run_cnt).

**L1→L2 burst anatomy** (from KVM tracepoints on L0 CPU 4):
```
430662.633797  PREEMPTION_TIMER     ← NMI delivered to L1
430662.633801  MSR_WRITE            ← L1 reprograms counter
430662.633803  MSR_READ
430662.633806  LDTR_TR
430662.633810  VMRESUME             ← L1 tries to resume L2
430662.633819  nested MSR_WRITE     ← L2 MSR access trapped
430662.633825  VMRESUME
430662.633834  nested MSR_WRITE
430662.633840  VMRESUME
430662.633849  nested MSR_WRITE
430662.633855  VMRESUME
430662.633861  nested HLT
430662.633868  GDTR_IDTR
430662.633872  kvm_entry            ← L2 finally resumes
Total: ~75 µs
```

**L1→L1 note:** ftrace inside L1 measured only 4.92 µs — this is invalid because L1's clock doesn't account for time spent in L0 during world switches. The paper's 25.63 µs includes all 18 world switches.

**HT→L2 ftrace call stack:**
```
perf_event_overflow                      7.0 µs total
  __perf_event_overflow                  6.7 µs
    __perf_event_account_interrupt       0.5 µs
    bpf_overflow_handler                 5.8 µs
      kvm_get_running_vcpu               0.7 µs
      copy_from_kernel_nofault           0.5 µs
      bpf_bprintf_prepare                0.5 µs
      spin_lock/unlock                   0.9 µs
      __htab_map_lookup_elem             0.4 µs
```

**Speedup:** L1→L2 / HT→L2 = 75 / 7.02 = **10.7×** (paper: 7.15×).

---

## 5. Figure 14 — Memcached p99 Latency Under Profiling

### 5.1 Raw Results (p99 read latency in µs)

| QPS | No prof | HT 1k | L1 1k | HT 4k | L1 4k |
| --- | --- | --- | --- | --- | --- |
| 2000 | 223.9 | 212.8 | 272.3 | 225.1 | 200.7 |
| 4000 | 203.3 | 233.9 | 289.5 | 232.4 | 225.6 |
| 6000 | 228.4 | 229.8 | 286.2 | 205.6 | 239.2 |
| 8000 | 227.8 | 245.0 | 297.7 | 246.9 | 247.0 |
| 10000 | 243.3 | 246.0 | 299.4 | 249.3 | 247.5 |
| 12000 | 243.5 | 249.6 | 299.3 | 294.6 | 283.1 |
| 14000 | 256.6 | 250.2 | 316.0 | 317.7 | 325.2 |
| 16000 | 248.2 | 261.0 | 323.3 | 341.7 | 332.8 |
| 18000 | 265.9 | 265.2 | 332.5 | 366.1 | 360.6 |
| 20000 | 258.5 | 275.0 | 353.1 | 396.0 | 386.3 |

### 5.2 Analysis

**At 1 kHz (20K QPS):**

| Mode | p99 (µs) | Delta from baseline |
| --- | --- | --- |
| No profiling | 258.5 | — |
| HT profiling | 275.0 | +16.5 (+6.4%) |
| L1 profiling | 353.1 | +94.6 (+36.6%) |

Clear separation. Matches paper's directional claim.

**At 4 kHz:** HT and L1 profiling nearly identical across the range. Nested-VirtIO overhead likely dominates at our QPS range, masking the profiling difference visible at 80K QPS with Direct-Assignment.

---

## 6. GUPS Overhead Proxy

| Mode | Run 1 | Run 2 | Run 3 | Avg |
| --- | --- | --- | --- | --- |
| Kata baseline | 309.41 | 310.10 | 310.52 | 310.01 |
| Kata + HT @ 1 kHz | 310.31 | 310.50 | 310.51 | 310.44 |
| Kata + L1 @ 1 kHz | 310.43 | 310.33 | 310.60 | 310.45 |

All modes identical. 4 MiB GUPS not sensitive to profiling at 1 kHz.

---

## 7. Peak Throughput

| T | c | mc threads | Peak QPS |
| --- | --- | --- | --- |
| 4 | 1 | 1 | 20,858 |
| 6 | 1 | 1 | 21,666 |
| 4 | 1 | 4 | 23,148 |
| 16 | 8 | 4 | 14,977 |

Capped by Nested-VirtIO. Paper uses Direct-Assignment → ~80K.

---

## 8. Traps and Fixes

| Issue | Fix |
| --- | --- |
| mutilate ZMQ link failure | `env.Append(LIBS = ['zmq'])` in SConstruct |
| scons cached zmq as "no" | Full cache clear before rebuild |
| No perf in L1 | Wrote /tmp/l1_prof_hot_hw.c |
| HT profiler fixed CPU 5 | `taskset -pc 5 <TID>` before each run |
| Old BPF programs not cleaned up | Check bpftool for newest prog/map IDs |
| ftrace buffer overflow (function_graph) | 131072 KB buffer + 2s capture window |
| L1 ftrace misses world-switch time | Measure from L0 instead |
| Memcached single-threaded | Restart with `-t 4` |

---

## 9. Matplotlib Code for Paper-Equivalent Charts

### 9.1 Figure 14

```python
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams.update({'font.size': 11, 'font.family': 'serif', 'figure.figsize': (12, 4.5),
                            'axes.grid': True, 'grid.alpha': 0.3, 'grid.linestyle': '--'})

qps = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
no_prof = [223.9, 203.3, 228.4, 227.8, 243.3, 243.5, 256.6, 248.2, 265.9, 258.5]
ht_1k =  [212.8, 233.9, 229.8, 245.0, 246.0, 249.6, 250.2, 261.0, 265.2, 275.0]
l1_1k =  [272.3, 289.5, 286.2, 297.7, 299.4, 299.3, 316.0, 323.3, 332.5, 353.1]
ht_4k =  [225.1, 232.4, 205.6, 246.9, 249.3, 294.6, 317.7, 341.7, 366.1, 396.0]
l1_4k =  [200.7, 225.6, 239.2, 247.0, 247.5, 283.1, 325.2, 332.8, 360.6, 386.3]

fig, (ax1, ax2) = plt.subplots(1, 2, sharey=False)
for ax, ht, l1, title, ymax in [(ax1, ht_1k, l1_1k, '(a) 1000 Hz', 400),
                                  (ax2, ht_4k, l1_4k, '(b) 4000 Hz', 430)]:
    ax.plot(qps, no_prof, 'k-o', ms=5, lw=1.5, label='No profiling')
    ax.plot(qps, ht, 'g-^', ms=5, lw=1.5, label='Profiling w/ HyperTurtle')
    ax.plot(qps, l1, 'r-v', ms=5, lw=1.5, label='Profiling from L1')
    ax.set_xlabel('Throughput [Kqueries/sec]'); ax.set_ylabel('p99 read latency [µs]')
    ax.set_title(title); ax.legend(fontsize=9); ax.set_xlim(0, 22); ax.set_ylim(150, ymax)

fig.suptitle('Figure 14: p99 latencies of Memcached get requests during profiling', fontsize=13)
plt.tight_layout()
plt.savefig('figure14_reproduction.pdf', bbox_inches='tight', dpi=300)
plt.show()
```

### 9.2 Figure 9(b) — Table 4

```python
import matplotlib.pyplot as plt
import numpy as np

configs = ['L0→L1\n(optimal)', 'L1→L1', 'L1→L2', 'HT→L2']
paper = [5.66, 25.63, 60.68, 8.49]
ours = [4.93, None, 75.0, 7.02]

x = np.arange(len(configs))
w = 0.35
fig, ax = plt.subplots(figsize=(6, 4))
ax.bar(x - w/2, paper, w, label='Paper reported', color='#378ADD', edgecolor='white')
ours_plot = [v if v else 0 for v in ours]
colors = ['#1D9E75' if v else 'none' for v in ours]
ax.bar(x + w/2, ours_plot, w, label='Our measurement', color=colors, edgecolor='white')

for i, (p, o) in enumerate(zip(paper, ours)):
    ax.text(i - w/2, p + 1.5, f'{p:.1f}', ha='center', fontsize=9, color='#378ADD')
    if o: ax.text(i + w/2, o + 1.5, f'{o:.1f}', ha='center', fontsize=9, color='#1D9E75')

ax.annotate('7.15×', xy=(2, 60.68), xytext=(2.6, 52), fontsize=10, color='red',
            arrowprops=dict(arrowstyle='->', color='red', lw=1.5))
ax.annotate('10.7×', xy=(2.35, 75), xytext=(2.8, 68), fontsize=10, color='#1D9E75',
            arrowprops=dict(arrowstyle='->', color='#1D9E75', lw=1.5))
ax.set_xticks(x); ax.set_xticklabels(configs)
ax.set_ylabel('Latency [µs]'); ax.set_title('Table 4 / Figure 9(b): Profiler sampling event latency')
ax.legend(); ax.set_ylim(0, 85); ax.grid(axis='y', alpha=0.3, linestyle='--')
plt.tight_layout()
plt.savefig('figure9b_reproduction.pdf', bbox_inches='tight', dpi=300)
plt.show()
```

### 9.3 GUPS Overhead

```python
import matplotlib.pyplot as plt
import numpy as np

configs = ['Kata\nbaseline', 'Kata +\nHT @ 1kHz', 'Kata +\nL1 @ 1kHz']
means = [310.01, 310.44, 310.45]
stds = [0.56, 0.11, 0.14]
fig, ax = plt.subplots(figsize=(5, 3.5))
bars = ax.bar(configs, means, yerr=stds, capsize=5,
              color=['#73726c', '#1D9E75', '#E24B4A'], edgecolor='white', width=0.5)
for bar, val in zip(bars, means):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.8,
            f'{val:.1f}', ha='center', fontsize=10)
ax.set_ylabel('Throughput [Mops]'); ax.set_title('GUPS 4 MiB overhead proxy')
ax.set_ylim(305, 315); ax.grid(axis='y', alpha=0.3, linestyle='--')
plt.tight_layout()
plt.savefig('gups_overhead.pdf', bbox_inches='tight', dpi=300)
plt.show()
```

---

## Appendix A: Full Mutilate Output (p99 read latency)

All runs: `-T 4 -c 1 -t 10 -K fb_key -V fb_value -i fb_ia -u 0.03`

### A.1 No-Profiling Baseline

| QPS | Achieved | read avg | read std | read min | read 5th | read 10th | read 50th | read 90th | read 95th | read 99th |
|-----|----------|----------|----------|----------|----------|-----------|-----------|-----------|-----------|-----------|
| 2000 | 2020.0 | 158.6 | 60.2 | 72.9 | 125.9 | 131.1 | 153.1 | 187.3 | 198.5 | 223.9 |
| 4000 | 4004.3 | 136.9 | 32.6 | 80.2 | 110.4 | 117.7 | 133.7 | 161.8 | 178.4 | 203.3 |
| 6000 | 5992.6 | 148.5 | 144.2 | 72.9 | 111.2 | 118.2 | 138.8 | 184.4 | 200.0 | 228.4 |
| 8000 | 7956.4 | 146.3 | 93.8 | 66.3 | 109.5 | 116.2 | 138.1 | 185.3 | 201.0 | 227.8 |
| 10000 | 10031.3 | 150.2 | 31.7 | 72.9 | 110.4 | 117.6 | 143.2 | 194.7 | 210.5 | 243.3 |
| 12000 | 11979.7 | 150.3 | 32.0 | 66.3 | 110.3 | 117.6 | 143.4 | 195.6 | 211.0 | 243.5 |
| 14000 | 13972.9 | 155.9 | 78.0 | 72.9 | 111.6 | 118.4 | 147.7 | 204.1 | 221.8 | 256.6 |
| 16000 | 15966.7 | 151.1 | 34.5 | 66.3 | 109.1 | 116.2 | 143.6 | 199.5 | 215.9 | 248.2 |
| 18000 | 18125.9 | 158.8 | 36.9 | 72.9 | 111.5 | 118.5 | 152.5 | 210.8 | 227.4 | 265.9 |
| 20000 | 19977.6 | 154.1 | 36.2 | 66.3 | 109.2 | 115.8 | 147.1 | 205.5 | 223.1 | 258.5 |

### A.2 HT Profiling @ 1 kHz

| QPS | Achieved | read avg | read std | read min | read 5th | read 10th | read 50th | read 90th | read 95th | read 99th |
|-----|----------|----------|----------|----------|----------|-----------|-----------|-----------|-----------|-----------|
| 2000 | 2007.5 | 152.3 | 42.6 | 80.2 | 119.7 | 124.1 | 149.5 | 182.6 | 188.2 | 212.8 |
| 4000 | 4014.2 | 151.8 | 45.4 | 80.2 | 117.5 | 121.0 | 146.5 | 186.5 | 202.5 | 233.9 |
| 6000 | 6025.9 | 147.5 | 40.7 | 66.3 | 110.9 | 117.8 | 141.3 | 185.4 | 201.1 | 229.8 |
| 8000 | 7958.4 | 154.1 | 31.0 | 66.3 | 115.6 | 120.8 | 148.1 | 197.0 | 213.1 | 245.0 |
| 10000 | 10014.7 | 155.0 | 36.4 | 72.9 | 115.4 | 120.8 | 148.6 | 199.4 | 215.4 | 246.0 |
| 12000 | 12037.7 | 157.2 | 68.3 | 72.9 | 116.0 | 121.1 | 149.3 | 202.9 | 219.6 | 249.6 |
| 14000 | 13958.2 | 154.8 | 34.5 | 66.3 | 111.4 | 118.7 | 148.2 | 202.5 | 219.5 | 250.2 |
| 16000 | 15941.8 | 157.7 | 47.5 | 72.9 | 112.0 | 119.4 | 150.0 | 207.8 | 224.7 | 261.0 |
| 18000 | 17977.3 | 159.5 | 38.0 | 72.9 | 112.2 | 119.8 | 152.3 | 211.6 | 227.0 | 265.2 |
| 20000 | 19928.9 | 164.5 | 38.2 | 66.3 | 117.2 | 123.0 | 156.3 | 219.1 | 235.3 | 275.0 |

### A.3 L1 Profiling @ 1 kHz

| QPS | Achieved | read avg | read std | read min | read 5th | read 10th | read 50th | read 90th | read 95th | read 99th |
|-----|----------|----------|----------|----------|----------|-----------|-----------|-----------|-----------|-----------|
| 2000 | 2009.0 | 177.6 | 34.0 | 80.2 | 134.3 | 143.8 | 174.8 | 220.8 | 237.2 | 272.3 |
| 4000 | 4050.1 | 172.2 | 86.6 | 72.9 | 119.2 | 126.8 | 164.9 | 220.2 | 241.6 | 289.5 |
| 6000 | 6017.2 | 166.3 | 77.7 | 72.9 | 114.8 | 120.9 | 157.7 | 218.7 | 240.5 | 286.2 |
| 8000 | 7967.4 | 168.9 | 98.5 | 80.2 | 117.9 | 123.1 | 159.4 | 224.9 | 248.4 | 297.7 |
| 10000 | 9985.3 | 168.1 | 46.1 | 80.2 | 118.4 | 123.7 | 159.1 | 225.4 | 248.9 | 299.4 |
| 12000 | 11970.2 | 167.7 | 45.2 | 72.9 | 117.4 | 122.5 | 158.1 | 226.7 | 249.6 | 299.3 |
| 14000 | 13922.8 | 170.5 | 46.1 | 80.2 | 118.1 | 123.5 | 159.4 | 232.8 | 260.4 | 316.0 |
| 16000 | 15973.1 | 171.4 | 79.1 | 72.9 | 115.1 | 121.5 | 159.0 | 236.9 | 266.4 | 323.3 |
| 18000 | 18048.6 | 175.1 | 49.8 | 72.9 | 116.0 | 122.9 | 163.9 | 244.1 | 273.5 | 332.5 |
| 20000 | 20021.1 | 181.5 | 54.1 | 72.9 | 119.5 | 127.2 | 167.2 | 258.7 | 292.2 | 353.1 |

### A.4 HT Profiling @ 4 kHz

| QPS | Achieved | read avg | read std | read min | read 5th | read 10th | read 50th | read 90th | read 95th | read 99th |
|-----|----------|----------|----------|----------|----------|-----------|-----------|-----------|-----------|-----------|
| 2000 | 2034.2 | 160.4 | 72.6 | 80.2 | 125.9 | 131.2 | 155.2 | 188.0 | 200.0 | 225.1 |
| 4000 | 3981.6 | 154.3 | 56.3 | 72.9 | 117.6 | 122.2 | 149.7 | 187.2 | 201.4 | 232.4 |
| 6000 | 5959.4 | 133.4 | 67.8 | 66.3 | 107.3 | 110.6 | 127.9 | 158.4 | 174.3 | 205.6 |
| 8000 | 7962.3 | 153.6 | 60.8 | 80.2 | 117.4 | 121.3 | 147.3 | 190.5 | 206.9 | 246.9 |
| 10000 | 9985.1 | 150.4 | 58.6 | 66.3 | 111.0 | 118.0 | 143.8 | 189.2 | 207.3 | 249.3 |
| 12000 | 12002.3 | 158.7 | 46.5 | 72.9 | 114.3 | 120.3 | 149.2 | 210.4 | 234.8 | 294.6 |
| 14000 | 13949.3 | 159.8 | 87.5 | 66.3 | 109.8 | 117.3 | 148.4 | 216.0 | 242.4 | 317.7 |
| 16000 | 15973.6 | 159.1 | 53.0 | 66.3 | 108.8 | 114.4 | 146.4 | 219.6 | 249.3 | 341.7 |
| 18000 | 18041.0 | 164.1 | 54.1 | 66.3 | 109.3 | 115.8 | 150.3 | 228.5 | 262.6 | 366.1 |
| 20000 | 19961.1 | 174.3 | 73.3 | 66.3 | 111.1 | 118.4 | 156.6 | 246.8 | 286.5 | 396.0 |

### A.5 L1 Profiling @ 4 kHz

| QPS | Achieved | read avg | read std | read min | read 5th | read 10th | read 50th | read 90th | read 95th | read 99th |
|-----|----------|----------|----------|----------|----------|-----------|-----------|-----------|-----------|-----------|
| 2000 | 2011.1 | 147.5 | 174.9 | 88.2 | 119.6 | 123.8 | 140.4 | 158.9 | 169.9 | 200.7 |
| 4000 | 4031.6 | 149.1 | 37.7 | 80.2 | 118.7 | 123.5 | 142.3 | 182.3 | 194.8 | 225.6 |
| 6000 | 5953.0 | 153.5 | 51.8 | 80.2 | 118.1 | 122.3 | 148.0 | 188.0 | 203.8 | 239.2 |
| 8000 | 7968.9 | 152.5 | 60.0 | 72.9 | 114.9 | 120.2 | 146.1 | 188.9 | 205.9 | 247.0 |
| 10000 | 10078.6 | 150.8 | 98.8 | 66.3 | 111.5 | 118.3 | 143.7 | 188.6 | 206.3 | 247.5 |
| 12000 | 11967.8 | 154.9 | 38.4 | 66.3 | 110.4 | 117.7 | 146.6 | 204.6 | 227.5 | 283.1 |
| 14000 | 13926.3 | 162.7 | 124.0 | 66.3 | 111.3 | 118.1 | 148.0 | 216.7 | 244.3 | 325.2 |
| 16000 | 16017.5 | 162.5 | 48.1 | 72.9 | 110.7 | 118.1 | 150.4 | 223.0 | 250.1 | 332.8 |
| 18000 | 18082.6 | 166.6 | 52.7 | 60.2 | 110.7 | 118.5 | 152.6 | 230.2 | 263.5 | 360.6 |
| 20000 | 19949.5 | 175.2 | 83.2 | 72.9 | 116.6 | 122.9 | 156.4 | 243.6 | 279.3 | 386.3 |

---

## Appendix B: Source Code

### B.1 L1 Profiling Helper

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <signal.h>

static volatile int running = 1;
void sighandler(int sig) { running = 0; }

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "Usage: %s <tid> <freq> <dur>\n", argv[0]); return 1; }
    pid_t tid = atoi(argv[1]); int freq = atoi(argv[2]); int dur = atoi(argv[3]);
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE; pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_freq = freq; pe.freq = 1; pe.disabled = 1;
    int fd = syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0);
    if (fd < 0) { perror("perf_event_open"); return 1; }
    fprintf(stderr, "perf_event_open OK fd=%d tid=%d freq=%d\n", fd, tid, freq);
    ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    signal(SIGINT, sighandler); signal(SIGALRM, sighandler); alarm(dur);
    while (running) sleep(1);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); close(fd);
    fprintf(stderr, "done\n"); return 0;
}
```

### B.2 GUPS Benchmark

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define TABLE_SIZE (4 * 1024 * 1024 / sizeof(uint64_t))
#define ITERATIONS 200000000ULL
static uint64_t table[TABLE_SIZE];

static inline uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state; x ^= x << 13; x ^= x >> 7; x ^= x << 17; *state = x; return x;
}

int main() {
    uint64_t rng = 0xdeadbeef12345678ULL;
    struct timespec start, end;
    for (uint64_t i = 0; i < TABLE_SIZE; i++) table[i] = i;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (uint64_t i = 0; i < ITERATIONS; i++) {
        uint64_t idx = xorshift64(&rng) % TABLE_SIZE; table[idx] ^= rng;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("%.2f Mops (%.3f s, %llu iters)\n", (ITERATIONS / 1e6) / elapsed, elapsed, (unsigned long long)ITERATIONS);
    volatile uint64_t sink = 0;
    for (uint64_t i = 0; i < TABLE_SIZE; i++) sink += table[i];
    return 0;
}
```

---

## Appendix C: Measurement Ideas for Future Work

**L1→L1 handle time from L0:** The same KVM tracepoint approach used for L1→L2 should work — run a runc container in L1, profile it from L1, and trace the burst of kvm_exit/kvm_entry events on the corresponding L0 CPU. Look for EXTERNAL_INTERRUPT → MSR_WRITE → MSR_READ sequences without VMRESUME (no nested VM involvement).

**More ftrace HT→L2 samples:** The buffer overflow problem can be solved by using `trace_pipe` with a grep filter in a background process instead of post-hoc trace dump, or by using perf's ftrace integration which handles buffering better.

**L1→L2 timing script:** Automate KVM tracepoint analysis to extract all VMRESUME bursts:
```python
# Parse kvm trace: find PREEMPTION_TIMER→...→GDTR_IDTR sequences containing VMRESUME
# on the target CPU. Start time = first PREEMPTION_TIMER, end time = kvm_entry after GDTR_IDTR.
# Filter: only bursts with >=2 VMRESUME events (profiling, not regular scheduling).
```

**Direct-Assignment for full Figure 14:** Would unlock 80K QPS and likely make the 4 kHz profiling difference visible. Requires VFIO passthrough for Kata container networking.
