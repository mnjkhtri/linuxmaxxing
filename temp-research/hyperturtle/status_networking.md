# HyperTurtle Networking Reproduction Report

Date: 2026-03-29
Scope: full networking-focused reproduction journey from first bring-up through the latest benchmark results.

---

## 1. Executive summary

This report documents the full end-to-end reproduction/debugging session for the networking portion of the HyperTurtle paper on the current setup.

It includes:
- topology and environment mapping
- all important bring-up/fix commands
- all benchmark designs used
- all major bugs and traps encountered
- all measured data points produced during the session
- what reproduced cleanly, what only reproduced approximately, and what remained partial

### Final outcome in one page

We successfully reproduced the **gist** of the paper’s networking results on this setup:

1. **HyperTurtle network functions are real and runnable on this hardware/software stack.**
   We got `pass`, `rate_limiter`, `tcp_top`, and a patched `packet_filter` firewall all working.

2. The initial “HT looks bad” result was a **benchmark setup bug**, not a HyperTurtle failure.
   The old L1 boot path enabled guest IOMMU (`intel_iommu=on`) and caused DMAR faults even with no HT filter attached. Once that path was removed for HT-only benchmarking, plain virtio and HT became stable and fast.

3. We captured the **Figure 12a gist (NGINX)** with a large-file benchmark:
   Nested-VirtIO-ish throughput was much lower than plain HT, while HT + `rate_limiter` and HT + `tcp_top` stayed much closer to the plain HT path.

4. We captured the **Figure 13 gist (Memcached + Firewall)** with a throughput-vs-p99-latency sweep:
   HT + Firewall sustained much more throughput than Nested-VirtIO-ish + Firewall at roughly the same 500 µs tail-latency target.

5. We produced a **Table 7 proxy** (not exact paper-faithful Table 7) with the rows we could collect cleanly now:
   - Nested-VirtIO-ish throughput
   - HT + Pass
   - HT + Firewall

6. Redis (Figure 12b gist) was **much less sensitive** than large-file NGINX on this setup; all Redis rows were close.

The most important practical conclusion is:

> On this setup, HyperTurtle’s networking path with useful eBPF/hyperupcalls can remain close to the good path and clearly outperform a weaker nested baseline on the workloads that are actually network-sensitive (large-file NGINX and Memcached under a latency SLA).

---

## 2. Environment and topology

### 2.1 Machine roles

- **L0**: outer host (`root@node0`) running QEMU and owning host tap devices
- **L1**: nested Ubuntu guest (`root@ubuntu`) where guest loaders and most HyperTurtle userland were run

### 2.2 Important filesystem roots

- L0 repo root: `/work/hyperturtle`
- L0 QEMU wrapper area: `/work/hyperturtle/hyperturtle-qemu`
- L1 shared mount: `/home/ubuntu/shared_folder`
- Hyperupcall header on L1: `/home/ubuntu/shared_folder/hyperupcall.h`
- Hyperupcalls on L1: `/home/ubuntu/shared_folder/hyperupcalls/network/...`

### 2.3 Interface / path mapping discovered

The benchmark datapath used throughout the successful part of the session was:

- **L0 `br0`**: `10.10.1.1/24`
- **L0 `tap1`**: bridge slave on `br0`
- **L1 `enp1s0f0`**: `10.10.1.2/24`
- MAC of benchmark NIC: `52:54:00:12:34:57`

Other interfaces existed, but the benchmark path we settled on was:

`L1 enp1s0f0 <-> L0 tap1 <-> L0 br0`

### 2.4 QEMU netdev mapping actually used

From QEMU + guest inspection, the key mapping was:

| QEMU netdev | L0 host device | L1 MAC | L1 interface |
|---|---|---|---|
| `net1` | `tap1` | `52:54:00:12:34:57` | `enp1s0f0` |

This mattered because HyperTurtle uses the **guest netdev index**, not the Linux ifindex.

---

## 3. Critical conceptual finding: HyperTurtle uses guest netdev index, not Linux ifindex

We initially treated `NETDEV_IFINDEX` as if it should match the Linux ifindex inside L1. That was wrong.

The underlying QEMU code path resolves a **QEMU netdev index** via `qemu_find_netdev_via_index()`. That means the right value for the benchmark NIC was:

- **guest netdev index = 1**

not Linux ifindex `5`.

### Fix applied in shared header

We updated the shared header to effectively use:

```c
#define NETDEV_IFINDEX 1
#define NETDEV_INDEX NETDEV_IFINDEX
```

### Effect

This fixed the initial “link to wrong interface/backend” confusion and allowed later successful `pass`/`tcp_top`/firewall attachments.

---

## 4. Source/build issues and fixes

### 4.1 Missing kernel header path for BPF builds

Initial BPF builds failed with a missing `asm/types.h` path.

### Working compile form

```bash
clang-12 -x c -g -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c <prog>.bpf.c -o <prog>.bpf.o
```

This became the standard BPF compile line used later.

---

### 4.2 `pass` Makefile / build path was incomplete

We manually built the `pass` family with:

```bash
gcc -g -O2 pass.guest.c ../../hyperupcall.c ../../hyperupcall.h -o pass.guest
gcc -g -O2 -DHYPERUPCALL_USE_TC_EGRESS pass.guest.c ../../hyperupcall.c ../../hyperupcall.h -o pass_tc_egress.guest
gcc -g -O2 -DHYPERUPCALL_USE_TC_INGRESS pass.guest.c ../../hyperupcall.c ../../hyperupcall.h -o pass_tc_ingress.guest
clang-12 -g -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c pass.bpf.c -o pass.bpf.o
```

---

### 4.3 `tcp_top` build failure: bad include path

`tcptop.bpf.c` originally contained:

```c
#include "../../packet.h"
```

But the actual header in this tree was:

- `/home/ubuntu/shared_folder/hyperupcalls/network/packet.h`

From `tcp_top/`, the correct relative path was:

```c
#include "../packet.h"
```

### Fix applied

Patched include:

```c
#include "../packet.h"
```

Then rebuilt successfully:

```bash
clang-12 -x c -g -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c tcptop.bpf.c -o tcptop.bpf.o
gcc -g -O2 tcptop.guest.c ../../../hyperupcall.c ../../../hyperupcall.h ./tcptop.h -o tcptop.guest
```

---

### 4.4 Original firewall sources were broken

The repo snapshot’s firewall path under:

- `/home/ubuntu/shared_folder/hyperupcalls/network/packet_filter`

was not runnable as-is.

Problems:
- `packet_filter.bpf.c` had incompatible assumptions / type issues
- `packet_counter.guest.c` was syntactically and semantically broken

### Firewall replacement strategy used

We replaced it with a minimal stateless XDP firewall and a clean guest loader.

The first patched firewall allowed:
- ARP
- ICMP
- TCP/UDP traffic where source or destination port was `11211`
- everything else dropped

Later, for Table 7 proxy microbenchmarks, we created a **microbench firewall variant** that allowed:
- `11211`
- `5201`
- `12865`
- `5202`
- `12866`

and eventually widened **UDP** to all ports because `netperf UDP_RR` negotiated additional data sockets/ports.

---

## 5. Runtime traps and the fixes that mattered

### 5.1 Stale `clsact` qdisc blocked TC attach

This hit both `pass` and `tcp_top`.

Symptom:
- Hypercall load succeeded
- TC link failed
- libbpf complained about exclusivity / hook creation

Inspection on L0 often showed an empty but present `clsact` qdisc on `tap1`.

### Fix

On L0:

```bash
sudo tc qdisc del dev tap1 clsact 2>/dev/null || true
```

This was required repeatedly before retrying TC-based attachments.

---

### 5.2 Orphaned XDP links prevented later XDP attaches

This occurred when `tcp_top` had attached an XDP program (`tcptop_br`) and the owner process was gone but the link was still active.

Symptoms:
- `rate_limiter` attach failed with
  `failed to attach to xdp: Device or resource busy`
- `ip link set dev tap1 xdp off` failed with
  `Can't replace active BPF XDP link`

### Fix

The eventual cleanup path was:
- stop the owning guest process if still alive
- if an orphan remained, use the HyperTurtle side cleanup to remove the program slot/unload the hyperupcall
- verify on L0 with:

```bash
sudo bpftool net show
ip -d link show dev tap1
```

Only after `prog/xdp` disappeared was the next XDP attach safe.

---

### 5.3 The biggest trap: wrong L1 boot profile (`intel_iommu=on`) poisoned the benchmark baseline

This was the single most important finding in the session.

On the original `-k` boot path, the L1 guest cmdline included guest-IOMMU-related arguments such as:
- `intel_iommu=on`
- related vIOMMU usage on the virtio NIC path

This led to repeated DMAR faults such as:

```text
DMAR: [DMA Write NO_PASID] Request device [01:00.0] fault addr 0x0 / 0x1000 [fault reason 0x05] PTE Write access is not set
```

Crucially, these faults happened:
- with HT attached
- **and with no HT attached**

So the issue was not HyperTurtle.

### Fix

We switched to a **clean HT-only boot** with no guest IOMMU for the virtio benchmark path.

After that:
- plain virtio became fast and stable
- HT networking experiments became interpretable
- DMAR faults disappeared in the clean runs

This invalidated all early throughput/latency conclusions taken from the broken boot.

---

## 6. Direct-Assignment (Kata + VFIO) bring-up

This path was brought up partially and is documented here because it consumed substantial debugging effort.

### 6.1 Rebind `01:00.0` to `vfio-pci` inside L1

Commands used:

```bash
sudo modprobe vfio
sudo modprobe vfio_iommu_type1
sudo modprobe vfio_pci
ip link set dev enp1s0f0 down 2>/dev/null || true
echo vfio-pci | sudo tee /sys/bus/pci/devices/0000:01:00.0/driver_override
echo 0000:01:00.0 | sudo tee /sys/bus/pci/devices/0000:01:00.0/driver/unbind
echo 0000:01:00.0 | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
```

Validation used:

```bash
lspci -nnk -s 01:00.0
readlink -f /sys/bus/pci/devices/0000:01:00.0/driver
ls -l /dev/vfio
ls -l /dev/vfio/18
```

Observed result:
- `Kernel driver in use: vfio-pci`
- `/dev/vfio/18` present

---

### 6.2 First Kata VFIO launch failure

Attempted launch:

```bash
docker run -d --name ht-vfio-test \
  --runtime io.containerd.kata.v2 \
  --device /dev/vfio/18 \
  --network none \
  --cap-add NET_ADMIN \
  launch_bash_ubuntu:latest sh -c 'sleep infinity'
```

Failure:

```text
cold_plug_vfio= or hot_plug_vfio= port is not set for device 0000:01:00.0 (BridgePort | RootPort | SwitchPort)
```

Cause:
- default Kata runtime path was using Cloud Hypervisor config, not a QEMU VFIO-capable config

---

### 6.3 Kata runtime reconfiguration for VFIO

We copied and edited a QEMU config:

```bash
sudo mkdir -p /etc/kata-containers
sudo cp -a /opt/kata/share/defaults/kata-containers/configuration-qemu.toml /etc/kata-containers/configuration-qemu.toml
```

Enabled/edited:
- `enable_iommu = true`
- `enable_iommu_platform = true`
- `hot_plug_vfio = "root-port"`
- `cold_plug_vfio = "root-port"` initially (later this turned out to be too much in some cases)

Repointed Docker/containerd config paths to the new file and restarted:

```bash
sudo systemctl restart containerd
sudo systemctl restart docker
```

---

### 6.4 Minimal DA Kata container eventually ran

A working DA-ish container was eventually launched and the passed-through NIC appeared inside as `eth0`.

Because the image was very minimal, we had to **stage host binaries and shared libraries into the container** to do basic networking and benchmarking.

#### Staged into container as needed
- `ip`
- `netperf`
- `iperf3`

The general pattern used was:
1. copy the host binary
2. copy all `ldd`-reported libs
3. copy the dynamic loader
4. `docker cp` the tree into the container under `/tmp/...`
5. execute with the loader, e.g.

```bash
$LD --library-path "$LIBS" "$IP" link set dev eth0 up
```

#### DA container IP configuration used

```bash
$LD --library-path "$LIBS" "$IP" link set dev eth0 up
$LD --library-path "$LIBS" "$IP" addr add 10.10.1.2/24 dev eth0
```

Validation:
- L1 host ping to `10.10.1.2` inside the DA container succeeded

---

### 6.5 Early DA throughput datapoint

A successful DA `iperf3` run from the DA Kata/VFIO container to L0 produced:

- sender: **4.57 Gbit/s**
- receiver: **4.54 Gbit/s**

Raw output from the successful validated run:

```text
[  5]   0.00-5.00   sec  2.66 GBytes  4.57 Gbits/sec    0             sender
[  5]   0.00-5.04   sec  2.66 GBytes  4.54 Gbits/sec                  receiver
```

This was enough to show the path worked, but DA was not carried forward as the primary next result because:
- it was config-fragile
- it was not yet apples-to-apples with the later clean HT-only experiments
- the paper’s gist could be demonstrated without DA

---

## 7. Early broken-boot datapoints (kept for forensic record, not final comparison)

These runs are important because they explained why the first numbers looked wrong.

### 7.1 HT + Pass under the wrong boot (IOMMU/DMAR present)

Measured:
- forward `iperf3`: **1.79 Gbit/s**
- reverse `iperf3`: **645–646 Mbit/s** with thousands of retransmits

Example reverse run:

```text
0.00-5.00 sec 385 MBytes 646 Mbits/sec 2757 retr (sender)
```

### 7.2 No-HT plain virtio under the same wrong boot

Measured:
- reverse `iperf3`: **655 Mbit/s** with retransmits
- forward `iperf3`: **1.69 Gbit/s**
- ping burst worked and produced **no DMAR faults**, but throughput traffic did

### 7.3 Interpretation

These numbers were **not HT overhead**. They were a benchmark-environment failure caused by guest IOMMU / DMAR faults on the virtio path.

They are kept here only to explain the debugging journey.

---

## 8. Clean HT-only boot validation

The validated clean HT-only boot showed:

```text
cmdline: root=/dev/vda1 rw nokaslr norandmaps console=ttyS0 ... mitigations=off nopti idle=poll isolcpus=1-2
```

Important points:
- benchmark NIC on L1: `enp1s0f0`
- benchmark IP restored as `10.10.1.2/24`
- no DMAR faults during the clean HT-only throughput checks

This became the base for all later valid HT networking experiments.

---

## 9. Clean HT-only microbenchmarks

### 9.1 Plain virtio / no hyperupcall (5-run baseline from early clean HT-only phase)

#### Throughput

Forward runs (Gb/s):
- 18.8
- 22.6
- 22.6
- 22.4
- 22.6

Average forward:
- **21.80 Gbit/s**

Reverse runs (Gb/s):
- 17.4
- 17.7
- 18.3
- 17.1
- 18.1

Average reverse:
- **17.72 Gbit/s**

#### UDP_RR

Rates (transactions/sec):
- 16392.62
- 16665.47
- 16405.11
- 16691.80
- 16493.12

Average rate:
- **16529.62 trans/sec**

Average RTT proxy:
- **60.50 µs**

---

### 9.2 Plain virtio / no hyperupcall (later clean-boot revalidation after reboot)

Single validated forward and reverse runs later in the session produced:

- forward: **19.3 Gbit/s**
- reverse: **23.3 Gbit/s**

and no DMAR faults after either run.

These later runs were used mainly as a revalidation that the clean boot remained healthy.

---

### 9.3 HT + Pass (5-run baseline)

#### Throughput

Forward runs (Gb/s):
- 21.1
- 18.8
- 19.4
- 18.9
- 18.6

Average forward:
- **19.36 Gbit/s**

Reverse runs (Gb/s):
- 15.8
- 18.2
- 17.4
- 14.9
- 15.9

Average reverse:
- **16.44 Gbit/s**

#### UDP_RR raw rates

Rates (transactions/sec):
- 16892.31
- 16302.10
- 16844.70
- 16406.42
- 16588.37

Average rate:
- **16606.78 trans/sec**

Average RTT proxy:
- **60.22 µs**

---

### 9.4 HT + Pass (later clean-boot revalidation)

Later single validated runs produced:

- forward: **18.2 Gbit/s**
- reverse: **20.6 Gbit/s**

Again, no DMAR faults were seen after those runs.

---

## 10. `tcp_top` bring-up and results

### 10.1 Attach behavior

After the include-path fix and `clsact` cleanup, `tcp_top` attached successfully as:

- XDP: `tcptop_br`
- TC egress: `tcptop_int`

Observed on L0:

```text
xdp:
  tap1(6) driver id 307

tc:
  tap1(6) clsact/egress tcptop_int:[306] id 306
```

### 10.2 Smoke throughput

Single smoke runs produced:
- forward: **19.5 Gbit/s**
- reverse: **18.0 Gbit/s**

### 10.3 5-run baseline captured later

Forward runs (Gb/s):
- 19.3
- 15.2
- 15.0
- 17.9
- 14.1

Average forward:
- **16.30 Gbit/s**

Reverse runs (Gb/s):
- 14.5
- 17.1
- 18.5
- 17.9
- 18.3

Average reverse:
- **17.26 Gbit/s**

Interpretation:
- `tcp_top` is stable and clearly runnable
- it introduces some throughput cost versus plain HT, but remained much healthier than the broken-boot results and close enough for app-level evaluation

---

## 11. `rate_limiter` bring-up and microbench results

### 11.1 Attach status

`rate_limiter.guest` attached successfully as an XDP program on `tap1`.

### 11.2 Smoke throughput

Single validated smoke runs produced:
- forward: **15.0 Gbit/s**
- reverse: **20.3 Gbit/s**

Interpretation:
- `rate_limiter` is measurably heavier than `pass`
- still stable, usable, and appropriate for app-level tests

---

## 12. First application benchmark attempt: tiny-response NGINX (not sensitive enough)

We first used a simple NGINX response body (`hello from nginx\n`) and a Python multi-threaded HTTP driver.

### Small-response NGINX results

| mode | req/s | avg ms | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| plain HT | 2566.51 | 12.448 | 11.994 | 19.647 | 23.634 |
| HT + rate_limiter | 2600.82 | 12.284 | 11.832 | 19.391 | 23.454 |
| HT + tcp_top | 2535.04 | 12.599 | 12.136 | 19.888 | 23.962 |
| Nested-VirtIO-ish | 2603.99 | 12.265 | 11.823 | 19.367 | 23.173 |

### Interpretation

This benchmark did **not** expose the paper’s win because the response was too small and the workload was dominated by request machinery rather than datapath throughput.

This was a useful trap to document:

> tiny-response app benchmarks were too insensitive on this setup.

---

## 13. Figure 12a gist: large-file NGINX benchmark

To make the network path matter, we switched NGINX to serve a **64 MiB static file** and used the same Python HTTP driver.

### Server setup used

#### Plain HT NGINX on L1 host network (`8080`)

Server config pattern:

```nginx
server {
  listen 10.10.1.2:8080 default_server;
  location = /healthz { return 200 "ok\n"; add_header Content-Type text/plain; }
  location / { root /var/www/html; }
}
```

Large file generated with:

```bash
dd if=/dev/zero of=/var/www/html/large.bin bs=1M count=64 status=none
```

#### Nested-VirtIO-ish Kata NGINX on `8081`

Server config pattern:

```nginx
server {
  listen 0.0.0.0:8080 default_server;
  location = /healthz { return 200 "ok\n"; add_header Content-Type text/plain; }
  location / { root /var/www/html; }
}
```

published with Docker/Kata port proxy:
- host `10.10.1.2:8081` -> container `:8080`

### Large-file driver used on L0

Python script saved as `/tmp/nginx_large_bench.py`, using:
- configurable URL
- configurable duration (used: 20s)
- configurable threads (used: 16)
- full body reads to completion
- outputs req/s, MiB/s, avg/p50/p95/p99 latency

### Large-file NGINX results

| mode | req/s | MiB/s | avg ms | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| Nested-VirtIO-ish | 15.64 | 1000.75 | 1019.622 | — | 1253.332 | 1369.686 |
| plain HT | 28.32 | 1812.38 | 561.055 | 480.610 | 1062.037 | 1239.394 |
| HT + rate_limiter | 25.65 | 1641.41 | 618.773 | 539.698 | 1120.911 | 1317.113 |
| HT + tcp_top | 26.66 | 1706.01 | 596.535 | 504.239 | 1141.350 | 1323.563 |

### Interpretation

This benchmark finally exposed the intended separation:

- plain HT was about **1.81x** faster than Nested-VirtIO-ish
- HT + `rate_limiter` was about **1.64x** faster than Nested-VirtIO-ish
- HT + `tcp_top` was about **1.70x** faster than Nested-VirtIO-ish

This captured the **Figure 12a gist** much better than the earlier tiny-response NGINX test.

---

## 14. Figure 13 gist: Memcached throughput vs p99 latency under a firewall

This became the strongest networking result we reproduced.

### 14.1 Patched firewall used for Memcached

Patched XDP firewall behavior:
- allow ARP
- allow ICMP
- allow TCP/UDP with source or destination port `11211`
- drop everything else

Smoke validation on L0:
- `ping 10.10.1.2` worked
- `curl http://10.10.1.2:8080/healthz` timed out / was blocked
- Memcached traffic on `11211` worked

### 14.2 Memcached setup used

Plain HT memcached container on L1 host network:

```bash
memcached -u root -m 512 -l 10.10.1.2 -p 11211 -v
```

Nested-VirtIO-ish memcached container via Kata:
- container listens on `0.0.0.0:11211`
- published as host `10.10.1.2:11211`

### 14.3 Memcached benchmark driver used on L0

Python script `/tmp/memcached_sweep.py`:
- pre-populates key `foo -> bar`
- repeatedly issues `get foo`
- sweep over thread counts:
  - 1, 2, 4, 8, 12, 16, 24, 32, 40, 48, 64
- fixed duration: 15 s per point
- records ops/s and avg/p50/p95/p99 latency

### 14.4 HT + Firewall sweep

| threads | ops/s | avg ms | p95 ms | p99 ms |
|---:|---:|---:|---:|---:|
| 1 | 12727.99 | 0.078 | 0.087 | 0.095 |
| 2 | 22861.44 | 0.085 | 0.111 | 0.121 |
| 4 | 38572.56 | 0.102 | 0.138 | 0.163 |
| 8 | 38072.11 | 0.208 | 0.343 | 0.460 |
| 12 | 43225.67 | 0.276 | 0.478 | 0.612 |
| 16 | 42228.93 | 0.377 | 0.706 | 0.932 |
| 24 | 40836.96 | 0.586 | 1.175 | 1.565 |
| 32 | 36671.60 | 0.870 | 1.714 | 2.309 |
| 40 | 40971.41 | 0.974 | 1.968 | 2.646 |
| 48 | 36754.57 | 1.302 | 2.587 | 3.504 |
| 64 | 36897.89 | 1.730 | 3.450 | 4.683 |

Best point under **0.5 ms p99**:
- **8 threads**
- **38072.11 ops/s**
- **0.460 ms p99**

---

### 14.5 plain HT / no-firewall sweep

| threads | ops/s | avg ms | p95 ms | p99 ms |
|---:|---:|---:|---:|---:|
| 1 | 11354.11 | 0.087 | 0.098 | 0.101 |
| 2 | 25799.89 | 0.076 | 0.090 | 0.102 |
| 4 | 39046.39 | 0.101 | 0.137 | 0.163 |
| 8 | 37449.30 | 0.212 | 0.347 | 0.464 |
| 12 | 38283.02 | 0.312 | 0.566 | 0.757 |
| 16 | 41096.42 | 0.387 | 0.734 | 0.969 |
| 24 | 41801.63 | 0.572 | 1.146 | 1.525 |
| 32 | 36270.05 | 0.879 | 1.739 | 2.340 |
| 40 | 36177.48 | 1.102 | 2.180 | 2.941 |
| 48 | 36404.76 | 1.315 | 2.615 | 3.542 |
| 64 | 36792.13 | 1.735 | 3.467 | 4.706 |

Best point under **0.5 ms p99**:
- **8 threads**
- **37449.30 ops/s**
- **0.464 ms p99**

Interpretation:
- HT + Firewall was essentially the same as the plain HT upper bound at the SLA point on this setup
- this means the firewall itself was cheap enough not to dominate performance

---

### 14.6 Nested-VirtIO-ish + Firewall sweep

To get this lower comparison curve, we:
- kept the patched outer firewall attached on `tap1`
- moved Memcached into the Nested-VirtIO-ish Kata container path
- published `10.10.1.2:11211`

Sweep results:

| threads | ops/s | avg ms | p95 ms | p99 ms |
|---:|---:|---:|---:|---:|
| 1 | 7769.88 | 0.128 | 0.149 | 0.178 |
| 2 | 15567.25 | 0.127 | 0.159 | 0.197 |
| 4 | 25304.36 | 0.156 | 0.224 | 0.273 |
| 8 | 30245.84 | 0.263 | 0.402 | 0.504 |
| 12 | 30776.63 | 0.388 | 0.605 | 0.747 |
| 16 | 28758.61 | 0.554 | 1.755 | 2.771 |
| 24 | 27570.99 | 0.869 | 3.637 | 3.863 |
| 32 | 28154.89 | 1.134 | 3.749 | 4.605 |
| 40 | 27337.95 | 1.461 | 3.926 | 4.808 |
| 48 | 27905.86 | 1.716 | 4.033 | 4.842 |
| 64 | 33196.98 | 1.924 | 4.093 | 5.065 |

Strictly under **0.5 ms p99**:
- **4 threads**
- **25304.36 ops/s**
- **0.273 ms p99**

Nearest knee / near-500 µs point:
- **8 threads**
- **30245.84 ops/s**
- **0.504 ms p99**

### 14.7 Figure 13 gist conclusion

At the 500 µs-style operating point:
- **HT + Firewall**: ~**38.1 Kops/s**
- **Nested-VirtIO-ish + Firewall**: ~**25.3 Kops/s** strictly under SLA, or ~**30.2 Kops/s** at the nearest knee

So on this setup:
- HT + Firewall delivered about **50% more throughput** than Nested-VirtIO-ish + Firewall under a strict-under-SLA reading
- or about **26% more throughput** using the nearest-knee comparison

This reproduced the **ranking and intent** of Figure 13 cleanly.

---

## 15. Table 7 proxy reproduction

We did **not** fully reproduce the paper’s Table 7 exactly. Instead, we built the strongest proxy we could on this setup without re-opening the fragile DA path.

### 15.1 What Table 7 requires in the paper

Paper rows:
- Nested-VirtIO
- Direct-Assignment
- HyperTurtle + Pass
- HyperTurtle + Firewall

Metrics:
- average latency
- 99p latency
- throughput

### 15.2 Why the nested latency row became `NA`

For the Nested-VirtIO-ish Kata container path, `iperf3` published cleanly via Docker/Kata port mapping, but `netperf UDP_RR` did not. The reason is structural:
- `netperf/netserver` uses a control socket and a separate negotiated data socket
- publishing only a single port through the Docker/Kata proxy path was insufficient

So for the nested row we recorded throughput but left latency as `NA`.

### 15.3 Another parser trap we fixed

Early in the session, the quick netperf parser accidentally read the trailing socket-size line (`212992 212992`) instead of the transaction-rate line, producing an obviously wrong derived latency of about `4.70 µs`.

We corrected this later and used the visible transaction rate lines directly.

### 15.4 Nested-VirtIO-ish throughput row

Throughput runs (Gb/s):
- 9.730
- 11.300
- 10.800

Average:
- **10.610 Gbit/s**

Latency:
- **NA**

### 15.5 HT + Pass row

Throughput runs (Gb/s):
- 19.500
- 19.300
- 19.400

Average throughput:
- **19.400 Gbit/s**

UDP_RR transaction rates:
- 16745.61
- 16763.96
- 16600.31

Average rate:
- **16703.29 trans/sec**

Average RTT proxy:
- **59.87 µs**

99p:
- **NA**

### 15.6 HT + Firewall row

For the Table 7 microbench firewall variant, we first allowed only fixed ports, which caused `netperf UDP_RR` to fail because the negotiated UDP data path used additional ports. We then widened the variant to **allow all UDP** temporarily while still preserving the intended TCP filtering for the microbench service ports.

Throughput runs (Gb/s):
- 18.0
- 17.7
- 20.5

Average throughput:
- **18.73 Gbit/s**

UDP_RR transaction rates:
- 16698.62
- 16754.60
- 16715.83

Average rate:
- **16723.02 trans/sec**

Average RTT proxy:
- **59.80 µs**

99p:
- **NA**

### 15.7 Table 7 proxy summary

| row | throughput (Gb/s) | avg latency proxy (µs) | p99 |
|---|---:|---:|---:|
| Nested-VirtIO-ish | 10.61 | NA | NA |
| HT + Pass | 19.40 | 59.87 | NA |
| HT + Firewall | 18.73 | 59.80 | NA |

### Interpretation

This proxy captured the **ranking/gist** of Table 7:
- HT + Pass and HT + Firewall were both about **1.8x** faster than Nested-VirtIO-ish in throughput
- their average latency proxies were nearly identical (~60 µs)

What remained missing from a full exact Table 7:
- Direct-Assignment row
- true 99p latency
- a clean nested latency row

---

## 16. Figure 12b gist: Redis throughput

### 16.1 Server setup

Plain HT Redis on L1 host network:

```bash
redis-server --bind 10.10.1.2 --port 6379 --protected-mode no --save "" --appendonly no
```

Nested-VirtIO-ish Redis on Kata:
- container binds `0.0.0.0:6379`
- published as host `10.10.1.2:6380`
- protected mode disabled to permit non-loopback access

### 16.2 Important trap: Redis protected mode

Initial Redis runs failed with:
- `DENIED Redis is running in protected mode ...`

We fixed this by recreating both Redis servers with:

```bash
--protected-mode no
```

### 16.3 Redis benchmark design

Driver: `/tmp/redis_bench.py`

Design:
- key: `blob`
- value size: **64 KiB**
- prep phase: `SET blob <64KiB>`
- benchmark phase: repeated `GET blob`
- duration: **20 s**
- threads: **32**
- metrics: ops/s, MiB/s, avg/p50/p95/p99 latency

### 16.4 Redis results

| mode | ops/s | MiB/s | avg ms | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| Nested-VirtIO-ish | 6981.08 | 436.32 | 4.579 | — | 6.895 | 8.392 |
| plain HT | 7090.24 | 443.14 | 4.508 | — | 6.849 | 8.168 |
| HT + rate_limiter | 7135.73 | 445.98 | 4.479 | — | 6.768 | 8.112 |
| HT + tcp_top | 7143.80 | 446.49 | 4.474 | — | 6.770 | 8.037 |

### Interpretation

Redis on this setup was **not** nearly as sensitive as large-file NGINX.

All four rows were close, so the Redis workload did **not** expose a large nested penalty here.

This is still an important negative result:

> the paper’s “big app gain” was workload-sensitive on this stack; it showed clearly in large-file NGINX and Memcached, but not in this Redis GET benchmark.

---

## 17. Final comparison tables

### 17.1 Clean HT-only microbench summary

| mode | fwd Gb/s | rev Gb/s | avg RTT proxy (µs) |
|---|---:|---:|---:|
| plain HT (5-run baseline) | 21.80 | 17.72 | 60.50 |
| HT + Pass (5-run baseline) | 19.36 | 16.44 | 60.22 |
| HT + tcp_top (5-run baseline) | 16.30 | 17.26 | — |
| HT + rate_limiter (smoke) | 15.0 | 20.3 | — |

---

### 17.2 Large-file NGINX summary

| mode | req/s | MiB/s | avg ms | p99 ms |
|---|---:|---:|---:|---:|
| Nested-VirtIO-ish | 15.64 | 1000.75 | 1019.62 | 1369.69 |
| plain HT | 28.32 | 1812.38 | 561.06 | 1239.39 |
| HT + rate_limiter | 25.65 | 1641.41 | 618.77 | 1317.11 |
| HT + tcp_top | 26.66 | 1706.01 | 596.54 | 1323.56 |

Key ratios:
- plain HT vs Nested-VirtIO-ish: **1.81x throughput**
- HT + rate_limiter vs Nested-VirtIO-ish: **1.64x throughput**
- HT + tcp_top vs Nested-VirtIO-ish: **1.70x throughput**

---

### 17.3 Memcached @ 500 µs-style comparison

| mode | best throughput near/under 0.5 ms p99 |
|---|---:|
| HT + Firewall | 38.07 Kops/s @ 0.460 ms p99 |
| plain HT / no firewall | 37.45 Kops/s @ 0.464 ms p99 |
| Nested-VirtIO-ish + Firewall | 25.30 Kops/s strict-under-SLA, or 30.25 Kops/s at 0.504 ms |

Interpretation:
- HT + Firewall was essentially equal to the plain HT upper bound on this setup
- HT + Firewall clearly beat the Nested-VirtIO-ish + Firewall lower baseline

---

### 17.4 Table 7 proxy summary

| row | throughput (Gb/s) | avg latency proxy (µs) | p99 |
|---|---:|---:|---:|
| Nested-VirtIO-ish | 10.61 | NA | NA |
| HT + Pass | 19.40 | 59.87 | NA |
| HT + Firewall | 18.73 | 59.80 | NA |

---

### 17.5 Redis summary

| mode | ops/s | MiB/s | avg ms | p99 ms |
|---|---:|---:|---:|---:|
| Nested-VirtIO-ish | 6981.08 | 436.32 | 4.579 | 8.392 |
| plain HT | 7090.24 | 443.14 | 4.508 | 8.168 |
| HT + rate_limiter | 7135.73 | 445.98 | 4.479 | 8.112 |
| HT + tcp_top | 7143.80 | 446.49 | 4.474 | 8.037 |

---

## 18. What was reproduced, what was partial, what was not

### Successfully reproduced (gist level)

- **Figure 12a gist**: yes
  Large-file NGINX showed a clear gap between Nested-VirtIO-ish and HT modes.

- **Figure 13 gist**: yes
  Memcached throughput-vs-p99-latency curves showed HT + Firewall clearly outperforming Nested-VirtIO-ish + Firewall near the 500 µs target.

- **Table 7 ranking / gist**: yes, approximately
  Using the proxy table we collected, HT + Pass / HT + Firewall were much faster than Nested-VirtIO-ish.

### Partially reproduced

- **Direct-Assignment**
  We brought up a DA-ish Kata/VFIO path and validated it with a working throughput datapoint, but did not fully integrate it into the final comparison tables.

### Not fully reproduced

- exact paper-faithful Table 7 with all columns and Direct-Assignment
- exact paper-faithful Figure 12b with a stronger Redis sensitivity gap
- exact paper-faithful Figure 13 absolute values

---

## 19. Reproduction traps to avoid

1. **Do not use Linux ifindex for `NETDEV_INDEX`.**
   Use the QEMU guest netdev index.

2. **Always inspect and clean `clsact` on `tap1` before retrying TC attaches.**

3. **Do not benchmark HT networking on the old `intel_iommu=on` boot path.**
   It produced DMAR faults even with no HT program attached.

4. **Minimal containers lack tools.**
   Be ready to stage host binaries/libraries or install packages inside the container.

5. **`tcp_top` needs the include path fix** from `../../packet.h` to `../packet.h`.

6. **The original firewall sources were broken.**
   Use the patched replacement documented here.

7. **Nested-VirtIO-ish via Docker/Kata port publish is fine for `iperf3` and apps, but not for `netperf UDP_RR` through a single published port.**

8. **Redis requires `--protected-mode no`** for remote benchmark access.

9. **Small-response NGINX was too insensitive.**
   Use the 64 MiB large-file variant if the goal is to expose datapath differences.

10. **For firewall microbenching with `netperf UDP_RR`, fixed-port allowlists are insufficient.**
    The data path negotiates additional UDP ports; allowing all UDP was the practical workaround.

---

## 20. Reproduction recipe (short form)

If someone wants to reproduce the core networking experiments from scratch on the same setup, the safest order is:

1. map the benchmark NIC path (`tap1` ↔ `enp1s0f0`) and set `NETDEV_INDEX=1`
2. use the **clean HT-only boot** (no guest IOMMU on the virtio benchmark path)
3. validate plain HT networking first (`10.10.1.1` / `10.10.1.2`)
4. fix build issues:
   - BPF include path for kernel headers
   - `tcp_top` include path
   - patched firewall sources
5. attach `pass`, `rate_limiter`, `tcp_top`, patched firewall one by one, cleaning stale TC/XDP state as needed
6. run:
   - large-file NGINX for Figure 12a gist
   - Memcached sweeps for Figure 13 gist
   - Table 7 proxy microbench rows if desired
7. only revisit DA later if a stronger upper bound is still desired

---

## 21. Bottom line

This reproduction did **not** yield an exact paper-faithful duplicate of every networking artifact, but it did establish the following clearly on this setup:

- HyperTurtle networking works on the current hardware/software stack.
- The first apparent HT failures were caused by benchmark-environment mistakes, not by HT itself.
- Once the environment was fixed, HT + eBPF/hyperupcalls behaved as intended.
- On the workloads that were actually sensitive to the datapath, HT reproduced the paper’s core networking story:
  - it stayed much closer to the good path than the weaker nested baseline
  - and HT + Firewall clearly beat Nested-VirtIO-ish + Firewall at a 500 µs-style tail-latency target.
