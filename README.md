# LINUXMAXXING

Linux internals experiments, collected on disposable Intel CloudLab hosts and rendered by a small static app. CloudLab is the execution environment. The Mac is the command client and dashboard host.

## Quick start

Create `cloudlab.json` in the repository root. It is intentionally ignored so an SSH target is local configuration:

```json
{
  "target": "user@node.cloudlab.us",
  "workspace": "linuxmaxxing-lab"
}
```

The checked-in template is [infra/cloudlab.example.json](infra/cloudlab.example.json). The target may point to any suitable node; CloudLab nodes are temporary, so the same setup command is safe to repeat after changing nodes.

```bash
./lab.sh setup
./lab.sh doctor
./lab.sh run scheduler
./lab.sh run all
./run-app.sh
```

`setup` runs on CloudLab. It installs the locked toolchain, downloads and verifies the pinned Ubuntu image, fetches the pinned Linux source, records environment facts, and applies a public-node baseline: UFW denies unsolicited inbound traffic while preserving SSH, fail2ban protects SSH, and unattended security upgrades are enabled. `build` and `run` synchronize the current source tree and execute remotely. A failed or replaced node can be rebuilt by running `./lab.sh setup` again.

The node is treated as disposable and potentially hostile: keep credentials out of the repository, use an SSH key, expose no experiment service ports, and run `./lab.sh setup` again whenever CloudLab reallocates the node. The firewall intentionally permits only the configured SSH port for inbound traffic; add any temporary experiment exception explicitly and remove it afterward.

The client needs Python 3 and SSH. It does not need Linux, QEMU, a kernel toolchain, libbpf, or root access. SSH keys and host aliases belong in the normal SSH configuration.

## Experiments

The eight supported experiments are defined by manifests under `experiments/`:

```text
scheduler    custom-kernel guest: CFS enqueue and runqueue state
memory       custom-kernel guest: MM phase snapshots and tracepoints
kapi         custom-kernel guest: kernel API module lifetime
io            custom-kernel guest: EDU device, DMA, IRQ, and workqueue
virt-ept     CloudLab host: KVM EPT and MMU transitions
virt-io      CloudLab host: KVM virtual I/O transitions
virt-virtio  CloudLab host: virtqueue and eventfd transitions
virt-vtd     CloudLab host plus assigned guest: VT-d/VFIO and guest DMA
```

Each experiment is self-contained under `experiments/<name>/`: its manifest, payload contract, build files, workload, observer, and resource-specific source live together. `common/` contains only reusable observer/runtime code. `framework/` contains the generic capture and execution machinery.

Use one experiment at a time while developing:

```bash
./lab.sh build memory
./lab.sh run memory
./lab.sh fetch memory
./lab.sh validate memory
```

`virt-vtd` requires an Intel host with an unused, isolated, FLR-capable NIC. If IOMMU is not enabled, run `./lab.sh prepare-vtd`, allow the node to reboot, and run it again. The management interface is audited and must remain available before, during, and after assignment.

The custom kernel remains a guest kernel. CloudLab supplies the Linux host and KVM capability; QEMU supplies the study guest for the guest experiments. A fresh overlay and swap disk are created per execution, while the pinned base image and kernel build are reused on that node.

## Capture contract

Every successful experiment publishes exactly one latest result:

```text
captures/<experiment>/events.ndjson
```

The file is replaced only after validation. A failed run leaves the previous valid capture unchanged. Temporary execution scratch is created on CloudLab and removed automatically; diagnostics are streamed through SSH.

Every event uses the same envelope:

```json
{
  "experiment": "scheduler",
  "sequence": 1,
  "source": {
    "collector": "observer",
    "mechanism": "ebpf",
    "domain": "guest",
    "hook": "kretprobe/__enqueue_entity"
  },
  "kind": "enqueue_entity",
  "timestamp_ns": "123456789",
  "clock_domain": "guest:monotonic",
  "context": {
    "cpu": 0,
    "pid": 123,
    "tid": 123,
    "comm": "workload",
    "phase": null,
    "operation": null
  },
  "quality": {"status": "complete", "reasons": []},
  "data": {}
}
```

There is one schema and no schema-number field. `data` is typed per registered event kind in that experiment's `payloads.json`. The envelope stays fixed across eBPF, tracefs, module, workload, sysfs, host, and guest observations.

The first and last records describe the capture lifecycle. Required lifecycle records are `capture_started`, `collector_ready`, `workload_started`, `workload_finished`, `collector_finished`, and `capture_finished`. A failed attempt is never published.

Host and guest monotonic clocks are separate explicit domains. `sequence` is output order, not a claim that host and guest timestamps share one timeline. Cross-domain relationships use operation, phase, or assignment identifiers.

## How to add an experiment

Start by writing the experiment question and evidence contract in the manifest. Declare the execution domain, build source, workload, observer, required and optional tracepoints, timeouts, and minimum event kinds. Add typed payload definitions to `payloads.json`.

The framework owns synchronization, dependency checks, process supervision, private tracefs instances, readiness, cleanup, loss accounting, validation, and atomic publication. The experiment owns only observation code, workload semantics, resource-specific preparation, and scientific assertions.

Collectors follow one lifecycle:

```text
preflight → prepare → attach → ready → workload → stop → drain → validate → publish
```

eBPF collects binary facts through the common observer ABI. The userspace observer serializes them. Tracefs uses a private monotonic instance and a declared decoder. Workloads emit phase markers through the same event contract. Diagnostics and control messages use separate streams from event data.

Run the framework tests with:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover closed payload types, malformed records, trace decoding, readiness and shutdown failures, event loss, source synchronization, workspace locking, clock domains, and atomic capture replacement. Live experiment acceptance requires a compatible CloudLab node and zero unexplained loss.

## Local dashboard

The visualizer is a static client and can be served locally:

```bash
./run-app.sh
```

Open `http://localhost:8000/app/`. Each view reads the latest `captures/<experiment>/events.ndjson`. Refresh reloads that capture; there are no run selectors or legacy capture readers. Missing, incomplete, and malformed captures are reported explicitly. Host and guest clocks remain separate; publication order is not elapsed time across machines.

Each experiment has exactly three files in `app/views/<experiment>/`: its HTML, CSS, and JavaScript. `app/theme.css` owns shared colors, typography, controls, and responsive layout. `app/common.js` owns capture loading, status, accessible details panels, and playback utilities; `app/app.js` owns navigation. Keep experiment-specific diagrams and evidence interpretation in the experiment's JavaScript and geometry in its CSS.

Laptop layouts keep controls visible and open the inspector with **Details**. Wide screens show the inspector beside the diagram. Narrow screens stack panels and scroll complex diagrams without shrinking their labels. Motion respects the operating-system reduced-motion preference.

GitHub Pages publishes the client only, not private capture data. It displays unavailable states until captures are supplied. A `captureBase` URL query parameter can point a view at an explicitly hosted capture directory (cross-origin hosting requires CORS). The shell propagates its `data-capture-base` HTML attribute to its views.

Browser regression checks require Playwright and Chromium:

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
python3 -m unittest discover -s tests -p 'test_app.py' -v
```

The browser suite checks every view at laptop, desktop, tablet, and phone sizes, plus malformed captures, exact timestamps, refresh failures, and inspector keyboard behavior. Real capture rendering checks use whichever local captures are available; an absent capture tests the unavailable state, not that experiment's scientific rendering.
