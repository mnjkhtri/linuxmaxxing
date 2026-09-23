# LINUXMAXXING

Linux internals experiments, collected on a dedicated lab server and rendered by a small static app. The lab server is the execution environment. The Mac is the command client and dashboard host.

## Quick start

Create `lab.json` in the repository root. It is intentionally ignored so the SSH target remains local configuration:

```json
{
  "target": "lab-server",
  "workspace": "linuxmaxxing-lab"
}
```

The checked-in template is [infra/lab.example.json](infra/lab.example.json). The target may point to any suitable Linux server; the setup command is safe to repeat after replacing or rebuilding the server.

```bash
./lab.sh setup
./lab.sh doctor
./lab.sh run scheduler
./lab.sh run all
./run-app.sh
```

`setup` runs on the lab server. It installs the locked toolchain, downloads and verifies the pinned Ubuntu image, fetches the pinned Linux source, records environment facts, and applies the server baseline: UFW denies unsolicited inbound traffic while preserving SSH, fail2ban protects SSH, and unattended security upgrades are enabled. `build` and `run` synchronize the current source tree and execute remotely. A failed or replaced server can be rebuilt by running `./lab.sh setup` again.

The server is treated as potentially hostile: keep credentials out of the repository, use an SSH key, expose no experiment service ports, and run `./lab.sh setup` again whenever the server is replaced. The firewall intentionally permits only the configured SSH port for inbound traffic; add any temporary experiment exception explicitly and remove it afterward.

The client needs Python 3 and SSH. It does not need Linux, QEMU, a kernel toolchain, libbpf, or root access. SSH keys and host aliases belong in the normal SSH configuration.

## Experiments

The eight supported experiments are defined by manifests under `experiments/`:

```text
scheduler    custom-kernel guest: CFS enqueue and runqueue state
memory       custom-kernel guest: MM phase snapshots and tracepoints
kapi         custom-kernel guest: kernel API module lifetime
io            custom-kernel guest: EDU device, DMA, IRQ, and workqueue
virt-ept     lab server host: KVM EPT and MMU transitions
virt-io      lab server host: KVM virtual I/O transitions
virt-virtio  lab server host: virtqueue and eventfd transitions
virt-vtd     lab server host plus assigned guest: VT-d/VFIO and guest DMA
```

Each experiment is self-contained under `experiments/<name>/`. Start at its `_run.py` to see the exact execution order and experiment-specific evidence checks, then follow its manifest, workload, observer, and BPF/C sources. `common/` and `framework/` provide shared observer and capture/transport primitives; they do not decide an experiment's sequence.

Use one experiment at a time while developing:

```bash
./lab.sh build memory
./lab.sh run memory
./lab.sh fetch memory
./lab.sh validate memory
```

`virt-vtd` requires an Intel host with an unused, isolated, FLR-capable NIC. If IOMMU is not enabled, run `./lab.sh prepare virt-vtd`, allow the node to reboot, and run it again. The management interface is audited and must remain available before, during, and after assignment.

The custom kernel remains a guest kernel. The lab server supplies the Linux host and KVM capability; QEMU supplies the study guest for the guest experiments. A fresh overlay and swap disk are created per execution, while the pinned base image and kernel build are reused on that server.

## Capture contract

Every successful experiment publishes exactly one latest result:

```text
captures/<experiment>/events.ndjson
```

The file is replaced only after validation. A failed run leaves the previous valid capture unchanged. Temporary execution scratch is created on the lab server and removed automatically; diagnostics are streamed through SSH.

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

Keep the experiment readable from its directory. Add:

```text
experiment.json   what is being taught and what evidence is required
payloads.json     the shapes of its event data
run.sh            ./lab.sh run <name>
Makefile          its build commands
workload/observer source files for the actual experiment
```

The framework handles only the common mechanics: copying the source to the lab
server, building, starting collectors, starting the workload, validating the
capture, and publishing the latest result. The experiment code owns the kernel
concept, its workload, its tracepoints, and its interpretation.

The capture lifecycle is intentionally small:

```text
start → collectors ready → workload → collectors stopped → publish
```

eBPF, tracefs, module, and workload observations all use the same event envelope,
but the raw collection code remains visible in the experiment directory.

Run the framework tests with:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover closed payload types, malformed records, trace decoding, readiness and shutdown failures, event loss, source synchronization, workspace locking, clock domains, and atomic capture replacement. Live experiment acceptance requires a compatible lab server and zero unexplained loss.

## Local dashboard

The visualizer is a static client and can be served locally:

```bash
./run-app.sh
```

Open `http://localhost:8000/app/`. Each view reads the latest `captures/<experiment>/events.ndjson`. Refresh reloads that capture; there are no run selectors or legacy capture readers. Missing, incomplete, and malformed captures are reported explicitly. Host and guest clocks remain separate; publication order is not elapsed time across machines.

Each experiment has exactly three files in `app/views/<experiment>/`: its HTML, CSS, and JavaScript. `app/theme.css` owns shared colors, typography, controls, and responsive layout. `app/common.js` owns capture loading, status, accessible details panels, and playback utilities; `app/app.js` owns navigation. Keep experiment-specific diagrams and evidence interpretation in the experiment's JavaScript and geometry in its CSS.

### Flow views

Flow views use one simple rule: an arrow is a directional handoff between two
actors; a point is an observation at one actor. Solid lines are observed,
dashed lines are inferred, and selection is the only strong accent. Long details
belong in the inspector, not on the diagram. IO is the reference view for the
other flow experiments.

Laptop layouts keep controls visible and open the inspector with **Details**. Wide screens show the inspector beside the diagram. Narrow screens stack panels and scroll complex diagrams without shrinking their labels. Motion respects the operating-system reduced-motion preference.

GitHub Pages publishes the client only, not private capture data. It displays unavailable states until captures are supplied. A `captureBase` URL query parameter can point a view at an explicitly hosted capture directory (cross-origin hosting requires CORS). The shell propagates its `data-capture-base` HTML attribute to its views.

Browser regression checks require Playwright and Chromium:

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
python3 -m unittest discover -s tests -p 'test_app.py' -v
```

The browser suite checks every view at laptop, desktop, tablet, and phone sizes, plus malformed captures, exact timestamps, refresh failures, and inspector keyboard behavior. Real capture rendering checks use whichever local captures are available; an absent capture tests the unavailable state, not that experiment's scientific rendering.
