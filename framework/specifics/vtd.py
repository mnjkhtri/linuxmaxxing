"""VT-d workload hooks. Process, observer, validation, and publication remain shared."""
import json
import os
from pathlib import Path
import re
import shlex
import signal
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from framework.core.runtime import LabError, ROOT, Session, atomic_json, command, ndjson, prepare_image, record, signals


def driver(pci):
    path = pci / "driver"
    return path.resolve().name if path.exists() else None


def audit():
    routes = json.loads(command(["ip", "-j", "route", "show", "default"]))
    if not routes or "dev" not in routes[0]:
        raise LabError("cannot identify management interface")
    management = Path("/sys/class/net") / routes[0]["dev"]
    if not (management / "device").exists():
        raise LabError("VT-d requires a PCI-backed management interface")
    mgmt_pci = (management / "device").resolve()
    candidates = []
    for net in Path("/sys/class/net").iterdir():
        if net == management or not (net / "device").exists() or (net / "master").exists():
            continue
        pci = (net / "device").resolve()
        if driver(pci) != "ixgbe" or not (pci / "iommu_group").exists():
            continue
        if any(item.get("addr_info") for item in json.loads(command(["ip", "-j", "addr", "show", "dev", net.name]))):
            continue
        if command(["ip", "route", "show", "dev", net.name]).strip():
            continue
        group = (pci / "iommu_group").resolve()
        if group == (mgmt_pci / "iommu_group").resolve() or len(list((group / "devices").iterdir())) != 1:
            continue
        if not (pci / "reset_method").exists() or "flr" not in (pci / "reset_method").read_text().split():
            continue
        if not (pci / "reset").exists():
            continue
        candidates.append(pci)
    if not candidates:
        raise LabError("no unused, isolated, FLR-capable ixgbe NIC; provision an eligible Intel CloudLab node with IOMMU enabled")
    return management, mgmt_pci, sorted(candidates)[0]


def gate(process, enabled):
    process.signal(signal.SIGUSR1 if enabled else signal.SIGUSR2)
    process.wait_control("LX_GATE enabled=%d" % enabled, 5)


def run(session):
    if "vmx" not in Path("/proc/cpuinfo").read_text():
        raise LabError("VT-d experiment requires Intel VMX")
    management, mgmt_pci, pci = audit()
    original_driver = driver(pci)
    management_driver = driver(mgmt_pci)
    original_override = (pci / "driver_override").read_text()
    original_override = "\n" if original_override.strip() == "(null)" else original_override
    command(["modprobe", "vfio-pci"])
    command(["modprobe", "vfio_iommu_type1"])
    if not Path("/sys/kernel/tracing/events").exists():
        command(["mount", "-t", "tracefs", "nodev", "/sys/kernel/tracing"])
    image = prepare_image()
    runtime = session.runtime
    key = runtime / "guest-key"
    known_hosts = runtime / "guest-known-hosts"
    for path in (key, key.with_suffix(".pub"), known_hosts):
        if path.exists():
            path.unlink()
    command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
    user_data = runtime / "user-data"
    config = {"users": [{"name": "lab", "sudo": "ALL=(ALL) NOPASSWD:ALL", "shell": "/bin/bash",
                         "ssh_authorized_keys": [key.with_suffix(".pub").read_text().strip()]}],
              "ssh_pwauth": False,
              "runcmd": [["mkdir", "-p", "/mnt/lab", "/mnt/host"],
                          ["mount", "-t", "9p", "-o", "trans=virtio,version=9p2000.L", "labrepo", "/mnt/lab"],
                          ["mount", "-t", "9p", "-o", "trans=virtio,version=9p2000.L", "hostshare", "/mnt/host"]]}
    user_data.write_text("#cloud-config\n" + json.dumps(config))
    seed = runtime / "seed.iso"
    command(["cloud-localds", seed, user_data])
    overlay = runtime / "guest.qcow2"
    if overlay.exists():
        overlay.unlink()
    command(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay])
    observer = session.observer()
    changed = False

    def check_management():
        routes = json.loads(command(["ip", "-j", "route", "show", "default"]))
        if not routes or routes[0].get("dev") != management.name or driver(mgmt_pci) != management_driver:
            raise LabError("management interface changed during assignment")

    def assignment(kind):
        session.capture.events.append(record("virt-vtd", "assignment", "sysfs", "host", kind,
                                              time.monotonic_ns(), {"host_bdf": pci.name, "host_driver": driver(pci),
                                                                   "management_bdf": mgmt_pci.name}, hook="pci:driver"))

    def restore():
        nonlocal changed
        if changed:
            current = driver(pci)
            if current and current != original_driver:
                (pci / "driver/unbind").write_text(pci.name)
            (pci / "driver_override").write_text(original_override)
            if driver(pci) != original_driver:
                (Path("/sys/bus/pci/drivers") / original_driver / "bind").write_text(pci.name)
            if driver(pci) != original_driver:
                raise LabError("failed to restore " + pci.name)
            check_management()
            assignment("host_reclaims_device")
            changed = False
    # Register before the first write. QEMU callbacks are registered later and run first.
    session.stack.callback(restore)
    check_management()
    assignment("host_owns_device")
    session.capture.lifecycle("workload_started", {"command": ["vfio-assign", pci.name]})
    changed = True
    (pci / "driver_override").write_text("vfio-pci\n")
    (pci / "driver/unbind").write_text(pci.name)
    Path("/sys/bus/pci/drivers/vfio-pci/bind").write_text(pci.name)
    if driver(pci) != "vfio-pci":
        raise LabError("VFIO bind failed")
    check_management()
    assignment("vfio_bound")
    argv = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-m", "2G", "-smp", "2",
            "-drive", "if=virtio,format=qcow2,file=" + str(overlay),
            "-drive", "if=virtio,format=raw,media=cdrom,file=" + str(seed),
            "-netdev", "user,id=mgmt,hostfwd=tcp:127.0.0.1:2222-:22", "-device", "virtio-net-pci,netdev=mgmt",
            "-device", "vfio-pci,host=" + pci.name,
            "-virtfs", "local,path=%s,mount_tag=labrepo,security_model=none" % ROOT,
            "-virtfs", "local,path=%s,mount_tag=hostshare,security_model=none" % (ROOT / "build/tree"),
            "-display", "none", "-monitor", "none", "-serial", "file:" + str(runtime / "console.log"), "-no-reboot"]
    vm = session.process(argv, "qemu", cwd=ROOT)
    ssh = ["ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
           "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
           "-o", "UserKnownHostsFile=" + str(known_hosts), "-p", "2222", "lab@127.0.0.1"]
    end = time.monotonic() + 300
    while time.monotonic() < end:
        if vm.child.poll() is not None:
            raise LabError("VT-d guest failed to boot")
        try:
            # The 9p mount is created by cloud-init as root and is intentionally
            # not world-readable.  Probe it with the same privileged boundary
            # used to launch the guest workload.
            command(ssh + ["sudo -n test -r /mnt/lab/framework/specifics/vtd.py"], timeout=10)
            break
        except LabError:
            time.sleep(1)
    else:
        raise LabError("VT-d guest SSH did not become ready")
    assignment("qemu_attached")
    assignment("guest_visible")
    gate(observer, 1)
    guest_scratch = "/mnt/lab/" + str(runtime.relative_to(ROOT))
    command(ssh + ["sudo -n env %s python3 /mnt/lab/framework/specifics/vtd.py --guest" %
                   shlex.quote("LAB_SHARED_SCRATCH=" + guest_scratch)], timeout=300, capture=False)
    gate(observer, 0)
    guest_events = list(ndjson(runtime / "guest-events.ndjson"))
    session.capture.events.extend(guest_events)
    vm.stop()
    restore()
    session.capture.lifecycle("workload_finished", {"exit_code": 0})
    session.collect()


def guest_main():
    session = Session("virt-vtd", "guest")
    nets = [net for net in Path("/sys/class/net").iterdir()
            if (net / "device").exists() and driver((net / "device").resolve()) == "ixgbe"]
    if len(nets) != 1:
        raise LabError("guest requires exactly one assigned ixgbe interface")
    if not Path("/sys/kernel/tracing/events").exists():
        command(["mount", "-t", "tracefs", "nodev", "/sys/kernel/tracing"])
    with session.stack:
        session.capture.lifecycle("workload_started", {"command": ["ethtool", "-t", nets[0].name, "offline"]})
        observer = session.observer([session.cwd / "build/vtd", "--guest", nets[0].name], label="guest-observer")
        gate(observer, 1)
        command(["ip", "link", "set", "dev", nets[0].name, "up"])
        # ethtool may report an unrelated offline test failure; the experiment requires loopback success.
        proc = session.process(["ethtool", "-t", nets[0].name, "offline"], "guest-workload")
        try:
            proc.wait(180, peers=[observer])
        except LabError:
            if proc.child.poll() is None:
                raise
        output = (session.runtime / "guest-workload.ndjson").read_text()
        import re
        if not re.search(r"^Loopback test.*\s0$", output, re.M):
            raise LabError("guest loopback test did not succeed")
        gate(observer, 0)
        session.capture.lifecycle("workload_finished", {"exit_code": 0})
        session.collect()
    session.capture.path = session.runtime / "guest-events.ndjson"
    session.capture.save()


if __name__ == "__main__":
    if sys.argv[1:] != ["--guest"]:
        raise SystemExit("vtd.py requires --guest when invoked directly")
    with signals():
        guest_main()
