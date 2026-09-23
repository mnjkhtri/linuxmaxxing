"""VT-d run sequence, guest workload, and capture-specific checks."""

import json
import shlex
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from framework.core.runtime import (
    ROOT,
    LabError,
    Session,
    command,
    ndjson,
    prepare_image,
    record,
    signals,
)


def driver(pci):
    path = pci / "driver"
    return path.resolve().name if path.exists() else None


SUPPORTED_DRIVERS = {"igb", "ixgbe"}


class DeviceOwnership:
    """Temporarily hand an audited NIC to VFIO and restore its host driver."""

    def __init__(self, session, pci, management, management_pci):
        self.session = session
        self.pci = pci
        self.management = management
        self.management_pci = management_pci
        self.original_driver = driver(pci)
        self.management_driver = driver(management_pci)
        override = (pci / "driver_override").read_text()
        self.original_override = "\n" if override.strip() == "(null)" else override
        self.active = False

    def check_management(self):
        routes = json.loads(command(["ip", "-j", "route", "show", "default"]))
        if (
            not routes
            or routes[0].get("dev") != self.management.name
            or driver(self.management_pci) != self.management_driver
        ):
            raise LabError("management interface changed during assignment")

    def record(self, kind):
        # These controller markers describe ownership changes, not kernel tracepoints.
        self.session.capture.events.append(
            record(
                "virt-vtd",
                "assignment",
                "sysfs",
                "host",
                kind,
                time.monotonic_ns(),
                {
                    "host_bdf": self.pci.name,
                    "host_driver": driver(self.pci),
                    "management_bdf": self.management_pci.name,
                },
                hook="pci:driver",
            )
        )

    def bind_vfio(self):
        self.active = True
        # This reserves the device for passthrough; QEMU attaches it to the VM later.
        (self.pci / "driver_override").write_text("vfio-pci\n")
        (self.pci / "driver/unbind").write_text(self.pci.name)
        Path("/sys/bus/pci/drivers/vfio-pci/bind").write_text(self.pci.name)
        if driver(self.pci) != "vfio-pci":
            raise LabError("VFIO bind failed")
        self.check_management()

    def restore(self):
        if not self.active:
            return
        current = driver(self.pci)
        if current and current != self.original_driver:
            # Detach VFIO first, then return the device to its original host driver.
            (self.pci / "driver/unbind").write_text(self.pci.name)
        (self.pci / "driver_override").write_text(self.original_override)
        if driver(self.pci) != self.original_driver:
            (Path("/sys/bus/pci/drivers") / self.original_driver / "bind").write_text(
                self.pci.name
            )
        if driver(self.pci) != self.original_driver:
            raise LabError("failed to restore " + self.pci.name)
        self.check_management()
        self.record("host_reclaims_device")
        self.active = False


def main(domain):
    if domain == "guest":
        guest_main()
        return
    if domain != "host":
        raise LabError("VT-d worker domain must be host or guest")
    Session("virt-vtd", domain).execute(run)


def prepare():
    if "vmx" not in Path("/proc/cpuinfo").read_text():
        raise LabError("VT-d preparation supports Intel hosts only")
    groups = Path("/sys/kernel/iommu_groups")
    if groups.exists() and any(groups.iterdir()):
        management, _, pci = audit()
        print(
            "VT-d candidate %s; management interface %s remains protected"
            % (pci.name, management.name)
        )
        return
    command(["sudo", "-n", "mkdir", "-p", "/etc/default/grub.d"])
    content = b'GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} intel_iommu=on iommu=pt"\n'
    command(
        ["sudo", "-n", "tee", "/etc/default/grub.d/90-linuxmaxxing.cfg"], input=content
    )
    command(["sudo", "-n", "update-grub"], timeout=120, capture=False)
    print(
        "IOMMU boot configuration installed. Reboot the node, then repeat ./lab.sh prepare virt-vtd."
    )


def audit():
    """Pick an idle, isolated NIC without risking the host management path."""
    routes = json.loads(command(["ip", "-j", "route", "show", "default"]))
    if not routes or "dev" not in routes[0]:
        raise LabError("cannot identify management interface")
    management = Path("/sys/class/net") / routes[0]["dev"]
    if not (management / "device").exists():
        raise LabError("VT-d requires a PCI-backed management interface")
    mgmt_pci = (management / "device").resolve()
    candidates = []
    for net in Path("/sys/class/net").iterdir():
        if (
            net == management
            or not (net / "device").exists()
            or (net / "master").exists()
        ):
            continue
        pci = (net / "device").resolve()
        if driver(pci) not in SUPPORTED_DRIVERS or not (pci / "iommu_group").exists():
            continue
        # Any configured address or route means the interface may carry host traffic.
        if any(
            item.get("addr_info")
            for item in json.loads(
                command(["ip", "-j", "addr", "show", "dev", net.name])
            )
        ):
            continue
        if command(["ip", "route", "show", "dev", net.name]).strip():
            continue
        group = (pci / "iommu_group").resolve()
        # VFIO needs an isolated IOMMU group, and FLR gives us a device-level reset.
        if (
            group == (mgmt_pci / "iommu_group").resolve()
            or len(list((group / "devices").iterdir())) != 1
        ):
            continue
        if (
            not (pci / "reset_method").exists()
            or "flr" not in (pci / "reset_method").read_text().split()
        ):
            continue
        if not (pci / "reset").exists():
            continue
        candidates.append(pci)
    if not candidates:
        raise LabError(
            "no unused, isolated, FLR-capable Intel NIC (igb/ixgbe); use an eligible Intel lab server with IOMMU enabled"
        )
    return management, mgmt_pci, sorted(candidates)[0]


def gate(process, enabled):
    process.signal(signal.SIGUSR1 if enabled else signal.SIGUSR2)
    process.wait_control("LX_GATE enabled=%d" % enabled, 5)


def run(session):
    if "vmx" not in Path("/proc/cpuinfo").read_text():
        raise LabError("VT-d experiment requires Intel VMX")
    # Keep the default-route NIC on its host driver; assign only a spare isolated NIC.
    management, mgmt_pci, pci = audit()
    ownership = DeviceOwnership(session, pci, management, mgmt_pci)
    # Load VFIO's PCI driver; the NIC is still owned by its normal host driver here.
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
    config = {
        "users": [
            {
                "name": "lab",
                "sudo": "ALL=(ALL) NOPASSWD:ALL",
                "shell": "/bin/bash",
                "ssh_authorized_keys": [key.with_suffix(".pub").read_text().strip()],
            }
        ],
        "ssh_pwauth": False,
        "runcmd": [
            ["mkdir", "-p", "/mnt/lab", "/mnt/host"],
            [
                "mount",
                "-t",
                "9p",
                "-o",
                "trans=virtio,version=9p2000.L",
                "labrepo",
                "/mnt/lab",
            ],
            [
                "mount",
                "-t",
                "9p",
                "-o",
                "trans=virtio,version=9p2000.L",
                "hostshare",
                "/mnt/host",
            ],
        ],
    }
    user_data.write_text("#cloud-config\n" + json.dumps(config))
    seed = runtime / "seed.iso"
    command(["cloud-localds", seed, user_data])
    overlay = runtime / "guest.qcow2"
    if overlay.exists():
        overlay.unlink()
    command(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay])
    # Attach before QEMU starts so the host trace sees KVM/VFIO setup calls.
    observer = session.observer()
    # Register before the first write. QEMU callbacks are registered later and run first.
    session.stack.callback(ownership.restore)
    ownership.check_management()
    ownership.record("host_owns_device")
    # Hand ownership from the host NIC driver to vfio-pci through sysfs.
    ownership.bind_vfio()
    ownership.record("vfio_bound")
    argv = [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-m",
        "2G",
        "-smp",
        "2",
        "-drive",
        "if=virtio,format=qcow2,file=" + str(overlay),
        "-drive",
        "if=virtio,format=raw,media=cdrom,file=" + str(seed),
        # Keep guest SSH on an emulated management NIC, separate from passthrough.
        "-netdev",
        "user,id=mgmt,hostfwd=tcp:127.0.0.1:2222-:22",
        "-device",
        "virtio-net-pci,netdev=mgmt",
        # QEMU attaches the already vfio-pci-owned host NIC to this VM.
        "-device",
        "vfio-pci,host=" + pci.name,
        "-virtfs",
        "local,path=%s,mount_tag=labrepo,security_model=none" % ROOT,
        "-virtfs",
        "local,path=%s,mount_tag=hostshare,security_model=none" % (ROOT / "build/tree"),
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "file:" + str(runtime / "console.log"),
        "-no-reboot",
    ]
    vm = session.process(argv, "qemu", cwd=ROOT)
    session.capture.lifecycle("qemu_started", {"command": argv})
    ssh = [
        "ssh",
        "-i",
        str(key),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "UserKnownHostsFile=" + str(known_hosts),
        "-p",
        "2222",
        "lab@127.0.0.1",
    ]
    end = time.monotonic() + 300
    while time.monotonic() < end:
        if vm.child.poll() is not None:
            raise LabError("VT-d guest failed to boot")
        try:
            # The 9p mount is created by cloud-init as root and is intentionally not world-readable.
            # Probe it with the same privileged boundary used to launch the guest workload.
            command(
                ssh + ["sudo -n test -r /mnt/lab/experiments/virt-vtd/_run.py"],
                timeout=10,
            )
            break
        except LabError:
            time.sleep(1)
    else:
        raise LabError("VT-d guest SSH did not become ready")
    # QEMU has started with the passthrough device; the guest OS can now enumerate it.
    ownership.record("qemu_attached")
    ownership.record("guest_visible")
    # Host probes remain attached; this adds a clock marker around the guest run.
    gate(observer, 1)
    guest_scratch = "/mnt/lab/" + str(runtime.relative_to(ROOT))
    command(
        ssh
        + [
            "sudo -n env %s python3 /mnt/lab/experiments/virt-vtd/_run.py --guest"
            % shlex.quote("LAB_SHARED_SCRATCH=" + guest_scratch)
        ],
        timeout=300,
        capture=False,
    )
    session.capture.lifecycle("cleanup_begin", {"reason": "guest workload complete"})
    gate(observer, 0)
    guest_events = list(ndjson(runtime / "guest-events.ndjson"))
    session.capture.events.extend(guest_events)
    vm.stop()
    session.capture.lifecycle("qemu_stopped", {"reason": "guest workload complete"})
    ownership.restore()
    session.collect()


def guest_main():
    session = Session("virt-vtd", "guest")
    # The assigned Intel NIC is distinct from QEMU's virtio management NIC.
    nets = [
        net
        for net in Path("/sys/class/net").iterdir()
        if (net / "device").exists()
        and driver((net / "device").resolve()) in SUPPORTED_DRIVERS
    ]
    if len(nets) != 1:
        raise LabError("guest requires exactly one assigned Intel igb/ixgbe interface")
    nic_driver = driver((nets[0] / "device").resolve())
    if not Path("/sys/kernel/tracing/events").exists():
        command(["mount", "-t", "tracefs", "nodev", "/sys/kernel/tracing"])
    with session.stack:
        session.capture.lifecycle(
            "workload_started", {"command": ["ethtool", "-t", nets[0].name, "offline"]}
        )
        observer = session.observer(
            [session.cwd / "build/vtd", "--guest", nets[0].name, nic_driver],
            label="guest-observer",
        )
        # This gate marks the observation window; interface-up and ethtool follow it.
        gate(observer, 1)
        command(["ip", "link", "set", "dev", nets[0].name, "up"])
        # ethtool may report an unrelated offline test failure; the experiment requires loopback success.
        workload_command = ["ethtool", "-t", nets[0].name, "offline"]
        session.capture.lifecycle(
            "guest_workload_begin",
            {"command": workload_command, "interface": nets[0].name},
        )
        proc = session.process(workload_command, "guest-workload")
        try:
            proc.wait(180, peers=[observer])
        except LabError:
            if proc.child.poll() is None:
                raise
        output = (session.runtime / "guest-workload.ndjson").read_text()
        import re

        if not re.search(r"^Loopback test.*\s0$", output, re.MULTILINE):
            raise LabError("guest loopback test did not succeed")
        session.capture.lifecycle(
            "guest_workload_end",
            {"interface": nets[0].name, "result": "loopback passed"},
        )
        gate(observer, 0)
        session.capture.lifecycle("workload_finished", {"exit_code": 0})
        session.collect()
    session.capture.path = session.runtime / "guest-events.ndjson"
    session.capture.save()


if __name__ == "__main__":
    if sys.argv[1:] != ["--guest"]:
        raise SystemExit("_run.py requires --guest when invoked directly")
    with signals():
        guest_main()
