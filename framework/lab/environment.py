"""Lab-server provisioning, source transport, and remote execution."""

import io
import os
import platform
import re
import shlex
import shutil
import tarfile
from pathlib import Path

from framework.core.runtime import (
    ROOT,
    LabError,
    atomic_json,
    command,
    digest,
    manifest,
    read_json,
)


def spec():
    return read_json(ROOT / "infra/environment.json")


def doctor(check_tools=True):
    expected = spec()
    if platform.system() != "Linux" or platform.machine() != expected["architecture"]:
        raise LabError("execution requires an x86-64 Linux lab server")
    release = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text().splitlines()
        if "=" in line
    )
    if (
        release.get("ID", "").strip('"') != expected["os"]
        or release.get("VERSION_ID", "").strip('"') != expected["release"]
    ):
        raise LabError("use the Ubuntu 24.04 lab-server image")
    command(["sudo", "-n", "true"])
    if check_tools:
        missing = [
            tool
            for tool in (
                "gcc",
                "clang",
                "make",
                "bpftool",
                "qemu-system-x86_64",
                "qemu-img",
                "cloud-localds",
                "virt-customize",
            )
            if not shutil.which(tool)
        ]
        if missing:
            raise LabError(
                "missing host tools: %s; run ./lab.sh setup" % ", ".join(missing)
            )
    return {
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "os": "ubuntu-24.04",
    }


def setup():
    facts = doctor(check_tools=False)
    cfg = spec()
    command(["sudo", "-n", "apt-get", "update"], timeout=600, capture=False)
    command(
        [
            "sudo",
            "-n",
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "-y",
        ]
        + cfg["packages"],
        timeout=1800,
        capture=False,
    )
    secure(cfg["security"])
    images = ROOT / "build/images"
    images.mkdir(parents=True, exist_ok=True)
    base = images / "ubuntu.qcow2"
    if not base.exists() or digest(base) != cfg["image_sha256"]:
        temporary = images / "ubuntu.download"
        command(
            [
                "curl",
                "--fail",
                "--location",
                "--retry",
                "3",
                "--output",
                temporary,
                cfg["image_url"],
            ],
            timeout=1800,
            capture=False,
        )
        if digest(temporary) != cfg["image_sha256"]:
            raise LabError("Ubuntu image checksum mismatch")
        temporary.replace(base)
    kernel = ROOT / "build/linux"
    if not kernel.exists():
        command(["git", "init", kernel])
        command(
            ["git", "-C", kernel, "remote", "add", "origin", cfg["kernel_repository"]]
        )
    else:
        remotes = command(["git", "-C", kernel, "remote"]).decode().split()
        if "origin" not in remotes:
            command(
                [
                    "git",
                    "-C",
                    kernel,
                    "remote",
                    "add",
                    "origin",
                    cfg["kernel_repository"],
                ]
            )
    if (
        command(["git", "-C", kernel, "remote", "get-url", "origin"]).decode().strip()
        != cfg["kernel_repository"]
    ):
        command(
            [
                "git",
                "-C",
                kernel,
                "remote",
                "set-url",
                "origin",
                cfg["kernel_repository"],
            ]
        )
    command(
        ["git", "-C", kernel, "fetch", "--depth=1", "origin", cfg["kernel_revision"]],
        timeout=1800,
        capture=False,
    )
    command(["git", "-C", kernel, "checkout", "--detach", cfg["kernel_revision"]])
    actual = command(["git", "-C", kernel, "rev-parse", "HEAD"]).decode().strip()
    if actual != cfg["kernel_revision"]:
        raise LabError("cached kernel revision differs from the environment lock")
    packages = (
        command(["dpkg-query", "-W", "-f=${Package}=${Version}\n"] + cfg["packages"])
        .decode()
        .splitlines()
    )
    facts.update(
        packages=packages,
        image_sha256=cfg["image_sha256"],
        kernel_revision=actual,
        qemu=command(["qemu-system-x86_64", "--version"]).decode().splitlines()[0],
    )
    atomic_json(ROOT / "build/environment.json", facts)
    print("Lab-server dependencies and pinned sources ready. Builds occur on demand.")


def secure(cfg):
    """Apply a repeatable minimum baseline to a publicly reachable node."""
    port = str(cfg["ssh_port"])
    command(["sudo", "-n", "ufw", "default", "deny", "incoming"], capture=False)
    command(["sudo", "-n", "ufw", "default", "allow", "outgoing"], capture=False)
    command(
        ["sudo", "-n", "ufw", "allow", port + "/tcp", "comment", "Lab-server SSH"],
        capture=False,
    )
    command(["sudo", "-n", "ufw", "--force", "enable"], capture=False)
    if cfg.get("fail2ban"):
        jail = (
            "[sshd]\n"
            "enabled = true\n"
            "port = %s\n"
            "maxretry = 5\n"
            "findtime = 10m\n"
            "bantime = 1h\n" % port
        )
        command(
            ["sudo", "-n", "tee", "/etc/fail2ban/jail.d/linuxmaxxing-sshd.local"],
            input=jail.encode(),
        )
        command(
            ["sudo", "-n", "systemctl", "enable", "--now", "fail2ban"],
            timeout=120,
            capture=False,
        )
    if cfg.get("unattended_upgrades"):
        command(
            [
                "sudo",
                "-n",
                "systemctl",
                "enable",
                "--now",
                "apt-daily.timer",
                "apt-daily-upgrade.timer",
            ],
            timeout=120,
            capture=False,
        )


def build(name):
    doctor()
    if not (ROOT / "build/environment.json").exists():
        raise LabError("node has not been provisioned; run ./lab.sh setup")
    cfg = manifest(name)
    if cfg["environment"] == "host":
        if "vmx" not in Path("/proc/cpuinfo").read_text():
            raise LabError("virtualization experiments require Intel VMX")
        command(["sudo", "-n", "modprobe", "kvm_intel"])
        if (
            not Path("/dev/kvm").exists()
            or not Path("/sys/kernel/btf/vmlinux").exists()
        ):
            raise LabError("KVM or host kernel BTF is unavailable")
    if cfg["environment"] == "guest":
        env = dict(
            os.environ,
            LAB_KERNEL_SOURCE=str(ROOT / "build/linux"),
            LAB_KERNEL_BUILD=str(ROOT / "build/kernel"),
        )
        command(
            ["bash", ROOT / "infra/build-kernel.sh"],
            timeout=10800,
            capture=False,
            env=env,
        )
    source = ROOT / cfg["source"]
    target = ROOT / "build/tree" / cfg["source"]
    target.mkdir(parents=True, exist_ok=True)
    identity = {
        "kernel_btf": digest(ROOT / "build/kernel/vmlinux")
        if cfg["environment"] == "guest"
        else digest("/sys/kernel/btf/vmlinux")
    }
    module_btf = Path("/sys/kernel/btf/kvm")
    if cfg["environment"] == "host" and module_btf.exists():
        identity["kvm_btf"] = digest(module_btf)
    identity_file = target / "kernel-identity.json"
    if not identity_file.exists() or read_json(identity_file) != identity:
        for directory in (target, target / "build"):
            for filename in ("vmlinux.h", "kvm_types.h", "kvm_compat.h"):
                path = directory / filename
                if path.exists():
                    path.unlink()
        atomic_json(identity_file, identity)
    for path in source.iterdir():
        if path.is_file() and (
            path.suffix in (".c", ".h", ".S") or path.name == "Makefile"
        ):
            destination = target / path.name
            if not destination.exists() or digest(path) != digest(destination):
                shutil.copy2(path, destination)
    common = ROOT / "build/tree/common"
    common.mkdir(parents=True, exist_ok=True)
    for path in (ROOT / "common").iterdir():
        if path.suffix in (".c", ".h"):
            destination = common / path.name
            if not destination.exists() or digest(path) != digest(destination):
                shutil.copy2(path, destination)
    make_args = [
        "make",
        "-C",
        target,
        "all",
        "CC=gcc",
        "ARCH=x86_64",
        "KDIR=" + str(ROOT / "build/kernel"),
        "KERNEL_BUILD=" + str(ROOT / "build/kernel"),
        "SHARED_DIR=" + str(common),
    ]
    # The distro bpftool wrapper follows the running kernel version. Use the
    # tool built from the pinned kernel source for every experiment so custom
    # host kernels and guest CO-RE artifacts use one deterministic generator.
    bpftool_dir = ROOT / "build/linux/tools/bpf/bpftool"
    bpftool = bpftool_dir / "bpftool"
    if cfg["environment"] == "guest" or not bpftool.exists():
        command(
            ["make", "-C", bpftool_dir, "-j2"],
            timeout=600,
            capture=False,
        )
    make_args.append("BPFTOOL=" + str(bpftool))
    command(make_args, timeout=1800, capture=False)
    return target


def prepare_vtd():
    doctor()
    if "vmx" not in Path("/proc/cpuinfo").read_text():
        raise LabError("VT-d preparation supports Intel hosts only")
    groups = Path("/sys/kernel/iommu_groups")
    if groups.exists() and any(groups.iterdir()):
        from framework.specifics.vtd import audit

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
        "IOMMU boot configuration installed. Reboot the node, then repeat ./lab.sh prepare-vtd."
    )


# Executed using the node's system Python, before project dependencies exist.
# A single lock covers source synchronization and the complete remote command.
BOOTSTRAP = r"""
import fcntl, hashlib, io, json, os, pathlib, subprocess, sys, tarfile
workspace, action, name = sys.argv[1:]
root = pathlib.Path.home() / workspace
if root.is_symlink():
    sys.exit('workspace must not be a symlink')
root.mkdir(mode=0o700, parents=True, exist_ok=True)
root = root.resolve()
with (root / '.lock').open('a') as mutex:
    try:
        fcntl.flock(mutex, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit('Lab-server workspace is busy')
    archive = tarfile.open(fileobj=sys.stdin.buffer, mode='r|')
    entries = []
    for member in archive:
        rel = pathlib.PurePosixPath(member.name)
        if rel.is_absolute() or '..' in rel.parts or not member.isfile():
            sys.exit('invalid source archive member')
        if rel.parts[0] not in ('framework', 'infra', 'experiments', 'common') and str(rel) != 'lab.sh':
            sys.exit('unexpected source archive member')
        entries.append((rel, member.mode & 0o777, archive.extractfile(member).read()))
    current = {str(rel) for rel, _, _ in entries}
    provenance = root / 'source-provenance.json'
    if provenance.exists():
        previous = json.loads(provenance.read_text())
        for item in previous.get('files', []):
            rel = pathlib.PurePosixPath(item[0])
            if str(rel) not in current and rel.parts and (rel.parts[0] in ('framework', 'infra', 'experiments', 'common') or str(rel) == 'lab.sh'):
                target = root / rel
                if target.is_symlink():
                    sys.exit('symlink in stale source destination')
                if target.is_file():
                    target.unlink()
    files = []
    for rel, mode, data in entries:
        target = root / rel
        if target.is_symlink() or any(p.is_symlink() for p in target.parents if p != root.parent):
            sys.exit('symlink in source destination')
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name('.' + target.name + '.sync')
        temporary.write_bytes(data)
        temporary.chmod(mode)
        temporary.replace(target)
        files.append((str(rel), hashlib.sha256(data).hexdigest()))
    digest = hashlib.sha256(json.dumps(sorted(files), separators=(',', ':')).encode()).hexdigest()
    (root / 'source-provenance.json').write_text(json.dumps({'digest': digest, 'files': files}))
    args = [sys.executable, str(root / 'framework/cli.py'), '--host', action]
    if name:
        args.append(name)
    child = subprocess.Popen(args, cwd=root)
    import signal
    def stop(signum, frame):
        child.send_signal(signal.SIGHUP)
        try:
            child.wait(timeout=60)
        except subprocess.TimeoutExpired:
            child.kill()
        sys.exit(128 + signum)
    signal.signal(signal.SIGHUP, stop)
    signal.signal(signal.SIGTERM, stop)
    sys.exit(child.wait())
"""


class Remote:
    def __init__(self, config=None):
        path = Path(config) if config else ROOT / "lab.json"
        if not path.exists():
            raise LabError(
                "missing lab.json; copy infra/lab.example.json and set the target"
            )
        cfg = read_json(path)
        if set(cfg) != {"target", "workspace"}:
            raise LabError(
                "lab.json accepts only target and workspace; put key/port settings in SSH config"
            )
        self.target, self.workspace = cfg["target"], cfg["workspace"]
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*", self.target):
            raise LabError("invalid SSH target")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", self.workspace):
            raise LabError("workspace must be a single relative directory name")
        self.ssh = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "StrictHostKeyChecking=accept-new",
            self.target,
        ]

    def archive(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            paths = [ROOT / "lab.sh"]
            for directory in ("framework", "infra", "experiments", "common"):
                for path in (ROOT / directory).rglob("*"):
                    rel = path.relative_to(ROOT)
                    if any(
                        p in ("__pycache__", "_captures", "build", "_exps")
                        for p in rel.parts
                    ):
                        continue
                    if (
                        path.is_file()
                        and not path.is_symlink()
                        and (
                            path.suffix
                            in (".py", ".json", ".c", ".h", ".S", ".sh", ".md")
                            or path.name == "Makefile"
                        )
                    ):
                        paths.append(path)
            for path in sorted(paths):
                tar.add(path, arcname=str(path.relative_to(ROOT)), recursive=False)
        return buf.getvalue()

    def execute(self, action, name=""):
        argv = self.ssh + [
            shlex.join(["python3", "-c", BOOTSTRAP, self.workspace, action, name])
        ]
        command(argv, input=self.archive(), timeout=14400, capture=False)

    def fetch(self, name):
        rel = "captures/%s/events.ndjson" % name
        # sudo reads only this workspace's named artifact, never arbitrary client paths.
        script = "from pathlib import Path; import sys; sys.stdout.buffer.write((Path.home() / sys.argv[1]).read_bytes())"
        path = self.workspace + "/" + rel
        return command(
            self.ssh + [shlex.join(["python3", "-c", script, path])], timeout=600
        )
