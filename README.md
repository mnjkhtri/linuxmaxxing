# linuxmaxxing

Personal Linux-kernel study lab. This is not meant to be a reusable framework; it is my workspace for building a custom kernel, running small QEMU workloads, capturing kernel state, and visualizing what happened.

## Setup

Install the basic kernel/QEMU/eBPF tooling:

```bash
sudo apt update
sudo apt install -y \
  build-essential bc bison flex libssl-dev libelf-dev dwarves clang llvm \
  libbpf-dev linux-tools-common qemu-system-x86 qemu-utils \
  cloud-image-utils ccache
```

Fetch Linux and create the guest disk once:

```bash
git submodule update --init --depth 1 linux
mkdir -p vm
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img -O vm/ubuntu-24.04.qcow2
cloud-localds vm/seed.iso vm/user-data vm/meta-data
```

## Build and boot

Build the kernel:

```bash
./build.sh
```

Boot QEMU:

```bash
./boot.sh
```

Inside QEMU, mount the host share:

```bash
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
```

If `/mnt/host` is already mounted, do not mount again.

## Study folders

Most study folders under `shared/` are self-contained:

```text
Makefile   build the observer/workload/module from the host
run.sh     run the capture or smoke test from inside QEMU
README.md  local notes for that specific experiment
```

So the normal pattern is:

```bash
make -C shared/<folder>
```

then inside QEMU:

```bash
/mnt/host/<folder>/run.sh
```

Captures are written under:

```bash
shared/_captures/
```

## Visual app

Serve the static app from the repo root:

```bash
python3 -m http.server 8000
```

Open:

```text
http://localhost:8000/app/
```

Current tabs:

```text
SCHED       task lifecycle traces
CFS         per-CPU CFS rb-tree snapshots
MM          mm_struct, VMAs, page tables, page cache, anon_vma
TASKS       task_struct/kapi capture view
LAYOUT      address-layout reference view
ALLOCATORS  allocator/kapi capture view
```

## QEMU controls

With `-nographic`:

| Action | Key |
|---|---|
| Quit QEMU | `Ctrl-a`, then `x` |
| Open monitor | `Ctrl-a`, then `c` |
| Quit from monitor | `quit` |
