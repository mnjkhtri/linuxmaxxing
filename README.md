# linuxmaxxing

linux internals maxxing in qemu. not a framework. not a product. just captures, kernel code, and visual brain damage.

## setup once

```bash
sudo apt update
sudo apt install -y \
  build-essential bc bison flex libssl-dev libelf-dev dwarves clang llvm \
  libbpf-dev linux-tools-common qemu-system-x86 qemu-utils \
  cloud-image-utils ccache

git submodule update --init --depth 1 linux
git -C linux branch --unset-upstream master 2>/dev/null || true
mkdir -p vm
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img -O vm/ubuntu-24.04.qcow2
cloud-localds vm/seed.iso vm/user-data vm/meta-data
```

## build + boot

```bash
./build.sh
./boot.sh
```

inside qemu:

```bash
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
```

if already mounted, stop mounting it again.

## experiments

Most folders in `shared/` follow this rule:

```bash
make -C shared/<folder>        # host
/mnt/host/<folder>/run.sh      # qemu
```

Captures land in:

```text
shared/_captures/
```

Useful folders right now:

```text
tracing     scheduler tracepoints
ebpf        CFS rb-tree snapshots
mm          VMA / page table / page cache / anon_vma
kapi        kernel API module capture
miscdriver  misc char driver
pci         QEMU EDU PCI driver
```

## app

```bash
python3 -m http.server 8000
```

open:

```text
http://localhost:8000/app/
```

## qemu escape hatch

```text
quit:    Ctrl-a x
monitor: Ctrl-a c
```
