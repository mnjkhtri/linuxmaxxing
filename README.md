# LINUXMAXXING

linux internals maxxing in qemu. not a framework. not a product. just captures, kernel code, and visual brain damage.

## Reproducibility

Clone with the pinned Linux submodule, then run `./setup.sh`, `./build.sh`, and `./boot.sh`. The setup script installs host dependencies, downloads the Ubuntu 24.04 image, and creates the QEMU seed. Inside QEMU, mount `hostshare` at `/mnt/host`; each experiment directory documents its own make/run.sh entry point.

KVM experiments run on CloudLab. Put user@node in the ignored shared/virt/cloudlab file, run the relevant setup script, then its run.sh; the runner builds remotely and fetches validated logs into shared/_captures/. VT-d requires an Intel host with an isolated NIC and may reboot once to enable IOMMU.

## setup once

```bash
./setup.sh
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

## app

```bash
./run-app.sh
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
