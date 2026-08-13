# LINUXMAXXING

linux internals maxxing in qemu. not a framework. not a product. just captures, kernel code, and visual brain damage.

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
