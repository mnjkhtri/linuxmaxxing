# kernel-oops

Build and run a custom Linux kernel in QEMU. Hook details are in [`docs/hooks.md`](docs/hooks.md).

## Layout

```text
app/        Static visualization frontend.
docs/       Notes about kernel instrumentation hooks.
shared/workloads/  Guest programs and scripts that trigger study hooks.
  core/          Process and scheduler workload.
  mm/            Memory-management workload.
  vfs/run.sh     Shared filesystem and block-I/O workload.
shared/modules/     Out-of-tree study modules.
shared/miscdriver/ Misc character driver.
shared/pci/        QEMU EDU PCI driver.
shared/_captures/  Flat generated capture files, prefixed by producer.
vm/         QEMU disk images, overlays, and cloud-init seed files.
downloads/  Downloaded source archives.
linux/      Linux source tree.
build-x86/  Out-of-tree kernel build output.
```

## Dependencies

Install the kernel build tools, QEMU, cloud-image utilities, and `ccache` for faster rebuilds.

```bash
sudo apt update
sudo apt install -y \
  build-essential bc bison flex libssl-dev libelf-dev dwarves \
  qemu-system-x86 qemu-utils cloud-image-utils ccache
```

## Kernel Source

Download and unpack Linux 6.6.30 into `linux/`, while keeping build output separate in `build-x86/`.

```bash
mkdir -p linux build-x86 shared downloads vm
wget -O downloads/linux-6.6.30.tar.xz https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.6.30.tar.xz
tar -xf downloads/linux-6.6.30.tar.xz -C linux --strip-components=1
```

## Configure And Build

Generate a default x86 config, accept any config updates, then build with the helper script.

```bash
make -C linux O=../build-x86 defconfig
make -C linux O=../build-x86 oldconfig
./build.sh
```

## Rootfs

Use an Ubuntu cloud image as the guest disk and create a seed ISO for cloud-init data.

```bash
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img -O vm/ubuntu-24.04.qcow2
cloud-localds vm/seed.iso vm/user-data vm/meta-data
```

## Boot

`boot.sh` starts the custom kernel with a disposable overlay disk.

```bash
./boot.sh
```

It skips normal init and drops directly into `/bin/bash` for quick kernel-debug loops.
It keeps the console quiet with `quiet loglevel=4`, so the custom `pr_info()` study records stay in the kernel ring buffer instead of flooding the serial console. The boot script sets `log_buf_len=128M` because the custom hooks can generate enough printk traffic to wrap the default kernel log buffer quickly.

## Shared Folder

The boot script exposes host `shared/` to the guest with the 9p mount tag `hostshare`.

Inside QEMU:

```bash
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
```

## Kernel Hook Studies

Study modes are mutually exclusive kernel config choices. Select one before building.

### None

```bash
./study-mode.sh none
./build.sh
```

### Core

The process and scheduler workload lives in `shared/workloads/core/`; captures use the `shared/_captures/core-*.txt` prefix.

```bash
./study-mode.sh core
./build.sh
x86_64-linux-gnu-gcc -O2 -Wall -static -o shared/workloads/core/workload shared/workloads/core/workload.c
```

Inside QEMU:

```bash
/mnt/host/workloads/core/workload
mkdir -p /mnt/host/_captures
dmesg | grep LIFE > /mnt/host/_captures/core-hook-lifecycle.txt
dmesg | grep CFS > /mnt/host/_captures/core-hook-cfs-rbtree.txt
```

### MM

The memory workload lives in `shared/workloads/mm/`; captures use the `shared/_captures/mm-*.txt` prefix.

```bash
./study-mode.sh mm
./build.sh
x86_64-linux-gnu-gcc -O2 -Wall -static -pthread -o shared/workloads/mm/workload shared/workloads/mm/workload.c
```

Inside QEMU:

```bash
/mnt/host/workloads/mm/workload
mkdir -p /mnt/host/_captures
dmesg | grep ALLOC > /mnt/host/_captures/mm-hook-allocpages.txt
dmesg | grep SLAB > /mnt/host/_captures/mm-hook-slab.txt
dmesg | grep ADDR > /mnt/host/_captures/mm-hook-address-space.txt
```

### VFS

The shared workload at `shared/workloads/vfs/run.sh` exercises procfs, sysfs, tmpfs, regular file I/O, and the block layer. One VFS mode enables both filesystem and block hooks so a single run captures the complete storage path.

```bash
./study-mode.sh vfs
./build.sh
```

Inside QEMU:

```bash
sh /mnt/host/workloads/vfs/run.sh
mkdir -p /mnt/host/_captures
dmesg | grep SUPER > /mnt/host/_captures/vfs-hook-super.txt
dmesg | grep INODE > /mnt/host/_captures/vfs-hook-inode.txt
dmesg | grep DENTRY > /mnt/host/_captures/vfs-hook-dentry.txt
dmesg | grep BLOCK > /mnt/host/_captures/vfs-hook-block-io.txt
```

## External Modules

Module tools live in `shared/modules/`. Each module has its own source/build folder under `shared/modules/`; captures are stored as `shared/_captures/core-module-tasks.txt` and `shared/_captures/mm-module-allocators.txt`.

```bash
./study-mode.sh none
./build.sh
make -C shared/modules
```

Inside QEMU:

```bash
sh /mnt/host/modules/w.sh core
sh /mnt/host/modules/w.sh mm
mkdir -p /mnt/host/_captures
dmesg | grep KOOPS_CORE > /mnt/host/_captures/core-module-tasks.txt
dmesg | grep KOOPS_MM > /mnt/host/_captures/mm-module-allocators.txt
```

## Misc Driver

The simple misc character driver lives in `shared/miscdriver/` and creates `/dev/llkd_miscdrv`.

Build it against the custom kernel:

```bash
make -C shared/miscdriver
```

Inside QEMU, load and smoke-test it with:

```bash
sh /mnt/host/miscdriver/w.sh
```

Unload it explicitly when needed:

```bash
rmmod llkd_miscdrv
```

## PCI

Detailed driver architecture and userspace behavior are documented in
[`shared/pci/README.md`](shared/pci/README.md).
The QEMU EDU PCI driver lives in `shared/pci/`. `boot.sh` creates its matching `1234:11e8` device with `-device edu`.

Build the driver against the custom kernel:

```bash
make -C shared/pci
```

Inside QEMU, load it with the dedicated runner:

```bash
sh /mnt/host/pci/w.sh
```

The runner leaves `qedu` loaded so it remains bound while testing BARs, interrupts, and DMA. Unload it explicitly when needed:

```bash
rmmod qedu
```

## Quit QEMU

With `-nographic`:

| Action | Command |
|---|---|
| Quit QEMU | `Ctrl-a`, then `x` |
| Open QEMU monitor | `Ctrl-a`, then `c` |
| Quit from monitor | `quit` |

## App

The app visualizes text captures collected under `shared/`.

```text
app/
  index.html        Main shell with visualization tabs.
  theme.css         Shared theme tokens used by the shell.
  views/            Subsystem visualization pages.
    core.html       Core subsystem viewer for lifecycle and CFS captures.
    mm.html         Memory allocator and slab viewer.
    block.html      Block I/O BIO/request flow viewer.
    fs.html         Superblock, inode, and dentry viewer.
```

Start the web server from the repository root:

```bash
./run-app.sh
```

Open:

```text
http://localhost:8000/app/
```

If port `8000` is busy, use another port, for example `8001`.
