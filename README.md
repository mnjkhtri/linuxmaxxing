# kernel-oops

Build and run a custom Linux kernel in QEMU.

## Layout

```text
app/        Static visualization frontend.
shared/_work/  Guest programs and scripts that trigger study hooks.
  fork_25_processes     Process and scheduler workload.
  exercise_memory_management        Memory-management workload.
shared/modules/     Out-of-tree study modules.
shared/miscdriver/ Misc character driver.
shared/pci/        QEMU EDU PCI driver.
shared/_captures/  Flat generated capture files, prefixed by producer.
vm/         QEMU disk images, overlays, and cloud-init seed files.
linux/      Linux source tree.
build/  Out-of-tree kernel build output.
```

## Workloads

Build the compiled workloads once from the repository root:

```bash
make -C shared/_work
```

## Dependencies

Install the kernel build tools, QEMU, cloud-image utilities, and `ccache` for
faster rebuilds.

```bash
sudo apt update
sudo apt install -y \
  build-essential bc bison flex libssl-dev libelf-dev dwarves clang llvm \
  libbpf-dev linux-tools-common qemu-system-x86 qemu-utils \
  cloud-image-utils ccache
```

`linux/` is a Git submodule pointing at upstream Linux. Build output stays separate in `build/`.

```bash
git submodule update --init --depth 1 linux
mkdir -p build shared vm
```

Move the kernel forward by updating the submodule checkout:

```bash
cd linux
git fetch --depth 1 origin master
git checkout origin/master
cd ..
git add linux
```

## Configure And Build

```bash
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

## Shared Folder

The boot script exposes host `shared/` to the guest with the 9p mount tag `hostshare`.

Inside QEMU:

```bash
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
```

## Subsystem Studies

- [Tracing studies](shared/tracing/README.md)
- [Memory state and trace observer](shared/mm/README.md)
- [CFS eBPF tree visualizer](shared/ebpf/README.md)
- [External kernel modules](shared/modules/README.md)
- [Misc character driver](shared/miscdriver/README.md)
- [QEMU EDU PCI driver](shared/pci/README.md)

## App

The static frontend visualizes captures under `shared/_captures/`. Start it from the repository root with `PORT=8001 ./run-app.sh` when port 8000 is busy, then open `http://localhost:8000/app/`.

## Quit QEMU

With `-nographic`:

| Action | Command |
|---|---|
| Quit QEMU | `Ctrl-a`, then `x` |
| Open QEMU monitor | `Ctrl-a`, then `c` |
| Quit from monitor | `quit` |
