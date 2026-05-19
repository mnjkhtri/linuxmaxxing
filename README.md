# kernel-oops

Build and experiment with a custom Linux kernel.

## Setup

### 1. Install build dependencies

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  bc \
  bison \
  flex \
  libssl-dev \
  libelf-dev \
  dwarves
```

| Package           | Purpose                                  |
| ----------------- | ---------------------------------------- |
| `build-essential` | GCC, `make`, linker, core build tools    |
| `bc`              | Build-script calculations                |
| `bison`           | Generates parsers for build/config tools |
| `flex`            | Generates lexers for build/config tools  |
| `libssl-dev`      | Certificates, signing, crypto host tools |
| `libelf-dev`      | ELF/module/BPF-related host tools        |
| `dwarves`         | Provides `pahole` for BTF debug info     |

### 2. Create directory layout

```bash
mkdir -p linux build-x86
```

### 3. Download kernel source

```bash
wget -O linux-6.6.30.tar.xz https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.6.30.tar.xz
```

### 4. Extract kernel source into `linux/`

```bash
tar -xf linux-6.6.30.tar.xz -C linux --strip-components=1
```

## Configuration

Generate the default x86 configuration:

```bash
make O=../build-x86 defconfig
```

Review and update configuration:

```bash
make O=../build-x86 oldconfig
```

## Build

Build the kernel with the repo helper. It keeps `build-x86/` intact for incremental builds and uses `ccache` automatically when available:

```bash
sudo apt install -y ccache
ccache --max-size=10G
ccache --show-stats

./build.sh
```

You can pass any kernel make target through the script:

```bash
./build.sh arch/x86/boot/bzImage
```

## Rootfs

Install QEMU and cloud image utilities:

```bash
sudo apt install -y qemu-system-x86 qemu-utils cloud-image-utils
```

Create an ext4 disk image with a minimal Ubuntu rootfs:

```bash
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img -O ubuntu-24.04.qcow2
```

Cloud images don't have password login by default, so create a seed ISO from the [`user-data`](user-data) file:

```bash
cloud-localds seed.iso user-data meta-data
```

## Boot The Custom Kernel

Use `./boot.sh` to create a fresh overlay and boot the custom kernel. The script contains the full QEMU command and keeps the guest state disposable across runs.

| File | Purpose |
| ---- | ------- |
| `boot.sh` | Recreates `run-overlay.qcow2` from `ubuntu-24.04.qcow2` and boots `build-x86/arch/x86/boot/bzImage` with the required QEMU flags. |
| `boot-fast.sh` | Recreates a separate fast overlay and boots into `/bin/bash` with no cloud-init or guest networking for the shortest debug loop. |

Run it with:

```bash
./boot.sh
```

For the aggressive fast path:

```bash
./boot-fast.sh
```

### Quit QEMU

When running with `-nographic`, QEMU uses its terminal escape sequence instead of a graphical window.

| Action | Command |
| ------ | ------- |
| Quit QEMU immediately | `Ctrl-a`, then `x` |
| Open the QEMU monitor | `Ctrl-a`, then `c` |
| Quit from the QEMU monitor | Type `quit` and press Enter |

In `tmux`, send the same key sequence directly to the QEMU pane: `Ctrl-a` then `x`. If your `tmux` prefix is also `Ctrl-a`, press `Ctrl-a` twice, then `x`.
