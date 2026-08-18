#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(dirname "$(realpath "$0")")
LINUX_DIR="$ROOT_DIR/linux"
QEMU_DIR="$ROOT_DIR/qemu"
IMAGE="$QEMU_DIR/ubuntu-24.04.qcow2"
SEED="$QEMU_DIR/seed.iso"
IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"

die()
{
    echo "setup: error: $*" >&2
    exit 1
}

verify_ubuntu()
{
    [[ "$IMAGE_URL" == *"/noble/"* && "$IMAGE" == *"24.04"* ]] ||
        die "disk image is not Ubuntu 24.04 (noble): $IMAGE_URL"
    echo "setup: disk image Ubuntu 24.04 (noble): $IMAGE"
}

verify_ubuntu

sudo apt update
sudo apt install -y build-essential bc bison flex libssl-dev libelf-dev dwarves clang llvm libbpf-dev bpftool linux-tools-common qemu-system-x86 qemu-utils cloud-image-utils ccache

git submodule update --init --depth 1 linux
git -C "$LINUX_DIR" branch --unset-upstream master 2>/dev/null || true

mkdir -p "$QEMU_DIR"
if [[ ! -f "$IMAGE" ]]; then
  wget "$IMAGE_URL" -O "$IMAGE"
else
  echo "setup: keeping existing $IMAGE"
fi

cloud-localds "$SEED" "$QEMU_DIR/user-data" "$QEMU_DIR/meta-data"

echo "setup: done"
echo "next: ./build.sh"
echo "then: ./boot.sh"
