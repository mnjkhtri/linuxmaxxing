#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(dirname "$(realpath "$0")")
OVERLAY="$ROOT_DIR/qemu/run-overlay.qcow2"
SWAP_IMAGE="$ROOT_DIR/qemu/run-swap.raw"
BASE_IMAGE="$ROOT_DIR/qemu/ubuntu-24.04.qcow2"
KERNEL_IMAGE="$ROOT_DIR/build/arch/x86/boot/bzImage"

rm -f "$OVERLAY"
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY"
truncate -s 128M "$SWAP_IMAGE"
chmod 600 "$SWAP_IMAGE"
mkswap --quiet --force --label linuxmaxxing-swap "$SWAP_IMAGE"

exec qemu-system-x86_64 \
  -m 1024 \
  -smp 2 \
  -kernel "$KERNEL_IMAGE" \
  -append "root=/dev/vda1 console=ttyS0 rootwait rw loglevel=4 printk.time=0 selinux=0 systemd.unit=rescue.target systemd.swap-extra=/dev/vdb" \
  -drive file="$OVERLAY",if=virtio,format=qcow2 \
  -drive file="$SWAP_IMAGE",if=virtio,format=raw \
  -virtfs local,path="$ROOT_DIR/shared",mount_tag=hostshare,security_model=none,id=hostshare \
  -device edu \
  -nographic \
  -no-reboot
