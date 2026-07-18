#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(dirname "$(realpath "$0")")
OVERLAY="$ROOT_DIR/vm/run-overlay.qcow2"
BASE_IMAGE="$ROOT_DIR/vm/ubuntu-24.04.qcow2"
KERNEL_IMAGE="$ROOT_DIR/build/arch/x86/boot/bzImage"

rm -f "$OVERLAY"
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY"

exec qemu-system-x86_64 \
  -m 1024 \
  -smp 1 \
  -kernel "$KERNEL_IMAGE" \
  -append "root=/dev/vda1 console=ttyS0 rootwait rw loglevel=4 printk.time=0 selinux=0 systemd.unit=rescue.target" \
  -drive file="$OVERLAY",if=virtio,format=qcow2 \
  -virtfs local,path="$ROOT_DIR/shared",mount_tag=hostshare,security_model=none,id=hostshare \
  -device edu \
  -nographic \
  -no-reboot
