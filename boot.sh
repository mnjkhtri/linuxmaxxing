#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")
OVERLAY="$SCRIPT_DIR/run-overlay.qcow2"
BASE_IMAGE="$SCRIPT_DIR/ubuntu-24.04.qcow2"
SEED_IMAGE="$SCRIPT_DIR/seed.iso"
KERNEL_IMAGE="$SCRIPT_DIR/build-x86/arch/x86/boot/bzImage"

rm -f "$OVERLAY"
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY"

exec qemu-system-x86_64 \
  -m 2048 \
  -smp 2 \
  -kernel "$KERNEL_IMAGE" \
  -append "root=/dev/vda1 console=ttyS0 rootwait rw" \
  -drive file="$OVERLAY",if=virtio,format=qcow2 \
  -drive file="$SEED_IMAGE",if=virtio,media=cdrom,format=raw \
  -nic user \
  -nographic \
  -no-reboot
