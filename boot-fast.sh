#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")
OVERLAY="$SCRIPT_DIR/run-fast-overlay.qcow2"
BASE_IMAGE="$SCRIPT_DIR/ubuntu-24.04.qcow2"
KERNEL_IMAGE="$SCRIPT_DIR/build-x86/arch/x86/boot/bzImage"

rm -f "$OVERLAY"
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY"

exec qemu-system-x86_64 \
  -m 1024 \
  -smp 1 \
  -kernel "$KERNEL_IMAGE" \
  -append "root=/dev/vda1 console=ttyS0 rootwait rw init=/bin/bash quiet loglevel=7 systemd.show_status=false rd.systemd.show_status=false printk.time=0" \
  -drive file="$OVERLAY",if=virtio,format=qcow2 \
  -nographic \
  -no-reboot
