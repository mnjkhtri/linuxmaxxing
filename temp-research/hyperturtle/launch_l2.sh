#!/usr/bin/env bash
set -euo pipefail

QEMU_BIN="/opt/kata/bin/qemu-system-x86_64"
if [[ ! -x "$QEMU_BIN" ]]; then
    QEMU_BIN="qemu-system-x86_64"
fi

IMAGE="/home/ubuntu/shared_folder/base-focal.img"
SEED="/home/ubuntu/shared_folder/seed.iso"
SHARE_DIR="/home/ubuntu/shared_folder/benchmarks"

MEM_MB=2048
VCPUS=1

echo "[*] Launching raw L2 (Pure QEMU) for EPT testing"
echo "    QEMU:   $QEMU_BIN"
echo "    Memory: ${MEM_MB}MB (Backed by /dev/shm)"

exec "$QEMU_BIN" \
  -vga none \
  -nic none \
  -serial mon:stdio \
  -nographic \
  -machine q35,accel=kvm \
  -cpu host,pmu=on \
  -m "${MEM_MB}M" \
  -object "memory-backend-file,id=mem0,size=${MEM_MB}M,mem-path=/dev/shm,share=on" \
  -numa "node,memdev=mem0" \
  -drive "file=${IMAGE},if=virtio,format=qcow2" \
  -drive "file=${SEED},if=virtio,format=raw" \
  -smp "${VCPUS}" \
  -virtfs "local,path=${SHARE_DIR},mount_tag=benchmount,security_model=none,id=benchshare"
