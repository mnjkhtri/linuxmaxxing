#!/usr/bin/env bash
set -euo pipefail

BASE=/work/hyperturtle

QEMU_BIN="$BASE/hyperturtle-qemu/build/qemu-system-x86_64"
IMAGE="$BASE/ubuntu-l1.qcow2"
BIOS="$BASE/bios.bin"
SHARE_DIR="$BASE"

MEM_GIB=64
VCPUS=12
SSH_PORT=2222
QMP_PORT=4444
SERIAL=mon:stdio

PREALLOC=on
DISABLE_THP=1

USE_DIRECT_KERNEL=0
BZIMAGE="$BASE/hyperturtle-linux/arch/x86/boot/bzImage"
KERNEL_APPEND="root=/dev/vda1 rw nokaslr norandmaps console=ttyS0 earlyprintk=serial,ttyS0 ignore_loglevel printk_delay=0 systemd.unified_cgroup_hierarchy=1 nopku noibrs noibpb nospectre_v1 nospectre_v2 no_spectre_v2_user no_stf_barrier l1tf=off mds=off tsx=off tsx_async_abort=off intel_iommu=on transparent_hugepages=never mitigations=off nopti idle=poll isolcpus=1-2"

for f in "$QEMU_BIN" "$IMAGE" "$BIOS"; do
  [[ -e "$f" ]] || { echo "Missing required file: $f" >&2; exit 1; }
done

if [[ "$DISABLE_THP" -eq 1 ]]; then
  echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled >/dev/null
fi

rm -f /tmp/qga.sock

MEMORY_ARGS=(
  -object "memory-backend-ram,size=${MEM_GIB}G,merge=off,prealloc=${PREALLOC},id=m0"
)

NET_ARGS=(
  -netdev "user,id=net0,hostfwd=tcp:0.0.0.0:${SSH_PORT}-:22"
  -device "virtio-net-pci,netdev=net0"
)

HUC_ROOT_PORTS=(
  -device "pcie-root-port,id=hp0,chassis=10,bus=pcie.0,slot=10,hotplug=true"
  -device "pcie-root-port,id=hp1,chassis=11,bus=pcie.0,slot=11,hotplug=true"
  -device "pcie-root-port,id=hp2,chassis=12,bus=pcie.0,slot=12,hotplug=true"
  -device "pcie-root-port,id=hp3,chassis=13,bus=pcie.0,slot=13,hotplug=true"
  -device "pcie-root-port,id=hp4,chassis=14,bus=pcie.0,slot=14,hotplug=true"
  -device "pcie-root-port,id=hp5,chassis=15,bus=pcie.0,slot=15,hotplug=true"
  -device "pcie-root-port,id=hp6,chassis=16,bus=pcie.0,slot=16,hotplug=true"
  -device "pcie-root-port,id=hp7,chassis=17,bus=pcie.0,slot=17,hotplug=true"
)

KERNEL_ARGS=()
if [[ "$USE_DIRECT_KERNEL" -eq 1 ]]; then
  [[ -e "$BZIMAGE" ]] || { echo "Missing bzImage: $BZIMAGE" >&2; exit 1; }
  KERNEL_ARGS=(
    -kernel "$BZIMAGE"
    -append "$KERNEL_APPEND"
  )
fi

echo "[*] Launching L1 for EPT work"
echo "    QEMU:   $QEMU_BIN"
echo "    Image:  $IMAGE"
echo "    BIOS:   $BIOS"
echo "    Memory: ${MEM_GIB}G"
echo "    vCPUs:  $VCPUS"
echo "    SSH:    host port ${SSH_PORT} -> guest 22"
echo "    QMP:    localhost:${QMP_PORT}"

exec "$QEMU_BIN" \
  -serial "$SERIAL" \
  -m "${MEM_GIB}G" \
  -nographic \
  -machine q35,accel=kvm,kernel-irqchip=split \
  -cpu host,migratable=no,pmu=on,+tsc,+tsc-deadline,+rdtscp,+invtsc,+monitor \
  "${MEMORY_ARGS[@]}" \
  "${NET_ARGS[@]}" \
  -drive "file=${IMAGE},if=virtio,format=qcow2" \
  -smp "${VCPUS},sockets=1" \
  -numa "node,nodeid=0,cpus=0-$((VCPUS-1)),memdev=m0" \
  -rtc clock=host \
  -qmp "tcp:localhost:${QMP_PORT},server,nowait" \
  -virtfs "local,path=${SHARE_DIR},mount_tag=hostshare,security_model=none,id=hostshare" \
  -chardev "socket,path=/tmp/qga.sock,server=on,wait=off,id=qga0" \
  -device virtio-serial \
  "${HUC_ROOT_PORTS[@]}" \
  -device "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0" \
  -bios "$BIOS" \
  "${KERNEL_ARGS[@]}"
