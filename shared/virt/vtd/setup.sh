#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
TARGET_FILE="${VIRT_TARGET_FILE:-$SCRIPT_DIR/../cloudlab}"
REMOTE_ROOT="kernel-oops-virt-vtd"
IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
LOCAL_CAPTURE_DIR="$REPO_ROOT/shared/_captures"

ssh_options=(
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o ServerAliveInterval=10
    -o ServerAliveCountMax=3
    -o StrictHostKeyChecking=no
)

target_from_file()
{
    sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$TARGET_FILE"
}

target="${1:-$(target_from_file)}"
[[ -n "$target" ]] || {
    echo "error: empty CloudLab target" >&2
    exit 1
}

# Setup stages only reusable cloud-init inputs; it never changes PCI ownership.
ssh "${ssh_options[@]}" "$target" "mkdir -p '$REMOTE_ROOT/qemu' '$REMOTE_ROOT/runtime'"
scp -p "${ssh_options[@]}" \
    "$REPO_ROOT/qemu/user-data" \
    "$REPO_ROOT/qemu/meta-data" \
    "$target:$REMOTE_ROOT/"

ssh "${ssh_options[@]}" "$target" "bash -s -- '$REMOTE_ROOT' '$IMAGE_URL'" <<'REMOTE'
set -euo pipefail

remote_root="$1"
image_url="$2"
qemu_dir="$HOME/$remote_root/qemu"
runtime_dir="$HOME/$remote_root/runtime"
setup_report="$runtime_dir/virt-vtd-setup.txt"
base_image="$qemu_dir/ubuntu-24.04.qcow2"
seed_image="$qemu_dir/seed.iso"

required_commands=(
    qemu-system-x86_64
    qemu-img
    cloud-localds
    lspci
    ip
    curl
    sshpass
    clang
    bpftool
    pkg-config
    jq
)

missing=()
for command_name in "${required_commands[@]}"; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
done

if ((${#missing[@]})); then
    sudo -n apt-get update
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        qemu-system-x86 qemu-utils cloud-image-utils pciutils iproute2 \
        curl sshpass clang llvm bpftool libbpf-dev pkg-config jq
fi

if [[ ! -s "$base_image" ]]; then
    curl --fail --location --retry 2 --output "$base_image.tmp" "$image_url"
    mv -- "$base_image.tmp" "$base_image"
fi

if [[ ! -s "$seed_image" ]]; then
    cloud-localds "$seed_image" "$HOME/$remote_root/user-data" "$HOME/$remote_root/meta-data"
fi

qemu-system-x86_64 --version | head -n1
qemu-img --version | head -n1

host_name=$(hostname)
host_kernel=$(uname -r)
host_os=$(sed -n 's/^PRETTY_NAME="\(.*\)"/\1/p' /etc/os-release)
kernel_cmdline=$(cat /proc/cmdline)
management_driver=$(basename "$(readlink -f /sys/bus/pci/devices/0000:81:00.0/driver)")
candidate_driver=$(basename "$(readlink -f /sys/bus/pci/devices/0000:81:00.1/driver)")
management_group=$(basename "$(readlink -f /sys/bus/pci/devices/0000:81:00.0/iommu_group)")
candidate_group=$(basename "$(readlink -f /sys/bus/pci/devices/0000:81:00.1/iommu_group)")
default_interface=$(ip route show default | awk 'NR == 1 { print $5 }')
dmar_present=false
[[ -e /sys/firmware/acpi/tables/DMAR ]] && dmar_present=true

{
    echo "VT-d setup"
    echo
    echo "[host]"
    echo "hostname=$host_name"
    echo "os=$host_os"
    echo "kernel=$host_kernel"
    echo "cmdline=$kernel_cmdline"
    echo "qemu_version=$(qemu-system-x86_64 --version | head -n1)"
    echo "kvm_device=/dev/kvm"
    echo "dmar_present=$dmar_present"
    echo
    echo "[management_device]"
    echo "bdf=0000:81:00.0"
    echo "interface=eno1"
    echo "driver=$management_driver"
    echo "iommu_group=$management_group"
    echo "default_route_interface=$default_interface"
    echo "protected=true"
    echo
    echo "[candidate_device]"
    echo "bdf=0000:81:00.1"
    echo "interface=eno2"
    echo "driver=$candidate_driver"
    echo "iommu_group=$candidate_group"
    echo "reset_methods=$(cat /sys/bus/pci/devices/0000:81:00.1/reset_method)"
    echo "vendor_device=8086:10fb"
    echo "name=Intel 82599ES 10-Gigabit SFI/SFP+ Network Connection"
    echo
    echo "[tracepoints]"
    for event in map unmap attach_device_to_domain io_page_fault; do
        present=false
        sudo -n test -r "/sys/kernel/tracing/events/iommu/$event/format" && present=true
        echo "iommu_$event=$present"
    done
    echo
    echo "[iommu_groups]"
    for group_path in /sys/kernel/iommu_groups/*; do
        group=$(basename "$group_path")
        for device_path in "$group_path"/devices/*; do
            [[ -e "$device_path" ]] || continue
            echo "group=$group bdf=$(basename "$device_path")"
        done
    done
    echo
    echo "[pci]"
    lspci -Dnnk -s 0000:81:00.0
    lspci -Dnnk -s 0000:81:00.1
    echo
    echo "[network]"
    ip -br link
    ip -br addr
    ip route
} > "$setup_report"

echo "VT-d host setup complete; report: $setup_report"
REMOTE

mkdir -p "$LOCAL_CAPTURE_DIR"
scp -p "${ssh_options[@]}" \
    "$target:$REMOTE_ROOT/runtime/virt-vtd-setup.txt" \
    "$LOCAL_CAPTURE_DIR/virt-vtd-setup.txt"
