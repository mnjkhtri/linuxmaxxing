#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
TARGET_FILE="${VIRT_TARGET_FILE:-$SCRIPT_DIR/../cloudlab}"
REMOTE_ROOT="linuxmaxxing-virt-vtd"
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

wait_for_reboot()
{
    local target="$1"
    local online=0

    sleep 8
    for _ in $(seq 1 90); do
        if ssh "${ssh_options[@]}" "$target" true >/dev/null 2>&1; then
            online=1
            break
        fi
        sleep 5
    done
    ((online)) || {
        echo "VT-d setup failure: CloudLab node did not return after reboot" >&2
        return 1
    }
}

ensure_dma_remapping_boot()
{
    local target="$1"
    local group_count

    group_count="$(ssh "${ssh_options[@]}" "$target" "find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l")"
    ((group_count > 0)) && return 0
    ssh "${ssh_options[@]}" "$target" "grep -q GenuineIntel /proc/cpuinfo" || {
        echo "VT-d setup failure: automatic boot configuration currently supports Intel hosts only" >&2
        return 1
    }
    ssh "${ssh_options[@]}" "$target" "sudo -n install -d -m 0755 /etc/default/grub.d && sudo -n tee /etc/default/grub.d/99-linuxmaxxing-vtd.cfg >/dev/null" <<'GRUB'
GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} intel_iommu=on iommu=pt"
GRUB
    ssh "${ssh_options[@]}" "$target" "sudo -n update-grub >/dev/null && sudo -n reboot" || true
    wait_for_reboot "$target"
    ssh "${ssh_options[@]}" "$target" "grep -qw intel_iommu=on /proc/cmdline && test \"\$(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)\" -gt 0" || {
        echo "VT-d setup failure: DMA-remapping groups are still unavailable after reboot" >&2
        return 1
    }
}

target="${1:-$(target_from_file)}"
[[ -n "$target" ]] || {
    echo "error: empty CloudLab target" >&2
    exit 1
}

ensure_dma_remapping_boot "$target"
ssh "${ssh_options[@]}" "$target" "mkdir -p '$REMOTE_ROOT/qemu' '$REMOTE_ROOT/runtime'"
scp -p "${ssh_options[@]}" "$REPO_ROOT/qemu/user-data" "$REPO_ROOT/qemu/meta-data" "$target:$REMOTE_ROOT/"

ssh "${ssh_options[@]}" "$target" "bash -s -- '$REMOTE_ROOT' '$IMAGE_URL'" <<'REMOTE'
set -euo pipefail

remote_root="$1"
image_url="$2"
qemu_dir="$HOME/$remote_root/qemu"
runtime_dir="$HOME/$remote_root/runtime"
setup_report="$runtime_dir/virt-vtd-setup.txt"
base_image="$qemu_dir/ubuntu-24.04.qcow2"
seed_image="$qemu_dir/seed.iso"

required_commands=(qemu-system-x86_64 qemu-img cloud-localds lspci ip curl sshpass clang bpftool pkg-config jq make cc)
missing=()
for command_name in "${required_commands[@]}"; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
done
pkg-config --exists libbpf 2>/dev/null || missing+=(libbpf-dev)
if ((${#missing[@]})); then
    sudo -n apt-get update
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        qemu-system-x86 qemu-utils cloud-image-utils pciutils iproute2 build-essential \
        curl sshpass clang llvm libbpf-dev pkg-config jq linux-tools-common "linux-tools-$(uname -r)"
fi

if ! mountpoint -q /sys/kernel/tracing; then
    sudo -n mount -t tracefs nodev /sys/kernel/tracing
fi

if [[ ! -s "$base_image" ]]; then
    curl --fail --location --retry 2 --output "$base_image.tmp" "$image_url"
    mv -- "$base_image.tmp" "$base_image"
fi
if [[ ! -s "$seed_image" ]]; then
    cloud-localds "$seed_image" "$HOME/$remote_root/user-data" "$HOME/$remote_root/meta-data"
fi

interface_bdf()
{
    basename "$(readlink -f "/sys/class/net/$1/device")"
}

pci_driver()
{
    basename "$(readlink -f "/sys/bus/pci/devices/$1/driver" 2>/dev/null)"
}

iommu_group()
{
    local link

    link="$(readlink -f "/sys/bus/pci/devices/$1/iommu_group" 2>/dev/null || true)"
    [[ -n "$link" ]] && basename "$link"
}

group_device_count()
{
    find "/sys/kernel/iommu_groups/$1/devices" -mindepth 1 -maxdepth 1 -type l 2>/dev/null | wc -l
}

candidate_is_safe()
{
    local interface="$1"
    local bdf="$2"
    local group

    [[ "$interface" != "$management_interface" ]] || return 1
    [[ -z "$(ip -o addr show dev "$interface" | awk '{print $4}')" ]] || return 1
    [[ -z "$(ip route show dev "$interface")" ]] || return 1
    [[ ! -e "/sys/class/net/$interface/master" ]] || return 1
    [[ -e "/sys/bus/pci/devices/$bdf/reset" ]] || return 1
    grep -qw flr "/sys/bus/pci/devices/$bdf/reset_method" 2>/dev/null || return 1
    group="$(iommu_group "$bdf")"
    [[ -n "$group" && "$group" != "$management_group" ]] || return 1
    [[ "$(group_device_count "$group")" == 1 ]] || return 1
}

select_candidate()
{
    local require_same_driver="$1"
    local path interface bdf driver

    for path in /sys/class/net/*; do
        interface="$(basename "$path")"
        [[ -e "$path/device" ]] || continue
        bdf="$(interface_bdf "$interface")"
        driver="$(pci_driver "$bdf")"
        if ((require_same_driver)) && [[ "$driver" != "$management_driver" ]]; then
            continue
        fi
        if candidate_is_safe "$interface" "$bdf"; then
            printf '%s %s\n' "$interface" "$bdf"
            return 0
        fi
    done
    return 1
}

management_interface="$(ip route show default | awk 'NR == 1 { print $5 }')"
[[ -n "$management_interface" && -e "/sys/class/net/$management_interface/device" ]] || {
    echo "VT-d setup failure: default-route interface is not PCI-backed" >&2
    exit 1
}
management_bdf="$(interface_bdf "$management_interface")"
management_driver="$(pci_driver "$management_bdf")"
management_group="$(iommu_group "$management_bdf")"
[[ -n "$management_group" ]] || {
    echo "VT-d setup failure: management device has no IOMMU group" >&2
    exit 1
}

candidate_pair="$(select_candidate 1 || select_candidate 0 || true)"
[[ -n "$candidate_pair" ]] || {
    echo "VT-d setup failure: no unused, FLR-capable, isolated PCI NIC is eligible" >&2
    exit 1
}
read -r candidate_interface candidate_bdf <<< "$candidate_pair"
candidate_driver="$(pci_driver "$candidate_bdf")"
candidate_group="$(iommu_group "$candidate_bdf")"
candidate_vendor="$(cat "/sys/bus/pci/devices/$candidate_bdf/vendor")"
candidate_device="$(cat "/sys/bus/pci/devices/$candidate_bdf/device")"
candidate_name="$(lspci -D -s "$candidate_bdf" | sed 's/^[^ ]* //')"

host_name="$(hostname)"
host_kernel="$(uname -r)"
host_os="$(sed -n 's/^PRETTY_NAME="\(.*\)"/\1/p' /etc/os-release)"
kernel_cmdline="$(cat /proc/cmdline)"
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
    echo "iommu_groups_present=true"
    echo
    echo "[management_device]"
    echo "bdf=$management_bdf"
    echo "interface=$management_interface"
    echo "driver=$management_driver"
    echo "iommu_group=$management_group"
    echo "default_route_interface=$management_interface"
    echo "protected=true"
    echo
    echo "[candidate_device]"
    echo "bdf=$candidate_bdf"
    echo "interface=$candidate_interface"
    echo "driver=$candidate_driver"
    echo "iommu_group=$candidate_group"
    echo "reset_methods=$(cat "/sys/bus/pci/devices/$candidate_bdf/reset_method")"
    echo "vendor=$candidate_vendor"
    echo "device=$candidate_device"
    echo "vendor_device=${candidate_vendor#0x}:${candidate_device#0x}"
    echo "name=$candidate_name"
    echo "selection=unused_no_address_no_route_no_master_flr_single_device_group"
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
        group="$(basename "$group_path")"
        for device_path in "$group_path"/devices/*; do
            [[ -e "$device_path" ]] || continue
            echo "group=$group bdf=$(basename "$device_path")"
        done
    done
    echo
    echo "[pci]"
    lspci -Dnnk -s "$management_bdf"
    lspci -Dnnk -s "$candidate_bdf"
    echo
    echo "[network]"
    ip -br link
    ip -br addr
    ip route
} > "$setup_report"

echo "VT-d host setup complete: management=$management_interface/$management_bdf candidate=$candidate_interface/$candidate_bdf group=$candidate_group" >&2
REMOTE

mkdir -p "$LOCAL_CAPTURE_DIR"
scp -p "${ssh_options[@]}" "$target:$REMOTE_ROOT/runtime/virt-vtd-setup.txt" "$LOCAL_CAPTURE_DIR/virt-vtd-setup.txt"
