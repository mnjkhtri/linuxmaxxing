#!/usr/bin/env bash
set -euo pipefail

REMOTE_ROOT="kernel-oops-virt-vtd"
MANAGEMENT_BDF="0000:81:00.0"
CANDIDATE_BDF="0000:81:00.1"
MANAGEMENT_INTERFACE="eno1"
CANDIDATE_INTERFACE="eno2"

# The local entry point stages the current sources, starts the remote workload, and fetches its capture.
dispatch_to_cloudlab()
{
    local script_dir repo_root mode bdf target_file target
    local ssh_options=(
        -o BatchMode=yes
        -o ConnectTimeout=10
        -o ServerAliveInterval=10
        -o ServerAliveCountMax=3
        -o StrictHostKeyChecking=no
    )

    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    repo_root="$(cd -- "$script_dir/../../.." && pwd)"
    mode="${1:-phase-a}"
    bdf="${2:-${1:-}}"

    if [[ "$mode" == "$CANDIDATE_BDF" ]]; then
        mode="phase-a"
        bdf="$CANDIDATE_BDF"
    fi

    [[ "$mode" == phase-a || "$mode" == phase-b ]] || {
        echo "usage: $0 [phase-a|phase-b] $CANDIDATE_BDF" >&2
        exit 2
    }
    [[ "$bdf" == "$CANDIDATE_BDF" ]] || {
        echo "usage: $0 [phase-a|phase-b] $CANDIDATE_BDF" >&2
        exit 2
    }

    target_file="${VIRT_TARGET_FILE:-$script_dir/../cloudlab}"
    target="$(sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$target_file")"
    [[ -n "$target" ]] || {
        echo "error: empty CloudLab target" >&2
        exit 1
    }

    # run.sh stages the current experiment sources and executes the remote workload.
    ssh "${ssh_options[@]}" "$target" "mkdir -p '$REMOTE_ROOT'"
    scp -p "${ssh_options[@]}" "$script_dir/run.sh" "$target:$REMOTE_ROOT/run.sh"
    if [[ "$mode" == phase-b ]]; then
        scp -p "${ssh_options[@]}" \
            "$script_dir/Makefile" \
            "$script_dir/vtd_event.h" \
            "$script_dir/vtd.bpf.c" \
            "$script_dir/observer.c" \
            "$repo_root/shared/json_writer.c" \
            "$repo_root/shared/json_writer.h" \
            "$target:$REMOTE_ROOT/"
    fi

    ssh "${ssh_options[@]}" "$target" \
        "chmod 700 '$REMOTE_ROOT/run.sh' && '$REMOTE_ROOT/run.sh' --remote '$mode' '$bdf'"
    mkdir -p "$repo_root/shared/_captures"
    scp -p "${ssh_options[@]}" \
        "$target:$REMOTE_ROOT/runtime/virt-vtd.assignment.ndjson" \
        "$target:$REMOTE_ROOT/runtime/virt-vtd.eBPF.ndjson" \
        "$repo_root/shared/_captures/"
    exit 0
}

if [[ "${1:-}" != "--remote" ]]; then
    dispatch_to_cloudlab "$@"
fi

mode="${2:-phase-a}"
bdf="${3:-}"
[[ "$bdf" == "$CANDIDATE_BDF" ]] || {
    echo "error: only candidate $CANDIDATE_BDF is permitted" >&2
    exit 2
}

experiment_root="$HOME/$REMOTE_ROOT"
qemu_dir="$experiment_root/qemu"
runtime_dir="$experiment_root/runtime"
base_image="$qemu_dir/ubuntu-24.04.qcow2"
seed_image="$qemu_dir/seed.iso"
overlay="$runtime_dir/vtd-overlay.qcow2"
assignment_capture="$runtime_dir/virt-vtd.assignment.ndjson"
ebpf_capture="$runtime_dir/virt-vtd.eBPF.ndjson"
qemu_output="$runtime_dir/qemu.log"
guest_pci="$runtime_dir/guest-pci.txt"
observer_status=""

qemu_pid=""
observer_pid=""
assignment_started=0
guest_bdf=""
guest_driver=""
guest_interface=""
guest_bars=null
guest_msix=null

# The driver symlink is the authoritative current owner of a host PCI function.
pci_driver()
{
    basename "$(readlink -f "/sys/bus/pci/devices/$1/driver" 2>/dev/null)"
}

# Linux exposes the assignment isolation boundary through each PCI device's IOMMU group.
iommu_group()
{
    local group

    for group in /sys/kernel/iommu_groups/*; do
        if [[ -e "$group/devices/$1" ]]; then
            basename "$group"
            return
        fi
    done
}

# Phase-A records preserve ownership and guest-enumeration facts that do not originate from eBPF.
record_assignment()
{
    local kind="$1"
    local source owner host_driver vfio_bound qemu_attached guest_present
    local observed_guest_bdf=""
    local observed_guest_driver=""
    local observed_guest_interface=""
    local bars_json=null
    local msix_present=null
    local sequence timestamp

    case "$kind" in
        host_owns_device|host_reclaims_device)
            source=host_sysfs
            owner=ixgbe
            host_driver=ixgbe
            vfio_bound=false
            qemu_attached=false
            guest_present=false
            ;;
        vfio_bound)
            source=host_sysfs
            owner=vfio-pci
            host_driver=vfio-pci
            vfio_bound=true
            qemu_attached=false
            guest_present=false
            ;;
        qemu_attached)
            source=qemu
            owner=vfio-pci
            host_driver=vfio-pci
            vfio_bound=true
            qemu_attached=true
            guest_present=false
            ;;
        guest_visible)
            source=guest_pci
            owner="guest ixgbe"
            host_driver=vfio-pci
            vfio_bound=true
            qemu_attached=true
            guest_present=true
            observed_guest_bdf="$guest_bdf"
            observed_guest_driver="$guest_driver"
            observed_guest_interface="$guest_interface"
            bars_json="$guest_bars"
            msix_present="$guest_msix"
            ;;
        *)
            echo "error: unknown Phase-A observation: $kind" >&2
            return 1
            ;;
    esac

    sequence="$(( $(wc -l < "$assignment_capture") + 1 ))"
    timestamp="$(date +%s%N)"

    jq -cn \
        --arg kind "$kind" \
        --arg source "$source" \
        --argjson seq "$sequence" \
        --argjson time_ns "$timestamp" \
        --arg host_driver "$host_driver" \
        --arg owner "$owner" \
        --argjson vfio_bound "$vfio_bound" \
        --argjson qemu_attached "$qemu_attached" \
        --argjson guest_present "$guest_present" \
        --arg guest_bdf "$observed_guest_bdf" \
        --arg guest_driver "$observed_guest_driver" \
        --arg guest_interface "$observed_guest_interface" \
        --argjson bars "$bars_json" \
        --argjson msix_present "$msix_present" \
        '{
            schema_version: 2,
            experiment: "virt-vtd",
            kind: $kind,
            source: $source,
            seq: $seq,
            time_ns: $time_ns,
            event_info: {phase: "A", observation: $kind},
            context: {pid: null, tid: null, cpu: null, comm: null},
            state: {
                assignment: {
                    owner: $owner,
                    host_driver: $host_driver,
                    vfio_bound: $vfio_bound,
                    qemu_attached: $qemu_attached
                },
                guest_device: {
                    present: $guest_present,
                    guest_bdf: (if $guest_present then $guest_bdf else null end),
                    driver: (if $guest_present then $guest_driver else null end),
                    interface: (if $guest_present and $guest_interface != "" then $guest_interface else null end),
                    bars: $bars,
                    msix_present: $msix_present
                }
            }
        }' >> "$assignment_capture"
}

# The management assertion protects the SSH/default-route function before and after every ownership change.
assert_management_path()
{
    [[ -e "/sys/class/net/$MANAGEMENT_INTERFACE" ]] || return 1
    [[ "$(ip route show default | awk 'NR==1 {print $5}')" == "$MANAGEMENT_INTERFACE" ]] || return 1
    [[ "$(basename "$(readlink -f "/sys/class/net/$MANAGEMENT_INTERFACE/device")")" == "$MANAGEMENT_BDF" ]] || return 1
    [[ "$(pci_driver "$MANAGEMENT_BDF")" == ixgbe ]] || return 1
}

# Phase B starts observing before any ownership or IOMMU state changes.
start_observer()
{
    local observer_ready=0

    [[ "$mode" == phase-b ]] || return 0
    make -C "$experiment_root" SHARED_DIR="$experiment_root" clean all >/dev/null
    observer_status="$(mktemp "$runtime_dir/.observer-status.XXXXXX")"
    sudo -n "$experiment_root/build/vtd" > "$ebpf_capture" 2> "$observer_status" &
    observer_pid=$!

    for _ in $(seq 1 50); do
        if grep -q '^LX_READY' "$observer_status"; then
            observer_ready=1
            break
        fi
        kill -0 "$observer_pid" 2>/dev/null || break
        sleep 0.1
    done
    if ((observer_ready == 0)); then
        echo "vtd observer failed to start" >&2
        cat "$observer_status" >&2
        return 1
    fi
}

# The safety audit proves that only the unused candidate function is eligible for assignment.
audit_candidate()
{
    # This is the final read-only gate before candidate ownership changes.
    assert_management_path || {
        echo "safety failure: management path is not eno1 -> 81:00.0 -> ixgbe" >&2
        return 1
    }
    [[ "$(basename "$(readlink -f "/sys/class/net/$CANDIDATE_INTERFACE/device")")" == "$bdf" ]] || {
        echo "safety failure: eno2 does not resolve to $bdf" >&2
        return 1
    }
    [[ "$(pci_driver "$bdf")" == ixgbe ]] || {
        echo "safety failure: candidate is not ixgbe-bound" >&2
        return 1
    }
    [[ -z "$(ip -o addr show dev "$CANDIDATE_INTERFACE" | awk '{print $4}')" ]] || {
        echo "safety failure: eno2 has an address" >&2
        return 1
    }
    [[ -z "$(ip route show dev "$CANDIDATE_INTERFACE")" ]] || {
        echo "safety failure: eno2 carries a route" >&2
        return 1
    }
    [[ ! -e "/sys/class/net/$CANDIDATE_INTERFACE/master" ]] || {
        echo "safety failure: eno2 has a network master" >&2
        return 1
    }
    [[ "$(iommu_group "$bdf")" == 13 ]] || {
        echo "safety failure: candidate is not isolated in group 13" >&2
        return 1
    }
    [[ "$(iommu_group "$MANAGEMENT_BDF")" == 12 ]] || {
        echo "safety failure: management function moved groups" >&2
        return 1
    }
    grep -qw flr "/sys/bus/pci/devices/$bdf/reset_method" 2>/dev/null || {
        echo "safety failure: function-local FLR is unavailable" >&2
        return 1
    }
    [[ -e "/sys/bus/pci/devices/$bdf/reset" ]] || {
        echo "safety failure: PCI reset interface is unavailable" >&2
        return 1
    }

}

# This targeted override transfers only the audited candidate to vfio-pci.
bind_candidate_to_vfio()
{
    sudo -n modprobe vfio-pci
    printf '%s\n' vfio-pci | sudo -n tee "/sys/bus/pci/devices/$bdf/driver_override" >/dev/null
    echo "$bdf" | sudo -n tee /sys/bus/pci/drivers/ixgbe/unbind >/dev/null
    echo "$bdf" | sudo -n tee /sys/bus/pci/drivers/vfio-pci/bind >/dev/null
    assignment_started=1

    [[ "$(pci_driver "$bdf")" == vfio-pci ]] || {
        echo "assignment failure: candidate did not bind vfio-pci" >&2
        return 1
    }
    assert_management_path || {
        echo "CRITICAL: management assertion failed after candidate bind" >&2
        return 1
    }
}

# QEMU receives the physical function while retaining a separate virtio management network.
start_qemu()
{
    local qemu_command=(
        sudo -n qemu-system-x86_64
        -machine q35,accel=kvm
        -cpu host
        -m 2G
        -smp 2
        -drive "if=virtio,format=qcow2,file=$overlay"
        -drive "if=virtio,format=raw,media=cdrom,file=$seed_image"
        -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:2222-:22
        -device virtio-net-pci,netdev=mgmt
        -device "vfio-pci,host=$bdf"
        -display none
        -monitor none
        -serial "file:$qemu_output"
        -no-reboot
    )

    "${qemu_command[@]}" &
    qemu_pid=$!
    sleep 2
    kill -0 "$qemu_pid" 2>/dev/null || {
        echo "QEMU failed to stay running" >&2
        return 1
    }
}

# Guest PCI inspection proves that the assigned physical function is visible and bound to ixgbe.
collect_guest_proof()
{
    local guest_probe guest_ready=0
    local ssh_command=(
        sshpass -p test ssh
        -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null
        -p 2222
        test@127.0.0.1
    )

    for _ in $(seq 1 60); do
        if "${ssh_command[@]}" true >/dev/null 2>&1; then
            guest_ready=1
            break
        fi
        sleep 1
    done
    [[ "$guest_ready" == 1 ]] || {
        echo "guest proof failure: SSH did not become ready" >&2
        return 1
    }

    read -r -d '' guest_probe <<'GUEST' || true
lspci -Dnnk
echo "-- target --"
bdf=$(lspci -Dnn | awk '/8086:10fb/{print $1; exit}')
lspci -Dnnk -s "$bdf"
echo "-- verbose --"
sudo -n lspci -Dvv -s "$bdf"
echo "-- interfaces --"
for interface_path in /sys/class/net/*; do
    [ -e "$interface_path/device" ] || continue
    [ "$(cat "$interface_path/device/vendor" 2>/dev/null)" = 0x8086 ] || continue
    [ "$(cat "$interface_path/device/device" 2>/dev/null)" = 0x10fb ] || continue
    interface=$(basename "$interface_path")
    echo "$interface"
    ethtool -i "$interface"
done
GUEST

    "${ssh_command[@]}" "$guest_probe" > "$guest_pci"
    guest_bdf="$(sed -n '/-- target --/{n; s/^\([^ ]*\).*/\1/p;}' "$guest_pci" | head -n1)"
    guest_driver="$(awk '/-- target --/{on=1; next} on && /Kernel driver in use:/{print $NF; exit}' "$guest_pci")"
    guest_interface="$(awk '/-- interfaces --/{on=1; next} on && /^[a-zA-Z0-9_.-]+$/{candidate=$0} on && /driver: ixgbe/{print candidate; exit}' "$guest_pci")"
    guest_bars="$(awk '/Region [0-9]+:/{sub(/^[[:space:]]*/,""); print}' "$guest_pci" | jq -Rsc 'split("\n") | map(select(length > 0))')"
    guest_msix=false
    grep -q 'MSI-X:' "$guest_pci" && guest_msix=true

    [[ -n "$guest_bdf" ]] || {
        echo "guest proof failure: 8086:10fb was not enumerated" >&2
        return 1
    }
    [[ "$guest_driver" == ixgbe ]] || {
        echo "guest proof failure: assigned device is not ixgbe-bound" >&2
        return 1
    }

    echo "Phase A guest proof: host $bdf -> guest $guest_bdf, driver=$guest_driver, interface=${guest_interface:-not-created}" >&2
}

# The cleanup trap prioritizes hardware restoration on success, failure, SIGINT, and SIGTERM.
cleanup()
{
    local current_driver restored=0

    set +e
    # QEMU exits first so the observer sees VFIO and IOMMU teardown.
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid"
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if [[ -n "$observer_pid" ]] && kill -0 "$observer_pid" 2>/dev/null; then
        kill -INT "$observer_pid"
        wait "$observer_pid" 2>/dev/null || true
    fi
    [[ -z "$observer_status" ]] || rm -f -- "$observer_status"
    if ((assignment_started)); then
        if [[ -e "/sys/bus/pci/devices/$bdf/driver" ]]; then
            current_driver="$(pci_driver "$bdf")"
            if [[ "$current_driver" != ixgbe ]]; then
                echo "$bdf" | sudo -n tee "/sys/bus/pci/drivers/$current_driver/unbind" >/dev/null
            fi
        fi
        printf '\n' | sudo -n tee "/sys/bus/pci/devices/$bdf/driver_override" >/dev/null
        sudo -n modprobe ixgbe
        echo "$bdf" | sudo -n tee /sys/bus/pci/drivers/ixgbe/bind >/dev/null

        [[ "$(pci_driver "$bdf")" == ixgbe ]] && restored=1
        assert_management_path || restored=0
        if ((restored)); then
            record_assignment host_reclaims_device
            echo "host restored: $bdf -> ixgbe; eno1 remains management" >&2
        else
            echo "CRITICAL RESTORE FAILURE" >&2
            echo "sudo sh -c 'echo $bdf > /sys/bus/pci/drivers/vfio-pci/unbind; echo > /sys/bus/pci/devices/$bdf/driver_override; modprobe ixgbe; echo $bdf > /sys/bus/pci/drivers/ixgbe/bind'" >&2
        fi
    fi
    set -e
}

trap cleanup EXIT INT TERM

# Each run uses a fresh overlay while preserving the reusable base image prepared by setup.sh.
mkdir -p "$qemu_dir" "$runtime_dir"
[[ -s "$base_image" ]] || {
    echo "error: base image missing; run setup.sh first" >&2
    exit 1
}
[[ -s "$seed_image" ]] || {
    echo "error: cloud-init seed missing; run setup.sh first" >&2
    exit 1
}
rm -f -- "$overlay" "$assignment_capture" "$ebpf_capture" "$qemu_output" "$guest_pci"
: > "$assignment_capture"
: > "$ebpf_capture"
qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$overlay" >/dev/null

# The outer flow is the experiment outline; each structural stage is called here in order.
start_observer
audit_candidate
record_assignment host_owns_device
bind_candidate_to_vfio
record_assignment vfio_bound
start_qemu
record_assignment qemu_attached
collect_guest_proof
record_assignment guest_visible
