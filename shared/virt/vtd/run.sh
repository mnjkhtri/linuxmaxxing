#!/usr/bin/env bash
set -euo pipefail

REMOTE_ROOT="kernel-oops-virt-vtd"

# The local entry point stages the current sources, starts the remote workload, and fetches its capture.
dispatch_to_cloudlab()
{
    local script_dir repo_root target_file target
    local ssh_options=(
        -o BatchMode=yes
        -o ConnectTimeout=10
        -o ServerAliveInterval=10
        -o ServerAliveCountMax=3
        -o StrictHostKeyChecking=no
    )

    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    repo_root="$(cd -- "$script_dir/../../.." && pwd)"
    (($# == 0)) || {
        echo "usage: $0" >&2
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
    scp -p "${ssh_options[@]}" \
        "$script_dir/Makefile" \
        "$script_dir/vtd_event.h" \
        "$script_dir/vtd.bpf.c" \
        "$script_dir/observer.c" \
        "$repo_root/shared/json_writer.c" \
        "$repo_root/shared/json_writer.h" \
        "$target:$REMOTE_ROOT/"

    ssh "${ssh_options[@]}" "$target" "chmod 700 '$REMOTE_ROOT/run.sh' && '$REMOTE_ROOT/run.sh' --remote"
    mkdir -p "$repo_root/shared/_captures"
    scp -p "${ssh_options[@]}" \
        "$target:$REMOTE_ROOT/runtime/virt-vtd.assignment.ndjson" \
        "$target:$REMOTE_ROOT/runtime/virt-vtd.eBPF.ndjson" \
        "$repo_root/shared/_captures/"
    [[ "$(wc -l < "$repo_root/shared/_captures/virt-vtd.assignment.ndjson")" == 5 ]] || {
        echo "capture validation failed: assignment lifecycle is incomplete" >&2
        exit 1
    }
    scp -p "${ssh_options[@]}" "$target:$REMOTE_ROOT/runtime/virt-vtd.guest.ndjson" "$repo_root/shared/_captures/"
    jq -e -s '
            .[0].kind == "capture_meta" and
            .[-1].kind == "capture_summary" and
            any(.[]; .kind == "kvm_memory_region_enter") and
            any(.[]; .kind == "vfio_dma_map_enter") and
            any(.[]; .kind == "iommu_map") and
            any(.[]; .kind == "vfio_dma_map_exit") and
        .[-1].state.ringbuf_dropped == 0 and
            .[-1].state.short_records == 0
    ' "$repo_root/shared/_captures/virt-vtd.eBPF.ndjson" >/dev/null || {
        echo "capture validation failed: Phase-B evidence is incomplete" >&2
        exit 1
    }
    jq -e -s '
            .[0].kind == "capture_meta" and
            .[-1].kind == "capture_summary" and
            any(.[]; .kind == "guest_ixgbe_run_loopback_entry") and
            any(.[]; .kind == "guest_ixgbe_xmit_entry") and
            any(.[]; .kind == "guest_dma_map_exit") and
            any(.[]; .kind == "guest_ixgbe_xmit_exit" and .event_info.result == 0) and
            any(.[]; .kind == "guest_ixgbe_clean_exit" and .state.dma.completed_descriptors >= 64) and
            any(.[]; .kind == "guest_ixgbe_run_loopback_exit" and .event_info.result == 0) and
            ([.[] | select(.kind == "guest_irq_handler_entry")] | length) > 1 and
            ([.[] | select(.kind == "guest_irq_handler_exit")] | length) == ([.[] | select(.kind == "guest_irq_handler_entry")] | length) and
            .[-1].state.ringbuf_dropped == 0 and
            .[-1].state.short_records == 0
    ' "$repo_root/shared/_captures/virt-vtd.guest.ndjson" >/dev/null || {
        echo "capture validation failed: guest DMA-use evidence is incomplete" >&2
        exit 1
    }
    exit 0
}

if [[ "${1:-}" != "--remote" ]]; then
    dispatch_to_cloudlab "$@"
fi

[[ $# == 1 ]] || {
    echo "error: --remote is an internal run.sh argument" >&2
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
guest_capture="$runtime_dir/virt-vtd.guest.ndjson"
guest_workload="$runtime_dir/guest-selftest.txt"
setup_report="$runtime_dir/virt-vtd-setup.txt"
observer_status=""
observer_pid_file=""
qemu_pid_file=""

qemu_pid=""
qemu_job_pid=""
observer_pid=""
observer_job_pid=""
assignment_started=0
guest_bdf=""
guest_driver=""
guest_interface=""
guest_bars=null
guest_msix=null

[[ -s "$setup_report" ]] || {
    echo "error: setup report missing; run setup.sh first" >&2
    exit 1
}

setup_value()
{
    local section="$1"
    local key="$2"

    awk -v section="[$section]" -v key="$key" '
        $0 == section { active=1; next }
        /^\[/ { active=0 }
        active && index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }
    ' "$setup_report"
}

MANAGEMENT_BDF="$(setup_value management_device bdf)"
MANAGEMENT_INTERFACE="$(setup_value management_device interface)"
MANAGEMENT_DRIVER="$(setup_value management_device driver)"
MANAGEMENT_GROUP="$(setup_value management_device iommu_group)"
CANDIDATE_BDF="$(setup_value candidate_device bdf)"
CANDIDATE_INTERFACE="$(setup_value candidate_device interface)"
CANDIDATE_HOST_DRIVER="$(setup_value candidate_device driver)"
CANDIDATE_GROUP="$(setup_value candidate_device iommu_group)"
CANDIDATE_VENDOR="$(setup_value candidate_device vendor)"
CANDIDATE_DEVICE="$(setup_value candidate_device device)"
CANDIDATE_NAME="$(setup_value candidate_device name)"
bdf="$CANDIDATE_BDF"

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

monotonic_time_ns()
{
    local uptime seconds fraction

    read -r uptime _ < /proc/uptime
    seconds="${uptime%%.*}"
    fraction="${uptime#*.}000000000"
    printf '%s%s\n' "$seconds" "${fraction:0:9}"
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
            owner="$CANDIDATE_HOST_DRIVER"
            host_driver="$CANDIDATE_HOST_DRIVER"
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
            owner="guest $guest_driver"
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
    timestamp="$(monotonic_time_ns)"

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
            clock: "monotonic",
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
    [[ "$(pci_driver "$MANAGEMENT_BDF")" == "$MANAGEMENT_DRIVER" ]] || return 1
}

# Phase B starts observing before any ownership or IOMMU state changes.
start_observer()
{
    local observer_ready=0

    # Load the observer's optional VFIO probe targets without binding either PCI function.
    sudo -n modprobe vfio-pci
    sudo -n modprobe vfio_iommu_type1
    make -C "$experiment_root" SHARED_DIR="$experiment_root" clean all >/dev/null
    observer_status="$(mktemp "$runtime_dir/.observer-status.XXXXXX")"
    observer_pid_file=/tmp/virt-vtd-host-observer.pid
    sudo -n rm -f -- "$observer_pid_file"
    sudo -n sh -c 'printf "%s\n" "$$" > "$1"; exec "$2"' sh "$observer_pid_file" "$experiment_root/build/vtd" > "$ebpf_capture" 2> "$observer_status" &
    observer_job_pid=$!

    for _ in $(seq 1 200); do
        [[ -s "$observer_pid_file" ]] && observer_pid="$(cat "$observer_pid_file")"
        if grep -q '^LX_READY' "$observer_status"; then
            observer_ready=1
            break
        fi
        kill -0 "$observer_job_pid" 2>/dev/null || break
        sleep 0.1
    done
    if ((observer_ready == 0)); then
        echo "vtd observer failed to start" >&2
        cat "$observer_status" >&2
        return 1
    fi
}

set_host_runtime_gate()
{
    local enabled="$1"
    local signal expected previous

    [[ -n "$observer_pid" ]] || {
        echo "capture failure: host observer PID is unavailable" >&2
        return 1
    }
    if [[ "$enabled" == 1 ]]; then
        signal=USR1
    else
        signal=USR2
    fi
    expected="LX_GATE enabled=$enabled"
    previous="$(grep -c "^$expected$" "$observer_status" || true)"
    sudo -n kill -"$signal" "$observer_pid"
    for _ in $(seq 1 100); do
        if [[ "$(grep -c "^$expected$" "$observer_status" || true)" -gt "$previous" ]]; then
            return 0
        fi
        sudo -n kill -0 "$observer_pid" 2>/dev/null || break
        sleep 0.05
    done
    echo "capture failure: host observer did not acknowledge runtime gate $enabled" >&2
    return 1
}

# The safety audit proves that only the unused candidate function is eligible for assignment.
audit_candidate()
{
    local candidate_group_count

    # This is the final read-only gate before candidate ownership changes.
    assert_management_path || {
        echo "safety failure: management path differs from $MANAGEMENT_INTERFACE -> $MANAGEMENT_BDF -> $MANAGEMENT_DRIVER" >&2
        return 1
    }
    [[ "$(basename "$(readlink -f "/sys/class/net/$CANDIDATE_INTERFACE/device")")" == "$bdf" ]] || {
        echo "safety failure: $CANDIDATE_INTERFACE does not resolve to $bdf" >&2
        return 1
    }
    [[ "$(pci_driver "$bdf")" == "$CANDIDATE_HOST_DRIVER" ]] || {
        echo "safety failure: candidate is not $CANDIDATE_HOST_DRIVER-bound" >&2
        return 1
    }
    [[ -z "$(ip -o addr show dev "$CANDIDATE_INTERFACE" | awk '{print $4}')" ]] || {
        echo "safety failure: $CANDIDATE_INTERFACE has an address" >&2
        return 1
    }
    [[ -z "$(ip route show dev "$CANDIDATE_INTERFACE")" ]] || {
        echo "safety failure: $CANDIDATE_INTERFACE carries a route" >&2
        return 1
    }
    [[ ! -e "/sys/class/net/$CANDIDATE_INTERFACE/master" ]] || {
        echo "safety failure: $CANDIDATE_INTERFACE has a network master" >&2
        return 1
    }
    [[ "$(iommu_group "$bdf")" == "$CANDIDATE_GROUP" ]] || {
        echo "safety failure: candidate moved from audited IOMMU group $CANDIDATE_GROUP" >&2
        return 1
    }
    [[ "$(iommu_group "$MANAGEMENT_BDF")" == "$MANAGEMENT_GROUP" ]] || {
        echo "safety failure: management function moved groups" >&2
        return 1
    }
    [[ "$CANDIDATE_GROUP" != "$MANAGEMENT_GROUP" ]] || {
        echo "safety failure: candidate shares the management IOMMU group" >&2
        return 1
    }
    candidate_group_count="$(find "/sys/kernel/iommu_groups/$CANDIDATE_GROUP/devices" -mindepth 1 -maxdepth 1 -type l | wc -l)"
    [[ "$candidate_group_count" == 1 ]] || {
        echo "safety failure: candidate IOMMU group contains $candidate_group_count devices" >&2
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
    # Cleanup becomes responsible before the first ownership-changing write.
    assignment_started=1
    echo "$bdf" | sudo -n tee "/sys/bus/pci/drivers/$CANDIDATE_HOST_DRIVER/unbind" >/dev/null
    echo "$bdf" | sudo -n tee /sys/bus/pci/drivers/vfio-pci/bind >/dev/null

    [[ "$(pci_driver "$bdf")" == vfio-pci ]] || {
        echo "assignment failure: candidate did not bind vfio-pci" >&2
        return 1
    }
    assert_management_path || {
        echo "CRITICAL: management assertion failed after candidate bind" >&2
        return 1
    }
}

# QEMU exits before the observer so teardown remains inside the same monotonic capture.
finish_observation()
{
    if [[ -n "$qemu_pid" ]] && sudo -n kill -0 "$qemu_pid" 2>/dev/null; then
        sudo -n kill "$qemu_pid"
        [[ -z "$qemu_job_pid" ]] || wait "$qemu_job_pid" 2>/dev/null || true
    fi
    qemu_pid=""
    qemu_job_pid=""
    if [[ -n "$observer_pid" ]] && sudo -n kill -0 "$observer_pid" 2>/dev/null; then
        sudo -n kill -INT "$observer_pid"
        [[ -z "$observer_job_pid" ]] || wait "$observer_job_pid"
    fi
    observer_pid=""
    observer_job_pid=""
    grep -q '^LX_DONE .* dropped=0 short=0$' "$observer_status" || {
        echo "capture validation failed: observer did not finish cleanly" >&2
        sed -n '1,160p' "$observer_status" >&2
        return 1
    }
    jq -e -s '
        .[0].kind == "capture_meta" and
        .[-1].kind == "capture_summary" and
        any(.[]; .kind == "kvm_memory_region_enter") and
        any(.[]; .kind == "vfio_dma_map_enter") and
        any(.[]; .kind == "iommu_map") and
        any(.[]; .kind == "vfio_dma_map_exit") and
        .[-1].state.ringbuf_dropped == 0 and
        .[-1].state.short_records == 0
    ' "$ebpf_capture" >/dev/null
}

# QEMU receives the physical function while retaining a separate virtio management network.
start_qemu()
{
    local qemu_command=(
        qemu-system-x86_64
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

    qemu_pid_file="$(mktemp "$runtime_dir/.qemu-pid.XXXXXX")"
    sudo -n sh -c 'printf "%s\n" "$$" > "$1"; shift; exec "$@"' sh "$qemu_pid_file" "${qemu_command[@]}" &
    qemu_job_pid=$!
    for _ in $(seq 1 50); do
        [[ -s "$qemu_pid_file" ]] && qemu_pid="$(cat "$qemu_pid_file")" && break
        kill -0 "$qemu_job_pid" 2>/dev/null || break
        sleep 0.1
    done
    [[ -n "$qemu_pid" ]] || {
        echo "QEMU failed to publish its process ID" >&2
        return 1
    }
    sleep 2
    sudo -n kill -0 "$qemu_pid" 2>/dev/null || {
        echo "QEMU failed to stay running" >&2
        return 1
    }
}

# Guest PCI inspection proves that the selected physical function is visible under its expected driver.
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
set -eu
lspci -Dnnk
echo "-- target --"
pci_id="${PCI_VENDOR#0x}:${PCI_DEVICE#0x}"
bdf=$(lspci -Dnn | awk -v id="$pci_id" 'tolower($0) ~ "\\[" tolower(id) "\\]" {print $1; exit}')
[ -n "$bdf" ] || exit 1
lspci -Dnnk -s "$bdf"
echo "-- verbose --"
sudo -n lspci -Dvv -s "$bdf"
echo "-- interfaces --"
for interface_path in /sys/class/net/*; do
    [ -e "$interface_path/device" ] || continue
    [ "$(cat "$interface_path/device/vendor" 2>/dev/null)" = "$PCI_VENDOR" ] || continue
    [ "$(cat "$interface_path/device/device" 2>/dev/null)" = "$PCI_DEVICE" ] || continue
    interface=$(basename "$interface_path")
    echo "$interface"
    ethtool -i "$interface"
done
GUEST

    "${ssh_command[@]}" env PCI_VENDOR="$CANDIDATE_VENDOR" PCI_DEVICE="$CANDIDATE_DEVICE" bash -s <<< "$guest_probe" > "$guest_pci"
    guest_bdf="$(sed -n '/-- target --/{n; s/^\([^ ]*\).*/\1/p;}' "$guest_pci" | head -n1)"
    guest_driver="$(awk '/-- target --/{on=1; next} on && /Kernel driver in use:/{print $NF; exit}' "$guest_pci")"
    guest_interface="$(awk -v expected="$CANDIDATE_HOST_DRIVER" '/-- interfaces --/{on=1; next} on && /^[a-zA-Z0-9_.-]+$/{candidate=$0} on && $0 == "driver: " expected {print candidate; exit}' "$guest_pci")"
    guest_bars="$(awk '/Region [0-9]+:/{sub(/^[[:space:]]*/,""); print}' "$guest_pci" | jq -Rsc 'split("\n") | map(select(length > 0))')"
    guest_msix=false
    grep -q 'MSI-X:' "$guest_pci" && guest_msix=true

    [[ -n "$guest_bdf" ]] || {
        echo "guest proof failure: ${CANDIDATE_VENDOR#0x}:${CANDIDATE_DEVICE#0x} was not enumerated" >&2
        return 1
    }
    [[ "$guest_driver" == "$CANDIDATE_HOST_DRIVER" ]] || {
        echo "guest proof failure: assigned device is not $CANDIDATE_HOST_DRIVER-bound" >&2
        return 1
    }

    echo "Phase A guest proof: host $bdf -> guest $guest_bdf, driver=$guest_driver, interface=${guest_interface:-not-created}" >&2
}

# One bounded ixgbe offline loopback run supplies guest DMA-API, descriptor, completion, and IRQ evidence.
collect_guest_dma_use()
{
    local guest_script guest_status=0
    local ssh_command=(sshpass -p test ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 test@127.0.0.1)
    local scp_command=(sshpass -p test scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222)

    [[ -n "$guest_interface" ]] || {
        echo "guest DMA-use failure: assigned ixgbe interface was not discovered" >&2
        return 1
    }
    "${scp_command[@]}" "$experiment_root/build/vtd" test@127.0.0.1:/tmp/virt-vtd-observer
    read -r -d '' guest_script <<'GUEST' || true
set -euo pipefail
capture=/tmp/virt-vtd.guest.ndjson
workload=/tmp/virt-vtd.guest-selftest.txt
status_file=$(mktemp /tmp/.virt-vtd-guest-status.XXXXXX)
pid_file=/tmp/virt-vtd-guest-observer.pid
observer_pid=""
observer_job=""

cleanup_guest()
{
    set +e
    if [ -n "$observer_pid" ] && sudo -n kill -0 "$observer_pid" 2>/dev/null; then
        sudo -n kill -INT "$observer_pid"
        [ -z "$observer_job" ] || wait "$observer_job"
    fi
    rm -f -- "$status_file"
    sudo -n rm -f -- "$pid_file"
}

trap cleanup_guest EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ! mountpoint -q /sys/kernel/tracing; then
    sudo -n mount -t tracefs nodev /sys/kernel/tracing
fi
sudo -n chmod 700 /tmp/virt-vtd-observer
rm -f -- "$pid_file"
: > "$capture"
: > "$workload"
sudo -n sh -c 'printf "%s\n" "$$" > "$1"; exec "$2" --guest "$3"' sh "$pid_file" /tmp/virt-vtd-observer "$GUEST_INTERFACE" > "$capture" 2> "$status_file" &
observer_job=$!
for _ in $(seq 1 200); do
    [ -s "$pid_file" ] && observer_pid=$(cat "$pid_file")
    if [ -n "$observer_pid" ] && grep -q '^LX_READY experiment=virt-vtd observer=guest clock=monotonic$' "$status_file"; then
        break
    fi
    kill -0 "$observer_job" 2>/dev/null || break
    sleep 0.1
done
if [ -z "$observer_pid" ] || ! grep -q '^LX_READY experiment=virt-vtd observer=guest clock=monotonic$' "$status_file"; then
    sed -n '1,160p' "$status_file" >&2
    exit 1
fi
sudo -n ip link set dev "$GUEST_INTERFACE" up
sudo -n ethtool -t "$GUEST_INTERFACE" offline > "$workload" 2>&1 || true
sudo -n kill -INT "$observer_pid"
wait "$observer_job"
observer_pid=""
observer_job=""
grep -q '^LX_DONE experiment=virt-vtd observer=guest .* dropped=0 short=0$' "$status_file" || {
    sed -n '1,160p' "$status_file" >&2
    exit 1
}
grep -Eq '^Loopback test.*[[:space:]]0$' "$workload" || {
    cat "$workload" >&2
    exit 1
}
trap - EXIT INT TERM
rm -f -- "$status_file" /tmp/virt-vtd-observer
sudo -n rm -f -- "$pid_file"
GUEST

    set_host_runtime_gate 1
    if ! "${ssh_command[@]}" env GUEST_INTERFACE="$guest_interface" bash -s <<< "$guest_script"; then
        guest_status=1
    fi
    set_host_runtime_gate 0 || guest_status=1
    ((guest_status == 0)) || return 1
    "${scp_command[@]}" test@127.0.0.1:/tmp/virt-vtd.guest.ndjson "$guest_capture"
    "${scp_command[@]}" test@127.0.0.1:/tmp/virt-vtd.guest-selftest.txt "$guest_workload"
    jq -e -s '
        .[0].kind == "capture_meta" and
        .[-1].kind == "capture_summary" and
        any(.[]; .kind == "guest_ixgbe_run_loopback_entry") and
        any(.[]; .kind == "guest_ixgbe_xmit_entry") and
        any(.[]; .kind == "guest_dma_map_exit") and
        any(.[]; .kind == "guest_ixgbe_xmit_exit" and .event_info.result == 0) and
        any(.[]; .kind == "guest_ixgbe_clean_exit" and .state.dma.completed_descriptors >= 64) and
        any(.[]; .kind == "guest_ixgbe_run_loopback_exit" and .event_info.result == 0) and
        ([.[] | select(.kind == "guest_irq_handler_entry")] | length) > 1 and
        ([.[] | select(.kind == "guest_irq_handler_exit")] | length) == ([.[] | select(.kind == "guest_irq_handler_entry")] | length) and
        .[-1].state.ringbuf_dropped == 0 and
        .[-1].state.short_records == 0
    ' "$guest_capture" >/dev/null || {
        echo "capture validation failed: guest DMA-use evidence is incomplete" >&2
        return 1
    }
}

# The cleanup trap prioritizes hardware restoration on success, failure, SIGINT, and SIGTERM.
cleanup()
{
    local current_driver restored=0

    set +e
    # QEMU exits first so the observer sees VFIO and IOMMU teardown.
    if [[ -n "$qemu_pid" ]] && sudo -n kill -0 "$qemu_pid" 2>/dev/null; then
        sudo -n kill "$qemu_pid"
        [[ -z "$qemu_job_pid" ]] || wait "$qemu_job_pid" 2>/dev/null || true
    fi
    if [[ -n "$observer_pid" ]] && sudo -n kill -0 "$observer_pid" 2>/dev/null; then
        sudo -n kill -INT "$observer_pid"
        [[ -z "$observer_job_pid" ]] || wait "$observer_job_pid" 2>/dev/null || true
    fi
    [[ -z "$observer_status" ]] || rm -f -- "$observer_status"
    [[ -z "$observer_pid_file" ]] || sudo -n rm -f -- "$observer_pid_file"
    [[ -z "$qemu_pid_file" ]] || rm -f -- "$qemu_pid_file"
    if ((assignment_started)); then
        if [[ -e "/sys/bus/pci/devices/$bdf/driver" ]]; then
            current_driver="$(pci_driver "$bdf")"
            if [[ "$current_driver" != "$CANDIDATE_HOST_DRIVER" ]]; then
                echo "$bdf" | sudo -n tee "/sys/bus/pci/drivers/$current_driver/unbind" >/dev/null
            fi
        fi
        printf '\n' | sudo -n tee "/sys/bus/pci/devices/$bdf/driver_override" >/dev/null
        sudo -n modprobe "$CANDIDATE_HOST_DRIVER"
        echo "$bdf" | sudo -n tee "/sys/bus/pci/drivers/$CANDIDATE_HOST_DRIVER/bind" >/dev/null

        [[ "$(pci_driver "$bdf")" == "$CANDIDATE_HOST_DRIVER" ]] && restored=1
        assert_management_path || restored=0
        if ((restored)); then
            record_assignment host_reclaims_device
            echo "host restored: $bdf -> $CANDIDATE_HOST_DRIVER; $MANAGEMENT_INTERFACE remains management" >&2
        else
            echo "CRITICAL RESTORE FAILURE" >&2
            echo "sudo sh -c 'echo $bdf > /sys/bus/pci/drivers/vfio-pci/unbind; echo > /sys/bus/pci/devices/$bdf/driver_override; modprobe $CANDIDATE_HOST_DRIVER; echo $bdf > /sys/bus/pci/drivers/$CANDIDATE_HOST_DRIVER/bind'" >&2
        fi
    fi
    set -e
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
rm -f -- "$overlay" "$assignment_capture" "$ebpf_capture" "$guest_capture" "$guest_workload" "$qemu_output" "$guest_pci"
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
collect_guest_dma_use
finish_observation
