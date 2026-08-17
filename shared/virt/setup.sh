#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${VIRT_TARGET_FILE:-$SCRIPT_DIR/../cloudlab}"
SSH_CONNECT_TIMEOUT="${SSH_CONNECT_TIMEOUT:-10}"

die()
{
    echo "error: $*" >&2
    exit 1
}

usage()
{
    cat >&2 <<EOF
usage: ./shared/virt/setup.sh [user@cloudlab]

If no target is given, reads the target from:
  $TARGET_FILE
EOF
}

target_from_file()
{
    [[ -s "$TARGET_FILE" ]] ||
        die "missing target file: $TARGET_FILE (put user@node.cloudlab.us in it)"
    sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$TARGET_FILE"
}

case $# in
    0) TARGET="$(target_from_file)"
       [[ -n "$TARGET" ]] || die "$TARGET_FILE does not contain a target" ;;
    1) TARGET="$1" ;;
    *) usage; exit 2 ;;
esac

command -v ssh >/dev/null 2>&1 || die "required command not found: ssh"

# Remote, self-contained compatibility probe run as a single bash session.
ssh -o BatchMode=yes \
    -o ConnectTimeout="$SSH_CONNECT_TIMEOUT" \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=1 \
    -o StrictHostKeyChecking=no \
    "$TARGET" 'bash -s' <<'REMOTE'
set -euo pipefail

NEED_CMDS=(gcc make clang bpftool pkg-config)
NEED_PKGS=(build-essential clang llvm pkg-config libbpf-dev libelf-dev zlib1g-dev linux-tools-common "linux-tools-$(uname -r)")
MIRROR="us.archive.ubuntu.com"

die() { echo "error: $*" >&2; exit 1; }

print_basics()
{
    printf "hostname: "; hostname
    printf "kernel:  "; uname -a
    printf "user:    "; id
    printf "uptime:  "; uptime
}

host_line()
{
    local ip
    ip="$(hostname -I | awk '{print $1}')"
    [[ -n "$ip" ]] || return 0
    grep -qE "[[:space:]]$(hostname)([[:space:]]|$)" /etc/hosts ||
        printf "%s %s\n" "$ip" "$(hostname)" | sudo -n tee -a /etc/hosts >/dev/null
}

dns_ok() { timeout 10 getent hosts "$MIRROR" >/dev/null 2>&1; }

repair_dns()
{
    dns_ok && return 0
    local iface
    iface="$(ip route show default | awk '{print $5; exit}')"
    if [[ -n "$iface" ]]; then
        echo "CloudLab deps: DNS failed; setting fallback DNS on $iface"
        sudo -n resolvectl dns "$iface" 1.1.1.1 8.8.8.8
        sudo -n resolvectl domain "$iface" "~."
    fi
    dns_ok || die "cannot resolve $MIRROR"
}

missing_deps()
{
    local missing=""
    for cmd in "${NEED_CMDS[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
    done
    pkg-config --exists libbpf 2>/dev/null || missing="$missing libbpf-dev"
    printf "%s" "$missing"
}

install_deps_if_needed()
{
    local missing
    missing="$(missing_deps)"
    if [[ -z "$missing" ]]; then
        echo "CloudLab deps: present"
        return 0
    fi
    command -v apt-get >/dev/null 2>&1 || die "apt-get is not available"
    echo "CloudLab deps: installing missing tools:$missing"
    repair_dns
    sudo -n apt-get update
    sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y "${NEED_PKGS[@]}"
    [[ -z "$(missing_deps)" ]] || die "still missing after install:$(missing_deps)"
}

verify_kvm()
{
    grep -qm1 vmx /proc/cpuinfo ||
        die "Intel VMX: missing; this observer decodes Intel EPT, not AMD NPT"
    echo "Intel VMX: detected"
    sudo -n modprobe kvm
    sudo -n modprobe kvm_intel
    [[ -e /dev/kvm ]] || die "/dev/kvm: missing"
    echo "/dev/kvm: available ($(stat -c '%A %U:%G' /dev/kvm))"
}

mount_tracing()
{
    sudo -n mkdir -p /sys/kernel/tracing /sys/kernel/debug
    mountpoint -q /sys/kernel/tracing ||
        sudo -n mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
    mountpoint -q /sys/kernel/debug ||
        sudo -n mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
}

find_events()
{
    local d
    for d in /sys/kernel/tracing/events/"$1" /sys/kernel/debug/tracing/events/"$1"; do
        if sudo -n test -d "$d"; then
            echo "$d"
            return 0
        fi
    done
    return 1
}

verify_tracefs()
{
    mount_tracing
    local kvm mmu
    kvm="$(find_events kvm)" || die "KVM tracepoints not found"
    mmu="$(find_events kvmmmu)" || die "KVM MMU tracepoints not found"
    echo "KVM tracepoints: $kvm"
    echo "KVM MMU tracepoints: $mmu"

    for event in kvm_entry kvm_exit kvm_userspace_exit kvm_unmap_hva_range; do
        sudo -n test -r "$kvm/$event/format" || die "KVM tracepoint missing: $event"
    done
    for event in kvm_mmu_spte_requested kvm_mmu_set_spte; do
        sudo -n test -r "$mmu/$event/format" || die "KVM MMU tracepoint missing: $event"
    done
    sudo -n awk '$3 == "kvm_flush_remote_tlbs" { found=1 } END { exit !found }' \
        /proc/kallsyms || die "KVM symbol missing: kvm_flush_remote_tlbs"
    echo "KVM EPT tracepoints: compatible"
}

verify_thp()
{
    local thp=/sys/kernel/mm/transparent_hugepage
    if ! sudo -n test -r "$thp/enabled" || ! sudo -n test -r "$thp/hpage_pmd_size"; then
        echo "transparent huge pages: unavailable; command 4 will show base-page EPT leaves"
        return 0
    fi
    echo "transparent huge pages: available ($(sudo -n cat "$thp/hpage_pmd_size") bytes)"
    echo "THP enabled policy: $(sudo -n cat "$thp/enabled")"
    echo "THP defrag policy:  $(sudo -n cat "$thp/defrag")"
}

print_basics
host_line
install_deps_if_needed
verify_kvm
verify_tracefs
verify_thp
REMOTE

echo "setup OK for $TARGET"