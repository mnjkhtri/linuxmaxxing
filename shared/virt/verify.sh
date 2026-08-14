#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${VIRT_TARGET_FILE:-$SCRIPT_DIR/cloudlab}"
SSH_CONNECT_TIMEOUT="${SSH_CONNECT_TIMEOUT:-10}"
SSH_KNOWN_HOSTS="${SSH_KNOWN_HOSTS:-$SCRIPT_DIR/../_captures/cloudlab-known-hosts}"

usage()
{
	cat >&2 <<EOF
usage: ./shared/virt/verify.sh [user@cloudlab]

If no target is given, reads the target from:
  $TARGET_FILE
EOF
}

target_from_file()
{
	[[ -s "$TARGET_FILE" ]] || {
		echo "error: missing target file: $TARGET_FILE" >&2
		echo "put a target like user@c220g5-xxxxxx.wisc.cloudlab.us in that file" >&2
		exit 1
	}
	sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$TARGET_FILE"
}

if [[ $# -gt 1 ]]; then
	usage
	exit 2
elif [[ $# -eq 1 ]]; then
	TARGET="$1"
else
	TARGET="$(target_from_file)"
	[[ -n "$TARGET" ]] || { echo "error: $TARGET_FILE does not contain a target" >&2; exit 1; }
fi

command -v ssh >/dev/null 2>&1 || { echo "error: required command not found: ssh" >&2; exit 1; }
mkdir -p "$(dirname -- "$SSH_KNOWN_HOSTS")"

ssh_opts=(
	-o BatchMode=yes
	-o ConnectTimeout="$SSH_CONNECT_TIMEOUT"
	-o ServerAliveInterval=5
	-o ServerAliveCountMax=1
	-o StrictHostKeyChecking=accept-new
	-o UserKnownHostsFile="$SSH_KNOWN_HOSTS"
)

REMOTE_SCRIPT=$(cat <<'REMOTE'
set -euo pipefail

need_commands=(gcc make clang bpftool pkg-config)
need_packages=(build-essential clang llvm pkg-config libbpf-dev libelf-dev zlib1g-dev linux-tools-common "linux-tools-$(uname -r)")

print_basics()
{
	printf "hostname: "; hostname
	printf "kernel: "; uname -a
	printf "user: "; id
	printf "uptime: "; uptime
}

fix_hostname_lookup()
{
	local name ip
	name="$(hostname)"
	ip="$(hostname -I | awk '{print $1}')"
	[[ -n "$ip" ]] || return 0
	grep -q "[[:space:]]$name\([[:space:]]\|$\)" /etc/hosts || printf "%s %s\n" "$ip" "$name" | sudo -n tee -a /etc/hosts >/dev/null
}

repair_dns_if_needed()
{
	local iface
	timeout 10 getent hosts us.archive.ubuntu.com >/dev/null 2>&1 && return 0
	iface="$(ip route show default | awk '{print $5; exit}')"
	[[ -n "$iface" ]] || { echo "CloudLab deps: no default interface for DNS repair"; exit 12; }
	echo "CloudLab deps: DNS failed; setting fallback DNS on $iface"
	sudo -n resolvectl dns "$iface" 1.1.1.1 8.8.8.8
	sudo -n resolvectl domain "$iface" "~."
	timeout 10 getent hosts us.archive.ubuntu.com >/dev/null 2>&1 || { echo "CloudLab deps: DNS still cannot resolve us.archive.ubuntu.com"; exit 12; }
}

missing_deps()
{
	local missing=""
	for cmd in "${need_commands[@]}"; do
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

	echo "CloudLab deps: installing missing tools:$missing"
	command -v apt-get >/dev/null 2>&1 || { echo "CloudLab deps: apt-get is not available"; exit 12; }
	repair_dns_if_needed
	sudo -n apt-get update
	sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y "${need_packages[@]}"

	missing="$(missing_deps)"
	[[ -z "$missing" ]] || { echo "CloudLab deps: still missing after install:$missing"; exit 13; }
}

verify_kvm()
{
	grep -qm1 vmx /proc/cpuinfo ||
		{ echo "Intel VMX: missing; this observer decodes Intel EPT, not AMD NPT"; exit 10; }
	echo "Intel VMX: detected"

	sudo -n modprobe kvm
	sudo -n modprobe kvm_intel

	[[ -e /dev/kvm ]] || { echo "/dev/kvm: missing"; exit 11; }
	echo "/dev/kvm: available"
	ls -l /dev/kvm
}

verify_tracefs()
{
	local tracepoints="not mounted" mmu_tracepoints="not mounted" d
	sudo -n mkdir -p /sys/kernel/tracing /sys/kernel/debug
	mountpoint -q /sys/kernel/tracing || sudo -n mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
	mountpoint -q /sys/kernel/debug || sudo -n mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true

	for d in /sys/kernel/tracing/events/kvm /sys/kernel/debug/tracing/events/kvm; do
		if sudo -n test -d "$d"; then
			tracepoints="$d"
			break
		fi
	done
	for d in /sys/kernel/tracing/events/kvmmmu /sys/kernel/debug/tracing/events/kvmmmu; do
		if sudo -n test -d "$d"; then
			mmu_tracepoints="$d"
			break
		fi
	done

	echo "KVM tracepoints: $tracepoints"
	[[ "$tracepoints" != "not mounted" ]] || exit 14
	for event in kvm_entry kvm_exit kvm_userspace_exit kvm_unmap_hva_range; do
		sudo -n test -r "$tracepoints/$event/format" ||
			{ echo "KVM tracepoint missing: $event"; exit 14; }
	done
	[[ "$mmu_tracepoints" != "not mounted" ]] ||
		{ echo "KVM MMU tracepoints: not mounted"; exit 14; }
	sudo -n test -r "$mmu_tracepoints/kvm_mmu_spte_requested/format" ||
		{ echo "KVM MMU tracepoint missing: kvm_mmu_spte_requested"; exit 14; }
	sudo -n test -r "$mmu_tracepoints/kvm_mmu_set_spte/format" ||
		{ echo "KVM MMU tracepoint missing: kvm_mmu_set_spte"; exit 14; }
	sudo -n awk '$3 == "kvm_flush_remote_tlbs" { found=1 } END { exit !found }' /proc/kallsyms ||
		{ echo "KVM symbol missing: kvm_flush_remote_tlbs"; exit 14; }
	echo "KVM state-sampling tracepoints: compatible"
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
	echo "THP defrag policy: $(sudo -n cat "$thp/defrag")"
}

print_basics
fix_hostname_lookup
install_deps_if_needed
verify_kvm
verify_tracefs
verify_thp
REMOTE
)

echo "checking $TARGET"
ssh "${ssh_opts[@]}" "$TARGET" 'bash -s' <<<"$REMOTE_SCRIPT"
