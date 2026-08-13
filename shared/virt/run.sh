#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
CAPTURE_DIR="$REPO_ROOT/shared/_captures"
TRACE_CAPTURE="${TRACE_CAPTURE:-$CAPTURE_DIR/kvm-trace.txt}"
EPT_CAPTURE="${EPT_CAPTURE:-$CAPTURE_DIR/ept.ndjson}"
TARGET_FILE="${VIRT_TARGET_FILE:-$SCRIPT_DIR/cloudlab}"
REMOTE_DIR="${REMOTE_DIR:-kernel-oops-virt}"
SSH_KNOWN_HOSTS="${SSH_KNOWN_HOSTS:-$CAPTURE_DIR/cloudlab-known-hosts}"
VIRT_FETCH_ONLY="${VIRT_FETCH_ONLY:-0}"

if [[ ! -s "$TARGET_FILE" ]]; then
	echo "error: missing CloudLab target file: $TARGET_FILE" >&2
	echo "put a target like user@cloudlab in that file" >&2
	exit 1
fi

TARGET="$(sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$TARGET_FILE")"
if [[ -z "$TARGET" ]]; then
	echo "error: $TARGET_FILE does not contain a target" >&2
	exit 1
fi

ssh_opts=(
	-o BatchMode=yes
	-o ConnectTimeout=10
	-o ServerAliveInterval=30
	-o ServerAliveCountMax=6
	-o StrictHostKeyChecking=accept-new
	-o UserKnownHostsFile="$SSH_KNOWN_HOSTS"
)

mkdir -p "$CAPTURE_DIR"

echo "target: $TARGET"
[[ "$TARGET" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] || { echo "error: invalid SSH target: $TARGET" >&2; exit 1; }
[[ "$REMOTE_DIR" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo "error: unsafe remote directory: $REMOTE_DIR" >&2; exit 1; }

fetch_captures()
{
	scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/kvm-trace.txt" "$TRACE_CAPTURE"
	scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/ept.ndjson" "$EPT_CAPTURE"
	echo "trace capture: $TRACE_CAPTURE"
	echo "ept capture: $EPT_CAPTURE"
}

if [[ "$VIRT_FETCH_ONLY" == 1 ]]; then
	fetch_captures
	exit 0
fi

ssh "${ssh_opts[@]}" "$TARGET" "mkdir -p -- '$REMOTE_DIR'"
scp -p "${ssh_opts[@]}" "$SCRIPT_DIR/vmm.c" "$SCRIPT_DIR/guest.S" "$SCRIPT_DIR/ept.c" "$SCRIPT_DIR/ept.bpf.c" "$SCRIPT_DIR/Makefile" "$TARGET:$REMOTE_DIR/"
ssh "${ssh_opts[@]}" "$TARGET" "cd '$REMOTE_DIR' && make all"
ssh "${ssh_opts[@]}" "$TARGET" "sudo -n bash -s -- '$REMOTE_DIR'" <<'REMOTE'
set -euo pipefail
REMOTE_DIR="$1"
cd "$REMOTE_DIR"
rm -rf captures
mkdir -p captures

./build/ept 2> captures/ept-observer.log &
observer=$!
trace_dir=""
trace_instance=""

cleanup() {
	if [[ -n "$trace_instance" ]]; then
		echo 0 > "$trace_instance/tracing_on" 2>/dev/null || true
		rmdir "$trace_instance" 2>/dev/null || true
	fi
	kill "$observer" 2>/dev/null || true
	wait "$observer" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 40); do
	if grep -q 'capturing KVM EPT snapshots' captures/ept-observer.log 2>/dev/null; then
		break
	fi
	if ! kill -0 "$observer" 2>/dev/null; then
		cat captures/ept-observer.log >&2 || true
		exit 1
	fi
	sleep 0.1
done
grep -q 'capturing KVM EPT snapshots' captures/ept-observer.log || {
	echo "error: EPT observer did not become ready" >&2
	exit 1
}

mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mountpoint -q /sys/kernel/debug || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do
	if [[ -d "$d/events/kvm/kvm_entry" && -d "$d/events/kvm/kvm_exit" && -d "$d/events/kvm/kvm_userspace_exit" ]]; then
		trace_dir="$d"
		break
	fi
done
[[ -n "$trace_dir" ]] || { echo "error: KVM tracepoints not found" >&2; exit 1; }
grep -q 'field:.*exit_reason;' "$trace_dir/events/kvm/kvm_exit/format" ||
	{ echo "error: kvm_exit tracepoint lacks exit_reason" >&2; exit 1; }
grep -q 'field:.*guest_rip;' "$trace_dir/events/kvm/kvm_exit/format" ||
	{ echo "error: kvm_exit tracepoint lacks guest_rip" >&2; exit 1; }
grep -q 'field:.*reason;' "$trace_dir/events/kvm/kvm_userspace_exit/format" ||
	{ echo "error: kvm_userspace_exit tracepoint lacks reason" >&2; exit 1; }

instance_name="kernel-oops-virt-$$"
mkdir "$trace_dir/instances/$instance_name"
trace_instance="$trace_dir/instances/$instance_name"
if grep -qw mono "$trace_instance/trace_clock"; then
	echo mono > "$trace_instance/trace_clock"
else
	echo "error: tracefs monotonic clock is unavailable" >&2
	exit 1
fi
echo 1 > "$trace_instance/events/kvm/kvm_entry/enable"
echo 1 > "$trace_instance/events/kvm/kvm_exit/enable"
echo 1 > "$trace_instance/events/kvm/kvm_userspace_exit/enable"
echo 1 > "$trace_instance/events/kvm/kvm_unmap_hva_range/enable"
echo 1 > "$trace_instance/events/kvmmmu/kvm_mmu_spte_requested/enable"
echo 1 > "$trace_instance/tracing_on"

./build/vmm

echo 0 > "$trace_instance/tracing_on"
cat "$trace_instance/trace" > captures/kvm-trace.txt
cleanup
trap - EXIT

cat captures/ept-observer.log >&2 || true
[[ -s captures/ept.ndjson ]] || { echo "error: EPT observer produced no snapshots" >&2; exit 1; }
[[ -s captures/kvm-trace.txt ]] || { echo "error: KVM trace produced no records" >&2; exit 1; }
REMOTE

fetch_captures
