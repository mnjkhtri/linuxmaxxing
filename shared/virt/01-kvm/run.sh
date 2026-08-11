#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VIRT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
CAPTURE_DIR="$REPO_ROOT/shared/_captures"
TRACE_CAPTURE="${TRACE_CAPTURE:-$CAPTURE_DIR/01-kvm-trace.txt}"
EPT_CAPTURE="${EPT_CAPTURE:-$CAPTURE_DIR/ept.ndjson}"
TARGET_FILE="${VIRT_TARGET_FILE:-$VIRT_DIR/cloudlab}"
REMOTE_DIR="${REMOTE_DIR:-~/kernel-oops-virt/01-kvm}"

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
	-o ServerAliveInterval=5
	-o ServerAliveCountMax=2
)

mkdir -p "$CAPTURE_DIR"

echo "target: $TARGET"
ssh "${ssh_opts[@]}" "$TARGET" "mkdir -p $REMOTE_DIR"
scp -p "${ssh_opts[@]}" "$SCRIPT_DIR/vmm.c" "$SCRIPT_DIR/guest.S" "$SCRIPT_DIR/ept.c" "$SCRIPT_DIR/ept.bpf.c" "$SCRIPT_DIR/Makefile" "$TARGET:$REMOTE_DIR/"
ssh "${ssh_opts[@]}" "$TARGET" "cd $REMOTE_DIR && make clean-ept && make all"
ssh "${ssh_opts[@]}" "$TARGET" "REMOTE_DIR=$REMOTE_DIR sudo -n bash -s" <<'REMOTE'
set -euo pipefail
cd "$REMOTE_DIR"
rm -rf captures
mkdir -p captures

./build/ept 2> captures/ept-observer.log &
observer=$!
trace_dir=""

cleanup() {
	if [[ -n "$trace_dir" ]]; then
		echo 0 > "$trace_dir/tracing_on" 2>/dev/null || true
		echo 0 > "$trace_dir/events/kvm/kvm_entry/enable" 2>/dev/null || true
		echo 0 > "$trace_dir/events/kvm/kvm_exit/enable" 2>/dev/null || true
		echo 0 > "$trace_dir/events/kvm/kvm_userspace_exit/enable" 2>/dev/null || true
		echo 0 > "$trace_dir/events/kvm/enable" 2>/dev/null || true
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

mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mountpoint -q /sys/kernel/debug || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do
	if [[ -d "$d/events/kvm/kvm_entry" && -d "$d/events/kvm/kvm_exit" && -d "$d/events/kvm/kvm_userspace_exit" ]]; then
		trace_dir="$d"
		break
	fi
done
[[ -n "$trace_dir" ]] || { echo "error: KVM tracepoints not found" >&2; exit 1; }

echo 0 > "$trace_dir/tracing_on"
echo > "$trace_dir/trace"
echo 0 > "$trace_dir/events/kvm/enable"
echo 1 > "$trace_dir/events/kvm/kvm_entry/enable"
echo 1 > "$trace_dir/events/kvm/kvm_exit/enable"
echo 1 > "$trace_dir/events/kvm/kvm_userspace_exit/enable"
echo 1 > "$trace_dir/tracing_on"

./build/vmm

echo 0 > "$trace_dir/tracing_on"
cat "$trace_dir/trace" > captures/01-kvm-trace.txt
cleanup
trap - EXIT

cat captures/ept-observer.log >&2 || true
[[ -s captures/ept.ndjson ]] || { echo "error: EPT observer produced no snapshots" >&2; exit 1; }
[[ -s captures/01-kvm-trace.txt ]] || { echo "error: KVM trace produced no records" >&2; exit 1; }
REMOTE

scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/01-kvm-trace.txt" "$TRACE_CAPTURE"
scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/ept.ndjson" "$EPT_CAPTURE"
echo "trace capture: $TRACE_CAPTURE"
echo "ept capture: $EPT_CAPTURE"
