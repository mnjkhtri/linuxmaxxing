#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
CAPTURE_ROOT="$REPO_ROOT/shared/_captures"
TARGET_FILE="$SCRIPT_DIR/../cloudlab"
REMOTE_DIR="kernel-oops-virt-io"
IO_DIR="$REMOTE_DIR/shared/virt/io"
TARGET="$(sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$TARGET_FILE")"
[ -n "$TARGET" ] || { echo "error: empty CloudLab target" >&2; exit 1; }
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -o StrictHostKeyChecking=no)
mkdir -p "$CAPTURE_ROOT"
fetch_captures()
{
	scp -p "${ssh_opts[@]}" "$TARGET:$IO_DIR/captures/virt-io-Trace.txt" "$CAPTURE_ROOT/virt-io-Trace.txt"
	scp -p "${ssh_opts[@]}" "$TARGET:$IO_DIR/captures/virt-io.eBPF.ndjson" "$CAPTURE_ROOT/virt-io.eBPF.ndjson"
}
if [ "${VIRT_FETCH_ONLY:-0}" = 1 ]; then
	fetch_captures
	exit 0
fi
# Stage the experiment as a mirrored tree on the remote.
# The Makefile SHARED_DIR (.. from shared/virt/io) then resolves to the shared/ dir holding json_writer.c.
ssh "${ssh_opts[@]}" "$TARGET" "mkdir -p -- '$IO_DIR' '$REMOTE_DIR/shared'"
scp -p "${ssh_opts[@]}" "$SCRIPT_DIR/vmm.c" "$SCRIPT_DIR/guest.S" "$SCRIPT_DIR/io.c" "$SCRIPT_DIR/io.bpf.c" "$SCRIPT_DIR/io_event.h" "$SCRIPT_DIR/device.h" "$SCRIPT_DIR/Makefile" "$TARGET:$IO_DIR/"
scp -p "${ssh_opts[@]}" "$REPO_ROOT/shared/json_writer.c" "$REPO_ROOT/shared/json_writer.h" "$TARGET:$REMOTE_DIR/shared/"
ssh "${ssh_opts[@]}" "$TARGET" "cd '$IO_DIR' && make all"
ssh "${ssh_opts[@]}" "$TARGET" "sudo -n bash -s -- '$IO_DIR'" <<'REMOTE'
set -euo pipefail
REMOTE_DIR="$1"
cd "$REMOTE_DIR"
rm -rf captures
mkdir -p captures
./build/io > captures/virt-io.eBPF.ndjson 2> captures/virt-io-observer.log &
observer=$!
trace_dir=""
trace_instance=""
cleanup()
{
	if [ -n "$trace_instance" ]; then
		echo 0 > "$trace_instance/tracing_on" 2>/dev/null || true
		rmdir "$trace_instance" 2>/dev/null || true
	fi
	kill "$observer" 2>/dev/null || true
	wait "$observer" 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 40); do
	grep -q '^LX_READY' captures/virt-io-observer.log 2>/dev/null && break
	kill -0 "$observer" 2>/dev/null || { cat captures/virt-io-observer.log >&2; exit 1; }
	sleep 0.1
done
grep -q '^LX_READY' captures/virt-io-observer.log || { cat captures/virt-io-observer.log >&2; exit 1; }
mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mountpoint -q /sys/kernel/debug || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do
	if [ -d "$d/events/kvm/kvm_entry" ]; then trace_dir="$d"; break; fi
done
[ -n "$trace_dir" ] || { echo "error: KVM tracepoints not found" >&2; exit 1; }
instance_name="kernel-oops-virt-io-$$"
mkdir "$trace_dir/instances/$instance_name"
trace_instance="$trace_dir/instances/$instance_name"
grep -qw mono "$trace_instance/trace_clock" || exit 1
echo mono > "$trace_instance/trace_clock"
for event in kvm_entry kvm_exit kvm_userspace_exit kvm_ioapic_set_irq kvm_apic_accept_irq kvm_inj_virq kvm_eoi kvm_apic kvm_msi_set_irq; do
	[ -d "$trace_instance/events/kvm/$event" ] || exit 1
	echo 1 > "$trace_instance/events/kvm/$event/enable"
done
echo 1 > "$trace_instance/tracing_on"
./build/vmm
echo 0 > "$trace_instance/tracing_on"
cat "$trace_instance/trace" > captures/virt-io-Trace.txt
cleanup
trap - EXIT
[ -s captures/virt-io-Trace.txt ] && [ -s captures/virt-io.eBPF.ndjson ] || exit 1
REMOTE
fetch_captures
