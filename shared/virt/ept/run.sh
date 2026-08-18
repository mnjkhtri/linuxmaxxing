#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
CAPTURE_ROOT="$REPO_ROOT/shared/_captures"
TARGET_FILE="$SCRIPT_DIR/../cloudlab"
REMOTE_DIR="kernel-oops-virt-ept"
EPT_DIR="$REMOTE_DIR/shared/virt/ept"
TARGET="$(sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$TARGET_FILE")"
[ -n "$TARGET" ] || { echo "error: empty CloudLab target" >&2; exit 1; }
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -o StrictHostKeyChecking=no)
mkdir -p "$CAPTURE_ROOT"
fetch_captures()
{
	scp -p "${ssh_opts[@]}" "$TARGET:$EPT_DIR/captures/virt-ept-Trace.txt" "$CAPTURE_ROOT/virt-ept-Trace.txt"
	scp -p "${ssh_opts[@]}" "$TARGET:$EPT_DIR/captures/virt-ept.eBPF.ndjson" "$CAPTURE_ROOT/virt-ept.eBPF.ndjson"
	# The observer log only exists for runs made after the fetch started including it.
	# A missing log must never abort the fetch of the two primary captures.
	scp -p "${ssh_opts[@]}" "$TARGET:$EPT_DIR/captures/virt-ept-observer.log" "$CAPTURE_ROOT/virt-ept-observer.log" 2>/dev/null || true
}
if [ "${VIRT_FETCH_ONLY:-0}" = 1 ]; then
	fetch_captures
	exit 0
fi
# Stage the experiment as a mirrored tree on the remote.
# The Makefile SHARED_DIR (.. from shared/virt/ept) then resolves to the shared/ dir holding json_writer.c.
ssh "${ssh_opts[@]}" "$TARGET" "mkdir -p -- '$EPT_DIR' '$REMOTE_DIR/shared'"
scp -p "${ssh_opts[@]}" "$SCRIPT_DIR/vmm.c" "$SCRIPT_DIR/guest.S" "$SCRIPT_DIR/ept.c" "$SCRIPT_DIR/ept.bpf.c" "$SCRIPT_DIR/ept_event.h" "$SCRIPT_DIR/Makefile" "$TARGET:$EPT_DIR/"
scp -p "${ssh_opts[@]}" "$REPO_ROOT/shared/json_writer.c" "$REPO_ROOT/shared/json_writer.h" "$TARGET:$REMOTE_DIR/shared/"
ssh "${ssh_opts[@]}" "$TARGET" "cd '$EPT_DIR' && make all"
ssh "${ssh_opts[@]}" "$TARGET" "sudo -n bash -s -- '$EPT_DIR'" <<'REMOTE'
set -euo pipefail
REMOTE_DIR="$1"
cd "$REMOTE_DIR"
rm -rf captures
mkdir -p captures
./build/ept > captures/virt-ept.eBPF.ndjson 2> captures/virt-ept-observer.log &
observer=$!
trace_dir=""
trace_instance=""
kprobe_event="kernel_oops_kvm_flush_$$"
cleanup()
{
	if [ -n "$trace_instance" ]; then
		echo 0 > "$trace_instance/tracing_on" 2>/dev/null || true
		if [ -e "$trace_instance/events/kprobes/$kprobe_event/enable" ]; then
			echo 0 > "$trace_instance/events/kprobes/$kprobe_event/enable" 2>/dev/null || true
		fi
		echo "-:kprobes/$kprobe_event" > "$trace_dir/kprobe_events" 2>/dev/null || true
		rmdir "$trace_instance" 2>/dev/null || true
	fi
	kill "$observer" 2>/dev/null || true
	wait "$observer" 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 40); do
	grep -q '^LX_READY' captures/virt-ept-observer.log 2>/dev/null && break
	kill -0 "$observer" 2>/dev/null || { cat captures/virt-ept-observer.log >&2; exit 1; }
	sleep 0.1
done
grep -q '^LX_READY' captures/virt-ept-observer.log || { cat captures/virt-ept-observer.log >&2; exit 1; }
mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mountpoint -q /sys/kernel/debug || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do
	if [ -d "$d/events/kvm/kvm_entry" ]; then trace_dir="$d"; break; fi
done
[ -n "$trace_dir" ] || { echo "error: KVM tracepoints not found" >&2; exit 1; }
instance_name="kernel-oops-virt-ept-$$"
mkdir "$trace_dir/instances/$instance_name"
trace_instance="$trace_dir/instances/$instance_name"
grep -qw mono "$trace_instance/trace_clock" || exit 1
echo mono > "$trace_instance/trace_clock"
for event in kvm_entry kvm_exit kvm_userspace_exit kvm_unmap_hva_range; do
	[ -d "$trace_instance/events/kvm/$event" ] || exit 1
	echo 1 > "$trace_instance/events/kvm/$event/enable"
done
echo 1 > "$trace_instance/events/kvmmmu/kvm_mmu_spte_requested/enable"
echo 1 > "$trace_instance/events/kvmmmu/kvm_mmu_set_spte/enable"
echo "p:kprobes/$kprobe_event kvm:kvm_flush_remote_tlbs" > "$trace_dir/kprobe_events"
echo 1 > "$trace_instance/events/kprobes/$kprobe_event/enable"
echo 1 > "$trace_instance/tracing_on"
./build/vmm
echo 0 > "$trace_instance/tracing_on"
cat "$trace_instance/trace" > captures/virt-ept-Trace.txt
cleanup
trap - EXIT
[ -s captures/virt-ept-Trace.txt ] && [ -s captures/virt-ept.eBPF.ndjson ] || exit 1
REMOTE
fetch_captures
