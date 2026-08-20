#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
CAPTURE_ROOT="$REPO_ROOT/shared/_captures"
TARGET_FILE="$SCRIPT_DIR/../cloudlab"
REMOTE_ROOT="kernel-oops-virt-paraio"
REMOTE_DIR="$REMOTE_ROOT/shared/virt/virtio"
TARGET="$(sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$TARGET_FILE")"
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -o StrictHostKeyChecking=no)

[ -n "$TARGET" ] || { echo "error: empty CloudLab target" >&2; exit 1; }
mkdir -p "$CAPTURE_ROOT"

fetch_captures()
{
	scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/virt-paraio.eBPF.ndjson" "$CAPTURE_ROOT/virt-paraio.eBPF.ndjson"
	scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/virt-paraio-Trace.txt" "$CAPTURE_ROOT/virt-paraio-Trace.txt"
	scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/virt-paraio-observer.log" "$CAPTURE_ROOT/virt-paraio-observer.log"
}

if [ "${VIRT_FETCH_ONLY:-0}" = 1 ]; then
	fetch_captures
	exit 0
fi

ssh "${ssh_opts[@]}" "$TARGET" "mkdir -p -- '$REMOTE_DIR' '$REMOTE_ROOT/shared'"
scp -p "${ssh_opts[@]}" "$SCRIPT_DIR/vmm.c" "$SCRIPT_DIR/guest.S" "$SCRIPT_DIR/virtio.h" "$SCRIPT_DIR/virtio_event.h" "$SCRIPT_DIR/virtio.bpf.c" "$SCRIPT_DIR/virtio.c" "$SCRIPT_DIR/Makefile" "$TARGET:$REMOTE_DIR/"
scp -p "${ssh_opts[@]}" "$REPO_ROOT/shared/json_writer.c" "$REPO_ROOT/shared/json_writer.h" "$TARGET:$REMOTE_ROOT/shared/"
ssh "${ssh_opts[@]}" "$TARGET" "cd '$REMOTE_DIR' && make clean all"

ssh "${ssh_opts[@]}" "$TARGET" "sudo -n bash -s -- '$REMOTE_DIR'" <<'REMOTE'
set -euo pipefail

REMOTE_DIR="$1"
cd "$REMOTE_DIR"
rm -rf captures
mkdir -p captures

./build/virtio > captures/virt-paraio.eBPF.ndjson 2> captures/virt-paraio-observer.log &
observer=$!
trace_instance=""

cleanup()
{
	if [ -n "$trace_instance" ]; then
		echo 0 > "$trace_instance/tracing_on" 2>/dev/null || true
		rmdir "$trace_instance" 2>/dev/null || true
	fi
	kill -INT "$observer" 2>/dev/null || true
	wait "$observer" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 50); do
	grep -q '^LX_READY experiment=virt-paraio observer=virtio$' captures/virt-paraio-observer.log 2>/dev/null && break
	kill -0 "$observer" 2>/dev/null || { cat captures/virt-paraio-observer.log >&2; exit 1; }
	sleep 0.1
done
grep -q '^LX_READY experiment=virt-paraio observer=virtio$' captures/virt-paraio-observer.log || { cat captures/virt-paraio-observer.log >&2; exit 1; }

mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mountpoint -q /sys/kernel/debug || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
trace_root=""
for root in /sys/kernel/tracing /sys/kernel/debug/tracing; do
	if [ -d "$root/events/kvm/kvm_entry" ]; then trace_root="$root"; break; fi
done
[ -n "$trace_root" ] || { echo "error: KVM tracepoints not found" >&2; exit 1; }

instance_name="kernel-oops-virt-paraio-$$"
mkdir "$trace_root/instances/$instance_name"
trace_instance="$trace_root/instances/$instance_name"
grep -qw mono "$trace_instance/trace_clock" || { echo "error: mono trace clock unavailable" >&2; exit 1; }
echo mono > "$trace_instance/trace_clock"

: > captures/virt-paraio-trace-formats.log
for event in kvm_entry kvm_exit kvm_userspace_exit; do
	[ -r "$trace_root/events/kvm/$event/format" ] || { echo "error: missing $event format" >&2; exit 1; }
	cat "$trace_root/events/kvm/$event/format" >> captures/virt-paraio-trace-formats.log
	echo 1 > "$trace_instance/events/kvm/$event/enable"
done

if [ -r "$trace_root/events/kvm/kvm_mmio/format" ]; then
	cat "$trace_root/events/kvm/kvm_mmio/format" >> captures/virt-paraio-trace-formats.log
	if grep -q 'field:.*gpa' "$trace_root/events/kvm/kvm_mmio/format"; then
		echo 1 > "$trace_instance/events/kvm/kvm_mmio/enable"
		echo "tracefs: enabled optional kvm_mmio with GPA field" >&2
	fi
fi

echo 1 > "$trace_instance/tracing_on"
./build/vmm
echo 0 > "$trace_instance/tracing_on"
cat "$trace_instance/trace" > captures/virt-paraio-Trace.txt

kill -INT "$observer"
wait "$observer"
grep -q '^LX_DONE experiment=virt-paraio observer=virtio records=' captures/virt-paraio-observer.log

cleanup
trap - EXIT
[ -s captures/virt-paraio-Trace.txt ] && [ -s captures/virt-paraio.eBPF.ndjson ]

python3 -c 'import json,sys; [json.loads(line) for line in open(sys.argv[1]) if line.strip()]' captures/virt-paraio.eBPF.ndjson
[ "$(grep -c '"register":"QueueNotify"' captures/virt-paraio.eBPF.ndjson)" -eq 1 ]
begin="$(grep '"event_name":"queue_backend_begin"' captures/virt-paraio.eBPF.ndjson)"
end="$(grep '"event_name":"queue_backend_end"' captures/virt-paraio.eBPF.ndjson)"
[ -n "$begin" ] && [ -n "$end" ]
grep -q '"descriptor":{"present":true,"index":0,"addr":"0x7000","len":32,"flags":"0x2","device_writable":true,"next":0}' <<<"$begin"
grep -q '"queue":{"present":true,"size":8,"ready":true,"last_avail_idx":0' <<<"$begin"
grep -q '"avail":{"present":true,"flags":"0x0","idx":1,"ring0":0}' <<<"$begin"
grep -q '"used":{"present":true,"flags":"0x0","idx":0,"ring0_id":0,"ring0_len":0}' <<<"$begin"
grep -q '"queue":{"present":true,"size":8,"ready":true,"last_avail_idx":1' <<<"$end"
grep -q '"used":{"present":true,"flags":"0x0","idx":1,"ring0_id":0,"ring0_len":32}' <<<"$end"
REMOTE

fetch_captures
