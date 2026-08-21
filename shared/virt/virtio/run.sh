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

python3 - captures/virt-paraio.eBPF.ndjson <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
meta = records[0]
snapshots = records[1:]
assert meta["schema_version"] == 3
assert meta["queue_size"] == 8
assert meta["phase_c_request_count"] == 5
assert meta["total_request_count"] == 6
assert meta["phase_c_notification"] == "KVM_EXIT_MMIO"
assert meta["phase_d_notification"] == "KVM_IOEVENTFD"

notifies = [record for record in snapshots if record["event_info"]["mmio"]["register"] == "QueueNotify"]
kicks = [record for record in snapshots if record["event_info"]["event_name"] == "ioeventfd_kick"]
begins = [record for record in snapshots if record["event_info"]["event_name"] == "queue_backend_begin"]
ends = [record for record in snapshots if record["event_info"]["event_name"] == "queue_backend_end"]
assert len(notifies) == 2
assert len(kicks) == 1
assert len(begins) == 3
assert len(ends) == 3
assert kicks[0]["event_info"]["phase"] == "D"
assert kicks[0]["event_info"]["ioeventfd"] == {"present": True, "count": 1, "address": "0x10000050", "length": 4, "datamatch": 0}

expected_buffers = [0x7000 + index * 0x100 for index in range(6)]
for index, address in enumerate(expected_buffers):
    entry = begins[2]["state"]["descriptor"]["entries"][index]
    assert int(entry["addr"], 16) == address
    assert entry["len"] == 32
    assert entry["flags"] == "0x2"
    assert entry["next"] == 0

assert begins[0]["state"]["avail"]["idx"] == 1
assert begins[0]["state"]["queue"]["last_avail_idx"] == 0
assert begins[0]["state"]["used"]["idx"] == 0
assert ends[0]["state"]["avail"]["idx"] == 1
assert ends[0]["state"]["queue"]["last_avail_idx"] == 1
assert ends[0]["state"]["used"]["idx"] == 1

assert begins[1]["state"]["avail"]["idx"] == 5
assert begins[1]["state"]["avail"]["ring"][:5] == [0, 1, 2, 3, 4]
assert begins[1]["state"]["queue"]["last_avail_idx"] == 1
assert begins[1]["state"]["used"]["idx"] == 1
assert ends[1]["state"]["avail"]["idx"] == 5
assert ends[1]["state"]["queue"]["last_avail_idx"] == 5
assert ends[1]["state"]["used"]["idx"] == 5
assert [(entry["id"], entry["len"]) for entry in ends[1]["state"]["used"]["ring"][:5]] == [(index, 32) for index in range(5)]

assert kicks[0]["state"]["avail"]["idx"] == 6
assert kicks[0]["state"]["queue"]["last_avail_idx"] == 5
assert kicks[0]["state"]["used"]["idx"] == 5
assert begins[2]["event_info"]["phase"] == "D"
assert begins[2]["state"]["avail"]["idx"] == 6
assert begins[2]["state"]["avail"]["ring"][5] == 5
assert begins[2]["state"]["queue"]["last_avail_idx"] == 5
assert begins[2]["state"]["used"]["idx"] == 5
assert ends[2]["event_info"]["phase"] == "D"
assert ends[2]["state"]["avail"]["idx"] == 6
assert ends[2]["state"]["queue"]["last_avail_idx"] == 6
assert ends[2]["state"]["used"]["idx"] == 6
assert ends[2]["state"]["used"]["ring"][5] == {"slot": 5, "id": 5, "len": 32}
PY
REMOTE

fetch_captures
