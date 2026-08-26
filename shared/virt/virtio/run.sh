#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
CAPTURE_ROOT="$REPO_ROOT/shared/_captures"
TARGET_FILE="$SCRIPT_DIR/../cloudlab"
REMOTE_ROOT="kernel-oops-virt-virtio"
REMOTE_DIR="$REMOTE_ROOT/shared/virt/virtio"
TARGET="$(sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$TARGET_FILE")"
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -o StrictHostKeyChecking=no)

[ -n "$TARGET" ] || { echo "error: empty CloudLab target" >&2; exit 1; }
mkdir -p "$CAPTURE_ROOT"

fetch_captures()
{
	scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/virt-virtio.eBPF.ndjson" "$CAPTURE_ROOT/virt-virtio.eBPF.ndjson"
	scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/virt-virtio-Trace.txt" "$CAPTURE_ROOT/virt-virtio-Trace.txt"
	scp -p "${ssh_opts[@]}" "$TARGET:$REMOTE_DIR/captures/virt-virtio-observer.log" "$CAPTURE_ROOT/virt-virtio-observer.log"
}

if [ "${VIRT_FETCH_ONLY:-0}" = 1 ]; then
	fetch_captures
	exit 0
fi

ssh "${ssh_opts[@]}" "$TARGET" "mkdir -p -- '$REMOTE_DIR' '$REMOTE_ROOT/shared'"
scp -p "${ssh_opts[@]}" "$SCRIPT_DIR/vmm.c" "$SCRIPT_DIR/backend.c" "$SCRIPT_DIR/backend.h" "$SCRIPT_DIR/guest.S" "$SCRIPT_DIR/virtio.h" "$SCRIPT_DIR/virtio_event.h" "$SCRIPT_DIR/virtio.bpf.c" "$SCRIPT_DIR/observer.c" "$SCRIPT_DIR/Makefile" "$TARGET:$REMOTE_DIR/"
scp -p "${ssh_opts[@]}" "$REPO_ROOT/shared/json_writer.c" "$REPO_ROOT/shared/json_writer.h" "$TARGET:$REMOTE_ROOT/shared/"
ssh "${ssh_opts[@]}" "$TARGET" "cd '$REMOTE_DIR' && make clean all"

ssh "${ssh_opts[@]}" "$TARGET" "sudo -n bash -s -- '$REMOTE_DIR'" <<'REMOTE'
set -euo pipefail

REMOTE_DIR="$1"
cd "$REMOTE_DIR"
rm -rf captures
mkdir -p captures

./build/virtio > captures/virt-virtio.eBPF.ndjson 2> captures/virt-virtio-observer.log &
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
	grep -q '^LX_READY experiment=virt-virtio observer=virtio$' captures/virt-virtio-observer.log 2>/dev/null && break
	kill -0 "$observer" 2>/dev/null || { cat captures/virt-virtio-observer.log >&2; exit 1; }
	sleep 0.1
done
grep -q '^LX_READY experiment=virt-virtio observer=virtio$' captures/virt-virtio-observer.log || { cat captures/virt-virtio-observer.log >&2; exit 1; }

mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mountpoint -q /sys/kernel/debug || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
trace_root=""
for root in /sys/kernel/tracing /sys/kernel/debug/tracing; do
	if [ -d "$root/events/kvm/kvm_entry" ]; then trace_root="$root"; break; fi
done
[ -n "$trace_root" ] || { echo "error: KVM tracepoints not found" >&2; exit 1; }

instance_name="kernel-oops-virt-virtio-$$"
mkdir "$trace_root/instances/$instance_name"
trace_instance="$trace_root/instances/$instance_name"
grep -qw mono "$trace_instance/trace_clock" || { echo "error: mono trace clock unavailable" >&2; exit 1; }
echo mono > "$trace_instance/trace_clock"

: > captures/virt-virtio-trace-formats.log
for event in kvm_entry kvm_exit kvm_userspace_exit; do
	[ -r "$trace_root/events/kvm/$event/format" ] || { echo "error: missing $event format" >&2; exit 1; }
	cat "$trace_root/events/kvm/$event/format" >> captures/virt-virtio-trace-formats.log
	echo 1 > "$trace_instance/events/kvm/$event/enable"
done

# These are existing KVM tracepoints. Enable whichever the target kernel exports so the
# interrupt handoff remains observable without making the experiment kernel-specific.
for event in kvm_set_irq kvm_ioapic_set_irq kvm_apic_accept_irq kvm_inj_virq kvm_eoi kvm_msi_set_irq; do
	if [ -r "$trace_root/events/kvm/$event/format" ]; then
		cat "$trace_root/events/kvm/$event/format" >> captures/virt-virtio-trace-formats.log
		echo 1 > "$trace_instance/events/kvm/$event/enable"
		echo "tracefs: enabled optional $event" >&2
	fi
done

if [ -r "$trace_root/events/kvm/kvm_mmio/format" ]; then
	cat "$trace_root/events/kvm/kvm_mmio/format" >> captures/virt-virtio-trace-formats.log
	if grep -q 'field:.*gpa' "$trace_root/events/kvm/kvm_mmio/format"; then
		echo 1 > "$trace_instance/events/kvm/kvm_mmio/enable"
		echo "tracefs: enabled optional kvm_mmio with GPA field" >&2
	fi
fi

echo 1 > "$trace_instance/tracing_on"
./build/vmm
echo 0 > "$trace_instance/tracing_on"
cat "$trace_instance/trace" > captures/virt-virtio-Trace.txt

kill -INT "$observer"
wait "$observer"
grep -q '^LX_DONE experiment=virt-virtio observer=virtio records=' captures/virt-virtio-observer.log

cleanup
trap - EXIT
[ -s captures/virt-virtio-Trace.txt ] && [ -s captures/virt-virtio.eBPF.ndjson ]

python3 - captures/virt-virtio.eBPF.ndjson <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
meta = records[0]
snapshots = records[1:]
assert meta["schema_version"] == 6
assert meta["structured_event_types"] == 11
assert meta["queue_size"] == 8
assert meta["phase_c_request_count"] == 5
assert meta["total_request_count"] == 6
assert meta["phase_c_request_notification"] == "KVM_EXIT_MMIO"
assert meta["phase_c_completion"] == "polling"
assert meta["phase_d_request_notification"] == "KVM_IOEVENTFD"
assert meta["phase_d_completion_notification"] == "KVM_IRQFD"
assert meta["irqfd_gsi"] == 5
assert meta["backend_location"] == "userspace"

notifies = [record for record in snapshots if record["event_info"]["event_name"] == "virtio_mmio" and record["event_info"]["mmio"]["register"] == "QueueNotify"]
kicks = [record for record in snapshots if record["event_info"]["event_name"] == "ioeventfd_kick"]
calls = [record for record in snapshots if record["event_info"]["event_name"] == "irqfd_signal"]
mmio_returns = [record for record in snapshots if record["event_info"]["event_name"] == "virtio_mmio_return"]
kick_returns = [record for record in snapshots if record["event_info"]["event_name"] == "ioeventfd_kick_return"]
call_returns = [record for record in snapshots if record["event_info"]["event_name"] == "irqfd_signal_return"]
begins = [record for record in snapshots if record["event_info"]["event_name"] == "queue_backend_begin"]
ends = [record for record in snapshots if record["event_info"]["event_name"] == "queue_backend_end"]
ioctl_enters = [record for record in snapshots if record["event_info"]["event_name"] == "sys_enter_ioctl"]
ioctl_exits = [record for record in snapshots if record["event_info"]["event_name"] == "sys_exit_ioctl"]
dispositions = [record for record in snapshots if record["event_info"]["event_name"] == "vmx_handle_exit_return"]
status_reads = [record for record in mmio_returns if record["event_info"]["mmio"]["register"] == "InterruptStatus"]
ack_writes = [record for record in mmio_returns if record["event_info"]["mmio"]["register"] == "InterruptACK"]
assert len(notifies) == 2
assert len(kicks) == 1
assert len(calls) == 1
assert len(mmio_returns) == len([record for record in snapshots if record["event_info"]["event_name"] == "virtio_mmio"]) == 36
assert len(kick_returns) == 1
assert len(call_returns) == 1
assert kick_returns[0]["event_info"]["operation_id"] == kicks[0]["event_info"]["operation_id"]
assert call_returns[0]["event_info"]["operation_id"] == calls[0]["event_info"]["operation_id"]
assert len(begins) == 3
assert len(ends) == 3
assert [record["event_info"]["operation_id"] for record in begins] == [record["event_info"]["operation_id"] for record in ends]
assert len(ioctl_enters) == len(ioctl_exits) and len(ioctl_enters) > 0
ioctl_names = {record["state"]["ioctl"]["request_name"] for record in ioctl_enters}
assert {"KVM_SET_USER_MEMORY_REGION", "KVM_RUN", "KVM_IOEVENTFD", "KVM_IRQFD"} <= ioctl_names
if meta["vmx_disposition_available"]:
    assert dispositions
assert len(status_reads) == 1
assert len(ack_writes) == 1
assert kicks[0]["event_info"]["phase"] == "D"
assert kicks[0]["event_info"]["ioeventfd"] == {"present": True, "count": 1, "address": "0x10000050", "length": 4, "datamatch": 0}
assert calls[0]["event_info"]["irqfd"] == {"present": True, "count": 1, "gsi": 5}

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
assert calls[0]["event_info"]["phase"] == "D"
assert calls[0]["state"]["device"]["interrupt_status"] == "0x1"
assert calls[0]["state"]["queue"]["last_avail_idx"] == 6
assert calls[0]["state"]["used"]["idx"] == 6
assert status_reads[0]["event_info"]["phase"] == "D"
assert status_reads[0]["event_info"]["mmio"]["direction"] == "read"
assert status_reads[0]["event_info"]["mmio"]["value"] == "0x1"
assert ack_writes[0]["event_info"]["phase"] == "D"
assert ack_writes[0]["event_info"]["mmio"]["direction"] == "write"
assert ack_writes[0]["event_info"]["mmio"]["value"] == "0x1"
assert ack_writes[0]["state"]["device"]["interrupt_status"] == "0x0"
PY
REMOTE

fetch_captures
