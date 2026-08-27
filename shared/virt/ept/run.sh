#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
CAPTURE_ROOT="$REPO_ROOT/shared/_captures"
TARGET_FILE="$SCRIPT_DIR/../cloudlab"
REMOTE_DIR="linuxmaxxing-virt-ept"
EPT_DIR="$REMOTE_DIR/shared/virt/ept"
TARGET="$(sed -n '1{/^[[:space:]]*#/d; s/^[[:space:]]*//; s/[[:space:]]*$//; p; q}' "$TARGET_FILE")"
[ -n "$TARGET" ] || { echo "error: empty CloudLab target" >&2; exit 1; }
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -o StrictHostKeyChecking=no)
mkdir -p "$CAPTURE_ROOT"

fetch_captures()
{
	scp -p "${ssh_opts[@]}" "$TARGET:$EPT_DIR/captures/virt-ept-Trace.txt" "$CAPTURE_ROOT/virt-ept-Trace.txt"
	scp -p "${ssh_opts[@]}" "$TARGET:$EPT_DIR/captures/virt-ept.eBPF.ndjson" "$CAPTURE_ROOT/virt-ept.eBPF.ndjson"
	scp -p "${ssh_opts[@]}" "$TARGET:$EPT_DIR/captures/virt-ept-observer.log" "$CAPTURE_ROOT/virt-ept-observer.log"
}

validate_captures()
{
	python3 - "$CAPTURE_ROOT" <<'PY_VALIDATE'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
records = [json.loads(line) for line in (root / "virt-ept.eBPF.ndjson").read_text().splitlines() if line.strip()]
assert records and records[0].get("kind") == "meta" and records[0].get("schema_version") == 4
snapshots = [record for record in records if record.get("kind") == "snapshot"]
names = [record["event_info"]["event_name"] for record in snapshots]
for required in ("kvm_entry", "kvm_exit", "kvm_userspace_exit", "kvm_unmap_hva_range", "kvm_mmu_spte_requested", "kvm_mmu_set_spte", "kvm_flush_remote_tlbs", "kvm_page_fault", "sys_enter_ioctl", "sys_exit_ioctl", "sys_enter_madvise", "sys_exit_madvise", "sys_enter_mmap", "sys_exit_mmap"):
    assert required in names, f"missing eBPF event: {required}"
assert names.count("control_begin") == 5 and names.count("control_end") == 5
assert names.count("memslot_begin") == 6 and names.count("memslot_end") == 6
ioctl_enters = [record for record in snapshots if record["event_info"]["event_name"] == "sys_enter_ioctl"]
ioctl_exits = [record for record in snapshots if record["event_info"]["event_name"] == "sys_exit_ioctl"]
assert len(ioctl_enters) == len(ioctl_exits)
assert {record["ioctl"]["call_id"] for record in ioctl_enters} == {record["ioctl"]["call_id"] for record in ioctl_exits}
ioctl_names = {record["ioctl"]["request_name"] for record in ioctl_enters}
for required in ("KVM_RUN", "KVM_SET_USER_MEMORY_REGION", "KVM_CLEAR_DIRTY_LOG"):
    assert required in ioctl_names, f"missing ioctl boundary: {required}"
madvise_enters = [record for record in snapshots if record["event_info"]["event_name"] == "sys_enter_madvise"]
madvise_exits = [record for record in snapshots if record["event_info"]["event_name"] == "sys_exit_madvise"]
assert len(madvise_enters) == len(madvise_exits)
assert {record["madvise"]["call_id"] for record in madvise_enters} == {record["madvise"]["call_id"] for record in madvise_exits}
assert {record["madvise"]["advice_name"] for record in madvise_enters} >= {"MADV_DONTNEED", "MADV_HUGEPAGE"}
mmap_enters = [record for record in snapshots if record["event_info"]["event_name"] == "sys_enter_mmap"]
mmap_exits = [record for record in snapshots if record["event_info"]["event_name"] == "sys_exit_mmap"]
assert len(mmap_enters) == len(mmap_exits) == 4
assert {record["mmap"]["call_id"] for record in mmap_enters} == {record["mmap"]["call_id"] for record in mmap_exits}
assert {record["mmap"]["length"] for record in mmap_enters} >= {"0x8000", "0x3000", "0x400000"}
if records[0].get("vmx_disposition_available"):
    assert "vmx_handle_exit_return" in names
if records[0].get("split_snapshot_available"):
    assert "kvm_mmu_split_huge_page" in names
if records[0].get("mmio_snapshot_available"):
    assert "mark_mmio_spte" in names
assert all(not record["control"]["completed"] for record in snapshots if record["event_info"]["event_name"] == "control_begin")
assert all(not record["memslot"]["completed"] for record in snapshots if record["event_info"]["event_name"] == "memslot_begin")
for kind, field, expected in (("control", "control", 5), ("memslot", "memslot", 6)):
    begins = {record[field]["operation_id"] for record in snapshots if record["event_info"]["event_name"] == f"{kind}_begin"}
    ends = {record[field]["operation_id"] for record in snapshots if record["event_info"]["event_name"] == f"{kind}_end"}
    assert len(begins) == expected and begins == ends, f"unpaired {kind} operations"
    assert all(record[field].get("result") == 0 for record in snapshots if record["event_info"]["event_name"] == f"{kind}_end")
trace = (root / "virt-ept-Trace.txt").read_text()
for required in ("kvm_entry:", "kvm_exit:", "kvm_userspace_exit:", "kvm_page_fault:", "kvm_mmu_spte_requested:", "kvm_mmu_set_spte:"):
    assert required in trace, f"missing tracepoint: {required}"
observer = (root / "virt-ept-observer.log").read_text()
assert "LX_READY experiment=virt-ept" in observer and "LX_DONE experiment=virt-ept" in observer
print(f"validated virt-ept: {len(snapshots)} eBPF records")
PY_VALIDATE
}

if [ "${VIRT_FETCH_ONLY:-0}" = 1 ]; then
	fetch_captures
	validate_captures
	exit 0
fi

# Stage one self-contained experiment tree. Generated BTF compatibility files remain remote build products.
ssh "${ssh_opts[@]}" "$TARGET" "mkdir -p -- '$EPT_DIR' '$REMOTE_DIR/shared'"
scp -p "${ssh_opts[@]}" "$SCRIPT_DIR/vmm.c" "$SCRIPT_DIR/guest.S" "$SCRIPT_DIR/observer.c" "$SCRIPT_DIR/ept.bpf.c" "$SCRIPT_DIR/ept_event.h" "$SCRIPT_DIR/Makefile" "$TARGET:$EPT_DIR/"
scp -p "${ssh_opts[@]}" "$REPO_ROOT/shared/json_writer.c" "$REPO_ROOT/shared/json_writer.h" "$TARGET:$REMOTE_DIR/shared/"
ssh "${ssh_opts[@]}" "$TARGET" "cd '$EPT_DIR' && make clean all"
ssh "${ssh_opts[@]}" "$TARGET" "sudo -n bash -s -- '$EPT_DIR'" <<'REMOTE'
set -euo pipefail
REMOTE_DIR="$1"
cd "$REMOTE_DIR"
rm -rf captures
mkdir -p captures
# Load the vendor KVM module before the observer resolves optional VMX symbols.
modprobe kvm_intel 2>/dev/null || true
observer=""
vmm=""
trace_dir=""
trace_instance=""

# Both libbpf attachment and the private tracefs instance require a mounted tracing filesystem.
mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mountpoint -q /sys/kernel/debug || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
for candidate in /sys/kernel/tracing /sys/kernel/debug/tracing; do
	if [ -d "$candidate/events/kvm/kvm_entry" ]; then trace_dir="$candidate"; break; fi
done
[ -n "$trace_dir" ] || { echo "error: KVM tracepoints not found" >&2; exit 1; }

./build/ept > captures/virt-ept.eBPF.ndjson 2> captures/virt-ept-observer.log &
observer=$!

stop_observer()
{
	if [ -n "${observer:-}" ] && kill -0 "$observer" 2>/dev/null; then
		kill -INT "$observer"
		wait "$observer"
	fi
	observer=""
}

cleanup()
{
	if [ -n "${vmm:-}" ] && kill -0 "$vmm" 2>/dev/null; then
		kill -TERM "$vmm" 2>/dev/null || true
		wait "$vmm" 2>/dev/null || true
	fi
	vmm=""
	if [ -n "$trace_instance" ]; then
		echo 0 > "$trace_instance/tracing_on" 2>/dev/null || true
		rmdir "$trace_instance" 2>/dev/null || true
	fi
	stop_observer 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 40); do
	grep -q '^LX_READY experiment=virt-ept ' captures/virt-ept-observer.log 2>/dev/null && break
	kill -0 "$observer" 2>/dev/null || { cat captures/virt-ept-observer.log >&2; exit 1; }
	sleep 0.1
done
grep -q '^LX_READY experiment=virt-ept ' captures/virt-ept-observer.log || { cat captures/virt-ept-observer.log >&2; exit 1; }

instance_name="linuxmaxxing-virt-ept-$$"
mkdir "$trace_dir/instances/$instance_name"
trace_instance="$trace_dir/instances/$instance_name"
grep -qw mono "$trace_instance/trace_clock"
echo mono > "$trace_instance/trace_clock"

enable_required()
{
	local group="$1" event="$2"
	[ -d "$trace_instance/events/$group/$event" ] || { echo "error: missing tracepoint $group:$event" >&2; exit 1; }
	echo 1 > "$trace_instance/events/$group/$event/enable"
}

enable_optional()
{
	local group="$1" event="$2"
	if [ -d "$trace_instance/events/$group/$event" ]; then
		echo 1 > "$trace_instance/events/$group/$event/enable"
		echo "enabled optional tracepoint $group:$event" >&2
	fi
}

for event in kvm_entry kvm_exit kvm_userspace_exit kvm_unmap_hva_range kvm_page_fault; do enable_required kvm "$event"; done
for event in kvm_mmu_spte_requested kvm_mmu_set_spte; do enable_required kvmmmu "$event"; done
for event in kvm_mmu_split_huge_page kvm_tdp_mmu_spte_changed mark_mmio_spte handle_mmio_page_fault check_mmio_spte fast_page_fault; do enable_optional kvmmmu "$event"; done

# Stop the child before exec so tracefs can be restricted to this exact VMM PID before any workload event fires.
bash -c 'kill -STOP "$$"; exec ./build/vmm' &
vmm=$!
for _ in $(seq 1 40); do
	state="$(ps -o stat= -p "$vmm" 2>/dev/null || true)"
	case "$state" in *T*) break;; esac
	kill -0 "$vmm" 2>/dev/null || { echo "error: VMM exited before trace gating" >&2; exit 1; }
	sleep 0.05
done
state="$(ps -o stat= -p "$vmm" 2>/dev/null || true)"
case "$state" in *T*) ;; *) echo "error: VMM did not stop for trace gating" >&2; exit 1;; esac
[ -w "$trace_instance/set_event_pid" ] || { echo "error: tracefs set_event_pid unavailable" >&2; exit 1; }
echo "$vmm" > "$trace_instance/set_event_pid"
echo 1 > "$trace_instance/tracing_on"
kill -CONT "$vmm"
wait "$vmm"
vmm=""
echo 0 > "$trace_instance/tracing_on"
cat "$trace_instance/trace" > captures/virt-ept-Trace.txt
stop_observer
grep -q '^LX_DONE experiment=virt-ept ' captures/virt-ept-observer.log || { cat captures/virt-ept-observer.log >&2; exit 1; }
cleanup
trap - EXIT
[ -s captures/virt-ept-Trace.txt ] && [ -s captures/virt-ept.eBPF.ndjson ] && [ -s captures/virt-ept-observer.log ]
REMOTE

fetch_captures
validate_captures
