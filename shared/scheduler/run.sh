#!/usr/bin/env bash
set -euo pipefail

# One workload run feeds both halves of the SCHED visualization:
#
#   tracefs sched_* events  -> scheduler-lifecycle.txt -> task lifetimes
#   eBPF __enqueue_entity   -> scheduler-cfs.ndjson    -> per-CPU RB trees
#
# Starting both observers before workload_fork keeps their timestamps aligned.
# Run this inside the guest after `make -C shared/scheduler` on the host.

capture_file=/mnt/host/_captures/scheduler-lifecycle.txt
cfs_capture=/mnt/host/_captures/scheduler-cfs.ndjson
observer_output=$(mktemp /tmp/scheduler-cfs.XXXXXX)
observer_pid=
workload_status=0

cleanup()
{
	set +e
	cd /sys/kernel/tracing
	echo 0 > tracing_on
	mkdir -p /mnt/host/_captures
	cat trace > "$capture_file"
	if [[ -n ${observer_pid:-} ]]; then
		kill -INT "$observer_pid" 2>/dev/null || true
		wait "$observer_pid" 2>/dev/null || true
	fi
	rm -f "$observer_output"
	echo 0 > events/sched/sched_process_fork/enable
	echo 0 > events/sched/sched_wakeup_new/enable
	echo 0 > events/sched/sched_switch/enable
	echo 0 > events/sched/sched_process_exit/enable
	echo 0 > events/sched/sched_process_wait/enable
	echo 0 > events/sched/sched_process_free/enable
	echo > trace
}

cd /sys/kernel/tracing

if [[ ! -x /mnt/host/scheduler/workload_fork ]]; then
	echo 'tracing: missing /mnt/host/scheduler/workload_fork; build shared/scheduler first' >&2
	exit 1
fi
mkdir -p /mnt/host/_captures
: > "$cfs_capture"

# The userspace loader writes newline-delimited CFS tree states to stdout and
# reserves stderr for attachment/verifier diagnostics.
/mnt/host/scheduler/cfs > "$cfs_capture" 2> "$observer_output" &
observer_pid=$!
for _ in $(seq 1 100); do
	if grep -q 'attached enqueue entry/return probes' "$observer_output"; then
		break
	fi
	if ! kill -0 "$observer_pid" 2>/dev/null; then
		cat "$observer_output" >&2
		exit 1
	fi
	sleep 0.1
done
echo 0 > tracing_on
echo 0 > events/enable
echo > set_event
echo > trace

# These tracepoints describe creation, first wakeup, CPU execution, exit, parent wait, and final task_struct release.
# They deliberately remain unfiltered so the lifelines include the workload, shell, workers, and idle tasks that actually exchanged CPU time during the same interval.

for event in sched_process_fork sched_wakeup_new sched_switch sched_process_exit sched_process_wait sched_process_free; do
	echo 0 > "events/sched/${event}/filter"
done
echo 1 > events/sched/sched_process_fork/enable
echo 1 > events/sched/sched_wakeup_new/enable
echo 1 > events/sched/sched_switch/enable
echo 1 > events/sched/sched_process_exit/enable
echo 1 > events/sched/sched_process_wait/enable
echo 1 > events/sched/sched_process_free/enable
trap cleanup EXIT INT TERM
echo 1 > tracing_on
/mnt/host/scheduler/workload_fork || workload_status=$?
cleanup
trap - EXIT INT TERM

if ! grep -q 'sched_' "$capture_file"; then
	echo "tracing: produced no sched trace records" >&2
	exit 1
fi
if ! grep -q '"type":"event"' "$cfs_capture"; then
	echo "scheduler: produced no CFS tree events" >&2
	exit 1
fi

exit "$workload_status"
