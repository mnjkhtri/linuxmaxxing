#!/usr/bin/env bash
set -euo pipefail

capture_file=/mnt/host/_captures/ebpf-cfs_tree-rbtree.ndjson
observer_output=$(mktemp /tmp/cfs-tree-run.XXXXXX)
workload_output=$(mktemp /tmp/cfs-tree-workload.XXXXXX)
tracer_pid=
tracer_status=0

stop_tracer()
{
	if [[ -n ${tracer_pid:-} ]]; then
		kill -INT "$tracer_pid" 2>/dev/null || true
		wait "$tracer_pid" || tracer_status=$?
		tracer_pid=
	fi
}

cleanup()
{
	stop_tracer
	rm -f "$observer_output" "$workload_output"
}

mkdir -p /mnt/host/_captures
: > "$capture_file"
/mnt/host/ebpf/cfs_tree > "$capture_file" 2> "$observer_output" &
tracer_pid=$!
trap cleanup EXIT INT TERM

observer_ready=0
for _ in $(seq 1 100); do
	if grep -q "attached enqueue entry/return probes" "$observer_output"; then
		observer_ready=1
		break
	fi
	if ! kill -0 "$tracer_pid" 2>/dev/null; then
		stop_tracer
		echo "cfs trace: observer failed before workload start" >&2
		cat "$observer_output" >&2
		exit "${tracer_status:-1}"
	fi
	sleep 0.1
done

if ((observer_ready == 0)); then
	stop_tracer
	echo "cfs trace: observer did not become ready before workload start" >&2
	cat "$observer_output" >&2
	exit 1
fi

workload_status=0
/mnt/host/_work/build/fork_25_processes > "$workload_output" || workload_status=$?
stop_tracer

if ! grep -q '"type":"event"' "$capture_file"; then
	echo "cfs trace: observer produced no CFS tree events" >&2
	cat "$observer_output" >&2
	exit 1
fi

rm -f "$observer_output" "$workload_output"
trap - EXIT INT TERM

if ((workload_status != 0)); then
	exit "$workload_status"
fi
exit "$tracer_status"
