#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# CAPTURE MODEL
#
# One workload_fork run feeds both halves of the Scheduler visualization:
#
#   tracefs sched_* events  -> scheduler-Trace.txt   (what happened)
#   eBPF post-enqueue CFS   -> scheduler.eBPF.ndjson (what state looked like)
#
# Both observers are active before the workload starts and both run on CLOCK_MONOTONIC.
# The eBPF observer emits only the schedNNN workload enqueues, so tracing ends the moment the workload exits.
# The tracefs instance still captures the full sched_* stream for cross-reference.
# The frontend compares tracefs seconds * 1e9 directly with the eBPF time_ns without offsets.
#
# Scheduler is currently the reference capture pattern for future experiments:
#   - private tracefs instance (never touches the global one)
#   - one machine-readable readiness line (LX_READY) gates the workload
#   - observer stdout is NDJSON only; diagnostics live on stderr
#   - structured cleanup on every exit path
# =============================================================================

# Run this inside the guest as root after `make -C shared/scheduler` on the host.

WORKLOAD=${SCHED_WORKLOAD:-/mnt/host/scheduler/workload_fork}
OBSERVER=${SCHED_OBSERVER:-/mnt/host/scheduler/cfs}
CAPTURE_DIR=${SCHED_CAPTURE_DIR:-/mnt/host/_captures}
TRACE_FILE="$CAPTURE_DIR/scheduler-Trace.txt"
NDJSON_FILE="$CAPTURE_DIR/scheduler.eBPF.ndjson"

TRACEFS=/sys/kernel/tracing
INSTANCE_NAME=linuxmaxxing-scheduler
INSTANCE="$TRACEFS/instances/$INSTANCE_NAME"

SCHED_EVENTS=(sched_process_fork sched_wakeup_new sched_switch sched_process_exit sched_process_wait sched_process_free)

OBSERVER_PID=
OBSERVER_LOG=
WORKLOAD_STATUS=0
OBSERVER_STATUS=0

log()
{
	printf 'scheduler: %s\n' "$*" >&2
}

fail()
{
	log "error: $*"
	exit 1
}

# -----------------------------------------------------------------------------
# preflight: root, binaries, tracefs, and a clean capture directory.
# -----------------------------------------------------------------------------
preflight()
{
	if [[ $(id -u) -ne 0 ]]; then
		fail "run this inside the guest as root"
	fi
	if [[ ! -x "$WORKLOAD" ]]; then
		fail "missing workload binary $WORKLOAD; run make -C shared/scheduler first"
	fi
	if [[ ! -x "$OBSERVER" ]]; then
		fail "missing eBPF observer $OBSERVER; run make -C shared/scheduler first"
	fi
	mkdir -p "$CAPTURE_DIR"
	: > "$TRACE_FILE"
	: > "$NDJSON_FILE"
	log "capture directory: $CAPTURE_DIR"
}

# -----------------------------------------------------------------------------
# setup_trace: a private tracefs instance on the mono clock with only the six lifecycle tracepoints enabled.
# The tracefs stream stays unfiltered by design: it keeps the full sched_* record for cross-referencing the scoped eBPF capture.
# -----------------------------------------------------------------------------
setup_trace()
{
	mountpoint -q /proc || mount -t proc proc /proc
	mountpoint -q /sys || mount -t sysfs sysfs /sys
	mountpoint -q "$TRACEFS" || mount -t tracefs tracefs "$TRACEFS" 2>/dev/null || true
	[[ -d "$TRACEFS/events" ]] || fail "tracefs not available at $TRACEFS"

	if [[ -d "$INSTANCE" ]]; then
		echo 0 > "$INSTANCE/tracing_on" 2>/dev/null || true
		rmdir "$INSTANCE" 2>/dev/null || rm -rf "$INSTANCE" 2>/dev/null || true
	fi
	mkdir "$INSTANCE" || fail "cannot create tracefs instance $INSTANCE_NAME"

	echo 0 > "$INSTANCE/tracing_on"
	echo > "$INSTANCE/trace"
	# The trace_clock file lists every available clock and marks the selected one with brackets, e.g. "local [mono] global counter".
	# Test that mono is the selected clock after writing it.
	if ! echo mono > "$INSTANCE/trace_clock" 2>/dev/null || ! grep -q '\[mono\]' "$INSTANCE/trace_clock"; then
		fail "monotonic trace clock cannot be configured on instance $INSTANCE_NAME"
	fi

	for event in "${SCHED_EVENTS[@]}"; do
		local control="$INSTANCE/events/sched/$event/enable"
		if [[ ! -e $control ]]; then
			fail "required tracepoint unavailable: $event"
		fi
		echo 0 > "$control"
		echo 1 > "$control"
	done
	log "private tracefs instance ready: $INSTANCE (clock=mono)"
}

# -----------------------------------------------------------------------------
# start_observer: the observer writes NDJSON to stdout and protocol lines to a temporary stderr log.
# Never mix the two streams.
# -----------------------------------------------------------------------------
start_observer()
{
	OBSERVER_LOG=$(mktemp /tmp/scheduler-cfs.XXXXXX)
	: > "$NDJSON_FILE"
	"$OBSERVER" > "$NDJSON_FILE" 2> "$OBSERVER_LOG" &
	OBSERVER_PID=$!
	log "observer started (pid $OBSERVER_PID)"
}

# -----------------------------------------------------------------------------
# wait_for_observer: block until LX_READY or the observer dies.
# -----------------------------------------------------------------------------
wait_for_observer()
{
	for _ in $(seq 1 100); do
		if grep -q '^LX_READY' "$OBSERVER_LOG" 2>/dev/null; then
			log "observer ready"
			return 0
		fi
		if ! kill -0 "$OBSERVER_PID" 2>/dev/null; then
			cat "$OBSERVER_LOG" >&2
			fail "eBPF observer exited before LX_READY"
		fi
		sleep 0.1
	done
	cat "$OBSERVER_LOG" >&2
	fail "timed out waiting for LX_READY"
}

# -----------------------------------------------------------------------------
# run_workload: only now may tracing be enabled; both observers are live.
# The workload exit status is preserved for the script's own exit.
# -----------------------------------------------------------------------------
run_workload()
{
	echo 1 > "$INSTANCE/tracing_on"
	log "tracing enabled; starting workload"
	"$WORKLOAD" || WORKLOAD_STATUS=$?
	echo 0 > "$INSTANCE/tracing_on"
	log "tracing disabled; workload exit status $WORKLOAD_STATUS"
}

# -----------------------------------------------------------------------------
# stop_capture: SIGINT the observer, wait for its clean LX_DONE, then copy the private instance trace to the public capture file.
# -----------------------------------------------------------------------------
stop_capture()
{
	if [[ -n ${OBSERVER_PID} ]] && kill -0 "$OBSERVER_PID" 2>/dev/null; then
		kill -INT "$OBSERVER_PID" 2>/dev/null || true
		wait "$OBSERVER_PID" || OBSERVER_STATUS=$?
		OBSERVER_PID=
	fi
	cat "$INSTANCE/trace" > "$TRACE_FILE"
	log "captured $(wc -l < "$TRACE_FILE") trace lines"
}

# -----------------------------------------------------------------------------
# validate_capture: plain-shell checks on both artifacts (no jq dependency).
# -----------------------------------------------------------------------------
validate_capture()
{
	if ! grep -q 'sched_' "$TRACE_FILE"; then
		fail "tracefs capture has no sched_* events"
	fi
	if ! sed -n '1p' "$NDJSON_FILE" | grep -q '"kind":"meta"'; then
		fail "eBPF output has no metadata record on the first line"
	fi
	if ! grep -q '"kind":"snapshot"' "$NDJSON_FILE"; then
		fail "eBPF output has no snapshots"
	fi
	log "captures validated"
}

# -----------------------------------------------------------------------------
# cleanup: restore everything on normal exit, SIGINT, SIGTERM, or any failure.
# -----------------------------------------------------------------------------
cleanup()
{
	local status=$?

	trap - EXIT HUP INT TERM
	set +e

	if [[ -n ${OBSERVER_PID:-} ]] && kill -0 "$OBSERVER_PID" 2>/dev/null; then
		kill -INT "$OBSERVER_PID" 2>/dev/null
		wait "$OBSERVER_PID" 2>/dev/null
		OBSERVER_PID=
	fi
	if [[ -n ${INSTANCE:-} && -d "$INSTANCE" ]]; then
		echo 0 > "$INSTANCE/tracing_on" 2>/dev/null
		for event in "${SCHED_EVENTS[@]:-}"; do
			[[ -e "$INSTANCE/events/sched/$event/enable" ]] && echo 0 > "$INSTANCE/events/sched/$event/enable" 2>/dev/null
		done
		rmdir "$INSTANCE" 2>/dev/null || rm -rf "$INSTANCE" 2>/dev/null
	fi
	[[ -n ${OBSERVER_LOG:-} ]] && rm -f "$OBSERVER_LOG" 2>/dev/null

	exit "$status"
}
trap cleanup EXIT HUP INT TERM

preflight
setup_trace
start_observer
wait_for_observer
run_workload
stop_capture
validate_capture

if (( WORKLOAD_STATUS != 0 )); then
	log "workload failed with status $WORKLOAD_STATUS"
	exit "$WORKLOAD_STATUS"
fi
if (( OBSERVER_STATUS != 0 )); then
	log "observer exited with status $OBSERVER_STATUS"
	exit "$OBSERVER_STATUS"
fi

log "done"
