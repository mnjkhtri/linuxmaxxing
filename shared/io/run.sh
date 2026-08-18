#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# CAPTURE MODEL
#
# One workload_qedu run feeds all three capture artifacts:
#
#   io-Phases.ndjson   workload structured phase records (source=workload)
#   io-Trace.txt       raw tracefs QEDU event activity
#   io-Report.txt      final post-workload driver/device state (sysfs+debugfs)
#
# The workload emits NDJSON phase records to stdout with sequence and monotonic
# time_ns; structured phases are authoritative.  The private-instance trace is
# a separate raw kernel-side source correlated to phases by time.
#
# This runner follows the scheduler/memory lifecycle pattern:
#   - private tracefs instance (never touches the global one)
#   - monotone clock, verified as [mono] before any capture
#   - pre-module-load tracing so vector_alloc/vector_config evidence at probe
#     is captured before qedu.ko is inserted
#   - workload stops itself so PID filters are installed before any device I/O
#   - structured cleanup on every exit path; the module is left loaded on
#     success so the driver state stays inspectable
# =============================================================================

MODULE=./qedu.ko
WORKLOAD=./workload_qedu
CAPTURE_DIR=${QEDU_CAPTURE_DIR:-../_captures}
PHASES_CAPTURE=${CAPTURE_DIR}/io-Phases.ndjson
TRACE_CAPTURE=${CAPTURE_DIR}/io-Trace.txt
REPORT_CAPTURE=${CAPTURE_DIR}/io-Report.txt
SYSFS_DIR=/sys/class/misc/qedu
DEBUGFS_DIR=/sys/kernel/debug/qedu
TRACEFS=/sys/kernel/tracing
INSTANCE_NAME=linuxmaxxing-io
INSTANCE="${TRACEFS}/instances/${INSTANCE_NAME}"

QEDU_IRQ=
WORKLOAD_PID=
ORIGINAL_TIMEOUT=
RUN_TIMEOUT=1500

# Events active before qedu.ko is inserted capture probe-time vector evidence.
# The worker lifecycle events are enabled here but pinned to the qedu_dma
# callback symbols right after insmod resolves them.
PRELOAD_REQUIRED=(irq/irq_handler_entry irq/irq_handler_exit
	workqueue/workqueue_queue_work workqueue/workqueue_activate_work
	workqueue/workqueue_execute_start workqueue/workqueue_execute_end)
# irq vectors are optional because some kernels expose them and others do not.
OPTIONAL_EVENTS=(irq_vectors/vector_config irq_vectors/vector_alloc)
# Workload events are enabled only once the workload PID is known, so their
# filters can be installed before any device I/O and no setup noise is captured.
WORKLOAD_REQUIRED=(syscalls/sys_enter_openat syscalls/sys_exit_openat
	syscalls/sys_enter_read syscalls/sys_exit_read
	syscalls/sys_enter_write syscalls/sys_exit_write
	syscalls/sys_enter_close syscalls/sys_exit_close
	sched/sched_switch sched/sched_wakeup sched/sched_waking
	exceptions/page_fault_user)
SKIPPED_EVENTS=()

log()
{
	printf 'qedu: %s\n' "$*" >&2
}

fail()
{
	log "error: $*"
	exit 1
}

event_ctl()
{
	printf '%s/events/%s/%s' "${INSTANCE}" "$1" "$2"
}

# -----------------------------------------------------------------------------
# preflight: root, binaries, and a clean capture directory.
# -----------------------------------------------------------------------------
preflight()
{
	if [[ $(id -u) -ne 0 ]]; then
		fail "run this inside the guest as root"
	fi
	if [[ ! -r ${MODULE} ]]; then
		fail "missing ${MODULE}; run make -C shared/io"
	fi
	if [[ ! -x ${WORKLOAD} ]]; then
		fail "missing ${WORKLOAD}; run make -C shared/io"
	fi
	mkdir -p "${CAPTURE_DIR}"
	: > "${PHASES_CAPTURE}"
	: > "${TRACE_CAPTURE}"
	: > "${REPORT_CAPTURE}"
}

# -----------------------------------------------------------------------------
# find_device: locate the QEMU EDU PCI device and its shared IRQ.
# -----------------------------------------------------------------------------
find_device()
{
	local device_path

	for device_path in /sys/bus/pci/devices/*; do
		[[ $(< "${device_path}/vendor") == 0x1234 ]] || continue
		[[ $(< "${device_path}/device") == 0x11e8 ]] || continue
		QEDU_IRQ=$(< "${device_path}/irq")
		log "QEMU EDU device ${device_path##*/} on IRQ ${QEDU_IRQ}"
		return 0
	done
	fail "QEMU EDU device 1234:11e8 was not found"
}

# -----------------------------------------------------------------------------
# reset_instance: create a fresh private tracefs instance.
# -----------------------------------------------------------------------------
reset_instance()
{
	mountpoint -q /proc || mount -t proc proc /proc
	mountpoint -q /sys || mount -t sysfs sysfs /sys
	mkdir -p /sys/kernel/debug
	mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug
	mkdir -p "${TRACEFS}"
	mountpoint -q "${TRACEFS}" || mount -t tracefs tracefs "${TRACEFS}" 2>/dev/null || true
	[[ -d "${TRACEFS}/events" ]] || fail "tracefs not available at ${TRACEFS}"

	if [[ -d ${INSTANCE} ]]; then
		echo 0 > "${INSTANCE}/tracing_on" 2>/dev/null || true
		rmdir "${INSTANCE}" 2>/dev/null || rm -rf "${INSTANCE}" 2>/dev/null || true
	fi
	mkdir "${INSTANCE}" || fail "cannot create tracefs instance ${INSTANCE_NAME}"

	echo 0 > "${INSTANCE}/tracing_on"
	echo nop > "${INSTANCE}/current_tracer" 2>/dev/null || true
	echo 32768 > "${INSTANCE}/buffer_size_kb" 2>/dev/null || true
	if ! echo mono > "${INSTANCE}/trace_clock" 2>/dev/null || ! grep -q '\[mono\]' "${INSTANCE}/trace_clock"; then
		fail "monotonic trace clock cannot be configured on instance ${INSTANCE_NAME}"
	fi
	echo > "${INSTANCE}/trace"
}

# -----------------------------------------------------------------------------
# enable_event: enable a tracepoint, recording unavailable optional ones.
# -----------------------------------------------------------------------------
enable_event()
{
	local event=$1
	local ctl
	ctl=$(event_ctl "${event}" enable)

	if [[ -e ${ctl} ]]; then
		echo 1 > "${ctl}"
		return 0
	fi
	if [[ " ${OPTIONAL_EVENTS[*]} " == *" ${event} "* ]]; then
		SKIPPED_EVENTS+=("${event}")
		return 0
	fi
	fail "required trace event unavailable: ${event}"
}

set_filter()
{
	local event=$1
	local filter=$2
	[[ -e $(event_ctl "${event}" filter) ]] && echo "${filter}" > "$(event_ctl "${event}" filter)"
}

enable_header()
{
	local event
	for event in "${PRELOAD_REQUIRED[@]}" "${OPTIONAL_EVENTS[@]}"; do
		enable_event "${event}"
	done

	# Permanent workqueue tracepoints expose the hardirq -> worker handoff.
	# The dedicated queue name keeps queue_work noise out.
	set_filter workqueue/workqueue_queue_work 'workqueue == "qedu_dma"'

	# QEDU IRQ evidence: only this device's shared IRQ line.
	set_filter irq/irq_handler_entry "irq == ${QEDU_IRQ}"
	set_filter irq/irq_handler_exit "irq == ${QEDU_IRQ}"
	set_filter irq_vectors/vector_config "irq == ${QEDU_IRQ}"
	set_filter irq_vectors/vector_alloc "irq == ${QEDU_IRQ}"

	if (( ${#SKIPPED_EVENTS[@]} > 0 )); then
		log "skipped unavailable trace events: ${SKIPPED_EVENTS[*]}"
	fi
	log "private tracefs instance ready: ${INSTANCE} (clock=mono)"
}

# -----------------------------------------------------------------------------
# enable_preload_trace + load_module: capture vector allocation/configuration
# that happens at probe, so tracing must be live before insmod.
# -----------------------------------------------------------------------------
enable_preload_trace()
{
	echo 1 > "${INSTANCE}/tracing_on"
}

load_module()
{
	if grep -q '^qedu ' /proc/modules; then
		rmmod qedu
	fi
	insmod "${MODULE}"
	log "qedu.ko inserted"
}

# -----------------------------------------------------------------------------
# configure_module_trace_filters: resolve the two qedu_dma callback symbols and
# pin the worker lifecycle events to those function identities.
# -----------------------------------------------------------------------------
configure_module_trace_filters()
{
	local advance finish pair
	advance=$(awk '$3 == "qedu_dma_advance_work" { print "0x"$1; exit }' /proc/kallsyms)
	finish=$(awk '$3 == "qedu_dma_finish_work" { print "0x"$1; exit }' /proc/kallsyms)
	if [[ -z ${advance} || -z ${finish} ]]; then
		fail "qedu_dma callback symbols not found; cannot filter worker events"
	fi
	pair="function == ${advance} || function == ${finish}"
	for event in workqueue/workqueue_activate_work workqueue/workqueue_execute_start workqueue/workqueue_execute_end; do
		set_filter "${event}" "${pair}"
	done
	log "qedu_dma worker filters: ${pair}"
}

# -----------------------------------------------------------------------------
# set_run_timeout: capture the driver default, override it for this run, and
# remember the original so it can be restored on every exit path.
# -----------------------------------------------------------------------------
set_run_timeout()
{
	ORIGINAL_TIMEOUT=$(< "${SYSFS_DIR}/timeout_ms")
	echo "${RUN_TIMEOUT}" > "${SYSFS_DIR}/timeout_ms"
	log "sysfs timeout_ms ${ORIGINAL_TIMEOUT} -> ${RUN_TIMEOUT}"
}

# -----------------------------------------------------------------------------
# start_workload: trace off; the workload stops itself immediately so its PID
# can be installed in PID-specific filters before any device I/O.
# -----------------------------------------------------------------------------
start_workload()
{
	echo 0 > "${INSTANCE}/tracing_on"
	"${WORKLOAD}" --trace-wait > "${PHASES_CAPTURE}" &
	WORKLOAD_PID=$!
	while [[ -r /proc/${WORKLOAD_PID}/status ]] && ! grep -q '^State:.*T' "/proc/${WORKLOAD_PID}/status"; do
		:
	done
	if ! kill -0 "${WORKLOAD_PID}" 2>/dev/null; then
		wait "${WORKLOAD_PID}"
		fail "workload exited before trace filters were installed"
	fi
	log "workload stopped (pid ${WORKLOAD_PID}) waiting for trace filters"
}

# -----------------------------------------------------------------------------
# configure_workload_filters: enable and pin PID-specific syscall, sched, and
# fault events.  Because the workload is stopped, filters are installed before
# any device I/O happens.
# -----------------------------------------------------------------------------
configure_workload_filters()
{
	local event
	for event in "${WORKLOAD_REQUIRED[@]}"; do
		enable_event "${event}"
	done
	for event in sys_enter_openat sys_exit_openat sys_enter_read sys_exit_read \
		sys_enter_write sys_exit_write sys_enter_close sys_exit_close; do
		set_filter "syscalls/${event}" "common_pid == ${WORKLOAD_PID}"
	done
	set_filter sched/sched_switch "prev_pid == ${WORKLOAD_PID} || next_pid == ${WORKLOAD_PID} || prev_comm ~ \"kworker*\" || next_comm ~ \"kworker*\""
	set_filter sched/sched_wakeup "pid == ${WORKLOAD_PID}"
	set_filter sched/sched_waking "pid == ${WORKLOAD_PID}"
	set_filter exceptions/page_fault_user "common_pid == ${WORKLOAD_PID}"
	log "workload trace filters installed on pid ${WORKLOAD_PID}"
}

# -----------------------------------------------------------------------------
# resume_workload: tracing on, release the workload, wait for completion.
# -----------------------------------------------------------------------------
resume_workload()
{
	echo 1 > "${INSTANCE}/tracing_on"
	kill -CONT "${WORKLOAD_PID}"
	wait "${WORKLOAD_PID}"
	log "workload completed (pid ${WORKLOAD_PID})"
	WORKLOAD_PID=
}

# -----------------------------------------------------------------------------
# restore_timeout: put the driver timeout back regardless of path.
# -----------------------------------------------------------------------------
restore_timeout()
{
	if [[ -n ${ORIGINAL_TIMEOUT} && -w ${SYSFS_DIR}/timeout_ms ]]; then
		echo "${ORIGINAL_TIMEOUT}" > "${SYSFS_DIR}/timeout_ms" 2>/dev/null || true
		ORIGINAL_TIMEOUT=
	fi
}

# -----------------------------------------------------------------------------
# stop_trace: flush the private instance to the raw trace capture.
# -----------------------------------------------------------------------------
stop_trace()
{
	echo 0 > "${INSTANCE}/tracing_on"
	cat "${INSTANCE}/trace" > "${TRACE_CAPTURE}"
	log "captured $(wc -l < "${TRACE_CAPTURE}") trace lines"
}

# -----------------------------------------------------------------------------
# collect_report: final post-workload metadata + sysfs + debugfs only.
# The workload no longer appears in the report; io-Phases.ndjson owns it.
# -----------------------------------------------------------------------------
collect_report()
{
	local trace_clock workload_pid
	trace_clock=$(sed -n 's/.*\[\([^]]*\)\].*/\1/p' "${INSTANCE}/trace_clock")
	workload_pid=$(sed -n 's/.*"context":{"pid":\([0-9]*\).*/\1/p' "${PHASES_CAPTURE}" | head -n 1)

	{
		echo '[metadata]'
		echo "workload_pid=${workload_pid:-unknown}"
		echo "qedu_irq=${QEDU_IRQ}"
		echo "trace_clock=${trace_clock:-unknown}"
		echo "kernel=$(uname -r)"
		echo "module=$(modinfo -F filename "${MODULE}" 2>/dev/null || echo "${MODULE}")"

		echo
		echo '[sysfs]'
		for attribute in tx rx timeout_ms; do
			printf '%s=' "${attribute}"
			cat "${SYSFS_DIR}/${attribute}"
		done

		echo
		echo '[debugfs]'
		cat "${DEBUGFS_DIR}/status"
	} > "${REPORT_CAPTURE}"
	log "report written: ${REPORT_CAPTURE}"
}

# -----------------------------------------------------------------------------
# validate_capture: semantic checks on the artifacts.
# io-Phases.ndjson is authoritative and carries its own sequence and monotonic
# time_ns.  The private-instance trace is a separate raw source; we check that
# it carries the kernel-side evidence (qedu_dma worker handoff and the device
# IRQ) on the same clock.
# -----------------------------------------------------------------------------
validate_capture()
{
	local seq
	if ! grep -q '"kind":"phase"' "${PHASES_CAPTURE}"; then
		fail "no phase records in ${PHASES_CAPTURE}"
	fi
	for seq in $(seq 1 10); do
		if ! grep -q "\"seq\":${seq}," "${PHASES_CAPTURE}"; then
			fail "phase record ${seq} missing"
		fi
	done
	# Semantic evidence that the DMA hardirq -> worker handoff was observed.
	if ! grep -q 'qedu_dma' "${TRACE_CAPTURE}"; then
		fail "no qedu_dma worker activity in trace"
	fi
	if ! grep -q 'irq_handler_entry.*qedu' "${TRACE_CAPTURE}"; then
		fail "no qedu IRQ handler activity in trace"
	fi

	if command -v python3 >/dev/null 2>&1; then
		python3 - "${PHASES_CAPTURE}" <<'PY' || fail "phase validation failed"
import json
import sys

records = []
with open(sys.argv[1], 'r', encoding='utf-8') as stream:
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
phases = [r for r in records if r.get('kind') == 'phase']
assert len(phases) == 10, 'expected 10 phase records'
assert [r['seq'] for r in phases] == list(range(1, 11)), 'phase seq must be 1..10'
assert [r['time_ns'] for r in phases] == sorted(r['time_ns'] for r in phases), 'phase time_ns is not monotonic'
for r in phases:
    assert r['experiment'] == 'io' and r['source'] == 'workload', 'phase schema mismatch'
    assert r['event_info']['action'] in ('begin', 'end'), 'bad phase action'
print('qedu: phases valid: %d records, seq 1..10, monotonic' % len(phases))
PY
	fi
	log "captures validated"
}

# -----------------------------------------------------------------------------
# cleanup: restore trace state, timeout, and any stray stopped workload on
# every exit path.  The module is intentionally left loaded on success.
# -----------------------------------------------------------------------------
cleanup()
{
	local status=$?

	trap - EXIT HUP INT TERM
	set +e

	if [[ -n ${WORKLOAD_PID:-} ]] && kill -0 "${WORKLOAD_PID}" 2>/dev/null; then
		kill -TERM "${WORKLOAD_PID}" 2>/dev/null
		kill -CONT "${WORKLOAD_PID}" 2>/dev/null
		wait "${WORKLOAD_PID}" 2>/dev/null
		WORKLOAD_PID=
	fi
	restore_timeout
	if [[ -n ${INSTANCE:-} && -d ${INSTANCE} ]]; then
		echo 0 > "${INSTANCE}/tracing_on" 2>/dev/null
		rmdir "${INSTANCE}" 2>/dev/null || rm -rf "${INSTANCE}" 2>/dev/null
	fi

	exit "${status}"
}
trap cleanup EXIT HUP INT TERM

preflight
find_device
reset_instance
enable_header
enable_preload_trace
load_module
configure_module_trace_filters
set_run_timeout
start_workload
configure_workload_filters
resume_workload
restore_timeout
stop_trace
collect_report
validate_capture

trap - EXIT HUP INT TERM
log "done"