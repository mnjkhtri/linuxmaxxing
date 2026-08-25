#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# CAPTURE MODEL
#
# One workload_qedu run preserves three independent capture artifacts.
#
# - io-Phases.ndjson stores workload markers on CLOCK_MONOTONIC.
# - io-Trace.txt stores raw tracefs records, including qedu semantic events.
# - io-Report.txt stores final resource state and trace-loss counters.
#
# Workload and tracefs timestamps share CLOCK_MONOTONIC.
# The UI reads these three artifacts independently and correlates them in memory.
#
# The runner uses a private tracefs instance without touching global tracing.
# It verifies the monotonic trace clock before capture.
# It starts tracing before module insertion to observe vector allocation at probe.
# It stops the workload before I/O so PID filters can be installed safely.
# Cleanup handles every exit path and leaves the module loaded after success.
# =============================================================================

MODULE=./qedu.ko
TRACE_MODULE=./qedu_trace.ko
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

QEDU_BDF=
QEDU_IRQ=
WORKLOAD_PID=
ORIGINAL_TIMEOUT=
RUN_TIMEOUT=1500

# Probe milestones, the coherent allocation, and optional vector routing are captured before qedu insertion.
# Workqueue events stay disabled until probe completes so unrelated setup noise is excluded.
PRELOAD_REQUIRED=(dma/dma_alloc)
OPTIONAL_EVENTS=(irq_vectors/vector_config irq_vectors/vector_alloc)
RUNTIME_REQUIRED=(irq/irq_handler_entry irq/irq_handler_exit
	workqueue/workqueue_queue_work workqueue/workqueue_activate_work
	workqueue/workqueue_execute_start workqueue/workqueue_execute_end)
QEDU_REQUIRED=(qedu/qedu_probe_stage qedu/qedu_file_op qedu/qedu_cpu_buffer_io
	qedu/qedu_dma_stage qedu/qedu_dma_submit qedu/qedu_irq_ack
	qedu/qedu_dma_work_queue qedu/qedu_completion_publish qedu/qedu_wait
	qedu/qedu_factorial_submit qedu/qedu_factorial_result)
WORKLOAD_REQUIRED=(syscalls/sys_enter_openat syscalls/sys_exit_openat
	syscalls/sys_enter_read syscalls/sys_exit_read
	syscalls/sys_enter_write syscalls/sys_exit_write
	syscalls/sys_enter_close syscalls/sys_exit_close
	sched/sched_switch sched/sched_wakeup sched/sched_waking)
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
# preflight verifies privileges, binaries, and a clean capture directory.
# -----------------------------------------------------------------------------
preflight()
{
	if [[ $(id -u) -ne 0 ]]; then
		fail "run this inside the guest as root"
	fi
	if [[ ! -r ${TRACE_MODULE} ]]; then
		fail "missing ${TRACE_MODULE}; run make -C shared/io"
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
# find_device locates the QEMU EDU PCI function and its shared IRQ.
# -----------------------------------------------------------------------------
find_device()
{
	local device_path

	for device_path in /sys/bus/pci/devices/*; do
		[[ $(< "${device_path}/vendor") == 0x1234 ]] || continue
		[[ $(< "${device_path}/device") == 0x11e8 ]] || continue
		QEDU_IRQ=$(< "${device_path}/irq")
		QEDU_BDF=${device_path##*/}
		log "QEMU EDU device ${QEDU_BDF} on IRQ ${QEDU_IRQ}"
		return 0
	done
	fail "QEMU EDU device 1234:11e8 was not found"
}

# -----------------------------------------------------------------------------
# reset_instance creates a fresh private tracefs instance.
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
# enable_event enables a tracepoint and records unavailable optional events.
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
	for event in "${PRELOAD_REQUIRED[@]}" "${QEDU_REQUIRED[@]}" "${OPTIONAL_EVENTS[@]}"; do
		enable_event "${event}"
	done
	set_filter dma/dma_alloc "device == \"${QEDU_BDF}\""
	set_filter irq_vectors/vector_config "irq == ${QEDU_IRQ}"
	set_filter irq_vectors/vector_alloc "irq == ${QEDU_IRQ}"

	if (( ${#SKIPPED_EVENTS[@]} > 0 )); then
		log "skipped unavailable trace events: ${SKIPPED_EVENTS[*]}"
	fi
	log "private tracefs instance ready: ${INSTANCE} (clock=mono)"
}

# -----------------------------------------------------------------------------
# enable_preload_trace and load_module capture vector allocation at probe.
# Tracing must therefore be active before qedu.ko is inserted.
# -----------------------------------------------------------------------------
load_trace_provider()
{
	if grep -q '^qedu ' /proc/modules; then
		rmmod qedu
	fi
	if grep -q '^qedu_trace ' /proc/modules; then
		rmmod qedu_trace
	fi
	insmod "${TRACE_MODULE}"
	log "qedu_trace.ko inserted; probe tracepoints are now available"
}

enable_preload_trace()
{
	echo 1 > "${INSTANCE}/tracing_on"
}

load_module()
{
	insmod "${MODULE}"
	echo 0 > "${INSTANCE}/tracing_on"
	log "qedu.ko inserted"
}

# enable_runtime_trace adds filtered IRQ and workqueue events after probe.
# The qedu semantic events remain enabled from the preload interval.
# -----------------------------------------------------------------------------
enable_runtime_trace()
{
	local event
	for event in "${RUNTIME_REQUIRED[@]}"; do
		enable_event "${event}"
	done
	set_filter irq/irq_handler_entry "irq == ${QEDU_IRQ}"
	set_filter irq/irq_handler_exit "irq == ${QEDU_IRQ}"
	set_filter workqueue/workqueue_queue_work 'workqueue == "qedu_dma"'
	log "filtered runtime events enabled; qedu semantic events remain active"
}

# -----------------------------------------------------------------------------
# configure_module_trace_filters resolves the two qedu_dma callback symbols.
# It pins worker lifecycle events to those function identities.
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
# set_run_timeout overrides the driver timeout for this run.
# It remembers the original timeout so every exit path can restore it.
# -----------------------------------------------------------------------------
set_run_timeout()
{
	ORIGINAL_TIMEOUT=$(< "${SYSFS_DIR}/timeout_ms")
	echo "${RUN_TIMEOUT}" > "${SYSFS_DIR}/timeout_ms"
	log "sysfs timeout_ms ${ORIGINAL_TIMEOUT} -> ${RUN_TIMEOUT}"
}

# -----------------------------------------------------------------------------
# start_workload launches a process that stops itself before device I/O.
# This allows PID-specific filters to be installed while tracing is disabled.
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
# configure_workload_filters enables PID-specific syscall and scheduler events.
# The stopped workload cannot perform device I/O before those filters are installed.
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
	log "workload trace filters installed on pid ${WORKLOAD_PID}"
}

# -----------------------------------------------------------------------------
# resume_workload enables tracing, releases the workload, and waits for completion.
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
# restore_timeout restores the driver timeout on every exit path.
# -----------------------------------------------------------------------------
restore_timeout()
{
	if [[ -n ${ORIGINAL_TIMEOUT} && -w ${SYSFS_DIR}/timeout_ms ]]; then
		echo "${ORIGINAL_TIMEOUT}" > "${SYSFS_DIR}/timeout_ms" 2>/dev/null || true
		ORIGINAL_TIMEOUT=
	fi
}

# -----------------------------------------------------------------------------
# stop_trace flushes the private instance into the raw trace capture.
# -----------------------------------------------------------------------------
stop_trace()
{
	echo 0 > "${INSTANCE}/tracing_on"
	cat "${INSTANCE}/trace" > "${TRACE_CAPTURE}"
	log "captured $(wc -l < "${TRACE_CAPTURE}") trace lines"
}

# -----------------------------------------------------------------------------
# collect_report stores final metadata, sysfs state, and debugfs state.
# Workload observations remain exclusively in io-Phases.ndjson.
# -----------------------------------------------------------------------------
collect_report()
{
	local trace_clock workload_pid stats cpu overrun dropped entries
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

		echo
		echo '[trace_stats]'
		for stats in "${INSTANCE}"/per_cpu/cpu*/stats; do
			[[ -r ${stats} ]] || continue
			cpu=$(basename "$(dirname "${stats}")")
			overrun=$(awk '$1 == "overrun:" { print $2 }' "${stats}")
			dropped=$(awk '$1 == "dropped" && $2 == "events:" { print $3 }' "${stats}")
			entries=$(awk '$1 == "entries:" { print $2 }' "${stats}")
			echo "${cpu}_overrun=${overrun:-0}"
			echo "${cpu}_dropped=${dropped:-0}"
			echo "${cpu}_entries=${entries:-0}"
		done
	} > "${REPORT_CAPTURE}"
	log "report written: ${REPORT_CAPTURE}"
}

# -----------------------------------------------------------------------------
# validate_capture performs semantic checks on every artifact.
# io-Phases.ndjson owns workload sequence numbers and monotonic timestamps.
# The private tracefs instance is an independent raw source on the same clock.
# Validation requires both the qedu DMA worker handoff and the device IRQ evidence.
# -----------------------------------------------------------------------------
validate_capture()
{
	local factorial_irq_line factorial_submit_line file_boundary seq
	if ! grep -q '"kind":"phase"' "${PHASES_CAPTURE}"; then
		fail "no phase records in ${PHASES_CAPTURE}"
	fi
	if [[ $(grep -c '"kind":"phase"' "${PHASES_CAPTURE}") -ne 10 ]] || ! awk -F'"time_ns":' '{ split($2, part, ","); if (part[1] <= previous) exit 1; previous = part[1] }' "${PHASES_CAPTURE}"; then
		fail "phase capture must contain exactly 10 monotonically ordered records"
	fi
	for seq in $(seq 1 10); do
		if ! grep -q "\"seq\":${seq}," "${PHASES_CAPTURE}"; then
			fail "phase record ${seq} missing"
		fi
	done
	if ! grep -q 'qedu_probe_stage:.*stage=PROBE_READY' "${TRACE_CAPTURE}"; then
		fail "no completed qedu initialization trace"
	fi
	if ! grep -q 'qedu_probe_stage:.*stage=DEVICE_STATE_READY api=devm_kzalloc' "${TRACE_CAPTURE}"; then
		fail "qedu initialization trace is missing captured API names"
	fi
	for file_boundary in 'operation=OPEN phase=ENTER' 'operation=OPEN phase=EXIT' 'operation=READ phase=ENTER' 'operation=READ phase=EXIT' 'operation=RELEASE phase=ENTER' 'operation=RELEASE phase=EXIT'; do
		if ! grep -q "qedu_file_op:.*${file_boundary}" "${TRACE_CAPTURE}"; then
			fail "missing qedu file-operation boundary: ${file_boundary}"
		fi
	done
	if ! grep -q 'qedu_file_op:.*operation=WRITE phase=EXIT .*engine=FACTORIAL' "${TRACE_CAPTURE}"; then
		fail "missing factorial write return boundary"
	fi
	if ! grep -q 'qedu_file_op:.*operation=WRITE phase=EXIT .*engine=DMA' "${TRACE_CAPTURE}"; then
		fail "missing DMA write return boundary"
	fi
	factorial_submit_line=$(awk '/qedu_factorial_submit:.*io_id=1 / { print NR; exit }' "${TRACE_CAPTURE}")
	factorial_irq_line=$(awk '/qedu_irq_ack:.*io_id=1 .*engine=FACTORIAL/ { print NR; exit }' "${TRACE_CAPTURE}")
	if [[ -z ${factorial_submit_line} || -z ${factorial_irq_line} || ${factorial_submit_line} -ge ${factorial_irq_line} ]]; then
		fail "factorial capture does not order MMIO submission before IRQ completion"
	fi
	if ! grep -q 'dma_alloc:.*size=4096' "${TRACE_CAPTURE}"; then
		fail "no coherent DMA allocation trace"
	fi
	if ! grep -q 'qedu_dma_submit:.*io_id=2 leg=0 direction=DMA_TO_DEVICE' "${TRACE_CAPTURE}" || ! grep -q 'qedu_dma_submit:.*io_id=2 leg=1 direction=DMA_FROM_DEVICE' "${TRACE_CAPTURE}"; then
		fail "DMA capture is missing one of its two directed submissions"
	fi
	if ! grep -q 'qedu_irq_ack:' "${TRACE_CAPTURE}"; then
		fail "no qedu IRQ acknowledgement tracepoints"
	fi
	if ! grep -q 'irq_handler_entry.*qedu' "${TRACE_CAPTURE}"; then
		fail "no generic qedu IRQ handler activity"
	fi
	if ! grep -q 'qedu_dma_work_queue:.*io_id=2 .*work_kind=ADVANCE .*queued=1' "${TRACE_CAPTURE}" || ! grep -q 'qedu_dma_work_queue:.*io_id=2 .*work_kind=FINISH .*queued=1' "${TRACE_CAPTURE}"; then
		fail "DMA capture is missing a successful IRQ-to-workqueue handoff"
	fi
	if grep -Eq '_(overrun|dropped)=[1-9][0-9]*' "${REPORT_CAPTURE}"; then
		fail "trace loss reported in ${REPORT_CAPTURE}"
	fi
	log "three independent captures validated"
}

# -----------------------------------------------------------------------------
# cleanup restores trace state, timeout state, and any stopped workload on every exit path.
# It intentionally leaves the module loaded after a successful capture.
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
load_trace_provider
enable_header
enable_preload_trace
load_module
enable_runtime_trace
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
log "done: ${PHASES_CAPTURE}, ${TRACE_CAPTURE}, ${REPORT_CAPTURE}"
