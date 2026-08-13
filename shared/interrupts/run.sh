#!/usr/bin/env bash
set -Eeuo pipefail

cd -- "$(dirname -- "$0")"

MODULE=./qedu.ko
WORKLOAD=./workload_qedu
CAPTURE_DIR=${QEDU_CAPTURE_DIR:-../_captures}
TRACE_CAPTURE=${CAPTURE_DIR}/interrupts-trace.txt
REPORT_CAPTURE=${CAPTURE_DIR}/interrupts-report.txt

TRACEFS=
TRACE_SAVED=0
ORIGINAL_TIMEOUT=
WORKLOAD_PID=

cleanup()
{
	local status=$?

	trap - EXIT HUP INT TERM
	set +e

	if [[ -n ${ORIGINAL_TIMEOUT} && -w /sys/class/misc/qedu/timeout_ms ]]; then
		echo "${ORIGINAL_TIMEOUT}" > /sys/class/misc/qedu/timeout_ms 2>/dev/null
	fi

	if [[ -n ${TRACEFS} && -e ${TRACEFS}/tracing_on ]]; then
		echo 0 > "${TRACEFS}/tracing_on" 2>/dev/null
		if (( ! TRACE_SAVED )) && [[ -r ${TRACEFS}/trace && -d ${CAPTURE_DIR} ]]; then
			cat "${TRACEFS}/trace" > "${TRACE_CAPTURE}" 2>/dev/null
		fi
		echo 0 > "${TRACEFS}/events/enable" 2>/dev/null
	fi
	if [[ -n ${WORKLOAD_PID} ]] && kill -0 "${WORKLOAD_PID}" 2>/dev/null; then
		kill -TERM "${WORKLOAD_PID}" 2>/dev/null
		kill -CONT "${WORKLOAD_PID}" 2>/dev/null
		wait "${WORKLOAD_PID}" 2>/dev/null
	fi

	exit "${status}"
}
trap cleanup EXIT HUP INT TERM

if [[ $(id -u) -ne 0 ]]; then
	echo 'qedu-run: error: run this inside the guest as root' >&2
	exit 1
fi
if [[ ! -r ${MODULE} ]]; then
	echo "qedu-run: error: missing ${MODULE}; run make -C shared/interrupts" >&2
	exit 1
fi
if [[ ! -x ${WORKLOAD} ]]; then
	echo "qedu-run: error: missing ${WORKLOAD}; run make -C shared/interrupts" >&2
	exit 1
fi

mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
mkdir -p /sys/kernel/debug
mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug
mkdir -p /sys/kernel/tracing
mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing
TRACEFS=/sys/kernel/tracing

mkdir -p "${CAPTURE_DIR}"
: > "${TRACE_CAPTURE}"
: > "${REPORT_CAPTURE}"

if grep -q '^qedu ' /proc/modules; then
	rmmod qedu
fi

QEDU_IRQ=
for device_path in /sys/bus/pci/devices/*; do
	[[ $(< "${device_path}/vendor") == 0x1234 ]] || continue
	[[ $(< "${device_path}/device") == 0x11e8 ]] || continue
	QEDU_IRQ=$(< "${device_path}/irq")
	break
done
if [[ -z ${QEDU_IRQ} ]]; then
	echo 'qedu-run: error: QEMU EDU device 1234:11e8 was not found' >&2
	exit 1
fi

echo 0 > "${TRACEFS}/tracing_on"
echo 0 > "${TRACEFS}/events/enable"
echo nop > "${TRACEFS}/current_tracer"
echo 32768 > "${TRACEFS}/buffer_size_kb"
echo mono > "${TRACEFS}/trace_clock"
echo > "${TRACEFS}/trace"

echo 0 > "${TRACEFS}/events/irq/filter"
echo 0 > "${TRACEFS}/events/syscalls/filter"
echo 0 > "${TRACEFS}/events/sched/filter"
echo 0 > "${TRACEFS}/events/exceptions/filter"
echo 0 > "${TRACEFS}/events/workqueue/filter"
for event in sched_switch sched_wakeup sched_waking; do
echo 0 > "${TRACEFS}/events/sched/${event}/filter"
done

echo 1 > "${TRACEFS}/events/irq/irq_handler_entry/enable"
echo 1 > "${TRACEFS}/events/irq/irq_handler_exit/enable"
echo 1 > "${TRACEFS}/events/irq_vectors/vector_config/enable"
echo 1 > "${TRACEFS}/events/irq_vectors/vector_alloc/enable"
echo "irq == ${QEDU_IRQ}" > "${TRACEFS}/events/irq/irq_handler_entry/filter"
echo "irq == ${QEDU_IRQ}" > "${TRACEFS}/events/irq/irq_handler_exit/filter"
echo "irq == ${QEDU_IRQ}" > "${TRACEFS}/events/irq_vectors/vector_config/filter"
echo "irq == ${QEDU_IRQ}" > "${TRACEFS}/events/irq_vectors/vector_alloc/filter"

# Permanent workqueue tracepoints expose the hardirq -> worker handoff. The
# dedicated queue name keeps queue_work noise out; the HTML matches the two
# qedu_dma callback symbols for the remaining lifecycle events.
echo 'workqueue == "qedu_dma"' > "${TRACEFS}/events/workqueue/workqueue_queue_work/filter"
echo 1 > "${TRACEFS}/events/workqueue/workqueue_queue_work/enable"
echo 1 > "${TRACEFS}/events/workqueue/workqueue_activate_work/enable"
echo 1 > "${TRACEFS}/events/workqueue/workqueue_execute_start/enable"
echo 1 > "${TRACEFS}/events/workqueue/workqueue_execute_end/enable"

echo 1 > "${TRACEFS}/tracing_on"
insmod "${MODULE}"

DMA_ADVANCE_FN=$(awk '$3 == "qedu_dma_advance_work" { print "0x"$1; exit }' /proc/kallsyms)
DMA_FINISH_FN=$(awk '$3 == "qedu_dma_finish_work" { print "0x"$1; exit }' /proc/kallsyms)
if [[ -n ${DMA_ADVANCE_FN} && -n ${DMA_FINISH_FN} ]]; then
	for event in workqueue_activate_work workqueue_execute_start workqueue_execute_end; do
		echo "function == ${DMA_ADVANCE_FN} || function == ${DMA_FINISH_FN}" > "${TRACEFS}/events/workqueue/${event}/filter"
	done
fi

ORIGINAL_TIMEOUT=$(< /sys/class/misc/qedu/timeout_ms)
echo 1500 > /sys/class/misc/qedu/timeout_ms

# The workload stops immediately so its PID can be installed in the trace filters before any device I/O happens.
echo 0 > "${TRACEFS}/tracing_on"
"${WORKLOAD}" --trace-wait &
WORKLOAD_PID=$!
while [[ -r /proc/${WORKLOAD_PID}/status ]] && ! grep -q '^State:.*T' "/proc/${WORKLOAD_PID}/status"; do
	:
done
if ! kill -0 "${WORKLOAD_PID}" 2>/dev/null; then
	wait "${WORKLOAD_PID}"
	exit 1
fi

for event in sys_enter_openat sys_exit_openat sys_enter_read sys_exit_read sys_enter_write sys_exit_write sys_enter_close sys_exit_close; do
	echo "common_pid == ${WORKLOAD_PID}" > "${TRACEFS}/events/syscalls/${event}/filter"
	echo 1 > "${TRACEFS}/events/syscalls/${event}/enable"
done
echo "prev_pid == ${WORKLOAD_PID} || next_pid == ${WORKLOAD_PID} || prev_comm ~ \"kworker*\" || next_comm ~ \"kworker*\"" > "${TRACEFS}/events/sched/sched_switch/filter"
echo "pid == ${WORKLOAD_PID}" > "${TRACEFS}/events/sched/sched_wakeup/filter"
echo "pid == ${WORKLOAD_PID}" > "${TRACEFS}/events/sched/sched_waking/filter"
echo "common_pid == ${WORKLOAD_PID}" > "${TRACEFS}/events/exceptions/page_fault_user/filter"
echo 1 > "${TRACEFS}/events/sched/sched_switch/enable"
echo 1 > "${TRACEFS}/events/sched/sched_wakeup/enable"
echo 1 > "${TRACEFS}/events/sched/sched_waking/enable"
echo 1 > "${TRACEFS}/events/exceptions/page_fault_user/enable"

echo 1 > "${TRACEFS}/tracing_on"
kill -CONT "${WORKLOAD_PID}"
wait "${WORKLOAD_PID}"
WORKLOAD_PID=

echo "${ORIGINAL_TIMEOUT}" > /sys/class/misc/qedu/timeout_ms
ORIGINAL_TIMEOUT=

echo 0 > "${TRACEFS}/tracing_on"
cat "${TRACEFS}/trace" > "${TRACE_CAPTURE}"
TRACE_SAVED=1
echo 0 > "${TRACEFS}/events/enable"

trace_clock=$(sed -n 's/.*\[\([^]]*\)\].*/\1/p' "${TRACEFS}/trace_clock")
{
	echo '[workload]'
	sed -n 's/^.*tracing_mark_write: \(QEDU_PHASE.*\)$/\1/p' "${TRACE_CAPTURE}"
	echo
	echo
	echo '[metadata]'
	echo "workload_pid=$(sed -n 's/.*phase=run action=begin pid=\([0-9]*\).*/\1/p' "${TRACE_CAPTURE}" | head -n 1)"
	echo "qedu_irq=${QEDU_IRQ}"
	echo "trace_clock=${trace_clock:-unknown}"
	echo "kernel=$(uname -r)"
	echo "module=$(modinfo -F filename "${MODULE}")"

	echo
	echo '[sysfs]'
	for attribute in tx rx timeout_ms; do
		printf '%s=' "${attribute}"
		cat "/sys/class/misc/qedu/${attribute}"
	done

	echo
	echo '[debugfs]'
	cat /sys/kernel/debug/qedu/status
} >> "${REPORT_CAPTURE}"

trap - EXIT HUP INT TERM
