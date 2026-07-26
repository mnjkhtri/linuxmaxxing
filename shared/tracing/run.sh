#!/usr/bin/env bash
set -euo pipefail
cd /sys/kernel/tracing
echo 0 > tracing_on
echo 0 > events/enable
echo > set_event
echo > trace
echo 1 > events/sched/sched_process_fork/enable
echo 1 > events/sched/sched_wakeup_new/enable
echo 1 > events/sched/sched_switch/enable
echo 1 > events/sched/sched_process_exit/enable
echo 1 > events/sched/sched_process_wait/enable
echo 1 > events/sched/sched_process_free/enable
echo 1 > tracing_on
/mnt/host/_work/build/fork_25_processes
echo 0 > tracing_on
mkdir -p /mnt/host/_captures
cat trace > /mnt/host/_captures/tracing-core-lifecycle.txt
echo 0 > events/sched/sched_process_fork/enable
echo 0 > events/sched/sched_wakeup_new/enable
echo 0 > events/sched/sched_switch/enable
echo 0 > events/sched/sched_process_exit/enable
echo 0 > events/sched/sched_process_wait/enable
echo 0 > events/sched/sched_process_free/enable
echo > trace
