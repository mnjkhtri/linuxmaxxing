"""Scheduler run sequence and capture-specific checks."""

import signal
import time

from framework.core.runtime import Session, stopped


def main(domain):
    Session("scheduler", domain).execute(run)


def run(session):
    # Keep this sequence beside the workload: enable tracefs, observe, gate,
    # release with filters installed, close the window, then collect.
    session.trace_start()
    session.observer()
    proc = session.start_workload()
    stopped(proc, session.cfg["timeouts"]["ready_s"])
    for event in session.trace.enabled:
        if event == "sched/sched_switch":
            expression = 'prev_comm ~ "sched*" || next_comm ~ "sched*"'
        elif event == "sched/sched_process_fork":
            expression = 'parent_comm ~ "sched*" || child_comm ~ "sched*"'
        else:
            expression = 'comm ~ "sched*"'
        session.trace.filter(event, expression)
    proc.signal(signal.SIGCONT)
    session.wait_workload(proc)
    for observer, _ in session.observers:
        observer.signal(signal.SIGUSR1)
    for event in session.trace.enabled:
        session.trace.filter(event, "0")
    time.sleep(session.cfg.get("post_workload_grace_ms", 0) / 1000)
    session.collect()
