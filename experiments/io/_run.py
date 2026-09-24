"""EDU device preparation, run sequence, and capture-specific checks."""

import signal
from pathlib import Path

from framework.runtime import LabError, Session, stopped


def main(domain):
    Session("io", domain).execute(run)


def prepare(session):
    session.module("qedu_trace")
    session.trace_start()
    devices = [
        path
        for path in Path("/sys/bus/pci/devices").iterdir()
        if (path / "vendor").read_text().strip() == "0x1234"
        and (path / "device").read_text().strip() == "0x11e8"
    ]
    if len(devices) != 1:
        raise LabError("expected exactly one QEMU EDU device")
    pci = devices[0]
    irq = (pci / "irq").read_text().strip()
    session.trace.filter("dma/dma_alloc", 'device == "%s"' % pci.name)
    for event in (
        "irq/irq_handler_entry",
        "irq/irq_handler_exit",
        "irq_vectors/vector_alloc",
        "irq_vectors/vector_config",
    ):
        session.trace.filter(event, "irq == " + irq)
    session.module("qedu")
    timeout = Path("/sys/class/misc/qedu/timeout_ms")
    previous = timeout.read_text()
    session.stack.callback(timeout.write_text, previous)
    timeout.write_text("1500\n")
    symbols = {
        fields[2]: fields[0]
        for line in Path("/proc/kallsyms").read_text().splitlines()
        if len(fields := line.split()) >= 3
    }
    workers = ("qedu_dma_advance_work", "qedu_dma_finish_work")
    if not all(symbols.get(name, "0").strip("0") for name in workers):
        raise LabError("EDU worker symbols are unavailable")
    expression = " || ".join("function == 0x" + symbols[name] for name in workers)
    for event in (
        "workqueue/workqueue_activate_work",
        "workqueue/workqueue_execute_start",
        "workqueue/workqueue_execute_end",
    ):
        session.trace.filter(event, expression)
    session.trace.filter("workqueue/workqueue_queue_work", 'workqueue == "qedu_dma"')


def run(session):
    prepare(session)
    proc = session.start_workload()
    stopped(proc, session.cfg["timeouts"]["ready_s"])
    pid = proc.child.pid
    for event in session.trace.enabled:
        if event.startswith("syscalls/"):
            session.trace.filter(event, "common_pid == %d" % pid)
    session.trace.filter(
        "sched/sched_switch",
        'prev_pid == %d || next_pid == %d || prev_comm ~ "kworker*" || next_comm ~ "kworker*"'
        % (pid, pid),
    )
    session.trace.filter("sched/sched_wakeup", "pid == %d" % pid)
    proc.signal(signal.SIGCONT)
    session.wait_workload(proc)
    session.collect()
