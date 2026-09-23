"""Memory run sequence and snapshot/phase consistency checks."""

from framework.core.runtime import Session, command


def main(domain):
    Session("memory", domain).execute(run)


def run(session):
    # Swap backs the workload's paging phases; then start both capture sources.
    command(["/sbin/swapon", "/dev/vdb"])
    session.trace_start()
    session.observer()
    proc = session.start_workload()
    # The BPF observer is workload-keyed; keep supplemental tracefs records
    # scoped to the same process so unrelated reclaim does not dominate.
    for event in session.trace.enabled:
        session.trace.filter(event, "common_pid == %d" % proc.child.pid)
    session.wait_workload(proc)
    session.collect()
