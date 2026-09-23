"""KVM virtual I/O run sequence."""

from framework.core.runtime import Session


def main(domain):
    Session("virt-io", domain).execute(run)


def run(session):
    session.trace_start()
    if session.cfg["observer"]:
        session.observer()
    session.wait_workload(session.start_workload())
    session.collect()
