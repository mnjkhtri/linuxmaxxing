"""EPT run sequence, operation pairing, and result checks."""

from framework.runtime import Session


def main(domain):
    Session("virt-ept", domain).execute(run)


def run(session):
    session.trace_start()
    if session.cfg["observer"]:
        session.observer()
    session.wait_workload(session.start_workload())
    session.collect()
