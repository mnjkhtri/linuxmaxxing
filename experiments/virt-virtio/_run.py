"""Virtio run sequence, queue completion, and eventfd handoff checks."""

from framework.core.runtime import Session


def main(domain):
    Session("virt-virtio", domain).execute(run)


def run(session):
    session.trace_start()
    if session.cfg["observer"]:
        session.observer()
    session.wait_workload(session.start_workload())
    session.collect()
