"""KAPI run sequence and printk-record decoding."""

import os
import re
import shlex
from decimal import Decimal
from pathlib import Path

from framework.runtime import LabError, Session, command, record


def main(domain):
    Session("kapi", domain).execute(run)


def run(session):
    marker = "LAB_KAPI_BEGIN_%d_%d" % (os.getpid(), session.acquired)
    Path("/dev/kmsg").write_text("<6>" + marker + "\n")
    session.capture.lifecycle("collector_ready", {"collector": "module"})
    session.capture.lifecycle(
        "workload_started", {"command": ["/sbin/insmod", "kapi.ko"]}
    )
    session.module("kapi")
    command(["/sbin/rmmod", "kapi"])
    session.capture.lifecycle("workload_finished", {"exit_code": 0})

    # Read only records after our marker; never clear or claim the global kernel log.
    active = False
    for line in command(["dmesg"]).decode().splitlines():
        if marker in line:
            active = True
        elif active and "KAPI_EVT " in line:
            match = re.search(r"\[\s*(\d+\.\d+)\]\s+KAPI_EVT (.*)", line)
            if not match:
                raise LabError("invalid KAPI log record")
            data = {}
            for token in shlex.split(match[2]):
                key, separator, value = token.partition("=")
                if not separator or key in data:
                    raise LabError("invalid KAPI field: " + token)
                if re.fullmatch(r"[0-9a-f]{16}", value):
                    value = "0x" + value if int(value, 16) else None
                data[key] = value
            session.capture.events.append(
                record(
                    "kapi",
                    "module",
                    "module",
                    "guest",
                    data["action"],
                    int(Decimal(match[1]) * 1_000_000_000),
                    data,
                    hook="kapi:printk",
                    context={
                        "phase": data["phase"],
                        "cpu": int(data["cpu"]) if "cpu" in data else None,
                        "pid": int(data["tgid"]) if "tgid" in data else None,
                        "tid": int(data["pid"]) if "pid" in data else None,
                        "comm": data.get("comm"),
                    },
                )
            )
    session.capture.lifecycle(
        "collector_finished", {"collector": "module", "dropped": 0, "failures": 0}
    )
