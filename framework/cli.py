#!/usr/bin/env python3
"""The only public command parser and remote dispatch entry point."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from framework.core.runtime import LabError, NAMES, ROOT, atomic_bytes, atomic_json, command, lock, manifest, signals


def parser():
    p = argparse.ArgumentParser(description="Build and run Linux experiments on a disposable CloudLab host.")
    p.add_argument("--config", help="CloudLab JSON configuration (default: cloudlab.json)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--host", action="store_true", help=argparse.SUPPRESS)
    mode.add_argument("--guest", action="store_true", help=argparse.SUPPRESS)
    mode.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="action", required=True)
    for action in ("setup", "doctor", "console", "list", "prepare-vtd"):
        sub.add_parser(action)
    for action in ("build", "run", "fetch", "validate"):
        cmd = sub.add_parser(action)
        cmd.add_argument("experiment", choices=(*NAMES, "all"))
    return p


def ownership(name):
    """Return only generated artifacts to the invoking SSH user after a root worker."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid is not None and gid is not None:
        for base in (ROOT / "captures" / name,):
            if base.exists():
                for path in [base, *base.rglob("*")]:
                    if not path.is_symlink():
                        os.chown(path, int(uid), int(gid))


def local_worker(args, name):
    from framework.core.runtime import Session
    result = Path(os.environ["LAB_SHARED_SCRATCH"]) / "guest-result.json" if args.guest else None
    try:
        Session(name, "guest" if args.guest else "host").execute()
        if result is not None:
            atomic_json(result, {"success": True, "error": ""})
    except BaseException as exc:
        if result is not None:
            atomic_json(result, {"success": False, "error": str(exc)})
        raise
    finally:
        ownership(name)


def main(argv=None):
    args = parser().parse_args(argv)
    if args.action == "list":
        for name in NAMES:
            print("%-14s %s" % (name, manifest(name)["environment"]))
        return
    names = NAMES if getattr(args, "experiment", None) == "all" else [getattr(args, "experiment", "")]
    if args.guest or args.worker:
        if args.action != "run" or len(names) != 1 or not names[0]:
            raise LabError("workers accept one run only")
        local_worker(args, names[0])
        return
    if args.action == "validate":
        from framework.core.runtime import validate
        for name in names:
            events = validate(ROOT / "captures" / name / "events.ndjson", name)
            print("%s: validated %d records" % (name, len(events)))
        return
    if args.host:
        from framework.cloudlab.environment import build, doctor, setup, prepare_vtd
        from framework.core import runtime as guest
        if args.action == "setup":
            setup()
        elif args.action == "doctor":
            print(doctor())
        elif args.action == "prepare-vtd":
            prepare_vtd()
        elif args.action == "console":
            build("scheduler")
            guest.run("scheduler", console=True)
        else:
            for name in names:
                build(name)
                if args.action == "run":
                    if manifest(name)["environment"] == "guest":
                        guest.run(name)
                    else:
                        command(["sudo", "-n", sys.executable, ROOT / "framework/cli.py", "--worker", "run", name],
                                timeout=1800, capture=False)
        return
    from framework.cloudlab.environment import Remote
    from framework.core.runtime import publish
    remote = Remote(args.config)
    lock_name = "linuxmaxxing-%s.lock" % hashlib.sha256(str(ROOT).encode()).hexdigest()[:16]
    with lock(Path(tempfile.gettempdir()) / lock_name):
        if args.action not in ("fetch",):
            remote.execute(args.action, getattr(args, "experiment", ""))
        if args.action in ("run", "fetch"):
            with tempfile.TemporaryDirectory(prefix="linuxmaxxing-fetch-") as staging:
                for name in names:
                    staged = Path(staging) / (name + ".ndjson")
                    atomic_bytes(staged, remote.fetch(name))
                    publish(staged, ROOT / "captures" / name / "events.ndjson", name)
                    print("%s: latest validated capture refreshed" % name)


if __name__ == "__main__":
    try:
        with signals():
            main()
    except (LabError, OSError, ValueError, KeyboardInterrupt) as exc:
        print("lab.sh: " + (str(exc) or "interrupted") + "; no successful result published for the failed attempt", file=sys.stderr)
        sys.exit(1)
