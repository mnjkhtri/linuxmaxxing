import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from framework.core.runtime import Capture, LabError, Process, atomic_bytes, check_type, lock, ndjson, publish, record, trace_record, validate
from framework.cloudlab.environment import Remote


def fixture(directory):
    """A deliberately small successful scheduler experiment, independent of runner implementation."""
    capture = Capture("scheduler", "guest", directory / "staged.ndjson")
    capture.lifecycle("capture_started", {
        "environment": {"kernel": "test-kernel", "architecture": "x86_64", "os": "ubuntu-24.04",
                        "packages": [], "image_sha256": "a" * 64, "kernel_revision": "b" * 40, "qemu": "test-qemu"},
        "source_digest": "c" * 64, "enabled": [], "skipped": []})
    for name in ("observer", "tracefs"):
        capture.lifecycle("collector_ready", {"collector": name})
    capture.lifecycle("workload_started", {"command": ["workload"]})
    runqueue = {"address": "0x1", "nr_running": "1", "root": "0x2", "leftmost": "0x2",
                "enqueued_entity": {"address": "0x3", "rb_node": "0x4"}, "node_count": "1",
                "truncated": False,
                "nodes": [{"address": "0x2", "left": None, "right": None, "color": "black", "comm": "workload"}]}
    capture.events.extend([
        record("scheduler", "observer", "ebpf", "guest", "enqueue_entity", 1,
               {"event_info": {"name": "enqueue_entity", "phase": "after", "probe": "test"},
                "state": {"runqueue": runqueue}, "producer_sequence": "1"}),
        record("scheduler", "tracefs", "tracefs", "guest", "sched_process_fork", 2,
               {"fields": {"comm": "workload", "pid": "1", "child_comm": "child", "child_pid": "2"}}),
        record("scheduler", "tracefs", "tracefs", "guest", "sched_switch", 3,
               {"fields": {"prev_comm": "workload", "prev_pid": "1", "prev_prio": "120", "prev_state": "R",
                            "next_comm": "child", "next_pid": "2", "next_prio": "120"}}),
    ])
    capture.lifecycle("workload_finished", {"exit_code": 0})
    for name in ("observer", "tracefs"):
        capture.lifecycle("collector_finished", {"collector": name, "dropped": 0, "failures": 0})
    capture.lifecycle("capture_finished", {"validated": True, "restored": True})
    capture.save()
    return capture


class ContractTests(unittest.TestCase):
    def test_failed_replacement_preserves_last_valid_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cap = fixture(root)
            target = root / "events.ndjson"
            publish(cap.path, target, "scheduler")
            previous = target.read_bytes()
            cap.events[4]["data"]["unexpected"] = 1
            cap.save()
            with self.assertRaises(LabError):
                publish(cap.path, target, "scheduler")
            self.assertEqual(target.read_bytes(), previous)

    def test_missing_evidence_and_loss_are_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            cap = fixture(Path(directory))
            validate(cap.path, "scheduler")
            cap.events = [e for e in cap.events if e["kind"] != "sched_switch"]
            cap.save()
            with self.assertRaisesRegex(LabError, "lifecycle context"):
                validate(cap.path, "scheduler")
            cap = fixture(Path(directory))
            next(e for e in cap.events if e["kind"] == "collector_finished")["data"]["dropped"] = "1"
            cap.save()
            with self.assertRaisesRegex(LabError, "evidence loss"):
                validate(cap.path, "scheduler")

    def test_host_guest_clocks_are_not_coerced(self):
        host = record("virt-vtd", "host-observer", "ebpf", "host", "example", 2**63, {})
        guest = record("virt-vtd", "guest-observer", "ebpf", "guest", "example", 19, {})
        self.assertEqual(host["timestamp_ns"], "9223372036854775808")
        self.assertEqual(guest["timestamp_ns"], "19")
        self.assertNotEqual(host["clock_domain"], guest["clock_domain"])

    def test_payload_types_and_unknown_fields_are_closed(self):
        spec = {"type": "object", "fields": {"size_bytes": {"type": "integer64"}}, "required": ["size_bytes"]}
        check_type({"size_bytes": "18446744073709551615"}, spec)
        for value in ({"size_bytes": 2**64 - 1}, {"size_bytes": "1", "color": "red"}, {}):
            with self.assertRaises(LabError):
                check_type(value, spec)

    def test_malformed_json_duplicate_keys_and_blank_records_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.ndjson"
            for value in ('{"x":1,"x":2}\n', '{"x":NaN}\n', '\n', '{'):
                path.write_text(value)
                with self.assertRaises(LabError):
                    list(ndjson(path))

    def test_trace_decode_checks_formats_and_uses_integer_nanoseconds(self):
        event = trace_record("virt-ept", "host", "vmm-42 [003] ..... 999999999.123456: kvm_entry: vcpu 0, rip 0xabc\n")
        self.assertEqual(event["timestamp_ns"], "999999999123456000")
        self.assertEqual(event["data"]["fields"], {"vcpu": "0", "rip": "0xabc"})
        with self.assertRaises(LabError):
            trace_record("virt-ept", "host", "vmm-42 [003] ..... 1.234: kvm_entry: new incompatible format\n")


class ProcessTests(unittest.TestCase):
    def process(self, root, code, control=True):
        return Process([sys.executable, "-c", code], cwd=root, stdout=root / "events", stderr=root / "log", control=control)

    def test_ready_uses_control_descriptor_not_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = self.process(root, "import os,time; os.write(int(os.environ['LAB_CONTROL_FD']), b'LX_READY observer=test\\n'); time.sleep(5)")
            try:
                self.assertEqual(proc.wait_control("LX_READY ", 1), "LX_READY observer=test")
                self.assertEqual((root / "log").read_bytes(), b"")
            finally:
                proc.stop()
                proc.close()

    def test_early_exit_and_readiness_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for code in ("raise SystemExit(3)", "import time;time.sleep(5)"):
                proc = self.process(root, code)
                try:
                    with self.assertRaises(LabError):
                        proc.wait_control("LX_READY ", 0.15)
                finally:
                    proc.stop()
                    proc.close()

    def test_workload_failure_and_hung_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = self.process(root, "raise SystemExit(7)")
            try:
                with self.assertRaisesRegex(LabError, "status 7"):
                    proc.wait(1)
            finally:
                proc.stop()
                proc.close()
            proc = self.process(root, "import signal,os,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);os.write(int(os.environ['LAB_CONTROL_FD']),b'LX_READY test\\n');time.sleep(5)")
            try:
                proc.wait_control("LX_READY ", 1)
                with self.assertRaisesRegex(LabError, "SIGKILL"):
                    proc.stop(timeout=0.1)
            finally:
                proc.close()


class TransportTests(unittest.TestCase):
    def test_workspace_lock_excludes_concurrent_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".lock"
            with lock(path):
                with self.assertRaises(LabError):
                    with lock(path):
                        pass

    def test_archive_excludes_credentials_captures_and_research(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"target": "user@node", "workspace": "lab"}))
            remote = Remote(config)
            with tarfile.open(fileobj=io.BytesIO(remote.archive())) as archive:
                names = archive.getnames()
                self.assertIn("infra/environment.json", names)
                self.assertFalse(any("_captures" in n or "cloudlab.json" in n or n.startswith("temp/") for n in names))
            for workspace in ("/", "../other", "x;id", "~"):
                config.write_text(json.dumps({"target": "user@node", "workspace": workspace}))
                with self.assertRaises(LabError):
                    Remote(config)

    def test_interrupted_atomic_write_preserves_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "events.ndjson"
            target.write_bytes(b"previous")
            with patch("framework.core.runtime.os.replace", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError):
                    atomic_bytes(target, b"new")
            self.assertEqual(target.read_bytes(), b"previous")
            self.assertEqual(list(Path(directory).iterdir()), [target])


if __name__ == "__main__":
    unittest.main()
