"""Capture, collection, and execution runtime for all experiments."""

import contextlib
import fcntl
import hashlib
import json
import os
import re
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from contextlib import ExitStack
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

NAMES = (
    "scheduler",
    "kapi",
    "io",
    "memory",
    "virt-ept",
    "virt-io",
    "virt-virtio",
    "virt-vtd",
)


class LabError(RuntimeError):
    pass


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise LabError("duplicate JSON key: " + key)
            result[key] = value
        return result

    return json.loads(
        Path(path).read_text(),
        object_pairs_hook=pairs,
        parse_constant=lambda v: (_ for _ in ()).throw(
            LabError("invalid JSON number: " + v)
        ),
    )


def manifest(name):
    if name not in NAMES:
        raise LabError("unknown experiment: " + name)
    result = read_json(ROOT / "experiments" / name / "experiment.json")
    if result["name"] != name:
        raise LabError("manifest name does not match directory")
    return result


def command(argv, *, cwd=None, timeout=120, input=None, capture=True, env=None):
    try:
        result = subprocess.run(
            [str(x) for x in argv],
            cwd=cwd,
            input=input,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LabError(str(exc)) from exc
    if result.returncode:
        detail = (result.stderr or b"").decode(errors="replace")[-8000:]
        raise LabError(
            "command failed (%s): %s\n%s" % (result.returncode, argv[0], detail)
        )
    return result.stdout or b""


@contextlib.contextmanager
def lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LabError("workspace busy; another lab command is active") from exc
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def atomic_bytes(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".staging-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, indent=2, allow_nan=False) + "\n").encode())


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@contextlib.contextmanager
def signals():
    def interrupted(signum, frame):
        raise LabError("interrupted by signal %d" % signum)

    previous = {
        s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGHUP)
    }
    try:
        yield
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)


CONTEXT = ("cpu", "pid", "tid", "comm", "phase", "operation")
ENVELOPE = {
    "experiment",
    "sequence",
    "source",
    "kind",
    "timestamp_ns",
    "clock_domain",
    "context",
    "quality",
    "data",
}
def normalize(value):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    if isinstance(value, str):
        if re.fullmatch(r"0x[0-9a-fA-F]+", value):
            return "0x" + value[2:].lower()
        return value
    raise LabError("unsupported observation value: " + repr(value))


def quality(data):
    reasons = []

    def walk(value, path):
        if isinstance(value, dict):
            for key, child in value.items():
                loc = path + "." + key
                if ("truncated" in key and child not in (False, "0", None)) or (
                    key == "sample_status" and child not in ("complete", "ok")
                ):
                    reasons.append(loc + "=" + str(child))
                walk(child, loc)
        elif isinstance(value, list):
            for i, child in enumerate(value):
                walk(child, path + "[%d]" % i)

    walk(data, "data")
    return {"status": "partial" if reasons else "complete", "reasons": reasons}


def record(
    experiment,
    collector,
    mechanism,
    domain,
    kind,
    timestamp,
    data,
    *,
    hook=None,
    context=None,
):
    ctx = dict.fromkeys(CONTEXT)
    supplied = context or {}
    for key in CONTEXT:
        value = supplied.get(key)
        ctx[key] = (
            str(value) if key in ("phase", "operation") and value is not None else value
        )
    payload = normalize(data)
    return {
        "experiment": experiment,
        "sequence": 0,
        "source": {
            "collector": collector,
            "mechanism": mechanism,
            "domain": domain,
            "hook": hook,
        },
        "kind": kind,
        "timestamp_ns": str(timestamp),
        "clock_domain": domain + ":monotonic",
        "context": ctx,
        "quality": quality(payload),
        "data": payload,
    }


def observation(experiment, collector, domain, raw, acquired_ns):
    """Normalize the typed C serializer output; it is an internal transport, never published."""
    info = raw.get("event_info", {})
    kind = info.get("event_name", info.get("name", raw.get("kind")))
    if raw.get("kind") in ("meta", "capture_meta"):
        kind = "collector_metadata"
    elif raw.get("kind") == "capture_summary":
        kind = "collector_summary"
    if raw.get("kind") == "snapshot" and experiment == "memory":
        kind = "memory_snapshot"
    context = dict(raw.get("context", {}))
    context["phase"] = info.get("phase_seq", info.get("phase", context.get("phase")))
    if raw.get("kind") == "phase":
        context["phase"] = raw.get("seq")
    context["operation"] = info.get(
        "operation_id", info.get("request_id", context.get("operation"))
    )
    reserved = {
        "experiment",
        "kind",
        "source",
        "seq",
        "time_ns",
        "clock",
        "context",
        "hook",
    }
    data = {k: v for k, v in raw.items() if k not in reserved}
    if "seq" in raw:
        data["producer_sequence"] = raw["seq"]
    # Preserve source-specific context fields rather than silently discarding them.
    extra = {k: v for k, v in raw.get("context", {}).items() if k not in CONTEXT}
    if extra:
        data["subject"] = extra
    return record(
        experiment,
        collector,
        "workload" if collector == "workload" else "ebpf",
        domain,
        kind,
        raw.get("time_ns", acquired_ns),
        data,
        hook=raw.get("hook", info.get("probe", info.get("hook"))),
        context=context,
    )


TRACE = re.compile(
    r"^\s*(.+?)-(\d+)\s+(?:\(\s*\d+\)\s+)?\[(\d+)\]\s+\S+\s+(\d+\.\d+):\s+(.*)$"
)
FIELDS = re.compile(r"(?:^|\s|,)([A-Za-z_][A-Za-z_0-9]*)[=:]\s*")


def trace_record(experiment, domain, line):
    match = TRACE.match(line)
    if not match:
        if not line.strip() or line.lstrip().startswith("#"):
            return None
        raise LabError("unrecognized trace record: " + line[:180])
    comm, tid, cpu, seconds, detail = match.groups()
    # Recent kernels include a quoted preview after the syscall buffer
    # pointer. That preview may contain parentheses, so the usual balanced
    # key/value parser cannot treat the whole print as one call. The public
    # contract needs the stable syscall arguments only.
    syscall_io = re.match(
        r"sys_(read|write)\(fd:\s*(\S+),\s*buf:\s*(\S+).*?,\s*count:\s*(\S+)\)", detail
    )
    if syscall_io:
        name, fd, buf, count = syscall_io.groups()
        return record(
            experiment,
            "tracefs",
            "tracefs",
            domain,
            "sys_enter_" + name,
            int(Decimal(seconds) * 1_000_000_000),
            {"fields": {"fd": fd, "buf": buf, "count": count}},
            hook="sys_enter_" + name,
            context={"tid": int(tid), "cpu": int(cpu), "comm": comm.strip()},
        )
    syscall = re.fullmatch(r"sys_(\w+)(?:\((.*)\)| -> (.*))", detail)
    if syscall:
        kind = "sys_" + ("enter_" if syscall[2] is not None else "exit_") + syscall[1]
        fields = (
            key_values(syscall[2]) if syscall[2] is not None else {"result": syscall[3]}
        )
    else:
        kind, separator, payload = detail.partition(": ")
        if not separator:
            raise LabError("unrecognized tracepoint boundary: " + detail)
        fields = decode(kind, payload.strip(), key_values)
    return record(
        experiment,
        "tracefs",
        "tracefs",
        domain,
        kind,
        int(Decimal(seconds) * 1_000_000_000),
        {"fields": fields},
        hook=kind,
        context={"tid": int(tid), "cpu": int(cpu), "comm": comm.strip()},
    )


def key_values(payload):
    matches = list(FIELDS.finditer(payload))
    if not matches or payload[: matches[0].start()].strip():
        raise LabError("unrecognized trace fields: " + payload[:160])
    fields = {}
    for i, field in enumerate(matches):
        key = field[1]
        if key in fields:
            raise LabError("duplicate trace field: " + key)
        fields[key] = payload[
            field.end() : matches[i + 1].start() if i + 1 < len(matches) else None
        ].strip(" ,")
    return fields


def ndjson(path):
    with Path(path).open() as stream:
        for index, line in enumerate(stream, 1):
            if not line.strip():
                raise LabError("blank capture record at %s:%d" % (path, index))
            try:

                def pairs(items):
                    result = {}
                    for key, value in items:
                        if key in result:
                            raise ValueError("duplicate key " + key)
                        result[key] = value
                    return result

                yield json.loads(
                    line,
                    object_pairs_hook=pairs,
                    parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)),
                )
            except ValueError as exc:
                raise LabError(
                    "invalid JSON at %s:%d: %s" % (path, index, exc)
                ) from exc


def check_type(value, spec, path="data", types=None):
    """Validate the documented closed type vocabulary in payloads.json."""
    if "$ref" in spec:
        spec = (types or {})[spec["$ref"]]
    if value is None:
        if spec.get("nullable"):
            return
        raise LabError(path + " cannot be null")
    typ = spec["type"]
    if typ == "object":
        if not isinstance(value, dict):
            raise LabError(path + " must be an object")
        props = spec["fields"]
        extra = value.keys() - props.keys()
        missing = set(spec.get("required", [])) - value.keys()
        if extra or missing:
            raise LabError(
                "%s: unknown %s, missing %s" % (path, sorted(extra), sorted(missing))
            )
        for key, child in value.items():
            check_type(child, props[key], path + "." + key, types)
    elif typ == "array":
        if not isinstance(value, list):
            raise LabError(path + " must be an array")
        for child in value:
            check_type(child, spec["items"], path + "[]", types)
    elif typ == "boolean":
        if type(value) is not bool:
            raise LabError(path + " must be boolean")
    elif typ in ("string", "integer64", "hex"):
        if not isinstance(value, str):
            raise LabError(path + " must be a string")
        if typ == "integer64" and not re.fullmatch(r"-?(0|[1-9][0-9]*)", value):
            raise LabError(path + " must be a decimal integer string")
        if typ == "hex" and not re.fullmatch(r"0x[0-9a-f]+", value):
            raise LabError(path + " must be hexadecimal")
    elif typ == "null":
        raise LabError(path + " only permits null")
    else:
        raise LabError("unknown contract type " + typ)


def validate_record(event, name, catalog, sequence):
    if (
        set(event) != ENVELOPE
        or event["experiment"] != name
        or event["sequence"] != sequence
    ):
        raise LabError("invalid envelope or sequence at record %d" % sequence)
    if not isinstance(event["timestamp_ns"], str) or not re.fullmatch(
        r"0|[1-9][0-9]*", event["timestamp_ns"]
    ):
        raise LabError("invalid nanosecond timestamp")
    source = event["source"]
    if set(source) != {"collector", "mechanism", "domain", "hook"}:
        raise LabError("invalid source envelope")
    if (
        source["domain"] not in ("host", "guest")
        or event["clock_domain"] != source["domain"] + ":monotonic"
    ):
        raise LabError("invalid clock domain")
    if source["mechanism"] not in (
        "framework",
        "ebpf",
        "tracefs",
        "workload",
        "module",
        "sysfs",
    ):
        raise LabError("unknown collection mechanism")
    ctx = event["context"]
    if set(ctx) != set(CONTEXT):
        raise LabError("invalid context envelope")
    for key in ("cpu", "pid", "tid"):
        if ctx[key] is not None and (
            type(ctx[key]) is not int or not 0 <= ctx[key] < 2**32
        ):
            raise LabError("invalid context " + key)
    for key in ("comm", "phase", "operation"):
        if ctx[key] is not None and not isinstance(ctx[key], str):
            raise LabError("invalid context " + key)
    q = event["quality"]
    if (
        set(q) != {"status", "reasons"}
        or q["status"] not in ("complete", "partial", "unavailable")
        or not isinstance(q["reasons"], list)
    ):
        raise LabError("invalid quality envelope")
    if (q["status"] == "complete") != (q["reasons"] == []):
        raise LabError("quality status and reasons disagree")
    key = source["mechanism"] + ":" + event["kind"]
    spec = catalog.get(key)
    if spec is None:
        raise LabError("unregistered event: " + key)
    check_type(event["data"], spec, types=catalog.get("$defs"))


def validate(path, name, *, evidence=True):
    catalog = read_json(ROOT / "experiments" / name / "payloads.json")
    catalog.update(read_json(ROOT / "framework" / "core" / "lifecycle.json"))
    events = list(ndjson(path))
    if (
        len(events) < 3
        or events[0]["kind"] != "capture_started"
        or events[-1]["kind"] != "capture_finished"
    ):
        raise LabError("capture lifecycle is incomplete")
    for seq, event in enumerate(events, 1):
        validate_record(event, name, catalog, seq)
    if any(e["kind"] == "capture_failed" for e in events):
        raise LabError("failed capture cannot be published")
    if evidence:
        validate_evidence(name, events)
    return events


def publish(staged, target, name):
    validate(staged, name)
    atomic_bytes(target, Path(staged).read_bytes())


class Capture:
    def __init__(self, name, domain, path):
        self.name, self.domain, self.path = name, domain, Path(path)
        self.events = []

    def lifecycle(self, kind, data):
        self.events.append(
            record(
                self.name,
                "controller",
                "framework",
                self.domain,
                kind,
                time.monotonic_ns(),
                data,
            )
        )

    def save(self):
        for seq, event in enumerate(self.events, 1):
            event["sequence"] = seq
        atomic_bytes(
            self.path,
            b"".join(
                (json.dumps(e, separators=(",", ":"), allow_nan=False) + "\n").encode()
                for e in self.events
            ),
        )


def validate_evidence(name, events):
    """Apply experiment-specific scientific assertions after envelope checks."""
    cfg = manifest(name)
    kinds = Counter(e["kind"] for e in events)

    def require(condition, message):
        if not condition:
            raise LabError("evidence: " + message)

    for kind in cfg["required"]:
        require(kinds[kind] > 0, "missing " + kind)
    require(
        kinds["capture_started"] == kinds["capture_finished"] == 1,
        "exactly one capture lifetime required",
    )
    require(
        kinds["workload_started"] > 0 and kinds["workload_finished"] > 0,
        "missing workload boundaries",
    )
    require(
        events[-1]["data"] == {"validated": True, "restored": True},
        "unsuccessful final status",
    )
    ready = Counter(
        e["data"]["collector"] for e in events if e["kind"] == "collector_ready"
    )
    done = Counter(
        e["data"]["collector"] for e in events if e["kind"] == "collector_finished"
    )
    require(ready and ready == done, "collector readiness/completion mismatch")
    for event in events:
        if event["kind"] == "collector_finished":
            require(
                event["data"]["dropped"] == event["data"]["failures"] == "0",
                "collector reported evidence loss",
            )
        if event["quality"]["status"] != "complete":
            require(
                cfg["allow_partial"] and event["quality"]["status"] == "partial",
                "undeclared partial observation",
            )
        if event["kind"] == "collector_summary":
            state = event["data"].get("state", {})
            require(
                state.get("ringbuf_dropped") == "0"
                and state.get("short_records") == "0",
                "observer summary reports loss",
            )

    def selected(kind, mechanism=None):
        return [
            event
            for event in events
            if event["kind"] == kind
            and (mechanism is None or event["source"]["mechanism"] == mechanism)
        ]

    if name == "scheduler":
        for event in selected("enqueue_entity"):
            runqueue = event["data"]["state"]["runqueue"]
            require(
                int(runqueue["node_count"]) == len(runqueue["nodes"]),
                "scheduler node count differs from payload",
            )
        require(
            selected("sched_process_fork", "tracefs")
            and selected("sched_switch", "tracefs"),
            "missing scheduler lifecycle context",
        )
    elif name == "memory":
        phases = selected("phase", "workload")
        snapshots = selected("memory_snapshot", "ebpf")
        require(
            [event["context"]["phase"] for event in phases]
            == [event["context"]["phase"] for event in snapshots],
            "memory phases and snapshots do not pair",
        )
        require(phases, "memory workload emitted no phases")
        for stream in (phases, snapshots):
            times = [int(event["timestamp_ns"]) for event in stream]
            require(times == sorted(times), "memory producer clock went backwards")
    elif name == "io":
        phases = selected("phase", "workload")
        phase_names = [event["data"]["event_info"].get("phase") for event in phases]
        phase_actions = [event["data"]["event_info"].get("action") for event in phases]
        phase_contract = [str(phase["id"]) for phase in cfg.get("phases", [])]
        expected_markers = [
            phase_id for phase_id in phase_contract for _ in ("begin", "end")
        ]
        expected_actions = [
            action for _ in phase_contract for action in ("begin", "end")
        ]
        require(
            len(phases) == len(expected_markers),
            "IO workload must emit one begin/end pair for each canonical phase",
        )
        require(
            phase_contract == ["driver_initialization", "factorial", "two_way_dma"],
            "IO manifest must define exactly three canonical phases",
        )
        require(
            phase_names == expected_markers,
            "IO workload phases are not ordered as driver initialization, factorial, two-way DMA",
        )
        require(
            phase_actions == expected_actions,
            "IO workload phase boundaries are incomplete",
        )
        fields = [
            event["data"]["fields"] for event in selected("qedu_dma_submit", "tracefs")
        ]
        require(
            {value["direction"] for value in fields}
            >= {"DMA_TO_DEVICE", "DMA_FROM_DEVICE"},
            "both DMA directions must be observed",
        )
        probe_apis = [
            event["data"]["fields"] for event in selected("qedu_probe_api", "tracefs")
        ]
        require(
            any(
                value["api"] == "qedu_probe"
                and value["resource"] == "bound_qedu_device"
                for value in probe_apis
            ),
            "EDU probe did not finish",
        )
        handoffs = [
            event["data"]["fields"]
            for event in selected("qedu_dma_work_queue", "tracefs")
        ]
        require(
            {value["work_kind"] for value in handoffs if value["queued"] == "1"}
            >= {"ADVANCE", "FINISH"},
            "EDU IRQ-to-worker handoff incomplete",
        )
    elif name == "kapi":
        require(
            any(
                event["data"].get("domain") == "module"
                for event in selected("ready", "module")
            ),
            "module never reached ready",
        )
    elif name == "virt-ept":
        for kind, field, count in (
            ("control", "control", 5),
            ("memslot", "memslot", 6),
        ):
            begins = selected(kind + "_begin", "ebpf")
            ends = selected(kind + "_end", "ebpf")
            require(len(begins) == len(ends) == count, "wrong EPT " + kind + " count")
            require(
                {event["data"][field]["operation_id"] for event in begins}
                == {event["data"][field]["operation_id"] for event in ends},
                "unpaired EPT " + kind,
            )
            require(
                all(event["data"][field]["result"] == "0" for event in ends),
                "failed EPT " + kind,
            )
    elif name == "virt-virtio":
        begins = selected("queue_backend_begin", "ebpf")
        ends = selected("queue_backend_end", "ebpf")
        require(
            len(begins) == len(ends) == 3, "expected three virtqueue backend operations"
        )
        require(
            len(selected("ioeventfd_kick", "ebpf"))
            == len(selected("irqfd_signal", "ebpf"))
            == 1,
            "missing eventfd handoff",
        )
        require(
            [event["data"]["state"]["used"]["idx"] for event in ends]
            == ["1", "5", "6"],
            "virtqueue completion indices differ",
        )
    elif name == "virt-vtd":
        lifecycle = [
            event["kind"] for event in events if event["source"]["mechanism"] == "sysfs"
        ]
        require(
            lifecycle
            == [
                "host_owns_device",
                "vfio_bound",
                "qemu_attached",
                "guest_visible",
                "host_reclaims_device",
            ],
            "incomplete PCI assignment lifetime",
        )
        for event in selected("guest_ixgbe_run_loopback_exit", "ebpf"):
            require(
                event["data"]["event_info"]["result"] == "0", "guest loopback failed"
            )
        require(
            len(selected("guest_irq_handler_entry"))
            == len(selected("guest_irq_handler_exit")),
            "unpaired guest IRQ boundaries",
        )

    enters = selected("sys_enter_ioctl", "ebpf")
    exits = selected("sys_exit_ioctl", "ebpf")
    if enters or exits:
        require(len(enters) == len(exits), "unpaired ioctl event counts")


class Process:
    def __init__(self, argv, *, cwd, stdout, stderr, env=None, control=False):
        self.out = Path(stdout).open("wb") if stdout is not None else None
        self.err = Path(stderr).open("ab") if stderr is not None else None
        self.read_fd = None
        self.buffer = b""
        self.messages = []
        write_fd = None
        child_env = dict(os.environ, **(env or {}))
        try:
            if control:
                self.read_fd, write_fd = os.pipe()
                os.set_blocking(self.read_fd, False)
                child_env["LAB_CONTROL_FD"] = str(write_fd)
            self.child = subprocess.Popen(
                [str(x) for x in argv],
                cwd=cwd,
                env=child_env,
                stdin=subprocess.PIPE,
                stdout=self.out,
                stderr=self.err,
                start_new_session=True,
                pass_fds=() if write_fd is None else (write_fd,),
            )
        except BaseException:
            self.close()
            raise
        finally:
            if write_fd is not None:
                os.close(write_fd)

    def receive(self):
        if self.read_fd is None:
            return
        while select.select([self.read_fd], [], [], 0)[0]:
            chunk = os.read(self.read_fd, 65536)
            if not chunk:
                break
            self.buffer += chunk
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            self.messages.append(line.decode("utf-8"))
        if len(self.buffer) > 65536:
            raise LabError("oversized collector control message")

    def wait_control(self, prefix, timeout):
        end = time.monotonic() + timeout
        while True:
            self.receive()
            for index, message in enumerate(self.messages):
                if message.startswith(prefix):
                    return self.messages.pop(index)
            if self.child.poll() is not None:
                raise LabError("collector exited without " + prefix)
            if time.monotonic() >= end:
                raise LabError("collector timed out waiting for " + prefix)
            time.sleep(0.05)

    def signal(self, sig):
        if self.child.poll() is None:
            os.killpg(self.child.pid, sig)

    def wait(self, timeout, peers=()):
        end = time.monotonic() + timeout
        while self.child.poll() is None:
            if any(p.child.poll() is not None for p in peers):
                raise LabError("collector exited while workload was active")
            if time.monotonic() >= end:
                raise LabError("process exceeded its timeout")
            time.sleep(0.05)
        if self.child.returncode:
            raise LabError("process exited with status %s" % self.child.returncode)

    def stop(self, sig=None, timeout=15):
        if sig is None:
            sig = signal.SIGTERM
        self.signal(sig)
        try:
            self.child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.signal(signal.SIGKILL)
            self.child.wait(timeout=5)
            raise LabError("process required SIGKILL during cleanup")

    def close(self):
        if hasattr(self, "child") and self.child.stdin:
            self.child.stdin.close()
        if getattr(self, "out", None) is not None:
            self.out.close()
        if getattr(self, "err", None) is not None:
            self.err.close()
        if self.read_fd is not None:
            os.close(self.read_fd)
            self.read_fd = None


# Explicit decoders for tracepoints whose print format is not key/value based.
PATTERNS = {
    "kvm_entry": r"vcpu (?P<vcpu>\d+)(?:, rip (?P<rip>\S+))?",
    "kvm_exit": r"vcpu (?P<vcpu>\d+) reason (?P<reason>\S+) rip (?P<rip>\S+) info1 (?P<info1>\S+) info2 (?P<info2>\S+) intr_info (?P<intr_info>\S+) error_code (?P<error_code>\S+)(?: \(.*\))?",
    "kvm_page_fault": r"vcpu (?P<vcpu>\d+) rip (?P<rip>\S+) address (?P<address>\S+) error_code (?P<error_code>\S+)",
    "kvm_userspace_exit": r"reason (?P<reason>\S+) \((?P<code>[^)]+)\)",
    "kvm_mmio": r"mmio (?P<direction>\S+) len (?P<length>\d+) gpa (?P<gpa>\S+) val (?P<value>\S+)",
    "kvm_pio": r"(?P<direction>pio_\w+) at (?P<port>\S+) size (?P<size>\d+) count (?P<count>\d+) val (?P<value>\S+)",
    "kvm_set_irq": r"gsi (?P<gsi>\d+) level (?P<level>\d+) source (?P<source>\d+)",
    "kvm_inj_virq": r"IRQ (?P<vector>\S+)(?: \[(?P<reinjected>[^]]+)\])?",
    "kvm_apic_accept_irq": r"apicid (?P<apic_id>\d+) vec (?P<vector>\d+) \((?P<mode>[^)]+)\)",
    "kvm_ioapic_set_irq": r"pin (?P<pin>\d+) dst (?P<destination>\d+) vec (?P<vector>\d+) \((?P<mode>[^)]+)\)",
    "kvm_msi_set_irq": r"dst (?P<destination>\d+) vec (?P<vector>\d+) \((?P<mode>[^)]+)\)",
    "kvm_cr": r"(?P<operation>cr_\w+) (?P<register>\d+) = (?P<value>\S+)",
    "kvm_apic": r"(?P<operation>apic_\w+) (?P<register>\S+) = (?P<value>\S+)",
    "kvm_emulate_insn": r"(?P<cs>[^:]+):(?P<rip>[^:]+):(?P<instruction>.*?) \((?P<mode>[^)]+)\)(?: (?P<failed>failed))?",
    "kvm_unmap_hva_range": r"mmu notifier unmap range: (?P<start>\S+) -- (?P<end>\S+)",
    "kvm_mmu_spte_requested": r"gfn (?P<gfn>\S+) pfn (?P<pfn>\S+) level (?P<level>\d+)",
    "kvm_mmu_set_spte": r"gfn (?P<gfn>\S+) spte (?P<spte>\S+) \((?P<permissions>[^)]+)\) level (?P<level>\d+) at (?P<address>\S+)",
    "kvm_tdp_mmu_spte_changed": r"as id (?P<address_space>\d+) gfn (?P<gfn>\S+) level (?P<level>\d+) old_spte (?P<old_spte>\S+) new_spte (?P<new_spte>\S+)",
    "kvm_mmu_split_huge_page": r"gfn (?P<gfn>\S+) spte (?P<spte>\S+) level (?P<level>\d+) errno (?P<errno>-?\d+)",
    "writeback_pages_written": r"(?P<pages>\d+)",
    "exit_mmap": r"mt_mod (?P<maple_tree>\S+), (?P<operation>\S+)",
    "workqueue_execute_start": r"work struct (?P<work>[^: ]+): function (?P<function>.+)",
    "workqueue_execute_end": r"work struct (?P<work>[^: ]+): function (?P<function>.+)",
}


class Trace:
    def __init__(self, name, runtime, buffer_kib):
        self.root = Path("/sys/kernel/tracing")
        if not (self.root / "events").exists():
            command(["mount", "-t", "tracefs", "nodev", self.root])
        self.path = self.root / "instances" / ("lab-" + name)
        if self.path.exists():
            raise LabError(
                "stale trace instance requires inspection: " + str(self.path)
            )
        self.runtime = runtime
        self.enabled, self.skipped = [], []
        self.thread = None
        self.error = None
        self.stopping = threading.Event()
        self.path.mkdir()
        try:
            self.write("tracing_on", "0")
            self.write("trace_clock", "mono")
            if "[mono]" not in (self.path / "trace_clock").read_text():
                raise LabError("tracefs did not select the monotonic clock")
            self.write("buffer_size_kb", str(buffer_kib))
            self.write("trace", "")
        except BaseException:
            self.close()
            raise

    def write(self, relative, value):
        (self.path / relative).write_text(value + "\n")

    def enable(self, events, required=True):
        catalog = read_json(
            ROOT / "experiments" / self.path.name.removeprefix("lab-") / "payloads.json"
        )
        formats = self.runtime / "trace-formats"
        formats.mkdir(exist_ok=True)
        for event in events:
            if "tracefs:" + event.split("/")[1] not in catalog:
                if required:
                    raise LabError(
                        "required tracepoint has no reviewed payload contract: " + event
                    )
                self.skipped.append(event + ": no reviewed payload contract")
                continue
            path = self.path / "events" / event
            if not (path / "enable").exists():
                if required:
                    raise LabError("missing required tracepoint: " + event)
                self.skipped.append(event)
                continue
            self.write("events/" + event + "/enable", "1")
            (formats / event.replace("/", "__")).write_text(
                (path / "format").read_text()
            )
            self.enabled.append(event)

    def filter(self, event, expression):
        if event in self.enabled:
            self.write("events/" + event + "/filter", expression)

    def start(self):
        def drain():
            fd = None
            try:
                fd = os.open(self.path / "trace_pipe", os.O_RDONLY | os.O_NONBLOCK)
                with (self.runtime / "trace.txt").open("wb") as stream:
                    idle = time.monotonic()
                    while not self.stopping.is_set() or time.monotonic() - idle < 0.25:
                        if select.select([fd], [], [], 0.05)[0]:
                            try:
                                chunk = os.read(fd, 65536)
                            except BlockingIOError:
                                continue
                            if chunk:
                                stream.write(chunk)
                                idle = time.monotonic()
            except BaseException as exc:
                self.error = exc
            finally:
                if fd is not None:
                    os.close(fd)

        self.thread = threading.Thread(target=drain, daemon=True)
        self.thread.start()
        self.write("tracing_on", "1")

    def stop(self):
        self.write("tracing_on", "0")
        self.stopping.set()
        if self.thread:
            self.thread.join(timeout=10)
            if self.thread.is_alive():
                raise LabError("trace drain did not finish")
        if self.error:
            raise LabError("trace drain failed: " + str(self.error))
        stats = {}
        for path in sorted((self.path / "per_cpu").glob("cpu*/stats")):
            values = dict(
                line.split(":", 1)
                for line in path.read_text().splitlines()
                if ":" in line
            )
            stats[path.parent.name] = values
            for key in ("overrun", "commit overrun", "dropped events"):
                if key not in values:
                    raise LabError("missing trace loss counter: " + key)
                if int(values[key].strip()):
                    raise LabError(
                        "trace data loss: %s %s=%s"
                        % (path.parent.name, key, values[key])
                    )
        if not stats:
            raise LabError("trace loss accounting is unavailable")
        atomic_json(self.runtime / "trace-stats.json", stats)
        return stats

    def close(self):
        if self.path.exists():
            self.write("tracing_on", "0")
            self.stopping.set()
            if self.thread:
                self.thread.join(timeout=10)
            for event in self.enabled:
                self.write("events/" + event + "/enable", "0")
            self.path.rmdir()


def decode(kind, payload, key_values):
    if kind in PATTERNS:
        match = re.fullmatch(PATTERNS[kind], payload)
        if not match:
            raise LabError("trace format changed for %s: %s" % (kind, payload[:180]))
        return match.groupdict()
    prefix = {}
    if kind == "dma_alloc":
        device, payload = payload.split(" ", 1)
        prefix["device"] = device
    elif kind.startswith("writeback_") or kind == "wbc_writepage":
        match = re.match(r"bdi (\S+): (?:sb_dev (\S+) )?", payload)
        if match:
            prefix["bdi"] = match[1]
            if match[2] is not None:
                prefix["sb_dev"] = match[2]
            payload = payload[match.end() :]
    elif kind in ("mm_filemap_add_to_page_cache", "mm_filemap_delete_from_page_cache"):
        match = re.match(r"dev (\S+) ino (\S+) ", payload)
        if not match:
            raise LabError("unrecognized filemap format")
        prefix.update(device=match[1], inode=match[2])
        payload = payload[match.end() :]
    elif kind == "workqueue_queue_work":
        payload = payload.replace("work struct=", "work=", 1)
    elif kind == "workqueue_activate_work":
        payload = payload.replace("work struct ", "work=", 1)
    fields = key_values(payload)
    if fields.keys() & prefix.keys():
        raise LabError("duplicate trace prefix field")
    return dict(prefix, **fields)


def module_record(line):
    """Normalize a structured KAPI printk line into the capture envelope."""
    match = re.search(r"\[\s*(\d+\.\d+)\]\s+KAPI_EVT (.*)", line)
    if not match:
        raise LabError("invalid KAPI log record")
    data = {}
    for token in shlex.split(match[2]):
        key, sep, value = token.partition("=")
        if not sep or key in data:
            raise LabError("invalid KAPI field: " + token)
        if re.fullmatch(r"[0-9a-f]{16}", value):
            value = "0x" + value if int(value, 16) else None
        data[key] = value
    return record(
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


def stopped(process, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        path = Path("/proc/%d/status" % process.child.pid)
        if not path.exists():
            raise LabError("workload exited before its tracing gate")
        if re.search(r"^State:\s+T", path.read_text(), re.MULTILINE):
            return
        time.sleep(0.02)
    raise LabError("workload did not stop at its tracing gate")


class Session:
    def __init__(self, name, domain):
        self.name, self.domain = name, domain
        self.cfg = manifest(name)
        shared = os.environ.get("LAB_SHARED_SCRATCH")
        if shared:
            self._scratch = None
            self.runtime = Path(shared)
            self.runtime.mkdir(parents=True, exist_ok=True)
        else:
            scratch_parent = ROOT / "build" if name == "virt-vtd" else None
            self._scratch = tempfile.TemporaryDirectory(
                prefix="linuxmaxxing-%s-" % name, dir=scratch_parent
            )
            self.runtime = Path(self._scratch.name)
        self.cwd = (
            Path("/mnt/host") / self.cfg["source"]
            if domain == "guest"
            else ROOT / "build/tree" / self.cfg["source"]
        )
        self.stack = ExitStack()
        self.capture = Capture(name, domain, self.runtime / "events.ndjson")
        self.observers = []
        self.trace = None
        self.acquired = time.monotonic_ns()

    def process(self, argv, label, control=False, cwd=None):
        proc = Process(
            argv,
            cwd=cwd or self.cwd,
            stdout=self.runtime / (label + ".ndjson"),
            stderr=None,
            control=control,
        )
        self.stack.callback(proc.close)
        self.stack.callback(proc.stop)
        return proc

    def observer(self, argv=None, label="observer"):
        proc = self.process(
            argv or [self.cwd / self.cfg["observer"]], label, control=True
        )
        self.observers.append((proc, label))
        proc.wait_control("LX_READY ", self.cfg["timeouts"]["ready_s"])
        self.capture.lifecycle("collector_ready", {"collector": label})
        return proc

    def trace_start(self):
        if not self.cfg["trace"]["required"] and not self.cfg["trace"]["optional"]:
            return
        self.trace = Trace(self.name, self.runtime, self.cfg["buffer_kib"])
        self.stack.callback(self.trace.close)
        self.trace.enable(self.cfg["trace"]["required"])
        self.trace.enable(self.cfg["trace"]["optional"], required=False)
        self.trace.start()
        self.capture.lifecycle("collector_ready", {"collector": "tracefs"})

    def module(self, name):
        if Path("/sys/module", name).exists():
            raise LabError("module already loaded; refusing to take ownership: " + name)
        command(["/sbin/insmod", self.cwd / (name + ".ko")])

        def remove():
            if Path("/sys/module", name).exists():
                command(["/sbin/rmmod", name])

        self.stack.callback(remove)

    def run_workload(self):
        self.capture.lifecycle("workload_started", {"command": self.cfg["workload"]})
        proc = self.process(self.cfg["workload"], "workload")
        if self.name == "scheduler":
            stopped(proc, self.cfg["timeouts"]["ready_s"])
            for event in self.trace.enabled:
                if event == "sched/sched_switch":
                    self.trace.filter(
                        event, 'prev_comm ~ "sched*" || next_comm ~ "sched*"'
                    )
                elif event == "sched/sched_process_fork":
                    self.trace.filter(
                        event, 'parent_comm ~ "sched*" || child_comm ~ "sched*"'
                    )
                else:
                    self.trace.filter(event, 'comm ~ "sched*"')
            proc.signal(signal.SIGCONT)
        elif self.name == "io":
            stopped(proc, self.cfg["timeouts"]["ready_s"])
            pid = proc.child.pid
            for event in self.trace.enabled:
                if event.startswith("syscalls/"):
                    self.trace.filter(event, "common_pid == %d" % pid)
            self.trace.filter(
                "sched/sched_switch",
                'prev_pid == %d || next_pid == %d || prev_comm ~ "kworker*" || next_comm ~ "kworker*"'
                % (pid, pid),
            )
            self.trace.filter("sched/sched_wakeup", "pid == %d" % pid)
            proc.signal(signal.SIGCONT)
        elif self.name == "memory":
            # The MM observer is already keyed to workload_mm. Keep the
            # supplemental trace stream equally narrow so background reclaim
            # and allocator activity cannot dominate the capture.
            pid = proc.child.pid
            for event in self.trace.enabled:
                self.trace.filter(event, "common_pid == %d" % pid)
        proc.wait(
            self.cfg["timeouts"]["workload_s"], peers=[p for p, _ in self.observers]
        )
        self.capture.lifecycle("workload_finished", {"exit_code": 0})
        if self.name == "scheduler":
            for observer, _ in self.observers:
                observer.signal(signal.SIGUSR1)
            for event in self.trace.enabled:
                self.trace.filter(event, "0")
            time.sleep(self.cfg.get("post_workload_grace_ms", 0) / 1000)

    def collect(self):
        for proc, label in self.observers:
            proc.signal(signal.SIGINT)
            proc.wait(self.cfg["timeouts"]["shutdown_s"])
            proc.wait_control("LX_DONE ", self.cfg["timeouts"]["shutdown_s"])
            health = proc.wait_control("LX_HEALTH ", 1)
            fields = dict(item.split("=", 1) for item in health.split()[1:])
            if fields != {"dropped": "0", "failures": "0"}:
                raise LabError("observer lost required evidence: " + health)
            for raw in ndjson(self.runtime / (label + ".ndjson")):
                self.capture.events.append(
                    observation(self.name, label, self.domain, raw, self.acquired)
                )
            self.capture.lifecycle(
                "collector_finished", {"collector": label, "dropped": 0, "failures": 0}
            )
        if self.trace:
            self.trace.stop()
            with (self.runtime / "trace.txt").open() as stream:
                for line in stream:
                    try:
                        event = trace_record(self.name, self.domain, line)
                    except LabError as exc:
                        raise LabError(
                            "trace decode failed: %s | %s" % (exc, line.strip())
                        ) from exc
                    if event:
                        self.capture.events.append(event)
            self.capture.lifecycle(
                "collector_finished",
                {"collector": "tracefs", "dropped": 0, "failures": 0},
            )
        if self.name in ("memory", "io"):
            for raw in ndjson(self.runtime / "workload.ndjson"):
                self.capture.events.append(
                    observation(self.name, "workload", self.domain, raw, self.acquired)
                )

    def io_prepare(self):
        self.module("qedu_trace")
        self.trace_start()
        devices = [
            p
            for p in Path("/sys/bus/pci/devices").iterdir()
            if (p / "vendor").read_text().strip() == "0x1234"
            and (p / "device").read_text().strip() == "0x11e8"
        ]
        if len(devices) != 1:
            raise LabError("expected exactly one QEMU EDU device")
        pci = devices[0]
        irq = (pci / "irq").read_text().strip()
        self.trace.filter("dma/dma_alloc", 'device == "%s"' % pci.name)
        for event in (
            "irq/irq_handler_entry",
            "irq/irq_handler_exit",
            "irq_vectors/vector_alloc",
            "irq_vectors/vector_config",
        ):
            self.trace.filter(event, "irq == " + irq)
        self.module("qedu")
        timeout = Path("/sys/class/misc/qedu/timeout_ms")
        previous = timeout.read_text()
        self.stack.callback(timeout.write_text, previous)
        timeout.write_text("1500\n")
        symbols = {
            fields[2]: fields[0]
            for line in Path("/proc/kallsyms").read_text().splitlines()
            if len(fields := line.split()) >= 3
        }
        names = ("qedu_dma_advance_work", "qedu_dma_finish_work")
        if not all(symbols.get(n, "0").strip("0") for n in names):
            raise LabError("EDU worker symbols are unavailable")
        expr = " || ".join("function == 0x" + symbols[n] for n in names)
        for event in (
            "workqueue/workqueue_activate_work",
            "workqueue/workqueue_execute_start",
            "workqueue/workqueue_execute_end",
        ):
            self.trace.filter(event, expr)
        self.trace.filter("workqueue/workqueue_queue_work", 'workqueue == "qedu_dma"')

    def kapi(self):
        marker = "LAB_KAPI_BEGIN_%d_%d" % (os.getpid(), self.acquired)
        Path("/dev/kmsg").write_text("<6>" + marker + "\n")
        self.capture.lifecycle("collector_ready", {"collector": "module"})
        self.capture.lifecycle(
            "workload_started", {"command": ["/sbin/insmod", "kapi.ko"]}
        )
        # dmesg is bounded by an explicit marker; no global log clearing.
        self.module("kapi")
        command(["/sbin/rmmod", "kapi"])
        # Successful explicit teardown disarms only this module callback.
        # The callback checks ownership state again on cleanup.
        self.capture.lifecycle("workload_finished", {"exit_code": 0})
        lines = command(["dmesg"]).decode().splitlines()
        active = False
        for line in lines:
            if marker in line:
                active = True
                continue
            if active and "KAPI_EVT " in line:
                self.capture.events.append(module_record(line))
        self.capture.lifecycle(
            "collector_finished", {"collector": "module", "dropped": 0, "failures": 0}
        )

    def execute(self):
        if os.geteuid() != 0:
            raise LabError(
                "experiment worker requires root in its execution environment"
            )
        facts = read_json(ROOT / "build/environment.json")
        self.capture.lifecycle(
            "capture_started",
            {
                "environment": facts,
                "source_digest": read_json(ROOT / "source-provenance.json")["digest"],
                "enabled": [],
                "skipped": [],
            },
        )
        try:
            if self.name == "virt-vtd":
                from framework.specifics.vtd import run

                run(self)
            elif self.name == "kapi":
                self.kapi()
            else:
                if self.name == "memory":
                    command(["/sbin/swapon", "/dev/vdb"])
                if self.name == "io":
                    self.io_prepare()
                else:
                    self.trace_start()
                if self.cfg["observer"]:
                    self.observer()
                self.run_workload()
                self.collect()
            if self.trace:
                self.capture.events[0]["data"]["enabled"] = self.trace.enabled
                self.capture.events[0]["data"]["skipped"] = self.trace.skipped
            self.stack.close()
            self.capture.lifecycle(
                "capture_finished", {"validated": True, "restored": True}
            )
            self.capture.save()
            publish(
                self.capture.path,
                ROOT / "captures" / self.name / "events.ndjson",
                self.name,
            )
        except BaseException as exc:
            try:
                self.stack.close()
            except BaseException as cleanup:
                exc = LabError("%s; cleanup failed: %s" % (exc, cleanup))
            self.capture.lifecycle(
                "capture_failed", {"error": str(exc) or type(exc).__name__}
            )
            self.capture.save()
            raise LabError(str(exc)) from exc


def prepare_image():
    cfg = read_json(ROOT / "infra/environment.json")
    image = ROOT / "build/images/study.qcow2"
    stamp = ROOT / "build/images/study.json"
    expected = {
        "base_sha256": cfg["image_sha256"],
        "packages": "python3,kmod,util-linux,libbpf1,libelf1,zlib1g,openssh-server,ethtool",
    }
    if image.exists() and stamp.exists() and read_json(stamp) == expected:
        return image
    temporary = image.with_name("study.preparing.qcow2")
    if temporary.exists():
        temporary.unlink()
    command(
        [
            "qemu-img",
            "convert",
            "-O",
            "qcow2",
            ROOT / "build/images/ubuntu.qcow2",
            temporary,
        ],
        timeout=600,
    )
    customize = [
        "sudo",
        "-n",
        "virt-customize",
        "-a",
        temporary,
        "--install",
        expected["packages"],
    ]
    # The first libguestfs invocation on a fresh lab server can race its
    # supermin appliance cache while apt/libguestfs packages are settling.
    # Retrying is safe because customization is performed on the disposable
    # staging image and the publish step below remains atomic.
    try:
        command(customize, timeout=1800, capture=False)
    except LabError:
        command(customize, timeout=1800, capture=False)
    temporary.replace(image)
    atomic_json(stamp, expected)
    return image


def run(name, console=False):
    cfg = read_json(ROOT / "infra/environment.json")
    image = prepare_image()
    build = ROOT / "build"
    build.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="linuxmaxxing-guest-", dir=build
    ) as scratch_name:
        runtime = Path(scratch_name)
        overlay = runtime / "guest.qcow2"
        swap = runtime / "swap.raw"
        result = runtime / "guest-result.json"
        command(
            ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay]
        )
        with swap.open("wb") as stream:
            stream.truncate(cfg["guest_swap_mib"] * 1024 * 1024)
        command(["mkswap", "--quiet", swap])
        argv = [
            "qemu-system-x86_64",
            "-accel",
            "tcg",
            "-m",
            str(cfg["guest_memory_mib"]),
            "-smp",
            str(cfg["guest_cpus"]),
            "-kernel",
            str(ROOT / "build/kernel/arch/x86/boot/bzImage"),
            "-append",
            "root=/dev/vda1 console=ttyS0 rootwait rw loglevel=4 init=/bin/sh",
            "-drive",
            "file=%s,if=virtio,format=qcow2" % overlay,
            "-drive",
            "file=%s,if=virtio,format=raw" % swap,
            "-virtfs",
            "local,path=%s,mount_tag=hostshare,security_model=none"
            % (ROOT / "build/tree"),
            "-virtfs",
            "local,path=%s,mount_tag=labrepo,security_model=none" % ROOT,
            "-device",
            "edu",
            "-nographic",
            "-no-reboot",
        ]
        if console:
            command(argv, capture=False, timeout=14400)
            return
        with ExitStack() as stack:
            proc = Process(argv, cwd=ROOT, stdout=runtime / "console.log", stderr=None)
            stack.callback(proc.close)
            stack.callback(proc.stop)
            timeout = manifest(name)["timeouts"]
            console_log = runtime / "console.log"
            shown = 0

            def stream_console():
                nonlocal shown
                text = console_log.read_text(errors="replace")
                if len(text) > shown:
                    print(text[shown:], file=sys.stderr, end="", flush=True)
                    shown = len(text)
                return text

            end = time.monotonic() + timeout["guest_boot_s"]
            while time.monotonic() < end:
                text = stream_console()
                if "job control" in text:
                    break
                if proc.child.poll() is not None:
                    raise LabError("study guest exited during boot")
                time.sleep(0.2)
            else:
                raise LabError("study guest shell did not become ready")
            relative = runtime.relative_to(ROOT)
            script = (
                "mount -t proc proc /proc; mount -t sysfs sysfs /sys; "
                "mount -t devtmpfs devtmpfs /dev; mkdir -p /mnt/host /mnt/lab /sys/fs/cgroup /sys/kernel/debug; "
                "mount -t debugfs debugfs /sys/kernel/debug; "
                "mount -t cgroup2 none /sys/fs/cgroup; "
                "mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host && "
                "mount -t 9p -o trans=virtio,version=9p2000.L labrepo /mnt/lab && "
                "LAB_SHARED_SCRATCH=/mnt/lab/" + str(relative) + " "
                "python3 /mnt/lab/framework/cli.py --guest run "
                + name
                + "; sync; poweroff -f\n"
            )
            proc.child.stdin.write(script.encode())
            proc.child.stdin.flush()
            end = time.monotonic() + timeout["workload_s"] + timeout["ready_s"] + 90
            while time.monotonic() < end:
                stream_console()
                if result.exists():
                    status = read_json(result)
                    if not status["success"]:
                        raise LabError("guest experiment failed: " + status["error"])
                    return
                if proc.child.poll() is not None:
                    raise LabError("guest stopped without a result")
                time.sleep(0.2)
            raise LabError("guest experiment timed out")
