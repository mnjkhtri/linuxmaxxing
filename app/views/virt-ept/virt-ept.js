/* SPDX-License-Identifier: GPL-2.0 */
(function () {
    "use strict";

    var stamp = Date.now();
    var BPF_PATH = "../../shared/_captures/virt-ept.eBPF.ndjson?v=" + stamp;
    var TRACE_PATH = "../../shared/_captures/virt-ept-Trace.txt?v=" + stamp;
    var M = { meta: null, events: [], rawTraceCount: 0, malformedEbpfCount: 0, phase: "A", selected: null, focusGfn: 0 };
    var playTimer = null;

    var PHASES = {
        A: { short: "Boot map", caption: "register RAM · demand-map code and data", focus: 0 },
        B: { short: "Discard refault", caption: "MADV_DONTNEED · invalidate and rebuild GFN 7", focus: 7 },
        C: { short: "Slot replace", caption: "delete slot 0 · register replacement HVA · rebuild", focus: 7 },
        D: { short: "Dirty clear", caption: "enable dirty logging · clear GFN 7 · flush", focus: 7 },
        E: { short: "MMIO hole", caption: "unmapped GPA 0xa001 · install software MMIO SPTE", focus: 10 },
        F: { short: "Huge leaf", caption: "register slot 1 · install a level-2 2 MiB leaf", focus: 512 },
        G: { short: "Huge split", caption: "enable dirty logging · split and protect the huge leaf", focus: 512 },
    };
    var ACTOR_POINT = { vmm: 8.333, kvmcore: 25, guest: 41.667, kvmmmu: 58.333, ept: 75, hostmm: 91.667 };
    var ACTOR_NAME = { vmm: "VMM", hostmm: "host MM", kvmmmu: "KVM MMU", ept: "EPT", kvmcore: "KVM core", guest: "guest vCPU" };
    var CORRELATED = { kvm_entry: true, kvm_exit: true, kvm_userspace_exit: true, kvm_unmap_hva_range: true, kvm_mmu_spte_requested: true, kvm_mmu_set_spte: true, kvm_page_fault: true, kvm_mmu_split_huge_page: true, mark_mmio_spte: true };

    function $(id) { return document.getElementById(id); }
    function esc(value) { return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
    function present(value) { return value !== null && value !== undefined; }
    function hex(value) {
        if (!present(value)) return "—";
        if (typeof value === "string") return value.indexOf("0x") === 0 ? value : "0x" + value;
        return "0x" + Number(value).toString(16);
    }
    function parseHex(value) { return parseInt(String(value || "0").replace(/^0x/, ""), 16); }
    function ioExit(info) {
        if (!info || info.reason !== "IO_INSTRUCTION" || !info.info1) return null;
        try {
            var qualification = BigInt(info.info1), port = Number((qualification >> 16n) & 0xffffn), input = Boolean(qualification & 8n);
            return { port: port, direction: input ? "IN" : "OUT", label: (input ? "IN " : "OUT ") + hex(port) };
        } catch (_) { return null; }
    }
    function faultAccess(info) {
        var code = parseHex(info && info.errorCode);
        if (code & 2) return "write";
        if (code & 4) return "execute";
        return "read";
    }
    function formatBytes(value) {
        var bytes = Number(value || 0);
        if (bytes === 0) return "0 B";
        if (bytes % (1024 * 1024) === 0) return bytes / (1024 * 1024) + " MiB";
        if (bytes % 1024 === 0) return bytes / 1024 + " KiB";
        return bytes + " B";
    }
    function relativeTime(event) { return ((event.timeNs - M.events[0].timeNs) / 1000).toFixed(1) + " µs"; }

    function parseEbpf(text) {
        var events = [];
        text.split(/\r?\n/).forEach(function (raw) {
            if (!raw.trim()) return;
            var record;
            try { record = JSON.parse(raw); }
            catch (_) { M.malformedEbpfCount++; return; }
            if (record.kind === "meta") { M.meta = record; return; }
            if (record.kind !== "snapshot") return;
            events.push({ source: "ebpf", name: record.event_info.event_name, timeNs: Number(record.time_ns), record: record, context: record.context || {}, state: record.state && record.state.present ? record.state : null, traceInfo: null });
        });
        if (!M.meta || M.meta.schema_version !== 4) throw Error("virt-ept schema 4 capture required");
        return events;
    }

    function parseTrace(text) {
        var events = [];
        text.split(/\r?\n/).forEach(function (raw, index) {
            var match = raw.match(/^\s*(.+?)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+([0-9]+\.[0-9]+):\s+([A-Za-z0-9_]+):\s*(.*)$/);
            if (!match) return;
            var event = { source: "tracefs", name: match[6], timeNs: Math.round(Number(match[5]) * 1e9), line: index + 1, context: { comm: match[1].trim(), pid: Number(match[2]), cpu: Number(match[3]), flags: match[4] }, info: { body: match[7] }, raw: raw.trim(), used: false };
            parseTraceBody(event);
            events.push(event);
        });
        M.rawTraceCount = events.length;
        return events;
    }

    function parseTraceBody(event) {
        var body = event.info.body, match;
        if (event.name === "kvm_entry") {
            match = body.match(/vcpu\s+(\d+),\s+rip\s+(0x[0-9a-f]+)/i);
            if (match) { event.info.vcpu = Number(match[1]); event.info.rip = match[2]; }
        } else if (event.name === "kvm_exit") {
            match = body.match(/vcpu\s+(\d+)\s+reason\s+(\S+)\s+rip\s+(0x[0-9a-f]+)\s+info1\s+(0x[0-9a-f]+)\s+info2\s+(0x[0-9a-f]+)/i);
            if (match) { event.info.vcpu = Number(match[1]); event.info.reason = match[2]; event.info.rip = match[3]; event.info.info1 = match[4]; event.info.info2 = match[5]; }
        } else if (event.name === "kvm_userspace_exit") {
            match = body.match(/reason\s+(.+?)\s+\((\d+)\)$/i);
            if (match) { event.info.reason = match[1]; event.info.reasonCode = Number(match[2]); }
        } else if (event.name === "kvm_unmap_hva_range") {
            match = body.match(/range:\s+(0x[0-9a-f]+)\s+--\s+(0x[0-9a-f]+)/i);
            if (match) { event.info.start = match[1]; event.info.end = match[2]; }
        } else if (event.name === "kvm_page_fault") {
            match = body.match(/vcpu\s+(\d+)\s+rip\s+(0x[0-9a-f]+)\s+address\s+(0x[0-9a-f]+)\s+error_code\s+(0x[0-9a-f]+)/i);
            if (match) { event.info.vcpu = Number(match[1]); event.info.rip = match[2]; event.info.address = match[3]; event.info.gfn = Math.floor(parseHex(match[3]) / 4096); event.info.errorCode = match[4]; }
        } else if (event.name === "kvm_mmu_spte_requested") {
            match = body.match(/gfn\s+([0-9a-f]+)\s+pfn\s+([0-9a-f]+)\s+level\s+(\d+)/i);
            if (match) { event.info.gfn = parseHex(match[1]); event.info.pfn = parseHex(match[2]); event.info.level = Number(match[3]); }
        } else if (event.name === "kvm_mmu_set_spte") {
            match = body.match(/gfn\s+([0-9a-f]+)\s+spte\s+([0-9a-f]+)\s+\(([^)]*)\)\s+level\s+(\d+)\s+at\s+([0-9a-f]+)/i);
            if (match) { event.info.gfn = parseHex(match[1]); event.info.spte = hex(match[2]); event.info.permissions = match[3]; event.info.level = Number(match[4]); event.info.table = hex(match[5]); }
        } else if (event.name === "kvm_tdp_mmu_spte_changed") {
            match = body.match(/as id\s+(\d+)\s+gfn\s+([0-9a-f]+)\s+level\s+(\d+)\s+old_spte\s+([0-9a-f]+)\s+new_spte\s+([0-9a-f]+)/i);
            if (match) {
                event.info.asId = Number(match[1]); event.info.gfn = parseHex(match[2]); event.info.level = Number(match[3]); event.info.oldSpte = hex(match[4]); event.info.newSpte = hex(match[5]);
                event.info.action = match[5] === "0" || match[5].toLowerCase() === "5a0" ? "invalidate" : match[4] === "0" ? "install" : "update";
            }
        } else if (event.name === "kvm_mmu_split_huge_page") {
            match = body.match(/gfn\s+([0-9a-f]+)\s+spte\s+([0-9a-f]+)\s+level\s+(\d+)\s+errno\s+(-?\d+)/i);
            if (match) { event.info.gfn = parseHex(match[1]); event.info.spte = hex(match[2]); event.info.level = Number(match[3]); event.info.errno = Number(match[4]); }
        } else if (event.name === "mark_mmio_spte") {
            match = body.match(/sptep:([0-9a-f]+)\s+gfn\s+([0-9a-f]+)\s+access\s+([0-9a-f]+)\s+gen\s+([0-9a-f]+)/i);
            if (match) { event.info.sptep = match[1]; event.info.gfn = parseHex(match[2]); event.info.access = parseHex(match[3]); event.info.generation = parseHex(match[4]); }
        } else if (event.name === "handle_mmio_page_fault") {
            match = body.match(/addr:([0-9a-f]+)\s+gfn\s+([0-9a-f]+)\s+access\s+([0-9a-f]+)/i);
            if (match) { event.info.address = hex(match[1]); event.info.gfn = parseHex(match[2]); event.info.access = parseHex(match[3]); }
        } else if (event.name === "check_mmio_spte") {
            match = body.match(/spte\s+([0-9a-f]+)\s+kvm_gen\s+([0-9a-f]+)\s+spte-gen\s+([0-9a-f]+)\s+valid\s+(\d+)/i);
            if (match) { event.info.spte = hex(match[1]); event.info.kvmGeneration = parseHex(match[2]); event.info.spteGeneration = parseHex(match[3]); event.info.valid = Number(match[4]); }
        } else if (event.name === "fast_page_fault") {
            match = body.match(/vcpu\s+(\d+)\s+gva\s+([0-9a-f]+)\s+error_code\s+(.*?)\s+sptep\s+(\S+)\s+old\s+(0x[0-9a-f]+)\s+new\s+([0-9a-f]+)\s+spurious\s+(\d+)\s+fixed\s+(\d+)/i);
            if (match) { event.info.vcpu = Number(match[1]); event.info.address = hex(match[2]); event.info.errorFlags = match[3]; event.info.sptep = match[4]; event.info.oldSpte = match[5]; event.info.newSpte = hex(match[6]); event.info.spurious = Number(match[7]); event.info.fixed = Number(match[8]); }
        }
    }

    function commandTimes(ebpf) {
        var begin = {}, end = {}, trigger = {}, exits = [];
        ebpf.forEach(function (event) {
            var control = event.record.control;
            if (event.name === "kvm_exit") { var decoded = ioExit(event.traceInfo); if (decoded && decoded.port === M.meta.control_port) exits.push(event); }
            if (!control || !control.present) return;
            if (event.name === "control_begin") begin[control.command] = event.timeNs;
            if (event.name === "control_end") end[control.command] = event.timeNs;
        });
        Object.keys(begin).forEach(function (command) {
            var preceding = exits.filter(function (event) { return event.timeNs <= begin[command]; }).pop();
            trigger[command] = preceding ? preceding.timeNs : begin[command];
        });
        return { begin: begin, end: end, trigger: trigger };
    }

    function phaseAt(timeNs, times) {
        if (timeNs < times.trigger[1]) return "A";
        if (timeNs < times.trigger[2]) return "B";
        if (timeNs < times.trigger[3]) return "C";
        if (timeNs <= times.end[3]) return "D";
        if (timeNs < times.trigger[4]) return "E";
        if (timeNs < times.trigger[5]) return "F";
        return "G";
    }

    function correlate(ebpf, trace) {
        ebpf.forEach(function (event) {
            if (!CORRELATED[event.name]) return;
            var best = null, distance = Infinity;
            trace.forEach(function (candidate) {
                if (candidate.used || candidate.name !== event.name) return;
                var delta = Math.abs(candidate.timeNs - event.timeNs);
                if (delta < distance) { best = candidate; distance = delta; }
            });
            if (best && distance <= 100000) { best.used = true; event.traceInfo = best.info; event.traceLine = best.line; }
        });
    }

    function aggregateTdp(events) {
        var output = [];
        for (var index = 0; index < events.length; index++) {
            var event = events[index];
            if (event.name !== "kvm_tdp_mmu_spte_changed" || !present(event.info.gfn)) { output.push(event); continue; }
            var group = [event], previous = event, minGfn = event.info.gfn, maxGfn = event.info.gfn;
            while (index + 1 < events.length) {
                var next = events[index + 1];
                if (next.name !== event.name || next.phase !== event.phase || next.info.action !== event.info.action || next.info.level !== event.info.level || next.timeNs - previous.timeNs > 100000) break;
                group.push(next); previous = next; minGfn = Math.min(minGfn, next.info.gfn); maxGfn = Math.max(maxGfn, next.info.gfn); index++;
            }
            if (group.length === 1) { output.push(event); continue; }
            output.push({ source: "tracefs", name: "tdp_spte_batch", timeNs: event.timeNs, timeEndNs: previous.timeNs, phase: event.phase, context: event.context, line: event.line, info: { action: event.info.action, level: event.info.level, count: group.length, minGfn: minGfn, maxGfn: maxGfn, firstOldSpte: event.info.oldSpte, lastNewSpte: previous.info.newSpte } });
        }
        return output;
    }

    function buildModel(ebpf, trace) {
        correlate(ebpf, trace);
        var times = commandTimes(ebpf);
        ebpf.forEach(function (event) { event.phase = phaseAt(event.timeNs, times); });
        trace.forEach(function (event) { event.phase = phaseAt(event.timeNs, times); });
        var suppressReentry = false;
        ebpf = ebpf.filter(function (event) {
            if (event.name === "kvm_exit" && event.traceInfo && event.traceInfo.reason === "EXTERNAL_INTERRUPT") { suppressReentry = true; return false; }
            if (suppressReentry && event.name === "kvm_entry") { suppressReentry = false; return false; }
            return true;
        });
        var captureEnd = ebpf.reduce(function (latest, event) { return Math.max(latest, event.timeNs); }, 0);
        var traceOnlyNames = { kvm_page_fault: true, kvm_tdp_mmu_spte_changed: true, kvm_mmu_split_huge_page: true, mark_mmio_spte: true, handle_mmio_page_fault: true, check_mmio_spte: true, fast_page_fault: true };
        var traceOnly = aggregateTdp(trace.filter(function (event) { return !event.used && traceOnlyNames[event.name] && event.timeNs <= captureEnd; }));
        M.events = ebpf.concat(traceOnly).sort(function (a, b) { return a.timeNs - b.timeNs || (a.source === "tracefs" ? -1 : 1); });
        var snapshots = [];
        M.events.forEach(function (event, index) {
            event.index = index;
            if (event.state) { event.stateOrigin = "eBPF snapshot · seq " + event.record.seq; snapshots.push(event); }
        });
        M.events.forEach(function (event) {
            if (event.source !== "tracefs" || event.state) return;
            var anchor = event.timeEndNs || event.timeNs, following = null, preceding = null;
            for (var index = 0; index < snapshots.length; index++) {
                if (snapshots[index].timeNs >= anchor) { following = snapshots[index]; break; }
                preceding = snapshots[index];
            }
            var source = following && following.timeNs - anchor <= 500000 ? following : preceding;
            if (source) { event.state = source.state; event.stateOrigin = (source === following ? "following" : "preceding") + " eBPF snapshot · seq " + source.record.seq; }
        });
    }

    function relation(event) {
        var info = event.traceInfo || event.info || {}, record = event.record || {}, control = record.control || {}, memslot = record.memslot || {}, ioctl = record.ioctl || {}, madvise = record.madvise || {}, mmap = record.mmap || {}, disposition = record.disposition || {};
        if (event.name === "kvm_entry") return { from: "kvmcore", to: "guest", label: "enter guest" };
        if (event.name === "kvm_exit") { var decoded = ioExit(info); return { from: "guest", to: "kvmcore", label: decoded ? decoded.label : info.reason || "VM exit" }; }
        if (event.name === "kvm_userspace_exit") return { from: "kvmcore", to: "vmm", label: (info.reason || "userspace exit").replace(/^KVM_EXIT_/, "") };
        if (event.name === "vmx_handle_exit_return") return { from: "kvmcore", to: "kvmcore", label: disposition.meaning || "exit disposition" };
        if (event.name === "sys_enter_ioctl") return { from: "vmm", to: "kvmcore", label: ioctl.request_name || "ioctl" };
        if (event.name === "sys_exit_ioctl") return { from: "kvmcore", to: "vmm", label: (ioctl.request_name || "ioctl") + " · ret " + ioctl.result };
        if (event.name === "sys_enter_madvise") return { from: "vmm", to: "hostmm", label: madvise.advice_name || "madvise" };
        if (event.name === "sys_exit_madvise") return { from: "hostmm", to: "vmm", label: (madvise.advice_name || "madvise") + " · ret " + madvise.result };
        if (event.name === "sys_enter_mmap") return { from: "vmm", to: "hostmm", label: "mmap · " + formatBytes(parseHex(mmap.length)) };
        if (event.name === "sys_exit_mmap") return { from: "hostmm", to: "vmm", label: "mmap · HVA " + (mmap.result_hva || "—") };
        if (event.name === "kvm_page_fault") return { from: "kvmcore", to: "kvmmmu", label: faultAccess(info) + " fault · " + hex(info.address) };
        if (event.name === "kvm_unmap_hva_range") return { from: "hostmm", to: "kvmmmu", label: "invalidate HVA" };
        if (event.name === "kvm_flush_remote_tlbs") return { from: "kvmmmu", to: "kvmcore", label: "remote TLB flush" };
        if (event.name === "kvm_mmu_spte_requested") return { from: "kvmmmu", to: "ept", label: "request GFN " + hex(info.gfn) };
        if (event.name === "kvm_mmu_set_spte") return { from: "kvmmmu", to: "ept", label: "install L" + (info.level || "?") + " leaf" };
        if (event.name === "kvm_tdp_mmu_spte_changed") return { from: "kvmmmu", to: "ept", label: info.action + " L" + info.level + " · GFN " + hex(info.gfn) };
        if (event.name === "tdp_spte_batch") return { from: "kvmmmu", to: "ept", label: info.action + " L" + info.level + " ×" + info.count };
        if (event.name === "mark_mmio_spte") return { from: "kvmmmu", to: "ept", label: "MMIO GFN " + hex(info.gfn) };
        if (event.name === "handle_mmio_page_fault") return { from: "kvmcore", to: "kvmmmu", label: "resolve MMIO · GFN " + hex(info.gfn) };
        if (event.name === "check_mmio_spte") return { from: "kvmmmu", to: "ept", label: "check MMIO marker" };
        if (event.name === "fast_page_fault") return { from: "kvmmmu", to: "ept", label: info.fixed ? "fix SPTE permissions" : info.spurious ? "spurious fault" : "fast fault" };
        if (event.name === "kvm_mmu_split_huge_page") return { from: "kvmmmu", to: "ept", label: "split L" + info.level + " leaf" };
        if (event.name === "memslot_begin") {
            var memslotAction = memslot.size === "0x0" ? "delete" : parseHex(memslot.flags) & 1 ? "LOG_DIRTY" : "register";
            return { from: "vmm", to: "vmm", label: "prepare " + memslotAction + " slot " + memslot.slot };
        }
        if (event.name === "memslot_end") return { from: "vmm", to: "vmm", label: "slot " + memslot.slot + " · ret " + memslot.result };
        if (event.name === "control_begin") return { from: "vmm", to: "vmm", label: "cmd " + control.command + " · " + commandName(control.command) };
        if (event.name === "control_end") return { from: "vmm", to: "vmm", label: "cmd " + control.command + " · ret " + control.result };
        return { from: "kvmmmu", to: "kvmmmu", label: event.name };
    }

    function commandName(command) {
        var item = (M.meta.control_commands || []).find(function (entry) { return entry.command === command; });
        return item ? item.operation : "COMMAND";
    }

    function eventTitle(event) {
        var info = event.traceInfo || event.info || {}, record = event.record || {};
        if (event.name === "control_begin") return "handle_control_command · " + commandName(record.control.command);
        if (event.name === "control_end") return "handle_control_command · return " + record.control.result;
        if (event.name === "memslot_begin") return "set_memory_region · prepare request";
        if (event.name === "memslot_end") return "set_memory_region · return " + record.memslot.result;
        if (event.name === "sys_enter_ioctl") return (record.ioctl.request_name || "ioctl") + " · request";
        if (event.name === "sys_exit_ioctl") return (record.ioctl.request_name || "ioctl") + " · return " + record.ioctl.result;
        if (event.name === "sys_enter_madvise") return (record.madvise.advice_name || "madvise") + " · request";
        if (event.name === "sys_exit_madvise") return (record.madvise.advice_name || "madvise") + " · return " + record.madvise.result;
        if (event.name === "sys_enter_mmap") return "mmap · request " + formatBytes(parseHex(record.mmap.length));
        if (event.name === "sys_exit_mmap") return "mmap · return " + record.mmap.result_hva;
        if (event.name === "vmx_handle_exit_return") return "vmx_handle_exit · " + (record.disposition.meaning || "disposition");
        if (event.name === "kvm_exit") return "kvm_exit · " + (info.reason || "unknown");
        if (event.name === "kvm_userspace_exit") return info.reason || "kvm_userspace_exit";
        if (event.name === "kvm_page_fault") return "kvm:kvm_page_fault";
        if (event.name === "kvm_mmu_spte_requested") return "kvmmmu:kvm_mmu_spte_requested";
        if (event.name === "kvm_mmu_set_spte") return "kvmmmu:kvm_mmu_set_spte";
        if (event.name === "kvm_tdp_mmu_spte_changed" || event.name === "tdp_spte_batch") return "kvmmmu:kvm_tdp_mmu_spte_changed";
        if (event.name === "mark_mmio_spte") return "kvmmmu:mark_mmio_spte";
        if (event.name === "handle_mmio_page_fault") return "kvmmmu:handle_mmio_page_fault";
        if (event.name === "check_mmio_spte") return "kvmmmu:check_mmio_spte";
        if (event.name === "fast_page_fault") return "kvmmmu:fast_page_fault";
        if (event.name === "kvm_mmu_split_huge_page") return "kvmmmu:kvm_mmu_split_huge_page";
        return event.name;
    }

    function eventKind(event) {
        if (event.source === "tracefs") return event.name === "tdp_spte_batch" ? "TRACEPOINT BATCH" : "TRACEPOINT";
        if (/^(control|memslot)_/.test(event.name)) return "UPROBE";
        if (/^sys_(enter|exit)_/.test(event.name)) return "SYSCALL TRACEPOINT";
        if (event.name === "kvm_flush_remote_tlbs" || event.name === "vmx_handle_exit_return") return "KPROBE";
        return "eBPF TRACEPOINT";
    }

    function phaseEvents() { return M.events.filter(function (event) { return event.phase === M.phase; }); }

    function renderRoadmap() {
        $("roadmap").innerHTML = Object.keys(PHASES).map(function (phase) {
            return '<button class="phase-button' + (phase === M.phase ? " active" : "") + '" data-phase="' + phase + '"><b>Phase ' + phase + "</b><span>" + esc(PHASES[phase].short) + "</span></button>";
        }).join("");
        $("roadmap").querySelectorAll("[data-phase]").forEach(function (button) { button.addEventListener("click", function () { selectPhase(button.dataset.phase); }); });
    }

    function flowKind(event) {
        if (event.name === "kvm_entry") return "entry";
        if (event.name === "kvm_exit") return "exit";
        if (event.name === "kvm_userspace_exit") return "handoff";
        if (/mmap|madvise|unmap_hva/.test(event.name)) return "memory";
        if (/page_fault|spte|mmu|tdp|tlb/.test(event.name)) return "mmu";
        return "control";
    }

    function lifelineMarkup() {
        var actors = ["vmm", "kvmcore", "guest", "kvmmmu", "ept", "hostmm"], selected = M.selected === null ? null : relation(M.events[M.selected]);
        return '<div class="lifelines">' + actors.map(function (actor, index) { var active = selected && (selected.from === actor || selected.to === actor); return '<i class="' + (active ? "active" : "") + '" style="left:' + ((index + .5) / actors.length * 100) + '%"></i>'; }).join("") + '</div>';
    }

    function rowMarkup(event) {
        var link = relation(event), from = ACTOR_POINT[link.from], to = ACTOR_POINT[link.to], local = from === to, arrow;
        if (local) arrow = '<i class="local-marker" style="left:' + from + '%"></i><code style="left:' + from + '%" title="local observation">' + esc(link.label) + "</code>";
        else {
            var left = Math.min(from, to), width = Math.abs(to - from), direction = to > from ? "forward" : "reverse";
            arrow = '<i class="message-arrow ' + direction + " " + flowKind(event) + '" style="left:' + left + "%;width:" + width + '%"></i><code style="left:' + ((from + to) / 2) + '%">' + esc(link.label) + "</code>";
        }
        return '<button class="message-row' + (local ? " local" : "") + (M.selected === event.index ? " current" : "") + '" data-event="' + event.index + '" data-name="' + event.name + '" data-from="' + link.from + '" data-to="' + link.to + '">' + arrow + '<span class="message-time">+' + relativeTime(event) + "</span></button>";
    }

    function renderTimeline() {
        var events = phaseEvents();
        $("timeline").innerHTML = '<div class="timeline-body" style="--rows:' + Math.max(events.length, 1) + '">' + lifelineMarkup() + events.map(rowMarkup).join("") + "</div>";
        $("timeline").querySelectorAll("[data-event]").forEach(function (row) { row.addEventListener("click", function () { selectEvent(Number(row.dataset.event)); }); });
        $("timeline-scope").textContent = "Phase " + M.phase + " · " + PHASES[M.phase].short + " · initiator → responder";
        $("phase-caption").textContent = PHASES[M.phase].caption;
    }

    function activeActors(event) {
        var link = event ? relation(event) : null;
        document.querySelectorAll("[data-actor]").forEach(function (actor) { actor.classList.toggle("active", !!link && (actor.dataset.actor === link.from || actor.dataset.actor === link.to)); });
    }

    function stateForView() {
        if (M.selected !== null) return M.events[M.selected].state || null;
        var events = phaseEvents();
        for (var index = events.length - 1; index >= 0; index--) if (events[index].record && events[index].record.state && events[index].record.state.present) return events[index].record.state;
        return null;
    }

    function stateOrigin() {
        if (M.selected !== null) return M.events[M.selected].stateOrigin || "state not sampled";
        return "phase endpoint eBPF snapshot";
    }

    function gfnRecord(state, gfn) {
        return state && state.gfns ? state.gfns.find(function (record) { return Number(record.gfn) === Number(gfn); }) : null;
    }

    function entryClass(entry) {
        if (!entry || (!entry.present && !entry.mmio)) return "empty";
        if (entry.mmio) return "mmio";
        if (entry.leaf && entry.level > 1) return "huge";
        if (entry.leaf) return "ram";
        return "table";
    }

    function renderWalk(state) {
        var record = gfnRecord(state, M.focusGfn), nodes = [];
        if (!record) {
            $("walk-summary").textContent = "GFN not sampled";
            $("walk").innerHTML = '<article class="walk-node"><small>GPA</small><b>' + hex(M.focusGfn * 4096) + "</b><code>not sampled</code></article>";
            return;
        }
        nodes.push('<article class="walk-node"><small>GPA</small><b>' + esc(record.gpa) + '</b><code>GFN ' + hex(record.gfn) + "</code></article>");
        var names = { 4: "PML4", 3: "PDPT", 2: "PD", 1: "PT" };
        (record.entries || []).forEach(function (entry) {
            var kind = entryClass(entry), stateLabel = entry.mmio ? "MMIO" : entry.leaf ? (entry.level > 1 ? "2 MiB leaf" : "4 KiB leaf") : entry.present ? "table" : "empty";
            var permissions = (entry.r ? "R" : "−") + (entry.w ? "W" : "−") + (entry.x ? "X" : "−") + " · " + (entry.a ? "A" : "−") + (entry.d ? "D" : "−");
            nodes.push('<article class="walk-node ' + kind + '"><small>' + names[entry.level] + " · IDX " + entry.index + "</small><b>" + stateLabel + "</b><em>" + permissions + "</em><code>" + esc(entry.spte) + "</code></article>");
        });
        var result = record.ept_mmio ? "MMIO marker" : record.ept_mapped ? "PFN " + record.leaf_pfn : "not mapped";
        $("walk-summary").textContent = "GVA " + record.gva + " · GPA " + record.gpa;
        nodes.push('<article class="walk-node ' + (record.ept_mmio ? "mmio" : record.leaf_level > 1 ? "huge" : record.ept_mapped ? "ram" : "empty") + '"><small>RESULT</small><b>' + esc(result) + "</b><code>leaf L" + (record.leaf_level || "—") + "</code></article>");
        $("walk").innerHTML = nodes.join("");
    }

    function latestBefore(names) {
        var selected = M.selected === null ? Infinity : M.selected, latest = null;
        phaseEvents().forEach(function (event) { if (event.index <= selected && names.indexOf(event.name) !== -1) latest = event; });
        return latest;
    }

    function lifecycleLabel(event) {
        if (!event) return "—";
        var info = event.traceInfo || event.info || {}, record = event.record || {};
        if (event.name === "kvm_exit") { var decoded = ioExit(info); return decoded ? decoded.label : info.reason || "VM exit"; }
        if (event.name === "kvm_userspace_exit") return (info.reason || "userspace exit").replace(/^KVM_EXIT_/, "");
        if (event.name === "vmx_handle_exit_return") return record.disposition.meaning;
        if (event.name === "sys_enter_ioctl" || event.name === "sys_exit_ioctl") return record.ioctl.request_name + (record.ioctl.completed ? " · ret " + record.ioctl.result : "");
        if (event.name === "kvm_page_fault") return faultAccess(info) + " GFN " + hex(info.gfn);
        if (event.name === "kvm_mmu_spte_requested") return "request GFN " + hex(info.gfn);
        if (event.name === "kvm_mmu_set_spte") return "install L" + info.level + " leaf";
        if (event.name === "mark_mmio_spte") return "MMIO GFN " + hex(info.gfn);
        if (event.name === "handle_mmio_page_fault") return "resolve MMIO " + hex(info.gfn);
        if (event.name === "check_mmio_spte") return "marker " + (info.valid ? "valid" : "stale");
        if (event.name === "fast_page_fault") return info.fixed ? "fix SPTE" : info.spurious ? "spurious fault" : "fast fault";
        if (event.name === "kvm_mmu_split_huge_page") return "split L" + info.level + " leaf";
        if (event.name === "kvm_tdp_mmu_spte_changed" || event.name === "tdp_spte_batch") return info.action + " L" + info.level;
        if (event.name === "kvm_unmap_hva_range") return "invalidate HVA";
        if (event.name === "kvm_flush_remote_tlbs") return "remote TLB flush";
        return relation(event).label;
    }

    function renderLifecycle() {
        var groups = {
            trigger: ["kvm_exit"],
            boundary: ["kvm_userspace_exit", "vmx_handle_exit_return", "sys_enter_ioctl", "sys_exit_ioctl"],
            mmu: ["kvm_page_fault", "kvm_mmu_spte_requested", "kvm_mmu_set_spte", "kvm_tdp_mmu_spte_changed", "tdp_spte_batch", "mark_mmio_spte", "kvm_mmu_split_huge_page", "handle_mmio_page_fault", "check_mmio_spte", "fast_page_fault"],
            coherence: ["kvm_unmap_hva_range", "kvm_flush_remote_tlbs"]
        };
        Object.keys(groups).forEach(function (key) {
            var event = latestBefore(groups[key]), article = $("life-" + key);
            $("life-" + key + "-value").textContent = lifecycleLabel(event);
            article.classList.toggle("active", !!event && event.index === M.selected);
        });
    }

    function renderState() {
        var state = stateForView(), origin = stateOrigin();
        renderLifecycle();
        $("state-source").textContent = origin;
        if (!state) {
            $("root-address").textContent = "ROOT —"; $("mapped-count").textContent = "—"; $("mmio-count").textContent = "—"; $("focus-gfn").textContent = hex(M.focusGfn); $("gfn-map").innerHTML = ""; renderWalk(null); $("state-kind").textContent = "NOT SAMPLED"; $("state-caption").textContent = "This boundary has no vCPU/EPT snapshot."; return;
        }
        var mapped = state.gfns.filter(function (record) { return record.ept_mapped; }).length;
        var mmio = state.gfns.filter(function (record) { return record.ept_mmio; }).length;
        $("root-address").textContent = "ROOT " + state.root_hpa; $("mapped-count").textContent = mapped + " / " + state.gfns.length; $("mmio-count").textContent = mmio; $("focus-gfn").textContent = hex(M.focusGfn);
        $("gfn-map").innerHTML = state.gfns.map(function (record) {
            var kind = record.ept_mmio ? "mmio" : record.ept_mapped && record.leaf_level > 1 ? "huge" : record.ept_mapped ? "ram" : "empty";
            return '<button class="gfn-cell ' + kind + (Number(record.gfn) === Number(M.focusGfn) ? " focus" : "") + '" data-gfn="' + record.gfn + '" title="GPA ' + esc(record.gpa) + '">GFN ' + Number(record.gfn).toString(16) + "</button>";
        }).join("");
        $("gfn-map").querySelectorAll("[data-gfn]").forEach(function (cell) { cell.addEventListener("click", function () { M.focusGfn = Number(cell.dataset.gfn); renderState(); }); });
        renderWalk(state);
        $("state-kind").textContent = mapped + " RAM · " + mmio + " MMIO";
        $("state-caption").textContent = state.gfns.length + " bounded GFN walks · root " + state.root_hpa;
    }

    function fieldRows(event) {
        var info = event.traceInfo || event.info || {}, record = event.record || {}, control = record.control || {}, memslot = record.memslot || {}, ioctl = record.ioctl || {}, madvise = record.madvise || {}, mmap = record.mmap || {}, disposition = record.disposition || {}, rows = [];
        var link = relation(event);
        rows.push(["capture", event.source === "tracefs" ? "tracefs · line " + event.line : "eBPF · seq " + record.seq]);
        rows.push(["initiator", ACTOR_NAME[link.from]]);
        rows.push(["responder", ACTOR_NAME[link.to]]);
        rows.push(["time", relativeTime(event)]);
        if (event.context && event.context.comm) rows.push(["context", event.context.comm + " · PID " + event.context.pid + " · CPU " + event.context.cpu]);
        if (event.name === "control_begin" || event.name === "control_end") {
            rows.push(["command", control.command + " · " + commandName(control.command)]); rows.push(["operation id", control.operation_id]);
            if (event.name === "control_end") { rows.push(["result", control.result]); rows.push(["duration", (Number(control.duration_ns) / 1000).toFixed(1) + " µs"]); }
        } else if (event.name === "memslot_begin" || event.name === "memslot_end") {
            rows.push(["operation", memslot.size === "0x0" ? "delete memory slot" : "register memory slot"]); rows.push(["slot", memslot.slot]); rows.push(["GPA base", memslot.guest_phys_addr]); rows.push(["size", memslot.size + " · " + formatBytes(parseHex(memslot.size))]); rows.push(["userspace HVA", memslot.userspace_addr]); rows.push(["flags", memslot.flags]);
            if (event.name === "memslot_end") { rows.push(["result", memslot.result]); rows.push(["duration", (Number(memslot.duration_ns) / 1000).toFixed(1) + " µs"]); }
        } else if (event.name === "sys_enter_ioctl" || event.name === "sys_exit_ioctl") {
            rows.push(["request", ioctl.request_name]); rows.push(["fd", ioctl.fd]); rows.push(["argument", ioctl.argument]); rows.push(["call id", ioctl.call_id]);
            if (ioctl.completed) { rows.push(["result", ioctl.result]); rows.push(["duration", (Number(ioctl.duration_ns) / 1000).toFixed(1) + " µs"]); }
        } else if (event.name === "sys_enter_madvise" || event.name === "sys_exit_madvise") {
            rows.push(["advice", madvise.advice_name]); rows.push(["HVA start", madvise.start]); rows.push(["length", madvise.length + " · " + formatBytes(parseHex(madvise.length))]); rows.push(["call id", madvise.call_id]);
            if (madvise.completed) { rows.push(["result", madvise.result]); rows.push(["duration", (Number(madvise.duration_ns) / 1000).toFixed(1) + " µs"]); }
        } else if (event.name === "sys_enter_mmap" || event.name === "sys_exit_mmap") {
            rows.push(["length", mmap.length + " · " + formatBytes(parseHex(mmap.length))]); rows.push(["protection", mmap.prot]); rows.push(["flags", mmap.flags]); rows.push(["fd", mmap.fd]); rows.push(["offset", mmap.offset]); rows.push(["call id", mmap.call_id]);
            if (mmap.completed) { rows.push(["result HVA", mmap.result_hva]); rows.push(["duration", (Number(mmap.duration_ns) / 1000).toFixed(1) + " µs"]); }
        } else if (event.name === "vmx_handle_exit_return") { rows.push(["result", disposition.result]); rows.push(["decision", disposition.meaning]);
        } else if (event.name === "kvm_entry") { rows.push(["vCPU", info.vcpu]); rows.push(["guest RIP", info.rip]); }
        else if (event.name === "kvm_exit") { var decoded = ioExit(info); rows.push(["reason", info.reason]); if (decoded) { rows.push(["I/O operation", decoded.direction]); rows.push(["I/O port", hex(decoded.port)]); } rows.push(["vCPU", info.vcpu]); rows.push(["guest RIP", info.rip]); rows.push(["qualification", info.info1]); }
        else if (event.name === "kvm_userspace_exit") { rows.push(["exit reason", info.reason]); if (present(info.reasonCode)) rows.push(["reason code", info.reasonCode]); }
        else if (event.name === "kvm_unmap_hva_range") { rows.push(["HVA start", info.start]); rows.push(["HVA end", info.end]); if (info.start && info.end) rows.push(["range", formatBytes(parseHex(info.end) - parseHex(info.start))]); }
        else if (event.name === "kvm_page_fault") { rows.push(["access", faultAccess(info)]); rows.push(["fault GPA", info.address]); rows.push(["GFN", hex(info.gfn)]); rows.push(["guest RIP", info.rip]); rows.push(["error code", info.errorCode]); }
        else if (event.name === "kvm_mmu_spte_requested") { rows.push(["GFN", hex(info.gfn)]); rows.push(["host PFN", hex(info.pfn)]); rows.push(["leaf level", info.level]); }
        else if (event.name === "kvm_mmu_set_spte") { rows.push(["GFN", hex(info.gfn)]); rows.push(["SPTE", info.spte]); rows.push(["permissions", info.permissions]); rows.push(["leaf level", info.level]); rows.push(["table HPA", info.table]); }
        else if (event.name === "kvm_tdp_mmu_spte_changed") { rows.push(["operation", info.action]); rows.push(["GFN", hex(info.gfn)]); rows.push(["level", info.level]); rows.push(["old SPTE", info.oldSpte]); rows.push(["new SPTE", info.newSpte]); }
        else if (event.name === "tdp_spte_batch") { rows.push(["operation", info.action]); rows.push(["changes", info.count]); rows.push(["GFN span", hex(info.minGfn) + " – " + hex(info.maxGfn)]); rows.push(["level", info.level]); rows.push(["first old SPTE", info.firstOldSpte]); rows.push(["last new SPTE", info.lastNewSpte]); }
        else if (event.name === "mark_mmio_spte") { rows.push(["GFN", hex(info.gfn)]); rows.push(["SPTE pointer token", info.sptep]); rows.push(["access", hex(info.access)]); rows.push(["generation", hex(info.generation)]); }
        else if (event.name === "kvm_mmu_split_huge_page") { rows.push(["GFN", hex(info.gfn)]); rows.push(["source SPTE", info.spte]); rows.push(["source level", info.level]); rows.push(["errno", info.errno]); }
        else if (event.name === "handle_mmio_page_fault") { rows.push(["address", info.address]); rows.push(["GFN", hex(info.gfn)]); rows.push(["access", hex(info.access)]); }
        else if (event.name === "check_mmio_spte") { rows.push(["SPTE", info.spte]); rows.push(["KVM generation", hex(info.kvmGeneration)]); rows.push(["SPTE generation", hex(info.spteGeneration)]); rows.push(["valid", info.valid ? "yes" : "no"]); }
        else if (event.name === "fast_page_fault") { rows.push(["GPA", info.address]); rows.push(["error flags", info.errorFlags]); rows.push(["old SPTE", info.oldSpte]); rows.push(["new SPTE", info.newSpte]); rows.push(["result", info.fixed ? "fixed" : info.spurious ? "spurious" : "unresolved"]); }
        else if (event.name === "kvm_flush_remote_tlbs") { if (event.state) { rows.push(["KVM", event.state.kvm]); rows.push(["MMU", event.state.mmu]); rows.push(["EPT root", event.state.root_hpa]); } }
        if (event.source === "tracefs" && event.stateOrigin) rows.push(["EPT state", event.stateOrigin]);
        return rows;
    }

    function renderInspector(event) {
        if (!event) { $("event-kind").textContent = "NO RECORD"; $("event-title").textContent = "No captured boundary"; $("source-badge").textContent = "—"; $("fields").innerHTML = ""; return; }
        $("event-kind").textContent = eventKind(event); $("event-title").textContent = eventTitle(event); $("source-badge").textContent = event.source === "tracefs" ? "tracefs" : "eBPF";
        $("fields").innerHTML = fieldRows(event).map(function (row) { return "<dt>" + esc(row[0]) + "</dt><dd>" + esc(row[1]) + "</dd>"; }).join("");
    }

    function renderToolbar() {
        var events = phaseEvents(), local = M.selected === null ? -1 : events.findIndex(function (event) { return event.index === M.selected; });
        $("scrub").max = Math.max(events.length - 1, 0); $("scrub").value = Math.max(local, 0); $("counter").textContent = local < 0 ? "— / " + events.length : local + 1 + " / " + events.length;
    }

    function render() {
        var event = M.selected === null ? null : M.events[M.selected];
        renderRoadmap(); renderTimeline(); activeActors(event); renderState(); renderInspector(event); renderToolbar();
        $("selected-time").textContent = event ? "t = +" + relativeTime(event) : "Phase " + M.phase;
        $("flow-kind").textContent = event ? eventKind(event) : "NO RECORD"; $("flow-caption").textContent = event ? relation(event).label : "No captured boundary in this phase.";
    }

    function selectPhase(phase) {
        M.phase = phase; M.focusGfn = PHASES[phase].focus; stopPlay();
        var first = M.events.find(function (event) { return event.phase === phase; });
        M.selected = first ? first.index : null; render(); $("timeline").scrollTop = 0;
    }
    function selectEvent(index) {
        M.selected = index; M.phase = M.events[index].phase;
        var info = M.events[index].traceInfo || M.events[index].info || {};
        if (present(info.gfn) && gfnRecord(M.events[index].state, info.gfn)) M.focusGfn = info.gfn;
        render();
        var current = $("timeline").querySelector(".message-row.current"); if (current) current.scrollIntoView({ block: "nearest" });
    }
    function move(step) {
        if (!M.events.length) return;
        if (M.selected === null) { var first = phaseEvents()[step > 0 ? 0 : phaseEvents().length - 1]; if (first) selectEvent(first.index); return; }
        selectEvent((M.selected + step + M.events.length) % M.events.length);
    }
    function stopPlay() { if (playTimer) clearInterval(playTimer); playTimer = null; if ($("play")) $("play").textContent = "▶"; }
    function togglePlay() { if (playTimer) { stopPlay(); return; } $("play").textContent = "Ⅱ"; playTimer = setInterval(function () { move(1); }, 900); }

    function bindControls() {
        $("prev").addEventListener("click", function () { move(-1); }); $("next").addEventListener("click", function () { move(1); }); $("play").addEventListener("click", togglePlay);
        $("scrub").addEventListener("input", function () { var events = phaseEvents(), event = events[Number(this.value)]; if (event) selectEvent(event.index); });
        document.addEventListener("keydown", function (event) { if (event.key === "ArrowRight") move(1); if (event.key === "ArrowLeft") move(-1); });
    }

    Promise.all([fetch(BPF_PATH).then(function (response) { if (!response.ok) throw Error("eBPF HTTP " + response.status); return response.text(); }), fetch(TRACE_PATH).then(function (response) { if (!response.ok) throw Error("trace HTTP " + response.status); return response.text(); })])
        .then(function (payloads) {
            var ebpf = parseEbpf(payloads[0]), trace = parseTrace(payloads[1]); buildModel(ebpf, trace); bindControls(); selectPhase("A");
            $("status").lastElementChild.textContent = ebpf.length + " eBPF · " + M.rawTraceCount + " trace · " + Object.keys(PHASES).length + " phases" + (M.malformedEbpfCount ? " · " + M.malformedEbpfCount + " malformed skipped" : "");
        })
        .catch(function (error) { $("status").lastElementChild.textContent = "EPT data error · " + error.message; });
})();
