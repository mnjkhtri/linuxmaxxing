/* SPDX-License-Identifier: GPL-2.0 */
/* Two raw parsers feed one normalized monotonic model; rendering never interprets capture strings. */
(function () {
    "use strict";

    var stamp = Date.now();
    var BPF = "../../shared/_captures/virt-virtio.eBPF.ndjson?v=" + stamp;
    var TRACE = "../../shared/_captures/virt-virtio-Trace.txt?v=" + stamp;
    var M = { meta: null, events: [], phase: "A", landmarks: { kicks: [], begins: [], ends: [] }, notifyMmio: 0, ioeventfdKicks: 0, irqfdSignals: 0 };
    var cursor = 0,
        playTimer = null;

    function $(id) {
        return document.getElementById(id);
    }
    function esc(value) {
        return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
        });
    }
    function missing(value) {
        return value === null || value === undefined;
    }
    function shown(value) {
        if (missing(value)) return "not sampled";
        if (value === true) return "true";
        if (value === false) return "false";
        return String(value);
    }
    function hexNumber(value) {
        if (missing(value)) return null;
        if (typeof value === "number") return value;
        return parseInt(String(value), 16);
    }

    var REGISTER = {
        0x000: "MagicValue",
        0x004: "Version",
        0x008: "DeviceID",
        0x00c: "VendorID",
        0x010: "DeviceFeatures",
        0x014: "DeviceFeaturesSel",
        0x020: "DriverFeatures",
        0x024: "DriverFeaturesSel",
        0x030: "QueueSel",
        0x034: "QueueSizeMax",
        0x038: "QueueSize",
        0x044: "QueueReady",
        0x050: "QueueNotify",
        0x060: "InterruptStatus",
        0x064: "InterruptACK",
        0x070: "Status",
        0x080: "QueueDescLow",
        0x084: "QueueDescHigh",
        0x090: "QueueDriverLow",
        0x094: "QueueDriverHigh",
        0x0a0: "QueueDeviceLow",
        0x0a4: "QueueDeviceHigh",
    };
    var QUEUE_OFFSETS = { 0x030: 1, 0x034: 1, 0x038: 1, 0x044: 1, 0x080: 1, 0x084: 1, 0x090: 1, 0x094: 1, 0x0a0: 1, 0x0a4: 1 };

    /* Normalize structured uprobe records while retaining each canonical NDJSON record for inspection logic. */
    function parseEbpf(text) {
        var out = [];
        text.split(/\r?\n/).forEach(function (raw) {
            if (!raw.trim()) return;
            var record;
            try {
                record = JSON.parse(raw);
            } catch (error) {
                throw Error("invalid NDJSON: " + error.message);
            }
            if (record.kind === "meta") {
                M.meta = record;
                return;
            }
            if (record.kind !== "snapshot") return;
            out.push({
                source: "ebpf",
                name: record.event_info.event_name,
                timeNs: Number(record.time_ns),
                phase: record.event_info.phase,
                info: record.event_info,
                context: record.context || {},
                state: record.state || null,
                raw: raw,
                record: record,
            });
        });
        return out;
    }

    /* Normalize raw tracefs lines into the KVM execution boundaries used by the chronogram. */
    function parseTrace(text) {
        var out = [],
            lineNo = 0;
        text.split(/\r?\n/).forEach(function (raw) {
            lineNo++;
            var match = raw.match(/^\s*(.+?)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+([0-9]+\.[0-9]+):\s+([a-zA-Z0-9_]+):\s+(.+)$/);
            if (!match) return;
            var event = {
                source: "tracefs",
                name: match[6],
                timeNs: Math.round(Number(match[5]) * 1e9),
                phase: null,
                state: null,
                raw: raw.trim(),
                line: lineNo,
                context: { comm: match[1].trim(), pid: Number(match[2]), tid: Number(match[2]), cpu: Number(match[3]) },
                info: { flags: match[4], body: match[7] },
            };
            if (event.name === "kvm_entry") {
                var entry = event.info.body.match(/vcpu\s+(\d+),\s+rip\s+(0x[0-9a-f]+)/i);
                if (entry) {
                    event.info.vcpu = Number(entry[1]);
                    event.info.rip = entry[2];
                }
            } else if (event.name === "kvm_exit") {
                var exit = event.info.body.match(/vcpu\s+(\d+)\s+reason\s+([^\s]+)\s+rip\s+(0x[0-9a-f]+)/i);
                if (exit) {
                    event.info.vcpu = Number(exit[1]);
                    event.info.reason = exit[2];
                    event.info.rip = exit[3];
                }
            } else if (event.name === "kvm_userspace_exit") {
                var handoff = event.info.body.match(/reason\s+(.+?)\s+\(\d+\)$/i);
                if (handoff) event.info.reason = handoff[1];
            } else if (event.name === "kvm_mmio") {
                var mmio = event.info.body.match(/mmio\s+([^\s]+)\s+len\s+(\d+)\s+gpa\s+(0x[0-9a-f]+)\s+val\s+(0x[0-9a-f]+)/i);
                if (mmio) {
                    event.info.operation = mmio[1];
                    event.info.length = Number(mmio[2]);
                    event.info.address = mmio[3];
                    event.info.value = mmio[4];
                    event.info.offset = hexNumber(mmio[3]) - 0x10000000;
                    event.info.register = REGISTER[event.info.offset] || "unknown";
                }
            } else if (event.name === "kvm_set_irq") {
                var irqLine = event.info.body.match(/gsi\s+(\d+)\s+level\s+(\d+)\s+source\s+(\d+)/i);
                if (irqLine) {
                    event.info.gsi = Number(irqLine[1]);
                    event.info.level = Number(irqLine[2]);
                    event.info.irqSource = Number(irqLine[3]);
                }
            } else if (event.name === "kvm_inj_virq") {
                var injected = event.info.body.match(/IRQ\s+(0x[0-9a-f]+)(?:\s+\[reinjected\])?/i);
                if (injected) {
                    event.info.vector = injected[1];
                    event.info.reinjected = /\[reinjected\]/i.test(event.info.body);
                }
            }
            out.push(event);
        });
        return out;
    }

    function previousExitTime(trace, index) {
        for (var i = index - 1; i >= 0; i--) if (trace[i].name === "kvm_exit") return trace[i].timeNs;
        return trace[index].timeNs;
    }

    /* Derive tracefs phases from real queue boundaries because guest marker exits are intentionally absent. */
    function classifyTracePhases(trace, ebpf) {
        var firstB = null,
            firstC = null,
            firstD = null;
        trace.forEach(function (event, index) {
            if (event.name !== "kvm_mmio" || missing(event.info.offset)) return;
            if (firstB === null && QUEUE_OFFSETS[event.info.offset]) firstB = previousExitTime(trace, index);
            if (firstC === null && event.info.offset === 0x050) firstC = previousExitTime(trace, index);
        });
        var kick = ebpf.find(function (event) {
            return event.name === "ioeventfd_kick";
        });
        if (kick) {
            var phaseCEnds = ebpf.filter(function (event) {
                return event.name === "queue_backend_end" && event.phase === "C";
            });
            firstD = kick.timeNs;
            if (phaseCEnds.length > 1)
                for (var index = 1; index < trace.length; index++)
                    if (trace[index].name === "kvm_entry" && trace[index].timeNs >= phaseCEnds[1].timeNs && trace[index].timeNs <= kick.timeNs && trace[index - 1].name === "kvm_exit" && trace[index - 1].info.reason === "EPT_VIOLATION") {
                        firstD = trace[index].timeNs;
                        break;
                    }
        }
        trace.forEach(function (event) {
            event.phase = firstD !== null && event.timeNs >= firstD ? "D" : firstC !== null && event.timeNs >= firstC ? "C" : firstB !== null && event.timeNs >= firstB ? "B" : "A";
        });
    }

    function lane(event) {
        if (event.source === "ebpf" && event.name === "sys_enter_ioctl") return "KVM REQUEST";
        if (event.source === "ebpf" && event.name === "sys_exit_ioctl") return "KVM RETURN";
        if (event.source === "ebpf" && event.name === "vmx_handle_exit_return") return "EXIT DISPOSITION";
        if (event.source === "ebpf" && event.name === "queue_backend_begin") return "BACKEND CALL";
        if (event.source === "ebpf" && event.name === "queue_backend_end") return "BACKEND RETURN";
        if (event.source === "ebpf" && event.name === "ioeventfd_kick") return "IOEVENTFD WAKE";
        if (event.source === "ebpf" && event.name === "irqfd_signal") return "IRQFD SIGNAL";
        if (event.source === "ebpf" && event.name === "virtio_mmio_return") return "VMM MMIO RETURN";
        if (event.source === "ebpf" && /_(kick|signal)_return$/.test(event.name)) return "BACKEND RETURN";
        if (event.source === "ebpf") return "VMM MMIO";
        if (event.name === "kvm_entry") return "KVM ENTRY";
        if (event.name === "kvm_exit") return "VM EXIT";
        if (event.name === "kvm_userspace_exit") return "VMM HANDOFF";
        if (event.name === "kvm_mmio") return "MMIO ACCESS";
        return "KVM";
    }

    function componentPoint(actor) {
        return { vmm: 8.333, kvm: 25, guest: 41.667, irqchip: 58.333, backend: 75, memory: 91.667 }[actor];
    }

    function componentActors(event) {
        var ioctlState = event.state && event.state.ioctl;
        var disposition = event.state && event.state.disposition;
        if (event.name === "sys_enter_ioctl") return { from: "vmm", to: "kvm", label: (ioctlState && ioctlState.request_name) || "ioctl" };
        if (event.name === "sys_exit_ioctl") return { from: "vmm", to: "vmm", label: ((ioctlState && ioctlState.request_name) || "ioctl") + " ret " + (ioctlState && ioctlState.result) };
        if (event.name === "vmx_handle_exit_return") return { from: "kvm", to: "kvm", label: (disposition && disposition.meaning) || "exit handled" };
        if (event.name === "kvm_entry") return { from: "kvm", to: "guest", label: "enter guest" };
        if (event.name === "kvm_exit") return { from: "guest", to: "kvm", label: event.info.reason || "VM exit" };
        if (event.name === "kvm_userspace_exit") return { from: "kvm", to: "vmm", label: (event.info.reason || "KVM handoff").replace(/^KVM_EXIT_/, "") };
        if (event.name === "kvm_mmio") return { from: "kvm", to: "kvm", label: (event.info.register || "MMIO") + " · " + (event.info.operation || "access") };
        if (event.name === "kvm_set_irq" || event.name === "kvm_ioapic_set_irq") return { from: "kvm", to: "irqchip", label: !missing(event.info.gsi) ? "GSI " + event.info.gsi + " = " + event.info.level : "route IRQ" };
        if (event.name === "kvm_apic_accept_irq") return { from: "irqchip", to: "irqchip", label: event.info.vector ? "accept " + event.info.vector : "accept IRQ" };
        if (event.name === "kvm_inj_virq") return { from: "irqchip", to: "guest", label: event.info.vector ? "inject " + event.info.vector : "inject IRQ" };
        if (event.name === "kvm_eoi") return { from: "guest", to: "irqchip", label: "EOI" };
        if (event.name === "kvm_msi_set_irq") return { from: "kvm", to: "irqchip", label: "route MSI" };
        if (event.source === "ebpf" && event.name === "virtio_mmio") {
            var register = event.info.mmio && event.info.mmio.register;
            if (register === "QueueNotify") return { from: "vmm", to: "backend", label: "dispatch QueueNotify" };
            return { from: "vmm", to: "vmm", label: register || "MMIO handler" };
        }
        if (event.source === "ebpf" && event.name === "virtio_mmio_return") return { from: "vmm", to: "vmm", label: "MMIO ret " + event.info.return_value };
        if (event.source === "ebpf" && event.name === "queue_backend_begin") return { from: "backend", to: "memory", label: "read avail ring" };
        if (event.source === "ebpf" && event.name === "queue_backend_end") return { from: "backend", to: "memory", label: "publish used ring" };
        if (event.source === "ebpf" && event.name === "ioeventfd_kick") return { from: "kvm", to: "backend", label: "ioeventfd wake" };
        if (event.source === "ebpf" && event.name === "irqfd_signal") return { from: "backend", to: "kvm", label: "irqfd signal" };
        if (event.source === "ebpf" && (event.name === "ioeventfd_kick_return" || event.name === "irqfd_signal_return")) return { from: "backend", to: "backend", label: event.name.replace(/_return$/, "") + " ret " + event.info.return_value };
        if (event.source === "tracefs") return { from: "kvm", to: "kvm", label: event.title };
        return { from: "vmm", to: "vmm", label: event.title };
    }

    function componentKind(event) {
        if (event.name === "kvm_entry") return "entry";
        if (event.name === "kvm_exit") return "exit";
        if (event.name === "kvm_userspace_exit" || event.name === "virtio_mmio") return "handoff";
        if (/^kvm_(set_irq|ioapic_set_irq|apic_accept_irq|inj_virq|eoi|msi_set_irq)$/.test(event.name) || event.name === "irqfd_signal") return "interrupt";
        if (/^queue_backend_/.test(event.name) || event.name === "ioeventfd_kick") return "queue";
        if (event.name === "sys_enter_ioctl" || event.name === "sys_exit_ioctl" || event.name === "vmx_handle_exit_return") return "run";
        return "handoff";
    }

    function activateComponentActors(event) {
        var relation = componentActors(event);
        document.querySelectorAll("[data-component-actor]").forEach(function (node) {
            node.classList.toggle("active", node.dataset.componentActor === relation.from || node.dataset.componentActor === relation.to);
        });
    }

    function componentFlowMarkup(event) {
        var relation = componentActors(event), kind = componentKind(event), from = componentPoint(relation.from), to = componentPoint(relation.to), dom =
            '<i class="component-life vmm"></i><i class="component-life kvm"></i><i class="component-life guest"></i><i class="component-life irqchip"></i><i class="component-life backend"></i><i class="component-life memory"></i>';
        if (from === to) {
            dom += '<i class="component-local ' + kind + '" style="left:' + from + '%"></i>';
            dom += '<span class="component-arrow-label local" style="left:' + from + '%">' + esc(relation.label) + '</span>';
        } else {
            var left = Math.min(from, to), width = Math.abs(to - from), direction = to > from ? "forward" : "reverse";
            dom += '<i class="component-arrow ' + direction + ' ' + kind + '" style="left:' + left + '%;width:' + width + '%"></i>';
            dom += '<span class="component-arrow-label" style="left:' + ((from + to) / 2) + '%">' + esc(relation.label) + '</span>';

        }
        return dom;
    }

    function title(event) {
        var ioctlState = event.state && event.state.ioctl;
        var disposition = event.state && event.state.disposition;
        if (event.source === "ebpf" && event.name === "sys_enter_ioctl") return (ioctlState && ioctlState.request_name) || "ioctl";
        if (event.source === "ebpf" && event.name === "sys_exit_ioctl") return ((ioctlState && ioctlState.request_name) || "ioctl") + " · return";
        if (event.source === "ebpf" && event.name === "vmx_handle_exit_return") return "vmx_handle_exit · " + ((disposition && disposition.meaning) || "unknown");
        if (event.source === "ebpf" && event.name === "virtio_mmio") return "do_mmio · " + ((event.info.mmio && event.info.mmio.register) || "MMIO");
        if (event.source === "ebpf" && event.name === "virtio_mmio_return") return "do_mmio return · " + ((event.info.mmio && event.info.mmio.register) || "MMIO") + " · " + event.info.return_value;
        if (event.source === "ebpf" && (event.name === "ioeventfd_kick_return" || event.name === "irqfd_signal_return")) return event.name.replace(/_return$/, "") + " · return " + event.info.return_value;
        if (event.source === "ebpf") return event.name;
        if (event.name === "kvm_exit") return "kvm_exit · " + (event.info.reason || "unknown");
        if (event.name === "kvm_userspace_exit") return event.info.reason || event.name;
        if (event.name === "kvm_mmio") return "kvm_mmio · " + (event.info.register || "MMIO") + " · " + (event.info.operation || "access");
        if (event.name === "kvm_set_irq" && !missing(event.info.gsi)) return "kvm_set_irq · GSI " + event.info.gsi + " = " + event.info.level;
        if (event.name === "kvm_inj_virq" && event.info.vector) return "kvm_inj_virq · " + event.info.vector + (event.info.reinjected ? " · reinjected" : "");
        if (/^kvm_(ioapic_set_irq|apic_accept_irq|eoi|msi_set_irq)$/.test(event.name)) return event.name;
        return event.name;
    }

    function tracePhaseAt(trace, timeNs) {
        var phase = "A";
        for (var index = 0; index < trace.length && trace[index].timeNs <= timeNs; index++) phase = trace[index].phase || phase;
        return phase;
    }

    /* Fuse both monotonic sources without inventing events for untrapped guest-memory stores. */
    function buildModel(ebpf, trace) {
        classifyTracePhases(trace, ebpf);
        ebpf.forEach(function (event) {
            var ioctlState = event.state && event.state.ioctl;
            if (event.name === "vmx_handle_exit_return" || (ioctlState && ioctlState.request_name === "KVM_RUN")) event.phase = tracePhaseAt(trace, event.timeNs);
            if (ioctlState && (ioctlState.request_name === "KVM_IOEVENTFD" || ioctlState.request_name === "KVM_IRQFD")) event.phase = "D";
        });
        M.events = ebpf.concat(trace).sort(function (a, b) {
            return a.timeNs - b.timeNs || (a.source === "tracefs" ? -1 : 1);
        });
        var base = M.events.length ? M.events[0].timeNs : 0;
        M.events.forEach(function (event, index) {
            event.index = index;
            event.timeUs = (event.timeNs - base) / 1000;
            event.lane = lane(event);
            event.title = title(event);
        });
        M.events.forEach(function (event, index) {
            if (event.source === "ebpf" && event.name === "virtio_mmio") {
                if (event.info.mmio.register === "QueueNotify") M.notifyMmio++;
            }
            if (event.source === "ebpf" && event.name === "queue_backend_begin") M.landmarks.begins.push(index);
            if (event.source === "ebpf" && event.name === "queue_backend_end") M.landmarks.ends.push(index);
            if (event.source === "ebpf" && event.name === "ioeventfd_kick") {
                M.ioeventfdKicks++;
                M.landmarks.kicks.push(index);
            }
            if (event.source === "ebpf" && event.name === "irqfd_signal") M.irqfdSignals++;
        });
        ["A", "B", "C", "D"].forEach(function (phase) {
            for (var i = 0; i < M.events.length; i++)
                if (M.events[i].phase === phase) {
                    M.landmarks["phase" + phase] = i;
                    break;
                }
        });
    }

    function statusDecode(raw) {
        var value = hexNumber(raw);
        if (value === null || isNaN(value)) return "not sampled";
        if (value === 0) return "reset";
        var bits = [];
        if (value & 1) bits.push("ACKNOWLEDGE");
        if (value & 2) bits.push("DRIVER");
        if (value & 8) bits.push("FEATURES_OK");
        if (value & 4) bits.push("DRIVER_OK");
        return bits.join(" | ") || "0";
    }

    function dlRows(host, rows) {
        host.innerHTML = rows
            .map(function (row) {
                var miss = missing(row[1]);
                return (
                    "<dt>" +
                    esc(row[0]) +
                    '</dt><dd class="' +
                    (miss ? "not-sampled" : "") +
                    '" title="' +
                    esc(shown(row[1])) +
                    '">' +
                    esc(shown(row[1])) +
                    "</dd>"
                );
            })
            .join("");
    }
    function stateGroup(event, name) {
        var group = event && event.state && event.state[name];
        return group && group.present ? group : null;
    }

    function metaNumber(meta, name) {
        var value = meta[name],
            number = hexNumber(value);
        if (missing(value) || Number.isNaN(number)) throw Error("capture meta is missing " + name);
        return number;
    }
    function gpa(value) {
        return "0x" + value.toString(16).padStart(4, "0");
    }
    function byteCount(value) {
        return value >= 1024 && value % 1024 === 0 ? value / 1024 + " KiB" : value + " B";
    }

    /* Context rows show only the region name and GPA range so the full memory map stays compact. */
    function memoryContext(start, end, name, unused) {
        return (
            '<div class="memory-context' +
            (unused ? " unused" : "") +
            '"><b>' +
            esc(name) +
            "</b><code>GPA " +
            gpa(start) +
            "–" +
            gpa(end) +
            "</code></div>"
        );
    }

    function renderMemoryMap(meta) {
        var slot = metaNumber(meta, "guest_memory_slot"),
            memoryStart = metaNumber(meta, "guest_memory_gpa"),
            memorySize = metaNumber(meta, "guest_memory_size"),
            pageSize = metaNumber(meta, "queue_region_size");
        var regions = [
            {
                start: metaNumber(meta, "guest_code_gpa"),
                size: metaNumber(meta, "guest_code_size"),
                kind: "context",
                name: "guest code region",
            },
            {
                start: metaNumber(meta, "guest_stack_bottom"),
                size: metaNumber(meta, "guest_stack_top") - metaNumber(meta, "guest_stack_bottom"),
                kind: "context",
                name: "stack range",
            },
            {
                start: metaNumber(meta, "guest_idt_gpa"),
                size: metaNumber(meta, "guest_idt_size"),
                kind: "context",
                name: "IDT + completion flag",
            },
            {
                start: metaNumber(meta, "descriptor_gpa"),
                size: pageSize,
                kind: "descriptor",
                name: "VIRTQUEUE DESCRIPTOR TABLE",
            },
            {
                start: metaNumber(meta, "avail_gpa"),
                size: pageSize,
                kind: "avail",
                name: "AVAILABLE RING",
            },
            {
                start: metaNumber(meta, "used_gpa"),
                size: pageSize,
                kind: "used",
                name: "USED RING",
            },
            {
                start: metaNumber(meta, "rng_buffer_gpa"),
                size: metaNumber(meta, "rng_buffer_stride") * (metaNumber(meta, "total_request_count") - 1) + metaNumber(meta, "rng_request_length"),
                kind: "buffer",
                name: "RNG BUFFERS",
            },
        ].sort(function (a, b) {
            return a.start - b.start;
        });
        var memoryEnd = memoryStart + memorySize,
            cursor = memoryStart,
            items = [];
        regions.forEach(function (region) {
            if (region.start < cursor || region.start + region.size > memoryEnd) throw Error("capture meta contains an invalid guest-memory region");
            if (region.start > cursor) items.push(memoryContext(cursor, region.start - 1, "UNREPORTED", true));
            if (region.kind === "context") items.push(memoryContext(region.start, region.start + region.size - 1, region.name, false));
            else {
                var fieldId = region.kind === "descriptor" ? "desc-fields" : region.kind + "-fields";
                items.push(
                    '<article class="memory-node ' +
                        region.kind +
                        '" data-node="' +
                        region.kind +
                        '"><header><b>' +
                        esc(region.name) +
                        "</b><code>GPA " +
                        gpa(region.start) +
                        '</code></header><div class="slot-grid" id="' +
                        fieldId +
                        '"></div></article>',
                );
            }
            cursor = region.start + region.size;
        });
        if (cursor < memoryEnd) items.push(memoryContext(cursor, memoryEnd - 1, "UNREPORTED", true));
        $("guest-memory-summary").textContent =
            "slot " + slot + " · " + byteCount(memorySize) + " · GPA " + gpa(memoryStart) + "–" + gpa(memoryEnd - 1) + " · increasing GPA ↓";
        $("queue-summary").textContent = "queue " + meta.queue_index + " · " + meta.queue_size + " entries";
        $("memory-map").innerHTML = items.join("");
    }

    function slotCells(entries, renderEntry) {
        var count = M.meta ? metaNumber(M.meta, "queue_size") : 8;
        return Array.from({ length: count }, function (_, index) {
            return renderEntry(entries && entries[index], index);
        }).join("");
    }

    function emptySlot(index) {
        return '<div class="queue-slot empty"><b>' + index + '</b><span>not sampled</span></div>';
    }

    /* Render only state sampled at the selected boundary, preserving unavailable values as not sampled. */
    function renderQueue(event) {
        var descriptor = stateGroup(event, "descriptor"),
            avail = stateGroup(event, "avail"),
            used = stateGroup(event, "used"),
            queue = stateGroup(event, "queue"),
            preview = stateGroup(event, "buffer_preview"),
            sampled = Boolean(queue && avail && used),
            pending = sampled ? (avail.idx - queue.last_avail_idx) & 0xffff : null,
            previous = previousSample(event),
            previousQueue = stateGroup(previous, "queue"),
            previousAvail = stateGroup(previous, "avail"),
            previousUsed = stateGroup(previous, "used"),
            previousPending = previousQueue && previousAvail ? (previousAvail.idx - previousQueue.last_avail_idx) & 0xffff : null;
        $("queue-avail").textContent = sampled ? avail.idx : "—";
        $("queue-consumed").textContent = sampled ? queue.last_avail_idx : "—";
        $("queue-used").textContent = sampled ? used.idx : "—";
        $("queue-pending").textContent = sampled ? pending : "—";
        $("queue-sample-state").textContent = sampled ? event.name : "not sampled at this boundary";
        document.querySelectorAll("[data-queue-counter]").forEach(function (counter) {
            var changed = false;
            if (sampled && counter.dataset.queueCounter === "avail") changed = Boolean(previousAvail) && avail.idx !== previousAvail.idx;
            if (sampled && counter.dataset.queueCounter === "consumed") changed = Boolean(previousQueue) && queue.last_avail_idx !== previousQueue.last_avail_idx;
            if (sampled && counter.dataset.queueCounter === "used") changed = Boolean(previousUsed) && used.idx !== previousUsed.idx;
            if (sampled && counter.dataset.queueCounter === "pending") changed = previousPending !== null && pending !== previousPending;
            counter.classList.toggle("changed", changed);
        });
        $("desc-fields").innerHTML = slotCells(descriptor && descriptor.entries, function (entry, index) {
            if (!entry) return emptySlot(index);
            var populated = hexNumber(entry.addr) !== 0 || entry.len !== 0 || hexNumber(entry.flags) !== 0;
            return '<div class="queue-slot ' + (populated ? "populated" : "empty") + '"><b>desc ' + index + '</b><code>' + esc(entry.addr) + '</code><span>' + entry.len + " B · " + (entry.device_writable ? "WRITE" : "—") + " · next " + entry.next + "</span></div>";
        });
        $("avail-fields").innerHTML = slotCells(avail && avail.ring, function (descriptorId, index) {
            if (!avail) return emptySlot(index);
            var published = index < avail.idx;
            return '<div class="queue-slot ' + (published ? "published" : "empty") + '"><b>slot ' + index + '</b><code>' + (published ? "descriptor " : "raw ") + descriptorId + '</code><span>' + (published ? "published" : "not published") + "</span></div>";
        });
        $("used-fields").innerHTML = slotCells(used && used.ring, function (entry, index) {
            if (!entry) return emptySlot(index);
            var completed = index < used.idx;
            return '<div class="queue-slot ' + (completed ? "completed" : "empty") + '"><b>slot ' + index + '</b><code>' + (completed ? "descriptor " : "raw id ") + entry.id + '</code><span>' + (completed ? entry.len + " B completed" : "not published") + "</span></div>";
        });
        var bytes =
            preview && Array.isArray(preview.bytes)
                ? preview.bytes
                      .map(function (value) {
                          return value.toString(16).padStart(2, "0");
                      })
                      .join(" ")
                : null;
        $("buffer-fields").innerHTML = slotCells(descriptor && descriptor.entries, function (entry, index) {
            if (!entry) return emptySlot(index);
            var populated = hexNumber(entry.addr) !== 0;
            return '<div class="queue-slot ' + (populated ? "populated" : "empty") + '"><b>buffer ' + index + '</b><code>' + esc(entry.addr) + '</code><span>' + (index === 0 && bytes ? bytes : populated ? entry.len + " B" : "unused") + "</span></div>";
        });
    }

    function eventRows(event) {
        var rows = [
            ["phase", event.phase],
            ["source", event.source],
            ["time", event.timeUs.toFixed(3) + " µs"],
            ["event", event.name],
        ];
        if (event.source === "ebpf" && event.info.mmio.present)
            rows.push(
                ["MMIO address", event.info.mmio.address],
                ["offset", event.info.mmio.offset],
                ["register", event.info.mmio.register],
                ["direction", event.info.mmio.direction],
                ["value", event.info.mmio.value],
            );
        if (event.source === "ebpf" && event.info.ioeventfd && event.info.ioeventfd.present)
            rows.push(
                ["ioeventfd address", event.info.ioeventfd.address],
                ["length", event.info.ioeventfd.length],
                ["datamatch", event.info.ioeventfd.datamatch],
                ["counter", event.info.ioeventfd.count],
            );
        if (event.source === "ebpf" && event.info.irqfd && event.info.irqfd.present) rows.push(["irqfd counter", event.info.irqfd.count], ["GSI", event.info.irqfd.gsi]);
        if (event.source === "ebpf" && event.info.operation_id) rows.push(["operation ID", event.info.operation_id]);
        if (event.source === "ebpf" && event.info.duration_ns) rows.push(["duration", event.info.duration_ns + " ns"]);
        if (event.source === "ebpf" && !missing(event.info.return_value)) rows.push(["return", event.info.return_value]);
        var ioctlState = event.state && event.state.ioctl;
        var disposition = event.state && event.state.disposition;
        if (ioctlState && ioctlState.present) {
            rows.push(["request", ioctlState.request_name], ["fd", ioctlState.fd], ["argument", ioctlState.argument]);
            if (ioctlState.completed) rows.push(["result", ioctlState.result], ["duration", ioctlState.duration_ns + " ns"]);
        }
        if (disposition && disposition.present) rows.push(["disposition", disposition.meaning], ["handler result", disposition.result]);
        if (event.source === "tracefs") {
            if (event.info.reason) rows.push(["reason", event.info.reason]);
            if (event.info.rip) rows.push(["guest RIP", event.info.rip]);
            if (event.info.address) rows.push(["MMIO GPA", event.info.address]);
            if (event.info.offset !== undefined) rows.push(["offset", "0x" + event.info.offset.toString(16)]);
            if (event.info.value) rows.push(["raw value", event.info.value]);
            if (!missing(event.info.gsi)) rows.push(["GSI", event.info.gsi], ["level", event.info.level], ["source", event.info.irqSource]);
            if (event.info.vector) rows.push(["vector", event.info.vector], ["reinjected", event.info.reinjected]);
        }
        return rows;
    }

    /* One field table keeps event metadata, execution context, and sampled state tied to one boundary. */
    function renderInspector(event) {
        $("source-badge").textContent = event.source;
        $("event-kind").textContent = event.lane + " · PHASE " + event.phase;
        $("event-title").textContent = event.title;
        var device = stateGroup(event, "device"),
            queue = stateGroup(event, "queue"),
            descriptor = stateGroup(event, "descriptor"),
            avail = stateGroup(event, "avail"),
            used = stateGroup(event, "used");
        var rows = eventRows(event).concat([
            ["pid", event.context.pid],
            ["cpu", event.context.cpu],
            ["comm", event.context.comm],
            ["status", device ? device.status : null],
            ["status decode", device ? statusDecode(device.status) : null],
            ["interrupt_status", device ? device.interrupt_status : null],
            ["queue ready", queue ? queue.ready : null],
            ["last_avail_idx", queue ? queue.last_avail_idx : null],
            ["descriptor entries", descriptor && Array.isArray(descriptor.entries) ? descriptor.entries.filter(function (entry) { return hexNumber(entry.addr) !== 0; }).length : null],
            ["avail.idx", avail ? avail.idx : null],
            ["used.idx", used ? used.idx : null],
            ["pending", queue && avail ? (avail.idx - queue.last_avail_idx) & 0xffff : null],
        ]);
        dlRows($("observation-fields"), rows);
    }

    /* Card highlights compare structured samples and never predict a later state transition. */
    function previousSample(event) {
        for (var index = event.index - 1; index >= 0; index--) {
            var state = M.events[index].state;
            if (state && ["device", "queue", "descriptor", "avail", "used", "buffer_preview"].some(function (name) { return state[name] && state[name].present; })) return M.events[index];
        }
        return null;
    }
    function sampledGroupChanged(event, previous, name) {
        var current = event.state && event.state[name],
            before = previous && previous.state && previous.state[name];
        return Boolean(previous && current && current.present) && JSON.stringify(current) !== JSON.stringify(before || null);
    }
    function highlightChanges(event) {
        document.querySelectorAll("[data-node]").forEach(function (node) {
            node.classList.remove("hot");
        });
        if (!event.state) return;
        var previous = previousSample(event),
            names = [];
        if (sampledGroupChanged(event, previous, "descriptor")) names.push("descriptor");
        if (sampledGroupChanged(event, previous, "avail")) names.push("avail");
        if (sampledGroupChanged(event, previous, "used")) names.push("used");
        if (sampledGroupChanged(event, previous, "buffer_preview")) names.push("buffer");
        names.forEach(function (name) {
            var node = document.querySelector('[data-node="' + name + '"]');
            if (node) node.classList.add("hot");
        });
    }

    function renderMachine(event) {
        highlightChanges(event);
        activateComponentActors(event);
        $("machine-caption").textContent = event.state
            ? "Highlights show fields changed since the preceding sampled boundary."
            : "Raw chronology boundary; queue fields are not sampled or highlighted.";
    }

    function renderTimeline() {
        var filtered = M.events.filter(function (event) {
            return event.phase === M.phase;
        });
        $("timeline-scope").textContent = "Phase " + M.phase + " · " + filtered.length + " observed messages";
        $("timeline").style.setProperty("--rows", filtered.length);
        $("timeline").innerHTML = filtered
            .map(function (event) {
                var previous = event.index > 0 ? M.events[event.index - 1] : null,
                    delta = previous ? ((event.timeNs - previous.timeNs) / 1000).toFixed(3) : "0.000",
                    lifelines = componentFlowMarkup(event);
                return (
                    '<button class="timeline-row ' +
                    (event.index === cursor ? "active" : "") +
                    '" data-index="' +
                    event.index +
                    '"><span class="life-space">' +
                    lifelines +
                    '</span><span class="component-time">+' +
                    delta +
                    "µs</span></button>"
                );
            })
            .join("");
        $("timeline")
            .querySelectorAll(".timeline-row")
            .forEach(function (row) {
                row.addEventListener("click", function () {
                    select(Number(row.dataset.index), false);
                });
            });
        var active = $("timeline").querySelector(".active");
        if (active) active.scrollIntoView({ block: "nearest" });
    }

    function renderRoadmap() {
        var definitions = { A: "BRING-UP", B: "QUEUE CONFIG", C: "MMIO POLL", D: "EVENTFD + IRQFD" };
        $("roadmap").innerHTML = ["A", "B", "C", "D"]
            .map(function (phase) {
                return (
                    '<button class="phase-zone ' +
                    (phase === M.phase ? "active" : "") +
                    '" data-phase="' +
                    phase +
                    '"><span class="phase-label">PHASE ' +
                    phase +
                    " · " +
                    definitions[phase] +
                    "</span></button>"
                );
            })
            .join("");
        $("roadmap")
            .querySelectorAll(".phase-zone")
            .forEach(function (zone) {
                zone.addEventListener("click", function () {
                    choosePhase(zone.dataset.phase);
                });
            });
    }

    function select(index, changePhase) {
        if (!M.events.length) return;
        cursor = Math.max(0, Math.min(M.events.length - 1, index));
        var event = M.events[cursor];
        if (changePhase !== false) M.phase = event.phase;
        $("selected-time").textContent = "t = " + event.timeUs.toFixed(3) + " µs";
        $("scrub").value = cursor;
        $("counter").textContent = cursor + 1 + " / " + M.events.length;
        renderRoadmap();
        renderQueue(event);
        renderMachine(event);
        renderInspector(event);
        renderTimeline();
    }

    function choosePhase(phase) {
        M.phase = phase;
        var target = phase === "C" ? M.landmarks.begins[0] : phase === "D" ? M.landmarks.kicks[0] : M.landmarks["phase" + phase];
        select(missing(target) ? 0 : target, false);
    }
    function stopPlay() {
        if (!playTimer) return;
        clearInterval(playTimer);
        playTimer = null;
        $("play").textContent = "▶";
        $("play").classList.remove("active");
    }
    function togglePlay() {
        if (playTimer) {
            stopPlay();
            return;
        }
        $("play").textContent = "Ⅱ";
        $("play").classList.add("active");
        playTimer = setInterval(function () {
            if (cursor >= M.events.length - 1) {
                stopPlay();
                return;
            }
            select(cursor + 1, true);
        }, 700);
    }

    function wire() {
        $("prev").addEventListener("click", function () {
            stopPlay();
            select(cursor - 1, true);
        });
        $("next").addEventListener("click", function () {
            stopPlay();
            select(cursor + 1, true);
        });
        $("play").addEventListener("click", togglePlay);
        $("scrub").addEventListener("input", function (event) {
            stopPlay();
            select(Number(event.target.value), true);
        });
        document.addEventListener("keydown", function (event) {
            if (event.key === "ArrowLeft") {
                stopPlay();
                select(cursor - 1, true);
            }
            if (event.key === "ArrowRight") {
                stopPlay();
                select(cursor + 1, true);
            }
            if (event.key === " ") {
                event.preventDefault();
                togglePlay();
            }
        });
    }

    Promise.all([
        fetch(BPF, { cache: "no-store" }).then(function (response) {
            if (!response.ok) throw Error("eBPF HTTP " + response.status);
            return response.text();
        }),
        fetch(TRACE, { cache: "no-store" }).then(function (response) {
            if (!response.ok) throw Error("trace HTTP " + response.status);
            return response.text();
        }),
    ])
        .then(function (parts) {
            var ebpf = parseEbpf(parts[0]),
                trace = parseTrace(parts[1]);
            if (!M.meta || !ebpf.length || !trace.length) throw Error("capture is incomplete");
            renderMemoryMap(M.meta);
            buildModel(ebpf, trace);
            if ([4, 5, 6].indexOf(M.meta.schema_version) < 0 || M.landmarks.begins.length !== 3 || M.landmarks.ends.length !== 3 || M.notifyMmio !== 2 || M.ioeventfdKicks !== 1 || M.irqfdSignals !== 1) throw Error("required Phase-C and Phase-D observations are missing");
            $("scrub").max = M.events.length - 1;
            $("status").lastElementChild.textContent = M.events.length + " boundaries · " + M.notifyMmio + " userspace notify exits · " + M.ioeventfdKicks + " kick · " + M.irqfdSignals + " call";
            wire();
            select(M.landmarks.phaseA, true);
        })
        .catch(function (error) {
            $("status").lastElementChild.textContent = "virtio data error · " + error.message;
        });
})();
