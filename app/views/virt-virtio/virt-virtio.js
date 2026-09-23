import {
  hookLabel,
  playback,
  mountView,
  observation,
  relativeNs,
  values,
  traceFields
} from '../../common.js';
/* SPDX-License-Identifier: GPL-2.0 */
/* Canonical eBPF and trace observations feed one host-monotonic model; rendering never interprets capture strings. */
(function() {
  "use strict";

  var M = {
    meta: null,
    events: [],
    phase: "A",
    landmarks: {
      kicks: [],
      begins: [],
      ends: []
    },
    notifyMmio: 0,
    ioeventfdKicks: 0,
    irqfdSignals: 0
  };
  var cursor = 0;

  function $(id) {
    return document.getElementById(id);
  }

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function(c) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      } [c];
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
  var QUEUE_OFFSETS = {
    0x030: 1,
    0x034: 1,
    0x038: 1,
    0x044: 1,
    0x080: 1,
    0x084: 1,
    0x090: 1,
    0x094: 1,
    0x0a0: 1,
    0x0a4: 1
  };

  /* Normalize structured uprobe records while retaining each canonical NDJSON record for inspection logic. */
  function parseEbpf(capture) {
    M.meta = values(capture.events.find(e => e.kind === 'collector_metadata' && e.source.mechanism === 'ebpf')?.data || {});
    return capture.events.filter(e => e.source.mechanism === 'ebpf' && e.data.state).map(e => {
      const r = observation(capture, e);
      return {
        source: 'ebpf',
        name: e.kind,
        timeNs: r.time_ns,
        record: r,
        context: e.context,
        state: r.state,
        phase: r.event_info?.phase,
        info: r.event_info || {},
        raw: JSON.stringify(e),
        traceInfo: null
      };
    });
  }
  /* Normalize raw tracefs lines into the KVM execution boundaries used by the chronogram. */
  function parseTrace(capture) {
    return capture.events.filter(e => e.source.mechanism === 'tracefs').map(e => {
      const info = traceFields(e);
      if (e.kind === 'kvm_mmio') {
        info.offset = Number(BigInt(info.address)) - 0x10000000;
        info.register = REGISTER[info.offset] || 'unknown'
      }
      return {
        source: 'tracefs',
        name: e.kind,
        timeNs: relativeNs(capture, e),
        phase: null,
        state: null,
        raw: JSON.stringify(e),
        line: e.sequence,
        context: e.context,
        info
      };
    });
  }

  function previousExitTime(trace, index) {
    for (var i = index - 1; i >= 0; i--)
      if (trace[i].name === "kvm_exit") return trace[i].timeNs;
    return trace[index].timeNs;
  }

  /* Derive tracefs phases from real queue boundaries because guest marker exits are intentionally absent. */
  function classifyTracePhases(trace, ebpf) {
    var firstB = null,
      firstC = null,
      firstD = null;
    trace.forEach(function(event, index) {
      if (event.name !== "kvm_mmio" || missing(event.info.offset)) return;
      if (firstB === null && QUEUE_OFFSETS[event.info.offset]) firstB = previousExitTime(trace, index);
      if (firstC === null && event.info.offset === 0x050) firstC = previousExitTime(trace, index);
    });
    var kick = ebpf.find(function(event) {
      return event.name === "ioeventfd_kick";
    });
    var phaseDSetup = ebpf.find(function(event) {
      var ioctl = event.state && event.state.ioctl;
      return event.name === "sys_enter_ioctl" && ioctl && ioctl.request_name === "KVM_IOEVENTFD";
    });
    if (phaseDSetup) firstD = phaseDSetup.timeNs;
    else if (kick) firstD = kick.timeNs;
    trace.forEach(function(event) {
      event.phase = firstD !== null && event.timeNs >= firstD ? "D" : firstC !== null && event.timeNs >= firstC ? "C" : firstB !== null && event.timeNs >= firstB ? "B" : "A";
    });
  }

  function lane(event) {
    if (event.source === "ebpf" && event.name === "sys_enter_ioctl") return "KVM REQUEST";
    if (event.source === "ebpf" && event.name === "sys_exit_ioctl") return "KVM RET";
    if (event.source === "ebpf" && event.name === "queue_backend_begin") return "BACKEND CALL";
    if (event.source === "ebpf" && event.name === "queue_backend_end") return "BACKEND END";
    if (event.source === "ebpf" && event.name === "ioeventfd_kick") return "IOEVENTFD WAKE";
    if (event.source === "ebpf" && event.name === "irqfd_signal") return "IRQFD SIGNAL";
    if (event.source === "ebpf" && event.name === "virtio_mmio_return") return "VMM MMIO RET";
    if (event.source === "ebpf" && /_(kick|signal)_return$/.test(event.name)) return "BACKEND RET";
    if (event.source === "ebpf") return "VMM MMIO";
    if (event.name === "kvm_entry") return "KVM ENTRY";
    if (event.name === "kvm_exit") return "VM EXIT";
    if (event.name === "kvm_userspace_exit") return "VMM HANDOFF";
    if (event.name === "kvm_mmio") return "MMIO ACCESS";
    return "KVM";
  }

  function componentPoint(actor) {
    return {
      vmm: 8.333,
      kvm: 25,
      guest: 41.667,
      irqchip: 58.333,
      backend: 75,
      memory: 91.667
    } [actor];
  }

  function componentActors(event) {
    var ioctlState = event.state && event.state.ioctl;
    if (event.name === "sys_enter_ioctl") return {
      from: "vmm",
      to: "kvm",
      label: (ioctlState && ioctlState.request_name) || "ioctl"
    };
    if (event.name === "sys_exit_ioctl") return {
      from: "kvm",
      to: "vmm",
      label: ((ioctlState && ioctlState.request_name) || "ioctl") + " · ret " + (ioctlState && ioctlState.result)
    };
    if (event.name === "kvm_entry") return {
      from: "kvm",
      to: "guest",
      label: "enter guest"
    };
    if (event.name === "kvm_exit") return {
      from: "guest",
      to: "kvm",
      label: event.info.reason || "VM exit"
    };
    if (event.name === "kvm_userspace_exit") return {
      from: "kvm",
      to: "vmm",
      label: (event.info.reason || "KVM handoff").replace(/^KVM_EXIT_/, "")
    };
    if (event.name === "kvm_mmio") return {
      from: "kvm",
      to: "kvm",
      label: (event.info.register || "MMIO") + " · " + (event.info.operation || "access")
    };
    if (event.name === "kvm_set_irq" || event.name === "kvm_ioapic_set_irq") return {
      from: "kvm",
      to: "irqchip",
      label: !missing(event.info.gsi) ? "GSI " + event.info.gsi + " = " + event.info.level : "route IRQ"
    };
    if (event.name === "kvm_apic_accept_irq") return {
      from: "irqchip",
      to: "irqchip",
      label: event.info.vector ? "accept " + event.info.vector : "accept IRQ"
    };
    if (event.name === "kvm_inj_virq") return {
      from: "irqchip",
      to: "guest",
      label: event.info.vector ? "inject " + event.info.vector : "inject IRQ"
    };
    if (event.name === "kvm_eoi") return {
      from: "guest",
      to: "irqchip",
      label: "EOI"
    };
    if (event.name === "kvm_msi_set_irq") return {
      from: "kvm",
      to: "irqchip",
      label: "route MSI"
    };
    if (event.source === "ebpf" && event.name === "virtio_mmio") {
      var register = event.info.mmio && event.info.mmio.register;
      if (register === "QueueNotify") return {
        from: "vmm",
        to: "backend",
        label: "dispatch QueueNotify"
      };
      return {
        from: "vmm",
        to: "vmm",
        label: register || "MMIO handler"
      };
    }
    if (event.source === "ebpf" && event.name === "virtio_mmio_return") {
      var returnedRegister = event.info.mmio && event.info.mmio.register;
      if (returnedRegister === "QueueNotify") return {
        from: "backend",
        to: "vmm",
        label: "QueueNotify · ret " + event.info.return_value
      };
      return {
        from: "vmm",
        to: "vmm",
        label: "MMIO · ret " + event.info.return_value
      };
    }
    if (event.source === "ebpf" && event.name === "queue_backend_begin") return {
      from: "backend",
      to: "memory",
      label: "read avail ring"
    };
    if (event.source === "ebpf" && event.name === "queue_backend_end") return {
      from: "backend",
      to: "memory",
      label: "publish used ring"
    };
    if (event.source === "ebpf" && event.name === "ioeventfd_kick") return {
      from: "kvm",
      to: "backend",
      label: "ioeventfd wake"
    };
    if (event.source === "ebpf" && event.name === "irqfd_signal") return {
      from: "backend",
      to: "kvm",
      label: "irqfd signal"
    };
    if (event.source === "ebpf" && event.name === "ioeventfd_kick_return") return {
      from: "backend",
      to: "kvm",
      label: "ioeventfd kick · ret " + event.info.return_value
    };
    if (event.source === "ebpf" && event.name === "irqfd_signal_return") return {
      from: "kvm",
      to: "backend",
      label: "irqfd signal · ret " + event.info.return_value
    };
    if (event.source === "tracefs") return {
      from: "kvm",
      to: "kvm",
      label: event.title
    };
    return {
      from: "vmm",
      to: "vmm",
      label: event.title
    };
  }

  function componentKind(event) {
    if (event.name === "kvm_entry") return "entry";
    if (event.name === "kvm_exit") return "exit";
    if (event.name === "kvm_userspace_exit" || event.name === "virtio_mmio") return "handoff";
    if (/^kvm_(set_irq|ioapic_set_irq|apic_accept_irq|inj_virq|eoi|msi_set_irq)$/.test(event.name) || event.name === "irqfd_signal") return "interrupt";
    if (/^queue_backend_/.test(event.name) || event.name === "ioeventfd_kick") return "queue";
    if (event.name === "sys_enter_ioctl" || event.name === "sys_exit_ioctl") return "run";
    return "handoff";
  }

  function activateComponentActors(event) {
    var relation = componentActors(event);
    document.querySelectorAll("[data-component-actor]").forEach(function(node) {
      node.classList.toggle("active", node.dataset.componentActor === relation.from || node.dataset.componentActor === relation.to);
    });
  }

  function componentFlowMarkup(event) {
    var relation = componentActors(event),
      kind = componentKind(event),
      from = componentPoint(relation.from),
      to = componentPoint(relation.to),
      dom = "";
    if (from === to) {
      dom += '<i class="component-local ' + kind + '" style="left:' + from + '%"></i>';
      dom += '<code class="local" style="left:' + from + '%" title="' + esc(event.raw) + '">' + esc(relation.label) + '</code>';
    } else {
      var left = Math.min(from, to),
        width = Math.abs(to - from),
        direction = to > from ? "forward" : "reverse";
      dom += '<i class="component-arrow ' + direction + ' ' + kind + '" style="left:' + left + '%;width:' + width + '%"></i>';
      dom += '<code style="left:' + ((from + to) / 2) + '%" title="' + esc(event.raw) + '">' + esc(relation.label) + '</code>';
    }
    return dom;
  }

  function title(event) {
    var ioctlState = event.state && event.state.ioctl;
    if (event.source === "ebpf" && event.name === "sys_enter_ioctl") return (ioctlState && ioctlState.request_name) || "ioctl";
    if (event.source === "ebpf" && event.name === "sys_exit_ioctl") return ((ioctlState && ioctlState.request_name) || "ioctl") + " · ret";
    if (event.source === "ebpf" && event.name === "virtio_mmio") return "do_mmio · " + ((event.info.mmio && event.info.mmio.register) || "MMIO");
    if (event.source === "ebpf" && event.name === "virtio_mmio_return") return "do_mmio · ret " + ((event.info.mmio && event.info.mmio.register) || "MMIO") + " · " + event.info.return_value;
    if (event.source === "ebpf" && (event.name === "ioeventfd_kick_return" || event.name === "irqfd_signal_return")) return event.name.replace(/_return$/, "") + " · ret " + event.info.return_value;
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
    M.landmarks = {
      kicks: [],
      begins: [],
      ends: []
    };
    M.notifyMmio = 0;
    M.ioeventfdKicks = 0;
    M.irqfdSignals = 0;
    classifyTracePhases(trace, ebpf);
    ebpf.forEach(function(event) {
      var ioctlState = event.state && event.state.ioctl;
      if (ioctlState && ioctlState.request_name === "KVM_RUN") event.phase = tracePhaseAt(trace, event.timeNs);
      if (ioctlState && (ioctlState.request_name === "KVM_IOEVENTFD" || ioctlState.request_name === "KVM_IRQFD")) event.phase = "D";
    });
    M.events = ebpf.concat(trace).sort(function(a, b) {
      return a.timeNs - b.timeNs || (a.source === "tracefs" ? -1 : 1);
    });
    var base = M.events.length ? M.events[0].timeNs : 0;
    M.events.forEach(function(event, index) {
      event.index = index;
      event.timeUs = (event.timeNs - base) / 1000;
      event.lane = lane(event);
      event.title = title(event);
    });
    M.events.forEach(function(event, index) {
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
    ["A", "B", "C", "D"].forEach(function(phase) {
      for (var i = 0; i < M.events.length; i++)
        if (M.events[i].phase === phase) {
          M.landmarks["phase" + phase] = i;
          break;
        }
    });
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
    var regions = [{
      start: metaNumber(meta, "guest_code_gpa"),
      size: metaNumber(meta, "guest_code_size"),
      kind: "context",
      name: "guest code",
    }, {
      start: metaNumber(meta, "guest_stack_bottom"),
      size: metaNumber(meta, "guest_stack_top") - metaNumber(meta, "guest_stack_bottom"),
      kind: "context",
      name: "stack",
    }, {
      start: metaNumber(meta, "guest_idt_gpa"),
      size: metaNumber(meta, "guest_idt_size"),
      kind: "context",
      name: "IDT + flag",
    }, {
      start: metaNumber(meta, "descriptor_gpa"),
      size: pageSize,
      kind: "descriptor",
      name: "DESC TABLE",
    }, {
      start: metaNumber(meta, "avail_gpa"),
      size: pageSize,
      kind: "avail",
      name: "AVAIL RING",
    }, {
      start: metaNumber(meta, "used_gpa"),
      size: pageSize,
      kind: "used",
      name: "USED RING",
    }, {
      start: metaNumber(meta, "rng_buffer_gpa"),
      size: metaNumber(meta, "rng_buffer_stride") * (metaNumber(meta, "total_request_count") - 1) + metaNumber(meta, "rng_request_length"),
      kind: "buffer",
      name: "RNG BUF",
    }, ].sort(function(a, b) {
      return a.start - b.start;
    });
    var memoryEnd = memoryStart + memorySize,
      cursor = memoryStart,
      items = [];
    regions.forEach(function(region) {
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
      "slot " + slot + " · " + byteCount(memorySize) + " · GPA " + gpa(memoryStart) + "–" + gpa(memoryEnd - 1);
    $("queue-summary").textContent = "queue " + meta.queue_index + " · " + meta.queue_size + " entries";
    $("memory-map").innerHTML = items.join("");
  }

  function slotCells(entries, renderEntry) {
    if (!Array.isArray(entries)) return '<div class="queue-slots-empty">not sampled</div>';
    var count = M.meta ? metaNumber(M.meta, "queue_size") : 8;
    return Array.from({
      length: count
    }, function(_, index) {
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
      pending = sampled ? (avail.idx - queue.last_avail_idx) & 0xffff : null;
    $("queue-state-line").innerHTML = sampled ?
      '<span>AVAIL ' + avail.idx + '</span><span>CONSUMED ' + queue.last_avail_idx + '</span><span>USED ' + used.idx + '</span><span>PENDING ' + pending + '</span>' :
      '<span class="queue-unsampled">not sampled</span>';
    $("queue-sample-state").textContent = sampled ? event.name : "not sampled at this boundary";
    $("desc-fields").innerHTML = slotCells(descriptor && descriptor.entries, function(entry, index) {
      if (!entry) return emptySlot(index);
      var populated = hexNumber(entry.addr) !== 0 || entry.len !== 0 || hexNumber(entry.flags) !== 0;
      return '<div class="queue-slot ' + (populated ? "populated" : "empty") + '"><b>desc ' + index + '</b><code>' + esc(entry.addr) + '</code><span>' + entry.len + "B " + (entry.device_writable ? "WR" : "—") + " n" + entry.next + "</span></div>";
    });
    $("avail-fields").innerHTML = slotCells(avail && avail.ring, function(descriptorId, index) {
      if (!avail) return emptySlot(index);
      var published = index < avail.idx;
      return '<div class="queue-slot ' + (published ? "published" : "empty") + '"><b>slot ' + index + '</b><code>' + (published ? "desc " : "raw ") + descriptorId + '</code><span>' + (published ? "pub" : "—") + "</span></div>";
    });
    $("used-fields").innerHTML = slotCells(used && used.ring, function(entry, index) {
      if (!entry) return emptySlot(index);
      var completed = index < used.idx;
      return '<div class="queue-slot ' + (completed ? "completed" : "empty") + '"><b>slot ' + index + '</b><code>' + (completed ? "desc " : "raw ") + entry.id + '</code><span>' + (completed ? entry.len + " B done" : "—") + "</span></div>";
    });
    var bytes =
      preview && Array.isArray(preview.bytes) ?
      preview.bytes
      .map(function(value) {
        return value.toString(16).padStart(2, "0");
      })
      .join(" ") :
      null;
    $("buffer-fields").innerHTML = slotCells(descriptor && descriptor.entries, function(entry, index) {
      if (!entry) return emptySlot(index);
      var populated = hexNumber(entry.addr) !== 0;
      return '<div class="queue-slot ' + (populated ? "populated" : "empty") + '"><b>buf ' + index + '</b><code>' + esc(entry.addr) + '</code><span>' + (index === 0 && bytes ? bytes : populated ? entry.len + " B" : "—") + "</span></div>";
    });
  }

  function eventRows(event) {
    var info = event.info || {},
      rows = [
      ["phase", event.phase],
      ["time", event.timeUs.toFixed(3) + " µs"],
      ["event", event.name],
    ];
    if (event.source === "ebpf" && info.mmio && info.mmio.present)
      rows.push(
        ["MMIO address", info.mmio.address],
        ["offset", info.mmio.offset],
        ["register", info.mmio.register],
        ["direction", info.mmio.direction],
        ["value", info.mmio.value],
      );
    if (event.source === "ebpf" && info.ioeventfd && info.ioeventfd.present)
      rows.push(
        ["ioeventfd address", info.ioeventfd.address],
        ["length", info.ioeventfd.length],
        ["datamatch", info.ioeventfd.datamatch],
        ["counter", info.ioeventfd.count],
      );
    if (event.source === "ebpf" && info.irqfd && info.irqfd.present) rows.push(["irqfd counter", info.irqfd.count], ["GSI", info.irqfd.gsi]);
    if (event.source === "ebpf" && info.operation_id) rows.push(["operation ID", info.operation_id]);
    if (event.source === "ebpf" && info.duration_ns) rows.push(["duration", info.duration_ns + " ns"]);
    if (event.source === "ebpf" && !missing(info.return_value)) rows.push(["ret", info.return_value]);
    var ioctlState = event.state && event.state.ioctl;
    if (ioctlState && ioctlState.present) {
      rows.push(["request", ioctlState.request_name], ["fd", ioctlState.fd], ["argument", ioctlState.argument]);
      if (ioctlState.completed) rows.push(["result", ioctlState.result], ["duration", ioctlState.duration_ns + " ns"]);
    }
    if (event.source === "tracefs") {
      if (info.reason) rows.push(["reason", info.reason]);
      if (info.rip) rows.push(["guest RIP", info.rip]);
      if (info.address) rows.push(["MMIO GPA", info.address]);
      if (info.offset !== undefined) rows.push(["offset", "0x" + info.offset.toString(16)]);
      if (info.value) rows.push(["raw value", info.value]);
      if (!missing(info.gsi)) rows.push(["GSI", info.gsi], ["level", info.level], ["source", info.irqSource]);
      if (info.vector) rows.push(["vector", info.vector], ["reinjected", info.reinjected]);
    }
    return rows;
  }

  function mechanismLabel(value) {
    return value === "ebpf" ? "eBPF" : value || "—";
  }

  function originContext(event) {
    var context = event.context || {},
      task = context.comm || "—",
      tid = context.tid != null ? "TID " + context.tid : context.pid != null ? "PID " + context.pid : "";
    return tid ? task + " · " + tid : task;
  }

  function renderOrigin(event) {
    var canonical = event.record && event.record.canonical,
      source = canonical && canonical.source || {},
      mechanism = source.mechanism || event.source,
      rows = [
        ["mechanism", mechanismLabel(mechanism)],
        ["hook", hookLabel(event.name, mechanism, source.hook)],
        ["CPU", event.context && event.context.cpu != null ? "CPU " + event.context.cpu : "—"],
        ["task", originContext(event)]
      ];
    $("event-origin").innerHTML = rows.map(function(row) {
      return '<div><small>' + esc(row[0]) + '</small><b title="' + esc(row[1]) + '">' + esc(row[1]) + '</b></div>';
    }).join("");
  }

  function rawFieldRows(event) {
    var canonical = event.record && event.record.canonical,
      fields = canonical && canonical.data && canonical.data.fields,
      rows = [];
    function append(value, prefix) {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        Object.keys(value).forEach(function(key) {
          append(value[key], prefix ? prefix + "." + key : key);
        });
      } else if (!missing(value) && value !== "") {
        rows.push([prefix, Array.isArray(value) ? JSON.stringify(value) : value]);
      }
    }
    if (fields && typeof fields === "object") Object.keys(fields).forEach(function(key) {
      append(fields[key], key);
    });
    return rows.length ? rows : eventRows(event);
  }

  /* Keep the inspector identical across the flow views: origin first, raw fields second. */
  function renderInspector(event) {
    renderOrigin(event);
    $("fields").innerHTML = rawFieldRows(event).map(function(row) {
      return '<div><small>' + esc(row[0]) + '</small><b title="' + esc(shown(row[1])) + '">' + esc(shown(row[1])) + '</b></div>';
    }).join("");
  }

  /* Card highlights compare structured samples and never predict a later state transition. */
  function previousSample(event) {
    for (var index = event.index - 1; index >= 0; index--) {
      var state = M.events[index].state;
      if (state && ["device", "queue", "descriptor", "avail", "used", "buffer_preview"].some(function(name) {
          return state[name] && state[name].present;
        })) return M.events[index];
    }
    return null;
  }

  function sampledGroupChanged(event, previous, name) {
    var current = event.state && event.state[name],
      before = previous && previous.state && previous.state[name];
    return Boolean(previous && current && current.present) && JSON.stringify(current) !== JSON.stringify(before || null);
  }

  function highlightChanges(event) {
    document.querySelectorAll("[data-node]").forEach(function(node) {
      node.classList.remove("hot");
    });
    if (!event.state) return;
    var previous = previousSample(event),
      names = [];
    if (sampledGroupChanged(event, previous, "descriptor")) names.push("descriptor");
    if (sampledGroupChanged(event, previous, "avail")) names.push("avail");
    if (sampledGroupChanged(event, previous, "used")) names.push("used");
    if (sampledGroupChanged(event, previous, "buffer_preview")) names.push("buffer");
    names.forEach(function(name) {
      var node = document.querySelector('[data-node="' + name + '"]');
      if (node) node.classList.add("hot");
    });
  }

  function renderMachine(event) {
    highlightChanges(event);
    activateComponentActors(event);
    $("flow-kind").textContent = event.source === "ebpf" ? "eBPF" : "tracefs";
    $("machine-caption").textContent = event.state ?
      "Highlights show fields changed since the preceding sampled boundary." :
      "Raw chronology boundary; queue fields are not sampled or highlighted.";
  }

  function renderTimeline() {
    var filtered = M.events.filter(function(event) {
      return event.phase === M.phase;
    });
    $("timeline-scope").textContent = "Phase " + M.phase;
    var current = M.events[cursor],
      currentRelation = current ? componentActors(current) : null,
      lifelines = '<div class="component-lifelines">' +
      ["vmm", "kvm", "guest", "irqchip", "backend", "memory"].map(function(actor) {
        var active = currentRelation && (currentRelation.from === actor || currentRelation.to === actor);
        return '<i class="' + (active ? "active" : "") + '" style="left:' + componentPoint(actor) + '%"></i>';
      }).join("") +
      '</div>';
    $("timeline").innerHTML = '<div class="component-body" style="--rows:' + Math.max(filtered.length, 1) + '">' + lifelines + filtered.map(function(event) {
      var relation = componentActors(event),
        local = relation.from === relation.to;
      return '<button type="button" class="component-row' + (local ? " local" : "") + (event.index === cursor ? " current" : "") + '" data-index="' + event.index + '">' + componentFlowMarkup(event) + '</button>';
    }).join("") + '</div>';
    $("timeline")
      .querySelectorAll(".component-row")
      .forEach(function(row) {
        row.addEventListener("click", function() {
          select(Number(row.dataset.index), false);
        });
      });
    var active = $("timeline").querySelector(".current");
    if (active) active.scrollIntoView({
      block: "nearest"
    });
  }

  function renderRoadmap() {
    var definitions = {
      A: "BRING-UP",
      B: "QUEUE CONFIG",
      C: "MMIO POLL",
      D: "EVENTFD"
    };
    $("roadmap").innerHTML = ["A", "B", "C", "D"]
      .map(function(phase) {
        return (
          '<button type="button" class="phase-button selector-option ' +
          (phase === M.phase ? "active" : "") +
          '" data-phase="' + phase + '"><span class="selector-kicker">PHASE ' + phase +
          '</span><span class="selector-label">' + definitions[phase] + '</span></button>'
        );
      })
      .join("");
    $("roadmap")
      .querySelectorAll(".phase-button")
      .forEach(function(zone) {
        zone.addEventListener("click", function() {
          choosePhase(zone.dataset.phase);
        });
      });
  }

  function select(index, changePhase) {
    if (!M.events.length) return;
    cursor = Math.max(0, Math.min(M.events.length - 1, index));
    var event = M.events[cursor];
    if (changePhase !== false) M.phase = event.phase;
    var scoped = M.events.filter(function(item) {
        return item.phase === M.phase;
      }),
      local = scoped.findIndex(function(item) {
        return item.index === cursor;
      }),
      first = scoped.length ? scoped[0].index : 0,
      last = scoped.length ? scoped[scoped.length - 1].index : M.events.length - 1;
    $("scrub").min = first;
    $("scrub").max = last;
    $("scrub").value = cursor;
    $("counter").textContent = (local + 1) + " / " + scoped.length;
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
  const transport = playback(() => {
    if (!M || !M.events.length || cursor >= M.events.length - 1) return false;
    select(cursor + 1, true);
  });

  function stopPlay() {
    transport.stop();
  }

  function togglePlay() {
    transport.toggle();
  }

  function wire() {
    $("prev").addEventListener("click", function() {
      stopPlay();
      select(cursor - 1, true);
    });
    $("next").addEventListener("click", function() {
      stopPlay();
      select(cursor + 1, true);
    });
    $("play").addEventListener("click", togglePlay);
    $("scrub").addEventListener("input", function(event) {
      stopPlay();
      select(Number(event.target.value), true);
    });
    document.addEventListener("keydown", function(event) {
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

  mountView('virt-virtio', async capture => {
    var ebpf = parseEbpf(capture),
      trace = parseTrace(capture);
    if (!M.meta || !ebpf.length || !trace.length) throw Error("capture is incomplete");
    renderMemoryMap(M.meta);
    buildModel(ebpf, trace);
    if (M.landmarks.begins.length !== 3 || M.landmarks.ends.length !== 3 || M.notifyMmio !== 2 || M.ioeventfdKicks !== 1 || M.irqfdSignals !== 1) throw Error("required Phase-C and Phase-D observations are missing");
    $("scrub").max = M.events.length - 1;
    $("status").lastElementChild.textContent = M.events.length + " boundaries · " + M.notifyMmio + " userspace notify exits · " + M.ioeventfdKicks + " kick · " + M.irqfdSignals + " call";
    if (!document.body.dataset.bound) {
      wire();
      document.body.dataset.bound = 'true';
    }
    select(M.landmarks.phaseA, true);
  });
})();
