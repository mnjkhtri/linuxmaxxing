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
(function() {
  "use strict";

  var M = {
    meta: null,
    events: [],
    rawTraceCount: 0,
    malformedEbpfCount: 0,
    phase: "A",
    selected: null,
    focusGfn: 0
  };

  var PHASES = {
    A: {
      short: "Boot map",
      focus: 0
    },
    B: {
      short: "Discard refault",
      focus: 7
    },
    C: {
      short: "Slot replace",
      focus: 7
    },
    D: {
      short: "Dirty clear",
      focus: 7
    },
    E: {
      short: "MMIO hole",
      focus: 10
    },
    F: {
      short: "Huge leaf",
      focus: 512
    },
    G: {
      short: "Huge split",
      focus: 512
    },
  };
  var ACTOR_POINT = {
    vmm: 8.333,
    kvmcore: 25,
    guest: 41.667,
    kvmmmu: 58.333,
    ept: 75,
    hostmm: 91.667
  };
  var ACTOR_NAME = {
    vmm: "VMM",
    hostmm: "host MM",
    kvmmmu: "KVM MMU",
    ept: "EPT",
    kvmcore: "KVM core",
    guest: "guest vCPU"
  };
  var CORRELATED = {
    kvm_entry: true,
    kvm_exit: true,
    kvm_userspace_exit: true,
    kvm_unmap_hva_range: true,
    kvm_mmu_spte_requested: true,
    kvm_mmu_set_spte: true,
    kvm_page_fault: true,
    kvm_mmu_split_huge_page: true,
    mark_mmio_spte: true
  };

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

  function present(value) {
    return value !== null && value !== undefined;
  }

  function hex(value) {
    if (!present(value)) return "—";
    if (typeof value === "string") return value.indexOf("0x") === 0 ? value : "0x" + value;
    return "0x" + Number(value).toString(16).toUpperCase();
  }

  function parseHex(value) {
    return parseInt(String(value || "0").replace(/^0x/, ""), 16);
  }

  function ioExit(info) {
    if (!info || info.reason !== "IO_INSTRUCTION" || !info.info1) return null;
    try {
      var qualification = BigInt(info.info1),
        port = Number((qualification >> 16n) & 0xffffn),
        input = Boolean(qualification & 8n);
      return {
        port: port,
        direction: input ? "IN" : "OUT",
        label: (input ? "IN " : "OUT ") + hex(port)
      };
    } catch (_) {
      return null;
    }
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

  function parseEbpf(capture) {
    M.meta = values(capture.events.find(e => e.kind === 'collector_metadata' && e.source.mechanism === 'ebpf')?.data || {});
    return capture.events.filter(e => e.source.mechanism === 'ebpf' && e.data.state).map(e => {
      const r = observation(capture, e);
      return {
        source: 'ebpf',
        name: e.kind,
        canonical: e,
        origin: {
          mechanism: e.source.mechanism,
          hook: e.source.hook || e.kind,
          domain: e.source.domain
        },
        timeNs: r.time_ns,
        record: r,
        context: e.context,
        state: r.state?.present ? r.state : null,
        phase: r.event_info?.phase,
        info: r.event_info,
        raw: JSON.stringify(e),
        traceInfo: null
      };
    });
  }

  function eptFields(event) {
    const raw = event.data.fields;
    const info = traceFields(event);
    // These tracepoints print unprefixed hexadecimal fields, even all-digit ones.
    const address = value => value == null ? undefined : '0x' + String(value).replace(/^0x/, '');
    const boundedHex = value => {
      if (value == null) return undefined;
      const integer = BigInt(address(value));
      if (integer > BigInt(Number.MAX_SAFE_INTEGER)) return address(value);
      return Number(integer);
    };
    if (raw.gfn != null) info.gfn = boundedHex(raw.gfn);
    if (raw.pfn != null) info.pfn = boundedHex(raw.pfn);
    for (const key of ['spte', 'sptep'])
      if (raw[key] != null) info[key] = address(raw[key]);
    if (raw.old_spte != null) info.oldSpte = address(raw.old_spte);
    if (raw.new_spte != null) info.newSpte = address(raw.new_spte);
    if (event.kind === 'kvm_page_fault') info.gfn = Number(BigInt(raw.address) / 4096n);
    if (event.kind === 'kvm_mmu_set_spte') info.table = address(raw.address);
    if (event.kind === 'kvm_tdp_mmu_spte_changed') {
      const next = BigInt(info.newSpte),
        previous = BigInt(info.oldSpte);
      info.action = next === 0n || next === 0x5a0n ? 'invalidate' : previous === 0n ? 'install' : 'update';
    }
    if (raw.access != null) info.access = boundedHex(raw.access);
    if (raw.gen != null) info.generation = boundedHex(raw.gen);
    if (raw.kvm_gen != null) info.kvmGeneration = boundedHex(raw.kvm_gen);
    if (raw.spte_gen != null) info.spteGeneration = boundedHex(raw.spte_gen);
    return info;
  }

  function parseTrace(capture) {
    const events = capture.events.filter(e => e.source.mechanism === 'tracefs').map(e => ({
      source: 'tracefs',
      name: e.kind,
      canonical: e,
      origin: {
        mechanism: e.source.mechanism,
        hook: e.source.hook || e.kind,
        domain: e.source.domain
      },
      timeNs: relativeNs(capture, e),
      line: e.sequence,
      context: e.context,
      info: eptFields(e),
      raw: JSON.stringify(e),
      used: false
    }));
    M.rawTraceCount = events.length;
    return events;
  }

  function commandTimes(ebpf) {
    var begin = {},
      end = {},
      trigger = {},
      reentry = {},
      exits = [];
    ebpf.forEach(function(event) {
      var control = event.record.control;
      if (event.name === "kvm_exit") {
        var decoded = ioExit(event.traceInfo);
        if (decoded && decoded.port === M.meta.control_port) exits.push(event);
      }
      if (!control || !control.present) return;
      if (event.name === "control_begin") begin[control.command] = event.timeNs;
      if (event.name === "control_end") end[control.command] = event.timeNs;
    });
    Object.keys(begin).forEach(function(command) {
      var preceding = exits.filter(function(event) {
        return event.timeNs <= begin[command];
      }).pop();
      trigger[command] = preceding ? preceding.timeNs : begin[command];
      var following = ebpf.find(function(event) {
        return event.name === "kvm_entry" && event.timeNs > end[command];
      });
      if (following) reentry[command] = following.timeNs;
    });
    if (end[3] && M.meta && M.meta.data_gfn != null) {
      var dirtyFault = ebpf.find(function(event) {
        return event.name === "kvm_page_fault" && event.timeNs > end[3] && event.traceInfo && String(event.traceInfo.gfn) === String(M.meta.data_gfn);
      });
      var mmioEntry = dirtyFault && ebpf.find(function(event) {
        return event.name === "kvm_entry" && event.timeNs > dirtyFault.timeNs;
      });
      if (mmioEntry) reentry[3] = mmioEntry.timeNs;
    }
    return {
      begin: begin,
      end: end,
      trigger: trigger,
      reentry: reentry
    };
  }

  function phaseAt(timeNs, times) {
    if (timeNs < times.trigger[1]) return "A";
    if (timeNs < times.trigger[2]) return "B";
    if (timeNs < times.trigger[3]) return "C";
    if (timeNs <= (times.reentry[3] || times.end[3])) return "D";
    if (timeNs < times.trigger[4]) return "E";
    if (timeNs < times.trigger[5]) return "F";
    return "G";
  }

  function correlate(ebpf, trace) {
    ebpf.forEach(function(event) {
      if (!CORRELATED[event.name]) return;
      var best = null,
        distance = Infinity;
      trace.forEach(function(candidate) {
        if (candidate.used || candidate.name !== event.name) return;
        var delta = Math.abs(candidate.timeNs - event.timeNs);
        if (delta < distance) {
          best = candidate;
          distance = delta;
        }
      });
      if (best && distance <= 100000) {
        best.used = true;
        event.traceInfo = best.info;
        event.traceLine = best.line;
      }
    });
  }

  function aggregateTdp(events) {
    var output = [];
    for (var index = 0; index < events.length; index++) {
      var event = events[index];
      if (event.name !== "kvm_tdp_mmu_spte_changed" || !present(event.info.gfn)) {
        output.push(event);
        continue;
      }
      var group = [event],
        previous = event,
        minGfn = event.info.gfn,
        maxGfn = event.info.gfn;
      while (index + 1 < events.length) {
        var next = events[index + 1];
        if (next.name !== event.name || next.phase !== event.phase || next.info.action !== event.info.action || next.info.level !== event.info.level || next.timeNs - previous.timeNs > 100000) break;
        group.push(next);
        previous = next;
        minGfn = Math.min(minGfn, next.info.gfn);
        maxGfn = Math.max(maxGfn, next.info.gfn);
        index++;
      }
      if (group.length === 1) {
        output.push(event);
        continue;
      }
      output.push({
        source: "tracefs",
        name: "tdp_spte_batch",
        canonical: event.canonical,
        origin: {
          mechanism: event.origin.mechanism,
          hook: event.origin.hook + ' · batch',
          domain: event.origin.domain
        },
        timeNs: event.timeNs,
        timeEndNs: previous.timeNs,
        phase: event.phase,
        context: event.context,
        line: event.line,
        info: {
          action: event.info.action,
          level: event.info.level,
          count: group.length,
          minGfn: minGfn,
          maxGfn: maxGfn,
          firstOldSpte: event.info.oldSpte,
          lastNewSpte: previous.info.newSpte
        }
      });
    }
    return output;
  }

  function buildModel(ebpf, trace) {
    correlate(ebpf, trace);
    var times = commandTimes(ebpf);
    ebpf.forEach(function(event) {
      event.phase = phaseAt(event.timeNs, times);
    });
    trace.forEach(function(event) {
      event.phase = phaseAt(event.timeNs, times);
    });
    var suppressReentry = false;
    ebpf = ebpf.filter(function(event) {
      if (event.name === "kvm_exit" && event.traceInfo && event.traceInfo.reason === "EXTERNAL_INTERRUPT") {
        suppressReentry = true;
        return false;
      }
      if (suppressReentry && event.name === "kvm_entry") {
        suppressReentry = false;
        return false;
      }
      return true;
    });
    var captureEnd = ebpf.reduce(function(latest, event) {
      return Math.max(latest, event.timeNs);
    }, 0);
    var traceOnlyNames = {
      kvm_page_fault: true,
      kvm_tdp_mmu_spte_changed: true,
      kvm_mmu_split_huge_page: true,
      mark_mmio_spte: true,
      handle_mmio_page_fault: true,
      check_mmio_spte: true,
      fast_page_fault: true
    };
    var traceOnly = aggregateTdp(trace.filter(function(event) {
      return !event.used && traceOnlyNames[event.name] && event.timeNs <= captureEnd;
    }));
    M.events = ebpf.concat(traceOnly).sort(function(a, b) {
      return a.timeNs - b.timeNs || (a.source === "tracefs" ? -1 : 1);
    });
    var snapshots = [];
    M.events.forEach(function(event, index) {
      event.index = index;
      if (event.state) {
        event.stateOrigin = "eBPF snapshot · seq " + event.record.seq;
        snapshots.push(event);
      }
    });
    M.events.forEach(function(event) {
      if (event.source !== "tracefs" || event.state) return;
      var anchor = event.timeEndNs || event.timeNs,
        following = null,
        preceding = null;
      for (var index = 0; index < snapshots.length; index++) {
        if (snapshots[index].timeNs >= anchor) {
          following = snapshots[index];
          break;
        }
        preceding = snapshots[index];
      }
      var source = following && following.timeNs - anchor <= 500000 ? following : preceding;
      if (source) {
        event.state = source.state;
        event.stateOrigin = (source === following ? "following" : "preceding") + " eBPF snapshot · seq " + source.record.seq;
      }
    });
  }

  function relation(event) {
    var info = event.traceInfo || event.info || {},
      record = event.record || {},
      control = record.control || {},
      memslot = record.memslot || {},
      ioctl = record.ioctl || {},
      madvise = record.madvise || {},
      mmap = record.mmap || {},
      disposition = record.disposition || {};
    if (event.name === "kvm_entry") return {
      from: "kvmcore",
      to: "guest",
      label: "enter guest"
    };
    if (event.name === "kvm_exit") {
      var decoded = ioExit(info);
      return {
        from: "guest",
        to: "kvmcore",
        label: decoded ? decoded.label : info.reason || "VM exit"
      };
    }
    if (event.name === "kvm_userspace_exit") return {
      from: "kvmcore",
      to: "vmm",
      label: (info.reason || "userspace exit").replace(/^KVM_EXIT_/, "")
    };
    if (event.name === "vmx_handle_exit_return") return {
      from: "kvmcore",
      to: "kvmcore",
      label: disposition.meaning || "exit disposition"
    };
    if (event.name === "sys_enter_ioctl") return {
      from: "vmm",
      to: "kvmcore",
      label: ioctl.request_name || "ioctl"
    };
    if (event.name === "sys_exit_ioctl") return {
      from: "kvmcore",
      to: "vmm",
      label: (ioctl.request_name || "ioctl") + " · ret " + ioctl.result
    };
    if (event.name === "sys_enter_madvise") return {
      from: "vmm",
      to: "hostmm",
      label: madvise.advice_name || "madvise"
    };
    if (event.name === "sys_exit_madvise") return {
      from: "hostmm",
      to: "vmm",
      label: (madvise.advice_name || "madvise") + " · ret " + madvise.result
    };
    if (event.name === "sys_enter_mmap") return {
      from: "vmm",
      to: "hostmm",
      label: "mmap · " + formatBytes(parseHex(mmap.length))
    };
    if (event.name === "sys_exit_mmap") return {
      from: "hostmm",
      to: "vmm",
      label: "mmap · HVA " + (mmap.result_hva || "—")
    };
    if (event.name === "kvm_page_fault") return {
      from: "kvmcore",
      to: "kvmmmu",
      label: faultAccess(info) + " fault · " + hex(info.address)
    };
    if (event.name === "kvm_unmap_hva_range") return {
      from: "hostmm",
      to: "kvmmmu",
      label: "invalidate HVA"
    };
    if (event.name === "kvm_flush_remote_tlbs") return {
      from: "kvmmmu",
      to: "kvmcore",
      label: "remote TLB flush"
    };
    if (event.name === "kvm_mmu_spte_requested") return {
      from: "kvmmmu",
      to: "ept",
      label: "request GFN " + hex(info.gfn)
    };
    if (event.name === "kvm_mmu_set_spte") return {
      from: "kvmmmu",
      to: "ept",
      label: "install L" + (info.level || "?") + " leaf"
    };
    if (event.name === "kvm_tdp_mmu_spte_changed") return {
      from: "kvmmmu",
      to: "ept",
      label: info.action + " L" + info.level + " · GFN " + hex(info.gfn)
    };
    if (event.name === "tdp_spte_batch") return {
      from: "kvmmmu",
      to: "ept",
      label: info.action + " L" + info.level + " ×" + info.count
    };
    if (event.name === "mark_mmio_spte") return {
      from: "kvmmmu",
      to: "ept",
      label: "MMIO GFN " + hex(info.gfn)
    };
    if (event.name === "handle_mmio_page_fault") return {
      from: "kvmcore",
      to: "kvmmmu",
      label: "resolve MMIO · GFN " + hex(info.gfn)
    };
    if (event.name === "check_mmio_spte") return {
      from: "kvmmmu",
      to: "ept",
      label: "check MMIO marker"
    };
    if (event.name === "fast_page_fault") return {
      from: "kvmmmu",
      to: "ept",
      label: info.fixed ? "fix SPTE permissions" : info.spurious ? "spurious fault" : "fast fault"
    };
    if (event.name === "kvm_mmu_split_huge_page") return {
      from: "kvmmmu",
      to: "ept",
      label: "split L" + info.level + " leaf"
    };
    if (event.name === "memslot_begin") {
      var memslotAction = memslot.size === "0x0" ? "delete" : parseHex(memslot.flags) & 1 ? "LOG_DIRTY" : "register";
      return {
        from: "vmm",
        to: "vmm",
        label: "prepare " + memslotAction + " slot " + memslot.slot
      };
    }
    if (event.name === "memslot_end") return {
      from: "vmm",
      to: "vmm",
      label: "slot " + memslot.slot + " · ret " + memslot.result
    };
    if (event.name === "control_begin") return {
      from: "vmm",
      to: "vmm",
      label: "cmd " + control.command + " · " + commandName(control.command)
    };
    if (event.name === "control_end") return {
      from: "vmm",
      to: "vmm",
      label: "cmd " + control.command + " · ret " + control.result
    };
    return {
      from: "kvmmmu",
      to: "kvmmmu",
      label: event.name
    };
  }

  function commandName(command) {
    var item = (M.meta.control_commands || []).find(function(entry) {
      return entry.command === command;
    });
    return item ? item.operation : "COMMAND";
  }

  function eventKind(event) {
    if (event.source === "tracefs") return event.name === "tdp_spte_batch" ? "TRACEPOINT BATCH" : "TRACEPOINT";
    if (/^(control|memslot)_/.test(event.name)) return "UPROBE";
    if (/^sys_(enter|exit)_/.test(event.name)) return "SYSCALL TRACEPOINT";
    if (event.name === "kvm_flush_remote_tlbs" || event.name === "vmx_handle_exit_return") return "KPROBE";
    return "eBPF TRACEPOINT";
  }

  function phaseEvents() {
    return M.events.filter(function(event) {
      return event.phase === M.phase;
    });
  }

  function renderRoadmap() {
    $("roadmap").innerHTML = Object.keys(PHASES).map(function(phase) {
      return '<button type="button" class="phase-button selector-option' + (phase === M.phase ? " active" : "") + '" data-phase="' + phase + '"><span class="selector-kicker">PHASE ' + phase + '</span><span class="selector-label">' + esc(PHASES[phase].short) + '</span></button>';
    }).join("");
    $("roadmap").querySelectorAll("[data-phase]").forEach(function(button) {
      button.addEventListener("click", function() {
        selectPhase(button.dataset.phase);
      });
    });
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
    var actors = ["vmm", "kvmcore", "guest", "kvmmmu", "ept", "hostmm"],
      selected = M.selected === null ? null : relation(M.events[M.selected]);
    return '<div class="lifelines">' + actors.map(function(actor, index) {
      var active = selected && (selected.from === actor || selected.to === actor);
      return '<i class="' + (active ? "active" : "") + '" style="left:' + ((index + .5) / actors.length * 100) + '%"></i>';
    }).join("") + '</div>';
  }

  function rowMarkup(event) {
    var link = relation(event),
      from = ACTOR_POINT[link.from],
      to = ACTOR_POINT[link.to],
      local = from === to,
      arrow;
    if (local) arrow = '<i class="local-marker" style="left:' + from + '%"></i><code style="left:' + from + '%" title="local observation">' + esc(link.label) + "</code>";
    else {
      var left = Math.min(from, to),
        width = Math.abs(to - from),
        direction = to > from ? "forward" : "reverse";
      arrow = '<i class="message-arrow ' + direction + " " + flowKind(event) + '" style="left:' + left + "%;width:" + width + '%"></i><code style="left:' + ((from + to) / 2) + '%">' + esc(link.label) + "</code>";
    }
    return '<button class="message-row' + (local ? " local" : "") + (M.selected === event.index ? " current" : "") + '" data-event="' + event.index + '" data-name="' + event.name + '" data-from="' + link.from + '" data-to="' + link.to + '">' + arrow + "</button>";
  }

  function renderTimeline() {
    var events = phaseEvents();
    $("timeline").innerHTML = '<div class="timeline-body" style="--rows:' + Math.max(events.length, 1) + '">' + lifelineMarkup() + events.map(rowMarkup).join("") + "</div>";
    $("timeline").querySelectorAll("[data-event]").forEach(function(row) {
      row.addEventListener("click", function() {
        selectEvent(Number(row.dataset.event));
      });
    });
    $("timeline-scope").textContent = "Phase " + M.phase + " · " + PHASES[M.phase].short + " · initiator → responder";
  }

  function activeActors(event) {
    var link = event ? relation(event) : null;
    document.querySelectorAll("[data-actor]").forEach(function(actor) {
      actor.classList.toggle("active", !!link && (actor.dataset.actor === link.from || actor.dataset.actor === link.to));
    });
  }

  function stateForView() {
    if (M.selected !== null) return M.events[M.selected].state || null;
    var events = phaseEvents();
    for (var index = events.length - 1; index >= 0; index--)
      if (events[index].record && events[index].record.state && events[index].record.state.present) return events[index].record.state;
    return null;
  }

  function stateOrigin() {
    if (M.selected !== null) return M.events[M.selected].stateOrigin || "state not sampled";
    return "phase endpoint eBPF snapshot";
  }

  function gfnRecord(state, gfn) {
    return state && state.gfns ? state.gfns.find(function(record) {
      return Number(record.gfn) === Number(gfn);
    }) : null;
  }

  function entryClass(entry) {
    if (!entry || (!entry.present && !entry.mmio)) return "empty";
    if (entry.mmio) return "mmio";
    if (entry.leaf && entry.level > 1) return "huge";
    if (entry.leaf) return "ram";
    return "table";
  }

  function renderWalk(state) {
    var record = gfnRecord(state, M.focusGfn),
      nodes = [];
    if (!record) {
      $("walk-summary").textContent = "GFN not sampled";
      $("walk").innerHTML = '<article class="walk-node"><small>GPA</small><b>' + hex(M.focusGfn * 4096) + "</b><code>not sampled</code></article>";
      return;
    }
    nodes.push('<article class="walk-node"><small>GPA</small><b>' + esc(record.gpa) + '</b><code>GFN ' + hex(record.gfn) + "</code></article>");
    var names = {
      4: "PML4",
      3: "PDPT",
      2: "PD",
      1: "PT"
    };
    (record.entries || []).forEach(function(entry) {
      var kind = entryClass(entry),
        stateLabel = entry.mmio ? "MMIO" : entry.leaf ? (entry.level > 1 ? "2 MiB leaf" : "4 KiB leaf") : entry.present ? "table" : "empty";
      var permissions = (entry.r ? "R" : "−") + (entry.w ? "W" : "−") + (entry.x ? "X" : "−") + " · " + (entry.a ? "A" : "−") + (entry.d ? "D" : "−");
      nodes.push('<article class="walk-node ' + kind + '"><small>' + names[entry.level] + " · IDX " + entry.index + "</small><b>" + stateLabel + "</b><em>" + permissions + "</em><code>" + esc(entry.spte) + "</code></article>");
    });
    var result = record.ept_mmio ? "MMIO" : record.ept_mapped ? "PFN " + record.leaf_pfn : "UNMAPPED",
      leaf = record.leaf_level ? "leaf L" + record.leaf_level : "no leaf";
    $("walk-summary").textContent = "GVA " + record.gva + " · GPA " + record.gpa;
    nodes.push('<article class="walk-node ' + (record.ept_mmio ? "mmio" : record.leaf_level > 1 ? "huge" : record.ept_mapped ? "ram" : "empty") + '"><small>EPT RESULT</small><b>' + esc(result) + "</b><code>" + esc(leaf) + "</code></article>");
    $("walk").innerHTML = nodes.join("");
  }

  function latestBefore(names) {
    var selected = M.selected === null ? Infinity : M.selected,
      latest = null;
    phaseEvents().forEach(function(event) {
      if (event.index <= selected && names.indexOf(event.name) !== -1) latest = event;
    });
    return latest;
  }

  function lifecycleLabel(event) {
    if (!event) return "—";
    var info = event.traceInfo || event.info || {},
      record = event.record || {};
    if (event.name === "kvm_exit") {
      var decoded = ioExit(info);
      return decoded ? decoded.label : info.reason || "VM exit";
    }
    if (event.name === "kvm_userspace_exit") return (info.reason || "userspace exit").replace(/^KVM_EXIT_/, "");
    if (event.name === "vmx_handle_exit_return") return record.disposition.meaning;
    if (event.name === "sys_enter_ioctl" || event.name === "sys_exit_ioctl") return record.ioctl.request_name + (record.ioctl.completed ? " · ret " + record.ioctl.result : "");
    if (event.name === "kvm_page_fault") return "page fault · " + faultAccess(info) + " GFN " + hex(info.gfn);
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

  function transitionLabel(event) {
    if (!event) return "—";
    var info = event.traceInfo || event.info || {},
      record = event.record || {},
      ioctl = record.ioctl || {},
      control = record.control || {};
    if (event.name === "kvm_entry") return "HOST · KVM → GUEST";
    if (event.name === "kvm_exit") return "GUEST → HOST · KVM";
    if (event.name === "kvm_userspace_exit") return "HOST · KVM → HOST · VMM";
    if (event.name === "sys_enter_ioctl") return "HOST · VMM → HOST · KVM";
    if (event.name === "sys_exit_ioctl") return "HOST · KVM → HOST · VMM";
    if (/^(kvm_page_fault|kvm_mmu_.*|kvm_tdp_.*|tdp_spte_batch|mark_mmio_spte|handle_mmio_page_fault|check_mmio_spte|fast_page_fault)$/.test(event.name)) return "HOST · KVM → HOST · KVM";
    if (/^(control_|memslot_)/.test(event.name)) return "HOST · VMM";
    return "HOST · KVM";
  }

  function renderLifecycle() {
    var groups = {
      transition: ["kvm_entry", "kvm_exit", "kvm_userspace_exit", "sys_enter_ioctl", "sys_exit_ioctl", "control_begin", "control_end", "memslot_begin", "memslot_end", "kvm_page_fault", "kvm_mmu_spte_requested", "kvm_mmu_set_spte", "kvm_tdp_mmu_spte_changed", "tdp_spte_batch", "mark_mmio_spte", "kvm_mmu_split_huge_page", "handle_mmio_page_fault", "check_mmio_spte", "fast_page_fault"],
      reason: ["kvm_entry", "kvm_exit", "kvm_userspace_exit", "sys_enter_ioctl", "sys_exit_ioctl", "control_begin", "control_end", "memslot_begin", "memslot_end", "kvm_page_fault", "kvm_mmu_spte_requested", "kvm_mmu_set_spte", "kvm_tdp_mmu_spte_changed", "tdp_spte_batch", "mark_mmio_spte", "kvm_mmu_split_huge_page", "handle_mmio_page_fault", "check_mmio_spte", "fast_page_fault"]
    };
    Object.keys(groups).forEach(function(key) {
      var event = (key === "transition" || key === "reason") && M.selected !== null && M.events[M.selected] && M.events[M.selected].phase === M.phase ? M.events[M.selected] : latestBefore(groups[key]),
        article = $("life-" + key);
      $("life-" + key + "-value").textContent = key === "transition" ? transitionLabel(event) : lifecycleLabel(event);
      article.classList.toggle("active", !!event && event.index === M.selected);
      article.classList.toggle("vm-exit", key === "transition" && !!event && event.name === "kvm_exit");
    });
  }

  function renderState() {
    var state = stateForView(),
      origin = stateOrigin();
    renderLifecycle();
    $("state-source").textContent = origin;
    if (!state) {
      $("root-address").textContent = "ROOT —";
      $("mapped-count").textContent = "—";
      $("mmio-count").textContent = "—";
      $("focus-gfn").textContent = hex(M.focusGfn);
      $("gfn-map").innerHTML = "";
      renderWalk(null);
      $("state-kind").textContent = "NOT SAMPLED";
      $("state-caption").textContent = "This boundary has no vCPU/EPT snapshot.";
      return;
    }
    var mapped = state.gfns.filter(function(record) {
      return record.ept_mapped;
    }).length;
    var mmio = state.gfns.filter(function(record) {
      return record.ept_mmio;
    }).length;
    $("root-address").textContent = "ROOT " + state.root_hpa;
    $("mapped-count").textContent = mapped + " / " + state.gfns.length;
    $("mmio-count").textContent = mmio;
    $("focus-gfn").textContent = hex(M.focusGfn);
    $("gfn-map").innerHTML = state.gfns.map(function(record) {
      var kind = record.ept_mmio ? "mmio" : record.ept_mapped && record.leaf_level > 1 ? "huge" : record.ept_mapped ? "ram" : "empty";
      return '<button class="gfn-cell ' + kind + (Number(record.gfn) === Number(M.focusGfn) ? " focus" : "") + '" data-gfn="' + record.gfn + '" title="GPA ' + esc(record.gpa) + '">GFN ' + Number(record.gfn).toString(16).toUpperCase() + "</button>";
    }).join("");
    $("gfn-map").querySelectorAll("[data-gfn]").forEach(function(cell) {
      cell.addEventListener("click", function() {
        M.focusGfn = Number(cell.dataset.gfn);
        renderState();
      });
    });
    renderWalk(state);
    $("state-kind").textContent = mapped + " RAM · " + mmio + " MMIO";
    $("state-caption").textContent = state.gfns.length + " bounded GFN walks · root " + state.root_hpa;
  }

  function renderInspector(event) {
    if (!event) {
      $("event-origin").innerHTML = "";
      $("fields").innerHTML = "";
      return;
    }
    renderOrigin("event-origin", event);
    $("fields").innerHTML = rawFieldRows(event).map(function(row) {
      return '<div><small>' + esc(row[0]) + '</small><b title="' + esc(row[1]) + '">' + esc(row[1]) + '</b></div>';
    }).join("");
  }

  function rawFieldRows(event) {
    var data = event.canonical && event.canonical.data || {},
      fields = data.fields || data.event_info || {},
      rows = [];
    function append(value, prefix) {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        Object.keys(value).forEach(function(key) {
          append(value[key], prefix ? prefix + "." + key : key);
        });
      } else rows.push([prefix, Array.isArray(value) ? JSON.stringify(value) : value]);
    }
    Object.keys(fields).forEach(function(key) {
      append(fields[key], key);
    });
    return rows.filter(function(row) {
      return row[1] !== null && row[1] !== undefined && row[1] !== "";
    });
  }

  function taskContext(context) {
    context = context || {};
    var task = context.comm || "—",
      pid = context.pid != null ? "PID " + context.pid : context.tid != null ? "TID " + context.tid : "";
    if (pid) task += " · " + pid;
    return task;
  }

  function renderOrigin(id, event) {
    var origin = event.origin || {},
      rows = [
        ["mechanism", mechanismLabel(origin.mechanism), ""],
        ["hook", hookLabel(event.name, origin.mechanism, origin.hook), ""],
        ["CPU", event.context && event.context.cpu != null ? "CPU " + event.context.cpu : "—", ""],
        ["task", taskContext(event.context), ""]
      ];
    $(id).innerHTML = rows.map(function(row) {
      return '<div class="' + row[2] + '"><small>' + esc(row[0]) + '</small><b title="' + esc(row[1]) + '">' + esc(row[1]) + '</b></div>';
    }).join("");
  }

  function mechanismLabel(value) {
    return value === "ebpf" ? "eBPF" : value || "—";
  }

  function renderToolbar() {
    var events = phaseEvents(),
      local = M.selected === null ? -1 : events.findIndex(function(event) {
        return event.index === M.selected;
      });
    $("scrub").max = Math.max(events.length - 1, 0);
    $("scrub").value = Math.max(local, 0);
    $("counter").textContent = local < 0 ? "— / " + events.length : local + 1 + " / " + events.length;
  }

  function render() {
    var event = M.selected === null ? null : M.events[M.selected];
    renderRoadmap();
    renderTimeline();
    activeActors(event);
    renderState();
    renderInspector(event);
    renderToolbar();
    $("flow-kind").textContent = event ? eventKind(event) : "NO RECORD";
    $("flow-caption").textContent = event ? relation(event).label : "No trace boundary in this phase.";
  }

  function selectPhase(phase) {
    M.phase = phase;
    M.focusGfn = PHASES[phase].focus;
    stopPlay();
    var first = M.events.find(function(event) {
      return event.phase === phase;
    });
    M.selected = first ? first.index : null;
    render();
    $("timeline").scrollTop = 0;
  }

  function selectEvent(index) {
    M.selected = index;
    M.phase = M.events[index].phase;
    var info = M.events[index].traceInfo || M.events[index].info || {};
    if (present(info.gfn) && gfnRecord(M.events[index].state, info.gfn)) M.focusGfn = info.gfn;
    render();
    var current = $("timeline").querySelector(".message-row.current");
    if (current) current.scrollIntoView({
      block: "nearest"
    });
  }

  function move(step) {
    if (!M.events.length) return;
    if (M.selected === null) {
      var first = phaseEvents()[step > 0 ? 0 : phaseEvents().length - 1];
      if (first) selectEvent(first.index);
      return;
    }
    selectEvent((M.selected + step + M.events.length) % M.events.length);
  }
  const transport = playback(() => {
    if (!M || !M.events.length || M.selected >= M.events.length - 1) return false;
    move(1);
  });

  function stopPlay() {
    transport.stop();
  }

  function togglePlay() {
    transport.toggle();
  }

  function bindControls() {
    $("prev").addEventListener("click", function() {
      move(-1);
    });
    $("next").addEventListener("click", function() {
      move(1);
    });
    $("play").addEventListener("click", togglePlay);
    $("scrub").addEventListener("input", function() {
      var events = phaseEvents(),
        event = events[Number(this.value)];
      if (event) selectEvent(event.index);
    });
    document.addEventListener("keydown", function(event) {
      if (event.key === "ArrowRight") move(1);
      if (event.key === "ArrowLeft") move(-1);
    });
  }

  mountView('virt-ept', async capture => {
    var ebpf = parseEbpf(capture),
      trace = parseTrace(capture);
    buildModel(ebpf, trace);
    if (!document.body.dataset.bound) {
      bindControls();
      document.body.dataset.bound = 'true';
    }
    selectPhase("A");
    $("status").lastElementChild.textContent = ebpf.length + " eBPF · " + M.rawTraceCount + " trace · " + Object.keys(PHASES).length + " phases" + (M.malformedEbpfCount ? " · " + M.malformedEbpfCount + " malformed skipped" : "");
  });
})();
