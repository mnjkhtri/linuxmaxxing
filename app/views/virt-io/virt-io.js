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
/*
 * KVM virt-I/O state observer.
 *
 * Joins canonical host eBPF snapshots and tracefs fields from events.ndjson.
 * Episodes are inferred groupings, not additional observed events.
 */
(function() {
  'use strict';



  var D = {},
    cursor = 0;

  function $(id) {
    return document.getElementById(id)
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      } [c]
    })
  }

  function ev() {
    return D.events[cursor]
  }

  /* ---- capture parsing ------------------------------------------------ */

  /* Parse the canonical eBPF NDJSON into snapshots ordered by sequence number. */
  function parseBpf(capture) {
    var out = [];
    D.meta = values(capture.events.find(e => e.kind === 'collector_metadata' && e.source.mechanism === 'ebpf')?.data || {});
    capture.events.filter(e => e.source.mechanism === 'ebpf' && e.data.state).forEach(function(event) {
      var r = observation(capture, event);
      var ei = r.event_info || {},
        st = r.state || {},
        ct = st.controller || {},
        d = st.dma || {},
        ms = st.msi || {},
        io = st.ioctl || {},
        mm = st.mmio || {},
        cmd = st.command || {};
      out.push({
        bpf_seq: Number(r.seq),
        canonical: event,
        origin: {
          mechanism: event.source.mechanism,
          hook: event.source.hook || event.kind,
          domain: event.source.domain
        },
        time_ns: Number(r.time_ns),
        name: ei.event_name,
        event: ei.event,
        vmexit_id: Number(ei.vmexit_id || 0),
        operation_id: Number(ei.operation_id || 0),
        call_id: Number(ei.call_id || 0),
        ctx: r.context || {},
        vcpu: st.vcpu,
        kvm: st.kvm,
        apic: st.apic,
        ioapic: st.ioapic,
        rte: ct.rte,
        tpr: ct.tpr,
        svr: ct.svr,
        irr: ct.irr,
        isr: ct.isr,
        msi_present: ms.present,
        msi_addr: ms.address,
        msi_data: ms.data,
        msi_vector: ms.vector,
        msi_dest: ms.destination,
        msi_logical: ms.logical,
        msi_level: ms.level_triggered,
        msi_delivery: ms.delivery_mode,
        dpresent: d.present,
        dcompleted: d.completed,
        dgpa: d.gpa,
        dhva: d.guest_hva,
        ddir: d.dir,
        dlen: d.len,
        dresult: d.result,
        dchecksum: d.checksum,
        dduration: d.duration_ns,
        ioctl_present: io.present,
        ioctl_completed: io.completed,
        ioctl_fd: io.fd,
        ioctl_request: io.request,
        ioctl_name: io.request_name,
        ioctl_arg: io.argument,
        ioctl_result: io.result,
        ioctl_duration: io.duration_ns,
        mmio_present: mm.present,
        mmio_offset: mm.offset,
        mmio_register: mm.register,
        mmio_value: mm.value,
        command_present: cmd.present,
        command_completed: cmd.completed,
        command: cmd.command,
        command_name: cmd.command_name,
        command_status: cmd.status,
        command_dma_gpa: cmd.dma_gpa,
        command_result: cmd.result,
        command_duration: cmd.duration_ns
      });
    });
    return out.sort(function(a, b) {
      return a.bpf_seq - b.bpf_seq
    });
  }

  /* Parse tracefs independently; the render model correlates matching observations by monotonic time. */
  function parseTrace(capture) {
    return capture.events.filter(e => e.source.mechanism === 'tracefs').map(e => {
      const f = traceFields(e),
        t = relativeNs(capture, e);
      return {
        ...f,
        ...e.context,
        line: e.sequence,
        canonical: e,
        origin: {
          mechanism: e.source.mechanism,
          hook: e.source.hook || e.kind,
          domain: e.source.domain
        },
        time: t / 1e9,
        time_ns: t,
        type: e.kind,
        body: f.body,
        raw: JSON.stringify(e),
        userspace_reason: f.reason,
        fault_gpa: f.address,
        fault_error: f.error_code,
        mmio_type: f.direction,
        mmio_len: f.length,
        mmio_gpa: f.gpa,
        mmio_val: f.value,
        pio_dir: f.direction?.replace('pio_', ''),
        pio_port: f.port,
        pio_size: f.size,
        pio_count: f.count,
        pio_val: f.value,
        irq_source: f.source,
        vec: f.vector == null ? f.vec : Number(BigInt(f.vector)),
        mode: [],
        flags: ''
      };
    });
  }
  /* ---- event model ------------------------------------------------------ */

  var KINDS = {
    kvm_entry: 'entry',
    kvm_exit: 'exit',
    kvm_userspace_exit: 'handoff',
    kvm_apic_accept_irq: 'irq',
    kvm_ioapic_set_irq: 'irq',
    kvm_msi_set_irq: 'msi',
    kvm_set_irq: 'irq',
    kvm_ack_irq: 'irq',
    kvm_inj_virq: 'irq',
    kvm_eoi: 'apic',
    kvm_apic: 'apic',
    kvm_page_fault: 'kvm_internal',
    kvm_mmio: 'kvm_internal',
    kvm_fast_mmio: 'kvm_internal',
    kvm_pio: 'kvm_internal',
    kvm_emulate_insn: 'kvm_internal',
    kvm_cr: 'kvm_internal',
    device_dma_transfer: 'dma',
    device_dma_transfer_return: 'dma_return',
    sys_enter_ioctl: 'ioctl_enter',
    sys_exit_ioctl: 'ioctl_return',
    device_mmio_write: 'device_dispatch',
    device_execute_command: 'command',
    device_execute_command_return: 'command_return'
  };

  function applyTrace(e, t) {
    if (!t) return e;
    var wasEbpf = e.source === 'ebpf';
    e.trace_line = t.line;
    e.trace_time_ns = t.time_ns;
    e.raw = t.raw;
    e.flags = t.flags;
    e.cpu = t.cpu;
    e.pid = t.pid;
    e.tid = t.tid;
    e.comm = t.comm;
    e.source = wasEbpf ? 'trace + eBPF' : 'tracefs';
    if (wasEbpf && e.origin && t.origin) e.origin = {
      mechanism: 'tracefs + eBPF',
      hook: t.origin.hook || e.origin.hook,
      domain: t.origin.domain || e.origin.domain
    };
    else e.origin = t.origin;
    ['rip', 'reason', 'info1', 'info2', 'intr_info', 'error_code', 'userspace_reason', 'fault_gpa', 'fault_error',
      'mmio_type', 'mmio_len', 'mmio_gpa', 'mmio_val', 'pio_dir', 'pio_port', 'pio_size', 'pio_count', 'pio_val',
      'gsi', 'level', 'irq_source', 'irqchip', 'pin', 'dst', 'vec', 'mode', 'apicid', 'apic_access', 'reg', 'val'
    ].forEach(function(k) {
      if (t[k] != null) e[k] = t[k];
    });
    if (t.type === 'kvm_apic') e.apic_text = t.body, e.apic_reg = t.reg, e.apic_val = t.val;
    if (t.type === 'kvm_apic_accept_irq' || t.type === 'kvm_ioapic_set_irq' || t.type === 'kvm_msi_set_irq' || t.type === 'kvm_set_irq' || t.type === 'kvm_ack_irq') e.irq_text = t.body;
    if (t.type === 'kvm_emulate_insn' || t.type === 'kvm_cr') e.handler_text = t.body;
    return e;
  }

  function eventFromBpf(f) {
    var e = {
      bpf_seq: f.bpf_seq,
      canonical: f.canonical,
      origin: f.origin,
      name: f.name,
      time_ns: f.time_ns,
      source: 'ebpf',
      controller_sampled: !!f.vcpu,
      vmexit_id: f.vmexit_id,
      operation_id: f.operation_id,
      call_id: f.call_id,
      vcpu_ptr: f.vcpu,
      kvm_ptr: f.kvm,
      apic_ptr: f.apic,
      ioapic_ptr: f.ioapic,
      irr: f.irr,
      isr: f.isr,
      rte: f.rte,
      tpr: f.tpr,
      svr: f.svr,
      msi_present: f.msi_present,
      msi_addr: f.msi_addr,
      msi_data: f.msi_data,
      msi_vector: f.msi_vector,
      msi_dest: f.msi_dest,
      msi_logical: f.msi_logical,
      msi_level: f.msi_level,
      msi_delivery: f.msi_delivery,
      dma_present: f.dpresent,
      dma_completed: f.dcompleted,
      dma_gpa: f.dgpa,
      dma_hva: f.dhva,
      dma_dir: f.ddir,
      dma_len: f.dlen,
      dma_result: f.dresult,
      dma_checksum: f.dchecksum,
      dma_duration_ns: f.dduration,
      ioctl_present: f.ioctl_present,
      ioctl_completed: f.ioctl_completed,
      ioctl_fd: f.ioctl_fd,
      ioctl_request: f.ioctl_request,
      ioctl_name: f.ioctl_name,
      ioctl_arg: f.ioctl_arg,
      ioctl_result: f.ioctl_result,
      ioctl_duration_ns: f.ioctl_duration,
      mmio_present: f.mmio_present,
      mmio_offset: f.mmio_offset,
      mmio_register: f.mmio_register,
      mmio_value: f.mmio_value,
      command_present: f.command_present,
      command_completed: f.command_completed,
      command: f.command,
      command_name: f.command_name,
      command_status: f.command_status,
      command_dma_gpa: f.command_dma_gpa,
      command_result: f.command_result,
      command_duration_ns: f.command_duration,
      reason: '',
      info1: '',
      userspace_reason: '',
      rip: '',
      apic_text: '',
      irq_text: '',
      cpu: f.ctx.cpu,
      pid: f.ctx.pid,
      tid: f.ctx.tid,
      comm: f.ctx.comm,
      flags: ''
    };
    e.raw = 'eBPF ' + e.name;
    return e;
  }

  function eventFromTrace(t) {
    var e = {
      name: t.type,
      time_ns: t.time_ns,
      source: 'tracefs',
      controller_sampled: false,
      vmexit_id: 0,
      operation_id: 0,
      call_id: 0,
      vcpu_ptr: null,
      kvm_ptr: null,
      apic_ptr: null,
      ioapic_ptr: null,
      msi_present: false,
      dma_present: false,
      reason: '',
      info1: '',
      userspace_reason: '',
      rip: '',
      apic_text: '',
      irq_text: '',
      cpu: t.cpu,
      pid: t.pid,
      tid: t.tid,
      comm: t.comm,
      flags: t.flags,
      raw: t.raw
    };
    e.canonical = t.canonical;
    e.origin = t.origin;
    return applyTrace(e, t);
  }

  /* Preserve both files independently, correlate duplicate observations, then order the render model by monotonic time. */
  function buildEvents(snaps, trs) {
    var byType = {},
      used = {},
      events = [];
    trs.forEach(function(t) {
      (byType[t.type] = byType[t.type] || []).push(t)
    });
    snaps.forEach(function(f) {
      var e = eventFromBpf(f),
        list = byType[f.name],
        slot = used[f.name] || 0,
        t = list && list[slot];
      if (t) {
        used[f.name] = slot + 1;
        applyTrace(e, t)
      }
      events.push(e);
    });
    trs.forEach(function(t) {
      var consumed = used[t.type] || 0;
      if (consumed > 0) {
        used[t.type] = consumed - 1;
        return
      }
      events.push(eventFromTrace(t));
    });
    events.sort(function(a, b) {
      return a.time_ns - b.time_ns || (a.source === 'tracefs' ? -1 : 1)
    });
    events.forEach(function(e, index) {
      e.seq = index + 1;
      e.kind = KINDS[e.name] || 'kvm_internal';
      if (e.kind === 'entry') {
        e.from = 'kvm';
        e.to = 'guest';
        e.label = 'VM entry'
      } else if (e.kind === 'exit') {
        e.from = 'guest';
        e.to = 'kvm';
        e.label = e.reason || 'VM exit'
      } else if (e.kind === 'handoff') {
        e.from = 'kvm';
        e.to = 'vmm';
        e.label = (e.userspace_reason || 'userspace exit').replace('KVM_EXIT_', '')
      } else if (e.kind === 'dma') {
        e.from = e.dma_dir === 'to_device' ? 'memory' : 'device';
        e.to = e.dma_dir === 'to_device' ? 'device' : 'memory';
        e.label = e.dma_dir === 'to_device' ? 'DMA → device' : 'DMA ← device'
      } else {
        e.from = '';
        e.to = '';
        e.label = e.name
      }
    });
    return events;
  }

  function metaGsi() {
    return D && D.meta ? D.meta.device_gsi : ''
  }

  function metaVec() {
    return D && D.meta ? D.meta.device_vector : ''
  }

  function metaMsiVec() {
    return D && D.meta ? D.meta.msi_vector : ''
  }

  /* Derive the shared timeline, cross-references, and hand-off pairing. */
  function finalize(events) {
    var base = events.length ? events[0].time_ns : 0,
      held = {},
      activeVmexit = 0,
      lastControllerSample = -1;
    var heldFields = ['vcpu_ptr', 'kvm_ptr', 'apic_ptr', 'ioapic_ptr', 'irr', 'isr', 'rte', 'tpr', 'svr'];
    events.forEach(function(e) {
      e.time_us = (e.time_ns - base) / 1000
    });
    events.forEach(function(e, index) {
      if (e.name === 'kvm_exit' && e.vmexit_id) activeVmexit = e.vmexit_id;
      else if (!e.vmexit_id && activeVmexit) e.vmexit_id = activeVmexit;
      if (e.controller_sampled) {
        lastControllerSample = index;
        e.controller_sample_index = index;
      } else {
        e.controller_sample_index = lastControllerSample;
      }
      heldFields.forEach(function(field) {
        if (e.controller_sampled && e[field] != null) held[field] = e[field];
        else if (!e.controller_sampled && held[field] != null) e[field] = held[field];
      });
      e.prev_seq = index > 0 ? events[index - 1].seq : null;
      e.next_seq = index < events.length - 1 ? events[index + 1].seq : null;
      e.dt_prev_us = index > 0 ? +(e.time_us - events[index - 1].time_us).toFixed(3) : null;
      e.dt_next_us = index < events.length - 1 ? +(events[index + 1].time_us - e.time_us).toFixed(3) : null;
      e.paired_handoff = '';
      if (e.kind === 'exit') {
        for (var j = index + 1; j < events.length && events[j].kind !== 'entry' && events[j].kind !== 'exit'; j++) {
          if (events[j].kind === 'handoff') {
            e.paired_handoff = events[j].userspace_reason || 'KVM_EXIT_?';
            break
          }
        }
      }
      if (e.kind === 'entry') activeVmexit = 0;
    });
    return events;
  }

  /* ---- episode derivation ----------------------------------------------- */

  /* Index of the first event matching pred, or -1. */
  function findIdx(events, pred) {
    for (var i = 0; i < events.length; i++)
      if (pred(events[i], i)) return i;
    return -1;
  }
  /* Strongest motif of a region, used to name and describe the episode. */
  function regionName(evs, isLast) {
    if (evs.some(function(e) {
        return e.name === 'device_dma_transfer'
      })) {
      var d = evs.filter(function(e) {
        return e.name === 'device_dma_transfer'
      })[0];
      return 'DMA ' + (d.dma_dir === 'to_device' ? '→' : '←') + ' device' + (isLast ? ' + tail' : '');
    }
    var ac = evs.filter(function(e) {
      return e.name === 'kvm_apic_accept_irq'
    }).length;
    var mis = evs.filter(function(e) {
      return e.name === 'kvm_exit' && e.reason === 'EPT_MISCONFIG'
    }).length;
    if (mis >= 6) return 'MMIO-heavy region';
    if (ac >= 3) return 'MSI + service';
    if (ac >= 1) return 'IRQ service';
    var em = evs.some(function(e) {
        return e.kind === 'handoff'
      }) ||
      evs.some(function(e) {
        return e.name === 'kvm_exit' && e.reason === 'EPT_MISCONFIG'
      });
    if (em) return 'first emulation';
    return 'bring-up';
  }

  function regionDesc(evs, startSeq, endSeq) {
    var facts = [];
    var dm = evs.filter(function(e) {
      return e.name === 'device_dma_transfer'
    });
    if (dm.length) facts.push('DMA ' + (dm[0].dma_dir === 'to_device' ? '→' : '←') + ' GPA ' + dm[0].dma_gpa);
    var ac = evs.filter(function(e) {
      return e.name === 'kvm_apic_accept_irq'
    }).length;
    if (ac) facts.push(ac + ' accepted ' + (ac > 1 ? 'edges' : 'edge') + ' (vec ' + (metaVec()) + ')');
    var msi = evs.filter(function(e) {
      return e.name === 'kvm_msi_set_irq'
    }).length;
    if (msi) facts.push(msi + ' MSI message vec ' + (metaMsiVec()) + ' · IOAPIC bypassed');
    var reas = {};
    evs.forEach(function(e) {
      if (e.name === 'kvm_exit' && e.reason) reas[e.reason] = (reas[e.reason] || 0) + 1
    });
    Object.keys(reas).forEach(function(k) {
      if (k === 'EPT_MISCONFIG') facts.push('EPT_MISCONFIG \u00d7' + reas[k]);
      else facts.push(k + (reas[k] > 1 ? ' \u00d7' + reas[k] : ''));
    });
    var hc = {};
    evs.forEach(function(e) {
      if (e.kind === 'handoff') {
        var k = (e.userspace_reason || '').replace('KVM_EXIT_', '') || '?';
        hc[k] = (hc[k] || 0) + 1
      }
    });
    var hparts = Object.keys(hc).sort().map(function(k) {
      return k + (hc[k] > 1 ? ' \u00d7' + hc[k] : '')
    });
    if (hparts.length) facts.push(hparts.join(' / ') + ' handoffs');
    if (!facts.length) facts.push('guest bring-up: entry, exit, APIC wiring');
    return 'seq ' + startSeq + '–' + endSeq + ' · ' + facts.join(' · ');
  }
  /* Guard markers the guest writes to port 0xe9 (PIO used only as a synchronization marker). */
  var PHASE_LABEL = {
    A: 'APIC ready',
    B: 'legacy IRQ',
    C: 'IRQ pending',
    D: 'direct MSI',
    E: 'virtual DMA'
  };
  function deriveEpisodes(events) {
    var accepts = [],
      dmas = [],
      markers = [];
    events.forEach(function(e, i) {
      if (e.name === 'kvm_apic_accept_irq') accepts.push(i);
      if (e.name === 'device_dma_transfer') dmas.push(i);
      if (e.kind === 'exit' && e.reason === 'IO_INSTRUCTION') {
        var info = parseInt(e.info1, 16) || 0;
        if (((info >> 16) & 0xffff) === 0xe9) markers.push(i);
      }
    });

    var eps = [];
    if (accepts.length >= 4) {
      var seenCount = {};
      for (var w = 0; w + 1 < accepts.length; w++) {
        var local = {};
        for (var j = accepts[w] + 1; j < accepts[w + 1]; j++) {
          var e = events[j];
          if (e.kind === 'exit' && /^0x[0-9a-f]{2,}$/i.test(e.rip || '')) local[parseInt(e.rip, 16)] = 1;
        }
        for (var r in local) seenCount[r] = (seenCount[r] || 0) + 1;
      }
      var recurring = [];
      for (var v in seenCount)
        if (seenCount[v] >= 2) recurring.push(Number(v));

      function inISR(rip) {
        return recurring.some(function(q) {
          return Math.abs(q - rip) <= 0x40
        })
      }

      function mmioExit(e) {
        return e.kind === 'exit' && (e.reason === 'EPT_MISCONFIG' || e.reason === 'EPT_VIOLATION')
      }

      var openB = 0;
      for (var k = markers.length ? markers[0] + 1 : 0; k < events.length; k++) {
        if (events[k].name === 'kvm_entry') {
          openB = k;
          break
        }
      }

      function openAfter(lo, hi) {
        for (var i = lo + 1; i < hi; i++) {
          var e = events[i];
          if (e.kind !== 'exit') continue;
          if (mmioExit(e) && !inISR(parseInt(e.rip || '0', 16))) return i;
        }
        return -1;
      }
      /* The boundary event closes Phase A; Phase B begins after enter guest. */
      var opens = [0, Math.min(openB + 1, events.length)];
      for (var i = 1; i <= 3; i++) {
        if (i >= accepts.length) break;
        opens.push(openAfter(accepts[i - 1], accepts[i]));
      }
      opens.push(events.length);
      if (opens.length === 6 && opens.every(function(o) {
          return o >= 0
        })) {
        var letters = ['A', 'B', 'C', 'D', 'E'];
        for (var s = 0; s < letters.length; s++) {
          var lo = opens[s],
            hi = opens[s + 1];
          if (hi <= lo) continue;
          var idx = [];
          for (var t = lo; t < hi; t++) idx.push(t);
          eps.push({
            start: events[lo].seq,
            end: events[hi - 1].seq,
            count: idx.length,
            indices: idx,
            name: 'Phase ' + letters[s] + ' \u00b7 ' + PHASE_LABEL[letters[s]],
            desc: regionDesc(events.slice(lo, hi), events[lo].seq, events[hi - 1].seq)
          });
        }
        if (eps.length) return eps;
      }
    }

    var starts = [0];
    var firstM = findIdx(events, function(e) {
      return e.kind === 'exit' && e.reason === 'EPT_MISCONFIG'
    });
    if (firstM >= 0) starts.push(firstM);
    if (accepts.length) starts.push(accepts[0]);
    for (var b = 0; b < accepts.length - 1; b++) {
      if (events[accepts[b + 1]].time_us - events[accepts[b]].time_us < 40) {
        starts.push(accepts[b]);
        break
      }
    }
    dmas.forEach(function(i) {
      starts.push(i)
    });
    starts = starts.filter(function(v, i) {
      return starts.indexOf(v) === i
    }).sort(function(a, b) {
      return a - b
    });
    for (var q = 0; q < starts.length; q++) {
      var sa = starts[q];
      if (sa >= events.length) break;
      var se = q + 1 < starts.length ? starts[q + 1] - 1 : events.length - 1;
      var seg = events.slice(sa, se + 1);
      eps.push({
        start: events[sa].seq,
        end: events[se].seq,
        count: se - sa + 1,
        indices: (function() {
          var r = [];
          for (var k = sa; k <= se; k++) r.push(k);
          return r
        })(),
        name: regionName(seg, q === starts.length - 1),
        desc: regionDesc(seg, events[sa].seq, events[se].seq)
      });
    }
    return eps;
  }

  function episodeFor(index) {
    for (var i = 0; i < D.episodes.length; i++) {
      var ep = D.episodes[i];
      if (ep.indices.length && index >= ep.indices[0] && index <= ep.indices[ep.indices.length - 1]) return i;
    }
    return D.episodes.length - 1;
  }

  /* ---- presentation helpers ------------------------------------------- */

  function prettyEvent(e) {
    if (e.name === 'kvm_entry') return 'VM entry';
    if (e.name === 'kvm_exit') return e.reason || 'VM exit';
    if (e.name === 'kvm_userspace_exit') return (e.userspace_reason || 'userspace exit').replace('KVM_EXIT_', '');
    if (e.name === 'sys_enter_ioctl') return e.ioctl_name || 'ioctl';
    if (e.name === 'sys_exit_ioctl') return (e.ioctl_name || 'ioctl') + ' ret';
    if (e.name === 'device_mmio_write') return (e.mmio_register || 'MMIO') + ' write';
    if (e.name === 'device_execute_command') return e.command_name || 'execute command';
    if (e.name === 'device_execute_command_return') return (e.command_name || 'command') + ' complete';
    if (e.name === 'device_dma_transfer') return e.dma_dir === 'to_device' ? 'DMA → device' : 'DMA ← device';
    if (e.name === 'device_dma_transfer_return') return 'DMA complete';
    if (e.name === 'kvm_page_fault') return 'EPT fault ' + (e.fault_gpa || '');
    if (e.name === 'kvm_mmio') return 'KVM MMIO ' + (e.mmio_type || '');
    if (e.name === 'kvm_pio') return 'KVM PIO ' + (e.pio_dir || '');
    if (e.name === 'kvm_emulate_insn') return 'emulate instruction';
    if (e.name === 'kvm_set_irq') return 'set GSI ' + (e.gsi != null ? e.gsi : '?') + '=' + e.level;
    if (e.name === 'kvm_ack_irq') return 'ack IRQ pin ' + (e.pin != null ? e.pin : '?');
    if (e.name === 'kvm_apic_accept_irq') return 'APIC accepts vec ' + (e.vec != null ? e.vec : '?');
    if (e.name === 'kvm_ioapic_set_irq') return 'IOAPIC set_irq';
    if (e.name === 'kvm_msi_set_irq') return 'MSI set_irq';
    if (e.name === 'kvm_apic') return 'APIC ' + (e.apic_reg || 'register');
    return e.name;
  }

  /* ---- renderers -------------------------------------------------------- */

  function renderRoadmap() {
    var active = episodeFor(cursor);
    $('roadmap').innerHTML = D.episodes.map(function(ep, ei) {
      var label = ep.name.replace(/^Phase [A-Z] · /, '');
      return '<button type="button" class="phase-button selector-option ' + (ei === active ? 'active' : '') + '" data-ep="' + ei + '"><span class="selector-kicker">PHASE ' + String.fromCharCode(65 + ei) + '</span><span class="selector-label">' + esc(label) + '</span></button>';
    }).join('');
    $('roadmap').querySelectorAll('[data-ep]').forEach(function(z) {
      z.addEventListener('click', function() {
        select(D.episodes[+z.dataset.ep].indices[0])
      });
    });
  }
  /* ---- execution chronogram helpers -------------------------------------- */

  function lapicWindow(win) {
    var out = [];
    if (win)
      for (var k = 0; k < 8; k++) {
        var w = win['b' + k];
        if (!w) continue;
        var bits = parseInt(w, 16);
        for (var b = 0; b < 32; b++)
          if (bits & (1 << b)) out.push(k * 32 + b);
      }
    return out;
  }

  function vecList(vecs) {
    if (!vecs.length) return '—';
    return vecs.map(function(v) {
      return '0x' + v.toString(16)
    }).join(', ');
  }

  /* Decode a kvm_exit ioinfo1 into port / direction / size for IO_INSTRUCTION. */
  function ioQualification(e) {
    if (e.kind !== 'exit' || e.reason !== 'IO_INSTRUCTION' || !e.info1) return null;
    var q = parseInt(e.info1, 16);
    if (q == null || isNaN(q)) return null;
    var port = (q >> 16) & 0xffff;
    var isIn = ((q >>> 3) & 1) === 1;
    var sizeCode = q & 7;
    var bytes = sizeCode === 0 ? 1 : sizeCode === 1 ? 2 : sizeCode === 3 ? 4 : null;
    return {
      port: port,
      dir: isIn ? 'IN' : 'OUT',
      bytes: bytes
    };
  }
  /* Compact terminal label for a tracepoint/hook observation site. */
  function compactObs(e) {
    if (e.name === 'kvm_mmio') return 'MMIO';
    if (e.name === 'kvm_emulate_insn') return 'emulate';
    if (e.name === 'device_mmio_write') return 'MMIO write';
    if (e.name === 'kvm_apic_accept_irq') return 'accept vec ' + (e.vec != null ? vecHex(e.vec) : '?');
    if (e.name === 'kvm_ioapic_set_irq') return 'route pin ' + (e.pin != null ? e.pin : '?');
    if (e.name === 'kvm_msi_set_irq') return 'MSI vec ' + (e.msi_vector != null ? vecHex(e.msi_vector) : '?');
    if (e.name === 'kvm_set_irq') return 'GSI ' + (e.gsi != null ? e.gsi : '?') + ' = ' + e.level;
    if (e.name === 'kvm_ack_irq') return 'ack pin ' + (e.pin != null ? e.pin : '?');
    if (e.name === 'kvm_apic') return (e.apic_reg || 'APIC') + ' ' + (e.apic_access || 'write');
    if (e.name === 'kvm_page_fault') return 'EPT fault · ' + (e.fault_gpa || '?');
    if (e.name === 'kvm_fast_mmio') return 'fast MMIO · ' + (e.mmio_gpa || '?');
    if (e.name === 'kvm_pio') return 'PIO ' + (e.pio_dir || '') + ' · ' + (e.pio_port || '?') + ' = ' + (e.pio_val || '?');
    if (e.name === 'kvm_cr') return String(e.handler_text || 'CR access').slice(0, 34);
    if (e.name === 'device_dma_transfer') return (e.dma_dir === 'to_device' ? 'DMA → device' : 'DMA ← device') + ' · ' + (e.dma_gpa || '');
    if (e.name === 'device_dma_transfer_return') return 'DMA ret ' + e.dma_result + ' · sum ' + e.dma_checksum;
    if (e.name === 'device_execute_command') return e.command_name || 'execute command';
    if (e.name === 'device_execute_command_return') return (e.command_name || 'command') + ' · status ' + e.command_status;
    if (e.name === 'sys_enter_ioctl') return e.ioctl_name || 'ioctl';
    if (e.name === 'sys_exit_ioctl') return (e.ioctl_name || 'ioctl') + ' ret ' + e.ioctl_result;
    return prettyEvent(e);
  }
  /* Label for the deepest IO_INSTRUCTION reason an exit row can carry. */
  function seqIoLabel(e) {
    var q = ioQualification(e);
    if (!q) return e.reason || 'IO_INSTRUCTION';
    var label = q.dir + ' 0x' + q.port.toString(16).toUpperCase();
    return q.port === 0xe9 ? label + ' · sync' : label;
  }
  /* Component lifelines use the same actor/message model as the native I/O view. */
  var COMPONENT_ACTORS = [{
    id: 'vmm',
    role: 'HOST',
    name: 'VMM'
  }, {
    id: 'kvm',
    role: 'HOST',
    name: 'KVM'
  }, {
    id: 'guest',
    role: 'GUEST',
    name: 'vCPU 0'
  }, {
    id: 'lapic',
    role: 'HOST',
    name: 'LAPIC'
  }, {
    id: 'ioapic',
    role: 'HOST',
    name: 'IOAPIC'
  }, {
    id: 'device',
    role: 'HOST',
    name: 'TOY DEVICE'
  }, {
    id: 'memory',
    role: 'GUEST',
    name: 'RAM'
  }];

  function actorDetail(actor) {
    if (actor.id === 'vmm') return D.events[0].comm + '-' + D.events[0].pid;
    if (actor.id === 'kvm') return 'KVM_RUN';
    if (actor.id === 'guest') return 'execution';
    if (actor.id === 'lapic') return 'vec ' + vecHex(metaVec()) + ' / ' + vecHex(metaMsiVec());
    if (actor.id === 'ioapic') return 'GSI ' + metaGsi();
    if (actor.id === 'device') return D.meta.device_buffer_size + ' B buffer';
    var gpas = [];
    D.events.forEach(function(event) {
      if (event.dma_present && gpas.indexOf(event.dma_gpa) < 0) gpas.push(event.dma_gpa)
    });
    return gpas.length ? gpas.join(' / ') : 'DMA GPAs';
  }

  function actorIndex(id) {
    for (var i = 0; i < COMPONENT_ACTORS.length; i++)
      if (COMPONENT_ACTORS[i].id === id) return i;
    return 0;
  }

  function interruptTransport(index) {
    for (var i = index - 1; i >= 0; i--) {
      if (D.events[i].name === 'kvm_msi_set_irq') return 'msi';
      if (D.events[i].name === 'kvm_ioapic_set_irq') return 'ioapic';
      if (D.events[i].name === 'kvm_apic_accept_irq') break;
    }
    return 'ioapic';
  }

  function componentMessage(from, to, label, kind) {
    return {
      from: from,
      to: to,
      label: label,
      kind: kind || 'control'
    };
  }

  function componentFlow(event, index) {
    var flow = [],
      vector = event.vec != null ? vecHex(event.vec) : vecHex(metaVec()),
      request = event.ioctl_name || 'ioctl';
    if (event.kind === 'entry') {
      flow.push(componentMessage('kvm', 'guest', 'enter guest', 'entry'));
    } else if (event.kind === 'exit') {
      flow.push(componentMessage('guest', 'kvm', event.reason === 'IO_INSTRUCTION' ? seqIoLabel(event) : (event.reason || 'VM exit'), 'exit'));
    } else if (event.kind === 'handoff') {
      flow.push(componentMessage('kvm', 'vmm', (event.userspace_reason || 'KVM_EXIT').replace('KVM_EXIT_', ''), 'handoff'));
    } else if (event.kind === 'ioctl_enter') {
      var requester = (request === 'KVM_IRQ_LINE' || request === 'KVM_SIGNAL_MSI') ? 'device' : 'vmm';
      flow.push(componentMessage(requester, 'kvm', request, 'run'));
    } else if (event.kind === 'ioctl_return') {
      var owner = (request === 'KVM_IRQ_LINE' || request === 'KVM_SIGNAL_MSI') ? 'device' : 'vmm';
      flow.push(componentMessage('kvm', owner, request + ' ret ' + event.ioctl_result, 'run'));
    } else if (event.name === 'device_mmio_write') {
      flow.push(componentMessage('vmm', 'device', 'MMIO write', 'handoff'));
    } else if (event.name === 'device_execute_command') {
      flow.push(componentMessage('vmm', 'device', 'execute ' + (event.command_name || 'command'), 'run'));
    } else if (event.name === 'device_execute_command_return') {
      flow.push(componentMessage('device', 'vmm', 'ret · ' + event.command_status, 'run'));
    } else if (event.name === 'kvm_set_irq') {
      flow.push(componentMessage('kvm', 'ioapic', 'GSI ' + (event.gsi != null ? event.gsi : metaGsi()) + ' = ' + event.level, 'interrupt'));
    } else if (event.name === 'kvm_ioapic_set_irq') {
      flow.push(componentMessage('kvm', 'ioapic', 'route pin ' + (event.pin != null ? event.pin : metaGsi()), 'interrupt'));
    } else if (event.name === 'kvm_msi_set_irq') {
      flow.push(componentMessage('kvm', 'lapic', 'MSI · vec ' + vecHex(event.msi_vector != null ? event.msi_vector : metaMsiVec()), 'interrupt'));
    } else if (event.name === 'kvm_apic_accept_irq') {
      flow.push(componentMessage(interruptTransport(index) === 'msi' ? 'kvm' : 'ioapic', 'lapic', 'accept ' + vector, 'interrupt'));
    } else if (event.name === 'kvm_inj_virq') {
      flow.push(componentMessage('lapic', 'guest', 'inject ' + vector, 'interrupt'));
    } else if (event.name === 'kvm_eoi') {
      flow.push(componentMessage('guest', 'lapic', 'EOI ' + vector, 'apic'));
    } else if (event.name === 'kvm_apic') {
      flow.push(componentMessage('kvm', 'lapic', (event.apic_reg || 'APIC') + ' ' + (event.apic_access || 'write'), 'apic'));
    } else if (event.name === 'kvm_ack_irq') {
      flow.push(componentMessage('ioapic', 'ioapic', 'ack pin ' + (event.pin != null ? event.pin : '?'), 'local'));
    } else if (event.name === 'device_dma_transfer') {
      var access = event.dma_dir === 'to_device' ? 'DMA read' : 'DMA write';
      var source = event.dma_dir === 'to_device' ? 'memory' : 'device';
      var target = event.dma_dir === 'to_device' ? 'device' : 'memory';
      flow.push(componentMessage(source, target, access + ' · ' + event.dma_gpa, 'dma'));
    } else if (event.name === 'device_dma_transfer_return') {
      var returnSource = event.dma_dir === 'to_device' ? 'device' : 'memory';
      var returnTarget = event.dma_dir === 'to_device' ? 'memory' : 'device';
      flow.push(componentMessage(returnSource, returnTarget, 'DMA ret ' + event.dma_result, 'dma'));
    } else {
      flow.push(componentMessage('kvm', 'kvm', compactObs(event), 'local'));
    }
    return flow;
  }

  function renderExec(e) {
    var ep = D.episodes[episodeFor(cursor)],
      host = $('exec-html'),
      interactions = [];
    ep.indices.forEach(function(global) {
      componentFlow(D.events[global], global).forEach(function(flow) {
        interactions.push({
          global: global,
          event: D.events[global],
          flow: flow
        })
      });
    });
    var currentFlows = componentFlow(e, cursor),
      active = {};
    currentFlows.forEach(function(flow) {
      active[flow.from] = true;
      active[flow.to] = true
    });
    $('rip-head').textContent = e.rip ? ('RIP ' + e.rip) : 'RIP —';

    var head = '<div class="component-head">' + COMPONENT_ACTORS.map(function(actor) {
      return '<article class="component-actor ' + (active[actor.id] ? 'active' : '') + '"><small>' + esc(actor.role) + '</small><b>' + esc(actor.name) + '</b><em>' + esc(actorDetail(actor)) + '</em></article>';
    }).join('') + '</div>';
    var laneLines = '<div class="component-lifelines">' + COMPONENT_ACTORS.map(function(actor, index) {
      return '<i class="' + (active[actor.id] ? 'active' : '') + '" style="left:' + ((index + .5) / COMPONENT_ACTORS.length * 100) + '%"></i>';
    }).join('') + '</div>';
    var rows = interactions.map(function(item) {
      var flow = item.flow,
        fromIndex = actorIndex(flow.from),
        toIndex = actorIndex(flow.to),
        selected = item.global === cursor ? ' current' : '',
        kind = ' ' + flow.kind;
      var from = (fromIndex + .5) / COMPONENT_ACTORS.length * 100,
        to = (toIndex + .5) / COMPONENT_ACTORS.length * 100;
      if (fromIndex === toIndex) {
        return '<button type="button" class="component-row local' + selected + '" data-index="' + item.global + '"><i class="component-local ' + flow.kind + '" style="left:' + from + '%"></i><code style="left:' + from + '%" title="' + esc(item.event.raw) + '">' + esc(flow.label) + '</code></button>';
      }
      var left = Math.min(from, to),
        width = Math.abs(to - from),
        direction = to > from ? 'forward' : 'reverse';
      return '<button type="button" class="component-row' + selected + '" data-index="' + item.global + '"><i class="component-arrow ' + direction + kind + '" style="left:' + left + '%;width:' + width + '%"></i><i class="component-point" style="left:' + from + '%"></i><i class="component-point" style="left:' + to + '%"></i><code style="left:' + ((from + to) / 2) + '%" title="' + esc(item.event.raw) + '">' + esc(flow.label) + '</code></button>';
    }).join('');
    var previous = host.querySelector('.component-track'),
      previousTop = previous ? previous.scrollTop : null;
    host.innerHTML = head + '<div class="component-track"><div class="component-body" style="--rows:' + Math.max(interactions.length, 1) + '">' + laneLines + rows + '</div></div>';
    host.querySelectorAll('.component-row').forEach(function(row) {
      row.addEventListener('click', function() {
        select(+row.dataset.index)
      })
    });
    var track = host.querySelector('.component-track');
    if (track && previousTop != null) track.scrollTop = previousTop;
    var selected = host.querySelector('.component-row.current');
    if (selected) selected.scrollIntoView({
      block: 'nearest'
    });

    $('flow-kind').textContent = e.source === 'trace + eBPF' ? 'trace + eBPF' : e.source;
    if (e.kind === 'entry') {
      $('flow-caption').textContent = 'kvm_entry transfers execution to the guest at ' + (e.rip || 'unknown RIP');
    } else if (e.kind === 'exit') {
      $('flow-caption').textContent = (e.reason || 'VM exit') + ' transfers control from guest to KVM' + (e.rip ? ' at ' + e.rip : '');
    } else if (e.kind === 'handoff') {
      $('flow-caption').textContent = (e.userspace_reason || 'KVM exit') + ' · ret KVM_RUN to the VMM';
    } else if (e.kind === 'ioctl_enter' || e.kind === 'ioctl_return') {
      $('flow-caption').textContent = (e.ioctl_name || 'ioctl') + ' · fd ' + e.ioctl_fd + (e.ioctl_completed ? ' · ret ' + e.ioctl_result + ' · ' + e.ioctl_duration_ns + ' ns' : '');
    } else if (e.name === 'device_dma_transfer' || e.name === 'device_dma_transfer_return') {
      $('flow-caption').textContent = e.dma_dir + ' · GPA ' + e.dma_gpa + ' · ' + e.dma_len + ' B' + (e.dma_completed ? ' · ret ' + e.dma_result + ' · checksum ' + e.dma_checksum : '');
    } else {
      $('flow-caption').textContent = compactObs(e);
    }
  }

  function vectorNumber(v) {
    if (typeof v === 'number') return v;
    var s = String(v == null ? '' : v).toLowerCase();
    return s.indexOf('0x') === 0 ? parseInt(s, 16) : parseInt(s, 10);
  }

  function commandNameFromEvent(e) {
    if (e.command_name) return e.command_name;
    if (e.name !== 'device_mmio_write' || e.mmio_register !== 'REG_COMMAND') return '';
    var command = vectorNumber(e.mmio_value);
    return {
      1: 'CMD_IRQ_ONLY',
      2: 'CMD_DMA_TO_DEVICE',
      3: 'CMD_DMA_FROM_DEVICE',
      4: 'CMD_MSI_ONLY'
    } [command] || '';
  }

  function hasLapicVector(e, field, vector) {
    return lapicWindow(e[field]).indexOf(vector) >= 0
  }

  function interruptCycle(index) {
    var start = -1,
      anchor = null;
    for (var i = index; i >= 0; i--) {
      var candidate = D.events[i];
      if (candidate.name === 'device_execute_command' || (candidate.name === 'device_mmio_write' && candidate.mmio_register === 'REG_COMMAND')) {
        start = i;
        anchor = candidate;
        break;
      }
    }
    if (start < 0) return {
      start: -1,
      transport: '',
      vector: null,
      operationId: 0,
      stages: {}
    };
    var command = commandNameFromEvent(anchor),
      transport = command === 'CMD_MSI_ONLY' ? 'msi' : 'legacy';
    var vector = vectorNumber(transport === 'msi' ? metaMsiVec() : metaVec());
    var cycle = {
      start: start,
      transport: transport,
      vector: vector,
      operationId: anchor.operation_id || 0,
      command: command,
      level: null,
      msiEvent: null,
      stages: {
        request: null,
        route: null,
        accept: null,
        pending: null,
        service: null,
        ack: null,
        cleared: null
      }
    };
    var sawService = false;
    for (i = start; i <= index; i++) {
      var event = D.events[i],
        request = event.ioctl_name;
      if (event.kind === 'ioctl_enter' && ((transport === 'msi' && request === 'KVM_SIGNAL_MSI') || (transport === 'legacy' && request === 'KVM_IRQ_LINE')) && !cycle.stages.request) cycle.stages.request = {
        index: i,
        event: event
      };
      if (transport === 'legacy' && event.name === 'kvm_set_irq') {
        cycle.level = event.level;
        if (event.level === 1 && !cycle.stages.route) cycle.stages.route = {
          index: i,
          event: event
        };
      }
      if (transport === 'legacy' && event.name === 'kvm_ioapic_set_irq' && !cycle.stages.route) cycle.stages.route = {
        index: i,
        event: event
      };
      if (transport === 'msi' && event.name === 'kvm_msi_set_irq') {
        cycle.msiEvent = event;
        if (!cycle.stages.route) cycle.stages.route = {
          index: i,
          event: event
        };
      }
      if (event.name === 'kvm_apic_accept_irq' && vectorNumber(event.vec) === vector && !cycle.stages.accept) cycle.stages.accept = {
        index: i,
        event: event
      };
      if (hasLapicVector(event, 'irr', vector) && !cycle.stages.pending) cycle.stages.pending = {
        index: i,
        event: event
      };
      if (hasLapicVector(event, 'isr', vector)) {
        sawService = true;
        if (!cycle.stages.service) cycle.stages.service = {
          index: i,
          event: event
        };
      }
      if (event.name === 'device_mmio_write' && event.mmio_register === 'REG_IRQ_ACK' && !cycle.stages.ack) cycle.stages.ack = {
        index: i,
        event: event
      };
      if (sawService && !hasLapicVector(event, 'isr', vector) && !cycle.stages.cleared && cycle.stages.service.index < i) cycle.stages.cleared = {
        index: i,
        event: event
      };
    }
    return cycle;
  }

  function irqRouteLabel(e, cycle) {
    if ((cycle && cycle.transport === 'msi') || e.kind === 'msi' || e.name === 'kvm_msi_set_irq') {
      var msi = cycle && cycle.msiEvent ? cycle.msiEvent : e;
      return 'MSI → ' + vecHex(msi.msi_vector != null ? msi.msi_vector : metaMsiVec());
    }
    if (e.rte != null && e.rte !== '') return 'GSI ' + D.meta.device_gsi + ' → ' + vecHex(metaVec());
    return 'GSI ' + D.meta.device_gsi + ' → —';
  }

  function irqStateMap(e, cycle) {
    var pending = lapicWindow(e.irr).sort(function(a, b) {
      return a - b
    });
    var inService = lapicWindow(e.isr).sort(function(a, b) {
      return a - b
    });
    return {
      irr: pending.join(' '),
      isr: inService.join(' '),
      svr: e.svr != null && e.svr !== '' ? e.svr : '0x0',
      tpr: e.tpr != null && e.tpr !== '' ? e.tpr : '0x0',
      rte: e.rte != null && e.rte !== '' ? e.rte : '0x0',
      route: irqRouteLabel(e, cycle)
    };
  }

  function irqStateDisplay(e, f, cycle) {
    if (f === 'irr' || f === 'isr') return vecList(lapicWindow(e[f]));
    return irqStateMap(e, cycle)[f];
  }

  function vecHex(v) {
    if (v == null) return '—';
    if (typeof v === 'number') return '0x' + v.toString(16);
    var s = String(v).toLowerCase();
    if (/^0x[0-9a-f]+$/.test(s)) return s;
    if (/^\d+$/.test(s)) return '0x' + parseInt(s, 10).toString(16);
    if (/^[0-9a-f]+$/.test(s)) return '0x' + parseInt(s, 16).toString(16);
    return '—';
  }

  function hexValue(v) {
    if (v == null) return '0x0';
    if (typeof v === 'number') return '0x' + v.toString(16);
    var s = String(v).toLowerCase();
    return s.indexOf('0x') === 0 ? s : '0x' + s;
  }

  function rteDecode(rte) {
    try {
      var v = BigInt(rte || 0),
        delivery = ['fixed', 'lowest', 'SMI', 'reserved', 'NMI', 'INIT', 'reserved', 'ExtINT'][Number((v >> 8n) & 7n)];
      return 'vec ' + vecHex(Number(v & 255n)) + ' · ' + delivery + ' · ' + (v & 2048n ? 'logical' : 'phys') + ' · ' + (v & 32768n ? 'level' : 'edge');
    } catch (ignore) {
      return rte || '0x0'
    }
  }

  function svrDecode(svr) {
    var v = parseInt(svr, 16);
    if (isNaN(v)) return svr || '0x0';
    return (v & 0x100 ? 'enabled' : 'disabled') + (v & 0xff ? ' · spiv vec 0x' + (v & 0xff).toString(16) : '');
  }

  function tprDecode(tpr) {
    var v = parseInt(tpr, 16);
    if (isNaN(v)) return tpr || '0x0';
    return 'priority 0x' + (v >>> 4).toString(16);
  }

  function stateDecode(f, v) {
    if (f === 'svr') return svrDecode(v);
    if (f === 'tpr') return tprDecode(v);
    if (f === 'rte') return rteDecode(v);
    if (f === 'irr') return 'pending';
    if (f === 'isr') return 'in service';
    return String(v).indexOf('MSI') === 0 ? 'message route · IOAPIC bypassed' : 'IOAPIC redirection route';
  }

  function lifecycleActive(stage, e, cycle) {
    var request = e.ioctl_name;
    if (stage === 'request') return e.kind === 'ioctl_enter' && ((cycle.transport === 'msi' && request === 'KVM_SIGNAL_MSI') || (cycle.transport === 'legacy' && request === 'KVM_IRQ_LINE'));
    if (stage === 'route') return cycle.transport === 'msi' ? e.name === 'kvm_msi_set_irq' : (e.name === 'kvm_set_irq' || e.name === 'kvm_ioapic_set_irq');
    if (stage === 'accept') return e.name === 'kvm_apic_accept_irq' && vectorNumber(e.vec) === cycle.vector;
    if (stage === 'pending') return hasLapicVector(e, 'irr', cycle.vector);
    if (stage === 'service') return hasLapicVector(e, 'isr', cycle.vector);
    if (stage === 'ack') return e.name === 'device_mmio_write' && e.mmio_register === 'REG_IRQ_ACK';
    return stage === 'cleared' && cycle.stages.cleared && cycle.stages.cleared.index === cursor;
  }

  function renderInterruptLifecycle(e, cycle) {
    var stages = ['request', 'route', 'accept', 'pending', 'service', 'ack', 'cleared'];
    if (cycle.start < 0) {
      $('irq-life-mode').textContent = 'no delivery';
      $('irq-life-summary').textContent = 'waiting for request';
      stages.forEach(function(stage) {
        var node = $('irq-step-' + stage);
        node.className = stage === 'cleared' ? 'derived' : '';
        node.querySelector('small').textContent = '—';
        node.removeAttribute('title')
      });
      return;
    }
    var msi = cycle.msiEvent,
      request = cycle.transport === 'msi' ? 'KVM_SIGNAL_MSI' : 'KVM_IRQ_LINE';
    $('irq-life-mode').textContent = cycle.transport === 'msi' ? 'MSI direct' : 'legacy line';
    if (cycle.transport === 'msi') {
      $('irq-life-summary').textContent = (msi ? 'addr ' + hexValue(msi.msi_addr) + ' · data ' + hexValue(msi.msi_data) : 'awaiting KVM_SIGNAL_MSI') + ' · vec ' + vecHex(cycle.vector) + (cycle.operationId ? ' · operation ' + cycle.operationId : '');
    } else {
      $('irq-life-summary').textContent = 'GSI ' + metaGsi() + (cycle.level == null ? '' : ' = ' + cycle.level) + ' · vec ' + vecHex(cycle.vector) + (cycle.operationId ? ' · operation ' + cycle.operationId : '');
    }
    var requestEvent = cycle.stages.request && cycle.stages.request.event;
    var facts = {
      request: request + (requestEvent ? ' · fd ' + requestEvent.ioctl_fd : ''),
      route: cycle.transport === 'msi' ? (msi ? 'kvm_msi_set_irq · ' + hexValue(msi.msi_data) : '—') : 'kvm_set_irq · GSI ' + metaGsi() + (cycle.level == null ? '' : ' = ' + cycle.level),
      accept: 'kvm_apic_accept_irq · ' + vecHex(cycle.vector),
      pending: 'LAPIC IRR · ' + vecHex(cycle.vector),
      service: 'LAPIC ISR · ' + vecHex(cycle.vector),
      ack: 'REG_IRQ_ACK · 0x1',
      cleared: 'ISR ' + vecHex(cycle.vector) + ' → clear'
    };
    stages.forEach(function(stage) {
      var node = $('irq-step-' + stage),
        evidence = cycle.stages[stage],
        classes = [];
      if (evidence) classes.push('seen');
      if (lifecycleActive(stage, e, cycle)) classes.push('active');
      if (stage === 'cleared') classes.push('derived');
      node.className = classes.join(' ');
      node.querySelector('small').textContent = evidence ? facts[stage] : '—';
      if (evidence) node.title = evidence.event.name + ' · seq ' + evidence.event.seq;
      else node.removeAttribute('title');
    });
  }
  var IRQ_STATE_ITEMS = ['irr', 'isr', 'svr', 'tpr', 'rte', 'route'];

  function renderIRQ(e) {
    var cycle = interruptCycle(cursor);
    var sampled = !!e.controller_sampled,
      stateAvailable = e.controller_sample_index >= 0,
      carryover = stateAvailable && !sampled,
      pending = stateAvailable ? lapicWindow(e.irr) : [],
      inService = stateAvailable ? lapicWindow(e.isr) : [];
    $('irq-address').textContent = irqRouteLabel(e, cycle);

    var previousCycle = cursor > 0 ? interruptCycle(cursor - 1) : null;
    var now = irqStateMap(e, cycle),
      prev = (cursor > 0) ? irqStateMap(D.events[cursor - 1], previousCycle) : null;
    IRQ_STATE_ITEMS.forEach(function(f) {
      var el = $('st-' + f),
        changed = sampled && prev !== null && e.controller_sample_index >= 0 &&
          D.events[cursor - 1].controller_sample_index >= 0 &&
          e.controller_sample_index !== D.events[cursor - 1].controller_sample_index &&
          prev[f] !== now[f];
      var nowF = stateAvailable ? irqStateDisplay(e, f, cycle) : '—',
        prevF = prev != null ? irqStateDisplay(D.events[cursor - 1], f, previousCycle) : null;
      el.classList.toggle('changed', changed);
      var val = el.querySelector('.val'),
        sub = el.querySelector('.sub');
      val.textContent = nowF;
      val.classList.toggle('big', changed);
      sub.textContent = !stateAvailable ? 'not sampled' : changed ? ('▲ ' + prevF + ' → ' + nowF) : stateDecode(f, now[f]);
      sub.title = sub.textContent;
    });
    renderInterruptLifecycle(e, cycle);
    var caption;
    if (!stateAvailable) {
      $('irq-state').textContent = 'not sampled';
      caption = 'controller state not sampled at this event';
    } else if (pending.length && inService.length) {
      $('irq-state').textContent = 'pending + in service';
      caption = vecList(pending) + ' pending; ' + vecList(inService) + ' in service'
    } else if (pending.length) {
      $('irq-state').textContent = 'pending';
      caption = 'IRR holds ' + vecList(pending) + ' at this observation'
    } else if (inService.length) {
      $('irq-state').textContent = 'in service';
      caption = vecList(inService) + ' in service at this observation'
    } else {
      $('irq-state').textContent = (e.kind === 'irq' || e.kind === 'msi') ? 'route' : 'idle';
      caption = (e.kind === 'irq' || e.kind === 'msi') ? 'IRR/ISR empty' : 'no pending/in-service vector'
    }
    $('irq-caption').classList.toggle('carryover', carryover);
    $('irq-caption').textContent = caption + (carryover ? ' · [carryover]' : '');
  }

  function renderDMA(e) {
    var to = $('dma-edge-to'),
      from = $('dma-edge-from');
    to.className = from.className = 'rt-edge';
    $('rt-src').classList.remove('hot');
    $('rt-dst').classList.remove('hot');
    if (e.dma_present) {
      (e.dma_dir === 'to_device' ? to : from).classList.add('hot');
      $(e.dma_dir === 'to_device' ? 'rt-src' : 'rt-dst').classList.add('hot');
      $('device-state').textContent = e.dma_dir === 'to_device' ? 'receiving ' + D.meta.dma_xfer_size + ' B' : 'sending ' + D.meta.dma_xfer_size + ' B';
      $('device-detail').textContent = e.dma_dir === 'to_device' ? 'storing guest bytes for the ret copy' : 'ret stored bytes (echo)';
      $('dma-state').textContent = e.dma_dir.replace('_', ' ');
      $('dma-caption').textContent = D.meta.dma_xfer_size + ' B at ' + e.dma_gpa + ' · ' + e.dma_dir;
    } else if (D.dmaFrom != null && cursor >= D.dmaFrom) {
      from.className = 'rt-edge dim';
      $('rt-dst').classList.add('hot');
      $('device-state').textContent = 'round trip ret';
      $('device-detail').textContent = 'guest compares ret bytes to the source';
      $('dma-state').textContent = 'round-trip · verifying';
      $('dma-caption').textContent = '';
    } else if (D.dmaTo != null && cursor >= D.dmaTo) {
      to.className = 'rt-edge dim';
      $('rt-src').classList.add('hot');
      $('device-state').textContent = 'outbound copy complete';
      $('device-detail').textContent = 'awaiting the ret copy · no DMA running';
      $('dma-state').textContent = 'staged';
      $('dma-caption').textContent = 'awaiting ret · no DMA';
    } else {
      $('device-state').textContent = D.meta.device_buffer_size + ' B buffer';
      $('device-detail').textContent = 'no transfer in this phase';
      $('dma-state').textContent = 'not present';
      $('dma-caption').textContent = 'two device_dma_transfer calls are observed at entry and ret';
    }
  }

  function renderNotebook(e) {
    renderOrigin(e);
    var rows = rawFieldRows(e);
    $('fields').innerHTML = rows.map(function(r) {
      return '<div><small>' + esc(r[0]) + '</small><b title="' + esc(r[1]) + '">' + esc(r[1]) + '</b></div>'
    }).join('');
  }

  function rawFieldRows(event) {
    var data = event.canonical && event.canonical.data || {},
      fields = data.fields || data.event_info || {},
      rows = [];
    function append(value, prefix) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        Object.keys(value).forEach(function(key) {
          append(value[key], prefix ? prefix + '.' + key : key);
        });
      } else rows.push([prefix, Array.isArray(value) ? JSON.stringify(value) : value]);
    }
    Object.keys(fields).forEach(function(key) {
      append(fields[key], key);
    });
    return rows.filter(function(row) {
      return row[1] !== null && row[1] !== undefined && row[1] !== '';
    });
  }

  function originContext(event) {
    var task = event.comm || '—',
      pid = event.pid != null ? 'PID ' + event.pid : event.tid != null ? 'TID ' + event.tid : '';
    if (pid) task += ' · ' + pid;
    return task;
  }

  function renderOrigin(event) {
    var origin = event.origin || {},
      rows = [
        ['mechanism', mechanismLabel(origin.mechanism), ''],
        ['hook', hookLabel(event.name, origin.mechanism, origin.hook), ''],
        ['CPU', event.cpu != null ? 'CPU ' + event.cpu : '—', ''],
        ['task', originContext(event), '']
      ];
    $('event-origin').innerHTML = rows.map(function(row) {
      return '<div class="' + row[2] + '"><small>' + esc(row[0]) + '</small><b title="' + esc(row[1]) + '">' + esc(row[1]) + '</b></div>';
    }).join('');
  }

  function mechanismLabel(value) {
    return value === 'ebpf' ? 'eBPF' : value || '—';
  }

  function select(index) {
    if (!D || !D.events.length) return;
    cursor = Math.max(0, Math.min(D.events.length - 1, index || 0));
    var e = ev();
    var ep = D.episodes[episodeFor(cursor)];
    var phaseStart = ep && ep.indices.length ? ep.indices[0] : 0;
    var phaseEnd = ep && ep.indices.length ? ep.indices[ep.indices.length - 1] : D.events.length - 1;
    var phaseIndex = ep ? ep.indices.indexOf(cursor) + 1 : cursor + 1;
    $('scrub').min = phaseStart;
    $('scrub').max = phaseEnd;
    $('scrub').value = cursor;
    $('counter').textContent = phaseIndex + ' / ' + (ep ? ep.indices.length : D.events.length);
    renderRoadmap();
    renderIRQ(e);
    renderDMA(e);
    renderNotebook(e);
    renderExec(e);
  }
  const transport = playback(() => {
    if (!D.events || cursor >= D.events.length - 1) return false;
    select(cursor + 1);
  });

  function togglePlay() {
    transport.toggle();
  }

  function wireToolbar() {
    $('next').addEventListener('click', function() {
      select(cursor + 1)
    });
    $('prev').addEventListener('click', function() {
      select(cursor - 1)
    });
    $('play').addEventListener('click', togglePlay);
    $('scrub').addEventListener('input', function(e) {
      select(+e.target.value)
    });
    document.addEventListener('keydown', function(e) {
      if (e.key === 'ArrowLeft') select(cursor - 1);
      if (e.key === 'ArrowRight') select(cursor + 1);
      if (e.key === ' ') {
        e.preventDefault();
        togglePlay()
      }
    });
  }

  /* ---- load ------------------------------------------------------------- */

  mountView('virt-io', async capture => {
    var snaps = parseBpf(capture),
      trace = parseTrace(capture);
    if (!snaps.length) throw Error('no eBPF snapshots parsed');
    D.events = finalize(buildEvents(snaps, trace));
    D.episodes = deriveEpisodes(D.events);
    D.dmaTo = null;
    D.dmaFrom = null;
    D.events.forEach(function(x, i) {
      if (x.name !== 'device_dma_transfer') return;
      if (x.dma_dir === 'to_device' && D.dmaTo == null) D.dmaTo = i;
      if (x.dma_dir === 'from_device' && D.dmaFrom == null) D.dmaFrom = i;
    });
    $('dma-src-sub').textContent = (D.dmaTo != null ? 'guest source · seq ' + (D.dmaTo + 1) : 'guest source');
    $('dma-dst-sub').textContent = (D.dmaFrom != null ? 'guest receive · seq ' + (D.dmaFrom + 1) + ' · echo' : 'guest receive');
    $('dma-xfer').textContent = D.meta.dma_xfer_size + ' B / transfer';
    $('scrub').max = D.events.length - 1;
    $('status').lastElementChild.textContent = snaps.length + ' eBPF · ' + trace.length + ' trace · ' + D.episodes.length + ' phases';
    if (!document.body.dataset.bound) {
      wireToolbar();
      document.body.dataset.bound = 'true';
    }
    select(0);
  });
})();
