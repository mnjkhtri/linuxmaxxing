import {
  hookLabel,
  mountView,
  observation,
  playback
} from '../../common.js';
(function() {
  "use strict";

  var assignmentRecords = [];
  var lifecycleRecords = [];
  var ebpfRecords = [];
  var guestRecords = [];
  var clockAnchors = {};
  var mapTransactions = [];
  var selectedTransaction = 0;
  var workloadTransaction = -1;
  var selectedChunk = 0;
  var phaseItems = [];
  var visibleLanes = [];
  var lanePositions = {};
  var eventsByPhase = {};
  var selectedIndex = 0;
  var transport;
  var selectedPhase = "S";
  var eventScope = "workload";
  var workloadEventsByPhase = {};
  var LANE = {
    GUEST: 0,
    NET: 1,
    DMA: 2,
    QEMU: 3,
    KVM: 4,
    VFIO: 5,
    MEMORY: 6,
    IOMMU: 7,
    NIC: 8
  };
  var actors = [{
    id: "guest",
    role: "GUEST",
    name: "DRIVER",
    scope: "guest"
  }, {
    id: "guest-net",
    role: "GUEST",
    name: "NET_RX",
    scope: "guest"
  }, {
    id: "guest-dma",
    role: "GUEST",
    name: "DMA API",
    scope: "guest"
  }, {
    id: "qemu",
    role: "HOST",
    name: "QEMU",
    scope: "outside"
  }, {
    id: "kvm",
    role: "HOST",
    name: "KVM",
    scope: "outside"
  }, {
    id: "vfio",
    role: "HOST",
    name: "VFIO",
    scope: "outside"
  }, {
    id: "memory",
    role: "HOST",
    name: "MM",
    scope: "outside"
  }, {
    id: "iommu",
    role: "HOST",
    name: "IOMMU",
    scope: "outside"
  }, {
    id: "nic",
    role: "DEVICE",
    name: "PCIe NIC",
    scope: "outside"
  }];


  function byId(id) {
    return document.getElementById(id);
  }

  function escapeHtml(value) {
    return String(value == null ? "—" : value).replace(/[&<>"']/g, function(character) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      } [character];
    });
  }

  function eventInfo(record) {
    return record && record.event_info ? record.event_info : {};
  }

  function recordState(record) {
    return record && record.state ? record.state : {};
  }

  function deviceInfo(record) {
    var source = record || assignmentRecords.find(function(candidate) {
      return candidate.host_bdf;
    }) || {};
    var attach = ebpfRecords.find(function(candidate) {
      return candidate.kind === "iommu_device_attach";
    });

    return {
      bdf: source.host_bdf || (attach ? addressInfo(attach).device : null) || "—",
      driver: source.host_driver || "—"
    };
  }

  function addressInfo(record) {
    var info = eventInfo(record);
    var state = recordState(record);
    var address = state.address_space || {};

    return {
      hva: address.hva != null ? address.hva : info.hva,
      gpa: address.gpa != null ? address.gpa : info.gpa,
      iova: address.iova != null ? address.iova : info.iova,
      hpa: address.hpa != null ? address.hpa : info.hpa,
      size: address.size != null ? address.size : info.size,
      returned_size: address.returned_size != null ? address.returned_size : info.returned_size,
      parent_iova: address.parent_iova != null ? address.parent_iova : info.parent_iova,
      parent_size: address.parent_size != null ? address.parent_size : info.parent_size,
      page_count: address.page_count != null ? address.page_count : info.page_count,
      device: state.device || info.device
    };
  }

  function dmaInfo(record) {
    var dma = recordState(record).dma || {};

    return {
      address: dma.address,
      length: dma.length,
      direction: dma.direction,
      completed: dma.completed_descriptors
    };
  }

  function interruptInfo(record) {
    return recordState(record).interrupt || {};
  }

  function executionInfo(record) {
    return recordState(record).execution || {};
  }

  function mechanismLabel(value) {
    return value === "ebpf" ? "eBPF" : value || "—";
  }

  function guestPhaseGroup(record) {
    var phase = executionInfo(record).phase;

    return {
      interface_start: "IXGBE OPEN",
      offline_diag: "OFFLINE DIAG",
      intr_test: "INTR TEST",
      loopback_setup: "LOOPBACK",
      loopback_run: "LOOPBACK",
      interface_restore: "RESTORE OPEN"
    } [phase] || "GUEST";
  }

  function phaseGroupAt(record) {
    var cutoff = anchoredTime(record);
    var phaseRecord = guestRecords.filter(function(candidate) {
      return executionInfo(candidate).phase && executionInfo(candidate).phase !== "none" && anchoredTime(candidate) <= cutoff;
    }).pop();

    return phaseRecord ? guestPhaseGroup(phaseRecord) : "HOST IRQ";
  }

  function isRuntimeInterrupt(record) {
    return Boolean(record) && (record.kind === "guest_irq_handler_entry" || record.kind === "guest_irq_handler_exit" ||
      record.kind === "guest_softirq_raise" || record.kind === "guest_softirq_entry" || record.kind === "guest_napi_poll" ||
      record.kind === "guest_softirq_exit" || record.kind === "kvm_pi_wakeup" || record.kind === "kvm_pi_wakeup_vector" ||
      record.kind === "kvm_pi_sync_pir_to_irr_exit" || record.kind === "vfio_msi_handler_entry" ||
      record.kind === "vfio_msi_handler_exit" || record.kind === "kvm_irqfd_wakeup" ||
      record.kind === "kvm_msi_route" || record.kind === "kvm_apic_accept_irq");
  }

  function mmioInfo(record) {
    return recordState(record).mmio || {};
  }

  function iommuInfo(record) {
    return recordState(record).iommu || {};
  }

  function faultInfo(record) {
    return recordState(record).fault || {};
  }

  // Captures contain host and guest monotonic clocks; compare their aligned wall-clock estimates.
  function compareRecords(left, right) {
    var leftRecord = left.record || left;
    var rightRecord = right.record || right;
    var leftTime = left.alignedTime != null ? left.alignedTime : alignedTime(leftRecord);
    var rightTime = right.alignedTime != null ? right.alignedTime : alignedTime(rightRecord);

    return leftTime < rightTime ? -1 : (leftTime > rightTime ? 1 : leftRecord.seq - rightRecord.seq);
  }

  function alignedTime(record) {
    var canonical = record && record.canonical;
    var domain = canonical && canonical.source && canonical.source.domain;
    var anchor = clockAnchors[domain];

    if (!canonical || !anchor)
      return BigInt(canonical && canonical.timestamp_ns || 0);
    return BigInt(canonical.timestamp_ns) - anchor.monotonic + anchor.realtime;
  }

  function anchoredTime(record) {
    return alignedTime(record);
  }

  function guestEvent(kind) {
    return guestRecords.find(function(record) {
      return record.kind === kind;
    }) || null;
  }

  function numeric(value) {
    if (typeof value === "number")
      return value;
    return Number.parseInt(value || "0", 16);
  }

  function big(value) {
    try {
      return BigInt(value || 0);
    } catch (error) {
      return 0n;
    }
  }

  function formatBytes(value) {
    var bytes = typeof value === "number" ? value : numeric(value);
    var units = ["B", "KiB", "MiB", "GiB"];
    var unit = 0;

    while (bytes >= 1024 && unit < units.length - 1) {
      bytes /= 1024;
      unit++;
    }
    return (bytes >= 10 || Number.isInteger(bytes) ? bytes.toFixed(0) : bytes.toFixed(1)) + " " + units[unit];
  }

  function dmaDirection(value) {
    return {
      0: "BIDIRECTIONAL",
      1: "TO_DEVICE",
      2: "FROM_DEVICE",
      3: "NONE"
    } [value] || null;
  }

  function hexLimit(start, size) {
    return "0x" + (big(start) + big(size)).toString(16);
  }

  function sameRange(left, right) {
    return left.iova === right.iova && left.size === right.size;
  }

  function rangeContains(outerStart, outerSize, innerStart, innerSize) {
    var outerBegin = big(outerStart);
    var outerEnd = outerBegin + big(outerSize);
    var innerBegin = big(innerStart);
    var innerEnd = innerBegin + big(innerSize);

    return big(outerSize) > 0n && big(innerSize) > 0n && outerBegin <= innerBegin && outerEnd >= innerEnd;
  }

  function rangesOverlap(left, right) {
    var leftStart = big(left.iova);
    var leftEnd = leftStart + big(left.size);
    var rightStart = big(right.iova);
    var rightEnd = rightStart + big(right.size);

    return leftStart < rightEnd && rightStart < leftEnd;
  }

  function requestRecords(requestId) {
    return ebpfRecords.filter(function(record) {
      return requestId && eventInfo(record).request_id === requestId;
    });
  }

  function matchingExit(enter, kind) {
    var info = eventInfo(enter);
    var address = addressInfo(enter);

    return ebpfRecords.find(function(record) {
      var candidate = addressInfo(record);
      return record.kind === kind && record.time_ns >= enter.time_ns &&
        ((info.request_id && eventInfo(record).request_id === info.request_id) ||
          (!info.request_id && record.context && enter.context && record.context.tid === enter.context.tid && sameRange(candidate, address)));
    });
  }

  function workloadMapIndex() {
    var dmaRecord = guestEvent("guest_dma_map_exit");
    var dmaAddress;
    var cutoff;
    var lastBoundary;

    if (!dmaRecord || !dmaInfo(dmaRecord).address)
      return -1;
    dmaAddress = dmaInfo(dmaRecord).address;
    // Link the guest-returned IOVA to a successful host VFIO map that covers it.
    // Address coverage is not proof that the device performed a DMA transfer.
    cutoff = Number.POSITIVE_INFINITY;
    lastBoundary = ebpfRecords.filter(function(record) {
      var address = addressInfo(record);
      return (record.kind === "vfio_dma_map_exit" || record.kind === "vfio_dma_unmap_exit") &&
        eventInfo(record).result === 0 && record.time_ns <= cutoff &&
        rangeContains(address.iova, address.size, dmaAddress, "0x1");
    }).pop();
    if (!lastBoundary || lastBoundary.kind !== "vfio_dma_map_exit")
      return -1;
    return mapTransactions.findIndex(function(transaction) {
      return transaction.exit === lastBoundary;
    });
  }

  function workloadChunkIndex(transaction) {
    var dmaRecord = guestEvent("guest_dma_map_exit");
    var dmaAddress = dmaRecord && dmaInfo(dmaRecord).address;

    if (!transaction || !dmaAddress)
      return 0;
    return Math.max(0, transaction.chunks.findIndex(function(record) {
      var address = addressInfo(record);
      return rangeContains(address.iova, address.size, dmaAddress, "0x1");
    }));
  }

  function buildTransactions() {
    mapTransactions = ebpfRecords.filter(function(record) {
      return record.kind === "vfio_dma_map_enter" && eventInfo(record).sample_status !== "invalid_argument";
    }).map(function(enter) {
      var info = eventInfo(enter);
      var address = addressInfo(enter);
      var exit = matchingExit(enter, "vfio_dma_map_exit");
      var related = requestRecords(info.request_id);
      var chunks = ebpfRecords.filter(function(record) {
        var chunk = addressInfo(record);
        return record.kind === "iommu_map" &&
          ((info.request_id && eventInfo(record).request_id === info.request_id) ||
            (!info.request_id && chunk.parent_iova === address.iova && chunk.parent_size === address.size &&
              record.time_ns >= enter.time_ns && (!exit || record.time_ns <= exit.time_ns)));
      });
      var pins = related.filter(function(record) {
        return record.kind.indexOf("vfio_page_pin_") === 0;
      });
      var type1 = related.filter(function(record) {
        return record.kind.indexOf("vfio_type1_map_") === 0;
      });

      return {
        enter: enter,
        exit: exit,
        chunks: chunks,
        pins: pins,
        type1: type1
      };
    });

    workloadTransaction = workloadMapIndex();
    selectedTransaction = workloadTransaction;
    if (selectedTransaction < 0) {
      selectedTransaction = mapTransactions.findIndex(function(transaction) {
        var address = addressInfo(transaction.enter);
        return transaction.exit && eventInfo(transaction.exit).result === 0 && numeric(address.size) >= 0x100000 && transaction.chunks.length > 1;
      });
    }
    if (selectedTransaction < 0)
      selectedTransaction = 0;
    selectedChunk = workloadChunkIndex(mapTransactions[selectedTransaction]);
  }

  function eventLane(record) {
    var canonical = record.canonical || {};
    var domain = canonical.source && canonical.source.domain;
    var kind = record.kind || "";

    if (domain === "guest")
      return LANE.GUEST;
    if (/iommu|irte|interrupt_remap|qi_/.test(kind))
      return LANE.IOMMU;
    if (/vfio|host_owns_device|host_reclaims_device/.test(kind))
      return LANE.VFIO;
    if (/kvm|memory_region/.test(kind))
      return LANE.KVM;
    if (/qemu|capture_|collector_|workload_/.test(kind))
      return LANE.QEMU;
    if (canonical.source && canonical.source.mechanism === "sysfs")
      return LANE.VFIO;
    return LANE.QEMU;
  }

  function eventDetail(record) {
    var info = eventInfo(record);
    var address = addressInfo(record);
    var details = [];

    if (info.request_id && info.request_id !== "0") details.push("req " + info.request_id);
    if (address.iova && address.iova !== "0x0") details.push("IOVA " + address.iova);
    if (address.size && address.size !== "0x0") details.push(formatBytes(address.size));
    if (info.result != null && info.result !== "0") details.push("ret " + info.result);
    if (record.context && record.context.comm) details.push(record.context.comm);
    return details.join(" · ");
  }

  function makeCapturedItem(record, phase) {
    var lane = eventLane(record);
    var canonical = record.canonical || {};
    var domain = canonical.source && canonical.source.domain;
    var item = {
      label: record.kind,
      detail: eventDetail(record),
      group: phase,
      record: record,
      from: lane,
      to: lane,
      scope: domain === "guest" ? "guest" : "outside",
      alignedTime: alignedTime(record),
      captured: true
    };

    return item;
  }

  function workloadBounds() {
    // These are observer-gate timestamps; guest interface-up happens after the begin marker.
    var begin = guestEvent("workload_begin");
    var end = guestEvent("workload_end");

    if (!begin)
      begin = lifecycleRecords.find(function(record) {
        return record.kind === "guest_workload_begin" || (record.kind === "workload_started" && record.canonical.source.domain === "guest");
      });
    if (!end)
      end = lifecycleRecords.find(function(record) {
        return record.kind === "guest_workload_end" || (record.kind === "workload_finished" && record.canonical.source.domain === "guest");
      });
    return { begin: begin && alignedTime(begin), end: end && alignedTime(end) };
  }

  function buildCapturedItems(events) {
    var bounds = workloadBounds();
    var phaseByCode = { S: [], W: [], C: [] };
    var allItems;

    allItems = events.filter(function(event) {
      return !event.kind.startsWith("collector_metadata") && !event.kind.startsWith("collector_summary");
    }).map(function(event) {
      return observation({ origins: new Map([[event.clock_domain, 0n]]) }, event);
    }).sort(compareRecords);
    allItems.forEach(function(record) {
      var time = alignedTime(record);
      var phase = bounds.begin != null && time >= bounds.begin && (bounds.end == null || time <= bounds.end) ? "W" :
        (bounds.begin != null && time > bounds.end ? "C" : "S");
      var item = makeCapturedItem(record, phase);

      phaseByCode[phase].push(item);
    });
    eventsByPhase = phaseByCode;
  }

  function phaseItemsFor(phase) {
    return eventsByPhase[phase] || [];
  }

  function visibleItemsFor(phase) {
    return eventScope === "workload" ? (workloadEventsByPhase[phase] || []) : phaseItemsFor(phase);
  }

  function recordSequence(record) {
    return record && record.canonical ? String(record.canonical.sequence) : null;
  }

  function addRecordSequence(set, record) {
    var sequence = recordSequence(record);
    if (sequence != null)
      set.add(sequence);
  }

  function buildWorkloadScope() {
    var setupSequences = new Set();
    var cleanupSequences = new Set();
    var transaction = mapTransactions[workloadTransaction];
    var workloadDma = guestEvent("guest_dma_map_exit");
    var dmaAddress = workloadDma && dmaInfo(workloadDma).address;
    var region = transaction && matchingKvmRegion(transaction);
    var regionExit = region && matchingExit(region, "kvm_memory_region_exit");
    var route = postedInterruptRoute();
    var bounds = workloadBounds();
    var lifecycleSetup = ["host_owns_device", "vfio_bound", "qemu_started", "qemu_attached", "guest_visible", "iommu_domain_attach_enter", "iommu_domain_attach_exit", "iommu_device_attach", "workload_started", "guest_workload_begin"];
    var lifecycleCleanup = ["guest_workload_end", "workload_finished", "cleanup_begin", "qemu_stopped", "host_reclaims_device"];

    capturedRecords().forEach(function(record) {
      if (lifecycleSetup.indexOf(record.kind) >= 0)
        addRecordSequence(setupSequences, record);
      if (lifecycleCleanup.indexOf(record.kind) >= 0)
        addRecordSequence(cleanupSequences, record);
    });

    // Setup is the linked ownership + KVM slot + VFIO map path, not every QEMU startup event.
    if (transaction) {
      [transaction.enter, transaction.exit].concat(transaction.chunks, transaction.pins, transaction.type1).forEach(function(record) {
        addRecordSequence(setupSequences, record);
      });
    }
    [region, regionExit].forEach(function(record) {
      addRecordSequence(setupSequences, record);
    });
    if (route) {
      [route.enter, route.exit, route.allocation, route.activation, route.message, route.update].forEach(function(record) {
        addRecordSequence(setupSequences, record);
      });
    }

    if (dmaAddress && bounds.end != null) {
      ebpfRecords.filter(function(record) {
        var address = addressInfo(record);
        return record.kind === "vfio_dma_unmap_enter" && anchoredTime(record) >= bounds.end &&
          rangeContains(address.iova, address.size, dmaAddress, "0x1");
      }).forEach(function(enter) {
        requestRecords(eventInfo(enter).request_id).forEach(function(record) {
          addRecordSequence(cleanupSequences, record);
        });
      });
    }

    workloadEventsByPhase = { S: [], W: [], C: [] };
    eventsByPhase.S.forEach(function(item) {
      if (setupSequences.has(recordSequence(item.record)))
        workloadEventsByPhase.S.push(item);
    });
    eventsByPhase.W.forEach(function(item) {
      var source = item.record.canonical.source || {};
      var inWorkload = bounds.begin == null || bounds.end == null ||
        (item.alignedTime >= bounds.begin && item.alignedTime <= bounds.end);
      var marker = source.domain === "guest" &&
        (item.record.kind === "workload_started" || item.record.kind === "workload_finished");

      if (inWorkload || marker)
        workloadEventsByPhase.W.push(item);
    });
    // Cleanup is brief; keep its linked events at the end of the workload phase.
    eventsByPhase.C.forEach(function(item) {
      if (cleanupSequences.has(recordSequence(item.record)))
        workloadEventsByPhase.W.push(Object.assign({}, item, { group: "W" }));
    });
    workloadEventsByPhase.W.sort(compareRecords);
  }

  function capturedRecords() {
    return Object.keys(eventsByPhase).reduce(function(records, phase) {
      return records.concat(eventsByPhase[phase].map(function(item) { return item.record; }));
    }, []);
  }

  function candidateAttach() {
    return ebpfRecords.find(function(record) {
      return record.kind === "iommu_device_attach";
    });
  }

  function matchingKvmRegion(transaction) {
    var mapping = transaction ? addressInfo(transaction.enter) : {};
    // Match the earlier KVM slot by its host-virtual backing range, not event proximity alone.
    var candidates = ebpfRecords.filter(function(record) {
      var memory = addressInfo(record);
      return record.kind === "kvm_memory_region_enter" && record.time_ns <= transaction.enter.time_ns &&
        rangeContains(memory.hva, memory.size, mapping.hva, mapping.size);
    });

    return candidates[candidates.length - 1] || null;
  }

  function matchingUnmap(transaction) {
    var mapping = transaction ? addressInfo(transaction.enter) : {};
    var after = transaction && transaction.exit ? transaction.exit.time_ns : transaction.enter.time_ns;
    var enters = ebpfRecords.filter(function(record) {
      return record.kind === "vfio_dma_unmap_enter" && record.time_ns >= after &&
        eventInfo(record).sample_status === "complete" && rangesOverlap(addressInfo(record), mapping);
    });
    var enter = enters[0];
    var requestId = enter && eventInfo(enter).request_id;
    var related = requestRecords(requestId);

    return enter ? {
      enter: enter,
      unmaps: related.filter(function(record) {
        return record.kind === "iommu_unmap";
      }),
      invalidations: related.filter(function(record) {
        return record.kind === "iommu_iotlb_invalidate";
      }),
      qi: related.filter(function(record) {
        return record.kind === "iommu_qi_submit" || record.kind === "iommu_qi_complete";
      }),
      unpins: related.filter(function(record) {
        return record.kind.indexOf("vfio_page_unpin_") === 0;
      }),
      exit: related.find(function(record) {
        return record.kind === "vfio_dma_unmap_exit";
      })
    } : null;
  }

  function message(group, label, detail, from, to, record, architectural, scope, orderRecord) {
    var domain = scope || (record && record.source === "guest-ebpf" ? "guest" : "outside");

    return {
      group: group,
      label: label,
      detail: detail,
      from: from,
      to: to,
      record: record || null,
      orderRecord: orderRecord || record || null,
      architectural: Boolean(architectural),
      scope: domain
    };
  }

  function postedInterruptRoute() {
    // Join VFIO IRQ_SET, IRTE/MSI programming, and the KVM posted-interrupt update by IRQ and time.
    var update = ebpfRecords.find(function(record) {
      return record.kind === "kvm_pi_irte_update" && interruptInfo(record).posted;
    });
    var irq = update && interruptInfo(update).irq;
    var requests;
    var enter;
    var related;
    var allocation;
    var activation;
    var messageRecord;

    if (!update)
      return null;
    requests = ebpfRecords.filter(function(record) {
      var interrupt = interruptInfo(record);
      return record.kind === "vfio_irq_set_enter" && interrupt.index === 2 && record.time_ns <= update.time_ns;
    });
    enter = requests[requests.length - 1] || null;
    related = enter ? requestRecords(eventInfo(enter).request_id) : [];
    allocation = ebpfRecords.filter(function(record) {
      return record.kind === "irte_alloc" && interruptInfo(record).irq === irq &&
        (!enter || record.time_ns >= enter.time_ns) && record.time_ns <= update.time_ns;
    }).pop() || null;
    activation = ebpfRecords.filter(function(record) {
      return record.kind === "irte_activate" && interruptInfo(record).irq === irq && (!enter || record.time_ns >= enter.time_ns) && record.time_ns <= update.time_ns;
    }).pop() || null;
    messageRecord = ebpfRecords.filter(function(record) {
      return record.kind === "interrupt_remap_msi_message" && interruptInfo(record).irq === irq && (!enter || record.time_ns >= enter.time_ns) && record.time_ns <= update.time_ns;
    }).pop() || null;
    return {
      enter: enter,
      exit: related.find(function(record) {
        return record.kind === "vfio_irq_set_exit";
      }) || null,
      allocation: allocation,
      activation: activation,
      message: messageRecord,
      update: update
    };
  }

  function hostEvent(kind) {
    return ebpfRecords.find(function(record) {
      return record.kind === kind;
    }) || null;
  }

  function phaseAItems() {
    var transaction = mapTransactions[selectedTransaction];
    var selectedMap = transaction && transaction.chunks[selectedChunk];
    var attach = candidateAttach();
    var domainEnter = hostEvent("iommu_domain_attach_enter");
    var domainExit = hostEvent("iommu_domain_attach_exit");
    var kvmEnter = transaction && matchingKvmRegion(transaction);
    var kvmExit = kvmEnter && matchingExit(kvmEnter, "kvm_memory_region_exit");
    var teardown = transaction && matchingUnmap(transaction);
    var route = postedInterruptRoute();
    var preparation = [];
    var mapping = [];
    var irqSetup = [];
    var runtime = [];
    var teardownItems = [];

    if (kvmEnter) {
      preparation.push(message("MEMORY", "KVM_SET_USER_MEMORY_REGION", "slot " + eventInfo(kvmEnter).slot + " · GPA " + addressInfo(kvmEnter).gpa + " · " + formatBytes(addressInfo(kvmEnter).size), LANE.QEMU, LANE.KVM, kvmEnter));
      if (kvmExit)
        preparation.push(message("MEMORY", "ret", "ret " + eventInfo(kvmExit).result, LANE.KVM, LANE.QEMU, kvmExit));
    }
    if (domainEnter)
      preparation.push(message("ATTACH", "domain_attach_iommu", "domain " + iommuInfo(domainEnter).domain + " · unit " + iommuInfo(domainEnter).unit_id, LANE.VFIO, LANE.IOMMU, domainEnter));
    if (domainExit)
      preparation.push(message("ATTACH", "ret", "ret " + eventInfo(domainExit).result, LANE.IOMMU, LANE.VFIO, domainExit));
    if (attach)
      preparation.push(message("ATTACH", "attach_device_to_domain", addressInfo(attach).device, LANE.VFIO, LANE.IOMMU, attach));
    preparation.sort(compareRecords);

    if (transaction) {
      /*
       * iommu:map is a leaf-level tracepoint.  Keep every leaf in the
       * address-space browser, but make the timeline speak in transactions:
       * one VFIO request, one grouped translation step, and its ret.
       */
      mapping = [message("MAP", "VFIO_IOMMU_MAP_DMA", "IOVA " + addressInfo(transaction.enter).iova + " · " + formatBytes(addressInfo(transaction.enter).size), LANE.QEMU, LANE.VFIO, transaction.enter)];
      if (selectedMap) {
        var leafSummary = message("MAP", "IOMMU leaves", transaction.chunks.length + " leaves · selected " + addressInfo(selectedMap).iova, LANE.VFIO, LANE.IOMMU, selectedMap);
        leafSummary.leafSummary = true;
        mapping.push(leafSummary);
      }
      if (transaction.exit)
        mapping.push(message("MAP", "ret", "ret " + eventInfo(transaction.exit).result, LANE.VFIO, LANE.QEMU, transaction.exit));
      mapping.sort(compareRecords);
    }

    if (route && route.allocation) {
      var allocation = interruptInfo(route.allocation);
      irqSetup.push(message("IRQ SETUP", "alloc_irte", "host IRQ " + allocation.irq + " · IRTE " + allocation.irte_index, LANE.VFIO, LANE.IOMMU, route.allocation));
    }
    if (route && route.enter) {
      var irqRequest = interruptInfo(route.enter);
      irqSetup.push(message("IRQ SETUP", "VFIO_DEVICE_SET_IRQS", "MSI-X " + irqRequest.start + " · count " + irqRequest.count, LANE.QEMU, LANE.VFIO, route.enter));
    }
    if (route && route.activation)
      irqSetup.push(message("IRQ SETUP", "intel_irq_remapping_activate", "host IRQ " + interruptInfo(route.activation).irq, LANE.VFIO, LANE.IOMMU, route.activation));
    if (route && route.message)
      irqSetup.push(message("IRQ SETUP", "intel_ir_compose_msi_msg", interruptInfo(route.message).address + " · data " + interruptInfo(route.message).data, LANE.VFIO, LANE.IOMMU, route.message));
    if (route && route.update) {
      var posted = interruptInfo(route.update);
      irqSetup.push(message("IRQ SETUP", "kvm_pi_irte_update", "vCPU " + posted.vcpu_id + " · vector 0x" + Number(posted.vector).toString(16), LANE.KVM, LANE.IOMMU, route.update));
    }
    if (route && route.exit)
      irqSetup.push(message("IRQ SETUP", "ret", "ret " + eventInfo(route.exit).result, LANE.VFIO, LANE.QEMU, route.exit));
    irqSetup.sort(compareRecords);

    var guestIrqEntries = guestRecords.filter(function(record) {
      return record.kind === "guest_irq_handler_entry";
    });
    var guestIrqExits = guestRecords.filter(function(record) {
      return record.kind === "guest_irq_handler_exit";
    });
    var guestNapiPolls = guestRecords.filter(function(record) {
      return record.kind === "guest_napi_poll";
    });

    guestRecords.forEach(function(record) {
      var dma = dmaInfo(record);
      var context = record.context || {};
      var group = guestPhaseGroup(record);
      var mappedDma;
      var translatedChunk;
      var translatedHpa;
      var rxDma;
      var rxChunk;
      var rxHpa;

      if (record.kind === "workload_begin" || record.kind === "workload_end" ||
        record.kind === "guest_irq_handler_entry" || record.kind === "guest_irq_handler_exit" ||
        record.kind === "guest_softirq_raise" || record.kind === "guest_softirq_entry" ||
        record.kind === "guest_napi_poll" || record.kind === "guest_softirq_exit")
        return;
      if (record.kind === "guest_ixgbe_open")
        runtime.push(message(group, "ixgbe_open", "CPU " + context.cpu + " · " + context.comm, LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_ixgbe_diag_entry")
        runtime.push(message(group, "ixgbe_diag_test", "ethtool offline self-test", LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_ixgbe_diag_exit")
        runtime.push(message(group, "ret", "ret " + eventInfo(record).result, LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_ixgbe_close")
        runtime.push(message(group, "ixgbe_close", "CPU " + context.cpu + " · " + context.comm, LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_ixgbe_intr_test_entry")
        runtime.push(message(group, "ixgbe_intr_test", "interrupt diagnostic", LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_ixgbe_intr_test_exit")
        runtime.push(message(group, "ret", "ret " + eventInfo(record).result, LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_ixgbe_loopback_test_entry")
        runtime.push(message(group, "ixgbe_loopback_test", "loopback setup", LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_ixgbe_loopback_test_exit")
        runtime.push(message(group, "ret", "ret " + eventInfo(record).result, LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_nic_run_loopback_entry")
        runtime.push(message(group, "nic_run_loopback_test", "64 TX/RX frames per batch", LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_ixgbe_xmit_entry")
        runtime.push(message(group, "ixgbe_xmit_frame_ring", formatBytes(dma.length) + " skb", LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_dma_map_entry")
        runtime.push(message(group, "dma_map_page_attrs", formatBytes(dma.length) + " · DMA_TO_DEVICE", LANE.GUEST, LANE.DMA, record));
      else if (record.kind === "guest_dma_map_exit")
        runtime.push(message(group, "ret", dma.address + " · " + formatBytes(dma.length), LANE.DMA, LANE.GUEST, record));
      else if (record.kind === "guest_ixgbe_xmit_exit") {
        runtime.push(message(group, "ret", "ret " + eventInfo(record).result, LANE.GUEST, LANE.GUEST, record));
        runtime.push(message(group, "TDT doorbell", "publish TX descriptors", LANE.GUEST, LANE.NIC, null, true, "guest", record));
        mappedDma = guestEvent("guest_dma_map_exit");
        translatedChunk = mappedDma && transaction && transaction.chunks.find(function(chunkRecord) {
          var chunk = addressInfo(chunkRecord);
          return big(dmaInfo(mappedDma).address) >= big(chunk.iova) && big(dmaInfo(mappedDma).address) < big(chunk.iova) + big(chunk.size);
        });
        if (translatedChunk) {
          translatedHpa = big(addressInfo(translatedChunk).hpa) + big(dmaInfo(mappedDma).address) - big(addressInfo(translatedChunk).iova);
          runtime.push(message(group, "DMA read request", "IOVA " + dmaInfo(mappedDma).address, LANE.NIC, LANE.IOMMU, null, true, "outside", record));
          runtime.push(message(group, "translated read", "HPA 0x" + translatedHpa.toString(16), LANE.IOMMU, LANE.MEMORY, null, true, "outside", record));
        }
        rxDma = guestEvent("guest_dma_sync_for_cpu");
        rxChunk = rxDma && transaction && transaction.chunks.find(function(chunkRecord) {
          var rxRange = addressInfo(chunkRecord);
          return big(dmaInfo(rxDma).address) >= big(rxRange.iova) && big(dmaInfo(rxDma).address) < big(rxRange.iova) + big(rxRange.size);
        });
        if (rxChunk) {
          rxHpa = big(addressInfo(rxChunk).hpa) + big(dmaInfo(rxDma).address) - big(addressInfo(rxChunk).iova);
          runtime.push(message(group, "DMA write request", "RX IOVA " + dmaInfo(rxDma).address, LANE.NIC, LANE.IOMMU, null, true, "outside", record));
          runtime.push(message(group, "translated write", "HPA 0x" + rxHpa.toString(16), LANE.IOMMU, LANE.MEMORY, null, true, "outside", record));
        }
      } else if (record.kind === "guest_ixgbe_clean_entry")
        runtime.push(message(group, "ixgbe_clean_test_rings", "poll TX DD and RX length", LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_dma_unmap")
        runtime.push(message(group, "dma_unmap_page_attrs", dma.address + " · " + formatBytes(dma.length), LANE.GUEST, LANE.DMA, record));
      else if (record.kind === "guest_dma_sync_for_cpu")
        runtime.push(message(group, "dma_sync_single_for_cpu", dma.address + " · " + formatBytes(dma.length), LANE.GUEST, LANE.DMA, record));
      else if (record.kind === "guest_dma_sync_for_device")
        runtime.push(message(group, "dma_sync_single_for_device", dma.address + " · " + formatBytes(dma.length), LANE.GUEST, LANE.DMA, record));
      else if (record.kind === "guest_ixgbe_clean_exit")
        runtime.push(message(group, "ret", dma.completed + " completed descriptors", LANE.GUEST, LANE.GUEST, record));
      else if (record.kind === "guest_nic_run_loopback_exit")
        runtime.push(message(group, "ret", "ret " + eventInfo(record).result, LANE.GUEST, LANE.GUEST, record));
    });

    if (guestIrqEntries.length) {
      var irqAnchor = guestIrqExits[guestIrqExits.length - 1] || guestIrqEntries[guestIrqEntries.length - 1];
      var irqSummary = message("IRQ", "guest IRQ activity", guestIrqEntries.length + " entry · " + guestIrqExits.length + " ret · " + guestNapiPolls.length + " NAPI", LANE.GUEST, LANE.GUEST, guestIrqEntries[0], false, "guest", irqAnchor);
      irqSummary.summary = true;
      runtime.push(irqSummary);
    }

    ebpfRecords.filter(function(record) {
      return record.kind === "kvm_pi_wakeup" || record.kind === "kvm_pi_wakeup_vector" || record.kind === "kvm_pi_sync_pir_to_irr_exit" ||
        record.kind === "vfio_msi_handler_entry" || record.kind === "vfio_msi_handler_exit" ||
        record.kind === "kvm_irqfd_wakeup" || record.kind === "kvm_msi_route" || record.kind === "kvm_apic_accept_irq";
    }).forEach(function(record) {
      var interrupt = interruptInfo(record);
      var context = record.context || {};
      var group = phaseGroupAt(record);

      if (record.kind === "kvm_pi_wakeup")
        runtime.push(message(group, "pi_wakeup_handler", "CPU " + context.cpu + " · " + (interrupt.wakeup_count ? "wake vCPU " + interrupt.vcpu_id : "no vCPU wake"), LANE.KVM, LANE.KVM, record));
      else if (record.kind === "kvm_pi_wakeup_vector")
        runtime.push(message(group, "sysvec_kvm_posted_intr_wakeup_ipi", "CPU " + context.cpu, LANE.KVM, LANE.KVM, record));
      else if (record.kind === "kvm_pi_sync_pir_to_irr_exit")
        runtime.push(message(group, "vmx_sync_pir_to_irr", "vCPU " + interrupt.vcpu_id + " · vector 0x" + Number(interrupt.vector).toString(16), LANE.KVM, LANE.KVM, record));
      else if (record.kind === "vfio_msi_handler_entry")
        runtime.push(message(group, "vfio_msihandler", "host IRQ " + interrupt.irq, LANE.NIC, LANE.VFIO, record));
      else if (record.kind === "vfio_msi_handler_exit")
        runtime.push(message(group, "ret", "ret " + eventInfo(record).result, LANE.VFIO, LANE.NIC, record));
      else if (record.kind === "kvm_irqfd_wakeup")
        runtime.push(message(group, "irqfd_wakeup", "eventfd notification", LANE.VFIO, LANE.KVM, record));
      else if (record.kind === "kvm_msi_route")
        runtime.push(message(group, "kvm_msi_set_irq", "vector " + interrupt.vector, LANE.VFIO, LANE.KVM, record));
      else
        runtime.push(message(group, "kvm_apic_accept_irq", "APIC " + interrupt.apic_id + " · vector " + interrupt.vector, LANE.KVM, LANE.GUEST, record));
    });
    runtime.sort(compareRecords);

    if (teardown) {
      var selectedUnmap = teardown.unmaps.find(function(record) {
        return selectedMap && sameRange(addressInfo(record), addressInfo(selectedMap));
      }) || teardown.unmaps[0];
      var qiSubmits = teardown.qi.filter(function(record) {
        return record.kind === "iommu_qi_submit";
      });
      var qiCompletions = teardown.qi.filter(function(record) {
        return record.kind === "iommu_qi_complete";
      });

      teardownItems = [message("TEARDOWN", "VFIO_IOMMU_UNMAP_DMA", "IOVA " + addressInfo(teardown.enter).iova + " · " + formatBytes(addressInfo(teardown.enter).size), LANE.QEMU, LANE.VFIO, teardown.enter)];
      if (selectedUnmap) {
        var unmapSummary = message("TEARDOWN", "IOMMU leaves", teardown.unmaps.length + " leaves removed", LANE.VFIO, LANE.IOMMU, selectedUnmap);
        unmapSummary.leafSummary = true;
        teardownItems.push(unmapSummary);
      }
      if (qiSubmits.length)
        teardownItems.push(message("IOTLB", "submit QI", qiSubmits.length + " queued invalidations", LANE.IOMMU, LANE.IOMMU, qiSubmits[0]));
      if (qiCompletions.length)
        teardownItems.push(message("IOTLB", "QI completion", qiCompletions.length + " complete", LANE.IOMMU, LANE.IOMMU, qiCompletions[qiCompletions.length - 1]));
      if (teardown.exit)
        teardownItems.push(message("TEARDOWN", "ret", "ret " + eventInfo(teardown.exit).result, LANE.VFIO, LANE.QEMU, teardown.exit));
      teardownItems.sort(compareRecords);
    }
    return preparation.concat(mapping, irqSetup, runtime, teardownItems);
  }


  function titleFor(record) {
    var titles = {
      host_owns_device: "host owns NIC",
      vfio_bound: "bind vfio-pci",
      qemu_started: "QEMU starts",
      qemu_attached: "QEMU attaches NIC",
      guest_visible: "guest sees NIC",
      guest_workload_begin: "guest workload",
      guest_workload_end: "workload ret",
      host_reclaims_device: "host reclaims NIC",
      iommu_device_attach: "attach requester",
      kvm_memory_region_enter: "KVM_SET_USER_MEMORY_REGION",
      kvm_memory_region_exit: "memslot result",
      vfio_dma_map_enter: "VFIO_IOMMU_MAP_DMA",
      vfio_type1_map_enter: "validate map request",
      vfio_page_pin_enter: "pin backing pages",
      vfio_page_pin_exit: "page-pin result",
      iommu_map: "iommu:map",
      vfio_type1_map_exit: "type1 map result",
      vfio_dma_map_exit: "map result",
      vfio_dma_unmap_enter: "VFIO_IOMMU_UNMAP_DMA",
      iommu_unmap: "iommu:unmap",
      vfio_page_unpin_enter: "release pinned pages",
      vfio_page_unpin_exit: "page-unpin result",
      vfio_dma_unmap_exit: "unmap result",
      vfio_irq_set_enter: "VFIO_DEVICE_SET_IRQS",
      vfio_irq_set_exit: "VFIO IRQ result",
      irte_alloc: "allocate IRTE",
      irte_activate: "activate IRTE",
      interrupt_remap_msi_message: "compose remappable MSI",
      kvm_pi_irte_update: "target IRTE to vCPU",
      guest_ixgbe_open: "ixgbe_open",
      guest_ixgbe_close: "ixgbe_close",
      guest_irq_handler_entry: "irq_handler_entry",
      guest_irq_handler_exit: "irq_handler_exit",
      guest_ixgbe_diag_entry: "ixgbe_diag_test",
      guest_ixgbe_diag_exit: "ixgbe_diag_test ret",
      guest_ixgbe_intr_test_entry: "ixgbe_intr_test",
      guest_ixgbe_intr_test_exit: "ixgbe_intr_test ret",
      guest_ixgbe_loopback_test_entry: "ixgbe_loopback_test",
      guest_ixgbe_loopback_test_exit: "ixgbe_loopback_test ret",
      guest_softirq_raise: "softirq_raise",
      guest_softirq_entry: "softirq_entry",
      guest_napi_poll: "napi_poll",
      guest_softirq_exit: "softirq_exit",
      kvm_pi_wakeup: "pi_wakeup_handler"
    };

    return titles[record.kind] || record.kind.replace(/_/g, " ");
  }

  function renderRoadmap() {
    var groups = [{
      phase: "S",
      phaseLabel: "PHASE A",
      label: eventScope === "workload" ? "WORKLOAD SETUP" : "SETUP",
      items: visibleItemsFor("S")
    }, {
      phase: "W",
      phaseLabel: "PHASE B",
      label: eventScope === "workload" ? "WORKLOAD" : "GUEST WORKLOAD",
      items: visibleItemsFor("W")
    }, {
      phase: "C",
      phaseLabel: "PHASE C",
      label: eventScope === "workload" ? "WORKLOAD CLEANUP" : "TEARDOWN",
      items: visibleItemsFor("C")
    }].filter(function(group) {
      return eventScope !== "workload" || (group.phase !== "C" && group.items.length > 0);
    });

    byId("roadmap").innerHTML = groups.map(function(group) {
      var active = group.phase === selectedPhase;
      return '<button type="button" class="phase-button selector-option' + (active ? " active" : "") + '" data-phase-zone="' + group.phase + '"><span class="selector-kicker">' + group.phaseLabel + '</span><span class="selector-label">' + group.label + '</span></button>';
    }).join("");

    byId("roadmap").querySelectorAll("[data-phase-zone]").forEach(function(zone) {
      zone.onclick = function() {
        selectPhase(zone.dataset.phaseZone);
      };
    });
  }

  function renderEventScope() {
    var workloadCount = ["S", "W", "C"].reduce(function(total, phase) {
      return total + (workloadEventsByPhase[phase] || []).length;
    }, 0);
    var allCount = ["S", "W", "C"].reduce(function(total, phase) {
      return total + phaseItemsFor(phase).length;
    }, 0);

    byId("scope-workload-count").textContent = workloadCount.toLocaleString() + " events";
    byId("scope-all-count").textContent = allCount.toLocaleString() + " events";
    byId("event-scope").querySelectorAll("[data-event-scope]").forEach(function(button) {
      var active = button.dataset.eventScope === eventScope;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
  }

  function currentTransaction() {
    return mapTransactions[selectedTransaction] || null;
  }

  function renderMapSelector() {
    byId("map-select").innerHTML = mapTransactions.map(function(transaction, index) {
      var address = addressInfo(transaction.enter);
      var request = eventInfo(transaction.enter).request_id || "legacy";
      var prefix = index === workloadTransaction ? "workload · " : "";

      return '<option value="' + index + '">' + prefix + 'req ' + request + ' · ' + escapeHtml(address.iova) + ' · ' + escapeHtml(formatBytes(address.size)) + '</option>';
    }).join("");
    byId("map-select").value = String(selectedTransaction);
  }

  function renderChunks() {
    var transaction = currentTransaction();
    var chunks = transaction ? transaction.chunks : [];
    var parent = transaction ? addressInfo(transaction.enter) : {};
    var selected;

    if (selectedChunk >= chunks.length)
      selectedChunk = 0;
    selected = chunks[selectedChunk];
    byId("chunk-caption").textContent = parent.iova ? "VFIO window [" + parent.iova + ", " + hexLimit(parent.iova, parent.size) + ")" : "No captured mapping.";
    byId("chunk-count").textContent = selected ? "MAP " + (selectedChunk + 1) + " / " + chunks.length : "no correlated maps";
    byId("range-start").textContent = parent.iova || "—";
    byId("range-end").textContent = parent.iova ? hexLimit(parent.iova, parent.size) + " exclusive" : "—";
    byId("chunk-list").innerHTML = chunks.map(function(record, index) {
      var address = addressInfo(record);
      var title = "IOVA " + address.iova + " → HPA " + address.hpa + " · " + address.size;
      return '<button class="chunk ' + (index === selectedChunk ? "active" : "") + '" type="button" data-chunk="' + index + '" title="' + escapeHtml(title) + '"><b>' + String(index + 1).padStart(2, "0") + '</b><span>' + escapeHtml(formatBytes(address.size)) + '</span></button>';
    }).join("") || '<span class="chunk">No correlated IOMMU maps.</span>';
    byId("map-summary").textContent = transaction ? (selectedTransaction === workloadTransaction ? "workload · " : "") + transaction.chunks.length + " leaves · req " + (eventInfo(transaction.enter).request_id || "legacy") : "no mappings";
    byId("chunk-list").querySelectorAll("[data-chunk]").forEach(function(button) {
      button.onclick = function() {
        selectedChunk = Number(button.dataset.chunk);
        renderChunks();
        renderState(phaseItems[selectedIndex]);
      };
    });
  }

  function renderActors(item) {
    var actorRow = byId("actor-row");

    visibleLanes = [];
    lanePositions = {};
    phaseItems.forEach(function(message) {
      [message.from, message.to].forEach(function(lane) {
        if (Number.isInteger(lane) && lane >= 0 && lane < actors.length && visibleLanes.indexOf(lane) < 0)
          visibleLanes.push(lane);
      });
    });
    visibleLanes.sort(function(a, b) { return a - b; });
    visibleLanes.forEach(function(lane, position) { lanePositions[lane] = position; });
    actorRow.style.setProperty("--actor-count", String(Math.max(visibleLanes.length, 1)));
    actorRow.innerHTML = visibleLanes.map(function(index) {
      var actor = actors[index];
      var active = item && (item.from === index || item.to === index);
      var resource = "";
      var candidate = deviceInfo();
      var transaction = currentTransaction();
      var address = transaction ? addressInfo(transaction.enter) : {};
      var actorName = actor.name;

      if (actor.id === "guest")
        resource = candidate.driver || "NIC driver";
      else if (actor.id === "guest-net")
        resource = "NAPI";
      else if (actor.id === "guest-dma")
        resource = "map / sync";
      else if (actor.id === "qemu")
        resource = "VFIO device";
      else if (actor.id === "kvm")
        resource = "APICv";
      else if (actor.id === "vfio")
        resource = "ownership";
      else if (actor.id === "memory")
        resource = "pinned pages";
      else if (actor.id === "iommu")
        resource = "VT-d";
      else
        resource = "DMA requester";
      return '<div class="lifeline-actor ' + actor.scope + '-domain' + (active ? " active" : "") + '"><small>' + actor.role + '</small><b>' + escapeHtml(actorName) + '</b><span>' + escapeHtml(resource) + '</span></div>';
    }).join("");
    byId("lifeline-lines").innerHTML = visibleLanes.map(function(lane, position) {
      var active = item && (item.from === lane || item.to === lane);
      return '<i class="' + (active ? "active" : "") + '" style="left:' + ((position + 0.5) / visibleLanes.length * 100) + '%"></i>';
    }).join("");
  }

  function renderMessage(item, index) {
    var from = lanePositions[item.from];
    var to = lanePositions[item.to];
    var low;
    var distance;
    var left;
    var width;
    var center;
    var direction;
    var evidence = item.architectural ? " architectural" : " observed";
    var scope = item.scope === "guest" ? " guest-scope" : " outside-scope";
    var style;

    if (from === undefined || to === undefined || !visibleLanes.length)
      return "";
    low = Math.min(from, to);
    distance = Math.abs(to - from);
    left = (low + 0.5) / visibleLanes.length * 100;
    width = distance / visibleLanes.length * 100;
    center = (low + distance / 2 + 0.5) / visibleLanes.length * 100;
    direction = to > from ? " forward" : (to < from ? " reverse" : " self");
    style = distance ? "left:" + left + "%;width:" + width + "%" : "left:" + ((from + 0.5) / visibleLanes.length * 100) + "%";

    if (!distance)
      return '<button class="interaction-row' + (index === selectedIndex ? " current" : "") + evidence + scope + '" type="button" data-message="' + index + '"><i class="local-marker" style="left:' + ((from + 0.5) / visibleLanes.length * 100) + '%"></i><code style="left:' + ((from + 0.5) / visibleLanes.length * 100) + '%" title="' + escapeHtml(item.detail) + '">' + escapeHtml(item.label) + '</code></button>';
    return '<button class="interaction-row' + (index === selectedIndex ? " current" : "") + evidence + scope + '" type="button" data-message="' + index + '"><i class="message-line' + direction + '" style="' + style + '"><i></i></i><code style="left:' + center + '%" title="' + escapeHtml(item.detail) + '">' + escapeHtml(item.label) + '</code></button>';
  }

  function mapPermissions(flags) {
    var permissions = [];

    if (flags & 1)
      permissions.push("READ");
    if (flags & 2)
      permissions.push("WRITE");
    return permissions.join(" · ") || "NONE";
  }

  function stateRow(label, value, detail) {
    return '<div class="state-row"><span>' + escapeHtml(label) + '</span><b>' + escapeHtml(value) + '</b>' + (detail ? '<small>' + escapeHtml(detail) + '</small>' : "") + '</div>';
  }

  function renderState(item) {
    var transaction = currentTransaction();
    var parent = transaction ? addressInfo(transaction.enter) : {};
    var chunkRecord = transaction && transaction.chunks[selectedChunk];
    var chunk = chunkRecord ? addressInfo(chunkRecord) : {};
    var domainRecord = hostEvent("iommu_domain_attach_exit") || hostEvent("iommu_domain_attach_enter");
    var domain = iommuInfo(domainRecord);
    var route = postedInterruptRoute();
    var selectedRecord = item && item.record;
    var semanticRecord = selectedRecord || (item && item.architectural ? item.orderRecord : null);
    var selectedExecution = executionInfo(semanticRecord);
    var stateAnchor = item && (item.orderRecord || selectedRecord);
    var stateCutoff = stateAnchor ? anchoredTime(stateAnchor) : 0n;
    var reached = function(record) {
      return Boolean(record) && anchoredTime(record) <= stateCutoff;
    };
    var faults = ebpfRecords.filter(function(record) {
      return record.kind === "iommu_page_fault" && reached(record);
    });
    var guestCutoff = stateCutoff;
    var guestSeen = guestRecords.filter(function(record) {
      return record.kind !== "workload_begin" && record.kind !== "workload_end" && anchoredTime(record) <= guestCutoff;
    });
    var group = item ? item.group : "MAP";
    var rows = [];
    var status = "OBSERVED";
    var title = "DMA ADDRESS SPACE";
    var caption = "Selected VFIO window and its VT-d translation state.";
    var addressGroups = ["MEMORY", "ATTACH", "MAP", "TEARDOWN", "IOTLB", "S", "W", "C"];
    var showMap = addressGroups.indexOf(group) >= 0 && !isRuntimeInterrupt(semanticRecord);

    if (group === "SETUP") {
      var setupKind = semanticRecord && semanticRecord.kind;
      var setupCandidate = deviceInfo(semanticRecord);
      var setupOwner = {
        host_owns_device: "HOST DRIVER",
        vfio_bound: "VFIO-PCI",
        qemu_started: "QEMU / KVM",
        qemu_attached: "QEMU / KVM",
        guest_visible: "GUEST"
      }[setupKind] || "—";

      title = "PASS-THROUGH SETUP";
      caption = "One physical NIC moves from the host into the guest path.";
      status = setupOwner;
      rows.push(stateRow("DEVICE", setupCandidate.bdf || "—", setupCandidate.interface || "physical PCIe function"));
      rows.push(stateRow("OWNER", setupOwner, item ? item.detail : "—"));
      rows.push(stateRow("NEXT", setupKind === "guest_visible" ? "DMA remapping" : "continue setup", "select the next boundary"));
    } else if (group === "RESTORE") {
      var candidate = deviceInfo(semanticRecord);

      title = "OWNERSHIP RESTORED";
      caption = "The physical function returns to its host driver.";
      status = "HOST";
      rows.push(stateRow("DEVICE", candidate.bdf || "—", candidate.interface || "PCIe function"));
      rows.push(stateRow("OWNER", "HOST", candidate.driver ? candidate.driver + " bound" : "host driver restored"));
      rows.push(stateRow("VFIO", "released", "guest access ended"));
    } else if (group.indexOf("IRQ") >= 0 || isRuntimeInterrupt(semanticRecord)) {
      var routeEnter = route && reached(route.enter) ? route.enter : null;
      var routeExit = route && reached(route.exit) ? route.exit : null;
      var routeUpdate = route && reached(route.update) ? route.update : null;
      var routeAllocation = route && reached(route.allocation) ? route.allocation : null;
      var routeMessage = route && reached(route.message) ? route.message : null;
      var routeInterrupt = interruptInfo(routeUpdate);
      var allocation = interruptInfo(routeAllocation);
      var messageState = interruptInfo(routeMessage);
      var guestEntries = guestSeen.filter(function(record) {
        return record.kind === "guest_irq_handler_entry";
      });
      var guestExits = guestSeen.filter(function(record) {
        return record.kind === "guest_irq_handler_exit";
      });
      var wakeEvents = ebpfRecords.filter(function(record) {
        return record.kind === "kvm_pi_wakeup" && reached(record);
      });
      var wakeCalls = wakeEvents.reduce(function(total, record) {
        return total + (interruptInfo(record).wakeup_count || 0);
      }, 0);
      var wakeVcpu0 = wakeEvents.filter(function(record) {
        return interruptInfo(record).wakeup_count && interruptInfo(record).vcpu_id === 0;
      }).length;
      var wakeVcpu1 = wakeEvents.filter(function(record) {
        return interruptInfo(record).wakeup_count && interruptInfo(record).vcpu_id === 1;
      }).length;
      var episodeRecords = selectedExecution.episode_id ? guestSeen.filter(function(record) {
        return executionInfo(record).episode_id === selectedExecution.episode_id;
      }) : [];
      var episodeEntry = episodeRecords.find(function(record) {
        return record.kind === "guest_irq_handler_entry";
      });
      var episodeNapi = episodeRecords.find(function(record) {
        return record.kind === "guest_napi_poll";
      });
      var episodeSoftirq = episodeRecords.find(function(record) {
        return record.kind === "guest_softirq_entry";
      });

      title = "INTERRUPT REMAPPING";
      caption = selectedExecution.episode_id ? "Configured posted route and the selected guest IRQ episode." : "Configured route and observed host posted-interrupt wakeups.";
      status = selectedExecution.episode_id ? "EPISODE " + selectedExecution.episode_id : (routeUpdate ? (routeInterrupt.posted ? "POSTED" : "CONFIGURED") : "CONFIGURING");
      rows.push(stateRow("VFIO ROUTE", routeEnter ? "MSI-X " + interruptInfo(routeEnter).start + " · count " + interruptInfo(routeEnter).count : "—", routeExit ? "VFIO_DEVICE_SET_IRQS · ret " + eventInfo(routeExit).result : ""));
      rows.push(stateRow("IRTE", routeAllocation ? allocation.irte_index + " · host IRQ " + allocation.irq : "—", messageState.address ? messageState.address + " · data " + messageState.data : ""));
      rows.push(stateRow("POSTED TARGET", routeUpdate ? "vCPU " + routeInterrupt.vcpu_id + " · vector 0x" + Number(routeInterrupt.vector).toString(16) : "—", routeInterrupt.pi_desc_address ? "PI descriptor " + routeInterrupt.pi_desc_address : ""));
      rows.push(stateRow("PI WAKEUP", wakeEvents.length + " handlers · " + wakeCalls + " vCPU wakes", "vCPU 0 " + wakeVcpu0 + " · vCPU 1 " + wakeVcpu1));
      rows.push(stateRow("GUEST EPISODE", episodeEntry ? "#" + selectedExecution.episode_id + " · IRQ " + executionInfo(episodeEntry).irq : guestEntries.length + " entries · " + guestExits.length + " exits", episodeEntry ? executionInfo(episodeEntry).action + " · CPU " + episodeEntry.context.cpu : (guestEntries.length === guestExits.length ? "balanced hard-IRQ boundaries" : "incomplete hard-IRQ pairing")));
      rows.push(stateRow("BOTTOM HALF", episodeSoftirq ? executionInfo(episodeSoftirq).softirq : "—", episodeNapi ? "napi_poll work " + executionInfo(episodeNapi).napi_work + " / budget " + executionInfo(episodeNapi).napi_budget : "no NAPI poll reached yet"));
    } else if (group === "WORKLOAD" || group === "LOOPBACK" || group === "DMA USE" || group === "COMPLETE" || group === "NET") {
      var workloadBegin = lifecycleRecords.find(function(record) {
        return record.kind === "guest_workload_begin";
      });
      var workloadEnd = lifecycleRecords.find(function(record) {
        return record.kind === "guest_workload_end";
      });
      var loopbackBegin = guestEvent("guest_nic_run_loopback_entry");
      var loopbackEnd = guestEvent("guest_nic_run_loopback_exit");
      var mapEnter = guestEvent("guest_dma_map_entry");
      var mapExit = guestEvent("guest_dma_map_exit");
      var map = mapExit ? dmaInfo(mapExit) : (mapEnter ? dmaInfo(mapEnter) : {});
      var guestIrqs = guestRecords.filter(function(record) {
        return record.kind === "guest_irq_handler_entry";
      });
      var guestIrqRets = guestRecords.filter(function(record) {
        return record.kind === "guest_irq_handler_exit";
      });

      title = "GUEST WORKLOAD";
      caption = "Only guest workload evidence captured by the observer is shown here.";
      status = workloadEnd || (loopbackEnd && eventInfo(loopbackEnd).result === 0) ? "PASS" : "IN PROGRESS";
      rows.push(stateRow("COMMAND", workloadBegin && Array.isArray(workloadBegin.command) ? workloadBegin.command.join(" ") : "ethtool loopback", workloadBegin && workloadBegin.interface ? workloadBegin.interface : "not sampled"));
      rows.push(stateRow("LOOPBACK", loopbackBegin ? "entered" : "not sampled", loopbackEnd ? "ret " + eventInfo(loopbackEnd).result : "ret not sampled"));
      rows.push(stateRow("DMA MAP", map.address || "not sampled", map.length ? formatBytes(map.length) + " · observed guest map" : "guest DMA map fields not sampled"));
      rows.push(stateRow("IRQ", guestIrqs.length + " entry · " + guestIrqRets.length + " ret", guestIrqs.length === guestIrqRets.length ? "guest handler boundaries balanced" : "pairing incomplete"));
    } else if (["IXGBE OPEN", "OFFLINE DIAG", "INTR TEST", "RESTORE OPEN"].indexOf(group) >= 0) {
      var phase = selectedExecution.phase || "none";
      var phaseRecords = guestSeen.filter(function(record) {
        return executionInfo(record).phase === phase;
      });
      var phaseIrqs = phaseRecords.filter(function(record) {
        return record.kind === "guest_irq_handler_entry";
      });
      var phaseNapi = phaseRecords.filter(function(record) {
        return record.kind === "guest_napi_poll";
      });
      var phaseWork = phaseNapi.reduce(function(total, record) {
        return total + (executionInfo(record).napi_work || 0);
      }, 0);
      var selectedContext = semanticRecord && semanticRecord.context ? semanticRecord.context : {};

      title = "GUEST DRIVER PHASE";
      caption = "ixgbe diagnostic phase and execution context.";
      status = group;
      rows.push(stateRow("FUNCTION", item ? item.label : "—", semanticRecord ? eventInfo(semanticRecord).hook : ""));
      rows.push(stateRow("PHASE", phase === "none" ? group : phase, "driver phase"));
      rows.push(stateRow("CONTEXT", selectedContext.comm || "—", selectedContext.cpu != null ? "CPU " + selectedContext.cpu + " · PID " + selectedContext.pid : ""));
      rows.push(stateRow("IRQ EPISODES", phaseIrqs.length, phaseIrqs.length ? phaseIrqs.map(function(record) {
        return "#" + executionInfo(record).episode_id;
      }).join(" · ") : "none observed"));
      rows.push(stateRow("NAPI", phaseNapi.length + " polls · " + phaseWork + " work", phaseNapi.length ? "budget " + executionInfo(phaseNapi[0]).napi_budget + " each" : "no target NAPI poll"));
    } else {
      var teardown = transaction && matchingUnmap(transaction);
      var invalidations = teardown ? teardown.invalidations.filter(reached).length : 0;
      var qiSubmitted = teardown ? teardown.qi.filter(function(record) {
        return record.kind === "iommu_qi_submit" && reached(record);
      }).length : 0;
      var completions = teardown ? teardown.qi.filter(function(record) {
        return record.kind === "iommu_qi_complete" && eventInfo(record).result === 0 && reached(record);
      }).length : 0;
      var parentReady = transaction && reached(transaction.enter);
      var mapReady = transaction && reached(transaction.exit);
      var leafReady = reached(chunkRecord);
      var domainReady = reached(domainRecord);
      var unmapped = teardown && reached(teardown.exit);

      if (group === "IOTLB") {
        title = "IOTLB INVALIDATION";
        caption = "Page-table removal followed by queued invalidation completion.";
        status = completions ? "COMPLETED" : "IN PROGRESS";
      } else if (group === "TEARDOWN" || group === "C") {
        title = "DMA TEARDOWN";
        caption = "Translation removal, cache invalidation, and backing-page release.";
        status = unmapped ? "UNMAPPED" : "TEARING DOWN";
      } else if (group === "MEMORY") {
        status = mapReady ? "REGISTERED" : "REQUESTED";
      } else if (group === "ATTACH") {
        status = domainReady ? "ATTACHED" : "ATTACHING";
      } else {
        status = mapReady ? "MAPPED" : (leafReady ? "TRANSLATING" : "MAPPING");
      }
      rows.push(stateRow("VFIO WINDOW", parentReady ? "[" + parent.iova + ", " + hexLimit(parent.iova, parent.size) + ")" : "—", parentReady && parent.hva ? "HVA " + parent.hva + " · " + mapPermissions(eventInfo(transaction.enter).flags) : ""));
      rows.push(stateRow("IOMMU DOMAIN", domainReady ? domain.domain : "—", domainReady && domain.unit_id != null ? "unit " + domain.unit_id + " · opaque identity" : ""));
      rows.push(stateRow("SELECTED LEAF", leafReady ? chunk.iova + " → " + chunk.hpa : "—", leafReady ? formatBytes(chunk.size) : ""));
      rows.push(stateRow("IOTLB", qiSubmitted + " QI · " + completions + " complete", invalidations ? invalidations + " explicit invalidations" : (teardown && reached(teardown.enter) ? "QI boundary sampled" : (mapReady ? "mapping remains active" : "not mapped"))));
      rows.push(stateRow("PROTECTION", parentReady ? mapPermissions(eventInfo(transaction.enter).flags) : "—", faults.length + " iommu:io_page_fault records"));
    }
    byId("state-title").textContent = title;
    byId("state-caption").textContent = caption;
    byId("state-status").textContent = status;
    byId("state-rows").innerHTML = rows.join("");
    byId("map-picker").classList.toggle("hidden", !showMap);
    byId("state-map-browser").classList.toggle("hidden", !showMap);
  }

  function renderPhaseA() {
    var current = selectedIndex >= 0 ? phaseItems[selectedIndex] : null;

    renderActors(current);
    renderState(current);
    byId("interaction-rows").innerHTML = phaseItems.map(renderMessage).join("");
    byId("interaction-rows").querySelectorAll("[data-message]").forEach(function(button) {
      button.onclick = function() {
        selectRecord(Number(button.dataset.message));
      };
    });
    var selectedRow = byId("interaction-rows").querySelector("[data-message='" + selectedIndex + "']");
    if (selectedRow)
      selectedRow.scrollIntoView({ block: "nearest" });
  }

  function phaseAFields(item) {
    var record = item.record;
    var info = eventInfo(record);
    var address = addressInfo(record);
    var dma = dmaInfo(record);
    var interrupt = interruptInfo(record);
    var iommu = iommuInfo(record);
    var fault = faultInfo(record);
    var mmio = mmioInfo(record);
    var execution = executionInfo(record);
    var context = record && record.context ? record.context : {};

    if (item && item.captured && record && record.canonical) {
      var canonical = record.canonical;
      var source = canonical.source || {};
      var context = canonical.context || {};
      var raw = {
        mechanism: mechanismLabel(source.mechanism),
        hook: source.hook ? hookLabel(record.kind, source.mechanism, source.hook) :
          (source.mechanism === "framework" ? "lifecycle · " + record.kind : record.kind),
        CPU: context.cpu == null ? null : "CPU " + context.cpu,
        task: context.comm ? context.comm + (context.tid == null ? "" : " · TID " + context.tid) :
          (context.tid == null ? null : "TID " + context.tid)
      };

      function includeField(path, value) {
        var key = path.slice(path.lastIndexOf(".") + 1);
        var zeroResult = key === "result" && /(?:_exit|_ret|_complete|_end)$/.test(record.kind);
        var zeroSlot = key === "slot" && record.kind.indexOf("kvm_memory_region") === 0;
        var zeroIndex = key === "index" && record.kind.indexOf("vfio_irq_set_") === 0;
        var zeroBase = (key === "gpa" || key === "iova") &&
          record.kind === "vfio_dma_map_enter" && path.indexOf("state.address_space.") === 0;

        if (value == null || value === "" || value === false || path === "producer_sequence" ||
            path === "event_info.hook" || path === "event_info.correlated" ||
            path === "state.clock_anchor" || path.indexOf("state.clock_anchor.") === 0)
          return false;
        if (path === "event_info.operation" && value === "none")
          return false;
        if (path === "event_info.sample_status" && (value === "complete" || value === "ok"))
          return false;
        if ((value === 0 || value === "0" || value === "0x0") &&
            !zeroResult && !zeroSlot && !zeroIndex && !zeroBase)
          return false;
        return true;
      }

      function flatten(prefix, value, depth) {
        if (!includeField(prefix, value))
          return;
        if (Array.isArray(value)) {
          if (prefix === "command" && value.length > 0 && String(value[0]).indexOf("qemu-system-") >= 0) {
            var summary = [String(value[0]).split("/").pop()];
            for (var index = 1; index < value.length - 1; index++) {
              if (["-machine", "-cpu", "-m", "-smp"].indexOf(value[index]) >= 0) {
                summary.push(String(value[index + 1]));
                index++;
              } else if (value[index] === "-device" && String(value[index + 1]).indexOf("vfio-pci") === 0) {
                summary.push(String(value[index + 1]));
                index++;
              }
            }
            raw.command = summary.join(" · ");
          } else {
            raw[prefix.replace(/^data\./, "")] = value.join(" ");
          }
          return;
        }
        if (typeof value === "object" && depth < 4) {
          Object.keys(value).forEach(function(key) {
            flatten(prefix ? prefix + "." + key : key, value[key], depth + 1);
          });
          return;
        }
        var label = prefix.replace(/^data\./, "").replace(/^event_info\./, "").replace(/^state\./, "");
        label = label.replace(/^address_space\./, "");
        if (label === "operation") label = "op";
        if (label === "request_id") label = "request";
        if (label === "sample_status") label = "sample";
        if (label === "hva" || label === "gpa" || label === "iova" || label === "hpa" ||
            label === "size" || label === "returned_size" || label === "parent_iova" ||
            label === "parent_size" || label === "page_count")
          label = label.toUpperCase();
        raw[label] = String(value);
      }

      Object.keys(canonical.data || {}).forEach(function(key) {
        flatten(key, canonical.data[key], 0);
      });
      return raw;
    }
    if (!record)
      return {
        evidence: "architecture",
        relationship: actors[item.from].name + " → " + actors[item.to].name
      };
    var source = record.canonical && record.canonical.source || {};
    return {
      mechanism: mechanismLabel(source.mechanism || record.source),
      hook: source.mechanism === "framework" ? "lifecycle · " + record.kind : hookLabel(record.kind, source.mechanism || record.source, info.hook || source.hook),
      op: info.operation !== "none" ? info.operation : null,
      request_id: info.request_id || null,
      fd: info.fd || null,
      command: Array.isArray(record.command) ? record.command.join(" ") : (info.command !== "0x0" ? info.command : null),
      slot: record.kind.indexOf("kvm_memory") === 0 ? info.slot : null,
      flags: info.flags || fault.flags || null,
      result: record.result || (/exit|return|complete|end/.test(record.kind) ? info.result : null),
      interface: record.interface || null,
      HVA: address.hva !== "0x0" ? address.hva : null,
      GPA: address.gpa !== "0x0" ? address.gpa : null,
      IOVA: address.iova !== "0x0" || /iommu|vfio_dma/.test(record.kind) ? address.iova : (iommu.iova !== "0x0" ? iommu.iova : fault.iova),
      HPA: address.hpa !== "0x0" ? address.hpa : null,
      size: address.size !== "0x0" ? address.size : (iommu.size !== "0x0" ? iommu.size : null),
      returned_size: address.returned_size !== "0x0" ? address.returned_size : null,
      pages: address.page_count || null,
      device: address.device || fault.device || null,
      driver: fault.driver || null,
      IOMMU_domain: iommu.domain !== "0x0" ? iommu.domain : null,
      IOMMU_unit: iommu.unit !== "0x0" ? iommu.unit : null,
      IOMMU_unit_id: iommu.unit_id || null,
      invalidation_hint: record.kind === "iommu_iotlb_invalidate" ? iommu.invalidation_hint : null,
      mapping_invalidation: record.kind === "iommu_iotlb_invalidate" ? iommu.mapping_invalidation : null,
      QI_descriptors: iommu.qi_count || null,
      QI_options: iommu.qi_options || null,
      DMA: dma.address && dma.address !== "0x0" ? dma.address : null,
      bytes: dma.length || null,
      direction: dmaDirection(dma.direction),
      completed: dma.completed || null,
      episode: execution.episode_id || null,
      phase: execution.phase && execution.phase !== "none" ? execution.phase : null,
      IRQ: interrupt.irq || execution.irq || null,
      IRQ_index: record.kind.indexOf("vfio_irq_set_") === 0 ? interrupt.index : null,
      vector_start: record.kind.indexOf("vfio_irq_set_") === 0 ? interrupt.start : null,
      vector_count: record.kind.indexOf("vfio_irq_set_") === 0 ? interrupt.count : null,
      IRTE: record.kind === "irte_alloc" ? interrupt.irte_index : null,
      GSI: record.kind === "kvm_pi_irte_update" ? interrupt.gsi : null,
      vCPU: /kvm_pi_/.test(record.kind) ? interrupt.vcpu_id : null,
      posted: record.kind === "kvm_pi_irte_update" ? interrupt.posted : null,
      PI_descriptor: record.kind === "kvm_pi_irte_update" ? interrupt.pi_desc_address : null,
      vector: interrupt.vector ? "0x" + Number(interrupt.vector).toString(16) : null,
      action: interrupt.action || null,
      softirq: execution.softirq || null,
      NAPI_work: execution.napi_work != null ? execution.napi_work : null,
      NAPI_budget: execution.napi_budget != null ? execution.napi_budget : null,
      PI_wakeups: record.kind === "kvm_pi_wakeup" ? interrupt.wakeup_count : null,
      MSI_address: record.kind === "interrupt_remap_msi_message" ? interrupt.address : null,
      MSI_data: record.kind === "interrupt_remap_msi_message" ? interrupt.data : null,
      MMIO_GPA: mmio.gpa || null,
      MMIO_value: mmio.value || null,
      MMIO_bytes: mmio.length || null,
      MMIO_access: mmio.type === 2 ? "WRITE" : (mmio.type === 1 ? "READ" : (mmio.type === 0 ? "READ UNSATISFIED" : null)),
      CPU: context.cpu,
      task: context.comm,
      pid: context.pid,
      tid: context.tid,
    };
  }

  function renderInspectorGrid(id, fields) {
    byId(id).innerHTML = Object.keys(fields).filter(function(key) {
      return fields[key] !== undefined && fields[key] !== null && fields[key] !== "";
    }).map(function(key) {
      return '<div><small>' + escapeHtml(key) + '</small><b title="' + escapeHtml(fields[key]) + '">' + escapeHtml(fields[key]) + '</b></div>';
    }).join("");
  }


  function renderInspector(item) {
    var record;
    var fields;
    var origin;

    if (!item) {
      byId("event-origin").innerHTML = "";
      byId("fields").innerHTML = "";
      return;
    }
    record = item.record;
    fields = phaseAFields(item);
    origin = {};
    ["mechanism", "hook", "CPU", "task"].forEach(function(key) {
      if (fields[key] !== undefined && fields[key] !== null && fields[key] !== "")
        origin[key] = fields[key];
      delete fields[key];
    });
    if (item.architectural)
      origin.mechanism = "architecture";
    renderInspectorGrid("event-origin", origin);
    renderInspectorGrid("fields", fields);
  }

  function selectRecord(index) {
    var item;

    if (!phaseItems.length)
      return;
    selectedIndex = Math.max(0, Math.min(phaseItems.length - 1, index));
    item = phaseItems[selectedIndex];
    renderPhaseA();
    renderInspector(item);
    renderRoadmap();
    byId("counter").textContent = (selectedIndex + 1).toLocaleString() + " / " + phaseItems.length.toLocaleString();
    byId("scrub").max = Math.max(phaseItems.length - 1, 0);
    byId("scrub").value = selectedIndex;
  }

  function selectPhase(phase) {
    var scopeItems;

    if (transport)
      transport.stop();
    selectedPhase = phase;
    scopeItems = visibleItemsFor(phase);
    byId("lifelines-caption").textContent = "Phase " + ({ S: "A", W: "B", C: "C" }[phase]);
    phaseItems = scopeItems;
    renderMapSelector();
    renderChunks();
    selectedIndex = 0;
    renderEventScope();
    selectRecord(0);
  }

  function selectEventScope(scope) {
    var current = phaseItems[selectedIndex];
    var sequence = current && recordSequence(current.record);
    var phase = selectedPhase;
    var available;

    eventScope = scope;
    available = ["S", "W", "C"].filter(function(candidate) {
      return visibleItemsFor(candidate).length > 0;
    });
    if (available.indexOf(phase) < 0)
      phase = available.indexOf("W") >= 0 ? "W" : (available[0] || "S");
    selectPhase(phase);
    if (sequence != null) {
      var matchingIndex = phaseItems.findIndex(function(item) {
        return recordSequence(item.record) === sequence;
      });
      if (matchingIndex >= 0)
        selectRecord(matchingIndex);
    }
  }


  byId("prev").onclick = function() {
    selectRecord(selectedIndex - 1);
  };
  byId("next").onclick = function() {
    selectRecord(selectedIndex + 1);
  };
  byId("play").onclick = function() {
    transport.toggle();
  };
  byId("scrub").oninput = function() {
    selectRecord(Number(this.value));
  };
  transport = playback(function() {
    if (!phaseItems.length || selectedIndex >= phaseItems.length - 1)
      return false;
    selectRecord(selectedIndex + 1);
  });
  byId("map-select").onchange = function() {
    selectedTransaction = Number(this.value);
    selectedChunk = selectedTransaction === workloadTransaction ? workloadChunkIndex(mapTransactions[selectedTransaction]) : 0;
    renderChunks();
    renderState(phaseItems[selectedIndex]);
  };
  byId("event-scope").querySelectorAll("[data-event-scope]").forEach(function(button) {
    button.onclick = function() {
      selectEventScope(button.dataset.eventScope);
    };
  });

  mountView('virt-vtd', capture => {
    assignmentRecords = capture.events.filter(e => e.source.mechanism === 'sysfs').map(e => ({
      ...observation(capture, e),
      source: e.source.domain + '-sysfs'
    }));
    lifecycleRecords = capture.events.filter(e => e.source.mechanism === 'framework').map(e => ({
      ...observation(capture, e),
      source: e.source.domain + '-framework'
    }));
    const host = capture.events.filter(e => e.source.mechanism === 'ebpf' && e.source.domain === 'host');
    const guest = capture.events.filter(e => e.source.mechanism === 'ebpf' && e.source.domain === 'guest');
    ebpfRecords = host.filter(e => !e.kind.startsWith('collector_')).map(e => ({
      ...observation(capture, e),
      source: e.source.domain + '-ebpf'
    }));
    guestRecords = guest.filter(e => !e.kind.startsWith('collector_')).map(e => ({
      ...observation(capture, e),
      source: e.source.domain + '-ebpf'
    }));
    if (!ebpfRecords.length || !guestRecords.length) throw Error('VT-d needs host and guest observations');
    clockAnchors = {};
    capture.events.forEach(function(event) {
      var anchor = event.data && event.data.state && event.data.state.clock_anchor;
      if (anchor && anchor.monotonic_ns != null && anchor.realtime_ns != null)
        clockAnchors[event.source.domain] = { monotonic: BigInt(anchor.monotonic_ns), realtime: BigInt(anchor.realtime_ns) };
    });
    buildTransactions();
    buildCapturedItems(capture.events);
    buildWorkloadScope();
    selectPhase('S');
  });
})();
