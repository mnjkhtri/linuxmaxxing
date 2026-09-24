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
  var dmaIovaTransaction = -1;
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
      device: state.device || info.device
    };
  }

  function dmaInfo(record) {
    var dma = recordState(record).dma || {};

    return {
      address: dma.address,
      length: dma.length,
      direction: dma.direction
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
      return markerKind(record.kind) === markerKind(kind);
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

  function dmaIovaMapIndex() {
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

  function dmaIovaChunkIndex(transaction) {
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

    dmaIovaTransaction = dmaIovaMapIndex();
    selectedTransaction = dmaIovaTransaction;
    if (selectedTransaction < 0) {
      selectedTransaction = mapTransactions.findIndex(function(transaction) {
        var address = addressInfo(transaction.enter);
        return transaction.exit && eventInfo(transaction.exit).result === 0 && numeric(address.size) >= 0x100000 && transaction.chunks.length > 1;
      });
    }
    if (selectedTransaction < 0)
      selectedTransaction = 0;
    selectedChunk = dmaIovaChunkIndex(mapTransactions[selectedTransaction]);
  }

  function eventLane(record) {
    var canonical = record.canonical || {};
    var domain = canonical.source && canonical.source.domain;
    var kind = (record.kind || "").toLowerCase();

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

  function markerKind(kind) {
    return {
      workload_begin: "WORKLOAD_BEGIN",
      workload_end: "WORKLOAD_END",
      guest_workload_begin: "GUEST_WORKLOAD_BEGIN",
      guest_workload_end: "GUEST_WORKLOAD_END",
      host_owns_device: "HOST_OWNS_DEVICE",
      vfio_bound: "VFIO_BOUND",
      qemu_started: "QEMU_STARTED",
      qemu_attached: "QEMU_ATTACHED",
      guest_visible: "GUEST_VISIBLE",
      cleanup_begin: "CLEANUP_BEGIN",
      qemu_stopped: "QEMU_STOPPED",
      host_reclaims_device: "HOST_RECLAIMS_DEVICE"
    }[kind] || kind;
  }

  function markerName(kind) {
    return markerKind(kind);
  }

  function makeCapturedItem(record, phase) {
    var lane = eventLane(record);
    var canonical = record.canonical || {};
    var domain = canonical.source && canonical.source.domain;
    var item = {
      label: markerName(record.kind),
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
    var begin = guestEvent("WORKLOAD_BEGIN");
    var end = guestEvent("WORKLOAD_END");
    return { begin: begin && alignedTime(begin), end: end && alignedTime(end) };
  }

  function buildCapturedItems(events) {
    var bounds = workloadBounds();
    var phaseByCode = { S: [], W: [], C: [] };
    var allItems;

    allItems = events.filter(function(event) {
      return !event.kind.startsWith("capture_") && !event.kind.startsWith("collector_") &&
        event.kind !== "workload_started" && event.kind !== "workload_finished";
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
    if (eventScope === "workload")
      return workloadEventsByPhase[phase] || [];
    if (phase === "W")
      return phaseItemsFor("W").concat(phaseItemsFor("C")).sort(compareRecords);
    return phaseItemsFor(phase);
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
    var transaction = mapTransactions[dmaIovaTransaction];
    var workloadDma = guestEvent("guest_dma_map_exit");
    var dmaAddress = workloadDma && dmaInfo(workloadDma).address;
    var region = transaction && matchingKvmRegion(transaction);
    var regionExit = region && matchingExit(region, "kvm_memory_region_exit");
    var route = postedInterruptRoute();
    var bounds = workloadBounds();
    var lifecycleSetup = ["HOST_OWNS_DEVICE", "VFIO_BOUND", "QEMU_STARTED", "QEMU_ATTACHED", "GUEST_VISIBLE", "iommu_domain_attach_enter", "iommu_domain_attach_exit", "iommu_device_attach", "GUEST_WORKLOAD_BEGIN"];
    var lifecycleCleanup = ["GUEST_WORKLOAD_END", "CLEANUP_BEGIN", "QEMU_STOPPED", "HOST_RECLAIMS_DEVICE"];

    capturedRecords().forEach(function(record) {
      if (lifecycleSetup.indexOf(markerKind(record.kind)) >= 0)
        addRecordSequence(setupSequences, record);
      if (lifecycleCleanup.indexOf(markerKind(record.kind)) >= 0)
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

    // Keep observed interrupt-remapping setup in Phase A based on its capture time,
    // independently of the later posted-interrupt route correlation above.
    if (bounds.begin != null) {
      capturedRecords().forEach(function(record) {
        var isRemapRecord = record.kind.indexOf("irte_") === 0 || record.kind.indexOf("interrupt_remap_") === 0;

        if (isRemapRecord && alignedTime(record) < bounds.begin)
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
      var marker = source.domain === "guest" && markerKind(item.record.kind) === "GUEST_WORKLOAD_BEGIN";

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

  function renderRoadmap() {
    var groups = [{
      phase: "S",
      phaseLabel: "PHASE A",
      label: "SETUP",
      items: visibleItemsFor("S")
    }, {
      phase: "W",
      phaseLabel: "PHASE B",
      label: "WORKLOAD",
      items: visibleItemsFor("W")
    }];

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
    var button = byId("event-scope-toggle");
    var active = eventScope === "workload";

    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
    button.setAttribute("aria-label", active ? "Workload-only events; turn off to show all events" : "All events; turn on for workload-only events");
  }

  function currentTransaction() {
    return mapTransactions[selectedTransaction] || null;
  }

  function mapMenuOpen(open, focusOption) {
    var trigger = byId("map-select");
    var menu = byId("map-options");

    trigger.setAttribute("aria-expanded", String(open));
    menu.hidden = !open;
    if (open && focusOption) {
      var option = menu.querySelector(".map-select-option.selected") || menu.querySelector(".map-select-option");
      if (option)
        option.focus();
    }
  }

  function renderMapSelector() {
    var transaction = currentTransaction();
    var address = transaction ? addressInfo(transaction.enter) : null;
    byId("map-select-value").textContent = transaction ? "MAP " + String(selectedTransaction + 1).padStart(2, "0") + " · " + address.iova + " · " + formatBytes(address.size) : "No maps";
    byId("map-select").disabled = !transaction;
    byId("map-options").innerHTML = mapTransactions.map(function(candidate, index) {
      var candidateAddress = addressInfo(candidate.enter);
      var selected = index === selectedTransaction;
      var label = "MAP " + String(index + 1).padStart(2, "0") + " · " + candidateAddress.iova + " · " + formatBytes(candidateAddress.size);
      return '<button class="map-select-option' + (selected ? " selected" : "") + '" type="button" role="option" tabindex="-1" aria-selected="' + selected + '" data-map-index="' + index + '">' + escapeHtml(label) + '</button>';
    }).join("");
    byId("map-options").querySelectorAll("[data-map-index]").forEach(function(option) {
      option.onclick = function() {
        selectedTransaction = Number(option.dataset.mapIndex);
        selectedChunk = selectedTransaction === dmaIovaTransaction ? dmaIovaChunkIndex(mapTransactions[selectedTransaction]) : 0;
        mapMenuOpen(false, false);
        renderMapSelector();
        renderState(phaseItems[selectedIndex]);
        renderChunks();
        byId("map-select").focus();
      };
    });
  }

  function renderChunks() {
    var transaction = currentTransaction();
    var chunks = transaction ? transaction.chunks : [];
    var parent = transaction ? addressInfo(transaction.enter) : {};
    var selected;

    if (selectedChunk >= chunks.length)
      selectedChunk = 0;
    selected = chunks[selectedChunk];
    byId("chunk-caption").textContent = parent.iova ? "Mapped ranges; gaps are unmapped." : "No captured mapping.";
    byId("chunk-count").textContent = selected ? "RANGE " + (selectedChunk + 1) + " / " + chunks.length : "no correlated ranges";
    var chartNode = byId("chunk-list");
    var chartBounds = chartNode.getBoundingClientRect();
    var chartWidth = Math.max(300, Math.round(chartBounds.width || 360));
    var chartHeight = Math.max(320, Math.round(chartBounds.height || 500));
    var plot = {
      top: 54,
      height: chartHeight - 102,
      iovaX: 12,
      iovaWidth: chartWidth * .38,
      hpaX: chartWidth * .62,
      hpaWidth: chartWidth * .36
    };
    var iovaStart = big(parent.iova);
    var iovaEnd = iovaStart + big(parent.size);
    var hpaRanges = chunks.map(function(record) {
      var address = addressInfo(record);
      var start = big(address.hpa);
      return { start: start, end: start + big(address.size) };
    }).filter(function(range) {
      return range.start > 0n && range.end > range.start;
    });
    var hpaStart = hpaRanges.reduce(function(min, range) { return range.start < min ? range.start : min; }, hpaRanges.length ? hpaRanges[0].start : 0n);
    var hpaEnd = hpaRanges.reduce(function(max, range) { return range.end > max ? range.end : max; }, hpaStart);
    var hpaSpan = hpaEnd - hpaStart || 1n;
    var iovaSpan = iovaEnd - iovaStart || 1n;
    var yAt = function(value, origin, span) {
      var offset = big(value) - origin;
      if (offset < 0n) offset = 0n;
      if (offset > span) offset = span;
      return plot.top + Number(offset * 1000000n / span) / 1000000 * plot.height;
    };
    var rangeY = function(start, end, origin, span) {
      var top = yAt(start, origin, span);
      return { y: top, height: Math.max(3, yAt(end, origin, span) - top) };
    };
    var iovaEndLabel = parent.iova ? hexLimit(parent.iova, parent.size) : "—";
    var hpaStartLabel = hpaRanges.length ? "0x" + hpaStart.toString(16) : "—";
    var hpaEndLabel = hpaRanges.length ? "0x" + hpaEnd.toString(16) : "—";
    var svg = '<svg class="iommu-map" viewBox="0 0 ' + chartWidth + ' ' + chartHeight + '" role="img" aria-label="Vertical IOVA and HPA ranges connected by IOMMU mappings"><defs><marker id="map-arrow" viewBox="0 0 6 6" refX="5" refY="3" markerWidth="5" markerHeight="5" orient="auto"><path d="M0 0 L6 3 L0 6 Z" class="map-arrowhead"/></marker></defs>' +
      '<text x="' + plot.iovaX + '" y="17" class="map-lane-label">IOVA</text><text x="' + plot.hpaX + '" y="17" class="map-lane-label">HPA</text>' +
      '<text x="' + plot.iovaX + '" y="39" class="map-bound">' + escapeHtml(parent.iova || "—") + '</text><text x="' + plot.hpaX + '" y="39" class="map-bound">' + escapeHtml(hpaStartLabel) + '</text>' +
      '<text x="' + (plot.iovaX + plot.iovaWidth) + '" y="' + (chartHeight - 20) + '" text-anchor="end" class="map-bound">' + escapeHtml(iovaEndLabel) + '</text><text x="' + (plot.hpaX + plot.hpaWidth) + '" y="' + (chartHeight - 20) + '" text-anchor="end" class="map-bound">' + escapeHtml(hpaEndLabel) + '</text>' +
      '<rect x="' + plot.iovaX + '" y="' + plot.top + '" width="' + plot.iovaWidth + '" height="' + plot.height + '" rx="3" class="map-track"/><rect x="' + plot.hpaX + '" y="' + plot.top + '" width="' + plot.hpaWidth + '" height="' + plot.height + '" rx="3" class="map-track"/>';
    var links = [];
    var mapBlocks = [];

    chunks.forEach(function(record, index) {
      var address = addressInfo(record);
      var iova = big(address.iova);
      var size = big(address.size);
      var iovaRange = rangeY(iova, iova + size, iovaStart, iovaSpan);
      var hpa = big(address.hpa);
      var hasHpa = hpa > 0n && hpa + size > hpa;
      var hpaRange = hasHpa ? rangeY(hpa, hpa + size, hpaStart, hpaSpan) : null;
      var active = index === selectedChunk;
      var label = "IOVA [" + address.iova + ", " + hexLimit(address.iova, address.size) + ")" +
        (hasHpa ? " maps to HPA [" + address.hpa + ", " + hexLimit(address.hpa, address.size) + ")" : " · HPA not sampled") +
        " · " + formatBytes(address.size);

      if (hpaRange)
        links.push('<g class="map-link' + (active ? " active" : "") + '" data-chunk="' + index + '" role="button" tabindex="0" aria-label="' + escapeHtml(label) + '"><line x1="' + (plot.iovaX + plot.iovaWidth) + '" y1="' + (iovaRange.y + iovaRange.height / 2).toFixed(2) + '" x2="' + plot.hpaX + '" y2="' + (hpaRange.y + hpaRange.height / 2).toFixed(2) + '" marker-end="url(#map-arrow)"/></g>');
      mapBlocks.push('<rect x="' + plot.iovaX + '" y="' + iovaRange.y.toFixed(2) + '" width="' + plot.iovaWidth + '" height="' + iovaRange.height.toFixed(2) + '" rx="2" class="map-range iova-range' + (active ? " active" : "") + '" data-chunk="' + index + '" aria-hidden="true"/>');
      if (hpaRange)
        mapBlocks.push('<rect x="' + plot.hpaX + '" y="' + hpaRange.y.toFixed(2) + '" width="' + plot.hpaWidth + '" height="' + hpaRange.height.toFixed(2) + '" rx="2" class="map-range hpa-range' + (active ? " active" : "") + '" data-chunk="' + index + '" aria-hidden="true"/>');
    });
    svg += links.join("") + mapBlocks.join("") + '</svg>';
    chartNode.innerHTML = chunks.length ? svg : '<div class="map-empty">No correlated IOMMU maps.</div>';
    byId("map-summary").textContent = transaction ? "MAP " + String(selectedTransaction + 1).padStart(2, "0") + " · " + transaction.chunks.length + " IOMMU ranges" : "no mappings";
    chartNode.querySelectorAll("[data-chunk]").forEach(function(button) {
      button.onclick = function() {
        selectedChunk = Number(button.dataset.chunk);
        renderState(phaseItems[selectedIndex]);
        renderChunks();
      };
      if (button.getAttribute("role") === "button") {
        button.onkeydown = function(event) {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            button.click();
          }
        };
      }
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

  function stateRow(label, value, detail) {
    return '<div class="state-row"><span>' + escapeHtml(label) + '</span><b>' + escapeHtml(value) + '</b>' + (detail ? '<small>' + escapeHtml(detail) + '</small>' : "") + '</div>';
  }

  function interruptMapNode(label, lines, observed) {
    var values = lines.filter(Boolean).map(function(value) {
      return '<code>' + escapeHtml(value) + '</code>';
    }).join("");
    return '<div class="interrupt-map-node' + (observed ? ' observed' : '') + '"><span>' + escapeHtml(label) + '</span>' + values + '</div>';
  }

  function renderState(item) {
    var transaction = currentTransaction();
    var selectedRecord = item && item.record;
    var stateAnchor = item && (item.orderRecord || selectedRecord);
    var stateCutoff = stateAnchor ? anchoredTime(stateAnchor) : 0n;
    var reached = function(record) {
      return Boolean(record) && anchoredTime(record) <= stateCutoff;
    };
    var latestReached = function(predicate) {
      return ebpfRecords.filter(function(record) {
        return reached(record) && predicate(record);
      }).sort(function(left, right) {
        return anchoredTime(left) < anchoredTime(right) ? -1 : (anchoredTime(left) > anchoredTime(right) ? 1 : left.seq - right.seq);
      }).pop() || null;
    };
    var selectedIrq = selectedRecord && /^(irte_|interrupt_remap_|kvm_pi_irte_update)/.test(selectedRecord.kind) ? interruptInfo(selectedRecord).irq : null;
    var latestIrqEvidence = latestReached(function(record) {
      return record.kind === "irte_activate" || record.kind === "interrupt_remap_msi_message" || record.kind === "kvm_pi_irte_update";
    });
    var routeIrq = selectedIrq && selectedIrq !== "0" ? selectedIrq : (latestIrqEvidence && interruptInfo(latestIrqEvidence).irq);
    var routeEnter = latestReached(function(record) {
      return record.kind === "vfio_irq_set_enter";
    });
    var routeExit = routeEnter && requestRecords(eventInfo(routeEnter).request_id).find(function(record) {
      return record.kind === "vfio_irq_set_exit" && reached(record);
    });
    var routeAllocation = latestReached(function(record) {
      return record.kind === "irte_alloc" && (!routeIrq || interruptInfo(record).irq === routeIrq);
    });
    var routeActivation = latestReached(function(record) {
      return record.kind === "irte_activate" && (!routeIrq || interruptInfo(record).irq === routeIrq);
    });
    var routeMessage = latestReached(function(record) {
      return record.kind === "interrupt_remap_msi_message" && (!routeIrq || interruptInfo(record).irq === routeIrq);
    });
    var routeUpdate = latestReached(function(record) {
      return record.kind === "kvm_pi_irte_update" && (!routeIrq || interruptInfo(record).irq === routeIrq);
    });
    var guestSeen = guestRecords.filter(function(record) {
      return markerKind(record.kind) !== "WORKLOAD_BEGIN" && markerKind(record.kind) !== "WORKLOAD_END" && reached(record);
    });
    var teardown = transaction && matchingUnmap(transaction);
    var routeInterrupt = interruptInfo(routeUpdate);
    var allocation = interruptInfo(routeAllocation);
    var messageState = interruptInfo(routeMessage);
    var guestEntries = guestSeen.filter(function(record) {
      return record.kind === "guest_irq_handler_entry";
    });
    var guestExits = guestSeen.filter(function(record) {
      return record.kind === "guest_irq_handler_exit";
    });
    var invalidations = teardown ? teardown.invalidations.filter(reached).length : 0;
    var qiSubmitted = teardown ? teardown.qi.filter(function(record) {
      return record.kind === "iommu_qi_submit" && reached(record);
    }).length : 0;
    var completions = teardown ? teardown.qi.filter(function(record) {
      return record.kind === "iommu_qi_complete" && eventInfo(record).result === 0 && reached(record);
    }).length : 0;
    var dmaNotes = [];
    if (qiSubmitted || completions || invalidations)
      dmaNotes.push('<span class="dma-note"><b>IOTLB</b><code>' + escapeHtml(qiSubmitted + " QI · " + completions + " done" + (invalidations ? " · " + invalidations + " inv." : "")) + '</code></span>');
    var routeNodes = [
      {
        label: "VFIO IRQ",
        lines: routeEnter ? ["index " + interruptInfo(routeEnter).index + " · " + interruptInfo(routeEnter).start + "+" + interruptInfo(routeEnter).count, routeExit ? "ret " + eventInfo(routeExit).result : ""] : [],
        seen: Boolean(routeEnter)
      },
      {
        label: "HOST / IRTE",
        lines: routeAllocation || routeActivation ? ["IRQ " + (routeIrq || "—")].concat(routeAllocation ? ["IRTE " + allocation.irte_index] : []).concat(routeActivation ? ["active"] : []) : [],
        seen: Boolean(routeAllocation || routeActivation)
      },
      {
        label: "MSI MESSAGE",
        lines: routeMessage ? [messageState.address || "address —", "data " + (messageState.data || "—")] : [],
        seen: Boolean(routeMessage)
      },
      {
        label: "GUEST VECTOR",
        lines: routeUpdate ? ["vCPU " + routeInterrupt.vcpu_id, "vec 0x" + Number(routeInterrupt.vector).toString(16)] : [],
        seen: Boolean(routeUpdate)
      }
    ];
    var routeDiagram = routeNodes.map(function(node, index) {
      var html = interruptMapNode(node.label, node.lines, node.seen);
      if (index < routeNodes.length - 1) {
        var edgeSeen = node.seen && routeNodes[index + 1].seen;
        html += '<span class="interrupt-map-edge' + (edgeSeen ? ' observed' : '') + '" aria-hidden="true">→</span>';
      }
      return html;
    }).join("");
    var irqRows = [
      stateRow("GUEST IRQ", guestEntries.length + " entry · " + guestExits.length + " ret")
    ];

    byId("dma-summary").innerHTML = dmaNotes.join("");
    byId("interrupt-map").innerHTML = routeDiagram;
    byId("interrupt-rows").innerHTML = irqRows.join("");
    byId("interrupt-rows").style.setProperty("--state-row-count", String(irqRows.length));
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
            path === "event_info.hook" ||
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
            label === "parent_size")
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
      hook: source.mechanism === "framework" ? "lifecycle · " + markerName(record.kind) : hookLabel(record.kind, source.mechanism || record.source, info.hook || source.hook),
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
    byId("lifelines-caption").textContent = "Phase " + ({ S: "A", W: "B" }[phase]);
    phaseItems = scopeItems;
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
    available = ["S", "W"].filter(function(candidate) {
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
  byId("map-select").onclick = function() {
    mapMenuOpen(this.getAttribute("aria-expanded") !== "true", true);
  };
  byId("map-select").onkeydown = function(event) {
    if (["ArrowDown", "ArrowUp", "Enter", " "].indexOf(event.key) >= 0) {
      event.preventDefault();
      mapMenuOpen(true, true);
    }
  };
  byId("map-options").onkeydown = function(event) {
    var options = Array.from(this.querySelectorAll(".map-select-option"));
    var index = options.indexOf(document.activeElement);
    var next = index;

    if (event.key === "Escape") {
      event.preventDefault();
      mapMenuOpen(false, false);
      byId("map-select").focus();
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp" || event.key === "Home" || event.key === "End") {
      event.preventDefault();
      if (event.key === "Home") next = 0;
      else if (event.key === "End") next = options.length - 1;
      else next = (index + (event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length;
      if (options[next]) options[next].focus();
    }
  };
  document.addEventListener("pointerdown", function(event) {
    if (!byId("map-picker").contains(event.target))
      mapMenuOpen(false, false);
  });
  byId("map-select").onblur = function(event) {
    if (!byId("map-picker").contains(event.relatedTarget) && !byId("map-options").contains(event.relatedTarget))
      mapMenuOpen(false, false);
  };
  byId("event-scope-toggle").onclick = function() {
    selectEventScope(eventScope === "workload" ? "all" : "workload");
  };
  var mapChartResizeObserver = new ResizeObserver(function(entries) {
    var bounds = entries[0].contentRect;
    if (bounds.width > 0 && bounds.height > 0)
      renderChunks();
  });
  mapChartResizeObserver.observe(byId("chunk-list"));
  window.addEventListener("resize", renderChunks);

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
    renderMapSelector();
    buildCapturedItems(capture.events);
    buildWorkloadScope();
    selectPhase('S');
    byId("status").lastElementChild.textContent = capture.events.length + " records · 2 phases";
  });
})();
