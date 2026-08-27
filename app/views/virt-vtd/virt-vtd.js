(function () {
    "use strict";

    var cacheKey = "?v=" + Date.now();
    var assignmentPath = "../../shared/_captures/virt-vtd.assignment.ndjson" + cacheKey;
    var ebpfPath = "../../shared/_captures/virt-vtd.eBPF.ndjson" + cacheKey;
    var guestPath = "../../shared/_captures/virt-vtd.guest.ndjson" + cacheKey;
    var setupPath = "../../shared/_captures/virt-vtd-setup.txt" + cacheKey;
    var assignmentRecords = [];
    var ebpfRecords = [];
    var guestRecords = [];
    var hostMeta = null;
    var guestMeta = null;
    var setupFacts = {};
    var mapTransactions = [];
    var selectedTransaction = 0;
    var workloadTransaction = -1;
    var selectedChunk = 0;
    var phaseItems = [];
    var selectedIndex = 0;
    var selectedPhase = "A";
    var skippedLines = 0;
    var LANE = { GUEST: 0, NET: 1, DMA: 2, QEMU: 3, KVM: 4, VFIO: 5, MEMORY: 6, IOMMU: 7, NIC: 8 };
    var actors = [
        { id: "guest", role: "GUEST · DRIVER", name: "IXGBE", scope: "guest" },
        { id: "guest-net", role: "GUEST · KERNEL", name: "NET_RX · NAPI", scope: "guest" },
        { id: "guest-dma", role: "GUEST · KERNEL", name: "DMA API", scope: "guest" },
        { id: "qemu", role: "HOST · USERSPACE", name: "QEMU", scope: "outside" },
        { id: "kvm", role: "HOST · KERNEL", name: "KVM · APICv", scope: "outside" },
        { id: "vfio", role: "HOST · KERNEL", name: "VFIO", scope: "outside" },
        { id: "memory", role: "HOST · MEMORY", name: "HOST MM", scope: "outside" },
        { id: "iommu", role: "DMA · TRANSLATION", name: "IOMMU · VT-d", scope: "outside" },
        { id: "nic", role: "PCIe · REQUESTER", name: "PCIe NIC", scope: "outside" }
    ];


    function byId(id) {
        return document.getElementById(id);
    }

    function escapeHtml(value) {
        return String(value == null ? "—" : value).replace(/[&<>"']/g, function (character) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character];
        });
    }

    function parseNdjson(text) {
        return text.split(/\r?\n/).filter(Boolean).reduce(function (records, line) {
            try {
                records.push(JSON.parse(line));
            } catch (error) {
                skippedLines++;
            }
            return records;
        }, []);
    }

    function parseSetup(text) {
        var section = "";
        var result = {};

        text.split(/\r?\n/).forEach(function (line) {
            var match = line.match(/^\[([^\]]+)\]$/);
            var separator;

            if (match) {
                section = match[1];
                result[section] = result[section] || { lines: [] };
                return;
            }
            if (section && line)
                result[section].lines.push(line);
            separator = line.indexOf("=");
            if (section && separator > 0)
                result[section][line.slice(0, separator)] = line.slice(separator + 1);
        });
        return result;
    }

    function eventInfo(record) {
        return record && record.event_info ? record.event_info : {};
    }

    function recordState(record) {
        return record && record.state ? record.state : {};
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

    function guestPhaseGroup(record) {
        var phase = executionInfo(record).phase;

        return {
            interface_start: "IXGBE OPEN",
            offline_diag: "OFFLINE DIAG",
            intr_test: "INTR TEST",
            loopback_setup: "LOOPBACK",
            loopback_run: "LOOPBACK",
            interface_restore: "RESTORE OPEN"
        }[phase] || "GUEST";
    }

    function phaseGroupAt(record) {
        var cutoff = anchoredTime(record);
        var phaseRecord = guestRecords.filter(function (candidate) {
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

    function clockOffset(meta) {
        var anchor = meta && recordState(meta).clock_anchor;

        return anchor ? big(anchor.realtime_ns) - big(anchor.monotonic_ns) : 0n;
    }

    function anchoredTime(record) {
        var offset = record && record.source === "guest-ebpf" ? clockOffset(guestMeta) : clockOffset(hostMeta);

        return big(record && record.time_ns) + offset;
    }

    function compareRecords(left, right) {
        var leftTime = anchoredTime(left.orderRecord || left.record);
        var rightTime = anchoredTime(right.orderRecord || right.record);

        return leftTime < rightTime ? -1 : (leftTime > rightTime ? 1 : 0);
    }

    function guestEvent(kind) {
        return guestRecords.find(function (record) { return record.kind === kind; }) || null;
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
        return { 0: "BIDIRECTIONAL", 1: "TO_DEVICE", 2: "FROM_DEVICE", 3: "NONE" }[value] || null;
    }

    function irqDisposition(value) {
        return { 0: "IRQ_NONE", 1: "IRQ_HANDLED", 2: "IRQ_WAKE_THREAD" }[value] || "ret " + value;
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
        return ebpfRecords.filter(function (record) {
            return requestId && eventInfo(record).request_id === requestId;
        });
    }

    function matchingExit(enter, kind) {
        var info = eventInfo(enter);
        var address = addressInfo(enter);

        return ebpfRecords.find(function (record) {
            var candidate = addressInfo(record);
            return record.kind === kind && record.time_ns >= enter.time_ns &&
                ((info.request_id && eventInfo(record).request_id === info.request_id) ||
                    (!info.request_id && record.context && enter.context && record.context.tid === enter.context.tid && sameRange(candidate, address)));
        });
    }

    function workloadMapIndex() {
        var dmaRecord = guestEvent("guest_dma_map_exit");
        var runtimeRecord = runtimeMmioRecord();
        var dmaAddress;
        var cutoff;
        var lastBoundary;

        if (!dmaRecord || !dmaInfo(dmaRecord).address)
            return -1;
        dmaAddress = dmaInfo(dmaRecord).address;
        cutoff = runtimeRecord ? runtimeRecord.time_ns : Number.POSITIVE_INFINITY;
        lastBoundary = ebpfRecords.filter(function (record) {
            var address = addressInfo(record);
            return (record.kind === "vfio_dma_map_exit" || record.kind === "vfio_dma_unmap_exit") &&
                eventInfo(record).result === 0 && record.time_ns <= cutoff &&
                rangeContains(address.iova, address.size, dmaAddress, "0x1");
        }).pop();
        if (!lastBoundary || lastBoundary.kind !== "vfio_dma_map_exit")
            return -1;
        return mapTransactions.findIndex(function (transaction) { return transaction.exit === lastBoundary; });
    }

    function workloadChunkIndex(transaction) {
        var dmaRecord = guestEvent("guest_dma_map_exit");
        var dmaAddress = dmaRecord && dmaInfo(dmaRecord).address;

        if (!transaction || !dmaAddress)
            return 0;
        return Math.max(0, transaction.chunks.findIndex(function (record) {
            var address = addressInfo(record);
            return rangeContains(address.iova, address.size, dmaAddress, "0x1");
        }));
    }

    function buildTransactions() {
        mapTransactions = ebpfRecords.filter(function (record) {
            return record.kind === "vfio_dma_map_enter" && eventInfo(record).sample_status !== "invalid_argument";
        }).map(function (enter) {
            var info = eventInfo(enter);
            var address = addressInfo(enter);
            var exit = matchingExit(enter, "vfio_dma_map_exit");
            var related = requestRecords(info.request_id);
            var chunks = ebpfRecords.filter(function (record) {
                var chunk = addressInfo(record);
                return record.kind === "iommu_map" &&
                    ((info.request_id && eventInfo(record).request_id === info.request_id) ||
                        (!info.request_id && chunk.parent_iova === address.iova && chunk.parent_size === address.size &&
                            record.time_ns >= enter.time_ns && (!exit || record.time_ns <= exit.time_ns)));
            });
            var pins = related.filter(function (record) { return record.kind.indexOf("vfio_page_pin_") === 0; });
            var type1 = related.filter(function (record) { return record.kind.indexOf("vfio_type1_map_") === 0; });

            return { enter: enter, exit: exit, chunks: chunks, pins: pins, type1: type1 };
        });

        workloadTransaction = workloadMapIndex();
        selectedTransaction = workloadTransaction;
        if (selectedTransaction < 0) {
            selectedTransaction = mapTransactions.findIndex(function (transaction) {
                var address = addressInfo(transaction.enter);
                return transaction.exit && eventInfo(transaction.exit).result === 0 && numeric(address.size) >= 0x100000 && transaction.chunks.length > 1;
            });
        }
        if (selectedTransaction < 0)
            selectedTransaction = 0;
        selectedChunk = workloadChunkIndex(mapTransactions[selectedTransaction]);
    }

    function preludeItems() {
        var order = ["host_owns_device", "vfio_bound", "qemu_attached", "guest_visible", "host_reclaims_device"];
        return order.map(function (kind) {
            var record = assignmentRecords.find(function (candidate) { return candidate.kind === kind; });
            return record ? { label: titleFor(record), group: "ASSIGNMENT", record: record } : null;
        }).filter(Boolean);
    }

    function candidateAttach() {
        var candidate = setupFacts.candidate_device || {};
        return ebpfRecords.find(function (record) {
            return record.kind === "iommu_device_attach" && addressInfo(record).device === candidate.bdf;
        }) || ebpfRecords.find(function (record) { return record.kind === "iommu_device_attach"; });
    }

    function matchingKvmRegion(transaction) {
        var mapping = transaction ? addressInfo(transaction.enter) : {};
        var candidates = ebpfRecords.filter(function (record) {
            var memory = addressInfo(record);
            return record.kind === "kvm_memory_region_enter" && record.time_ns <= transaction.enter.time_ns &&
                rangeContains(memory.hva, memory.size, mapping.hva, mapping.size);
        });

        return candidates[candidates.length - 1] || null;
    }

    function matchingUnmap(transaction) {
        var mapping = transaction ? addressInfo(transaction.enter) : {};
        var after = transaction && transaction.exit ? transaction.exit.time_ns : transaction.enter.time_ns;
        var enters = ebpfRecords.filter(function (record) {
            return record.kind === "vfio_dma_unmap_enter" && record.schema_version >= 3 && record.time_ns >= after &&
                eventInfo(record).sample_status === "complete" && rangesOverlap(addressInfo(record), mapping);
        });
        var enter = enters[0];
        var requestId = enter && eventInfo(enter).request_id;
        var related = requestRecords(requestId);

        return enter ? {
            enter: enter,
            unmaps: related.filter(function (record) { return record.kind === "iommu_unmap"; }),
            invalidations: related.filter(function (record) { return record.kind === "iommu_iotlb_invalidate"; }),
            qi: related.filter(function (record) { return record.kind === "iommu_qi_submit" || record.kind === "iommu_qi_complete"; }),
            unpins: related.filter(function (record) { return record.kind.indexOf("vfio_page_unpin_") === 0; }),
            exit: related.find(function (record) { return record.kind === "vfio_dma_unmap_exit"; })
        } : null;
    }

    function pinEventsForChunk(transaction, chunkRecord) {
        var mapping = transaction ? addressInfo(transaction.enter) : {};
        var chunk = addressInfo(chunkRecord);
        var expectedHva;
        var enter;
        var exit;

        if (!transaction || !chunkRecord)
            return [];
        expectedHva = big(mapping.hva) + big(chunk.iova) - big(mapping.iova);
        enter = transaction.pins.find(function (record) {
            return record.kind === "vfio_page_pin_enter" && big(addressInfo(record).hva) === expectedHva;
        });
        exit = enter && transaction.pins.find(function (record) {
            return record.kind === "vfio_page_pin_exit" && record.time_ns >= enter.time_ns;
        });
        return [enter, exit].filter(Boolean);
    }

    function teardownEventsForChunk(teardown, chunkRecord) {
        var chunk = addressInfo(chunkRecord);
        var unmap;
        var invalidation;
        var qiSubmit;
        var qiComplete;
        var unpinEnter;
        var unpinExit;

        if (!teardown || !chunkRecord)
            return teardown ? [teardown.enter, teardown.exit].filter(Boolean) : [];
        unmap = teardown.unmaps.find(function (record) { return sameRange(addressInfo(record), chunk); }) ||
            teardown.unmaps.find(function (record) { return rangesOverlap(addressInfo(record), chunk); });
        invalidation = teardown.invalidations.find(function (record) {
            var iommu = iommuInfo(record);
            return rangesOverlap({ iova: iommu.iova, size: iommu.size }, chunk);
        });
        qiSubmit = invalidation && teardown.qi.find(function (record) {
            return record.kind === "iommu_qi_submit" && record.time_ns >= invalidation.time_ns;
        });
        qiComplete = qiSubmit && teardown.qi.find(function (record) {
            return record.kind === "iommu_qi_complete" && record.time_ns >= qiSubmit.time_ns;
        });
        unpinEnter = teardown.unpins.find(function (record) {
            return record.kind === "vfio_page_unpin_enter" && big(addressInfo(record).iova) === big(chunk.iova);
        });
        unpinExit = unpinEnter && teardown.unpins.find(function (record) {
            return record.kind === "vfio_page_unpin_exit" && record.time_ns >= unpinEnter.time_ns;
        });
        return [teardown.enter, unmap, invalidation, qiSubmit, qiComplete, unpinEnter, unpinExit, teardown.exit].filter(Boolean);
    }


    function message(group, label, detail, from, to, record, architectural, scope, orderRecord) {
        var domain = scope || (record && record.source === "guest-ebpf" ? "guest" : "outside");

        return { group: group, label: label, detail: detail, from: from, to: to, record: record || null, orderRecord: orderRecord || record || null, architectural: Boolean(architectural), scope: domain };
    }

    function guestBarForGpa(gpa) {
        var visible = assignmentRecords.find(function (record) { return record.kind === "guest_visible"; });
        var bars = visible && recordState(visible).guest_device ? recordState(visible).guest_device.bars : [];
        var target = big(gpa);

        return (Array.isArray(bars) ? bars : []).map(parseBar).find(function (bar) {
            var start = big(String(bar.address).indexOf("0x") === 0 ? bar.address : "0x" + bar.address);
            var sizeMatch = String(bar.size).match(/^(\d+)([KMG])$/i);
            var multiplier = sizeMatch ? { K: 1024n, M: 1048576n, G: 1073741824n }[sizeMatch[2].toUpperCase()] : 1n;
            var size = sizeMatch ? BigInt(sizeMatch[1]) * multiplier : 0n;

            return target >= start && target < start + size;
        }) || null;
    }

    function runtimeMmioRecord() {
        return ebpfRecords.find(function (record) {
            var mmio = mmioInfo(record);
            return record.kind === "kvm_mmio" && mmio.type === 2 && guestBarForGpa(mmio.gpa);
        }) || null;
    }

    function msixTableWrites() {
        var writes = ebpfRecords.filter(function (record) {
            var mmio = mmioInfo(record);
            var bar = record.kind === "kvm_mmio" ? guestBarForGpa(mmio.gpa) : null;
            return bar && bar.region === "4" && mmio.type === 2;
        });
        var address = writes.find(function (record) {
            var mmio = mmioInfo(record);
            return big(mmio.gpa) % 16n === 0n && (big(mmio.value) & 0xfff00000n) === 0xfee00000n;
        });
        var data = address && writes.find(function (record) {
            return record.time_ns >= address.time_ns && big(mmioInfo(record).gpa) === big(mmioInfo(address).gpa) + 8n;
        });

        return { address: address || null, data: data || null };
    }

    function postedInterruptRoute() {
        var update = ebpfRecords.find(function (record) { return record.kind === "kvm_pi_irte_update" && interruptInfo(record).posted; });
        var irq = update && interruptInfo(update).irq;
        var requests;
        var enter;
        var related;
        var allocation;
        var activation;
        var messageRecord;

        if (!update)
            return null;
        requests = ebpfRecords.filter(function (record) {
            var interrupt = interruptInfo(record);
            return record.kind === "vfio_irq_set_enter" && interrupt.index === 2 && record.time_ns <= update.time_ns;
        });
        enter = requests[requests.length - 1] || null;
        related = enter ? requestRecords(eventInfo(enter).request_id) : [];
        allocation = ebpfRecords.filter(function (record) {
            return record.kind === "irte_alloc" && interruptInfo(record).irq === irq &&
                (!enter || record.time_ns >= enter.time_ns) && record.time_ns <= update.time_ns;
        }).pop() || null;
        activation = ebpfRecords.filter(function (record) {
            return record.kind === "irte_activate" && interruptInfo(record).irq === irq && (!enter || record.time_ns >= enter.time_ns) && record.time_ns <= update.time_ns;
        }).pop() || null;
        messageRecord = ebpfRecords.filter(function (record) {
            return record.kind === "interrupt_remap_msi_message" && interruptInfo(record).irq === irq && (!enter || record.time_ns >= enter.time_ns) && record.time_ns <= update.time_ns;
        }).pop() || null;
        return {
            enter: enter,
            exit: related.find(function (record) { return record.kind === "vfio_irq_set_exit"; }) || null,
            allocation: allocation,
            activation: activation,
            message: messageRecord,
            update: update
        };
    }

    function hostEvent(kind) {
        return ebpfRecords.find(function (record) { return record.kind === kind; }) || null;
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
        var selectedPins = pinEventsForChunk(transaction, selectedMap);
        var msix = msixTableWrites();
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
            mapping = [transaction.enter].concat(transaction.type1, selectedPins, selectedMap || [], transaction.exit || []).filter(Boolean).map(function (record) {
                var address = addressInfo(record);
                var entering;

                if (record.kind === "vfio_dma_map_enter")
                    return message("MAP", "VFIO_IOMMU_MAP_DMA", "IOVA " + address.iova + " · " + formatBytes(address.size), LANE.QEMU, LANE.VFIO, record);
                if (record.kind === "vfio_type1_map_enter")
                    return message("MAP", "validate map", "VFIO type1 backend", LANE.VFIO, LANE.VFIO, record);
                if (record.kind === "vfio_type1_map_exit")
                    return message("MAP", "ret", "ret " + eventInfo(record).result, LANE.VFIO, LANE.VFIO, record);
                if (record.kind.indexOf("vfio_page_pin_") === 0) {
                    entering = record.kind === "vfio_page_pin_enter";
                    return message("MAP", entering ? "pin pages" : "ret", entering ? "HVA " + address.hva + " · " + address.page_count + " pages" : eventInfo(record).result + " pages", entering ? LANE.VFIO : LANE.MEMORY, entering ? LANE.MEMORY : LANE.VFIO, record);
                }
                if (record.kind === "iommu_map")
                    return message("MAP", "iommu:map", "IOVA " + address.iova + " → HPA " + address.hpa + " · " + formatBytes(address.size), LANE.VFIO, LANE.IOMMU, record);
                return message("MAP", "ret", "ret " + eventInfo(record).result, LANE.VFIO, LANE.QEMU, record);
            });
            if (!selectedPins.length)
                mapping.splice(1, 0, message("MAP", "vfio_pin_pages_remote", "QEMU HVA → resident host pages", LANE.VFIO, LANE.MEMORY, null, true, "outside", transaction.enter));
            mapping.sort(compareRecords);
        }

        if (route && route.allocation) {
            var allocation = interruptInfo(route.allocation);
            irqSetup.push(message("IRQ SETUP", "alloc_irte", "host IRQ " + allocation.irq + " · IRTE " + allocation.irte_index, LANE.VFIO, LANE.IOMMU, route.allocation));
        }
        if (msix.address)
            irqSetup.push(message("IRQ SETUP", "write MSI-X address", mmioInfo(msix.address).gpa + " ← " + mmioInfo(msix.address).value, LANE.GUEST, LANE.KVM, msix.address));
        if (msix.data)
            irqSetup.push(message("IRQ SETUP", "write MSI-X data", mmioInfo(msix.data).gpa + " ← " + mmioInfo(msix.data).value, LANE.GUEST, LANE.KVM, msix.data));
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

        guestRecords.forEach(function (record) {
            var dma = dmaInfo(record);
            var interrupt = interruptInfo(record);
            var execution = executionInfo(record);
            var context = record.context || {};
            var group = guestPhaseGroup(record);
            var mappedDma;
            var translatedChunk;
            var translatedHpa;
            var rxDma;
            var rxChunk;
            var rxHpa;

            if (record.kind === "workload_begin" || record.kind === "workload_end")
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
            else if (record.kind === "guest_ixgbe_run_loopback_entry")
                runtime.push(message(group, "ixgbe_run_loopback_test", "64 TX/RX frames per batch", LANE.GUEST, LANE.GUEST, record));
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
                translatedChunk = mappedDma && transaction && transaction.chunks.find(function (chunkRecord) {
                    var chunk = addressInfo(chunkRecord);
                    return big(dmaInfo(mappedDma).address) >= big(chunk.iova) && big(dmaInfo(mappedDma).address) < big(chunk.iova) + big(chunk.size);
                });
                if (translatedChunk) {
                    translatedHpa = big(addressInfo(translatedChunk).hpa) + big(dmaInfo(mappedDma).address) - big(addressInfo(translatedChunk).iova);
                    runtime.push(message(group, "DMA read request", "IOVA " + dmaInfo(mappedDma).address, LANE.NIC, LANE.IOMMU, null, true, "outside", record));
                    runtime.push(message(group, "translated read", "HPA 0x" + translatedHpa.toString(16), LANE.IOMMU, LANE.MEMORY, null, true, "outside", record));
                }
                rxDma = guestEvent("guest_dma_sync_for_cpu");
                rxChunk = rxDma && transaction && transaction.chunks.find(function (chunkRecord) {
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
            else if (record.kind === "guest_ixgbe_run_loopback_exit")
                runtime.push(message(group, "ret", "ret " + eventInfo(record).result, LANE.GUEST, LANE.GUEST, record));
            else if (record.kind === "guest_irq_handler_entry") {
                if (route && route.update) {
                    runtime.push(message(group, "PCIe MSI-X message", "episode " + execution.episode_id + " · device cause unobserved", LANE.NIC, LANE.IOMMU, null, true, "outside", record));
                runtime.push(message(group, "VT-d IRTE lookup", "remapped posted-interrupt route", LANE.IOMMU, LANE.KVM, null, true, "outside", record));
                runtime.push(message(group, "APICv delivery", "guest hard-IRQ boundary", LANE.KVM, LANE.GUEST, null, true, "outside", record));
                }
                runtime.push(message(group, "irq_handler_entry", interrupt.action + " · IRQ " + interrupt.irq + " · CPU " + context.cpu, LANE.GUEST, LANE.GUEST, record));
            } else if (record.kind === "guest_softirq_raise")
                runtime.push(message(group, "softirq_raise", execution.softirq + " · episode " + execution.episode_id, LANE.GUEST, LANE.NET, record));
            else if (record.kind === "guest_irq_handler_exit")
                runtime.push(message(group, "irq_handler_exit", irqDisposition(eventInfo(record).result), LANE.GUEST, LANE.GUEST, record));
            else if (record.kind === "guest_softirq_entry")
                runtime.push(message(group, "softirq_entry", execution.softirq + " · CPU " + context.cpu, LANE.NET, LANE.NET, record));
            else if (record.kind === "guest_napi_poll")
                runtime.push(message(group, "napi_poll", "work " + execution.napi_work + " / budget " + execution.napi_budget, LANE.NET, LANE.GUEST, record));
            else if (record.kind === "guest_softirq_exit")
                runtime.push(message(group, "softirq_exit", execution.softirq + " · episode " + execution.episode_id, LANE.NET, LANE.NET, record));
        });

        ebpfRecords.filter(function (record) {
            return record.kind === "kvm_pi_wakeup" || record.kind === "kvm_pi_wakeup_vector" || record.kind === "kvm_pi_sync_pir_to_irr_exit" ||
                record.kind === "vfio_msi_handler_entry" || record.kind === "vfio_msi_handler_exit" ||
                record.kind === "kvm_irqfd_wakeup" || record.kind === "kvm_msi_route" || record.kind === "kvm_apic_accept_irq";
        }).forEach(function (record) {
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
            teardownItems = teardownEventsForChunk(teardown, selectedMap).map(function (record) {
                var address = addressInfo(record);
                var iommu = iommuInfo(record);
                var entering;

                if (record.kind === "vfio_dma_unmap_enter")
                    return message("TEARDOWN", "VFIO_IOMMU_UNMAP_DMA", "IOVA " + address.iova + " · " + formatBytes(address.size), LANE.QEMU, LANE.VFIO, record);
                if (record.kind === "iommu_unmap")
                    return message("TEARDOWN", "remove translation", "IOVA " + address.iova + " · " + formatBytes(address.returned_size), LANE.VFIO, LANE.IOMMU, record);
                if (record.kind === "iommu_iotlb_invalidate")
                    return message("IOTLB", "invalidate IOTLB", "IOVA " + iommu.iova + " · " + formatBytes(iommu.size), LANE.IOMMU, LANE.IOMMU, record);
                if (record.kind === "iommu_qi_submit")
                    return message("IOTLB", "submit QI", iommu.qi_count + " descriptor", LANE.IOMMU, LANE.IOMMU, record);
                if (record.kind === "iommu_qi_complete")
                    return message("IOTLB", "QI completion", "ret " + eventInfo(record).result, LANE.IOMMU, LANE.IOMMU, record);
                if (record.kind.indexOf("vfio_page_unpin_") === 0) {
                    entering = record.kind === "vfio_page_unpin_enter";
                    return message("TEARDOWN", entering ? "release pages" : "ret", entering ? address.page_count + " pages" : "ret " + eventInfo(record).result, entering ? LANE.VFIO : LANE.MEMORY, entering ? LANE.MEMORY : LANE.VFIO, record);
                }
                return message("TEARDOWN", "ret", "ret " + eventInfo(record).result + " · " + formatBytes(address.returned_size), LANE.VFIO, LANE.QEMU, record);
            });
            teardownItems.sort(compareRecords);
        }
        return preparation.concat(mapping, irqSetup, runtime, teardownItems);
    }


    function titleFor(record) {
        var titles = {
            host_owns_device: "host ownership",
            vfio_bound: "vfio-pci bind",
            qemu_attached: "QEMU attach",
            guest_visible: "guest visible",
            host_reclaims_device: "host reclaim",
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

    function renderSetupFacts() {
        var host = setupFacts.host || {};
        var management = setupFacts.management_device || {};
        var candidate = setupFacts.candidate_device || {};
        var networkLines = (setupFacts.network && setupFacts.network.lines) || [];
        var groupLines = (setupFacts.iommu_groups && setupFacts.iommu_groups.lines) || [];
        var groups = {};
        var managementLink = networkLines.find(function (line) { return management.interface && line.indexOf(management.interface + " ") === 0; });
        var candidateLink = networkLines.find(function (line) { return candidate.interface && line.indexOf(candidate.interface + " ") === 0; });

        groupLines.forEach(function (line) {
            var match = line.match(/^group=(\d+) bdf=(\S+)$/);
            if (!match)
                return;
            groups[match[1]] = groups[match[1]] || [];
            groups[match[1]].push(match[2]);
        });
        byId("physical-bdf").textContent = candidate.bdf || "not sampled";
        byId("physical-name").textContent = [candidate.name, candidate.vendor_device].filter(Boolean).join(" · ") || "not sampled";
        byId("host-driver-label").textContent = "HOST " + (candidate.driver || "DRIVER");
        byId("guest-driver-label").textContent = "GUEST " + (candidate.driver || "DRIVER");
        byId("management-bdf").textContent = management.bdf || "not sampled";
        byId("management-detail").textContent = [management.interface, management.driver, management.iommu_group ? "IOMMU group " + management.iommu_group : null].filter(Boolean).join(" · ");
        byId("candidate-bdf").textContent = candidate.bdf || "not sampled";
        byId("candidate-detail").textContent = [candidate.interface, candidate.driver, candidate.iommu_group ? "IOMMU group " + candidate.iommu_group : null].filter(Boolean).join(" · ");
        byId("setup-host").textContent = [host.hostname, host.os].filter(Boolean).join(" · ") || "not sampled";
        byId("setup-kernel").textContent = host.kernel || "not sampled";
        byId("setup-dmar").textContent = host.dmar_present === "true" ? "ACPI DMAR table present" : "not reported";
        byId("setup-qemu").textContent = host.qemu_version || "not sampled";
        byId("setup-kvm").textContent = host.kvm_device || "not sampled";
        byId("setup-cmdline").textContent = (host.cmdline || "not sampled").trim().split(/\s+/).join("\n");
        byId("setup-cmdline").title = host.cmdline || "";
        byId("setup-route").textContent = [management.default_route_interface, management.bdf].filter(Boolean).join(" → ") || "not sampled";
        byId("setup-management-link").textContent = managementLink || "not sampled";
        byId("setup-candidate-link").textContent = candidateLink || "not sampled";
        byId("setup-reset").textContent = candidate.reset_methods || "not sampled";
        byId("setup-management-group").textContent = management.iommu_group || "not sampled";
        byId("setup-candidate-group").textContent = candidate.iommu_group || "not sampled";
        var groupIds = Object.keys(groups).sort(function (left, right) { return Number(left) - Number(right); });
        byId("group-summary").textContent = groupIds.length + " groups · group " + (management.iommu_group || "—") + " ≠ group " + (candidate.iommu_group || "—");
        byId("group-map").innerHTML = groupIds.slice(0, 64).map(function (group) {
            var className = group === management.iommu_group ? " management" : (group === candidate.iommu_group ? " candidate" : "");
            return '<div class="iommu-group' + className + '" title="' + escapeHtml(groups[group].join(" · ")) + '"><b>G' + escapeHtml(group) + '</b><span>' + groups[group].length + '</span></div>';
        }).join("");
    }

    function renderRoadmap() {
        var groups = [
            { phase: "P", phaseLabel: "PRELUDE", label: "ASSIGNMENT", items: preludeItems() },
            { phase: "A", phaseLabel: "PHASE A", label: "DMA REMAPPING", items: phaseAItems() }
        ];

        byId("roadmap").innerHTML = '<header class="roadmap-head"><b>EXECUTION</b><span>FLOW</span></header>' + groups.map(function (group) {
            var active = group.phase === selectedPhase;
            var current = active && group.items[selectedIndex];

            return '<section class="roadmap-zone' + (active ? " active" : "") + '" data-phase-zone="' + group.phase + '"><div class="zone-copy"><b><em>' + group.phaseLabel + '</em></b><span>' + group.label + '</span>' + (current ? '<small>' + escapeHtml(current.label) + '</small>' : "") + '</div></section>';
        }).join("") + '<section class="roadmap-zone future"><div class="zone-copy"><b><em>PHASE B</em></b><span>DMA PROTECTION</span><small>future</small></div></section>';

        byId("roadmap").querySelectorAll("[data-phase-zone]").forEach(function (zone) {
            zone.onclick = function () { selectPhase(zone.dataset.phaseZone); };
        });
    }


    function parseBar(bar) {
        var match = String(bar).match(/^Region\s+(\d+):\s+(.+?)\s+at\s+(\S+)(?:\s+\(([^)]+)\))?\s+\[size=([^\]]+)\]/);
        return match ? { region: match[1], type: match[2], address: match[3], attributes: match[4] || "", size: match[5] } : { region: "PCI", type: String(bar), address: "not sampled", attributes: "", size: "" };
    }

    function renderBar(bar) {
        var parsed = parseBar(bar);
        var attributes = parsed.attributes.split(",").map(function (part) { return part.trim(); }).filter(Boolean).join(" · ");
        return '<article class="bar-card" title="' + escapeHtml(bar) + '"><header><b>REGION ' + escapeHtml(parsed.region) + '</b><span>' + escapeHtml(parsed.size) + '</span></header><strong>' + escapeHtml(parsed.type) + '</strong><code>' + escapeHtml(parsed.address) + '</code>' + (attributes ? '<small>' + escapeHtml(attributes) + '</small>' : "") + '</article>';
    }

    function renderPrelude(record) {
        var current = recordState(record);
        var candidate = setupFacts.candidate_device || {};
        var assignment = current.assignment || {};
        var guest = current.guest_device || {};
        var nodes = [byId("host-owner"), byId("vfio-owner"), byId("qemu-owner"), byId("guest-owner")];

        byId("physical-bdf").textContent = candidate.bdf || "not sampled";
        byId("physical-name").textContent = [candidate.name, candidate.vendor_device].filter(Boolean).join(" · ");
        byId("host-interface").textContent = candidate.interface || "not sampled";
        byId("guest-interface").textContent = guest.present ? [guest.guest_bdf, guest.interface].filter(Boolean).join(" · ") : "not present";
        byId("guest-driver-label").textContent = "GUEST " + (guest.driver || candidate.driver || "DRIVER");
        nodes.forEach(function (node) { node.classList.remove("active"); node.classList.add("inactive"); });
        if (record.kind === "host_owns_device" || record.kind === "host_reclaims_device")
            byId("host-owner").classList.remove("inactive");
        if (assignment.vfio_bound) {
            byId("vfio-owner").classList.remove("inactive");
            byId("qemu-owner").classList.toggle("inactive", !assignment.qemu_attached);
            byId("guest-owner").classList.toggle("inactive", !guest.present);
        }
        if (record.kind === "host_owns_device" || record.kind === "host_reclaims_device")
            byId("host-owner").classList.add("active");
        else if (record.kind === "vfio_bound")
            byId("vfio-owner").classList.add("active");
        else if (record.kind === "qemu_attached")
            byId("qemu-owner").classList.add("active");
        else if (record.kind === "guest_visible")
            byId("guest-owner").classList.add("active");

        byId("guest-proof").classList.toggle("hidden", record.kind !== "guest_visible");
        byId("host-bdf-proof").textContent = candidate.bdf || "not sampled";
        byId("guest-bdf-proof").textContent = guest.present ? guest.guest_bdf : "not present";
        byId("guest-bars").innerHTML = (Array.isArray(guest.bars) ? guest.bars : []).map(renderBar).join("");
    }

    function currentTransaction() {
        return mapTransactions[selectedTransaction] || null;
    }

    function renderMapSelector() {
        byId("map-select").innerHTML = mapTransactions.map(function (transaction, index) {
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
        byId("chunk-list").innerHTML = chunks.map(function (record, index) {
            var address = addressInfo(record);
            var title = "IOVA " + address.iova + " → HPA " + address.hpa + " · " + address.size;
            return '<button class="chunk ' + (index === selectedChunk ? "active" : "") + '" type="button" data-chunk="' + index + '" title="' + escapeHtml(title) + '"><b>' + String(index + 1).padStart(2, "0") + '</b><span>' + escapeHtml(formatBytes(address.size)) + '</span></button>';
        }).join("") || '<span class="chunk">No correlated IOMMU maps.</span>';
        byId("map-summary").textContent = transaction ? (selectedTransaction === workloadTransaction ? "workload active · " : "") + transaction.chunks.length + " iommu:map records · request " + (eventInfo(transaction.enter).request_id || "legacy") : "no mappings";
        byId("chunk-list").querySelectorAll("[data-chunk]").forEach(function (button) {
            button.onclick = function () {
                selectedChunk = Number(button.dataset.chunk);
                phaseItems = phaseAItems();
                selectedIndex = phaseItems.findIndex(function (item) { return item.record === chunks[selectedChunk]; });
                if (selectedIndex < 0)
                    selectedIndex = 0;
                renderChunks();
                selectRecord(selectedIndex);
            };
        });
    }

    function renderActors(item) {
        byId("actor-row").innerHTML = actors.map(function (actor, index) {
            var active = item && (item.from === index || item.to === index);
            var resource = "";
            var candidate = setupFacts.candidate_device || {};
            var transaction = currentTransaction();
            var address = transaction ? addressInfo(transaction.enter) : {};
            var actorName = actor.id === "guest" ? (candidate.driver || actor.name) : actor.name;

            if (actor.id === "qemu")
                resource = address.hva ? "HVA " + address.hva : "guest RAM owner";
            else if (actor.id === "guest-net")
                resource = "softirq + NAPI poll";
            else if (actor.id === "guest-dma")
                resource = "guest DMA addresses";
            else if (actor.id === "kvm")
                resource = "memslots + posted IRQ";
            else if (actor.id === "vfio")
                resource = transaction ? "fd " + eventInfo(transaction.enter).fd : "container";
            else if (actor.id === "memory")
                resource = "pinned pages";
            else if (actor.id === "iommu")
                resource = "IOVA maps + IRTEs";
            else if (actor.id === "nic")
                resource = candidate.bdf || "PCIe requester";
            else
                resource = "DMA descriptors";
            return '<div class="lifeline-actor ' + actor.scope + '-domain' + (active ? " active" : "") + '"><small>' + actor.role + '</small><b>' + escapeHtml(actorName) + '</b><span>' + escapeHtml(resource) + '</span></div>';
        }).join("");
        byId("lifeline-lines").innerHTML = actors.map(function (_, index) {
            return '<i style="left:' + ((index + 0.5) / actors.length * 100) + '%"></i>';
        }).join("");
    }

    function renderMessage(item, index) {
        var low = Math.min(item.from, item.to);
        var distance = Math.abs(item.to - item.from);
        var left = (low + 0.5) / actors.length * 100;
        var width = distance / actors.length * 100;
        var direction = item.to > item.from ? " forward" : (item.to < item.from ? " reverse" : " self");
        var evidence = item.architectural ? " architectural" : " observed";
        var scope = item.scope === "guest" ? " guest-scope" : " outside-scope";
        var style = distance ? "left:" + left + "%;width:" + width + "%" : "left:" + ((item.from + 0.5) / actors.length * 100) + "%";

        return '<button class="interaction-row' + (index === selectedIndex ? " current" : "") + evidence + scope + '" type="button" data-message="' + index + '"><span class="message-group">' + escapeHtml(item.group) + '</span><span class="message-line' + direction + '" style="' + style + '"><i></i><span class="message-copy"><b>' + escapeHtml(item.label) + '</b><small>' + escapeHtml(item.detail) + '</small></span></span></button>';
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
        var reached = function (record) { return Boolean(record) && anchoredTime(record) <= stateCutoff; };
        var faults = ebpfRecords.filter(function (record) { return record.kind === "iommu_page_fault" && reached(record); });
        var guestCutoff = stateCutoff;
        var guestSeen = guestRecords.filter(function (record) {
            return record.kind !== "workload_begin" && record.kind !== "workload_end" && anchoredTime(record) <= guestCutoff;
        });
        var txMap = guestSeen.filter(function (record) { return record.kind === "guest_dma_map_exit"; }).pop();
        var txUnmap = guestSeen.filter(function (record) { return record.kind === "guest_dma_unmap"; }).pop();
        var rxCpu = guestSeen.filter(function (record) { return record.kind === "guest_dma_sync_for_cpu"; }).pop();
        var rxDevice = guestSeen.filter(function (record) { return record.kind === "guest_dma_sync_for_device"; }).pop();
        var completion = guestSeen.filter(function (record) { return record.kind === "guest_ixgbe_clean_exit"; }).pop();
        var allTx = guestEvent("guest_dma_map_exit");
        var allRx = guestEvent("guest_dma_sync_for_cpu");
        var group = item ? item.group : "MAP";
        var rows = [];
        var status = "OBSERVED";
        var title = "DMA ADDRESS SPACE";
        var caption = "Selected VFIO window and its VT-d translation state.";
        var addressGroups = ["MEMORY", "ATTACH", "MAP", "TEARDOWN", "IOTLB"];
        var showMap = addressGroups.indexOf(group) >= 0;

        if (group.indexOf("IRQ") >= 0 || isRuntimeInterrupt(semanticRecord)) {
            var routeEnter = route && reached(route.enter) ? route.enter : null;
            var routeExit = route && reached(route.exit) ? route.exit : null;
            var routeUpdate = route && reached(route.update) ? route.update : null;
            var routeAllocation = route && reached(route.allocation) ? route.allocation : null;
            var routeMessage = route && reached(route.message) ? route.message : null;
            var routeInterrupt = interruptInfo(routeUpdate);
            var allocation = interruptInfo(routeAllocation);
            var messageState = interruptInfo(routeMessage);
            var guestEntries = guestSeen.filter(function (record) { return record.kind === "guest_irq_handler_entry"; });
            var guestExits = guestSeen.filter(function (record) { return record.kind === "guest_irq_handler_exit"; });
            var wakeEvents = ebpfRecords.filter(function (record) { return record.kind === "kvm_pi_wakeup" && reached(record); });
            var wakeCalls = wakeEvents.reduce(function (total, record) { return total + (interruptInfo(record).wakeup_count || 0); }, 0);
            var wakeVcpu0 = wakeEvents.filter(function (record) { return interruptInfo(record).wakeup_count && interruptInfo(record).vcpu_id === 0; }).length;
            var wakeVcpu1 = wakeEvents.filter(function (record) { return interruptInfo(record).wakeup_count && interruptInfo(record).vcpu_id === 1; }).length;
            var episodeRecords = selectedExecution.episode_id ? guestSeen.filter(function (record) { return executionInfo(record).episode_id === selectedExecution.episode_id; }) : [];
            var episodeEntry = episodeRecords.find(function (record) { return record.kind === "guest_irq_handler_entry"; });
            var episodeNapi = episodeRecords.find(function (record) { return record.kind === "guest_napi_poll"; });
            var episodeSoftirq = episodeRecords.find(function (record) { return record.kind === "guest_softirq_entry"; });

            title = "INTERRUPT REMAPPING";
            caption = selectedExecution.episode_id ? "Configured posted route and the selected guest IRQ episode." : "Configured route and observed host posted-interrupt wakeups.";
            status = selectedExecution.episode_id ? "EPISODE " + selectedExecution.episode_id : (routeUpdate ? (routeInterrupt.posted ? "POSTED" : "CONFIGURED") : "CONFIGURING");
            rows.push(stateRow("VFIO ROUTE", routeEnter ? "MSI-X " + interruptInfo(routeEnter).start + " · count " + interruptInfo(routeEnter).count : "—", routeExit ? "VFIO_DEVICE_SET_IRQS · ret " + eventInfo(routeExit).result : ""));
            rows.push(stateRow("IRTE", routeAllocation ? allocation.irte_index + " · host IRQ " + allocation.irq : "—", messageState.address ? messageState.address + " · data " + messageState.data : ""));
            rows.push(stateRow("POSTED TARGET", routeUpdate ? "vCPU " + routeInterrupt.vcpu_id + " · vector 0x" + Number(routeInterrupt.vector).toString(16) : "—", routeInterrupt.pi_desc_address ? "PI descriptor " + routeInterrupt.pi_desc_address : ""));
            rows.push(stateRow("PI WAKEUP", wakeEvents.length + " handlers · " + wakeCalls + " vCPU wakes", "vCPU 0 " + wakeVcpu0 + " · vCPU 1 " + wakeVcpu1));
            rows.push(stateRow("GUEST EPISODE", episodeEntry ? "#" + selectedExecution.episode_id + " · IRQ " + executionInfo(episodeEntry).irq : guestEntries.length + " entries · " + guestExits.length + " exits", episodeEntry ? executionInfo(episodeEntry).action + " · CPU " + episodeEntry.context.cpu : (guestEntries.length === guestExits.length ? "balanced hard-IRQ boundaries" : "incomplete hard-IRQ pairing")));
            rows.push(stateRow("BOTTOM HALF", episodeSoftirq ? executionInfo(episodeSoftirq).softirq : "—", episodeNapi ? "napi_poll work " + executionInfo(episodeNapi).napi_work + " / budget " + executionInfo(episodeNapi).napi_budget : "no NAPI poll reached yet"));
        } else if (group === "LOOPBACK" || group === "DMA USE" || group === "COMPLETE" || group === "NET") {
            var tx = allTx ? dmaInfo(allTx) : {};
            var rx = allRx ? dmaInfo(allRx) : {};
            var translated = transaction && tx.address ? transaction.chunks.find(function (record) {
                var address = addressInfo(record);
                return rangeContains(address.iova, address.size, tx.address, "0x1");
            }) : null;
            var txReleased = txUnmap && (!txMap || anchoredTime(txUnmap) >= anchoredTime(txMap));
            var cycleComplete = completion && (!txMap || anchoredTime(completion) >= anchoredTime(txMap));
            var txOwner = txReleased ? "UNMAPPED" : (txMap ? "DEVICE" : "CPU");
            var rxOwner = rxDevice && (!rxCpu || anchoredTime(rxDevice) >= anchoredTime(rxCpu)) ? "DEVICE" : (rxCpu ? "CPU" : "DEVICE");

            title = "DMA OWNERSHIP";
            caption = "Streaming DMA ownership reconstructed from the guest DMA API boundaries.";
            status = cycleComplete ? "COMPLETE" : (txMap ? "DEVICE OWNED" : "CPU OWNED");
            rows.push(stateRow("TX BUFFER", tx.address || "—", tx.length ? formatBytes(tx.length) + " · DMA_TO_DEVICE" : ""));
            rows.push(stateRow("TX OWNER", txOwner, txUnmap ? "mapping released" : (txMap ? "CPU must not touch until unmap" : "not mapped")));
            rows.push(stateRow("RX BUFFER", rx.address || "—", rx.length ? formatBytes(rx.length) + " · DMA_FROM_DEVICE" : ""));
            rows.push(stateRow("RX OWNER", rxOwner, rxCpu ? "sync_for_cpu observed" + (rxDevice ? " · returned to device" : "") : "prior RX mapping not captured"));
            rows.push(stateRow("TRANSLATION", translated ? addressInfo(translated).iova + " → " + addressInfo(translated).hpa : "—", translated ? formatBytes(addressInfo(translated).size) + " IOMMU leaf" : "no containing leaf"));
            rows.push(stateRow("COMPLETION", cycleComplete ? dmaInfo(completion).completed + " descriptors" : "—", cycleComplete ? "frame patterns verified" : "not yet observed"));
        } else if (["IXGBE OPEN", "OFFLINE DIAG", "INTR TEST", "RESTORE OPEN"].indexOf(group) >= 0) {
            var phase = selectedExecution.phase || "none";
            var phaseRecords = guestSeen.filter(function (record) { return executionInfo(record).phase === phase; });
            var phaseIrqs = phaseRecords.filter(function (record) { return record.kind === "guest_irq_handler_entry"; });
            var phaseNapi = phaseRecords.filter(function (record) { return record.kind === "guest_napi_poll"; });
            var phaseWork = phaseNapi.reduce(function (total, record) { return total + (executionInfo(record).napi_work || 0); }, 0);
            var selectedContext = semanticRecord && semanticRecord.context ? semanticRecord.context : {};

            title = "GUEST DRIVER PHASE";
            caption = "Observed ixgbe diagnostic phase and its execution context.";
            status = group;
            rows.push(stateRow("FUNCTION", item ? item.label : "—", semanticRecord ? eventInfo(semanticRecord).hook : ""));
            rows.push(stateRow("PHASE", phase === "none" ? group : phase, "captured driver phase"));
            rows.push(stateRow("CONTEXT", selectedContext.comm || "—", selectedContext.cpu != null ? "CPU " + selectedContext.cpu + " · PID " + selectedContext.pid : ""));
            rows.push(stateRow("IRQ EPISODES", phaseIrqs.length, phaseIrqs.length ? phaseIrqs.map(function (record) { return "#" + executionInfo(record).episode_id; }).join(" · ") : "none observed"));
            rows.push(stateRow("NAPI", phaseNapi.length + " polls · " + phaseWork + " work", phaseNapi.length ? "budget " + executionInfo(phaseNapi[0]).napi_budget + " each" : "no target NAPI poll"));
        } else {
            var teardown = transaction && matchingUnmap(transaction);
            var invalidations = teardown ? teardown.invalidations.filter(reached).length : 0;
            var completions = teardown ? teardown.qi.filter(function (record) { return record.kind === "iommu_qi_complete" && eventInfo(record).result === 0 && reached(record); }).length : 0;
            var parentReady = transaction && reached(transaction.enter);
            var mapReady = transaction && reached(transaction.exit);
            var leafReady = reached(chunkRecord);
            var domainReady = reached(domainRecord);
            var unmapped = teardown && reached(teardown.exit);

            if (group === "IOTLB") {
                title = "IOTLB INVALIDATION";
                caption = "Page-table removal followed by queued invalidation completion.";
                status = completions ? "COMPLETED" : "IN PROGRESS";
            } else if (group === "TEARDOWN") {
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
            rows.push(stateRow("IOTLB", invalidations + " invalidations · " + completions + " complete", teardown && reached(teardown.enter) ? "correlated request " + eventInfo(teardown.enter).request_id : (mapReady ? "mapping remains active" : "not mapped")));
            rows.push(stateRow("PROTECTION", parentReady ? mapPermissions(eventInfo(transaction.enter).flags) : "—", faults.length + " iommu:io_page_fault records"));
        }
        byId("state-title").textContent = title;
        byId("state-caption").textContent = caption;
        byId("state-status").textContent = status;
        byId("state-rows").innerHTML = rows.join("");
        byId("state-map-browser").classList.toggle("hidden", !showMap);
    }

    function renderPhaseA() {
        var current = selectedIndex >= 0 ? phaseItems[selectedIndex] : null;

        renderActors(current);
        renderState(current);
        byId("interaction-rows").innerHTML = phaseItems.map(renderMessage).join("");
        byId("flow-caption").textContent = current ? (current.scope === "guest" ? "GUEST" : "HOST / DEVICE") + " · " + current.group + " · " + current.label : "Select a message to inspect its captured boundary.";
        byId("interaction-rows").querySelectorAll("[data-message]").forEach(function (button) {
            button.onclick = function () { selectRecord(Number(button.dataset.message)); };
        });
    }


    function preludeFields(record) {
        var current = recordState(record);
        var candidate = setupFacts.candidate_device || {};
        var assignment = current.assignment || {};
        var guest = current.guest_device || {};
        return {
            source: record.source,
            time_ns: record.time_ns,
            host_bdf: candidate.bdf,
            host_driver: assignment.host_driver,
            owner: assignment.owner,
            vfio_bound: assignment.vfio_bound,
            qemu_attached: assignment.qemu_attached,
            guest_bdf: guest.present ? guest.guest_bdf : null,
            guest_driver: guest.present ? guest.driver : null,
            guest_interface: guest.present ? guest.interface : null,
            msix: guest.present ? guest.msix_present : null
        };
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

        if (!record)
            return { evidence: "architecture", relationship: actors[item.from].name + " → " + actors[item.to].name };
        return {
            hook: info.hook,
            operation: info.operation !== "none" ? info.operation : null,
            request_id: info.request_id || null,
            fd: info.fd || null,
            command: info.command !== "0x0" ? info.command : null,
            slot: record.kind.indexOf("kvm_memory") === 0 ? info.slot : null,
            flags: info.flags || fault.flags || null,
            result: /exit|return|complete/.test(record.kind) ? info.result : null,
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
            time_ns: record.time_ns
        };
    }


    function renderInspector(item) {
        var record;
        var fields;

        if (!item) {
            byId("fields").innerHTML = "";
            byId("source-badge").textContent = "no selection";
            byId("event-title").textContent = "select a boundary";
            byId("selected-time").textContent = "t = —";
            return;
        }
        record = item.record;
        fields = selectedPhase === "P" ? preludeFields(record) : phaseAFields(item);

        byId("fields").innerHTML = Object.keys(fields).filter(function (key) {
            return fields[key] !== undefined && fields[key] !== null && fields[key] !== "";
        }).map(function (key) {
            return '<dt>' + escapeHtml(key) + '</dt><dd title="' + escapeHtml(fields[key]) + '">' + escapeHtml(fields[key]) + '</dd>';
        }).join("");
        byId("source-badge").textContent = item.architectural ? "architecture" : (item.scope === "guest" ? "guest" : "host / device");
        byId("event-title").textContent = item.label;
        byId("selected-time").textContent = record ? "t = " + record.time_ns + " ns" : "architectural path";
    }

    function selectRecord(index) {
        var item;

        if (!phaseItems.length)
            return;
        selectedIndex = Math.max(0, Math.min(phaseItems.length - 1, index));
        item = phaseItems[selectedIndex];
        if (selectedPhase === "P")
            renderPrelude(item.record);
        else
            renderPhaseA();
        renderInspector(item);
        renderRoadmap();
        byId("counter").textContent = (selectedIndex + 1) + " / " + phaseItems.length;
    }

    function selectPhase(phase) {
        selectedPhase = phase;
        byId("prelude-state").classList.toggle("hidden", phase !== "P");
        byId("phase-a-state").classList.toggle("hidden", phase !== "A");
        byId("machine-title").textContent = phase === "P" ? "Assignment prelude" : "DMA remapping";
        byId("machine-caption").textContent = phase === "P" ? "One physical function changing software ownership." : "Address-space registration, DMA ownership, interrupt remapping, and invalidation.";
        phaseItems = phase === "P" ? preludeItems() : phaseAItems();
        if (phase === "A") {
            renderMapSelector();
            renderChunks();
        }
        selectedIndex = 0;
        selectRecord(0);
    }


    function loadText(path) {
        return fetch(path, { cache: "no-store" }).then(function (response) {
            if (!response.ok)
                throw Error("HTTP " + response.status + " for " + path);
            return response.text();
        });
    }

    byId("prev").onclick = function () { selectRecord(selectedIndex - 1); };
    byId("next").onclick = function () { selectRecord(selectedIndex + 1); };
    byId("map-select").onchange = function () {
        selectedTransaction = Number(this.value);
        selectedChunk = selectedTransaction === workloadTransaction ? workloadChunkIndex(mapTransactions[selectedTransaction]) : 0;
        phaseItems = phaseAItems();
        renderChunks();
        selectedIndex = phaseItems.findIndex(function (item) { return item.record === mapTransactions[selectedTransaction].enter; });
        selectRecord(selectedIndex < 0 ? 0 : selectedIndex);
    };

    Promise.all([loadText(assignmentPath), loadText(ebpfPath), loadText(guestPath), loadText(setupPath)]).then(function (texts) {
        var hostCapture;
        var guestCapture;

        assignmentRecords = parseNdjson(texts[0]);
        hostCapture = parseNdjson(texts[1]);
        guestCapture = parseNdjson(texts[2]);
        hostMeta = hostCapture.find(function (record) { return record.kind === "capture_meta"; }) || null;
        guestMeta = guestCapture.find(function (record) { return record.kind === "capture_meta"; }) || null;
        ebpfRecords = hostCapture.filter(function (record) { return record.kind !== "capture_meta" && record.kind !== "capture_summary"; });
        guestRecords = guestCapture.filter(function (record) { return record.kind !== "capture_meta" && record.kind !== "capture_summary"; });
        setupFacts = parseSetup(texts[3]);
        buildTransactions();
        renderSetupFacts();
        byId("status").innerHTML = '<i class="trace-dot"></i><span>assignment + host eBPF + guest eBPF' + (skippedLines ? " · " + skippedLines + " skipped" : "") + '</span>';
        selectPhase(window.location.hash === "#prelude" ? "P" : "A");
    }).catch(function (error) {
        byId("status").textContent = "VT·D data error · " + error.message;
    });
})();
