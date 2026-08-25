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
    var setupFacts = {};
    var mapTransactions = [];
    var selectedTransaction = 0;
    var selectedChunk = 0;
    var phaseItems = [];
    var selectedIndex = 0;
    var selectedPhase = "A";
    var skippedLines = 0;
    var LANE = { DMA: 0, GUEST: 1, KVM: 2, NIC: 3, QEMU: 4, VFIO: 5, IOMMU: 6, MEMORY: 7 };
    var actors = [
        { id: "guest-dma", role: "GUEST KERNEL", name: "DMA API" },
        { id: "guest", role: "GUEST", name: "IXGBE" },
        { id: "kvm", role: "CPU MEMORY", name: "KVM · EPT" },
        { id: "nic", role: "REQUESTER", name: "PCIe NIC" },
        { id: "qemu", role: "USERSPACE", name: "QEMU" },
        { id: "vfio", role: "DMA CONTROL", name: "VFIO" },
        { id: "iommu", role: "TRANSLATION", name: "IOMMU · VT-d" },
        { id: "memory", role: "BACKING", name: "HOST MM" }
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

    function mmioInfo(record) {
        return recordState(record).mmio || {};
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

        selectedTransaction = mapTransactions.findIndex(function (transaction) {
            var address = addressInfo(transaction.enter);
            return transaction.exit && eventInfo(transaction.exit).result === 0 && numeric(address.size) >= 0x100000 && transaction.chunks.length > 1;
        });
        if (selectedTransaction < 0)
            selectedTransaction = 0;
    }

    function phaseAItems() {
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
        var unpinEnter;
        var unpinExit;

        if (!teardown || !chunkRecord)
            return teardown ? [teardown.enter, teardown.exit].filter(Boolean) : [];
        unmap = teardown.unmaps.find(function (record) { return sameRange(addressInfo(record), chunk); }) ||
            teardown.unmaps.find(function (record) { return rangesOverlap(addressInfo(record), chunk); });
        unpinEnter = teardown.unpins.find(function (record) {
            return record.kind === "vfio_page_unpin_enter" && big(addressInfo(record).iova) === big(chunk.iova);
        });
        unpinExit = unpinEnter && teardown.unpins.find(function (record) {
            return record.kind === "vfio_page_unpin_exit" && record.time_ns >= unpinEnter.time_ns;
        });
        return [teardown.enter, unmap, unpinEnter, unpinExit, teardown.exit].filter(Boolean);
    }

    function message(group, label, detail, from, to, record, architectural) {
        return { group: group, label: label, detail: detail, from: from, to: to, record: record || null, architectural: Boolean(architectural) };
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

    function hostEvent(kind) {
        return ebpfRecords.find(function (record) { return record.kind === kind; }) || null;
    }

    function phaseBItems() {
        var transaction = mapTransactions[selectedTransaction];
        var selectedMap = transaction && transaction.chunks[selectedChunk];
        var attach = candidateAttach();
        var kvmEnter = transaction && matchingKvmRegion(transaction);
        var kvmExit = kvmEnter && matchingExit(kvmEnter, "kvm_memory_region_exit");
        var teardown = transaction && matchingUnmap(transaction);
        var selectedPins = pinEventsForChunk(transaction, selectedMap);
        var mmioRecord = runtimeMmioRecord();
        var physicalIrq = hostEvent("vfio_msi_handler_entry") || hostEvent("vfio_intx_handler_entry");
        var irqfd = hostEvent("kvm_irqfd_wakeup");
        var msiRoute = hostEvent("kvm_msi_route");
        var apicAccept = hostEvent("kvm_apic_accept_irq");
        var preparation = [];
        var mappingEvents = [];
        var teardownEvents = [];
        var items = [];

        if (kvmEnter) {
            preparation.push(message("MEMORY", "KVM_SET_USER_MEMORY_REGION", "slot " + eventInfo(kvmEnter).slot + " · GPA " + addressInfo(kvmEnter).gpa + " · " + formatBytes(addressInfo(kvmEnter).size), LANE.QEMU, LANE.KVM, kvmEnter));
            if (kvmExit)
                preparation.push(message("MEMORY", "memslot result", "ret " + eventInfo(kvmExit).result, LANE.KVM, LANE.QEMU, kvmExit));
        } else {
            preparation.push(message("MEMORY", "KVM memslot registration", "GPA → QEMU HVA", LANE.QEMU, LANE.KVM, null, true));
        }
        if (attach)
            preparation.push(message("DOMAIN", "attach requester", addressInfo(attach).device, LANE.VFIO, LANE.IOMMU, attach));
        preparation.sort(function (left, right) {
            if (!left.record)
                return -1;
            if (!right.record)
                return 1;
            return left.record.time_ns - right.record.time_ns;
        });
        items = items.concat(preparation);

        if (transaction) {
            mappingEvents = [transaction.enter].concat(transaction.type1, selectedPins, selectedMap || [], transaction.exit || []).filter(Boolean);
            mappingEvents.sort(function (left, right) { return left.time_ns - right.time_ns; });
            mappingEvents.forEach(function (record) {
                var address = addressInfo(record);
                var entering;

                if (record.kind === "vfio_dma_map_enter")
                    items.push(message("MAP", "VFIO_IOMMU_MAP_DMA", "fd " + eventInfo(record).fd + " · IOVA " + address.iova + " · " + formatBytes(address.size), LANE.QEMU, LANE.VFIO, record));
                else if (record.kind === "vfio_type1_map_enter")
                    items.push(message("MAP", "validate map request", "VFIO type1 backend", LANE.VFIO, LANE.VFIO, record));
                else if (record.kind === "vfio_type1_map_exit")
                    items.push(message("MAP", "type1 map result", "ret " + eventInfo(record).result, LANE.VFIO, LANE.VFIO, record));
                else if (record.kind.indexOf("vfio_page_pin_") === 0) {
                    entering = record.kind === "vfio_page_pin_enter";
                    items.push(message("MAP", entering ? "pin backing pages" : "page-pin result", entering ? "HVA " + address.hva + " · " + address.page_count + " pages" : "pinned " + eventInfo(record).result + " pages", entering ? LANE.VFIO : LANE.MEMORY, entering ? LANE.MEMORY : LANE.VFIO, record));
                } else if (record.kind === "iommu_map")
                    items.push(message("MAP", "iommu:map", "IOVA " + address.iova + " → HPA " + address.hpa + " · " + formatBytes(address.size), LANE.VFIO, LANE.IOMMU, record));
                else if (record.kind === "vfio_dma_map_exit")
                    items.push(message("MAP", "map result", "ret " + eventInfo(record).result, LANE.VFIO, LANE.QEMU, record));
            });
            if (!selectedPins.length) {
                var mapRequestIndex = items.findIndex(function (item) { return item.record === transaction.enter; });
                items.splice(mapRequestIndex + 1, 0, message("MAP", "pin backing pages", "QEMU HVA → resident host pages", LANE.VFIO, LANE.MEMORY, null, true));
            }
        }
        if (mmioRecord) {
            var mmio = mmioInfo(mmioRecord);
            var mmioBar = guestBarForGpa(mmio.gpa);
            items.push(message("MMIO", "BAR MMIO write", "BAR " + (mmioBar ? mmioBar.region : "—") + " · GPA " + mmio.gpa + " · " + mmio.length + " bytes", LANE.GUEST, LANE.KVM, mmioRecord));
        }
        var loopbackActive = false;
        var loopbackComplete = false;

        guestRecords.forEach(function (record) {
            var dma = dmaInfo(record);
            var interrupt = interruptInfo(record);
            var mappedDma;
            var irqGroup;
            var translatedChunk;
            var translatedHpa;

            if (record.kind === "guest_ixgbe_run_loopback_entry") {
                loopbackActive = true;
                items.push(message("DMA USE", "run loopback test", "64 TX/RX frames per batch", LANE.GUEST, LANE.GUEST, record));
            } else if (record.kind === "guest_ixgbe_xmit_entry")
                items.push(message("DMA USE", "submit test frame", formatBytes(dma.length) + " skb", LANE.GUEST, LANE.GUEST, record));
            else if (record.kind === "guest_dma_map_entry")
                items.push(message("DMA USE", "map TX buffer", formatBytes(dma.length) + " · DMA_TO_DEVICE", LANE.GUEST, LANE.DMA, record));
            else if (record.kind === "guest_dma_map_exit")
                items.push(message("DMA USE", "return DMA address", dma.address + " · " + formatBytes(dma.length), LANE.DMA, LANE.GUEST, record));
            else if (record.kind === "guest_ixgbe_xmit_exit") {
                items.push(message("DMA USE", "publish TX tail", "ixgbe_xmit_frame_ring() · ret " + eventInfo(record).result, LANE.GUEST, LANE.NIC, record));
                mappedDma = guestEvent("guest_dma_map_exit");
                translatedChunk = mappedDma && transaction && transaction.chunks.find(function (chunkRecord) {
                    var chunk = addressInfo(chunkRecord);
                    return big(dmaInfo(mappedDma).address) >= big(chunk.iova) && big(dmaInfo(mappedDma).address) < big(chunk.iova) + big(chunk.size);
                });
                if (translatedChunk) {
                    translatedHpa = big(addressInfo(translatedChunk).hpa) + big(dmaInfo(mappedDma).address) - big(addressInfo(translatedChunk).iova);
                    items.push(message("DMA USE", "fetch TX descriptor/data", "IOVA " + dmaInfo(mappedDma).address, LANE.NIC, LANE.IOMMU, null, true));
                    items.push(message("DMA USE", "VT-d translation", "HPA 0x" + translatedHpa.toString(16), LANE.IOMMU, LANE.MEMORY, null, true));
                }
            } else if (record.kind === "guest_ixgbe_clean_entry")
                items.push(message("COMPLETION", "inspect test rings", "TX descriptor writeback + RX length", LANE.GUEST, LANE.NIC, record));
            else if (record.kind === "guest_dma_unmap")
                items.push(message("COMPLETION", "unmap TX buffer", dma.address + " · " + formatBytes(dma.length), LANE.GUEST, LANE.DMA, record));
            else if (record.kind === "guest_dma_sync_for_cpu")
                items.push(message("COMPLETION", "sync RX for CPU", dma.address + " · " + formatBytes(dma.length), LANE.GUEST, LANE.DMA, record));
            else if (record.kind === "guest_dma_sync_for_device")
                items.push(message("COMPLETION", "return RX to device", dma.address + " · " + formatBytes(dma.length), LANE.GUEST, LANE.DMA, record));
            else if (record.kind === "guest_ixgbe_clean_exit")
                items.push(message("COMPLETION", "frames verified", dma.completed + " descriptors + frame patterns", LANE.NIC, LANE.GUEST, record));
            else if (record.kind === "guest_irq_handler_entry") {
                irqGroup = loopbackActive ? "LOOPBACK IRQ" : (loopbackComplete ? "POST-LOOPBACK IRQ" : "PRE-LOOPBACK IRQ");
                items.push(message(irqGroup, "IRQ handler enters", interrupt.action + " · IRQ " + interrupt.irq, LANE.NIC, LANE.GUEST, record));
            } else if (record.kind === "guest_irq_handler_exit") {
                irqGroup = loopbackActive ? "LOOPBACK IRQ" : (loopbackComplete ? "POST-LOOPBACK IRQ" : "PRE-LOOPBACK IRQ");
                items.push(message(irqGroup, "IRQ handler exits", "IRQ " + interrupt.irq + " · " + irqDisposition(eventInfo(record).result), LANE.GUEST, LANE.GUEST, record));
            } else if (record.kind === "guest_ixgbe_run_loopback_exit") {
                items.push(message("COMPLETION", "loopback run result", "ret " + eventInfo(record).result, LANE.GUEST, LANE.GUEST, record));
                loopbackActive = false;
                loopbackComplete = true;
            }
        });
        if (physicalIrq)
            items.push(message("INTERRUPT", physicalIrq.kind.indexOf("msi") >= 0 ? "VFIO MSI-X handler" : "VFIO INTx handler", "host IRQ " + interruptInfo(physicalIrq).irq, LANE.NIC, LANE.VFIO, physicalIrq));
        if (irqfd)
            items.push(message("INTERRUPT", "wake KVM irqfd", "VFIO eventfd notification", LANE.VFIO, LANE.KVM, irqfd));
        if (msiRoute)
            items.push(message("INTERRUPT", "route guest MSI", "vector " + interruptInfo(msiRoute).vector, LANE.VFIO, LANE.KVM, msiRoute));
        if (apicAccept)
            items.push(message("INTERRUPT", "LAPIC accepts vector", "vCPU APIC " + interruptInfo(apicAccept).apic_id + " · vector " + interruptInfo(apicAccept).vector, LANE.KVM, LANE.GUEST, apicAccept));
        if (teardown) {
            teardownEvents = teardownEventsForChunk(teardown, selectedMap);
            teardownEvents.sort(function (left, right) { return left.time_ns - right.time_ns; });
            teardownEvents.forEach(function (record) {
                var address = addressInfo(record);
                var entering;

                if (record.kind === "vfio_dma_unmap_enter")
                    items.push(message("TEARDOWN", "VFIO_IOMMU_UNMAP_DMA", "IOVA " + address.iova + " · " + formatBytes(address.size), LANE.QEMU, LANE.VFIO, record));
                else if (record.kind === "iommu_unmap")
                    items.push(message("TEARDOWN", "iommu:unmap", "IOVA " + address.iova + " · removed " + formatBytes(address.returned_size), LANE.VFIO, LANE.IOMMU, record));
                else if (record.kind.indexOf("vfio_page_unpin_") === 0) {
                    entering = record.kind === "vfio_page_unpin_enter";
                    items.push(message("TEARDOWN", entering ? "release pinned pages" : "page-unpin result", entering ? address.page_count + " pages" : "released " + eventInfo(record).result + " pages", entering ? LANE.VFIO : LANE.MEMORY, entering ? LANE.MEMORY : LANE.VFIO, record));
                } else if (record.kind === "vfio_dma_unmap_exit")
                    items.push(message("TEARDOWN", "unmap result", "ret " + eventInfo(record).result + " · removed " + formatBytes(address.returned_size), LANE.VFIO, LANE.QEMU, record));
            });
        }
        return items;
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
            vfio_dma_unmap_exit: "unmap result"
        };

        return titles[record.kind] || record.kind.replace(/_/g, " ");
    }

    function compactLabel(value) {
        return String(value || "—");
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
            { phase: "A", label: "DEVICE ASSIGNMENT", items: phaseAItems() },
            { phase: "B", label: "DMA REMAPPING", items: phaseBItems() }
        ];

        byId("roadmap").innerHTML = '<header class="roadmap-head"><b>EXECUTION</b><span>PHASE · BOUNDARY</span></header>' + groups.map(function (group) {
            var active = group.phase === selectedPhase;
            var current = active && group.items[selectedIndex];
            var dots = group.items.map(function (item, index) {
                return '<button class="boundary-dot' + (active && index === selectedIndex ? " current" : "") + '" type="button" data-boundary-phase="' + group.phase + '" data-boundary-index="' + index + '" title="' + escapeHtml(item.label) + '"></button>';
            }).join("");
            return '<section class="roadmap-zone' + (active ? " active" : "") + '" data-phase-zone="' + group.phase + '" style="flex-grow:' + Math.max(1, group.items.length) + '"><div class="zone-copy"><b><em>' + group.phase + '</em> · ' + group.label + '</b><span>' + group.items.length + ' boundaries' + (current ? " · " + escapeHtml(current.label) : "") + '</span></div><div class="zone-dots">' + dots + '</div></section>';
        }).join("") + '<section class="roadmap-zone future"><div class="zone-copy"><b><em>C</em> · DMA PROTECTION</b><span>future phase</span></div></section><section class="roadmap-zone future"><div class="zone-copy"><b><em>D</em> · INTERRUPT REMAPPING</b><span>future phase</span></div></section>';

        byId("roadmap").querySelectorAll("[data-boundary-index]").forEach(function (button) {
            button.onclick = function (event) {
                event.stopPropagation();
                if (selectedPhase !== button.dataset.boundaryPhase)
                    selectPhase(button.dataset.boundaryPhase);
                selectRecord(Number(button.dataset.boundaryIndex));
            };
        });
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

    function renderPhaseA(record) {
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
            return '<option value="' + index + '">' + (index + 1) + ' · IOVA ' + escapeHtml(address.iova) + ' · ' + escapeHtml(formatBytes(address.size)) + ' · ' + transaction.chunks.length + ' maps</option>';
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
        byId("map-summary").textContent = transaction ? "request " + (eventInfo(transaction.enter).request_id || "legacy") : "no mappings";
        byId("chunk-list").querySelectorAll("[data-chunk]").forEach(function (button) {
            button.onclick = function () {
                selectedChunk = Number(button.dataset.chunk);
                phaseItems = phaseBItems();
                selectedIndex = phaseItems.findIndex(function (item) { return item.record === chunks[selectedChunk]; });
                if (selectedIndex < 0)
                    selectedIndex = 0;
                renderChunks();
                renderPhaseB();
                renderInspector(phaseItems[selectedIndex]);
                renderRoadmap();
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
            else if (actor.id === "guest-dma")
                resource = "guest DMA addresses";
            else if (actor.id === "kvm")
                resource = "GPA memslots";
            else if (actor.id === "vfio")
                resource = transaction ? "fd " + eventInfo(transaction.enter).fd : "container";
            else if (actor.id === "memory")
                resource = "pinned pages";
            else if (actor.id === "iommu")
                resource = "IOVA mappings";
            else if (actor.id === "nic")
                resource = candidate.bdf || "PCIe requester";
            else
                resource = "DMA descriptors";
            return '<div class="lifeline-actor' + (active ? " active" : "") + '"><small>' + actor.role + '</small><b>' + escapeHtml(actorName) + '</b><span>' + escapeHtml(resource) + '</span></div>';
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
        var style = distance ? "left:" + left + "%;width:" + width + "%" : "left:" + ((item.from + 0.5) / actors.length * 100) + "%";

        return '<button class="interaction-row' + (index === selectedIndex ? " current" : "") + evidence + '" type="button" data-message="' + index + '"><span class="message-group">' + escapeHtml(item.group) + '</span><span class="message-line' + direction + '" style="' + style + '"><i></i><span class="message-copy"><b>' + escapeHtml(item.label) + '</b><small>' + escapeHtml(item.detail) + '</small></span></span></button>';
    }

    function renderPhaseB() {
        var current = selectedIndex >= 0 ? phaseItems[selectedIndex] : null;

        renderActors(current);
        byId("interaction-rows").innerHTML = phaseItems.map(renderMessage).join("");
        byId("flow-caption").textContent = current ? current.group + " · " + current.label : "Select a message to inspect its captured boundary.";
        byId("interaction-rows").querySelectorAll("[data-message]").forEach(function (button) {
            button.onclick = function () { selectRecord(Number(button.dataset.message)); };
        });
    }

    function phaseAFields(record) {
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

    function phaseBFields(item) {
        var record = item.record;
        var info = eventInfo(record);
        var address = addressInfo(record);
        var dma = dmaInfo(record);
        var interrupt = interruptInfo(record);
        var mmio = mmioInfo(record);
        var context = record && record.context ? record.context : {};

        if (!record)
            return { classification: "architecture", relationship: actors[item.from].name + " → " + actors[item.to].name };
        return {
            hook: info.hook,
            operation: info.operation,
            request_id: info.request_id || null,
            fd: info.fd || null,
            command: info.command !== "0x0" ? info.command : null,
            argsz: info.argsz || null,
            slot: record.kind.indexOf("kvm_memory") === 0 ? info.slot : null,
            flags: info.flags || null,
            result: /exit|result/.test(record.kind) || record.kind.indexOf("_exit") >= 0 ? info.result : null,
            HVA: address.hva !== "0x0" ? address.hva : null,
            GPA: address.gpa !== "0x0" ? address.gpa : null,
            IOVA: address.iova !== "0x0" || /iommu|vfio_dma/.test(record.kind) ? address.iova : null,
            HPA: address.hpa !== "0x0" ? address.hpa : null,
            size: address.size !== "0x0" ? address.size : null,
            returned_size: address.returned_size !== "0x0" ? address.returned_size : null,
            pages: address.page_count || null,
            device: address.device || null,
            DMA: dma.address && dma.address !== "0x0" ? dma.address : null,
            bytes: dma.length || null,
            direction: dmaDirection(dma.direction),
            completed: dma.completed || null,
            IRQ: interrupt.irq || null,
            vector: interrupt.vector || null,
            APIC: interrupt.apic_id || null,
            action: interrupt.action || null,
            MMIO_GPA: mmio.gpa || null,
            MMIO_value: mmio.value || null,
            MMIO_bytes: mmio.length || null,
            MMIO_access: mmio.type === 2 ? "WRITE" : (mmio.type === 1 ? "READ" : (mmio.type === 0 ? "READ UNSATISFIED" : null)),
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
        fields = selectedPhase === "A" ? phaseAFields(record) : phaseBFields(item);

        byId("fields").innerHTML = Object.keys(fields).filter(function (key) {
            return fields[key] !== undefined && fields[key] !== null && fields[key] !== "";
        }).map(function (key) {
            return '<dt>' + escapeHtml(key) + '</dt><dd title="' + escapeHtml(fields[key]) + '">' + escapeHtml(fields[key]) + '</dd>';
        }).join("");
        byId("source-badge").textContent = record ? compactLabel(eventInfo(record).hook || record.source) : "architecture";
        byId("event-title").textContent = item.label;
        byId("selected-time").textContent = record ? "t = " + record.time_ns + " ns" : "architectural path";
    }

    function selectRecord(index) {
        var item;

        if (!phaseItems.length)
            return;
        selectedIndex = Math.max(0, Math.min(phaseItems.length - 1, index));
        item = phaseItems[selectedIndex];
        if (selectedPhase === "A")
            renderPhaseA(item.record);
        else
            renderPhaseB();
        renderInspector(item);
        renderRoadmap();
        byId("counter").textContent = (selectedIndex + 1) + " / " + phaseItems.length;
    }

    function selectPhase(phase) {
        selectedPhase = phase;
        byId("phase-a-state").classList.toggle("hidden", phase !== "A");
        byId("phase-b-state").classList.toggle("hidden", phase !== "B");
        byId("machine-title").textContent = phase === "A" ? "Device assignment" : "DMA remapping";
        byId("machine-caption").textContent = phase === "A" ? "One physical function, changing software ownership." : "QEMU registers memory; VFIO and VT-d make it reachable to the assigned device.";
        phaseItems = phase === "A" ? phaseAItems() : phaseBItems();
        if (phase === "B") {
            selectedIndex = -1;
            renderMapSelector();
            renderChunks();
            renderPhaseB();
            renderInspector(null);
            renderRoadmap();
            byId("counter").textContent = "— / " + phaseItems.length;
            return;
        }
        selectedIndex = 0;
        selectRecord(selectedIndex);
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
        selectedChunk = 0;
        phaseItems = phaseBItems();
        renderChunks();
        selectedIndex = -1;
        renderPhaseB();
        renderInspector(null);
        renderRoadmap();
        byId("counter").textContent = "— / " + phaseItems.length;
    };

    Promise.all([loadText(assignmentPath), loadText(ebpfPath), loadText(guestPath), loadText(setupPath)]).then(function (texts) {
        assignmentRecords = parseNdjson(texts[0]);
        ebpfRecords = parseNdjson(texts[1]).filter(function (record) { return record.kind !== "capture_meta" && record.kind !== "capture_summary"; });
        guestRecords = parseNdjson(texts[2]).filter(function (record) { return record.kind !== "capture_meta" && record.kind !== "capture_summary"; });
        setupFacts = parseSetup(texts[3]);
        buildTransactions();
        renderSetupFacts();
        byId("status").innerHTML = '<i class="trace-dot"></i><span>assignment + host eBPF + guest eBPF' + (skippedLines ? " · " + skippedLines + " skipped" : "") + '</span>';
        selectPhase(window.location.hash === "#B" ? "B" : "A");
    }).catch(function (error) {
        byId("status").textContent = "VT·D data error · " + error.message;
    });
})();
