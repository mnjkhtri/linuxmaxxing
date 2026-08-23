(function () {
    "use strict";

    var cacheKey = "?v=" + Date.now();
    var assignmentPath = "../../shared/_captures/virt-vtd.assignment.ndjson" + cacheKey;
    var ebpfPath = "../../shared/_captures/virt-vtd.eBPF.ndjson" + cacheKey;
    var setupPath = "../../shared/_captures/virt-vtd-setup.txt" + cacheKey;
    var assignmentRecords = [];
    var ebpfRecords = [];
    var setupFacts = {};
    var mapTransactions = [];
    var selectedTransaction = 0;
    var selectedChunk = 0;
    var phaseRecords = [];
    var selectedIndex = 0;
    var selectedPhase = "A";

    function byId(id) {
        return document.getElementById(id);
    }

    function escapeHtml(value) {
        return String(value == null ? "not sampled" : value).replace(/[&<>"']/g, function (character) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character];
        });
    }

    function eventInfo(record) {
        return record && record.event_info ? record.event_info : {};
    }

    function recordState(record) {
        return record && record.state ? record.state : {};
    }

    function parseNdjson(text) {
        return text.split(/\r?\n/).filter(Boolean).map(function (line) {
            return JSON.parse(line);
        });
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

    function numeric(value) {
        return Number.parseInt(value || "0", 16);
    }

    function sameRange(left, right) {
        return left.iova === right.iova && left.size === right.size;
    }

    function buildTransactions() {
        var exits = ebpfRecords.filter(function (record) { return record.kind === "vfio_dma_map_exit"; });
        var chunks = ebpfRecords.filter(function (record) { return record.kind === "iommu_map"; });
        var usedExits = new Set();

        mapTransactions = ebpfRecords.filter(function (record) {
            return record.kind === "vfio_dma_map_enter";
        }).map(function (enter) {
            var enterInfo = eventInfo(enter);
            var exit = exits.find(function (candidate) {
                var candidateInfo = eventInfo(candidate);
                return !usedExits.has(candidate) &&
                    candidate.time_ns >= enter.time_ns &&
                    candidate.context.tid === enter.context.tid &&
                    sameRange(candidateInfo, enterInfo);
            });
            var relatedChunks;

            if (exit)
                usedExits.add(exit);
            relatedChunks = chunks.filter(function (chunk) {
                var info = eventInfo(chunk);
                return info.parent_iova === enterInfo.iova &&
                    info.parent_size === enterInfo.size &&
                    chunk.time_ns >= enter.time_ns &&
                    (!exit || chunk.time_ns <= exit.time_ns);
            });
            return { enter: enter, exit: exit, chunks: relatedChunks };
        });

        selectedTransaction = mapTransactions.findIndex(function (transaction) {
            var info = eventInfo(transaction.enter);
            return transaction.exit && eventInfo(transaction.exit).result === 0 &&
                numeric(info.size) >= 0x100000 && transaction.chunks.length > 1;
        });
        if (selectedTransaction < 0)
            selectedTransaction = 0;
    }

    function phaseARecords() {
        var order = ["host_owns_device", "vfio_bound", "qemu_attached", "guest_visible", "host_reclaims_device"];
        return order.map(function (kind) {
            return assignmentRecords.find(function (record) { return record.kind === kind; });
        }).filter(Boolean);
    }

    function candidateAttach() {
        var candidate = setupFacts.candidate_device || {};
        return ebpfRecords.find(function (record) {
            return record.kind === "iommu_device_attach" && eventInfo(record).device === candidate.bdf;
        }) || ebpfRecords.find(function (record) { return record.kind === "iommu_device_attach"; });
    }

    function teardownRecord() {
        return ebpfRecords.find(function (record) {
            return record.kind === "iommu_unmap" && eventInfo(record).hook === "iommu:unmap";
        });
    }

    function phaseBRecords() {
        var transaction = mapTransactions[selectedTransaction];
        var chunk = transaction && transaction.chunks[selectedChunk];
        return [candidateAttach(), transaction && transaction.enter, chunk,
            transaction && transaction.exit, teardownRecord()].filter(Boolean);
    }

    function compactSubjectFor(record) {
        var subjects = {
            host_owns_device: "HOST IXGBE",
            vfio_bound: "VFIO-PCI",
            qemu_attached: "QEMU · Q35",
            guest_visible: "GUEST IXGBE",
            host_reclaims_device: "HOST IXGBE",
            iommu_device_attach: "IOMMU DOMAIN",
            vfio_dma_map_enter: "VFIO DMA MAP",
            iommu_map: "VT-d TRANSLATION",
            vfio_dma_map_exit: "VFIO DMA MAP",
            iommu_unmap: "IOMMU DOMAIN"
        };

        return subjects[record.kind] || record.kind.replace(/_/g, " ").toUpperCase();
    }

    function compactLabel(value) {
        return String(value || "—").replace(/_/g, " ").toUpperCase();
    }

    function renderSetupFacts() {
        var host = setupFacts.host || {};
        var management = setupFacts.management_device || {};
        var candidate = setupFacts.candidate_device || {};
        var tracepoints = setupFacts.tracepoints || {};
        var networkLines = (setupFacts.network && setupFacts.network.lines) || [];
        var groupLines = (setupFacts.iommu_groups && setupFacts.iommu_groups.lines) || [];
        var groups = {};
        var availableHooks = Object.keys(tracepoints).filter(function (name) {
            return name !== "lines" && tracepoints[name] === "true";
        }).map(function (name) {
            return name.replace(/^iommu_/, "iommu:");
        });
        var managementLink = networkLines.find(function (line) {
            return management.interface && line.indexOf(management.interface + " ") === 0;
        });
        var candidateLink = networkLines.find(function (line) {
            return candidate.interface && line.indexOf(candidate.interface + " ") === 0;
        });

        groupLines.forEach(function (line) {
            var match = line.match(/^group=(\d+) bdf=(\S+)$/);
            if (!match)
                return;
            groups[match[1]] = groups[match[1]] || [];
            groups[match[1]].push(match[2]);
        });

        byId("physical-bdf").textContent = candidate.bdf || "not sampled";
        byId("physical-name").textContent = [candidate.name, candidate.vendor_device].filter(Boolean).join(" · ") || "not sampled";
        byId("management-bdf").textContent = management.bdf || "not sampled";
        byId("management-detail").textContent = [management.interface, management.driver,
            management.iommu_group ? "IOMMU group " + management.iommu_group : null].filter(Boolean).join(" · ");
        byId("candidate-bdf").textContent = candidate.bdf || "not sampled";
        byId("candidate-detail").textContent = [candidate.interface, candidate.driver,
            candidate.iommu_group ? "IOMMU group " + candidate.iommu_group : null].filter(Boolean).join(" · ");
        byId("requester-bdf").textContent = candidate.bdf || "not sampled";
        byId("requester-name").textContent = candidate.name ? candidate.name + " requester" : "not sampled";
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
        byId("setup-tracepoints").textContent = availableHooks.join(" · ") || "not sampled";
        byId("group-summary").textContent = Object.keys(groups).length + " groups · group " +
            (management.iommu_group || "—") + " ≠ group " + (candidate.iommu_group || "—");
        byId("group-map").innerHTML = Object.keys(groups).sort(function (left, right) {
            return Number(left) - Number(right);
        }).map(function (group) {
            var className = group === management.iommu_group ? " management" :
                (group === candidate.iommu_group ? " candidate" : "");
            var devices = groups[group];
            return '<div class="iommu-group' + className + '" title="' + escapeHtml(devices.join(" · ")) + '">' +
                '<b>G' + escapeHtml(group) + '</b><span>' + devices.length + '</span></div>';
        }).join("");
    }

    function timelineTitleFor(record) {
        var titles = {
            host_owns_device: "HOST OWNERSHIP",
            vfio_bound: "VFIO BIND",
            qemu_attached: "QEMU ATTACH",
            guest_visible: "GUEST VISIBLE",
            host_reclaims_device: "HOST RECLAIM",
            iommu_device_attach: "DOMAIN ATTACH",
            vfio_dma_map_enter: "VFIO MAP REQUEST",
            iommu_map: "IOMMU MAP",
            vfio_dma_map_exit: "VFIO MAP RESULT",
            iommu_unmap: "IOMMU UNMAP"
        };

        return titles[record.kind] || record.kind.toUpperCase();
    }

    function renderRoadmap() {
        var groups = [
            { phase: "A", label: "DEVICE ASSIGNMENT", records: phaseARecords() },
            { phase: "B", label: "DMA REMAPPING", records: phaseBRecords() }
        ];
        var roadmap = byId("roadmap");

        roadmap.innerHTML = "<header class=\"roadmap-head\"><b>EXECUTION</b><span>PHASE · BOUNDARY</span></header>" +
            groups.map(function (group) {
                var isActive = group.phase === selectedPhase;
                var activeRecord = isActive && group.records[selectedIndex];
                var detail = group.records.length + " boundaries" +
                    (activeRecord ? " · " + timelineTitleFor(activeRecord) : "");
                var dots = group.records.map(function (record, index) {
                    var current = isActive && index === selectedIndex ? " current" : "";
                    var hook = eventInfo(record).hook || record.source;
                    return "<button class=\"boundary-dot" + current + "\" type=\"button\" data-boundary-phase=\"" +
                        group.phase + "\" data-boundary-index=\"" + index + "\" title=\"" +
                        escapeHtml(timelineTitleFor(record) + " · " + hook) + "\" aria-label=\"Select " +
                        escapeHtml(timelineTitleFor(record)) + "\"></button>";
                }).join("");
                return "<section class=\"roadmap-zone" + (isActive ? " active" : "") +
                    "\" data-phase-zone=\"" + group.phase + "\" style=\"flex-grow:" + Math.max(1, group.records.length) + "\">" +
                    "<div class=\"zone-copy\"><b><em>" + group.phase + "</em> · " + escapeHtml(group.label) +
                    "</b><span>" + escapeHtml(detail) + "</span></div><div class=\"zone-dots\">" + dots + "</div></section>";
            }).join("") +
            "<section class=\"roadmap-zone future\"><div class=\"zone-copy\"><b><em>C</em> · DMA PROTECTION</b><span>future phase</span></div></section>" +
            "<section class=\"roadmap-zone future\"><div class=\"zone-copy\"><b><em>D</em> · INTERRUPT REMAPPING</b><span>future phase</span></div></section>";

        roadmap.querySelectorAll("[data-boundary-index]").forEach(function (button) {
            button.onclick = function (event) {
                event.stopPropagation();
                if (selectedPhase !== button.dataset.boundaryPhase)
                    selectPhase(button.dataset.boundaryPhase);
                selectRecord(Number(button.dataset.boundaryIndex));
            };
        });
        roadmap.querySelectorAll("[data-phase-zone]").forEach(function (zone) {
            zone.onclick = function () { selectPhase(zone.dataset.phaseZone); };
        });
    }

    function clearHighlights() {
        document.querySelectorAll(".node.active").forEach(function (node) {
            node.classList.remove("active");
        });
    }

    function parseBar(bar) {
        var match = String(bar).match(/^Region\s+(\d+):\s+(.+?)\s+at\s+(\S+)(?:\s+\(([^)]+)\))?\s+\[size=([^\]]+)\]/);

        if (!match)
            return { region: "PCI", type: String(bar), address: "not sampled", attributes: "", size: "" };
        return { region: match[1], type: match[2], address: match[3], attributes: match[4] || "", size: match[5] };
    }

    function renderBar(bar) {
        var parsed = parseBar(bar);
        var attributes = parsed.attributes.split(",").map(function (part) {
            return part.trim();
        }).filter(Boolean).join(" · ");

        return "<article class=\"bar-card\" title=\"" + escapeHtml(bar) + "\"><header><b>REGION " +
            escapeHtml(parsed.region) + "</b><span>" + escapeHtml(parsed.size) + "</span></header>" +
            "<strong>" + escapeHtml(parsed.type) + "</strong><code>" + escapeHtml(parsed.address) + "</code>" +
            (attributes ? "<small>" + escapeHtml(attributes) + "</small>" : "") + "</article>";
    }

    function renderGuestProof(physical, guest) {
        var bars = Array.isArray(guest.bars) ? guest.bars : [];

        if (guest.present !== true) {
            byId("host-bdf-proof").textContent = physical.host_bdf || "not sampled";
            byId("guest-bdf-proof").textContent = "not present";
            byId("guest-bars").innerHTML = "<span class=\"bar-empty\">The function is not present in guest PCI topology at this boundary.</span>";
            return;
        }
        byId("host-bdf-proof").textContent = physical.host_bdf || "not sampled";
        byId("guest-bdf-proof").textContent = guest.guest_bdf || "not sampled";
        byId("guest-bars").innerHTML = bars.map(renderBar).join("");
    }

    function renderPhaseA(record) {
        var current = recordState(record);
        var candidate = setupFacts.candidate_device || {};
        var physical = {
            host_bdf: candidate.bdf,
            name: candidate.name,
            vendor_device: candidate.vendor_device,
            host_interface: candidate.interface
        };
        var assignment = current.assignment || {};
        var guest = current.guest_device || {};
        var nodes = [byId("host-owner"), byId("vfio-owner"), byId("qemu-owner"), byId("guest-owner")];

        byId("physical-bdf").textContent = physical.host_bdf || "not sampled";
        byId("physical-name").textContent = [physical.name, physical.vendor_device].filter(Boolean).join(" · ");
        byId("host-interface").textContent = physical.host_interface || "not sampled";
        byId("guest-interface").textContent = guest.present ? [guest.guest_bdf, guest.interface].filter(Boolean).join(" · ") : "not present";

        nodes.forEach(function (node) { node.classList.add("inactive"); });
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
        renderGuestProof(physical, guest);
    }

    function currentTransaction() {
        return mapTransactions[selectedTransaction] || null;
    }

    function renderMapSelector() {
        byId("map-select").innerHTML = mapTransactions.map(function (transaction, index) {
            var info = eventInfo(transaction.enter);
            return '<option value="' + index + '">' + (index + 1) + ' · IOVA ' + escapeHtml(info.iova) +
                ' · size ' + escapeHtml(info.size) + ' · ' + transaction.chunks.length + ' chunks</option>';
        }).join("");
        byId("map-select").value = String(selectedTransaction);
    }

    function renderChunks() {
        var transaction = currentTransaction();
        var chunks = transaction ? transaction.chunks : [];
        var parent = transaction ? eventInfo(transaction.enter) : {};

        byId("chunk-caption").textContent = parent.iova ? "Observed chunks inside IOVA " + parent.iova + " + " + parent.size : "No captured mapping.";
        byId("chunk-count").textContent = chunks.length + " captured chunks";
        byId("chunk-list").innerHTML = chunks.map(function (record, index) {
            var info = eventInfo(record);
            return '<button class="chunk ' + (index === selectedChunk ? "active" : "") + '" type="button" data-chunk="' + index + '">' +
                '<b>chunk ' + index + '</b><span>IOVA ' + escapeHtml(info.iova) + '</span><span>HPA ' +
                escapeHtml(info.hpa) + '</span><span>size ' + escapeHtml(info.size) + '</span></button>';
        }).join("") || '<span class="chunk">No correlated IOMMU chunks captured.</span>';
        byId("chunk-list").querySelectorAll("[data-chunk]").forEach(function (button) {
            button.onclick = function () {
                selectedChunk = Number(button.dataset.chunk);
                phaseRecords = phaseBRecords();
                renderChunks();
                selectRecord(Math.min(2, phaseRecords.length - 1));
            };
        });
    }

    function renderPhaseB(record) {
        var info = eventInfo(record);
        var transaction = currentTransaction();
        var isMap = record.kind === "iommu_map";
        var isEnter = record.kind === "vfio_dma_map_enter";
        var isExit = record.kind === "vfio_dma_map_exit";
        var displayedHva = "not sampled";
        var displayedIova = "not sampled";
        var displayedSize = "not sampled";
        var displayedPermissions = "not sampled";

        if (isEnter) {
            displayedHva = info.hva;
            displayedIova = info.iova;
            displayedSize = info.size;
            displayedPermissions = numeric(info.flags) === 3 ? "device READ / WRITE" : "flags " + info.flags;
        } else if (isMap) {
            displayedIova = info.parent_iova;
            displayedSize = info.parent_size;
        } else if (isExit) {
            displayedIova = info.iova;
            displayedSize = info.size;
        }

        byId("hva-value").textContent = "HVA " + displayedHva;
        byId("vfio-iova").textContent = "IOVA " + displayedIova;
        byId("vfio-size").textContent = "size " + displayedSize;
        byId("vfio-permissions").textContent = displayedPermissions;
        byId("map-summary").textContent = transaction ? transaction.chunks.length + " correlated iommu:map records" : "no mappings";
        byId("runtime-iova").textContent = "IOVA " + (isMap ? info.iova : "not sampled");
        byId("hpa-value").textContent = "HPA " + (isMap ? info.hpa : "not sampled");
        byId("chunk-size").textContent = isMap ? "mapping size " + info.size : "not sampled at this boundary";
        byId("domain-state").textContent = record.kind === "iommu_device_attach" ? "device attachment observed" : "attached for assigned requester";

        if (isEnter || isExit) {
            byId("qemu-map").classList.add("active");
            byId("vfio-map").classList.add("active");
        } else if (record.kind === "iommu_device_attach") {
            byId("iommu-domain").classList.add("active");
            byId("requester").classList.add("active");
        } else if (isMap) {
            byId("vtd-translation").classList.add("active");
            byId("host-page").classList.add("active");
        }
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
            host_interface: candidate.interface,
            owner: assignment.owner,
            vfio_bound: assignment.vfio_bound,
            qemu_attached: assignment.qemu_attached,
            guest_bdf: guest.present ? guest.guest_bdf : null,
            guest_driver: guest.present ? guest.driver : null,
            guest_interface: guest.present ? guest.interface : null,
            msix: guest.present ? guest.msix_present : null
        };
    }

    function phaseBFields(record) {
        var info = eventInfo(record);
        var fields = {
            source: record.source,
            hook: info.hook,
            time_ns: record.time_ns,
            pid: record.context && record.context.pid,
            tid: record.context && record.context.tid
        };

        if (record.kind === "vfio_dma_map_enter")
            Object.assign(fields, { command: info.command, HVA: info.hva, IOVA: info.iova, size: info.size, flags: info.flags });
        else if (record.kind === "vfio_dma_map_exit")
            Object.assign(fields, { command: info.command, IOVA: info.iova, size: info.size, result: info.result });
        else if (record.kind === "iommu_map")
            Object.assign(fields, { IOVA: info.iova, HPA: info.hpa, size: info.size,
                parent_iova: info.parent_iova, parent_size: info.parent_size, correlated: info.correlated });
        else if (record.kind === "iommu_unmap")
            Object.assign(fields, { IOVA: info.iova, size: info.size });
        else if (record.kind === "iommu_device_attach")
            fields.device = info.device;
        return fields;
    }

    function renderInspector(record) {
        var fields = selectedPhase === "A" ? phaseAFields(record) : phaseBFields(record);

        byId("fields").innerHTML = Object.keys(fields).filter(function (key) {
            return fields[key] !== undefined && fields[key] !== null && fields[key] !== "";
        }).map(function (key) {
            return "<dt>" + escapeHtml(key) + "</dt><dd title=\"" + escapeHtml(fields[key]) + "\">" + escapeHtml(fields[key]) + "</dd>";
        }).join("");
        byId("source-badge").textContent = compactLabel(record.source);
        byId("event-kind").textContent = timelineTitleFor(record);
        byId("event-title").textContent = compactSubjectFor(record);
    }

    function selectRecord(index) {
        var record;

        if (!phaseRecords.length)
            return;
        selectedIndex = Math.max(0, Math.min(phaseRecords.length - 1, index));
        record = phaseRecords[selectedIndex];
        clearHighlights();
        byId("selected-time").textContent = "t = " + record.time_ns + " ns";
        if (selectedPhase === "A")
            renderPhaseA(record);
        else
            renderPhaseB(record);
        renderInspector(record);
        renderRoadmap();
        byId("counter").textContent = (selectedIndex + 1) + " / " + phaseRecords.length;
    }

    function selectPhase(phase) {
        selectedPhase = phase;
        byId("phase-a-state").classList.toggle("hidden", phase !== "A");
        byId("phase-b-state").classList.toggle("hidden", phase !== "B");
        byId("machine-title").textContent = phase === "A" ? "Device assignment" : "DMA remapping";
        byId("machine-caption").textContent = phase === "A" ? "One physical function, changing software ownership." : "Software installs mappings; VT-d hardware uses them.";
        byId("mechanism-title").textContent = phase === "A" ? "OWNERSHIP MECHANISM" : "DMA TRANSLATION MACHINERY";
        byId("mechanism-subtitle").textContent = phase === "A" ? "host → VFIO → guest" : "mapping setup beside the device path";
        phaseRecords = phase === "A" ? phaseARecords() : phaseBRecords();
        byId("event-count").textContent = phaseRecords.length + " boundaries";
        if (phase === "B") {
            renderMapSelector();
            renderChunks();
        }
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
        selectedChunk = 0;
        phaseRecords = phaseBRecords();
        renderChunks();
        byId("event-count").textContent = phaseRecords.length + " boundaries";
        selectRecord(Math.min(1, phaseRecords.length - 1));
    };

    Promise.all([loadText(assignmentPath), loadText(ebpfPath), loadText(setupPath)]).then(function (texts) {
        assignmentRecords = parseNdjson(texts[0]);
        ebpfRecords = parseNdjson(texts[1]);
        setupFacts = parseSetup(texts[2]);
        buildTransactions();
        renderSetupFacts();
        byId("status").innerHTML = '<i class="trace-dot"></i><span>assignment + eBPF + host inventory</span>';
        selectPhase(window.location.hash === "#B" ? "B" : "A");
    }).catch(function (error) {
        byId("status").textContent = "VT·D data error · " + error.message;
    });
})();
