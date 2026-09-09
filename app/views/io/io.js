import {
  mountView,
  relativeNs,
  values
} from '../../common.js';
/* The UI reads the three experiment artifacts independently and correlates them only in browser memory. */
(function() {
  'use strict';

  var tracepoints = [],
    markers = [],
    resources = [];
  var operations = [],
    journeys = {},
    navigation = [],
    selectedJourney = null,
    selectedNav = 0,
    selectedEvent = null,
    selectedSequenceSeq = null,
    selectedSequenceStep = null;
  var workloadPid = 0,
    deviceResource = null,
    fileResource = null,
    dmaResource = null,
    barResource = null,
    localResource = null,
    irqResource = null,
    controllerResource = null;

  function $(id) {
    return document.getElementById(id)
  }

  function esc(value) {
    return String(value == null ? '—' : value).replace(/[&<>"']/g, function(c) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      } [c]
    })
  }

  function number(value, fallback) {
    var parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : (fallback == null ? 0 : fallback)
  }

  function integer(value, fallback) {
    var parsed = String(value).toLowerCase().indexOf('0x') === 0 ? parseInt(value, 16) : parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : (fallback == null ? 0 : fallback)
  }

  function hex(value, width) {
    var parsed = integer(value, 0);
    return '0x' + parsed.toString(16).padStart(width || 1, '0')
  }

  function ns(record) {
    return number(record && record.time_ns)
  }

  function bytes(value) {
    value = number(value);
    if (value >= 1048576) return (value / 1048576).toFixed(1) + ' MiB';
    if (value >= 1024) return (value / 1024).toFixed(value % 1024 ? 1 : 0) + ' KiB';
    return value + ' B'
  }

  function shortResource(value) {
    var text = String(value == null ? '' : value),
      parts = text.split('/').filter(Boolean);
    return parts[parts.length - 1] || text
  }

  function traceName(record) {
    return (record.tracepoint || '').split(':')[1] || record.tracepoint || 'event'
  }

  function field(record, key, fallback) {
    var value = record && record.fields && record.fields[key];
    return value == null ? (fallback == null ? '—' : fallback) : value
  }

  function raw(record) {
    return field(record, 'raw_payload', '')
  }

  function isQedu(record) {
    return (record.tracepoint || '').indexOf('qedu:') === 0
  }

  function resource(type) {
    return resources.find(function(item) {
      return item.resource_type === type
    }) || {
      fields: {}
    }
  }

  function marker(name, edge) {
    return markers.find(function(record) {
      return record.marker === name && record.edge === edge
    })
  }

  function phaseTitle(name) {
    var begin = marker(name, 'begin');
    return begin && begin.facts.label || name.replace(/_/g, ' ')
  }

  function contextClass(record) {
    return (record.context && record.context.execution) || 'process'
  }

  function parseTraceFields(system, event, payload) {
    var fields = {
      ...values(payload)
    };
    fields.raw_payload = JSON.stringify(payload);
    if (system === 'syscalls') {
      if (fields.filename) fields.path = String(fields.filename).match(/"([^"]+)"/)?.[1];
      if (event.startsWith('sys_exit_')) fields.return_value = integer(fields.result, -1);
      if (event === 'sys_exit_openat') fields.return_fd = fields.return_value;
    }
    if (system === 'dma') {
      fields.direction = fields.dir;
      fields.dma_address = '0x' + String(fields.dma_addr).replace(/^0x/, '');
      fields.size_bytes = Number(fields.size);
      fields.cpu_pointer_token = fields.virt_addr
    }
    ['io_id', 'leg', 'bytes', 'count', 'offset', 'requested', 'completed', 'irq', 'timeout_ms', 'wait_ret', 'event_bit', 'queued', 'pid', 'cpu', 'ret', 'input', 'result', 'prev_pid', 'next_pid'].forEach(function(key) {
      if (fields[key] != null && /^-?(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(fields[key])) fields[key] = integer(fields[key])
    });
    if (fields.queued != null) fields.queued = !!fields.queued;
    if (event === 'qedu_dma_submit') {
      var command = integer(fields.command);
      fields.command = {
        raw: hex(command, 16),
        start: !!(command & 1),
        direction_from_device: !!(command & 2),
        interrupt_enable: !!(command & 4)
      };
      fields.source_address = hex(fields.src, 16);
      fields.destination_address = hex(fields.dst, 16);
      fields.source_space = fields.src_space;
      fields.destination_space = fields.dst_space;
      delete fields.src;
      delete fields.dst;
      delete fields.src_space;
      delete fields.dst_space
    }
    if (event === 'qedu_irq_ack') {
      var status = integer(fields.status),
        ack = integer(fields.ack);
      fields.status = {
        raw: hex(status, 8),
        factorial: !!(status & 1),
        dma: !!(status & 0x100)
      };
      fields.ack = hex(ack, 8)
    }
    if (event === 'qedu_probe_api') {
      var address = fields.address,
        size = fields.size,
        api = fields.api;
      delete fields.address;
      delete fields.size;
      if (api === 'qedu_probe' && fields.resource === 'pci_driver_probe') {
        fields.pci_dev = address;
        fields.object_size_bytes = integer(size)
      } else if (api === 'qedu_probe') {
        fields.qedu_dev = address;
        fields.object_size_bytes = integer(size)
      } else if (api === 'devm_kzalloc') {
        fields.qedu_dev = address;
        fields.object_size_bytes = integer(size)
      } else if (api === 'pci_enable_device') fields.pci_dev = address;
      else if (api === 'pci_request_regions') {
        fields.bar0_bus_address = address;
        fields.bar0_length_bytes = integer(size)
      } else if (api === 'pci_iomap') {
        fields.bar0_kernel_virtual_address = address;
        fields.mapped_length_bytes = integer(size)
      } else if (api === 'request_irq') {
        fields.linux_irq = integer(address);
        fields.irq_flags = hex(size)
      } else if (api === 'dma_set_mask_and_coherent') {
        fields.coherent_dma_mask = address;
        fields.dma_mask_bits = integer(size)
      } else if (api === 'pci_set_master') fields.bus_master_enabled = fields.result === 0;
      else if (api === 'dma_alloc_coherent') {
        fields.dma_address = address;
        fields.size_bytes = integer(size)
      } else if (api === 'alloc_ordered_workqueue') fields.workqueue_struct = address;
      else if (api === 'misc_register') fields.misc_minor = integer(address);
      else if (api === 'debugfs_create_dir' || api === 'debugfs_create_file') {
        fields.dentry = address;
        fields.mode = integer(size).toString(8).padStart(4, '0')
      }
    }
    if (event === 'qedu_factorial_submit' && fields.status_command != null) fields.status_command = hex(fields.status_command, 8);
    return fields
  }

  function parseTrace(capture) {
    const systems = {
      dma_alloc: 'dma',
      irq_handler_entry: 'irq',
      irq_handler_exit: 'irq',
      vector_alloc: 'irq_vectors',
      vector_config: 'irq_vectors'
    };
    return capture.events.filter(e => e.source.mechanism === 'tracefs').map(e => {
      const system = e.kind.startsWith('qedu_') ? 'qedu' : e.kind.startsWith('sys_') ? 'syscalls' : e.kind.startsWith('workqueue_') ? 'workqueue' : e.kind.startsWith('sched_') ? 'sched' : systems[e.kind] || 'kernel';
      const fields = parseTraceFields(system, e.kind, e.data.fields),
        correlation = {
          device: fields.device,
          operation_id: Number(fields.io_id || 0),
          dma_leg: fields.leg
        };
      const execution = e.kind.includes('irq_handler') || e.kind === 'qedu_irq_ack' || (e.kind === 'qedu_completion_publish' && fields.engine === 'FACTORIAL') ? 'hardirq' : e.context.comm?.startsWith('kworker') ? 'workqueue' : 'process';
      return {
        record: 'tracepoint',
        source: 'events.ndjson',
        time_ns: relativeNs(capture, e),
        tracepoint: system + ':' + e.kind,
        context: {
          ...e.context,
          pid: e.context.tid,
          execution
        },
        correlation,
        fields,
        canonical: e
      };
    });
  }

  function buildResources(debug, devicePath) {
    var vector = tracepoints.find(function(record) {
        return record.tracepoint === 'irq_vectors:vector_config'
      }),
      dmaTransfer = tracepoints.find(function(record) {
        return record.tracepoint === 'qedu:qedu_dma_submit'
      }),
      localAddress = field(dmaTransfer, 'source_space') === 'EDU_LOCAL' ? field(dmaTransfer, 'source_address') : field(dmaTransfer, 'destination_address'),
      device = debug.pci_device || 'unknown';
    return [{
      resource_type: 'pci_function',
      id: device,
      fields: {
        bdf: device,
        vendor_device: debug.vendor_device || 'qedu',
        driver: 'qedu'
      }
    }, {
      resource_type: 'character_device',
      id: devicePath,
      fields: {
        path: devicePath,
        name: 'qedu',
        minor: integer(debug.misc_minor)
      }
    }, {
      resource_type: 'bar_mapping',
      id: device + ':bar0',
      fields: {
        bus_start: debug.bar0_start,
        length: debug.bar0_length
      }
    }, {
      resource_type: 'dma_allocation',
      id: device + ':dma0',
      fields: {
        cpu_virtual_address: debug.cpu_address,
        dma_address: debug.device_address,
        size_bytes: integer(debug.buffer_size),
        dma_mask_bits: integer(debug.dma_mask_bits)
      }
    }, {
      resource_type: 'device_local_buffer',
      id: device + ':edu-buffer',
      fields: {
        offset: localAddress
      }
    }, {
      resource_type: 'irq_route',
      id: device + ':irq',
      fields: {
        linux_irq: integer(debug.irq),
        delivery: 'INTx'
      }
    }, {
      resource_type: 'interrupt_controller',
      id: device + ':controller-route',
      fields: {
        route: 'IOAPIC → LAPIC',
        vector: field(vector, 'vector'),
        target_cpu: field(vector, 'cpu')
      }
    }]
  }

  function parseSources(capture) {
    markers = capture.events.filter(e => e.source.mechanism === 'workload' && e.kind === 'phase').map(e => {
      const info = e.data.event_info;
      return {
        record: 'workload_marker',
        source: 'events.ndjson',
        time_ns: relativeNs(capture, e),
        tracepoint: 'workload:phase',
        marker: info.phase,
        edge: info.action,
        facts: info,
        context: e.context,
        canonical: e
      };
    });
    tracepoints = parseTrace(capture);
    if (!markers.length || !tracepoints.length) throw Error('Missing I/O workload or trace evidence');
    workloadPid = markers[0]?.context.pid || 0;
    const probeApis = capture.events.filter(e => e.kind === 'qedu_probe_api').map(e => e.data.fields);
    const probe = api => probeApis.find(f => f.api === api) || {};
    const dma = capture.events.find(e => e.kind === 'dma_alloc' && e.data.fields.device === probeApis[0]?.device)?.data.fields || {};
    const debug = {
      pci_device: probeApis[0]?.device,
      bar0_start: probe('pci_request_regions').address,
      bar0_length: probe('pci_request_regions').size,
      device_address: probe('dma_alloc_coherent').address,
      buffer_size: probe('dma_alloc_coherent').size,
      dma_mask_bits: probe('dma_set_mask_and_coherent').size,
      irq: probe('request_irq').address,
      misc_minor: probe('misc_register').address,
      cpu_address: dma.virt_addr || 'not captured'
    };
    markers.concat(tracepoints).sort((a, b) => ns(a) - ns(b)).forEach((record, index) => {
      record.seq = index + 1;
    });
    resources = buildResources(debug, markers[0].facts.device || '/dev/qedu');
    deviceResource = resource('pci_function');
    fileResource = resource('character_device');
    dmaResource = resource('dma_allocation');
    barResource = resource('bar_mapping');
    localResource = resource('device_local_buffer');
    irqResource = resource('irq_route');
    controllerResource = resource('interrupt_controller');
    buildOperations();
    buildJourneys();
    renderSummary();
  }

  function renderSummary() {
    var hooks = {};
    tracepoints.forEach(function(record) {
      if (record.tracepoint) hooks[record.tracepoint] = true
    });
    $('io-summary-text').textContent = [
      Object.keys(journeys).length + ' phases',
      Object.keys(hooks).length + ' hooks',
      operations.length + ' operations'
    ].join(' · ')
  }

  function buildOperations() {
    var operationIds = {};
    tracepoints.forEach(function(record) {
      var operationId = record.correlation && record.correlation.operation_id;
      if (operationId) operationIds[operationId] = true
    });
    operations = Object.keys(operationIds).map(Number).sort(function(a, b) {
      return a - b
    }).map(function(operationId) {
      var own = tracepoints.filter(function(record) {
        return record.correlation && record.correlation.operation_id === operationId
      });
      var dma = own.some(function(record) {
        return record.tracepoint === 'qedu:qedu_dma_submit'
      });
      var phase = dma ? 'two_way_dma' : 'factorial',
        begin = marker(phase, 'begin'),
        end = marker(phase, 'end');
      var operation = {
        id: operationId,
        kind: dma ? 'dma' : 'factorial',
        label: phaseTitle(phase),
        start: ns(begin) || ns(own[0]),
        end: ns(end) || ns(own[own.length - 1]),
        semantic: own
      };
      operation.events = operationEvents(operation);
      return operation
    })
  }

  function operationEvents(operation) {
    var windowEvents = tracepoints.filter(function(record) {
      return ns(record) >= operation.start && ns(record) <= operation.end
    });
    var deviceSyscalls = [],
      deviceIrqRecords = [],
      deviceFd = null,
      pendingDeviceCall = null,
      activeQeduIrq = {};
    windowEvents.forEach(function(record) {
      var name = record.tracepoint || '';
      if (name === 'irq:irq_handler_entry' && number(field(record, 'irq', -1)) === number(irqResource.fields.linux_irq) && field(record, 'name') === 'qedu') {
        deviceIrqRecords.push(record);
        activeQeduIrq[record.context.cpu] = (activeQeduIrq[record.context.cpu] || 0) + 1;
        return
      }
      if (name === 'irq:irq_handler_exit' && activeQeduIrq[record.context.cpu]) {
        deviceIrqRecords.push(record);
        activeQeduIrq[record.context.cpu]--;
        return
      }
      if (record.context.pid !== workloadPid || name.indexOf('syscalls:') !== 0) return;
      if (name === 'syscalls:sys_enter_openat' && field(record, 'path') === fileResource.fields.path) {
        deviceSyscalls.push(record);
        pendingDeviceCall = 'openat';
        return
      }
      if (name === 'syscalls:sys_exit_openat' && pendingDeviceCall === 'openat') {
        deviceSyscalls.push(record);
        deviceFd = number(field(record, 'return_fd'), -1);
        pendingDeviceCall = null;
        return
      }
      var enter = name.match(/^syscalls:sys_enter_(read|write|close)$/);
      if (enter && number(field(record, 'fd'), -1) === deviceFd) {
        deviceSyscalls.push(record);
        pendingDeviceCall = enter[1];
        return
      }
      var exit = name.match(/^syscalls:sys_exit_(read|write|close)$/);
      if (exit && pendingDeviceCall === exit[1]) {
        deviceSyscalls.push(record);
        pendingDeviceCall = null
      }
    });
    var selected = windowEvents.filter(function(record) {
      var name = record.tracepoint || '',
        correlation = record.correlation || {};
      if (isQedu(record)) return (traceName(record) === 'qedu_file_op' && field(record, 'operation') === 'OPEN') || correlation.operation_id === operation.id;
      if (name.indexOf('irq:') === 0) return deviceIrqRecords.indexOf(record) >= 0;
      if (name.indexOf('workqueue:') === 0) return raw(record).indexOf('qedu_dma_') >= 0;
      if (name.indexOf('syscalls:') === 0) return deviceSyscalls.indexOf(record) >= 0;
      return false
    });
    var waitBegin = operation.semantic.find(function(record) {
      return record.tracepoint === 'qedu:qedu_wait' && field(record, 'phase') === 'BEGIN'
    });
    var completion = operation.semantic.find(function(record) {
      return record.tracepoint === 'qedu:qedu_completion_publish'
    });
    if (waitBegin) {
      var sleep = windowEvents.find(function(record) {
        return record.tracepoint === 'sched:sched_switch' && ns(record) > ns(waitBegin) && number(field(record, 'prev_pid', -1)) === workloadPid
      });
      if (sleep) selected.push(sleep)
    }
    if (completion) {
      var wakeup = windowEvents.find(function(record) {
        return record.tracepoint === 'sched:sched_wakeup' && ns(record) > ns(completion) && number(field(record, 'pid', -1)) === workloadPid
      });
      var running = windowEvents.find(function(record) {
        return record.tracepoint === 'sched:sched_switch' && ns(record) > ns(completion) && number(field(record, 'next_pid', -1)) === workloadPid
      });
      if (wakeup) selected.push(wakeup);
      if (running) selected.push(running)
    }
    return selected.filter(function(record, index, list) {
      return list.indexOf(record) === index
    }).sort(function(a, b) {
      return ns(a) - ns(b)
    })
  }

  function event(operation, name, test, index) {
    var matches = operation.events.filter(function(record) {
      return traceName(record) === name && (!test || test(record))
    });
    return matches[index || 0] || null
  }

  function range(operation, start, end) {
    var from = typeof start === 'number' ? start : ns(start),
      to = end ? (typeof end === 'number' ? end : ns(end)) : operation.end + 1;
    return operation.events.filter(function(record) {
      return ns(record) >= from && ns(record) < to
    })
  }

  function stage(anchor, stageRecords) {
    return {
      anchor: anchor,
      records: stageRecords.filter(Boolean).sort(function(a, b) {
        return ns(a) - ns(b)
      })
    }
  }

  function buildJourneys() {
    var setup = buildSetupJourney();
    var factorial = operations.find(function(operation) {
      return operation.kind === 'factorial'
    });
    var dma = operations.find(function(operation) {
      return operation.kind === 'dma'
    });
    journeys = {};
    if (setup) journeys.setup = setup;
    if (factorial) journeys.factorial = buildFactorialJourney(factorial);
    if (dma) journeys.dma = buildDmaJourney(dma);
    Object.keys(journeys).forEach(function(kind) {
      journeys[kind].fullFlow = fullJourneyItem(journeys[kind])
    });
    navigation = [];
    ['setup', 'factorial', 'dma'].forEach(function(kind) {
      var journey = journeys[kind];
      if (!journey) return;
      navigation.push({
        journey: journey,
        item: journey.fullFlow
      })
    })
  }

  function fullJourneyItem(journey) {
    var records = [],
      seen = {};
    journey.steps.forEach(function(item) {
      item.records.forEach(function(record) {
        if (seen[record.seq]) return;
        seen[record.seq] = true;
        records.push(record)
      })
    });
    records.sort(function(a, b) {
      return ns(a) - ns(b)
    });
    return {
      anchor: journey.steps[0] && (journey.steps[0].anchor || records[0]),
      records: records
    }
  }

  function buildSetupJourney() {
    var setupEvents = tracepoints.filter(function(record) {
      var isDeviceDma = record.tracepoint === 'dma:dma_alloc' && record.correlation.device === deviceResource.fields.bdf,
        isDeviceVector = record.tracepoint.indexOf('irq_vectors:vector_') === 0 && number(field(record, 'irq', -1)) === number(irqResource.fields.linux_irq);
      return record.tracepoint === 'qedu:qedu_probe_api' || isDeviceDma || isDeviceVector
    }).sort(function(a, b) {
      return ns(a) - ns(b)
    });
    if (!setupEvents.length) return null;
    var operation = {
      id: 'probe',
      kind: 'setup',
      label: phaseTitle('driver_initialization'),
      start: ns(setupEvents[0]),
      end: ns(setupEvents[setupEvents.length - 1]),
      semantic: setupEvents,
      events: setupEvents
    };

    function probeStages(names, resourceName) {
      return setupEvents.filter(function(record) {
        return names.indexOf(field(record, 'api')) >= 0 && (!resourceName || field(record, 'resource') === resourceName)
      })
    }

    function probeStage(name, resourceName) {
      return setupEvents.find(function(record) {
        return field(record, 'api') === name && (!resourceName || field(record, 'resource') === resourceName)
      })
    }
    var allocation = setupEvents.find(function(record) {
      return record.tracepoint === 'dma:dma_alloc'
    });
    return {
      kind: 'setup',
      operation: operation,
      title: operation.label,
      steps: [
        stage(probeStage('qedu_probe'), probeStages(['qedu_probe', 'devm_kzalloc']).filter(function(record) {
          return field(record, 'resource') !== 'bound_qedu_device'
        })),
        stage(probeStage('pci_enable_device'), probeStages(['pci_enable_device', 'pci_request_regions', 'pci_iomap'])),
        stage(probeStage('request_irq'), setupEvents.filter(function(record) {
          return field(record, 'api') === 'request_irq' || record.tracepoint.indexOf('irq_vectors:vector_') === 0
        })),
        stage(probeStage('dma_set_mask_and_coherent'), probeStages(['dma_set_mask_and_coherent', 'pci_set_master'])),
        stage(allocation || probeStage('dma_alloc_coherent'), [allocation, probeStage('dma_alloc_coherent')]),
        stage(probeStage('alloc_ordered_workqueue'), probeStages(['alloc_ordered_workqueue'])),
        stage(probeStage('misc_register'), probeStages(['misc_register'])),
        stage(probeStage('debugfs_create_dir'), probeStages(['debugfs_create_dir', 'debugfs_create_file'])),
        stage(probeStage('qedu_probe', 'bound_qedu_device'), probeStages(['qedu_probe'], 'bound_qedu_device'))
      ].filter(function(item) {
        return item.records.length
      })
    }
  }

  function buildFactorialJourney(operation) {
    var submit = event(operation, 'qedu_factorial_submit');
    var waitBegin = event(operation, 'qedu_wait', function(record) {
      return field(record, 'engine') === 'FACTORIAL' && field(record, 'phase') === 'BEGIN'
    });
    var waitEnd = event(operation, 'qedu_wait', function(record) {
      return field(record, 'engine') === 'FACTORIAL' && field(record, 'phase') === 'END'
    });
    var irqAck = event(operation, 'qedu_irq_ack', function(record) {
      return field(record, 'engine') === 'FACTORIAL'
    });
    var result = event(operation, 'qedu_factorial_result');
    var copyOut = event(operation, 'qedu_cpu_buffer_io', function(record) {
      return field(record, 'operation') === 'COPY_TO_USER'
    });
    var openEnter = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'OPEN' && field(record, 'phase') === 'ENTER'
    });
    var writeOpEnter = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'WRITE' && field(record, 'phase') === 'ENTER'
    });
    var writeOpExit = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'WRITE' && field(record, 'phase') === 'EXIT'
    });
    var readOpEnter = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'READ' && field(record, 'phase') === 'ENTER'
    });
    var releaseEnter = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'RELEASE' && field(record, 'phase') === 'ENTER'
    });
    var writeEnter = event(operation, 'sys_enter_write');
    var readEnter = event(operation, 'sys_enter_read');
    var closeEnter = event(operation, 'sys_enter_close');
    var interruptStart = event(operation, 'irq_handler_entry') || irqAck;
    return {
      kind: 'factorial',
      operation: operation,
      title: operation.label,
      steps: [
        stage(openEnter, range(operation, operation.start, writeEnter)),
        stage(writeOpEnter || writeEnter, range(operation, writeEnter, submit)),
        stage(submit, [submit]),
        stage(waitBegin, range(operation, waitBegin, interruptStart)),
        stage(irqAck, range(operation, interruptStart, waitEnd)),
        stage(waitEnd, range(operation, waitEnd, result)),
        stage(result, [result]),
        stage(writeOpExit, range(operation, writeOpExit, readEnter)),
        stage(readOpEnter || copyOut, range(operation, readEnter, closeEnter)),
        stage(releaseEnter, range(operation, closeEnter, operation.end + 1))
      ].filter(function(item) {
        return item.anchor && item.records.length
      })
    }
  }

  function buildDmaJourney(operation) {
    var copyIn = event(operation, 'qedu_cpu_buffer_io', function(record) {
      return field(record, 'operation') === 'COPY_FROM_USER'
    });
    var submits = operation.events.filter(function(record) {
      return traceName(record) === 'qedu_dma_submit'
    }).sort(function(a, b) {
      return field(a, 'leg') - field(b, 'leg')
    });
    var submit0 = submits[0],
      submit1 = submits[1];
    var irqEntries = operation.events.filter(function(record) {
      return traceName(record) === 'irq_handler_entry'
    });
    var irqAcks = operation.events.filter(function(record) {
      return traceName(record) === 'qedu_irq_ack' && field(record, 'engine') === 'DMA'
    });
    var advance = event(operation, 'qedu_dma_stage', function(record) {
      return field(record, 'reason') === 'ADVANCE_WORK'
    });
    var finish = event(operation, 'qedu_dma_stage', function(record) {
      return field(record, 'reason') === 'FINISH_WORK'
    });
    var waitBegin = event(operation, 'qedu_wait', function(record) {
      return field(record, 'engine') === 'DMA' && field(record, 'phase') === 'BEGIN'
    });
    var waitEnd = event(operation, 'qedu_wait', function(record) {
      return field(record, 'engine') === 'DMA' && field(record, 'phase') === 'END'
    });
    var copyOut = event(operation, 'qedu_cpu_buffer_io', function(record) {
      return field(record, 'operation') === 'COPY_TO_USER'
    });
    var openEnter = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'OPEN' && field(record, 'phase') === 'ENTER'
    });
    var writeOpEnter = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'WRITE' && field(record, 'phase') === 'ENTER'
    });
    var writeOpExit = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'WRITE' && field(record, 'phase') === 'EXIT'
    });
    var readOpEnter = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'READ' && field(record, 'phase') === 'ENTER'
    });
    var releaseEnter = event(operation, 'qedu_file_op', function(record) {
      return field(record, 'operation') === 'RELEASE' && field(record, 'phase') === 'ENTER'
    });
    var writeEnter = event(operation, 'sys_enter_write');
    var readEnter = event(operation, 'sys_enter_read');
    var closeEnter = event(operation, 'sys_enter_close');
    var entry0 = irqEntries[0] || irqAcks[0],
      entry1 = irqEntries[1] || irqAcks[1];
    return {
      kind: 'dma',
      operation: operation,
      title: operation.label,
      steps: [
        stage(openEnter, range(operation, operation.start, writeEnter)),
        stage(writeOpEnter || copyIn, range(operation, writeEnter, submit0)),
        stage(submit0, [submit0]),
        stage(waitBegin, range(operation, waitBegin, entry0)),
        stage(irqAcks[0], range(operation, entry0, advance)),
        stage(advance, range(operation, advance, submit1)),
        stage(submit1, [submit1]),
        stage(irqAcks[1], range(operation, entry1, finish)),
        stage(finish, range(operation, finish, waitEnd)),
        stage(waitEnd, range(operation, waitEnd, writeOpExit)),
        stage(writeOpExit, range(operation, writeOpExit, readEnter)),
        stage(readOpEnter || copyOut, range(operation, readEnter, closeEnter)),
        stage(releaseEnter, range(operation, closeEnter, operation.end + 1))
      ].filter(function(item) {
        return item.anchor && item.records.length
      })
    }
  }

  function eventTitle(record) {
    return traceName(record)
  }

  function workFunction(record) {
    var match = raw(record).match(/function[= ]([A-Za-z0-9_]+)/);
    return match ? match[1] : 'work item'
  }

  function actorModel(journey) {
    if (journey.kind === 'setup') return [{
      id: 'pci',
      type: 'PCI',
      name: deviceResource.fields.bdf,
      detail: 'probe owner'
    }, {
      id: 'driver',
      type: 'DRIVER',
      name: 'qedu_probe()',
      detail: 'resource owner'
    }, {
      id: 'devres',
      type: 'DEVRES',
      name: 'devm_kzalloc()',
      detail: 'device state'
    }, {
      id: 'irq_core',
      type: 'IRQ',
      name: 'request_irq()',
      detail: 'IRQ ' + irqResource.fields.linux_irq + ' · INTx'
    }, {
      id: 'controller',
      type: 'LAPIC',
      name: 'vector ' + controllerResource.fields.vector,
      detail: 'CPU ' + controllerResource.fields.target_cpu
    }, {
      id: 'dma_api',
      type: 'DMA API',
      name: 'dma_alloc_coherent',
      detail: dmaResource.fields.dma_mask_bits + '-bit coherent'
    }, {
      id: 'ram',
      type: 'RAM',
      name: 'coherent buffer',
      detail: bytes(dmaResource.fields.size_bytes) + ' · CPU + DMA'
    }, {
      id: 'workqueue_core',
      type: 'WORKQUEUE',
      name: 'ordered workqueue',
      detail: 'qedu_dma'
    }, {
      id: 'misc_core',
      type: 'MISC',
      name: 'misc_register',
      detail: fileResource.fields.path
    }, {
      id: 'debugfs_core',
      type: 'DEBUGFS',
      name: 'qedu debugfs',
      detail: 'status snapshot'
    }];
    var operation = journey.operation;
    var processRecord = operation.events.find(function(record) {
      return record.context && record.context.pid === workloadPid
    });
    var irqRecord = operation.events.find(function(record) {
      return contextClass(record) === 'hardirq'
    });
    var workerRecord = operation.events.find(function(record) {
      return contextClass(record) === 'workqueue'
    });
    var openExit = operation.events.find(function(record) {
      return record.tracepoint === 'syscalls:sys_exit_openat'
    });
    var processName = processRecord && processRecord.context.comm || 'PID ' + workloadPid;
    var irqName = irqRecord && field(irqRecord, 'name', 'IRQ ' + irqResource.fields.linux_irq) || 'IRQ ' + irqResource.fields.linux_irq;
    var common = [{
      id: 'user',
      type: 'REQUEST',
      name: processName,
      detail: 'PID ' + workloadPid
    }, {
      id: 'file',
      type: 'FILE',
      name: fileResource.fields.path,
      detail: 'fd ' + field(openExit, 'return_fd') + ' · minor ' + fileResource.fields.minor
    }, {
      id: 'driver',
      type: 'DRIVER',
      name: deviceResource.fields.driver,
      detail: deviceResource.fields.bdf
    }, {
      id: 'device',
      type: 'DEVICE',
      name: deviceResource.fields.vendor_device,
      detail: deviceResource.fields.bdf
    }, {
      id: 'scheduler',
      type: 'SCHEDULER',
      name: 'sched core',
      detail: 'switch + wakeup'
    }, {
      id: 'state',
      type: 'WAIT',
      name: 'job_wait',
      detail: 'completed_events'
    }, {
      id: 'irq',
      type: 'IRQ CTX',
      name: irqName,
      detail: 'IRQ ' + irqResource.fields.linux_irq
    }, {
      id: 'controller',
      type: 'IRQ ROUTE',
      name: controllerResource.fields.route,
      detail: 'vector ' + controllerResource.fields.vector + ' · CPU ' + controllerResource.fields.target_cpu,
      inferred: true
    }, {
      id: 'irq_core',
      type: 'IRQ CORE',
      name: 'irq_desc chain',
      detail: 'shared IRQ ' + irqResource.fields.linux_irq
    }, {
      id: 'ram',
      type: 'RAM',
      name: 'coherent buffer',
      detail: bytes(dmaResource.fields.size_bytes) + ' · DMA buffer'
    }];
    if (journey.kind === 'dma') common.push({
      id: 'worker',
      type: 'WORKQUEUE',
      name: workerRecord && workerRecord.context.comm || 'qedu_dma',
      detail: workerRecord ? 'PID ' + workerRecord.context.pid : 'no PID'
    });
    return common
  }

  function recordFlow(record, journey) {
    var name = traceName(record),
      operation = field(record, 'operation'),
      execution = contextClass(record),
      edges = [],
      nodes = [];

    function connect(from, to, label, kind, evidence) {
      var rawKind = String(kind || 'control'),
        inferred = evidence || (/\binferred-route\b/.test(rawKind) ? 'inferred' : 'observed');
      edges.push({
        from: from,
        to: to,
        label: label || record.tracepoint,
        kind: rawKind.replace(/\binferred-route\b/g, '').trim().replace(/\s+/g, '-') || 'control',
        evidence: inferred,
        local: from === to,
        step: edges.length + 1
      })
    }

    function activate(id) {
      if (nodes.indexOf(id) < 0) nodes.push(id)
    }
    if (journey.kind === 'setup') {
      if (name === 'dma_alloc') connect('dma_api', 'ram', 'allocate ' + bytes(field(record, 'size_bytes')) + ' coherent RAM', 'allocation');
      else if (name === 'vector_alloc') connect('irq_core', 'controller', 'vector_alloc · vector ' + field(record, 'vector'), 'configuration');
      else if (name === 'vector_config') connect('irq_core', 'controller', 'vector_config · CPU ' + field(record, 'cpu'), 'configuration');
      else if (name === 'qedu_probe_api') {
        var probeApi = field(record, 'api'),
          api = probeApi,
          resourceName = field(record, 'resource'),
          label = api + ' · ' + shortResource(resourceName);
        if (probeApi === 'qedu_probe' && resourceName === 'pci_driver_probe') connect('pci', 'driver', label, 'probe');
        else if (probeApi === 'qedu_probe' && resourceName === 'bound_qedu_device') connect('driver', 'pci', api + ' · return=' + field(record, 'result'), 'probe');
        else if (probeApi === 'devm_kzalloc') connect('driver', 'devres', api + ' · ' + bytes(field(record, 'object_size_bytes')) + ' ' + resourceName, 'allocation');
        else if (probeApi === 'pci_enable_device') connect('driver', 'pci', label, 'resource');
        else if (probeApi === 'pci_request_regions') connect('driver', 'pci', api + ' · BAR0 ' + bytes(field(record, 'bar0_length_bytes')), 'resource');
        else if (probeApi === 'pci_iomap') connect('driver', 'pci', api + ' · ' + bytes(field(record, 'mapped_length_bytes')), 'resource');
        else if (probeApi === 'request_irq') connect('driver', 'irq_core', api + ' · IRQ ' + field(record, 'linux_irq'), 'registration');
        else if (probeApi === 'dma_set_mask_and_coherent') connect('driver', 'dma_api', api + ' · ' + field(record, 'dma_mask_bits') + '-bit', 'configuration');
        else if (probeApi === 'pci_set_master') connect('driver', 'pci', api + ' · result=' + field(record, 'result'), 'configuration');
        else if (probeApi === 'dma_alloc_coherent') connect('ram', 'driver', api + ' returned · DMA ' + field(record, 'dma_address'), 'allocation');
        else if (probeApi === 'alloc_ordered_workqueue') connect('driver', 'workqueue_core', label, 'registration');
        else if (probeApi === 'misc_register') connect('driver', 'misc_core', label, 'publication');
        else if (probeApi === 'debugfs_create_dir' || probeApi === 'debugfs_create_file') connect('driver', 'debugfs_core', label + ' · result=' + field(record, 'result'), 'publication')
      }
      edges.forEach(function(edge) {
        activate(edge.from);
        activate(edge.to)
      });
      return {
        edges: edges,
        nodes: nodes,
        record: record
      }
    }
    if (/^sys_(enter|entry)_(openat|read|write|close)$/.test(name)) {
      var syscallName = name.replace(/^sys_(enter|entry)_/, '');
      var syscallLabel = syscallName === 'openat' ? 'openat("' + field(record, 'path', fileResource.fields.path) + '")' : syscallName === 'close' ? 'close(fd=' + field(record, 'fd') + ')' : syscallName + '(fd=' + field(record, 'fd') + ', count=' + field(record, 'count') + ')';
      connect('user', 'file', syscallLabel, 'syscall')
    } else if (/^sys_exit_(openat|read|write|close)$/.test(name)) connect('file', 'user', name.replace(/^sys_exit_/, '') + ' return=' + field(record, 'return_value'), 'syscall');
    else if (name === 'qedu_file_op') {
      var fileLabel = operation.toLowerCase() + ' ' + field(record, 'phase').toLowerCase();
      if (field(record, 'phase') === 'ENTER') connect('file', 'driver', fileLabel + ' · count=' + field(record, 'count') + ' · offset=' + field(record, 'offset'), 'dispatch');
      else connect('driver', 'file', fileLabel + ' · result=' + field(record, 'result') + (field(record, 'engine') !== 'NONE' ? ' · ' + field(record, 'engine') : ''), 'dispatch')
    } else if (name === 'qedu_cpu_buffer_io' && operation === 'COPY_FROM_USER') {
      connect('driver', 'user', operation + ' · requested=' + field(record, 'requested') + ' B', 'cpu-copy');
      connect('user', 'ram', 'completed=' + field(record, 'completed') + ' B', 'cpu-copy')
    } else if (name === 'qedu_cpu_buffer_io' && operation === 'COPY_TO_USER') {
      connect('driver', 'ram', operation + ' · requested=' + field(record, 'requested') + ' B', 'cpu-copy');
      connect('ram', 'user', 'completed=' + field(record, 'completed') + ' B', 'cpu-copy')
    } else if (name === 'qedu_cpu_buffer_io' && operation === 'CLEAR_FOR_DMA_RETURN') connect('worker', 'ram', operation + ' · ' + field(record, 'completed') + ' B', 'cpu-copy');
    else if (name === 'qedu_factorial_submit') connect('driver', 'device', 'input=' + field(record, 'input') + ' · status_command=' + field(record, 'status_command'), 'mmio');
    else if (name === 'qedu_factorial_result') connect('driver', 'device', 'read result register · value=' + field(record, 'result'), 'mmio');
    else if (name === 'qedu_dma_submit') {
      var executor = execution === 'workqueue' ? 'worker' : 'driver',
        direction = field(record, 'direction'),
        command = field(record, 'command', {});
      connect(executor, 'device', 'CMD ' + command.raw + ' · ' + field(record, 'bytes') + ' B', 'mmio');
      connect('device', 'ram', (direction === 'DMA_TO_DEVICE' ? 'DMA read submitted · RAM → EDU' : 'DMA write submitted · EDU → RAM') + ' · ' + field(record, 'bytes') + ' B', 'dma-submitted')
    } else if (name === 'irq_handler_entry') {
      connect('device', 'controller', 'INTx delivery', 'route', 'inferred');
      connect('controller', 'irq_core', 'vector ' + controllerResource.fields.vector + ' · CPU ' + controllerResource.fields.target_cpu, 'interrupt', 'inferred');
      connect('irq_core', 'irq', record.tracepoint + ' · irq=' + field(record, 'irq') + ' · ' + field(record, 'name'), 'interrupt')
    } else if (name === 'irq_handler_exit') connect('irq', 'irq_core', record.tracepoint + ' · ret=' + field(record, 'ret'), 'interrupt');
    else if (name === 'qedu_irq_ack') connect('irq', 'device', 'STATUS ' + field(record, 'status', {}).raw + ' · ACK ' + field(record, 'ack'), 'mmio');
    else if (name === 'qedu_dma_work_queue') connect('irq', 'worker', field(record, 'work_kind') + ' · queued=' + field(record, 'queued'), 'workqueue');
    else if (name === 'workqueue_queue_work') connect('irq', 'worker', record.tracepoint + ' · ' + workFunction(record), 'workqueue');
    else if (name === 'qedu_completion_publish') connect(execution === 'hardirq' ? 'irq' : 'worker', 'state', 'bit ' + field(record, 'event_bit') + ' · ' + field(record, 'bits_before') + ' → ' + field(record, 'bits_after'), 'state');
    else if (name === 'qedu_wait') connect(
      field(record, 'phase') === 'BEGIN' ? 'driver' : 'state',
      field(record, 'phase') === 'BEGIN' ? 'state' : 'driver',
      record.tracepoint + ' · ' + field(record, 'phase'),
      'state'
    );
    else if (name === 'sched_wakeup') {
      var waker = execution === 'hardirq' ? 'irq' : execution === 'workqueue' ? 'worker' : 'state';
      connect(waker, 'scheduler', record.tracepoint + ' · pid=' + field(record, 'pid'), 'scheduler');
      connect('scheduler', 'user', 'runnable · CPU ' + field(record, 'target_cpu'), 'scheduler')
    } else if (name === 'sched_switch') {
      if (number(field(record, 'prev_pid', -1)) === workloadPid) connect('user', 'scheduler', 'prev_state=' + field(record, 'prev_state'), 'scheduler');
      if (number(field(record, 'next_pid', -1)) === workloadPid) connect('scheduler', 'user', 'next_pid=' + field(record, 'next_pid') + ' · CPU ' + record.context.cpu, 'scheduler');
      if (journey.kind === 'dma' && String(field(record, 'prev_comm', '')).indexOf('kworker') === 0) connect('worker', 'scheduler', 'prev_state=' + field(record, 'prev_state'), 'scheduler');
      if (journey.kind === 'dma' && String(field(record, 'next_comm', '')).indexOf('kworker') === 0) connect('scheduler', 'worker', 'next_pid=' + field(record, 'next_pid') + ' · CPU ' + record.context.cpu, 'scheduler')
    } else if (name.indexOf('workqueue_') === 0 || execution === 'workqueue') activate('worker');
    else activate(execution === 'hardirq' ? 'irq' : 'driver');
    edges.forEach(function(edge) {
      activate(edge.from);
      activate(edge.to)
    });
    if (isQedu(record)) {
      var executorActor = execution === 'workqueue' ? 'worker' : execution === 'hardirq' ? 'irq' : 'driver';
      activate(executorActor)
    }
    return {
      edges: edges,
      nodes: nodes,
      record: record
    }
  }

  function renderActorGraph() {
    var item = selectedJourney.fullFlow,
      focus = selectedEvent && item.records.indexOf(selectedEvent) >= 0 ? selectedEvent : item.anchor || item.records[0],
      active = {},
      nodes = actorModel(selectedJourney);
    if (focus) recordFlow(focus, selectedJourney).nodes.forEach(function(id) {
      active[id] = true
    });
    var order = selectedJourney.kind === 'setup' ? ['pci', 'driver', 'devres', 'irq_core', 'controller', 'dma_api', 'ram', 'workqueue_core', 'misc_core', 'debugfs_core'] : ['user', 'file', 'driver', 'ram', 'device', 'controller', 'irq_core', 'irq', 'worker', 'state', 'scheduler'];
    nodes.sort(function(a, b) {
      return order.indexOf(a.id) - order.indexOf(b.id)
    });
    var laneById = {};
    nodes.forEach(function(node, index) {
      laneById[node.id] = index
    });
    $('sequence-head').style.gridTemplateColumns = 'repeat(' + nodes.length + ',minmax(82px,1fr))';
    $('sequence-head').innerHTML = nodes.map(function(node) {
      return '<article data-actor="' + esc(node.id) + '" class="sequence-actor ' + (active[node.id] ? 'active ' : '') + (node.inferred ? 'inferred' : '') + '"><small>' + esc(node.type) + '</small><b>' + esc(node.name) + '</b><em>' + esc(node.detail) + '</em></article>'
    }).join('');
    var interactions = [];
    item.records.forEach(function(record) {
      var mapped = recordFlow(record, selectedJourney);
      if (mapped.edges.length) mapped.edges.forEach(function(flow) {
        interactions.push({
          flow: flow,
          record: record
        })
      });
      else mapped.nodes.forEach(function(actorId) {
        interactions.push({
          flow: {
            from: actorId,
            to: actorId,
            label: eventTitle(record),
            kind: 'observation',
            evidence: 'observed',
            local: true,
            step: 1
          },
          record: record
        })
      })
    });
    $('sequence-body').style.setProperty('--rows', Math.max(interactions.length, 1));
    var lifelines = '<div class="sequence-lifelines">' + nodes.map(function(node, index) {
      return '<i class="' + (active[node.id] ? 'active ' : '') + (node.inferred ? 'inferred' : '') + '" style="left:' + ((index + .5) / nodes.length * 100) + '%"></i>'
    }).join('') + '</div>';
    var rows = interactions.map(function(interaction) {
      var record = interaction.record,
        flow = interaction.flow,
        label = flow.label || eventTitle(record),
        selected = selectedSequenceSeq === record.seq && selectedSequenceStep === flow.step ? ' selected' : '',
        kind = esc(flow.kind || 'control'),
        evidence = esc(flow.evidence || 'observed'),
        metadata = ' data-flow-kind="' + kind + '" data-flow-evidence="' + evidence + '" data-flow-step="' + flow.step + '"';
      if (laneById[interaction.flow.from] == null || laneById[interaction.flow.to] == null) return '';
      var from = (laneById[interaction.flow.from] + .5) / nodes.length * 100,
        to = (laneById[interaction.flow.to] + .5) / nodes.length * 100,
        left = Math.min(from, to),
        width = Math.abs(to - from),
        direction = to > from ? 'forward' : 'reverse';
      if (flow.local || from === to) {
        return '<button type="button" class="sequence-row local' + selected + '" data-sequence-event="' + record.seq + '"' + metadata + ' aria-label="' + esc(label) + '"><i class="sequence-local-mark ' + kind + ' evidence-' + evidence + '" style="left:' + from + '%"></i><span class="sequence-label local" style="left:' + from + '%">' + esc(label.split(':').pop()) + '</span></button>'
      }
      return '<button type="button" class="sequence-row' + selected + '" data-sequence-event="' + record.seq + '"' + metadata + ' aria-label="' + esc(interaction.flow.from + ' to ' + interaction.flow.to + ' · ' + label) + '"><i class="sequence-arrow ' + direction + ' ' + kind + ' evidence-' + evidence + '" data-from="' + esc(interaction.flow.from) + '" data-to="' + esc(interaction.flow.to) + '" style="left:' + left + '%;width:' + width + '%"></i><i class="sequence-point evidence-' + evidence + '" style="left:' + from + '%"></i><i class="sequence-point evidence-' + evidence + '" style="left:' + to + '%"></i><span class="sequence-label" style="left:' + ((from + to) / 2) + '%">' + esc(label.split(':').pop()) + '</span></button>'
    }).join('');
    $('sequence-body').innerHTML = lifelines + (rows || '<p class="sequence-empty">No captured interaction in this stage.</p>');
    Array.prototype.forEach.call(document.querySelectorAll('[data-sequence-event]'), function(row) {
      row.onclick = function() {
        selectRecord(number(row.dataset.sequenceEvent), number(row.dataset.flowStep))
      }
    })
  }

  function renderRoadmap() {
    var kinds = ['setup', 'factorial', 'dma'];
    var phase = 0;
    $('step-roadmap').innerHTML = kinds.map(function(kind) {
      var journey = journeys[kind];
      if (!journey) return '';
      phase++;
      return '<button type="button" class="selector-option ' + (journey === selectedJourney ? 'active' : '') + '" data-navigation="' + navigation.findIndex(function(entry) {
        return entry.journey === journey
      }) + '"><span class="selector-kicker">PHASE ' + phase + '</span><span class="selector-label">' + esc(journey.title) + '</span></button>';
    }).join('');
    Array.prototype.forEach.call(document.querySelectorAll('[data-navigation]'), function(button) {
      button.onclick = function() {
        selectNavigation(number(button.dataset.navigation))
      }
    })
  }

  function renderStep() {
    var item = selectedJourney.fullFlow,
      anchor = item.anchor || item.records[0];
    if (!selectedEvent || item.records.indexOf(selectedEvent) < 0) selectedEvent = anchor || item.records[0] || null;
    renderActorGraph();
    renderInspector()
  }

  function renderResources() {
    function compact(parts) {
      return parts.filter(function(value) {
        return value !== null && value !== undefined && value !== ''
      }).join(' · ') || '—'
    }
    var rows = [
      ['PCI', compact([deviceResource.fields.bdf, deviceResource.fields.vendor_device])],
      ['BAR0', compact([barResource.fields.bus_start, barResource.fields.length])],
      ['FILE', compact([fileResource.fields.path, fileResource.fields.minor == null ? null : 'minor ' + fileResource.fields.minor])],
      ['IRQ', compact([irqResource.fields.linux_irq == null ? null : 'Linux ' + irqResource.fields.linux_irq, irqResource.fields.delivery])],
      ['VECTOR', compact([controllerResource.fields.vector, controllerResource.fields.target_cpu == null ? null : 'CPU ' + controllerResource.fields.target_cpu])],
      ['RAM', compact([dmaResource.fields.cpu_virtual_address, bytes(dmaResource.fields.size_bytes)])],
      ['DMA', compact([dmaResource.fields.dma_address])],
      ['LOCAL', compact([localResource.fields.offset])]
    ];
    $('journey-resources').innerHTML = rows.map(function(row) {
      return '<span class="journey-resource" title="' + esc(row[0] + ' · ' + row[1]) + '"><small>' + esc(row[0]) + '</small><i aria-hidden="true">|</i><b>' + esc(row[1]) + '</b></span>'
    }).join('')
  }

  function flatten(value, prefix, out) {
    out = out || [];
    if (value && typeof value === 'object' && !Array.isArray(value)) Object.keys(value).forEach(function(key) {
      flatten(value[key], prefix ? prefix + '.' + key : key, out)
    });
    else out.push([prefix, value]);
    return out
  }

  function renderInspector() {
    var record = selectedEvent;
    if (!record) return;
    renderOrigin('inspect-origin', record);
    var canonicalData = record.canonical && record.canonical.data || {},
      rawFields = canonicalData.fields || canonicalData.event_info || {},
      rawRows = flatten(rawFields, '', []).filter(function(item) {
      return item[1] !== null && item[1] !== undefined && item[1] !== ''
    });
    function list(rows, empty) {
      return rows.length ? rows.map(function(item) {
        return '<div><small>' + esc(item[0]) + '</small><b title="' + esc(item[1]) + '">' + esc(item[1]) + '</b></div>'
      }).join('') : '<p class="fields-empty">' + empty + '</p>'
    }
    $('inspect-fields').innerHTML = list(rawRows, 'no fields');
  }

  function taskContext(context) {
    context = context || {};
    var task = context.comm || '—',
      pid = context.pid != null ? 'PID ' + context.pid : context.tid != null ? 'TID ' + context.tid : '';
    if (pid) task += ' · ' + pid;
    return task;
  }

  function renderOrigin(id, record) {
    var source = record.canonical && record.canonical.source || {},
      mechanism = mechanismLabel(source.mechanism || (record.record === 'workload_marker' ? 'workload' : '—')),
      hook = record.tracepoint || source.hook || 'phase',
      context = record.canonical && record.canonical.context || record.context || {};
    var rows = [
      ['mechanism', mechanism, ''],
      ['hook', hook, ''],
      ['CPU', context.cpu == null ? '—' : 'CPU ' + context.cpu, ''],
      ['task', taskContext(context), '']
    ];
    $(id).innerHTML = rows.map(function(row) {
      return '<div class="' + row[2] + '"><small>' + esc(row[0]) + '</small><b title="' + esc(row[1]) + '">' + esc(row[1]) + '</b></div>'
    }).join('')
  }

  function mechanismLabel(value) {
    return value === 'ebpf' ? 'eBPF' : value || '—'
  }

  function selectNavigation(index) {
    selectedNav = Math.max(0, Math.min(navigation.length - 1, index));
    var entry = navigation[selectedNav];
    selectedJourney = entry.journey;
    selectedSequenceSeq = null;
    selectedSequenceStep = null;
    var item = entry.item;
    selectedEvent = item.anchor || item.records[0] || null;
    if (window.location.hash !== '#' + selectedJourney.kind) history.replaceState(null, '', '#' + selectedJourney.kind);
    renderResources();
    renderRoadmap();
    renderStep()
  }

  function selectRecord(sequence, flowStep) {
    selectedSequenceSeq = sequence;
    selectedSequenceStep = flowStep;
    selectedEvent = tracepoints.find(function(record) {
      return record.seq === sequence
    }) || null;
    renderRoadmap();
    renderStep()
  }

  function bindControls() {
    document.addEventListener('keydown', function(event) {
      if (event.target && /input|textarea|select/i.test(event.target.tagName)) return;
      if (event.key === 'ArrowLeft') selectNavigation(selectedNav - 1);
      if (event.key === 'ArrowRight') selectNavigation(selectedNav + 1)
    })
  }

  function render() {
    var requested = window.location.hash.slice(1),
      initial = navigation.findIndex(function(entry) {
        return entry.journey.kind === requested
      });
    if (initial < 0) initial = 0;
    bindControls();
    selectNavigation(initial)
  }

  mountView('io', capture => {
    parseSources(capture);
    selectedNav = 0;
    render()
  });
})();
