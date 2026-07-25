(function () {
  'use strict';

  function parseFields(payload) {
    var result = {}, match;
    var equals = /([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)/g;
    while ((match = equals.exec(payload))) result[match[1]] = match[2];

    /* Several MM tracepoints use "key value" for their leading identity. */
    var spaced = /\b(dev|ino|index|pfn|order|migratetype)\s+([^\s]+)/g;
    while ((match = spaced.exec(payload))) {
      if (result[match[1]] == null) result[match[1]] = match[2];
    }
    match = payload.match(/\bbdi\s+([0-9]+:[0-9]+):/);
    if (match) result.bdi = match[1];
    match = payload.match(/^mt_mod\s+([^,\s]+),\s*(\S+)/);
    if (match) {
      result.mt_mod = match[1];
      result.operation = match[2];
    }
    if (/^mm_phase=/.test(payload)) result.phase = payload.slice(9).trim();
    return result;
  }

  function byteValue(value) {
    var match = String(value || '0').match(/^(-?[0-9.]+)([KMG]?B)?$/i);
    if (!match) return 0;
    var scale = { KB: 1024, MB: 1048576, GB: 1073741824 }[(match[2] || 'B').toUpperCase()] || 1;
    return Number(match[1]) * scale;
  }

  function top(map, limit) {
    return Object.keys(map).map(function (key) {
      var value = map[key];
      return {
        name: key,
        count: value.count || value,
        bytes: value.bytes || 0,
        waste: value.waste || 0
      };
    }).sort(function (a, b) { return b.count - a.count; }).slice(0, limit);
  }

  function category(type) {
    if (type === 'tracing_mark_write') return 'phase';
    if (/filemap|writeback/.test(type)) return 'cache';
    if (type === 'rss_stat') return 'physical';
    if (/kmalloc|kfree|kmem_cache/.test(type)) return 'objects';
    if (/fault|mmap|unmapped|collapse_huge|khugepaged/.test(type)) return 'virtual';
    if (/vmscan|reclaim|kswapd|lru|compact|migrate/.test(type)) return 'reclaim';
    if (/page_alloc|page_free|pcpu|extfrag/.test(type)) return 'physical';
    return 'other';
  }

  self.onmessage = function (message) {
    fetch(message.data, { cache: 'no-store' }).then(function (response) {
      if (!response.ok) throw Error('HTTP ' + response.status);
      return response.text();
    }).then(function (text) {
      var lines = text.split(/\n/), events = [], counts = {}, sites = {}, caches = {};
      var tasks = {}, taskStats = {}, orders = {}, gfps = {}, samples = {}, cpuCounts = {}, phases = [], mappings = [], faults = [];
      var bytesReq = 0, bytesAlloc = 0, rssState = {}, rssOwners = {}, workloadPid = null;

      lines.forEach(function (raw) {
        var match = raw.match(/^\s*(.+?)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+([0-9.]+):\s+([A-Za-z0-9_]+):\s*(.*)$/);
        if (!match) return;
        var fields = parseFields(match[7]);
        var event = {
          task: match[1].trim(), pid: +match[2], cpu: +match[3], flags: match[4],
          time: +match[5], type: match[6], fields: fields, payload: match[7],
          raw: raw.trim(), category: category(match[6])
        };
        events.push(event);
        cpuCounts[event.cpu] = (cpuCounts[event.cpu] || 0) + 1;
        counts[event.type] = (counts[event.type] || 0) + 1;
        tasks[event.task] = (tasks[event.task] || 0) + 1;
        taskStats[event.task] = taskStats[event.task] || { events: 0, faults: 0, maps: 0, objects: 0, pageAlloc: 0, pageFree: 0 };
        taskStats[event.task].events++;
        if (/fault/.test(event.type)) taskStats[event.task].faults++;
        if (/mmap|unmapped|rss_stat/.test(event.type)) taskStats[event.task].maps++;
        if (/kmalloc|kmem_cache_alloc/.test(event.type)) taskStats[event.task].objects++;
        if (event.type === 'mm_page_alloc') taskStats[event.task].pageAlloc += Math.pow(2, +(fields.order || 0));
        if (/mm_page_free/.test(event.type)) taskStats[event.task].pageFree += Math.pow(2, +(fields.order || 0));
        if (!samples[event.type]) samples[event.type] = [];
        if (samples[event.type].length < 4) samples[event.type].push(event);

        if (event.type === 'tracing_mark_write' && fields.phase) {
          if (workloadPid == null) workloadPid = event.pid;
          phases.push({ name: fields.phase, time: event.time, index: events.length - 1 });
        }
        if (event.type === 'tracing_mark_write' && fields.mm_mapping) {
          mappings.push({ name: fields.mm_mapping, fields: Object.assign({}, fields), time: event.time, index: events.length - 1 });
        }
        if (event.type === 'tracing_mark_write' && fields.mm_faults) {
          faults.push({ name: fields.mm_faults, minor: +(fields.minor || 0), major: +(fields.major || 0), fields: Object.assign({}, fields), time: event.time, index: events.length - 1 });
        }
        if (event.type === 'rss_stat' && fields.mm_id) {
          var mm = fields.mm_id;
          var member = fields.member || fields.type || 'unknown';
          rssState[mm] = rssState[mm] || {};
          rssState[mm][member] = Math.max(0, byteValue(fields.size));
          if (fields.curr === '1') rssOwners[mm] = { task: event.task, pid: event.pid };
          event.rss = Object.assign({}, rssState[mm]);
          event.mmOwner = rssOwners[mm] || null;
        }

        if (event.type === 'kmem_cache_alloc' || event.type === 'kmalloc') {
          var site = fields.call_site || 'unknown';
          var requested = +(fields.bytes_req || 0), allocated = +(fields.bytes_alloc || 0);
          sites[site] = sites[site] || { count: 0, bytes: 0, waste: 0 };
          sites[site].count++;
          sites[site].bytes += allocated;
          sites[site].waste += Math.max(0, allocated - requested);
          bytesReq += requested;
          bytesAlloc += allocated;
          if (fields.name) {
            caches[fields.name] = caches[fields.name] || { count: 0, bytes: 0, waste: 0 };
            caches[fields.name].count++;
            caches[fields.name].bytes += allocated;
            caches[fields.name].waste += Math.max(0, allocated - requested);
          }
        }
        if (event.type === 'mm_page_alloc') {
          var order = fields.order || '0';
          orders[order] = (orders[order] || 0) + 1;
          var gfp = fields.gfp_flags || 'none';
          gfps[gfp] = (gfps[gfp] || 0) + 1;
        }
      });

      if (!events.length) throw Error('no trace events parsed');
      var start = events[0].time, end = events[events.length - 1].time;
      if (phases.length) {
        start = phases[0].time;
        end = phases[phases.length - 1].time;
      }
      var span = Math.max(0.000001, end - start), binCount = 160, bins = {};
      Object.keys(counts).forEach(function (type) { bins[type] = Array(binCount).fill(0); });
      events.forEach(function (event) {
        if (event.time < start || event.time > end) return;
        var index = Math.min(binCount - 1, Math.floor((event.time - start) / span * binCount));
        bins[event.type][index]++;
      });

      /* Identify the workload file from its dominant cache insertions during seeding. */
      var seed = phases.find(function (phase) { return /^file backed: seed/.test(phase.name); });
      var seedIndex = seed ? phases.indexOf(seed) : -1;
      var seedEnd = seedIndex >= 0 && phases[seedIndex + 1] ? phases[seedIndex + 1].time : end;
      var identities = {};
      events.forEach(function (event) {
        if (!seed || event.time < seed.time || event.time >= seedEnd || event.type !== 'mm_filemap_add_to_page_cache' || event.pid !== workloadPid) return;
        var key = (event.fields.dev || '?') + '/' + (event.fields.ino || '?');
        identities[key] = (identities[key] || 0) + 1;
      });
      var identity = Object.keys(identities).sort(function (a, b) { return identities[b] - identities[a]; })[0] || '';
      var identityParts = identity.split('/'), targetInode = identityParts[1] ? parseInt(identityParts[1], 16) : -1;
      var cacheEvents = [], cacheLength = 0;
      var cacheTypes = /^(mm_filemap_add_to_page_cache|mm_filemap_delete_from_page_cache|mm_filemap_fault|mm_filemap_get_pages|mm_filemap_map_pages|writeback_dirty_folio)$/;
      events.forEach(function (event) {
        if (!cacheTypes.test(event.type) || !event.fields.ino) return;
        var inode = event.type === 'writeback_dirty_folio' ? parseInt(event.fields.ino, 10) : parseInt(event.fields.ino, 16);
        if (inode !== targetInode) return;
        var action = { mm_filemap_add_to_page_cache: 'cache', mm_filemap_delete_from_page_cache: 'evict', mm_filemap_fault: 'fault', mm_filemap_get_pages: 'read', mm_filemap_map_pages: 'map', writeback_dirty_folio: 'dirty' }[event.type];
        var first, last;
        if (event.type === 'writeback_dirty_folio') {
          first = +(event.fields.index || 0) * 4096;
          last = first + 4096;
        } else {
          var range = String(event.fields.ofs || '0').split('-');
          first = +range[0] || 0;
          last = range.length > 1 ? (+range[1] || first) + 1 : first + 4096 * Math.pow(2, +(event.fields.order || 0));
        }
        cacheLength = Math.max(cacheLength, last);
        cacheEvents.push({ time: event.time, action: action, start: first, end: last, pfn: event.fields.pfn || '', type: event.type });
      });
      var fileCache = { dev: identityParts[0] || '?', inode: targetInode, inodeHex: targetInode >= 0 ? targetInode.toString(16) : '?', length: cacheLength, events: cacheEvents };

      self.postMessage({
        total: events.length, start: start, end: end, events: events, counts: counts,
        types: Object.keys(counts).sort(), bins: bins, samples: samples, phases: phases, mappings: mappings, faults: faults,
        sites: top(sites, 12), caches: top(caches, 16), tasks: top(tasks, 12),
        orders: top(orders, 8), gfps: top(gfps, 8), bytesReq: bytesReq,
        bytesAlloc: bytesAlloc, cpuCounts: cpuCounts, rss: rssState, rssOwners: rssOwners,
        cacheStats: caches,
        taskStats: taskStats, workloadPid: workloadPid, fileCache: fileCache
      });
    }).catch(function (error) {
      self.postMessage({ error: error.message });
    });
  };
}());
