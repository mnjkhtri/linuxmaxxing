/*
 * KAPI view: kernel API study report -> task / address-space / allocator map.
 * Parsing boundary: parseCapture() and parseFields() are the only functions that read the raw report text.
 * Everything downstream (build*, render*) works on the normalized event model and never re-parses the capture.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  let events = [];
  let cursor = 0;
  let taskEvents = [];
  let regions = [];
  let objectDefs = {};

  const GROUPS = [
    {
      title: 'BUDDY / PAGE',
      color: 'var(--blue)',
      objects: ['one_page', 'zero_page', 'order_pages', 'page_desc', 'exact_pages']
    },
    {
      title: 'SLUB OBJECTS',
      color: 'var(--violet)',
      objects: ['slab_buf', 'slab_context', 'custom_cache',
        'custom_object_0', 'custom_object_1', 'custom_object_2', 'custom_object_3',
        'custom_object_4', 'custom_object_5', 'custom_object_6', 'custom_object_7']
    },
    {
      title: 'VMALLOC AREA',
      color: 'var(--orange)',
      objects: ['vbuf', 'vzbuf']
    }
  ];

  /* Parse one key=value field list as emitted by the kernel. */
  function parseFields(text) {
    const out = {};
    const re = /([A-Za-z_][\w]*)=(?:"([^"]*)"|(\S+))/g;
    let m;
    while ((m = re.exec(text))) out[m[1]] = m[2] !== undefined ? m[2] : m[3];
    return out;
  }

  /* The single parsing boundary: raw report text -> normalized events. */
  function parseCapture(text) {
    return text.split(/\r?\n/)
      .map((line, index) => {
        const m = line.match(/^\[\s*([\d.]+)\]\s+KAPI_EVT\s+(.+)$/);
        if (!m) return null;
        const f = parseFields(m[2]);
        return {
          index,
          time: +m[1],
          domain: f.domain || 'other',
          phase: f.phase || 'other',
          action: f.action || 'event',
          fields: f,
          raw: m[2]
        };
      })
      .filter(Boolean)
      .map((e, i) => { e.index = i; return e; });
  }

  /* ---- value helpers --------------------------------------------------- */

  function number(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  }

  function bytes(v) {
    let n = number(v);
    if (n >= 1152921504606846976) return (n / 1152921504606846976).toFixed(2) + ' EiB';
    if (n >= 1125899906842624) return (n / 1125899906842624).toFixed(2) + ' PiB';
    if (n >= 1099511627776) return (n / 1099511627776).toFixed(2) + ' TiB';
    if (n >= 1073741824) return (n / 1073741824).toFixed(2) + ' GiB';
    if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MiB';
    if (n >= 1024) return (n / 1024).toFixed(1) + ' KiB';
    return n + ' B';
  }

  function esc(s) {
    return String(s == null ? '—' : s)
      .replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  }

  function shortAddr(v) {
    v = String(v || '');
    return v.length > 14 ? v.slice(0, 6) + '…' + v.slice(-7) : v;
  }

  function ptrLabel(v) {
    v = String(v || '');
    return /^0+$/.test(v.replace(/^0x/, '')) ? 'NULL' : shortAddr(v);
  }

  function asBig(v) {
    try { return BigInt(v); } catch { return 0n; }
  }

  function hex64(v) {
    return '0x' + v.toString(16).padStart(16, '0');
  }

  /* ---- normalized model ----------------------------------------------- */

  function buildModel() {
    taskEvents = events.filter((e) => e.action === 'task');
    regions = events.filter((e) => e.phase === 'layout' && e.action === 'region');
    events.forEach((e) => {
      const id = e.fields.id;
      const ok = ['page_allocator', 'slab', 'custom_cache', 'vmalloc', 'mapping', 'memory', 'cleanup'].includes(e.phase);
      if (!id || !ok) return;
      if (!objectDefs[id]) objectDefs[id] = { id, alloc: null, create: null, free: null, destroy: null, maps: [], sample: null, summary: null };
      const o = objectDefs[id];
      if (e.action === 'alloc') o.alloc = e;
      if (e.action === 'create') o.create = e;
      if (e.action === 'free') o.free = e;
      if (e.action === 'destroy') o.destroy = e;
      if (e.action === 'page') o.maps.push(e);
      if (e.action === 'sample') o.sample = e;
      if (e.action === 'summary') o.summary = e;
    });
  }

  function objectEvent(o) {
    return o && (o.alloc || o.create);
  }

  function objectPages(o) {
    return o && o.maps ? o.maps.slice().sort((a, b) => number(a.fields.index) - number(b.fields.index)) : [];
  }

  function objectAddress(o) {
    const e = objectEvent(o);
    return (e && (e.fields.addr || e.fields.kva)) || '';
  }

  function objectSize(o) {
    const e = objectEvent(o);
    const s = o && o.summary;
    if (e && e.fields.actual) return bytes(e.fields.actual);
    if (s && s.fields.bytes) return bytes(s.fields.bytes);
    if (e && e.fields.requested) return bytes(e.fields.requested);
    if (e && e.fields.object_size) return bytes(e.fields.object_size);
    return '—';
  }

  function printedApi(o) {
    const e = objectEvent(o);
    return e ? esc(e.fields.api || e.action) : '—';
  }

  function printedPages(o) {
    const s = o && o.summary;
    const m = objectPages(o);
    return s ? esc(s.fields.pages || m.length || 0) : String(m.length);
  }

  function pfnRuns(maps) {
    const runs = [];
    maps.forEach((m) => {
      const p = number(m.fields.pfn);
      const last = runs[runs.length - 1];
      if (last && p === last.end + 1) { last.end = p; last.count++; }
      else runs.push({ start: p, end: p, count: 1 });
    });
    return runs;
  }

  function printedPfnRun(o) {
    const maps = objectPages(o);
    if (!maps.length) return '—';
    const runs = pfnRuns(maps);
    return runs.length === 1 ? String(runs[0].start) + (runs[0].end !== runs[0].start ? '–' + runs[0].end : '') : 'runs ' + runs.length;
  }

  function printedContig(o) {
    return o && o.summary ? esc(o.summary.fields.physical_contiguous || '—') : '—';
  }

  function regionContainingAddress(addr) {
    const value = asBig('0x' + String(addr || '').replace(/^0x/, ''));
    if (!value) return null;
    let found = null;
    regions.forEach((e) => {
      const start = asBig(e.fields.start);
      const end = asBig(e.fields.end);
      if (value >= start && value < end) found = e;
    });
    return found;
  }

  function targetRegionForObject(o) {
    return regionContainingAddress(objectAddress(o));
  }

  function targetEvidence(o) {
    const addr = objectAddress(o);
    const r = targetRegionForObject(o);
    if (!addr) return 'no returned KVA';
    return r ? 'KVA ' + addr + ' inside ' + r.fields.id : 'KVA ' + addr + ' outside observed regions';
  }

  /* ---- selection ------------------------------------------------------- */

  function markSelected() {
    document.querySelectorAll('[data-selected]').forEach((n) => delete n.dataset.selected);
    document.querySelectorAll('[data-event="' + cursor + '"]').forEach((n) => (n.dataset.selected = '1'));
  }

  function selectEvent(index) {
    cursor = Math.max(0, Math.min(events.length - 1, index));
    render();
    markSelected();
  }

  function installSelectionDelegation() {
    const root = document.querySelector('.stage-wrap');
    if (!root) return;
    root.addEventListener('mousedown', (ev) => {
      const card = ev.target.closest('[data-event]');
      if (!card || !root.contains(card)) return;
      ev.preventDefault();
      ev.stopPropagation();
      selectEvent(number(card.dataset.event));
    }, true);
  }

  /* ---- builders --------------------------------------------------------- */

  function buildTasks() {
    const root = $('task-list');
    root.innerHTML = '<div class="task-list-head"><span>TASK</span><span>PID/TGID</span><span>CPU</span><span>TYPE</span><span>TASK_STRUCT</span><span>KSTACK</span><span>MM_STRUCT</span></div>';
    taskEvents.forEach((e) => {
      const kind = e.fields.type && e.fields.type.indexOf('user') === 0 ? 'user' : e.fields.type === 'idle' ? 'idle' : 'kthread';
      const row = document.createElement('button');
      row.className = 'task-row ' + kind;
      row.dataset.event = e.index;
      row.innerHTML = '<span class="task-main"><b>' + esc(e.fields.comm) + '</b></span>' +
        '<span class="task-id">' + esc(e.fields.pid) + '/' + esc(e.fields.tgid) + '</span>' +
        '<span class="task-cpu">' + esc(e.fields.cpu) + '</span>' +
        '<span class="task-type" title="parent ' + esc(e.fields.ppid) + '">' + esc(e.fields.type) + '</span>' +
        '<span class="task-pointers"><code title="' + esc(e.fields.task) + '">' + esc(ptrLabel(e.fields.task)) + '</code>' +
        '<code title="' + esc(e.fields.stack) + '">' + esc(ptrLabel(e.fields.stack)) + '</code>' +
        '<code title="' + esc(e.fields.mm) + '">' + esc(ptrLabel(e.fields.mm)) + '</code></span>';
      root.appendChild(row);
    });
    const users = taskEvents.filter((e) => (e.fields.type || '').indexOf('user') === 0).length;
    const kthreads = taskEvents.filter((e) => e.fields.type === 'kthread').length;
    $('task-summary').innerHTML = '<span class="summary-chip"><b>' + taskEvents.length + '</b> tasks</span>' +
      '<span class="summary-chip"><b>' + kthreads + '</b> kthreads</span>' +
      '<span class="summary-chip"><b>' + users + '</b> user tasks</span>';
  }

  function buildLayout() {
    const root = $('vas-stack');
    root.innerHTML = '<div class="vas-table-head"><span>REGION</span><span>ADDRESS RANGE</span><span>SIZE</span></div>';
    const palette = {
      kernel_image: 'var(--green)', module_space: 'var(--blue)',
      vmalloc: 'var(--orange)', physical_direct_map: 'var(--blue)',
      struct_page_array: 'var(--violet)', reserved: 'var(--faint)',
      guard: 'var(--red)', invalid: 'var(--red)', efi_runtime: 'var(--orange)',
      per_cpu_entry: 'var(--green)', conditional: 'var(--violet)', process_specific: 'var(--green)'
    };
    regions.slice().sort((a, b) => asBig(b.fields.start) > asBig(a.fields.start) ? 1 : -1).forEach((e) => {
      const start = asBig(e.fields.start);
      const end = asBig(e.fields.end);
      const displayEnd = end ? end - 1n : end;
      const id = e.fields.id || 'region';
      const kind = e.fields.kind || 'region';
      const full = hex64(start) + ' → ' + hex64(displayEnd);
      const shown = shortAddr(hex64(start)) + ' → ' + shortAddr(hex64(displayEnd));
      const node = document.createElement('button');
      node.className = 'vas-region known';
      node.dataset.event = e.index;
      node.dataset.regionId = id;
      node.style.setProperty('--region-color', palette[kind] || 'var(--cyan)');
      node.innerHTML = '<b title="' + esc(kind.replace(/_/g, ' ')) + '">' + esc(id.replace(/_/g, ' ')) + '</b>' +
        '<code title="' + esc(full) + '">' + esc(shown) + '</code>' +
        '<span class="vas-size">' + esc(bytes(e.fields.bytes)) + '</span>';
      root.appendChild(node);
    });
  }

  function buildAllocatorLinks() {
    const root = $('allocator-links');
    root.innerHTML = '<header class="alloc-title"><b>ALLOCATOR → VIRTUAL RANGE</b><span>range lookup from returned KVA</span></header><div class="alloc-stack"></div>';
    const stack = root.querySelector('.alloc-stack');
    GROUPS.forEach((g) => {
      const section = document.createElement('section');
      section.className = 'alloc-group';
      section.style.setProperty('--group-color', g.color);
      section.innerHTML = '<header><b>' + esc(g.title) + '</b></header>' +
        '<div class="alloc-table-head"><span>object</span><span>kva</span><span>api</span><span>size</span><span>pages</span><span>pfn</span><span>contig</span></div>' +
        '<div class="alloc-list"></div>';
      const list = section.querySelector('.alloc-list');
      g.objects.forEach((id) => {
        const o = objectDefs[id];
        const e = objectEvent(o);
        if (!e) return;
        const region = targetRegionForObject(o);
        const addr = objectAddress(o);
        const button = document.createElement('button');
        button.className = 'alloc-row';
        button.dataset.event = e.index;
        button.dataset.object = id;
        button.dataset.target = region ? region.fields.id : '';
        button.title = targetEvidence(o);
        button.innerHTML = '<b class="alloc-cell alloc-name">' + esc(id.replace(/_/g, ' ')) + '</b>' +
          '<code class="alloc-cell alloc-kva" title="' + esc(addr) + '">' + esc(addr || '—') + '</code>' +
          '<span class="alloc-cell">' + printedApi(o) + '</span>' +
          '<span class="alloc-cell">' + objectSize(o) + '</span>' +
          '<span class="alloc-cell">' + printedPages(o) + '</span>' +
          '<span class="alloc-cell">' + printedPfnRun(o) + '</span>' +
          '<span class="alloc-cell">' + printedContig(o) + '</span>';
        list.appendChild(button);
      });
      stack.appendChild(section);
    });
  }

  function taskRegionHits(e) {
    const hits = {};
    if (!e || e.action !== 'task') return hits;
    [['task_struct', e.fields.task], ['kstack', e.fields.stack], ['mm_struct', e.fields.mm]].forEach(([label, addr]) => {
      const r = regionContainingAddress(addr);
      if (!r) return;
      const id = r.fields.id;
      (hits[id] || (hits[id] = [])).push(label);
    });
    return hits;
  }

  /* ---- rendering --------------------------------------------------------- */

  function renderTasks() {
    document.querySelectorAll('.task-row').forEach((n) => n.classList.toggle('current', number(n.dataset.event) === cursor));
    $('stage-stat').textContent = taskEvents.length + ' task_struct records';
  }

  function renderLayout(e) {
    const taskHits = taskRegionHits(e);
    let firstTaskTarget = null;
    document.querySelectorAll('.vas-region[data-event]').forEach((n) => {
      n.classList.toggle('current', number(n.dataset.event) === cursor);
      const hit = taskHits[n.dataset.regionId];
      n.classList.toggle('task-target', !!hit);
      if (hit) {
        n.dataset.taskHit = hit.join(' + ');
        if (!firstTaskTarget) firstTaskTarget = n;
      } else {
        delete n.dataset.taskHit;
      }
    });
    if (e.action === 'task' && firstTaskTarget) firstTaskTarget.scrollIntoView({ block: 'center', inline: 'nearest' });
    const selectedRegion = e.action === 'region' ? e : (e.action === 'task' ? null : targetRegionForObject(e.fields.id && objectDefs[e.fields.id]));
    const target = selectedRegion && selectedRegion.fields.id;
    document.querySelectorAll('.vas-region[data-region-id]').forEach((n) => n.classList.toggle('alloc-target', target && n.dataset.regionId === target));
    document.querySelectorAll('.alloc-row').forEach((n) => {
      n.classList.toggle('current', n.dataset.object === e.fields.id);
      n.classList.toggle('region-match', e.action === 'region' && n.dataset.target === target);
    });
    const hitCount = Object.keys(taskHits).length;
    $('stage-stat').textContent = hitCount
      ? ('task addresses in ' + hitCount + ' canonical region' + (hitCount === 1 ? '' : 's'))
      : (regions.length + ' regions · allocator targets highlighted');
  }

  function render() {
    const e = events[cursor] || events[0];
    $('stage-title').textContent = 'Kernel API map';
    $('stage-description').textContent = 'task_struct inventory · canonical regions · allocator return addresses · physical backing';
    renderLayout(e);
    renderTasks(e);
  }

  /* ---- load --------------------------------------------------------------- */

  fetch('../../shared/_captures/kapi-Report.txt?v=' + Date.now(), { cache: 'no-store' })
    .then((r) => {
      if (!r.ok) throw Error('HTTP ' + r.status);
      return r.text();
    })
    .then((text) => {
      events = parseCapture(text);
      if (!events.length) throw Error('no kernel API events');
      buildModel();
      buildTasks();
      buildLayout();
      buildAllocatorLinks();
      installSelectionDelegation();
      cursor = regions[0] ? regions[0].index : 0;
      $('status').innerHTML = '<i class="trace-dot"></i><span>' + events.length + ' kernel API events</span>';
      render();
      markSelected();
    })
    .catch((err) => {
      $('status').textContent = 'KAPI data error · ' + err.message;
    });
})();