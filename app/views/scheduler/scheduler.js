/*
 * Scheduler capture lab: CFS per-CPU runqueues.
 *
 * Architecture
 * ------------
 *   capture loading   -> raw text from scheduler.eBPF.ndjson + scheduler-Trace.txt
 *   NDJSON parsing    -> parseSnapshot(): canonical v1 envelope -> internal frame
 *   tracefs parsing   -> parseSchedulerTrace(): raw lines -> lifecycle model
 *   model/index       -> parseCapture(): frames, per-CPU streams, migrations
 *   RB-tree validation-> verifyFrame(): derive invariants from captured state
 *   tree layout       -> layoutTree(): depth / slot positions from the captured root
 *   tree rendering    -> paintTree(): SVG RB tree per CPU
 *   lifecycle rendering-> drawLifecycle(): task lanes + playhead
 *   notebook rendering-> renderNotebook(): details + invariant checks + migration
 *   playback          -> render()/setPlaying()/schedule(): scrub, prev/next, speed
 *
 * All rendering reads only the normalized internal frame/lifecycle model, never raw capture JSON fields.
 */
(function () {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* Constants                                                          */
  /* ------------------------------------------------------------------ */

  var SVG_NS = 'http://www.w3.org/2000/svg';
  var NODE_RADIUS = 22;
  var ZERO_ADDR = '0000000000000000';
  var SCHEMA_VERSION = 1;
  var NDJSON_PATH = '/shared/_captures/scheduler.eBPF.ndjson';
  var TRACE_PATH = '/shared/_captures/scheduler-Trace.txt';

  /* ------------------------------------------------------------------ */
  /* State                                                              */
  /* ------------------------------------------------------------------ */

  var frames = [];
  var streams = [];
  var panels = {};
  var currentIndex = -1;
  var playing = false;
  var animationTimer = null;
  var rafById = {};
  var migrationFrames = [];
  var playAnchorTime = 0;
  var playAnchorIndex = 0;
  var lifecycle = { rows: [], start: 0, end: 0 };

  /* ------------------------------------------------------------------ */
  /* DOM helpers                                                        */
  /* ------------------------------------------------------------------ */

  function byId(id) {
    return document.getElementById(id);
  }

  function valid(value) {
    return !!value && value !== ZERO_ADDR && value !== '0x0' && value !== '(null)';
  }

  function short(value) {
    return valid(value) ? '\u2026' + String(value).slice(-8) : 'null';
  }

  function svgEl(name) {
    return document.createElementNS(SVG_NS, name);
  }

  function svgAdd(parent, name, attrs, text) {
    var node = svgEl(name);
    Object.keys(attrs || {}).forEach(function (key) {
      node.setAttribute(key, attrs[key]);
    });
    if (text != null) node.textContent = text;
    parent.appendChild(node);
    return node;
  }

  /* ------------------------------------------------------------------ */
  /* NDJSON parsing (normalization boundary)                            */
  /* ------------------------------------------------------------------ */

  /*
   * Consume one canonical v1 snapshot record and return the internal frame representation the renderer works with, or null for meta records and malformed lines.
   * This is the only place capture JSON fields are read.
   */
  function parseSnapshot(record) {
    if (!record || record.kind !== 'snapshot' || record.schema_version !== SCHEMA_VERSION) {
      return null;
    }
    var ctx = record.context || {};
    var rq = record.state && record.state.runqueue;
    if (!rq || ctx.cpu == null || !valid(rq.address)) {
      return null;
    }

    var map = {};
    (rq.nodes || []).forEach(function (node) {
      if (!valid(node.address)) return;
      map[node.address] = {
        address: node.address,
        left: valid(node.left) ? node.left : null,
        right: valid(node.right) ? node.right : null,
        color: node.color === 'red' ? 'red' : 'black',
        comm: node.comm || '?'
      };
    });
    if (!Object.keys(map).length) return null;

    var trigger = record.trigger || {};
    var enqueued = rq.enqueued_entity || {};

    return {
      key: rq.address,
      cpu: +ctx.cpu,
      rq: rq.address,
      op: trigger.name || 'enqueue',
      timeNs: Number(record.time_ns || 0),
      seq: Number(record.seq || 0),
      tid: ctx.tid == null ? 0 : +ctx.tid,
      comm: ctx.comm || '',
      entity: valid(enqueued.address) ? enqueued.address : null,
      runNode: valid(enqueued.rb_node) ? enqueued.rb_node : null,
      focus: valid(enqueued.rb_node) && map[enqueued.rb_node] ? enqueued.rb_node : null,
      root: valid(rq.root) ? rq.root : null,
      leftmost: valid(rq.leftmost) ? rq.leftmost : null,
      nrRunning: rq.nr_running,
      nodeCount: rq.node_count,
      truncated: !!rq.truncated,
      map: map,
      count: Object.keys(map).length
    };
  }

  /*
   * Build the playback model: ordered frames (seq = output order), per-CPU streams, and cross-CPU reappearance edges keyed on the enqueued entity.
   */
  function parseCapture(text) {
    var outFrames = [];
    var streamsByKey = {};
    var localByKey = {};
    var lastCpuByEntity = {};
    var keyCpuByRq = {};

    text.split(/\n/).forEach(function (line) {
      if (!line.trim()) return;
      var record;
      try {
        record = JSON.parse(line);
      } catch (err) {
        return;
      }
      var frame = parseSnapshot(record);
      if (!frame) return;

      frame.global = outFrames.length + 1;
      localByKey[frame.key] = (localByKey[frame.key] || 0) + 1;
      frame.local = localByKey[frame.key];

      var previousKey = frame.entity != null ? lastCpuByEntity[frame.entity] : null;
      frame.from = previousKey && previousKey !== frame.key ? previousKey : null;
      if (frame.entity != null) lastCpuByEntity[frame.entity] = frame.key;

      outFrames.push(frame);

      var stream = streamsByKey[frame.key];
      if (!stream) {
        stream = streamsByKey[frame.key] = {
          key: frame.key,
          cpu: frame.cpu,
          rq: frame.rq,
          frames: [],
          max: 0,
          migrations: 0
        };
      }
      stream.frames.push(frame);
      stream.max = Math.max(stream.max, frame.count);
      if (frame.from) stream.migrations++;
    });

    /*
     * A cfs_rq belongs to exactly one CPU, but the probe may have run on a different CPU during wakeups and remote enqueues.
     * Derive the owning CPU by majority across each runqueue's frames so one physical runqueue renders as one panel.
     */
    Object.keys(streamsByKey).forEach(function (key) {
      var stream = streamsByKey[key];
      var counts = {};
      stream.frames.forEach(function (frame) {
        counts[frame.cpu] = (counts[frame.cpu] || 0) + 1;
      });
      var best = 0;
      var winner = 0;
      Object.keys(counts).forEach(function (cpu) {
        if (counts[cpu] > best) {
          best = counts[cpu];
          winner = +cpu;
        }
      });
      keyCpuByRq[key] = winner;
      stream.cpu = winner;
      stream.frames.forEach(function (frame) {
        frame.cpu = winner;
      });
    });

    outFrames.forEach(function (frame) {
      if (frame.from) frame.fromCpu = keyCpuByRq[frame.from];
    });

    var streamList = Object.keys(streamsByKey).map(function (key) {
      return streamsByKey[key];
    }).sort(function (a, b) {
      return a.cpu - b.cpu || String(a.rq).localeCompare(String(b.rq));
    });

    return { frames: outFrames, streams: streamList };
  }

  /* ------------------------------------------------------------------ */
  /* Tracefs parsing (isolated; raw text never leaves this function)     */
  /* ------------------------------------------------------------------ */

  /*
   * Parse the raw tracefs capture into a lifecycle model.
   * Timestamps are normalized to timeNs = seconds * 1e9, the same unit as eBPF time_ns.
   */
  function parseSchedulerTrace(text) {
    var rows = {};
    var start = Infinity;
    var end = 0;
    var lineRe = /^\s*(.+?)-(\d+)\s+\[(\d+)\]\s+\S+\s+([0-9.]+):\s+([A-Za-z0-9_]+):\s*(.*)$/;

    function fields(line) {
      var out = {};
      var m;
      var re = /([A-Za-z_]+)=([^\s]+)/g;
      while ((m = re.exec(line))) out[m[1]] = m[2];
      return out;
    }

    function row(pid, name, timeNs) {
      if (!pid) return null;
      return rows[pid] || (rows[pid] = {
        pid: pid,
        name: name || ('pid ' + pid),
        first: timeNs,
        last: timeNs,
        runs: [],
        marks: [],
        running: null
      });
    }

    function mark(r, type, timeNs) {
      if (!r) return;
      r.marks.push({ timeNs: timeNs, type: type });
      r.last = timeNs;
    }

    text.split(/\n/).forEach(function (raw) {
      var m = raw.match(lineRe);
      if (!m) return;
      var timeNs = Math.round(parseFloat(m[4]) * 1e9);
      var cpu = +m[3];
      var type = m[5];
      var f = fields(m[6]);

      if (type === 'sched_process_fork') {
        mark(row(f.child_pid, f.child_comm, timeNs), 'fork', timeNs);
        row(f.pid, f.comm, timeNs);
      } else if (type === 'sched_wakeup_new') {
        mark(row(f.pid, f.comm, timeNs), 'wake', timeNs);
      } else if (type === 'sched_switch') {
        var prev = row(f.prev_pid, f.prev_comm, timeNs);
        var next = row(f.next_pid, f.next_comm, timeNs);
        if (prev && f.prev_comm) prev.name = f.prev_comm;
        if (next && f.next_comm) next.name = f.next_comm;
        if (prev && prev.running) {
          prev.runs.push({ from: prev.running.timeNs, to: timeNs, cpu: prev.running.cpu });
          prev.running = null;
          prev.last = timeNs;
        }
        if (next) {
          next.running = { timeNs: timeNs, cpu: cpu };
          next.last = timeNs;
        }
      } else if (type === 'sched_process_wait' ||
                 type === 'sched_process_exit' ||
                 type === 'sched_process_free') {
        mark(row(f.pid, f.comm, timeNs), type.replace('sched_process_', ''), timeNs);
      }

      if (type === 'sched_process_fork' || type === 'sched_wakeup_new' ||
          type === 'sched_switch' || type === 'sched_process_wait' ||
          type === 'sched_process_exit' || type === 'sched_process_free') {
        start = Math.min(start, timeNs);
        end = Math.max(end, timeNs);
      }
    });

    Object.keys(rows).forEach(function (pid) {
      var r = rows[pid];
      if (r.running) {
        r.runs.push({ from: r.running.timeNs, to: end, cpu: r.running.cpu });
        r.running = null;
      }
      start = Math.min(start, r.first);
      end = Math.max(end, r.last);
    });

    return {
      rows: Object.keys(rows).map(function (id) {
        return rows[id];
      }).sort(function (a, b) {
        return a.first - b.first || a.pid - b.pid;
      }),
      start: start,
      end: end
    };
  }

  /* ------------------------------------------------------------------ */
  /* RB-tree validation (derived from captured state only)               */
  /* ------------------------------------------------------------------ */

  function structuralMinimum(map, root) {
    var min = root;
    while (min && map[min] && map[min].left) min = map[min].left;
    return min;
  }

  function verifyFrame(frame) {
    var map = frame.map;
    var root = frame.root;
    var seen = {};
    var redOK = true;
    var bhOK = true;
    var cycle = false;

    function walk(address, parentRed) {
      if (!address || !map[address]) return 1;
      if (seen[address]) {
        cycle = true;
        return 0;
      }
      seen[address] = true;
      var node = map[address];
      var isRed = node.color === 'red';
      if (isRed && parentRed) redOK = false;
      var left = walk(node.left, isRed);
      var right = walk(node.right, isRed);
      if (left !== right) bhOK = false;
      return left + (isRed ? 0 : 1);
    }

    var height = walk(root, false);
    var rootBlack = !root || map[root].color !== 'red';
    var leftmostCorrect = !frame.leftmost || frame.leftmost === structuralMinimum(map, root);

    return {
      root: root,
      rootBlack: rootBlack,
      red: redOK && !cycle,
      bh: bhOK && !cycle,
      height: Math.max(0, height - 1),
      leftmost: leftmostCorrect,
      ok: rootBlack && redOK && bhOK && !cycle && leftmostCorrect
    };
  }

  /* ------------------------------------------------------------------ */
  /* Tree layout (from the captured root)                                */
  /* ------------------------------------------------------------------ */

  function layoutTree(svg, frame) {
    var map = frame.map;
    var root = frame.root;
    var width = svg.clientWidth || 520;
    var height = svg.clientHeight || 440;
    var raw = {};
    var seen = {};
    var slot = 0;
    var maxDepth = 0;

    function walk(address, depth) {
      if (!address || !map[address] || seen[address]) return null;
      seen[address] = true;
      var node = map[address];
      var left = walk(node.left, depth + 1);
      var right = walk(node.right, depth + 1);
      var s;
      if (left == null && right == null) {
        s = slot++;
      } else if (left != null && right != null) {
        s = (left + right) / 2;
      } else {
        s = left != null ? left + 0.7 : right - 0.7;
      }
      raw[address] = { slot: s, depth: depth };
      maxDepth = Math.max(maxDepth, depth);
      return s;
    }

    walk(root, 0);

    var addresses = Object.keys(raw);
    var min = 0;
    var max = 0;
    if (addresses.length) {
      min = max = raw[addresses[0]].slot;
      addresses.forEach(function (a) {
        min = Math.min(min, raw[a].slot);
        max = Math.max(max, raw[a].slot);
      });
    }

    var pos = {};
    var padX = 45;
    var padY = 43;
    addresses.forEach(function (a) {
      pos[a] = {
        x: addresses.length === 1
          ? width / 2
          : padX + (raw[a].slot - min) / Math.max(1, max - min) * (width - padX * 2),
        y: maxDepth ? padY + raw[a].depth / maxDepth * (height - padY * 2) : height / 2
      };
    });

    return { pos: pos, depth: maxDepth + 1, root: root };
  }

  /* ------------------------------------------------------------------ */
  /* Tree rendering                                                      */
  /* ------------------------------------------------------------------ */

  function inspectNode(frame, address) {
    var node = frame.map[address];
    byId('layer').textContent = 'CPU ' + frame.cpu + ' / rb_node';
    byId('title').textContent = node.comm;
    byId('copy').textContent = 'Embedded rb_node ' + (node.color === 'red' ? 'is red' : 'is black') +
      '. Its child links are left ' + short(node.left) + ' and right ' + short(node.right) + '.';
    byId('v-node').textContent = address;
    byId('v-node').title = address;
  }

  function paintTree(panel, frame, laid) {
    var svg = panel.svg;
    var target = laid.pos;
    var keys = Object.keys(target);
    var start = {};
    var old = panel.pos || {};
    var t0 = performance.now();

    keys.forEach(function (key) {
      start[key] = old[key] || target[key];
    });
    if (rafById[panel.key]) cancelAnimationFrame(rafById[panel.key]);

    function animate(now) {
      var t = playing ? 1 : Math.min(1, (now - t0) / 160);
      var ease = t * t * (3 - 2 * t);
      var pos = {};
      keys.forEach(function (key) {
        pos[key] = {
          x: start[key].x + (target[key].x - start[key].x) * ease,
          y: start[key].y + (target[key].y - start[key].y) * ease
        };
      });

      svg.innerHTML = '';
      keys.forEach(function (a) {
        var node = frame.map[a];
        [node.left, node.right].forEach(function (to) {
          if (!to || !pos[to]) return;
          svgAdd(svg, 'line', {
            x1: pos[a].x,
            y1: pos[a].y,
            x2: pos[to].x,
            y2: pos[to].y,
            'class': 'edge'
          });
        });
      });

      keys.forEach(function (a) {
        var node = frame.map[a];
        var p = pos[a];
        var isRed = node.color === 'red';
        var group = svgEl('g');
        var circleClass = 'circle ' + (isRed ? 'red' : 'black');
        if (a === frame.focus) circleClass += ' focus';
        if (a === frame.leftmost) circleClass += ' leftmost';

        group.setAttribute('class', 'tree-node');
        group.setAttribute('tabindex', '0');
        group.setAttribute('role', 'button');
        group.setAttribute('aria-label', node.comm + ' ' + (isRed ? 'red' : 'black') + ' node');

        svgAdd(group, 'circle', {
          cx: p.x,
          cy: p.y,
          r: NODE_RADIUS,
          'class': circleClass
        });

        var label = node.comm.length > 10 ? node.comm.slice(0, 9) + '\u2026' : node.comm;
        svgAdd(group, 'text', { x: p.x, y: p.y - 7, 'class': 'node-text comm' }, label);
        svgAdd(group, 'text', { x: p.x, y: p.y + 4, 'class': 'node-text' }, short(a));
        svgAdd(group, 'text', { x: p.x, y: p.y + 15, 'class': 'node-text ' + (isRed ? 'red' : '') },
          isRed ? 'RED' : 'BLACK');

        function inspect() {
          inspectNode(frame, a);
        }
        group.addEventListener('click', inspect);
        group.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            inspect();
          }
        });

        svg.appendChild(group);
      });

      panel.pos = pos;
      if (t < 1) rafById[panel.key] = requestAnimationFrame(animate);
    }

    animate(t0);
  }

  function frameAtStream(stream, global) {
    var list = stream.frames;
    var lo = 0;
    var hi = list.length - 1;
    var best = null;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      if (list[mid].global <= global) {
        best = list[mid];
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return best;
  }

  function renderTreePanel(stream, frame, isCurrent) {
    var panel = panels[stream.key];
    panel.el.classList.toggle('current', isCurrent);
    if (!frame) {
      panel.empty.style.display = 'grid';
      panel.empty.textContent = 'No snapshot yet at capture ' + (currentIndex + 1);
      panel.svg.innerHTML = '';
      panel.meta.innerHTML = '<span>waiting for first CPU ' + stream.cpu + ' event</span>';
      panel.lastGlobal = 0;
      return;
    }
    panel.empty.style.display = 'none';
    var checks = verifyFrame(frame);
    var laid = layoutTree(panel.svg, frame);
    panel.meta.innerHTML =
      '<span>' + frame.count + ' nodes</span>' +
      '<span>depth ' + laid.depth + '</span>' +
      '<span class="' + (checks.ok ? 'pass' : 'fail') + '">RB ' + (checks.ok ? 'pass' : 'fail') + '</span>' +
      '<span class="frame">local ' + frame.local + ' \u00b7 updated @ ' + frame.global + '</span>';
    if (panel.lastGlobal !== frame.global) {
      paintTree(panel, frame, laid);
      panel.lastGlobal = frame.global;
    }
  }

  /* ------------------------------------------------------------------ */
  /* Notebook / details rendering                                        */
  /* ------------------------------------------------------------------ */

  function frameComm(frame) {
    return frame.focus && frame.map[frame.focus] ? frame.map[frame.focus].comm : short(frame.entity);
  }

  function renderMigration(frame) {
    var prev = null;
    var next = null;
    migrationFrames.forEach(function (candidate) {
      if (candidate.global < frame.global) prev = candidate;
      if (candidate.global > frame.global && !next) next = candidate;
    });
    byId('migration-count').textContent = migrationFrames.length + ' events';
    byId('prev-mig').disabled = !prev;
    byId('next-mig').disabled = !next;
    var box = byId('migration');
    var text = byId('migration-text');
    if (frame.from) {
      box.className = 'migration show';
      text.textContent = frameComm(frame) + ' \u00b7 CPU ' + frame.fromCpu + ' \u2192 CPU ' +
        frame.cpu + ' \u00b7 event ' + frame.global;
    } else {
      box.className = 'migration';
      text.textContent = next
        ? 'Next: ' + frameComm(next) + ' \u00b7 event ' + next.global + ' \u00b7 CPU ' +
          next.fromCpu + ' \u2192 CPU ' + next.cpu
        : 'No later cross-CPU event.';
    }
  }

  function renderNotebook(frame) {
    var checks = verifyFrame(frame);
    byId('op').textContent = frame.op;
    byId('layer').textContent = 'CPU ' + frame.cpu;
    byId('title').textContent = frame.focus && frame.map[frame.focus]
      ? frame.map[frame.focus].comm
      : 'enqueue snapshot';
    byId('v-cpu').textContent = 'CPU ' + frame.cpu;
    byId('v-rq').textContent = frame.rq;
    byId('v-rq').title = frame.rq;
    byId('v-tid').textContent = String(frame.tid);
    byId('v-se').textContent = frame.entity || '\u2014';
    byId('v-se').title = frame.entity || '';
    byId('v-node').textContent = frame.focus || 'not present';
    byId('v-left').textContent = frame.leftmost || '\u2014';
    byId('v-left').title = frame.leftmost || '';

    var rows = [
      ['Root is black', checks.rootBlack],
      ['No red-red parent/child', checks.red],
      ['Equal black height: ' + checks.height, checks.bh],
      ['Cached leftmost is structural minimum', checks.leftmost]
    ];
    byId('checks').innerHTML = rows.map(function (item) {
      return '<div class="check ' + (item[1] ? '' : 'bad') + '"><i></i><span>' + item[0] + '</span></div>';
    }).join('');

    renderMigration(frame);
  }

  function jumpMigration(direction) {
    if (!migrationFrames.length) return;
    var g = frames[currentIndex].global;
    var target = null;
    if (direction > 0) {
      for (var i = 0; i < migrationFrames.length; i++) {
        if (migrationFrames[i].global > g) {
          target = migrationFrames[i];
          break;
        }
      }
    } else {
      for (var j = migrationFrames.length - 1; j >= 0; j--) {
        if (migrationFrames[j].global < g) {
          target = migrationFrames[j];
          break;
        }
      }
    }
    if (target) {
      setPlaying(false);
      render(target.global - 1);
    }
  }

  /* ------------------------------------------------------------------ */
  /* Task lifecycle rendering                                            */
  /* ------------------------------------------------------------------ */

  function drawLifecycle() {
    var root = byId('life-canvas');
    if (!root || !lifecycle.rows.length) return;
    root.innerHTML = '';

    var span = Math.max(0.001, lifecycle.end - lifecycle.start);
    var available = Math.max(200, root.clientHeight - 16);
    var rowHeight = Math.max(10, Math.min(16, available / lifecycle.rows.length));

    lifecycle.rows.forEach(function (r) {
      var row = document.createElement('div');
      row.className = 'life-row';
      row.style.height = rowHeight + 'px';
      row.style.flexBasis = rowHeight + 'px';

      var name = document.createElement('span');
      name.className = 'life-name';
      name.textContent = r.name;
      name.title = r.name + ' [' + r.pid + ']';

      var track = document.createElement('div');
      track.className = 'life-track';
      r.runs.forEach(function (run) {
        var bar = document.createElement('i');
        bar.className = 'life-run cpu-' + run.cpu;
        bar.style.left = (run.from - lifecycle.start) / span * 100 + '%';
        bar.style.width = Math.max(0.6, (run.to - run.from) / span * 100) + '%';
        track.appendChild(bar);
      });
      r.marks.forEach(function (ev) {
        var mark = document.createElement('i');
        mark.className = 'life-mark ' + ev.type;
        mark.style.left = (ev.timeNs - lifecycle.start) / span * 100 + '%';
        track.appendChild(mark);
      });

      row.appendChild(name);
      row.appendChild(track);
      root.appendChild(row);
    });

    var axis = document.createElement('div');
    axis.className = 'life-axis';
    axis.innerHTML = '<span>0 ms</span><span>' + ((lifecycle.end - lifecycle.start) / 1e6).toFixed(0) + ' ms</span>';
    root.appendChild(axis);

    var playhead = document.createElement('i');
    playhead.id = 'life-playhead';
    playhead.className = 'life-playhead';
    root.appendChild(playhead);

    updateLifecyclePlayhead(frames[currentIndex] ? frames[currentIndex].timeNs : lifecycle.start);
  }

  function updateLifecyclePlayhead(timeNs) {
    var playhead = byId('life-playhead');
    var root = byId('life-canvas');
    if (!playhead || !root || timeNs == null) return;
    var trackStart = 95;
    var trackWidth = Math.max(0, root.clientWidth - trackStart);
    var span = Math.max(1, lifecycle.end - lifecycle.start);
    var progress = Math.max(0, Math.min(1, (timeNs - lifecycle.start) / span));
    playhead.style.left = trackStart + progress * trackWidth + 'px';
  }

  /* ------------------------------------------------------------------ */
  /* Playback                                                            */
  /* ------------------------------------------------------------------ */

  function render(index) {
    if (!frames.length) return;
    currentIndex = Math.max(0, Math.min(index, frames.length - 1));
    var current = frames[currentIndex];
    streams.forEach(function (stream) {
      renderTreePanel(stream, frameAtStream(stream, current.global), stream.key === current.key);
    });
    renderNotebook(current);
    updateLifecyclePlayhead(current.timeNs);
    byId('scrub').value = String(currentIndex);
    byId('counter').textContent = (currentIndex + 1) + ' / ' + frames.length;
    byId('prev').disabled = currentIndex === 0;
    byId('next').disabled = currentIndex === frames.length - 1;
  }

  function setPlaying(value) {
    playing = value;
    byId('play').textContent = value ? 'Pause' : 'Play';
    byId('play').classList.toggle('active', value);
    if (animationTimer) cancelAnimationFrame(animationTimer);
    animationTimer = null;
    if (value) {
      playAnchorTime = performance.now();
      playAnchorIndex = currentIndex;
      schedule();
    }
  }

  function schedule() {
    if (!playing) return;
    animationTimer = requestAnimationFrame(function (now) {
      var rate = Number(byId('speed').value);
      var target = Math.min(frames.length - 1, playAnchorIndex + Math.floor((now - playAnchorTime) * rate / 1000));
      if (target !== currentIndex) render(target);
      if (currentIndex >= frames.length - 1) {
        setPlaying(false);
        return;
      }
      schedule();
    });
  }

  /* ------------------------------------------------------------------ */
  /* CPU rail / panel construction                                       */
  /* ------------------------------------------------------------------ */

  function build() {
    var rail = byId('cpu-rail');
    var trees = byId('trees');
    rail.innerHTML = '';
    trees.innerHTML = '';
    panels = {};

    streams.forEach(function (stream) {
      var card = document.createElement('button');
      card.className = 'cpu-card';
      card.innerHTML =
        '<strong>CPU ' + stream.cpu + '</strong>' +
        '<span>' + stream.frames.length.toLocaleString() + ' frames \u00b7 max ' + stream.max + ' nodes</span>' +
        '<code>cfs_rq ' + short(stream.rq) + '</code>';
      card.addEventListener('click', function () {
        var best = stream.frames.reduce(function (a, f) {
          return f.count > a.count ? f : a;
        }, stream.frames[0]);
        render(best.global - 1);
        updateLifecyclePlayhead(frames[currentIndex] ? frames[currentIndex].timeNs : null);
      });
      rail.appendChild(card);

      var el = document.createElement('section');
      el.className = 'panel tree-panel';
      el.innerHTML =
        '<header class="panel-head"><i class="pulse"></i><h2>CPU ' + stream.cpu + '</h2>' +
        '<span>cfs_rq ' + short(stream.rq) + '</span></header>' +
        '<div class="canvas"><svg role="img" aria-label="CPU ' + stream.cpu + ' CFS runqueue tree"></svg>' +
        '<div class="empty">waiting for snapshot</div></div>' +
        '<footer class="tree-meta"></footer>';
      trees.appendChild(el);

      panels[stream.key] = {
        key: stream.key,
        el: el,
        svg: el.querySelector('svg'),
        empty: el.querySelector('.empty'),
        meta: el.querySelector('.tree-meta'),
        pos: {},
        lastGlobal: 0
      };
    });
  }

  /* ------------------------------------------------------------------ */
  /* Capture loading                                                     */
  /* ------------------------------------------------------------------ */

  function loadCapture(text) {
    var parsed = parseCapture(text);
    frames = parsed.frames;
    streams = parsed.streams;
    migrationFrames = frames.filter(function (frame) {
      return !!frame.from;
    });
    byId('status').innerHTML =
      '<i class="trace-dot"></i><span>' + frames.length.toLocaleString() + ' frames \u00b7 ' +
      streams.length + ' runqueues \u00b7 ' + migrationFrames.length + ' cross-CPU reappearances</span>';
    if (!frames.length) return;
    build();
    byId('scrub').max = String(frames.length - 1);
    render(0);
  }

  function loadLifecycle(text) {
    lifecycle = parseSchedulerTrace(text);
    byId('life-summary').textContent = lifecycle.rows.length + ' task lanes';
    drawLifecycle();
  }

  function fetchWithCacheBust(path) {
    return fetch(path + '?v=' + Date.now(), { cache: 'no-store' }).then(function (response) {
      if (!response.ok) throw new Error(path + ' HTTP ' + response.status);
      return response.text();
    });
  }

  function loadCaptures() {
    Promise.all([fetchWithCacheBust(NDJSON_PATH), fetchWithCacheBust(TRACE_PATH)])
      .then(function (parts) {
        loadLifecycle(parts[1]);
        loadCapture(parts[0]);
      })
      .catch(function (err) {
        byId('status').textContent = 'SCHED data error \u00b7 ' + err.message;
        byId('life-summary').textContent = 'task data unavailable';
      });
  }

  /* ------------------------------------------------------------------ */
  /* Event listeners                                                     */
  /* ------------------------------------------------------------------ */

  function bindEvents() {
    byId('prev-mig').addEventListener('click', function () {
      jumpMigration(-1);
    });
    byId('next-mig').addEventListener('click', function () {
      jumpMigration(1);
    });
    byId('load').addEventListener('click', function () {
      byId('file').click();
    });
    byId('file').addEventListener('change', function () {
      var file = this.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function (event) {
        loadCapture(event.target.result);
      };
      reader.readAsText(file);
      this.value = '';
    });
    byId('prev').addEventListener('click', function () {
      setPlaying(false);
      render(currentIndex - 1);
    });
    byId('next').addEventListener('click', function () {
      setPlaying(false);
      render(currentIndex + 1);
    });
    byId('play').addEventListener('click', function () {
      setPlaying(!playing);
    });
    byId('scrub').addEventListener('input', function () {
      setPlaying(false);
      render(+this.value);
    });
    byId('speed').addEventListener('change', function () {
      if (playing) {
        playAnchorTime = performance.now();
        playAnchorIndex = currentIndex;
      }
    });
    document.addEventListener('keydown', function (e) {
      if (/INPUT|SELECT|BUTTON/.test(e.target.tagName)) return;
      if (e.key === 'ArrowLeft') byId('prev').click();
      if (e.key === 'ArrowRight') byId('next').click();
      if (e.key === ' ') {
        e.preventDefault();
        byId('play').click();
      }
    });
    window.addEventListener('resize', function () {
      Object.keys(panels).forEach(function (key) {
        panels[key].lastGlobal = 0;
        panels[key].pos = {};
      });
      if (lifecycle.rows.length) drawLifecycle();
      if (currentIndex >= 0) render(currentIndex);
    });
  }

  /* ------------------------------------------------------------------ */
  /* Startup                                                             */
  /* ------------------------------------------------------------------ */

  bindEvents();
  loadCaptures();
})();
