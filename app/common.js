const appBase = new URL('./', import.meta.url);
const names = new Set(['scheduler', 'kapi', 'memory', 'io', 'virt-ept', 'virt-io', 'virt-virtio', 'virt-vtd']);

export function parseCapture(text, experiment) {
  if (!text.trim()) throw Error('Capture is empty');
  const lines = text.trimEnd().split(/\r?\n/);
  const events = lines.map((line, index) => {
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      throw Error(`Invalid JSON at record ${index + 1}`);
    }
    if (!event || event.experiment !== experiment || event.sequence !== index + 1 ||
      !event.source || !['host', 'guest'].includes(event.source.domain) ||
      event.clock_domain !== `${event.source.domain}:monotonic` ||
      !/^\d+$/.test(event.timestamp_ns) || typeof event.timestamp_ns !== 'string' ||
      typeof event.kind !== 'string' || !event.kind ||
      !event.context || !event.data || Array.isArray(event.data) || typeof event.data !== 'object' || !event.quality ||
      !['complete', 'partial', 'unavailable'].includes(event.quality.status)) {
      throw Error(`Invalid capture envelope at record ${index + 1}`);
    }
    return event;
  });
  if (events.length < 3 || events[0].kind !== 'capture_started' ||
    events.at(-1).kind !== 'capture_finished' || events.at(-1).data.validated !== true ||
    events.some(event => event.kind === 'capture_failed')) throw Error('Capture is incomplete');
  const origins = new Map();
  for (const event of events) {
    const time = BigInt(event.timestamp_ns);
    if (!origins.has(event.clock_domain) || time < origins.get(event.clock_domain)) origins.set(event.clock_domain, time);
  }
  return {
    events,
    experiment,
    origins,
    partial: events.filter(event => event.quality.status !== 'complete').length
  };
}

export async function loadCapture(experiment, {
  signal
} = {}) {
  if (!names.has(experiment)) throw Error('Unknown experiment');
  const configured = new URLSearchParams(location.search).get('captureBase');
  const base = configured ? new URL(configured, location.href) : new URL('../captures/', appBase);
  const url = new URL(`${experiment}/events.ndjson`, base);
  const response = await fetch(url, {
    cache: 'no-store',
    signal
  });
  if (!response.ok) throw Error(response.status === 404 ? 'Capture unavailable. Collect and fetch this experiment first.' : `Capture HTTP ${response.status}`);
  return parseCapture(await response.text(), experiment);
}

export function relativeNs(capture, event) {
  const delta = BigInt(event.timestamp_ns) - capture.origins.get(event.clock_domain);
  if (delta > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Capture interval exceeds exact drawing precision');
  return Number(delta);
}

// The rendering model uses numbers for bounded counters, and strings for addresses
// and large integers. The original canonical event stays available for inspection.
export function values(value) {
  if (Array.isArray(value)) return value.map(values);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, values(item)]));
  if (typeof value === 'string' && /^-?\d+$/.test(value) && Number.isSafeInteger(Number(value))) return Number(value);
  return value;
}

export function observation(capture, event) {
  return {
    ...values(event.data),
    kind: event.kind,
    context: event.context,
    seq: event.sequence,
    time_ns: relativeNs(capture, event),
    canonical: event
  };
}

export function traceFields(event) {
  const f = values(event.data.fields || {});
  return {
    ...f,
    body: Object.entries(f).map(([key, value]) => `${key}=${value}`).join(' '),
    errorCode: f.error_code,
    reasonCode: f.code,
    oldSpte: f.old_spte,
    newSpte: f.new_spte,
    asId: f.as_id,
    irqSource: f.source,
    operation: f.direction,
    length: f.length,
    address: f.address ?? f.gpa,
    value: f.value,
    table: f.sptep
  };
}

export function reportState(state, message = '') {
  document.documentElement.dataset.captureState = state;
  const status = document.getElementById('capture-message');
  if (status) status.textContent = message;
  if (state === 'error' || state === 'unavailable') {
    const headingStatus = document.getElementById('status');
    if (headingStatus) headingStatus.textContent = state === 'error' ? 'Capture error' : 'No capture available';
  }
  if (parent !== window) parent.postMessage({
    type: 'capture-state',
    state,
    message
  }, location.origin);
}

// Every animated view uses the same cadence and lifecycle. Drawing remains local.
export function playback(advance, interval = 700) {
  let timer = null;

  function stop() {
    clearInterval(timer);
    timer = null;
    const button = document.getElementById('play');
    if (button) {
      button.textContent = 'Play';
      button.classList.remove('active');
      button.setAttribute('aria-label', 'Play');
    }
  }

  function toggle() {
    if (timer) return stop();
    const button = document.getElementById('play');
    if (button) {
      button.textContent = 'Pause';
      button.classList.add('active');
      button.setAttribute('aria-label', 'Pause');
    }
    timer = setInterval(() => {
      if (advance() === false) stop();
    }, interval);
  }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stop();
  });
  window.addEventListener('pagehide', stop);
  document.addEventListener('capture-refresh', stop);
  return {
    stop,
    toggle
  };
}

export function mountView(experiment, renderCapture) {
  document.body.dataset.experiment = experiment;
  const bar = document.createElement('div');
  bar.className = 'view-controls';
  bar.innerHTML = '<span id="capture-message" role="status">Loading capture…</span><button id="capture-refresh">Refresh</button><button id="details-toggle" aria-expanded="false">Details</button>';
  document.body.append(bar);
  const detail = document.querySelector('.inspector, .notebook, .detail-panel, .side-panel');
  const toggle = bar.querySelector('#details-toggle');
  let previousFocus;

  function close() {
    document.body.classList.remove('details-open');
    toggle.setAttribute('aria-expanded', 'false');
    if (detail) {
      detail.removeAttribute('aria-modal');
      detail.removeAttribute('role');
    }
    previousFocus?.focus();
  }
  if (detail) {
    detail.classList.add('view-details');
    detail.id ||= 'view-details';
    toggle.setAttribute('aria-controls', detail.id);
    const closeButton = document.createElement('button');
    closeButton.className = 'details-close';
    closeButton.textContent = 'Close details';
    closeButton.onclick = close;
    detail.prepend(closeButton);
    toggle.onclick = () => {
      if (document.body.classList.contains('details-open')) return close();
      previousFocus = document.activeElement;
      document.body.classList.add('details-open');
      toggle.setAttribute('aria-expanded', 'true');
      if (innerWidth < 1440) {
        detail.setAttribute('role', 'dialog');
        detail.setAttribute('aria-modal', 'true');
        detail.setAttribute('aria-label', 'Observation details');
      }
      closeButton.focus();
      window.dispatchEvent(new Event('resize'));
    };
    document.addEventListener('keydown', event => {
      if (!document.body.classList.contains('details-open')) return;
      if (event.key === 'Escape') close();
      if (event.key === 'Tab' && innerWidth < 1440) {
        const focusable = [...detail.querySelectorAll('button,input,select,a[href],[tabindex="0"]')].filter(node => !node.disabled && node.getClientRects().length);
        const first = focusable[0],
          last = focusable.at(-1);
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    });
  } else toggle.hidden = true;
  matchMedia('(min-width:1440px)').addEventListener('change', () => {
    if (document.body.classList.contains('details-open')) close();
  });
  // Controls must remain usable when the inspector is closed.
  const transport = document.querySelector('.toolbar, .playback-bar');
  if (transport) {
    transport.classList.add('shared-playback');
    bar.prepend(transport);
  }
  for (const [id, label] of [
      ['prev', 'Previous observation'],
      ['next', 'Next observation'],
      ['play', 'Play'],
      ['scrub', 'Observation'],
      ['speed', 'Playback speed']
    ]) {
    document.getElementById(id)?.setAttribute('aria-label', label);
  }
  // Arrow keys inside fields belong to the field, not the diagram's shortcuts.
  document.addEventListener('keydown', event => {
    if (event.target.matches('input,select,textarea,[contenteditable="true"]')) event.stopPropagation();
  }, true);
  let busy = false;
  let rendered = false;
  async function refresh() {
    if (busy) return;
    document.dispatchEvent(new Event('capture-refresh'));
    busy = true;
    bar.querySelector('#capture-refresh').disabled = true;
    reportState('loading', 'Loading capture…');
    try {
      const capture = await loadCapture(experiment);
      document.querySelectorAll('[data-capture-disabled]').forEach(control => {
        control.disabled = false;
        delete control.dataset.captureDisabled;
      });
      await renderCapture(capture);
      rendered = true;
      reportState('ready', `${capture.events.length} records${capture.partial ? ` · ${capture.partial} partial observations` : ''}`);
    } catch (error) {
      reportState(error.message.startsWith('Capture unavailable') ? 'unavailable' : 'error', error.message);
      if (!rendered) document.querySelectorAll('main button:not(.details-close), .shared-playback button, .shared-playback input').forEach(control => {
        control.disabled = true;
        control.dataset.captureDisabled = 'true';
      });
    } finally {
      busy = false;
      bar.querySelector('#capture-refresh').disabled = false;
    }
  }
  bar.querySelector('#capture-refresh').onclick = refresh;
  function removeHoverTooltips(root) {
    const elements = [];
    if (root.nodeType === Node.ELEMENT_NODE && root.matches('[title]')) elements.push(root);
    if (root.querySelectorAll) elements.push(...root.querySelectorAll('[title]'));
    elements.forEach(element => {
      const title = element.getAttribute('title');
      if (title && !element.hasAttribute('aria-label') && /^(A|BUTTON|INPUT|SELECT|TEXTAREA)$/.test(element.tagName)) {
        element.setAttribute('aria-label', title);
      }
      element.removeAttribute('title');
    });
  }
  removeHoverTooltips(document);
  const tooltipObserver = new MutationObserver(records => {
    records.forEach(record => {
      record.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) removeHoverTooltips(node);
      });
      if (record.type === 'attributes') removeHoverTooltips(record.target.parentElement || document);
    });
  });
  tooltipObserver.observe(document.body, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ['title']
  });
  const resize = new ResizeObserver(() => requestAnimationFrame(() => window.dispatchEvent(new Event('resize'))));
  const stage = document.querySelector('.stage, .stage-wrap, .active-flow, .machine');
  if (stage) resize.observe(stage);
  window.addEventListener('pagehide', () => {
    resize.disconnect();
    tooltipObserver.disconnect();
  }, {
    once: true
  });
  refresh();
}
