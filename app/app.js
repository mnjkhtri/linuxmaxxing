(function() {
  'use strict';
  var views = {
    sched: {
      description: 'CFS runqueues · task lifetimes · CPU migration'
    },
    kapi: {
      description: 'tasks · canonical memory map · allocator mechanisms'
    },
    mm: {
      description: 'mm_struct · VMA topology · page tables'
    },
    io: {
      description: 'coherent DMA · MMIO submission · INTx · deferred work'
    },
    virt: {
      description: 'KVM_RUN · EPT state · MMU invalidation (toy-VMM)'
    },
    virtio: {
      description: 'device MMIO · virtual DMA · IOAPIC/LAPIC · guest ISR (toy MMIO device)'
    },
    'virt-virtio': {
      description: 'virtio-mmio · split virtqueue · shared-memory I/O · QueueNotify'
    },
    vtd: {
      description: 'VFIO DMA maps · IOVA → VT-d → HPA'
    }
  };
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.view-tab')),
    frame = document.getElementById('viewer-frame'),
    description = document.getElementById('view-description'),
    loader = document.getElementById('frame-loader');

  function activate(name, focus) {
    var tab = tabs.filter(function(t) {
      return t.dataset.view === name
    })[0] || tabs[0];
    tabs.forEach(function(item) {
      var on = item === tab;
      item.classList.toggle('active', on);
      item.setAttribute('aria-selected', String(on));
      item.tabIndex = on ? 0 : -1
    });
    description.textContent = views[tab.dataset.view].description;
    if (frame.dataset.view !== tab.dataset.view) {
      loader.classList.remove('hidden');
      var url = new URL(tab.dataset.src, location.href);
      url.searchParams.set('v', 'kapi-2');
      var base = document.documentElement.dataset.captureBase;
      if (base) url.searchParams.set('captureBase', new URL(base, location.href).href);
      frame.dataset.view = tab.dataset.view;
      frame.src = url.href
    };
    if (location.hash !== '#' + tab.dataset.view) history.replaceState(null, '', '#' + tab.dataset.view);
    if (focus) tab.focus()
  }
  tabs.forEach(function(tab, index) {
    tab.addEventListener('click', function() {
      activate(tab.dataset.view)
    });
    tab.addEventListener('keydown', function(e) {
      var next;
      if (e.key === 'ArrowRight') next = (index + 1) % tabs.length;
      if (e.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
      if (next != null) {
        e.preventDefault();
        activate(tabs[next].dataset.view, true)
      }
    })
  });
  window.addEventListener('message', function(event) {
    if (event.origin !== location.origin || event.source !== frame.contentWindow || event.data?.type !== 'capture-state') return;
    loader.classList.toggle('hidden', event.data.state !== 'loading');
    document.getElementById('view-state').textContent = event.data.state.toUpperCase()
  });
  frame.addEventListener('load', function() {
    loader.classList.add('hidden')
  });
  window.addEventListener('hashchange', function() {
    activate(location.hash.slice(1))
  });
  activate(location.hash.slice(1) || 'sched');
})();
