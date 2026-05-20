// Admin UI shared JS. Loaded once from base.html; per-page scripts stay
// inline so they can bind to template data without an extra fetch.

// Promise-based modal confirm. Replaces window.confirm for our destructive
// flows. Esc / clicking the backdrop = cancel; Enter = confirm.
window.confirmModal = function (opts) {
  return new Promise(function (resolve) {
    var ov = document.getElementById('confirm-modal');
    document.getElementById('confirm-step').textContent = opts.step || '';
    document.getElementById('confirm-title').textContent = opts.title || 'Confirm';
    document.getElementById('confirm-body').textContent = opts.body || '';
    var ok = document.getElementById('confirm-ok');
    var cancel = document.getElementById('confirm-cancel');
    ok.textContent = opts.confirmLabel || 'Continue';
    ov.style.display = '';
    function done(result) {
      ov.style.display = 'none';
      ok.removeEventListener('click', onOk);
      cancel.removeEventListener('click', onCancel);
      ov.removeEventListener('click', onBackdrop);
      document.removeEventListener('keydown', onKey);
      resolve(result);
    }
    function onOk()     { done(true); }
    function onCancel() { done(false); }
    function onBackdrop(e) { if (e.target === ov) done(false); }
    function onKey(e) {
      if (e.key === 'Escape') done(false);
      else if (e.key === 'Enter') { e.preventDefault(); done(true); }
    }
    ok.addEventListener('click', onOk);
    cancel.addEventListener('click', onCancel);
    ov.addEventListener('click', onBackdrop);
    document.addEventListener('keydown', onKey);
    ok.focus();
  });
};

// Generic single-step confirm. Any <button data-confirm-title="..."
// data-confirm-body="..." [data-confirm-label="..."]> shows the modal and,
// on OK, re-fires the click with a flag that bypasses this handler so
// native form-submit / formaction takes over. Use for revoke / disable /
// enable / any future single-action confirm.
document.querySelectorAll('button[data-confirm-title]').forEach(function (btn) {
  btn.addEventListener('click', async function (e) {
    if (btn.dataset.confirmed === '1') return;
    e.preventDefault();
    var ok = await window.confirmModal({
      title: btn.dataset.confirmTitle,
      body: btn.dataset.confirmBody || '',
      confirmLabel: btn.dataset.confirmLabel || 'Continue',
    });
    if (!ok) return;
    btn.dataset.confirmed = '1';
    btn.click();
  });
});

// Show a spinner on a submit button while its form's POST is in flight.
// Replaces the button's inner content with a spinner and disables it so
// double-clicks during the round-trip can't fire a second request. The
// form has already collected its data by the time the 'submit' event
// fires, so disabling here doesn't block the in-flight request. No-JS
// fallback: if this script doesn't run, the form still submits normally.
window.showButtonBusy = function (btn) {
  if (!btn || btn.dataset.busy === '1') return;
  btn.dataset.busy = '1';
  btn.setAttribute('aria-busy', 'true');
  // Lock dimensions so the spinner doesn't collapse the button.
  var w = btn.offsetWidth, h = btn.offsetHeight;
  if (w) btn.style.minWidth = w + 'px';
  if (h) btn.style.minHeight = h + 'px';
  if (btn.classList.contains('toggle-switch')) {
    btn.classList.add('loading');
    btn.innerHTML = '<span class="btn-spinner" aria-hidden="true"></span>';
  } else {
    var sm = btn.classList.contains('btn-icon') ? ' sm' : '';
    btn.innerHTML = '<span class="btn-spinner' + sm + '" aria-hidden="true"></span>';
  }
  // Disable AFTER the current event tick so the browser has already
  // packaged the submitter into the outgoing request.
  setTimeout(function () { btn.disabled = true; }, 0);
};

// Catch every native form submit and spinner-ify the triggering button.
// e.submitter is the button that initiated the submit (works for buttons
// with formaction too). form.submit() does NOT fire this event, so
// handlers that call form.submit() (bulk-form below) call showButtonBusy
// themselves.
document.addEventListener('submit', function (e) {
  if (e.submitter) window.showButtonBusy(e.submitter);
}, true);

// Generic copy-to-clipboard. Any <button data-copy-from="#selector"> grabs
// the textContent of the matched element and writes it to the clipboard.
// Briefly swaps the button label to confirm. Falls back to a textarea +
// execCommand path for browsers that block clipboard API on http://.
document.querySelectorAll('[data-copy-from]').forEach(function (btn) {
  btn.addEventListener('click', async function () {
    var src = document.querySelector(btn.dataset.copyFrom);
    if (!src) return;
    var text = src.textContent.trim();
    var ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (e) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (e2) { ok = false; }
      document.body.removeChild(ta);
    }
    if (!ok) { alert('Could not copy. Select the text manually.'); return; }
    var orig = btn.innerHTML;
    btn.innerHTML = '✓ Copied';
    btn.disabled = true;
    setTimeout(function () { btn.innerHTML = orig; btn.disabled = false; }, 1500);
  });
});

// Click-to-sort tables. Opt in with <table data-sortable>; mark sortable
// headers with <th data-sort-key="..."> (+ optional data-sort-type=
// "text"|"number"|"date"). First click on a column = ascending; clicking
// the active column flips direction. Cell value is data-sort-value if
// present, else textContent (so badges/spans sort by their text).
(function () {
  function cellValue(row, idx, type) {
    var cell = row.children[idx];
    if (!cell) return type === 'number' ? -Infinity : '';
    var v = cell.getAttribute('data-sort-value');
    if (v === null) v = cell.textContent;
    v = (v || '').trim();
    if (type === 'number') {
      var n = parseFloat(v);
      return isNaN(n) ? -Infinity : n;
    }
    return v.toLowerCase();
  }
  function sortRows(table, th, dir) {
    var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
    var type = th.dataset.sortType || 'text';
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var rows = Array.prototype.slice.call(tbody.rows);
    var mul = dir === 'ascending' ? 1 : -1;
    rows.sort(function (a, b) {
      var va = cellValue(a, idx, type);
      var vb = cellValue(b, idx, type);
      if (va < vb) return -1 * mul;
      if (va > vb) return  1 * mul;
      return 0;
    });
    rows.forEach(function (r) { tbody.appendChild(r); });
  }
  document.querySelectorAll('table[data-sortable]').forEach(function (table) {
    var headers = table.querySelectorAll('thead th[data-sort-key]');
    headers.forEach(function (th) {
      th.addEventListener('click', function () {
        var dir = th.getAttribute('aria-sort') === 'ascending' ? 'descending' : 'ascending';
        headers.forEach(function (h) { h.removeAttribute('aria-sort'); });
        th.setAttribute('aria-sort', dir);
        sortRows(table, th, dir);
      });
    });
  });
})();

// Auto-wires any <form class="bulk-form" data-name="..."> so its bulk-delete
// button is hidden until at least one row is checked. Click runs a two-stage
// modal confirm using data-confirm1-* and data-confirm2-* on the form.
(function () {
  document.querySelectorAll('form.bulk-form').forEach(function (form) {
    var name = form.dataset.name;
    var btn = form.querySelector('[data-bulk-btn]');
    var counter = form.querySelector('[data-bulk-count]');
    var selectAll = form.querySelector('input[type=checkbox][data-select-all]');
    if (!btn || !counter) return;
    function update() {
      var n = form.querySelectorAll('input[name="' + name + '"]:checked').length;
      btn.style.display = n ? '' : 'none';
      counter.textContent = n;
    }
    form.addEventListener('change', function (e) {
      if (e.target && (e.target.name === name || e.target === selectAll)) update();
    });
    if (selectAll) {
      selectAll.addEventListener('click', function () {
        form.querySelectorAll('input[name="' + name + '"]').forEach(function (c) {
          c.checked = selectAll.checked;
        });
        update();
      });
    }
    btn.addEventListener('click', async function (e) {
      if (form.dataset.confirmed === '1') return;  // re-entry after modal -> let submit through
      e.preventDefault();
      var n = form.querySelectorAll('input[name="' + name + '"]:checked').length;
      if (n === 0) return;
      var fmt = function (s) { return (s || '').replace('{n}', n); };
      var ok1 = await window.confirmModal({
        step: 'step 1 of 2',
        title: fmt(form.dataset.confirm1Title),
        body: fmt(form.dataset.confirm1Body),
        confirmLabel: 'Continue',
      });
      if (!ok1) return;
      var ok2 = await window.confirmModal({
        step: 'step 2 of 2 — final confirmation',
        title: fmt(form.dataset.confirm2Title),
        body: fmt(form.dataset.confirm2Body),
        confirmLabel: fmt(form.dataset.confirm2Label) || 'Delete',
      });
      if (!ok2) return;
      form.dataset.confirmed = '1';
      // form.submit() bypasses the 'submit' event, so spinner-ify manually.
      window.showButtonBusy(btn);
      form.submit();
    });
    update();
  });
})();

// Client-side row filter for tables with lots of rows. Opt in by adding
// `data-filter-target="#sel"` to an <input>; the selector points at the
// table to filter (or a wrapper containing one). Filters by case-insensitive
// substring against the row's full textContent. Empty input = show all.
//
// Used on customers, licenses (per product), events. Works alongside the
// existing data-sortable behavior on the same table.
(function () {
  function applyFilter(input) {
    var sel = input.getAttribute('data-filter-target');
    if (!sel) return;
    var target = document.querySelector(sel);
    if (!target) return;
    var table = target.tagName === 'TABLE' ? target : target.querySelector('table');
    if (!table || !table.tBodies[0]) return;
    var q = (input.value || '').trim().toLowerCase();
    var rows = table.tBodies[0].rows;
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      if (!q || r.textContent.toLowerCase().indexOf(q) !== -1) {
        r.style.display = '';
        shown++;
      } else {
        r.style.display = 'none';
      }
    }
    var counter = document.querySelector(input.getAttribute('data-filter-counter') || '');
    if (counter) counter.textContent = q ? (shown + ' shown') : '';
  }
  document.querySelectorAll('input[data-filter-target]').forEach(function (input) {
    input.addEventListener('input', function () { applyFilter(input); });
    // Pre-apply in case the input has a value from the URL (deep-link).
    if (input.value) applyFilter(input);
  });
})();

// Sidebar: collapse/expand toggle (persisted via localStorage), active-link
// highlight by URL prefix, mobile overlay open/close. The pre-paint script
// in base.html already applied data-collapsed; here we wire the controls
// and the resize behavior.
(function () {
  var body = document.body;
  if (body.getAttribute('data-has-sidebar') !== '1') return;  // not logged in

  // ---- active link --------------------------------------------------------
  // Match the most-specific data-nav-key against the current path. We anchor
  // on path prefix so /admin/products/<slug> still highlights "Products".
  var path = window.location.pathname.replace(/\/+$/, '') || '/admin';
  var routes = {
    'dashboard':           function (p) { return p === '/admin'; },
    'products':            function (p) { return p === '/admin/products' || p.indexOf('/admin/products/') === 0; },
    'customers':           function (p) { return p === '/admin/customers' || p.indexOf('/admin/customers/') === 0; },
    'events':              function (p) { return p.indexOf('/admin/events') === 0; },
    'webhook-deliveries':  function (p) { return p.indexOf('/admin/webhook-deliveries') === 0; },
  };
  document.querySelectorAll('.sidebar-nav a[data-nav-key]').forEach(function (a) {
    var key = a.getAttribute('data-nav-key');
    if (routes[key] && routes[key](path)) a.classList.add('active');
  });

  // ---- collapse toggle ---------------------------------------------------
  var toggle = document.getElementById('sidebar-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var collapsed = body.getAttribute('data-collapsed') === '1';
      if (collapsed) {
        body.removeAttribute('data-collapsed');
        try { localStorage.setItem('yg_sidebar_collapsed', '0'); } catch (e) {}
        toggle.setAttribute('aria-label', 'Collapse sidebar');
      } else {
        body.setAttribute('data-collapsed', '1');
        try { localStorage.setItem('yg_sidebar_collapsed', '1'); } catch (e) {}
        toggle.setAttribute('aria-label', 'Expand sidebar');
      }
    });
  }

  // Keyboard shortcut: Ctrl/Cmd + B toggles the sidebar, VS Code style.
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key && e.key.toLowerCase() === 'b') {
      // Don't hijack the shortcut while the user is typing in a form field.
      var t = e.target;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
      e.preventDefault();
      if (toggle) toggle.click();
    }
  });

  // ---- mobile overlay ----------------------------------------------------
  var mobileToggle = document.getElementById('mobile-toggle');
  var mobileOverlay = document.getElementById('mobile-overlay');
  function closeMobile() { body.removeAttribute('data-mobile-open'); }
  if (mobileToggle) {
    mobileToggle.addEventListener('click', function () {
      body.setAttribute('data-mobile-open', '1');
    });
  }
  if (mobileOverlay) {
    mobileOverlay.addEventListener('click', closeMobile);
  }
  // Tapping any nav link on mobile dismisses the overlay (the link still
  // navigates -- this just stops the half-open state from lingering during
  // the page transition).
  document.querySelectorAll('.sidebar-nav a').forEach(function (a) {
    a.addEventListener('click', closeMobile);
  });
  // ESC closes mobile drawer.
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeMobile();
  });
})();
