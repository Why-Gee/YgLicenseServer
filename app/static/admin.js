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
