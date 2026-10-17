/* ==========================================================================
   script.js - Security Log Triage Lab
   --------------------------------------------------------------------------
   This file is ONLY the user interface. All analysis lives in triage-core.js.

   SECURITY RULES FOR THIS FILE (please keep them true):
     1. NO network calls. No fetch calls, no XHR objects, no sockets, no beacons.
     2. NO storage. No localStorage, sessionStorage, cookies, IndexedDB.
        Settings and log data live in memory and vanish on refresh.
     3. NEVER insert uploaded text as HTML. Everything that came out of the CSV
        is written with textContent, or through el() below, which also uses
        textContent. There is no innerHTML anywhere in this file - search for it
        and you will not find it.
   ========================================================================== */
(function () {
  'use strict';

  const Core = window.TriageCore;
  if (!Core) {
    // Without the engine there is nothing to do. Say so plainly instead of
    // throwing a confusing error into the console.
    document.addEventListener('DOMContentLoaded', function () {
      const status = document.getElementById('status-region');
      if (status) {
        status.className = 'status status--error';
        status.textContent = 'triage-core.js could not be loaded, so the analysis engine is missing. Make sure all files were copied together.';
      }
    });
    return;
  }

  /* ------------------------------------------------------------------------
   * Tiny DOM helpers
   * ------------------------------------------------------------------------
   * el() creates an element and sets its text with textContent, which renders
   * any characters as plain text. That is what makes it impossible for a
   * malicious CSV cell such as <img src=x onerror=alert(1)> to run as code.
   */
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function $(id) { return document.getElementById(id); }

  function clear(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function setHidden(node, hidden) {
    if (!node) return;
    if (hidden) node.setAttribute('hidden', '');
    else node.removeAttribute('hidden');
  }

  function formatBytes(bytes) {
    if (typeof bytes !== 'number' || isNaN(bytes)) return 'unknown';
    if (bytes < 1024) return bytes + ' bytes';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  function plural(count, singular, pluralForm) {
    return count + ' ' + (count === 1 ? singular : (pluralForm || singular + 's'));
  }

  /* ------------------------------------------------------------------------
   * Application state
   * ------------------------------------------------------------------------
   * Everything here is deliberately in-memory only.
   */
  const state = {
    fileName: '',
    fileSize: 0,
    isDemo: false,
    result: null // the object returned by Core.parse()
  };

  /* Cached elements */
  const dom = {};

  function cacheDom() {
    [
      'file-input', 'drop-zone', 'file-meta', 'meta-filename', 'meta-filesize',
      'meta-delimiter', 'meta-encoding', 'btn-reset', 'status-region', 'error-region',
      'parse-panel', 'stat-events', 'stat-rows', 'stat-skipped', 'stat-columns',
      'stat-missing', 'stat-range', 'detected-columns', 'missing-columns', 'missing-note',
      'warning-region', 'warning-list', 'preview-body', 'demo-chip', 'demo-hint', 'demo-info',
      'recognition-body', 'unrecognised-note',
      'footer-version',
      'btn-sample-normal', 'btn-sample-guessing', 'btn-sample-privilege', 'btn-sample-mixed'
    ].forEach(function (id) {
      dom[id] = $(id);
    });
  }

  /* ------------------------------------------------------------------------
   * Status and error display
   * ------------------------------------------------------------------------
   * Two separate places on purpose:
   *   - #status-region is a polite live region: "Parsed 42 events". It must not
   *     interrupt a screen-reader user mid-sentence.
   *   - #error-region is an assertive alert: something the user must act on.
   */
  function setStatus(kind, message) {
    const node = dom['status-region'];
    if (!node) return;
    node.className = 'status' + (kind ? ' status--' + kind : '');
    node.textContent = message;
  }

  function showError(title, message, help) {
    const box = dom['error-region'];
    if (!box) return;
    clear(box);
    box.appendChild(el('p', 'error-box__title', title));
    if (message) box.appendChild(el('p', null, message));
    if (help) box.appendChild(el('p', 'error-box__help', help));
    setHidden(box, false);
  }

  function clearError() {
    const box = dom['error-region'];
    if (!box) return;
    clear(box);
    setHidden(box, true);
  }

  /* ------------------------------------------------------------------------
   * Reading a file the private way
   * ------------------------------------------------------------------------
   * FileReader is a browser API that hands the bytes of a local file straight to
   * this page. Nothing is sent anywhere: there is no upload endpoint, and the
   * Content-Security-Policy in index.html blocks outbound connections anyway.
   */
  function readFile(file) {
    if (!file) return;

    const name = String(file.name || '');
    const lower = name.toLowerCase();

    // Refuse the two formats that would only confuse a beginner.
    if (lower.endsWith('.evtx')) {
      showError('Raw .evtx files are not supported in this version.',
        'The file you chose is a Windows event log file (.evtx), which is a binary format.',
        'Use the export instructions above to save the events as CSV or tab-delimited text, then upload that instead.');
      setStatus('error', 'Nothing was analysed.');
      return;
    }
    if (lower.endsWith('.zip') || lower.endsWith('.gz')) {
      showError('Compressed files cannot be read directly.',
        'Please unzip the file first, then upload the CSV or text file inside it.', '');
      setStatus('error', 'Nothing was analysed.');
      return;
    }
    if (file.size === 0) {
      showError('That file is empty.', 'It contains no data at all.', 'Check that the export completed successfully.');
      setStatus('error', 'Nothing was analysed.');
      return;
    }
    if (file.size > Core.LIMITS.maxFileBytes) {
      showError('That file is too large to analyse safely in a browser tab.',
        'The file is ' + formatBytes(file.size) + ' and the limit is ' + formatBytes(Core.LIMITS.maxFileBytes) + '.',
        'Export a shorter time range or fewer Event IDs, then try again. This limit exists so a huge file cannot freeze your browser.');
      setStatus('error', 'Nothing was analysed.');
      return;
    }

    clearError();
    setStatus('busy', 'Reading ' + name + ' locally in your browser...');

    const reader = new FileReader();

    reader.onerror = function () {
      showError('The file could not be read.', 'The browser reported an error while reading it.', 'Try copying the file to your desktop and uploading it again.');
      setStatus('error', 'Nothing was analysed.');
    };

    reader.onload = function () {
      let result;
      try {
        // parseBytes handles BOM detection and UTF-16 decoding for us.
        result = Core.parseBytes(reader.result, { keepRaw: false });
      } catch (err) {
        // The engine is written not to throw, but if it ever does we still fail
        // safely and explain rather than dumping a stack trace on the user.
        showError('Something went wrong while reading that file.',
          'The tool could not process the file, and it has not analysed anything.',
          'This is usually a file that is not really a text export. Try re-exporting it and uploading again.');
        setStatus('error', 'Nothing was analysed.');
        return;
      }
      handleParseResult(result, { name: name, size: file.size, isDemo: false });
    };

    // readAsArrayBuffer (not readAsText) so we can detect UTF-16 files, which
    // PowerShell often produces.
    reader.readAsArrayBuffer(file);
  }

  /* ------------------------------------------------------------------------
   * Showing the result of a parse
   * ------------------------------------------------------------------------
   * Two paths: a hard failure (explain and stop) or success (report what was
   * understood, then hand over to the analysis stages that come next).
   */
  function handleParseResult(result, meta) {
    state.result = result;
    state.fileName = meta.name;
    state.fileSize = meta.size;
    state.isDemo = !!meta.isDemo;

    // The "Demo Data" label must be visible whenever the data is not the user's
    // own. It is shown here rather than only in the demo bar, so it stays on
    // screen while the user scrolls through the results.
    setHidden(dom['demo-chip'], !state.isDemo);
    if (meta.dataset) showDemoInfo(meta.dataset);
    else hideDemoInfo();

    if (!result || !result.ok) {
      renderParseFailure(result);
      return;
    }

    renderFileMeta(result);
    renderParseSummary(result);
    renderRecognition(result);
    renderPreview(result);

    const count = result.stats ? result.stats.events : 0;
    const warningCount = result.warnings.length;
    setStatus(warningCount ? 'warn' : 'ok',
      'Parsed ' + plural(count, 'event') + ' from ' + meta.name
      + (state.isDemo ? ' (Demo Data - fictional, built into the app)' : '')
      + ' locally in your browser.'
      + (warningCount ? ' ' + plural(warningCount, 'note') + ' about this file - see below.' : ''));
  }

  function renderParseFailure(result) {
    setHidden(dom['parse-panel'], true);
    setHidden(dom['file-meta'], true);

    const error = result && result.errors && result.errors[0]
      ? result.errors[0]
      : { message: 'The file could not be read.', help: '' };

    showError('That file could not be analysed.', error.message, error.help);
    setStatus('error', 'Nothing was analysed.');

    // When the problem is a missing Event ID column, showing the columns we DID
    // find is far more useful than a generic error.
    if (result && result.headers && result.headers.length) {
      const box = dom['error-region'];
      const details = el('details', 'howto');
      details.appendChild(el('summary', 'howto__summary', 'Columns found in your file (' + result.headers.length + ')'));
      const list = el('ul', 'col-list');
      result.headers.forEach(function (header) {
        list.appendChild(el('li', null, header === '' ? '(blank header)' : header));
      });
      details.appendChild(list);
      if (box) box.appendChild(details);
    }
  }

  /* ------------------------------------------------------------------------
   * File metadata strip
   * ------------------------------------------------------------------------ */
  function renderFileMeta(result) {
    if (dom['meta-filename']) dom['meta-filename'].textContent = state.fileName || '(demo data)';
    if (dom['meta-filesize']) dom['meta-filesize'].textContent = state.fileSize ? formatBytes(state.fileSize) : '(built in)';
    if (dom['meta-delimiter']) {
      dom['meta-delimiter'].textContent = result.stats
        ? result.stats.delimiterLabel + ' separated' + (result.stats.delimiterConfident ? '' : ' (assumed)')
        : 'unknown';
    }
    if (dom['meta-encoding']) {
      dom['meta-encoding'].textContent = (result.stats && result.stats.encoding) || 'utf-8';
    }
    setHidden(dom['file-meta'], false);
  }

  /* ------------------------------------------------------------------------
   * Parse-check summary: statistics, column report and notes
   * ------------------------------------------------------------------------ */
  function renderParseSummary(result) {
    const stats = result.stats || {};
    setHidden(dom['parse-panel'], false);

    if (dom['stat-events']) dom['stat-events'].textContent = String(stats.events || 0);
    if (dom['stat-rows']) dom['stat-rows'].textContent = String(stats.dataRows || 0);
    if (dom['stat-skipped']) dom['stat-skipped'].textContent = String(stats.skipped || 0);
    if (dom['stat-columns']) dom['stat-columns'].textContent = String(stats.columnsFound || 0);
    if (dom['stat-missing']) dom['stat-missing'].textContent = String(stats.columnsMissing || 0);

    if (dom['stat-range']) {
      if (stats.timeRange) {
        const start = Core.toIsoString(stats.timeRange.startMs);
        const end = Core.toIsoString(stats.timeRange.endMs);
        dom['stat-range'].textContent = start.slice(0, 10) + ' to ' + end.slice(0, 10);
        dom['stat-range'].setAttribute('title', start + '  to  ' + end);
      } else {
        dom['stat-range'].textContent = 'not available';
        dom['stat-range'].setAttribute('title', 'No readable timestamps were found in this file.');
      }
    }

    /* Which columns we understood */
    const detected = dom['detected-columns'];
    clear(detected);
    Core.CANONICAL_FIELDS.forEach(function (field) {
      const column = result.mapping[field];
      if (!column) return;
      const item = el('li');
      item.appendChild(el('span', 'col-list__name', Core.FIELD_LABELS[field] || field));
      item.appendChild(el('span', 'col-list__value', column.header));
      detected.appendChild(item);
    });
    if (!detected.childNodes.length) {
      detected.appendChild(el('li', null, 'No recognised columns.'));
    }

    /* Which columns we did not find */
    const missing = dom['missing-columns'];
    clear(missing);
    result.missing.forEach(function (field) {
      const item = el('li');
      item.appendChild(el('span', 'col-list__name', Core.FIELD_LABELS[field] || field));
      item.appendChild(el('span', 'col-list__value', 'not found'));
      missing.appendChild(item);
    });
    if (!result.missing.length) {
      missing.appendChild(el('li', null, 'Nothing important was missing.'));
    }

    const note = dom['missing-note'];
    if (note) {
      if (result.ignoredColumns.length) {
        note.textContent = 'Ignored column(s) that the tool did not need: ' + result.ignoredColumns.join(', ') + '.';
        setHidden(note, false);
      } else {
        setHidden(note, true);
      }
    }

    /* Notes / warnings */
    const warnList = dom['warning-list'];
    clear(warnList);
    removeSkippedDetails();
    if (result.warnings.length) {
      result.warnings.forEach(function (warning) {
        warnList.appendChild(el('li', null, warning.message));
      });
      setHidden(dom['warning-region'], false);
    } else {
      setHidden(dom['warning-region'], true);
    }

    /* Skipped rows, listed so a beginner can see exactly which lines were a problem */
    if (result.skipped.length) {
      const details = el('details', 'howto');
      details.appendChild(el('summary', 'howto__summary', 'Rows that were skipped (' + result.skipped.length + ')'));
      const list = el('ul', 'col-list');
      result.skipped.slice(0, 10).forEach(function (skip) {
        const item = el('li');
        item.appendChild(el('span', 'col-list__name', 'Line ' + skip.line));
        item.appendChild(el('span', 'col-list__value', skip.reason));
        list.appendChild(item);
      });
      details.appendChild(list);
      dom['warning-region'].appendChild(details);
    }
  }

  /** Collapses whitespace so a multi-line event message stays readable in a table cell. */
  function shorten(text, max) {
    const flat = String(text == null ? '' : text).replace(/\s+/g, ' ').trim();
    return flat.length > max ? flat.slice(0, max) + '...' : flat;
  }

  /** Removes the "rows that were skipped" block from a previous file. */
  function removeSkippedDetails() {
    const region = dom['warning-region'];
    if (!region) return;
    Array.prototype.slice.call(region.querySelectorAll('details.howto')).forEach(function (node) {
      node.parentNode.removeChild(node);
    });
  }

/* ------------------------------------------------------------------------
   * Event ID recognition table
   * ------------------------------------------------------------------------
   * Shows which Windows events the tool understood, what each one means, and the
   * priority it carries on its own. The "on its own" wording is deliberate: a
   * 4625 here is Low, and it only becomes interesting once several are seen
   * together. That distinction is the point of the whole project.
   */
  function severityClass(severity) {
    switch (severity) {
      case 'High': return 'badge--high';
      case 'Medium': return 'badge--medium';
      case 'Low': return 'badge--low';
      default: return 'badge--info';
    }
  }

  function renderRecognition(result) {
    const body = dom['recognition-body'];
    if (!body) return;
    clear(body);

    const stats = result.stats || {};
    const list = stats.recognisedEventIds || [];

    list.forEach(function (entry) {
      const tr = el('tr');
      tr.appendChild(el('td', 'cell-mono', String(entry.eventId)));
      tr.appendChild(el('td', null, entry.title));
      tr.appendChild(el('td', null, entry.category));
      tr.appendChild(el('td', 'cell-mono', String(entry.count)));

      const severityCell = el('td');
      severityCell.appendChild(el('span', 'badge ' + severityClass(entry.baseSeverity), entry.baseSeverity));
      tr.appendChild(severityCell);

      body.appendChild(tr);
    });

    if (!list.length) {
      const tr = el('tr');
      const td = el('td', 'table-empty', 'None of the Windows Event IDs this version explains were found in this file.');
      td.colSpan = 5;
      tr.appendChild(td);
      body.appendChild(tr);
    }

    /* Unrecognised IDs are counted and shown, never silently dropped. */
    const note = dom['unrecognised-note'];
    if (!note) return;
    const unknown = stats.unrecognisedEventIds || {};
    const keys = Object.keys(unknown);
    if (keys.length) {
      const summary = keys.map(function (id) { return id + ' (x' + unknown[id] + ')'; }).join(', ');
      note.textContent = plural(stats.unrecognisedEvents, 'event') + ' used '
        + plural(keys.length, 'Event ID') + ' that this version does not explain yet: ' + summary
        + '. They are counted in the totals, but not treated as suspicious just because they are unfamiliar.';
      setHidden(note, false);
    } else {
      setHidden(note, true);
    }
  }
  /* ------------------------------------------------------------------------
   * Preview table: proof that the file was read the way the student expects
   * ------------------------------------------------------------------------
   * Every value is written with textContent via el(), so a CSV cell containing
   * HTML or JavaScript is displayed as harmless text, never executed.
   */
  function renderPreview(result) {
    const body = dom['preview-body'];
    if (!body) return;
    clear(body);

    const rows = result.events.slice(0, Core.LIMITS.maxPreviewRows);

    rows.forEach(function (event) {
      const tr = el('tr');
      tr.appendChild(el('td', 'cell-mono', event.line));
      tr.appendChild(el('td', 'cell-mono', event.timestamp && event.timestamp.raw ? event.timestamp.raw : '-'));
      tr.appendChild(el('td', 'cell-mono', String(event.eventId)));
      tr.appendChild(el('td', null, event.rawLevel || event.rawLevelText || '-'));
      tr.appendChild(el('td', null, event.account || '(not available)'));
      tr.appendChild(el('td', null, event.computer || '-'));
      tr.appendChild(el('td', 'cell-message', shorten(event.message, 160) || '-'));
      body.appendChild(tr);
    });

    if (!rows.length) {
      const tr = el('tr');
      const td = el('td', 'table-empty', 'No data rows were found in this file.');
      td.colSpan = 7;
      tr.appendChild(td);
      body.appendChild(tr);
    }
  }

  /* ------------------------------------------------------------------------
   * Clearing everything
   * ------------------------------------------------------------------------
   * Because nothing is stored, "clearing" really does mean the data is gone:
   * we drop the reference and let the browser reclaim the memory.
   */
  function resetAll() {
    state.result = null;
    state.fileName = '';
    state.fileSize = 0;
    state.isDemo = false;

    if (dom['file-input']) dom['file-input'].value = '';
    setHidden(dom['parse-panel'], true);
    setHidden(dom['file-meta'], true);
    setHidden(dom['warning-region'], true);
    clearError();
    clear(dom['preview-body']);
    clear(dom['detected-columns']);
    clear(dom['missing-columns']);
    clear(dom['warning-list']);
    if (dom['missing-note']) setHidden(dom['missing-note'], true);
    // Clear the demo labelling too, so the page never claims stale demo data.
    setHidden(dom['demo-chip'], true);
    hideDemoInfo();
    setStatus(null, 'No file loaded yet. Everything stays in your browser.');
  }

  /* ------------------------------------------------------------------------
   * Wiring up the upload controls
   * ------------------------------------------------------------------------
   * The file input is the accessible control (it can be reached with the Tab key
   * and opened with Enter or Space). Drag and drop is a convenience on top of
   * it, never the only way in.
   */
  function bindUpload() {
    const input = dom['file-input'];
    const zone = dom['drop-zone'];

    if (input) {
      input.addEventListener('change', function () {
        const file = input.files && input.files[0];
        if (file) readFile(file);
      });
    }

    if (zone) {
      ['dragenter', 'dragover'].forEach(function (type) {
        zone.addEventListener(type, function (event) {
          event.preventDefault();
          zone.classList.add('is-dragover');
        });
      });

      ['dragleave', 'dragend'].forEach(function (type) {
        zone.addEventListener(type, function () {
          zone.classList.remove('is-dragover');
        });
      });

      zone.addEventListener('drop', function (event) {
        event.preventDefault();
        zone.classList.remove('is-dragover');
        const transfer = event.dataTransfer;
        const file = transfer && transfer.files && transfer.files[0];
        if (file) {
          readFile(file);
        } else {
          setStatus('warn', 'That drop did not contain a file. Try dragging a single CSV file onto the box.');
        }
      });
    }

    // Dropping a file anywhere else in the page would normally make the browser
    // navigate away from the tool and lose the loaded data. Stop that.
    window.addEventListener('dragover', function (event) { event.preventDefault(); });
    window.addEventListener('drop', function (event) { event.preventDefault(); });
  }

  /* ------------------------------------------------------------------------
   * Demo datasets ("test mode")
   * ------------------------------------------------------------------------
   * The four datasets live in samples/sample-data.js, which index.html loads as
   * an ordinary script. That is precisely why the demo buttons work when the
   * page is opened by double-clicking index.html: nothing has to be fetched,
   * because browsers block a file:// page from reading other local files.
   *
   * The .csv files in samples/ contain exactly the same text, for students who
   * want to practise the real upload path. A test fails the build if the two
   * ever disagree.
   */
  function demoData() {
    if (typeof window !== 'undefined' && window.TRIAGE_SAMPLE_DATA) return window.TRIAGE_SAMPLE_DATA;
    return null;
  }

  function loadDataset(key) {
    const data = demoData();
    if (!data || !data[key]) {
      showError('That demo dataset is not available.',
        'The file samples/sample-data.js did not load, so the built-in demo data is missing.',
        'Check that sample-data.js is in the samples folder next to index.html, then refresh this page.');
      setStatus('error', 'Nothing was analysed.');
      return;
    }

    const dataset = data[key];
    clearError();
    setStatus('busy', 'Loading the demo dataset "' + dataset.label + '" in your browser...');

    let result;
    try {
      result = Core.parse(dataset.csv, { keepRaw: false });
    } catch (err) {
      showError('The demo dataset could not be read.',
        'This would be a bug in the tool rather than something you did.',
        'Please report it, with the dataset name: ' + dataset.label);
      setStatus('error', 'Nothing was analysed.');
      return;
    }

    // Clear the file picker, so uploading the matching .csv file afterwards
    // still triggers a change event.
    if (dom['file-input']) dom['file-input'].value = '';

    handleParseResult(result, {
      name: dataset.file,
      size: 0,
      isDemo: true,
      dataset: dataset
    });

    // Move the user to the results without stealing focus from the button.
    if (dom['parse-panel'] && typeof dom['parse-panel'].scrollIntoView === 'function') {
      dom['parse-panel'].scrollIntoView({ block: 'start' });
    }
  }

  function showDemoInfo(dataset) {
    const box = dom['demo-info'];
    if (!box) return;
    clear(box);

    const headline = el('p', 'demo-info__line');
    headline.appendChild(el('strong', null, 'Demo Data: '));
    headline.appendChild(el('span', null, dataset.label));
    box.appendChild(headline);

    box.appendChild(el('p', 'demo-info__line', dataset.summary));
    box.appendChild(el('p', 'demo-info__line demo-info__expect',
      'What this scenario is designed to show: ' + dataset.expectation));

    setHidden(box, false);
  }

  function hideDemoInfo() {
    const box = dom['demo-info'];
    if (!box) return;
    clear(box);
    setHidden(box, true);
  }

  /**
   * Turns the four demo buttons on. They are disabled in the HTML so that the
   * page never offers a button that does nothing if sample-data.js is missing.
   */
  function bindDemoButtons() {
    const data = demoData();
    if (!data) return 0;

    let wired = 0;
    Object.keys(data).forEach(function (key) {
      const dataset = data[key];
      const button = dataset && dataset.buttonId ? $(dataset.buttonId) : null;
      if (!button) return;
      button.disabled = false;
      button.removeAttribute('title');
      button.addEventListener('click', function () { loadDataset(key); });
      wired++;
    });
    return wired;
  }

  function init() {
    cacheDom();
    bindUpload();

    if (dom['btn-reset']) dom['btn-reset'].addEventListener('click', resetAll);

    // The version shown in the footer is taken from the engine, so the two can
    // never disagree.
    if (dom['footer-version']) {
      dom['footer-version'].textContent = 'Version ' + Core.VERSION
        + ' - educational SOC triage tool. Findings are a reason to investigate, not proof.';
    }

    // Turn on the demo buttons. If samples/sample-data.js is missing they stay
    // disabled and the note below says why, instead of failing silently.
    const wired = bindDemoButtons();
    if (dom['demo-hint']) {
      dom['demo-hint'].textContent = wired
        ? 'These four datasets are fictional and safe to use in presentations. Loading one changes nothing on your computer.'
        : 'The demo datasets could not be loaded, so these buttons are unavailable. Check that samples/sample-data.js exists next to index.html.';
    }

    setStatus(null, 'No file loaded yet. Nothing you load here leaves your browser.');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();




