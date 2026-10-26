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
    result: null,    // the object returned by Core.parse()
    settings: null,  // analysis settings, session only
    analysis: null,  // the object returned by Core.analyse()
    filters: { eventId: '', account: '', severity: '', sourceIp: '', category: '', search: '' }
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
      'findings-panel', 'findings-summary', 'findings-list', 'analysis-notes', 'analysis-notes-list',
      'dashboard-panel', 'dash-total', 'dash-success', 'dash-failed', 'dash-created', 'dash-priv',
      'dash-cleared', 'dash-process', 'dash-investigate', 'dash-top-accounts', 'dash-top-failures',
      'dash-top-ids', 'dash-severity', 'dash-timeline-body', 'dash-timeline-note',
      'dash-activity', 'dash-activity-range', 'dash-activity-note', 'dash-scope',
      'workspace-empty', 'events-empty', 'details-card',
      'btn-open-events', 'btn-privacy-jump', 'btn-goto-dashboard',
      'tab-dashboard', 'tab-events', 'tab-learn', 'tab-export', 'tab-privacy',
      'panel-dashboard', 'panel-events', 'panel-learn', 'panel-export', 'panel-privacy',
      'admin-panel', 'admin-summary', 'admin-explanation', 'admin-body',
      'explorer-panel', 'explorer-heading', 'filter-eventid', 'filter-account', 'filter-severity', 'filter-ip',
      'filter-category', 'filter-search', 'btn-clear-filters', 'filter-count', 'events-body',
      'events-limit-note',
      'settings-panel', 'setting-threshold', 'setting-window', 'setting-use-window', 'window-status',
      'btn-apply-settings', 'btn-reset-settings',
      'footer-version',
      'btn-sample-normal', 'btn-sample-guessing', 'btn-sample-privilege', 'btn-sample-mixed'
    ].forEach(function (id) {
      dom[id] = $(id);
    });
  }

  /* ------------------------------------------------------------------------
   * Tab navigation
   * ------------------------------------------------------------------------
   * A small ARIA tablist implementation: click to switch, arrow keys / Home / End
   * to move between tabs, and only the active tab is in the tab order. No routing
   * and no history API - the state of a demo should not depend on the URL.
   */
  const TAB_IDS = ['tab-dashboard', 'tab-events', 'tab-learn', 'tab-export', 'tab-privacy'];
  const PANEL_IDS = ['panel-dashboard', 'panel-events', 'panel-learn', 'panel-export', 'panel-privacy'];

  function selectTab(tabId) {
    if (TAB_IDS.indexOf(tabId) === -1) return;

    TAB_IDS.forEach(function (id) {
      const tab = $(id);
      if (!tab) return;
      const selected = id === tabId;
      tab.classList.toggle('is-active', selected);
      tab.setAttribute('aria-selected', selected ? 'true' : 'false');
      tab.tabIndex = selected ? 0 : -1;
    });

    PANEL_IDS.forEach(function (id) {
      const panel = $(id);
      if (!panel) return;
      panel.hidden = id !== tabId.replace('tab-', 'panel-');
    });
  }

  function initTabs() {
    const tabs = TAB_IDS.map(function (id) { return $(id); }).filter(Boolean);
    if (!tabs.length) return;

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () { selectTab(tab.id); });

      tab.addEventListener('keydown', function (event) {
        const index = tabs.indexOf(tab);
        let next = -1;

        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = tabs.length - 1;
        else return;

        event.preventDefault();
        selectTab(tabs[next].id);
        tabs[next].focus();
      });
    });

    selectTab('tab-dashboard');
  }

  /* ------------------------------------------------------------------------
   * Empty states
   * ------------------------------------------------------------------------
   * Before any data is loaded the dashboard shows an invitation, not fake
   * numbers. Opening the Events tab before loading anything explains how to get
   * there. Both are switched off as soon as real data exists.
   */
  function setWorkspaceEmpty(isEmpty) {
    ['workspace-empty', 'events-empty'].forEach(function (id) {
      const node = dom[id];
      if (!node) return;
      if (isEmpty) node.removeAttribute('hidden');
      else node.setAttribute('hidden', '');
    });

    /* File details are meaningless without a file, so the collapsible panel is
       only offered once something has been parsed. */
    if (dom['details-card']) {
      if (isEmpty) dom['details-card'].setAttribute('hidden', '');
      else dom['details-card'].removeAttribute('hidden');
    }
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

    // Real data is present, so the invitation empty state goes away.
    setWorkspaceEmpty(false);

    // Rebuild the filter choices for the new file, and start with no filters.
    state.filters = { eventId: '', account: '', severity: '', sourceIp: '', category: '', search: '' };
    populateFilterOptions(result);

    // Run the detection rules on the freshly parsed data.
    runAnalysis();

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
    setWorkspaceEmpty(true);

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
   * Findings
   * ------------------------------------------------------------------------
   * Each finding is rendered as a card containing exactly the sections the
   * specification asks for: what was observed, why it matters, what could
   * explain it innocently, what to investigate next, and how the priority score
   * was reached. Every value is written with textContent, so nothing that came
   * out of the uploaded file can be interpreted as HTML.
   */
  function severitySuffix(severity) {
    switch (severity) {
      case 'High': return 'high';
      case 'Medium': return 'medium';
      case 'Low': return 'low';
      default: return 'info';
    }
  }

  /* ------------------------------------------------------------------------
   * Sequence and comparison rendering
   * ------------------------------------------------------------------------
   * Rule 2 produces a chronological sequence, and the most useful question about
   * it is whether the successful sign-in came from the same place as the
   * failures. Both are shown as plain lists so a beginner can read them line by
   * line rather than having to parse a sentence.
   */
  function comparisonBadge(status) {
    switch (status) {
      case 'match': return 'badge--low';
      case 'differ': return 'badge--medium';
      case 'partial': return 'badge--medium';
      default: return 'badge--info';
    }
  }

  function comparisonStatusText(status) {
    switch (status) {
      case 'match': return 'Same';
      case 'differ': return 'Different';
      case 'partial': return 'Partly matches';
      default: return 'Cannot be determined';
    }
  }

  function sequenceSection(finding) {
    const section = el('div', 'finding__section');
    section.appendChild(el('h4', null, 'Sequence of events'));
    section.appendChild(el('p', 'sequence__chain', finding.sequenceText));

    const list = el('ol', 'sequence');
    const shown = finding.sequence.slice(0, 12);
    shown.forEach(function (step) {
      const successful = step.kind === 'successful sign-in';
      const item = el('li', 'sequence__step sequence__step--' + (successful ? 'success' : 'failure'));
      item.appendChild(el('span', 'sequence__time', step.iso || 'no timestamp'));
      item.appendChild(el('span', 'sequence__what',
        step.eventId + ' \u2013 ' + step.kind + (step.sourceIp ? ' from ' + step.sourceIp : '')));
      list.appendChild(item);
    });
    section.appendChild(list);

    if (finding.sequence.length > shown.length) {
      section.appendChild(el('p', 'sequence__more',
        '...and ' + plural(finding.sequence.length - shown.length, 'further event') + ' in this sequence.'));
    }
    return section;
  }

  function comparisonSection(finding) {
    const section = el('div', 'finding__section');
    section.appendChild(el('h4', null, 'Do the sources match?'));
    const list = el('ul', 'comparison-list');
    finding.comparisons.forEach(function (comparison) {
      const item = el('li', 'comparison');
      const head = el('div', 'comparison__head');
      head.appendChild(el('span', 'comparison__label', comparison.label));
      head.appendChild(el('span', 'badge ' + comparisonBadge(comparison.status),
        comparisonStatusText(comparison.status)));
      item.appendChild(head);
      item.appendChild(el('p', 'comparison__text', comparison.text));
      list.appendChild(item);
    });
    section.appendChild(list);
    return section;
  }

  function findingCard(finding) {
    const card = el('article', 'finding finding--' + severitySuffix(finding.severity));
    card.setAttribute('aria-label', finding.name + ' for ' + (finding.account || 'an unnamed account'));

    const header = el('div', 'finding__header');
    header.appendChild(el('h3', 'finding__title', finding.name));
    const badges = el('div', 'finding__badges');
    badges.appendChild(el('span', 'badge ' + severityClass(finding.severity), 'Severity: ' + finding.severity));
    badges.appendChild(el('span', 'badge badge--calm', 'Score ' + finding.score.total));
    header.appendChild(badges);
    card.appendChild(header);

    const meta = el('dl', 'finding__meta');
    const addFact = function (label, value, mono) {
      meta.appendChild(el('dt', null, label));
      meta.appendChild(el('dd', mono ? 'mono' : null, value || 'not available'));
    };
    addFact('Account', finding.account || 'not named in these events');
    addFact('Events', finding.eventIds.join(' \u2192 ') + ' (' + plural(finding.eventCount, 'event') + ')', true);
    addFact('Time range', finding.timeRangeText);
    addFact('Duration', finding.durationText || 'not applicable');
    addFact('Source IP', finding.sourceIps.length ? finding.sourceIps.join(', ') : 'not available in these events');
    addFact('Workstation', finding.workstations.length ? finding.workstations.join(', ') : 'not available in these events');
    card.appendChild(meta);

    if (finding.severityReasons.length) {
      const section = el('div', 'finding__section');
      section.appendChild(el('h4', null, 'Why this priority'));
      const list = el('ul');
      finding.severityReasons.forEach(function (reason) {
        list.appendChild(el('li', 'finding__severity-reason', reason));
      });
      section.appendChild(list);
      card.appendChild(section);
    }

    const addSection = function (heading, body, ordered) {
      if (!body || (Array.isArray(body) && !body.length)) return;
      const section = el('div', 'finding__section');
      section.appendChild(el('h4', null, heading));
      if (Array.isArray(body)) {
        const list = el(ordered ? 'ol' : 'ul');
        body.forEach(function (item) { list.appendChild(el('li', null, item)); });
        section.appendChild(list);
      } else {
        section.appendChild(el('p', null, body));
      }
      card.appendChild(section);
    };

    addSection('Observed activity', finding.observedActivity);

    if (finding.sequence && finding.sequence.length) {
      card.appendChild(sequenceSection(finding));
    }
    if (finding.comparisons && finding.comparisons.length) {
      card.appendChild(comparisonSection(finding));
    }

    addSection('Why this matters', finding.whyItMatters);

    /* The longer reference material collapses, so a finding stays scannable while
       all of it remains one click away. */
    const details = el('details', 'finding__details');
    details.appendChild(el('summary', null, 'Benign explanation and investigation steps'));

    if (finding.benign) {
      const benign = el('div', 'finding__section');
      benign.appendChild(el('h4', null, 'Possible benign explanation'));
      benign.appendChild(el('p', null, finding.benign));
      details.appendChild(benign);
    }
    if (finding.investigation && finding.investigation.length) {
      const steps = el('div', 'finding__section');
      steps.appendChild(el('h4', null, 'Suggested investigation'));
      const list = el('ol');
      finding.investigation.forEach(function (step) { list.appendChild(el('li', null, step)); });
      steps.appendChild(list);
      details.appendChild(steps);
    }
    card.appendChild(details);

    if (finding.score.factors.length) {
      const score = el('div', 'score');
      score.appendChild(el('p', 'score__title', 'Investigation score - how this was reached'));
      const list = el('ul', 'score__list');
      finding.score.factors.forEach(function (factor) {
        const item = el('li');
        item.appendChild(el('span', null, factor.label));
        item.appendChild(el('span', 'score__points', '+' + factor.points));
        list.appendChild(item);
      });
      score.appendChild(list);

      const total = el('div', 'score__total');
      total.appendChild(el('span', null, 'Total'));
      total.appendChild(el('span', null, String(finding.score.total)));
      score.appendChild(total);

      score.appendChild(el('p', 'score__note',
        'This is an educational way of putting findings in an order. It is not a probability, and it does not mean anything malicious happened.'));
      card.appendChild(score);
    }

    if (finding.crossReferences.length || finding.notes.length) {
      const notes = el('div', 'finding__section finding__notes');
      if (finding.crossReferences.length) {
        notes.appendChild(el('h4', null, 'Related findings'));
        const related = el('ul');
        finding.crossReferences.forEach(function (reference) { related.appendChild(el('li', null, reference)); });
        notes.appendChild(related);
      }
      if (finding.notes.length) {
        notes.appendChild(el('h4', null, 'Notes on this finding'));
        const list = el('ul');
        finding.notes.forEach(function (note) { list.appendChild(el('li', null, note)); });
        notes.appendChild(list);
      }
      card.appendChild(notes);
    }

    return card;
  }

  /* ------------------------------------------------------------------------
   * Dashboard
   * ------------------------------------------------------------------------
   * The tiles are plain counts. The bar lists show relative sizes only, and each
   * one states its numbers in text as well, so nothing depends on reading a bar.
   */
  function renderBarList(node, items, emptyText, labelOf) {
    if (!node) return;
    clear(node);

    if (!items.length) {
      node.appendChild(el('li', 'bar-list__empty', emptyText));
      return;
    }

    const max = Math.max.apply(null, items.map(function (item) { return item.value; })) || 1;
    items.forEach(function (item) {
      const li = el('li', 'bar-item');
      const head = el('div', 'bar-item__head');
      head.appendChild(el('span', 'bar-item__label', labelOf(item)));
      head.appendChild(el('span', 'bar-item__value', String(item.value)));
      li.appendChild(head);

      const track = el('div', 'bar-item__track');
      const fill = el('div', 'bar-item__fill');
      fill.setAttribute('style', 'width:' + Math.max(3, Math.round((item.value / max) * 100)) + '%');
      track.appendChild(fill);
      li.appendChild(track);

      node.appendChild(li);
    });
  }

  function renderDashboard() {
    const dashboard = state.analysis && state.analysis.dashboard;
    if (!dashboard) return;

    setHidden(dom['dashboard-panel'], false);

    const set = function (id, value) {
      if (dom[id]) dom[id].textContent = String(value);
    };
    set('dash-total', dashboard.totalEvents);
    set('dash-success', dashboard.successfulLogons);
    set('dash-failed', dashboard.failedLogons);
    set('dash-created', dashboard.accountsCreated);
    set('dash-priv', dashboard.privilegeChanges);
    set('dash-cleared', dashboard.logCleared);
    set('dash-process', dashboard.processCreations);
    set('dash-investigate', dashboard.eventsRequiringInvestigation);

    /* A one-line scope statement so the numbers always have context. */
    if (dom['dash-scope']) {
      const scope = [];
      if (state.fileName) scope.push(state.fileName);
      scope.push(plural(dashboard.totalEvents, 'event'));
      if (state.isDemo) scope.push('Demo Data');
      if (state.result && state.result.stats && state.result.stats.timeRange) {
        scope.push('from ' + Core.toIsoString(state.result.stats.timeRange.startMs).slice(0, 10)
          + ' to ' + Core.toIsoString(state.result.stats.timeRange.endMs).slice(0, 10));
      }
      dom['dash-scope'].textContent = scope.join(' \u00B7 ');
    }

    renderActivityChart(dashboard);

    renderBarList(dom['dash-top-accounts'],
      dashboard.topAccounts.map(function (item) { return { label: item.account, value: item.count }; }),
      'No account names were found in this file.',
      function (item) { return item.label; });

    renderBarList(dom['dash-top-failures'],
      dashboard.topFailedAccounts.map(function (item) { return { label: item.account, value: item.count }; }),
      'No failed logons in this file.',
      function (item) { return item.label; });

    renderBarList(dom['dash-top-ids'],
      dashboard.topEventIds.map(function (item) { return { label: item.eventId + ' - ' + item.title, value: item.count }; }),
      'No events in this file.',
      function (item) { return item.label; });

    const severities = ['High', 'Medium', 'Low', 'Informational'];
    renderBarList(dom['dash-severity'],
      severities.map(function (severity) {
        return { label: severity, value: dashboard.bySeverity[severity] || 0 };
      }),
      'No events in this file.',
      function (item) { return item.label; });

    const body = dom['dash-timeline-body'];
    clear(body);
    dashboard.timeline.forEach(function (item) {
      const tr = el('tr');
      tr.appendChild(el('td', 'cell-mono', item.iso || 'no timestamp'));
      tr.appendChild(el('td', 'cell-mono', String(item.eventId)));
      tr.appendChild(el('td', null, item.title));
      tr.appendChild(el('td', null, item.account || '(not named)'));
      tr.appendChild(el('td', null, item.reason));
      body.appendChild(tr);
    });
    if (!dashboard.timeline.length) {
      const tr = el('tr');
      const td = el('td', 'table-empty', 'Nothing noteworthy to place on a timeline.');
      td.colSpan = 5;
      tr.appendChild(td);
      body.appendChild(tr);
    }

    const note = dom['dash-timeline-note'];
    if (note) {
      if (!dashboard.timelineAvailable) {
        note.textContent = 'No readable timestamps were found, so this list follows the order of the rows in the file rather than time order.';
        setHidden(note, false);
      } else if (dashboard.timelineTotal > dashboard.timeline.length) {
        note.textContent = 'Showing the first ' + dashboard.timeline.length + ' of '
          + dashboard.timelineTotal + ' noteworthy events.';
        setHidden(note, false);
      } else {
        setHidden(note, true);
      }
    }
  }

  /* ------------------------------------------------------------------------
   * Activity chart
   * ------------------------------------------------------------------------
   * A CSS bar chart built from the events actually in the file: one bar per
   * time bucket, with the count and the bucket label in the tooltip and in the
   * accessible name. No chart library, no canvas, no invented data.
   *
   * When the timestamps are missing or ambiguous the chart is replaced with an
   * explanation, because a timeline drawn from unreliable times would be a lie.
   */
  function renderActivityChart(dashboard) {
    const container = dom['dash-activity'];
    const rangeNode = dom['dash-activity-range'];
    const noteNode = dom['dash-activity-note'];
    if (!container) return;

    clear(container);

    if (rangeNode) rangeNode.textContent = '';
    if (noteNode) setHidden(noteNode, true);

    if (!dashboard.timelineAvailable) {
      container.appendChild(el('div', 'chart__empty',
        'No reliable timestamps in this file, so activity cannot be plotted over time.'));
      if (noteNode) {
        noteNode.textContent = 'The events are still analysed; only the time-based view is unavailable.';
        setHidden(noteNode, false);
      }
      return;
    }

    const events = (state.result && state.result.events) || [];
    const times = [];
    events.forEach(function (event) {
      if (event.timestamp && event.timestamp.valid) times.push(event.timestamp.ms);
    });

    if (!times.length) {
      container.appendChild(el('div', 'chart__empty', 'No readable timestamps in this file.'));
      return;
    }

    const minMs = Math.min.apply(null, times);
    const maxMs = Math.max.apply(null, times);
    const spanMs = Math.max(maxMs - minMs, 1);

    /* Pick a bucket size that suits the span, so a short burst does not collapse
       into a single bar and a month of activity does not need hundreds. */
    const MINUTE = 60000;
    const HOUR = 60 * MINUTE;
    const DAY = 24 * HOUR;
    let bucketMs;
    let bucketName;

    if (spanMs <= 30 * MINUTE) { bucketMs = MINUTE; bucketName = '1-minute'; }
    else if (spanMs <= 6 * HOUR) { bucketMs = 15 * MINUTE; bucketName = '15-minute'; }
    else if (spanMs <= 36 * HOUR) { bucketMs = HOUR; bucketName = 'hourly'; }
    else if (spanMs <= 40 * DAY) { bucketMs = DAY; bucketName = 'daily'; }
    else { bucketMs = 7 * DAY; bucketName = 'weekly'; }

    const buckets = {};
    let peak = 0;
    times.forEach(function (ms) {
      const key = Math.floor((ms - minMs) / bucketMs);
      buckets[key] = (buckets[key] || 0) + 1;
      if (buckets[key] > peak) peak = buckets[key];
    });

    const maxBucket = Math.max.apply(null, Object.keys(buckets).map(Number));
    const barCount = Math.min(maxBucket + 1, 44);

    for (let i = 0; i < barCount; i++) {
      const count = buckets[i] || 0;
      const bucketStart = minMs + i * bucketMs;
      const label = Core.toIsoString(bucketStart).slice(0, bucketMs < HOUR ? 16 : 10);
      const bar = el('div', 'chart__bar');
      const height = count === 0 ? 2 : Math.max(6, Math.round((count / peak) * 100));
      bar.setAttribute('style', 'height:' + height + '%');
      bar.setAttribute('title', label + ': ' + plural(count, 'event'));
      bar.setAttribute('aria-label', label + ': ' + plural(count, 'event'));
      bar.setAttribute('role', 'img');
      if (count === 0) bar.setAttribute('aria-hidden', 'true');
      container.appendChild(bar);
    }

    const axis = el('div', 'chart__axis');
    axis.appendChild(el('span', null, Core.toIsoString(minMs).slice(0, 16)));
    axis.appendChild(el('span', null, Core.toIsoString(maxMs).slice(0, 16)));

    /* Re-rendering (for example after changing a setting) must not stack up
       axis labels, so any previous one is removed first. */
    const parent = container.parentNode;
    if (parent) {
      Array.prototype.slice.call(parent.querySelectorAll('.chart__axis')).forEach(function (node) {
        node.parentNode.removeChild(node);
      });
      parent.insertBefore(axis, container.nextSibling);
    }

    if (rangeNode) {
      rangeNode.textContent = plural(events.length, 'event') + ' in ' + bucketName + ' buckets';
    }
  }

  /* __CHUNK__ */

  /* ------------------------------------------------------------------------
   * Administrative / privilege activity
   * ------------------------------------------------------------------------
   * A summary, not a finding: no severity, and no claim that the events are
   * related. The explanation above the table says that explicitly, because a list
   * of administrative events is exactly where a beginner is most likely to assume
   * a connection that the data does not support.
   */
  function renderAdministrativeActivity() {
    const summary = state.analysis && state.analysis.administrativeActivity;

    if (!summary) {
      setHidden(dom['admin-panel'], true);
      return;
    }

    setHidden(dom['admin-panel'], false);

    if (dom['admin-summary']) {
      dom['admin-summary'].textContent = plural(summary.total, 'event')
        + ' changed an account, a group, a service or the audit log in this file'
        + (summary.privilegedChanges ? ', including ' + plural(summary.privilegedChanges, 'change') + ' to a privileged group' : '')
        + (summary.logCleared ? ', and the audit log was cleared' : '') + '.';
    }

    if (dom['admin-explanation']) {
      dom['admin-explanation'].textContent = summary.explanation
        + (summary.actors.length > 1
          ? ' The activity involves ' + plural(summary.actors.length, 'different account') + ': '
            + summary.actors.map(function (actor) { return actor.name + ' (' + actor.count + ')'; }).join(', ') + '.'
          : '');
    }

    const body = dom['admin-body'];
    clear(body);
    summary.items.forEach(function (item) {
      const tr = el('tr');
      tr.appendChild(el('td', 'cell-mono', item.iso || 'no timestamp'));
      tr.appendChild(el('td', 'cell-mono', String(item.eventId)));
      tr.appendChild(el('td', null, item.title));
      tr.appendChild(el('td', null, item.account || '(not named)'));
      tr.appendChild(el('td', null, item.actor || '(not named)'));
      tr.appendChild(el('td', null, item.detail || '-'));
      tr.appendChild(el('td', 'cell-mono', String(item.line)));
      body.appendChild(tr);
    });
  }

  /* ------------------------------------------------------------------------
   * Filters and the event explorer
   * ------------------------------------------------------------------------
   * Filters narrow what is DISPLAYED. They never change the analysis: the findings
   * were computed from the whole file, and hiding rows here cannot make a finding
   * disappear, which would be a confusing thing for a teaching tool to do.
   */
  const MAX_EXPLORER_ROWS = 500;

  function populateFilterOptions(result) {
    const events = result.events || [];

    const idCounts = {};
    events.forEach(function (event) { idCounts[event.eventId] = (idCounts[event.eventId] || 0) + 1; });
    const idSelect = dom['filter-eventid'];
    if (idSelect) {
      clear(idSelect);
      const allIds = el('option', null, 'All Event IDs');
      allIds.value = '';
      idSelect.appendChild(allIds);
      Object.keys(idCounts).map(Number).sort(function (a, b) { return a - b; }).forEach(function (id) {
        const info = Core.getEventInfo(id);
        const option = el('option', null, id + (info ? ' - ' + info.title : ' - not explained') + ' (' + idCounts[id] + ')');
        option.value = String(id);
        idSelect.appendChild(option);
      });
    }

    /* Accounts use the grouping key as the value, so the filter matches the same
       account regardless of domain prefix or letter case. */
    const accounts = {};
    events.forEach(function (event) {
      if (!event.accountKey) return;
      accounts[event.accountKey] = event.account;
    });
    const accountSelect = dom['filter-account'];
    if (accountSelect) {
      clear(accountSelect);
      const all = el('option', null, 'All accounts');
      all.value = '';
      accountSelect.appendChild(all);
      Object.keys(accounts).sort().forEach(function (key) {
        const option = el('option', null, accounts[key]);
        option.value = key;
        accountSelect.appendChild(option);
      });
    }

    const addresses = {};
    events.forEach(function (event) {
      const ip = event.fields && event.fields.sourceIp;
      if (ip) addresses[ip] = true;
    });
    const ipSelect = dom['filter-ip'];
    if (ipSelect) {
      clear(ipSelect);
      const all = el('option', null, 'All source addresses');
      all.value = '';
      ipSelect.appendChild(all);
      Object.keys(addresses).sort().forEach(function (ip) {
        const option = el('option', null, ip);
        option.value = ip;
        ipSelect.appendChild(option);
      });
    }

    const categories = {};
    events.forEach(function (event) {
      if (event.category) categories[event.category] = true;
    });
    const categorySelect = dom['filter-category'];
    if (categorySelect) {
      clear(categorySelect);
      const all = el('option', null, 'All event types');
      all.value = '';
      categorySelect.appendChild(all);
      Object.keys(categories).sort().forEach(function (category) {
        const option = el('option', null, category);
        option.value = category;
        categorySelect.appendChild(option);
      });
    }
  }

  function readFilters() {
    state.filters = {
      eventId: dom['filter-eventid'] ? dom['filter-eventid'].value : '',
      account: dom['filter-account'] ? dom['filter-account'].value : '',
      severity: dom['filter-severity'] ? dom['filter-severity'].value : '',
      sourceIp: dom['filter-ip'] ? dom['filter-ip'].value : '',
      category: dom['filter-category'] ? dom['filter-category'].value : '',
      search: dom['filter-search'] ? dom['filter-search'].value : ''
    };
    return state.filters;
  }

  /** The priority an event carries: its worst finding, or its own base severity. */
  function currentSeverityFor(event) {
    const dashboard = state.analysis && state.analysis.dashboard;
    if (dashboard && dashboard.severityByIndex && dashboard.severityByIndex[event.index]) {
      return dashboard.severityByIndex[event.index];
    }
    return event.baseSeverity || 'Informational';
  }

  function renderExplorer() {
    if (!state.result || !state.result.ok) return;
    setHidden(dom['explorer-panel'], false);
    if (dom['events-empty']) dom['events-empty'].setAttribute('hidden', '');

    const filters = state.filters;
    const search = (filters.search || '').trim().toLowerCase();
    const events = state.result.events || [];

    const matches = events.filter(function (event) {
      if (filters.eventId && String(event.eventId) !== filters.eventId) return false;
      if (filters.account && event.accountKey !== filters.account) return false;
      if (filters.severity && currentSeverityFor(event) !== filters.severity) return false;
      if (filters.sourceIp && (event.fields.sourceIp || '') !== filters.sourceIp) return false;
      if (filters.category && event.category !== filters.category) return false;
      if (search) {
        const haystack = [event.account, event.computer, event.message,
          event.fields.sourceIp, event.title].join(' ').toLowerCase();
        if (haystack.indexOf(search) === -1) return false;
      }
      return true;
    });

    const body = dom['events-body'];
    clear(body);

    matches.slice(0, MAX_EXPLORER_ROWS).forEach(function (event) {
      const severity = currentSeverityFor(event);
      const tr = el('tr');

      tr.appendChild(el('td', 'cell-mono',
        event.timestamp && event.timestamp.valid
          ? Core.toIsoString(event.timestamp.ms)
          : ((event.timestamp && event.timestamp.raw) || '-')));
      tr.appendChild(el('td', 'cell-mono', String(event.eventId)));
      tr.appendChild(el('td', null, event.title));
      tr.appendChild(el('td', null, event.account || '(not named)'));
      tr.appendChild(el('td', null, event.computer || '-'));
      tr.appendChild(el('td', 'cell-mono', event.fields.sourceIp || '-'));

      const severityCell = el('td');
      severityCell.appendChild(el('span', 'badge ' + severityClass(severity), severity));
      tr.appendChild(severityCell);

      tr.appendChild(el('td', 'cell-message', shorten(event.message, 140) || '-'));
      body.appendChild(tr);
    });

    if (!matches.length) {
      const tr = el('tr');
      const td = el('td', 'table-empty', 'No events match these filters.');
      td.colSpan = 8;
      tr.appendChild(td);
      body.appendChild(tr);
    }

    const anyFilter = filters.eventId || filters.account || filters.severity
      || filters.sourceIp || filters.category || search;

    if (dom['filter-count']) {
      dom['filter-count'].textContent = 'Showing ' + matches.length + ' of '
        + plural(events.length, 'event') + (anyFilter ? ' after filtering.' : '. No filters applied.');
    }

    const note = dom['events-limit-note'];
    if (note) {
      if (matches.length > MAX_EXPLORER_ROWS) {
        note.textContent = 'Only the first ' + MAX_EXPLORER_ROWS + ' matching events are shown, to keep the page responsive. '
          + 'Narrow the filters to see a specific part of the file.';
        setHidden(note, false);
      } else {
        setHidden(note, true);
      }
    }
  }

  function clearFilters() {
    state.filters = { eventId: '', account: '', severity: '', sourceIp: '', category: '', search: '' };
    ['filter-eventid', 'filter-account', 'filter-severity', 'filter-ip', 'filter-category'].forEach(function (id) {
      if (dom[id]) dom[id].value = '';
    });
    if (dom['filter-search']) dom['filter-search'].value = '';
    renderExplorer();
  }

  /* ------------------------------------------------------------------------
   * Clearing everything
   * ------------------------------------------------------------------------
   * Because nothing is stored, "clearing" really does mean the data is gone:
   * we drop the reference and let the browser reclaim the memory.
   */
  function renderFindings() {
    const analysis = state.analysis;
    if (!analysis || !analysis.ok) return;

    setHidden(dom['findings-panel'], false);
    setHidden(dom['settings-panel'], false);

    const list = dom['findings-list'];
    clear(list);

    const summary = dom['findings-summary'];
    clear(summary);

    if (!analysis.findings.length) {
      summary.textContent = 'No findings. Every rule ran and nothing reached the current thresholds.';
      const empty = el('div', 'empty-state');
      empty.appendChild(el('span', 'empty-state__title', 'Nothing to escalate with these settings'));
      empty.appendChild(el('span', 'empty-state__text',
        'That is reassuring, but it is not proof that nothing happened. This tool only sees the events in the file you loaded, '
        + 'and only the activity its rules look for. Try lowering the failed logon threshold, or load a demo dataset to see what a finding looks like.'));
      list.appendChild(empty);
    } else {
      const stats = analysis.stats;
      summary.textContent = plural(stats.totalFindings, 'finding') + ' worth a look. Highest priority: '
        + stats.highestSeverity + '. ' + plural(stats.eventsRequiringInvestigation, 'event')
        + ' from this file are involved in at least one finding.';
      analysis.findings.forEach(function (finding) {
        list.appendChild(findingCard(finding));
      });
    }

    const notesRegion = dom['analysis-notes'];
    const notesList = dom['analysis-notes-list'];
    clear(notesList);
    if (analysis.notes.length) {
      analysis.notes.forEach(function (note) { notesList.appendChild(el('li', null, note)); });
      setHidden(notesRegion, false);
    } else {
      setHidden(notesRegion, true);
    }
  }

  /* ------------------------------------------------------------------------
   * Settings
   * ------------------------------------------------------------------------
   * Deliberately session-only: nothing is written to localStorage or cookies, so
   * a student's thresholds vanish when the tab closes, along with the log data.
   */
  function readSettingsFromForm() {
    const threshold = dom['setting-threshold'] ? Number(dom['setting-threshold'].value) : undefined;
    const windowMinutes = dom['setting-window'] ? Number(dom['setting-window'].value) : undefined;
    const useWindow = dom['setting-use-window'] ? !!dom['setting-use-window'].checked : undefined;
    // Core.normalizeSettings clamps anything silly, so a typo cannot break a rule.
    return Core.normalizeSettings({
      failedLogonThreshold: threshold,
      failedLogonWindowMinutes: windowMinutes,
      useTimeWindow: useWindow
    });
  }

  function writeSettingsToForm(settings) {
    if (dom['setting-threshold']) dom['setting-threshold'].value = String(settings.failedLogonThreshold);
    if (dom['setting-window']) dom['setting-window'].value = String(settings.failedLogonWindowMinutes);
    if (dom['setting-use-window']) dom['setting-use-window'].checked = settings.useTimeWindow;
    updateWindowStatus();
  }

  function updateWindowStatus() {
    const node = dom['window-status'];
    if (!node) return;

    const useWindow = dom['setting-use-window'] ? !!dom['setting-use-window'].checked : true;
    const hasData = !!(state.result && state.result.ok);
    const reliable = hasData && !!state.result.stats.timelineReliable;

    if (!useWindow) {
      node.textContent = 'The time window is switched off: failures for one account are counted together no matter how far apart they are.';
    } else if (!hasData) {
      node.textContent = 'The time window will be applied if the loaded file has reliable timestamps.';
    } else if (reliable) {
      node.textContent = 'Timestamps in this file look reliable, so the time window is being applied.';
    } else {
      node.textContent = 'Timestamps in this file are missing or ambiguous, so the time window cannot be applied. Failures are counted together instead, and each finding says so.';
    }
  }

  function applySettings() {
    state.settings = readSettingsFromForm();
    writeSettingsToForm(state.settings);
    runAnalysis();
  }

  function runAnalysis() {
    if (!state.result || !state.result.ok) return;
    state.analysis = Core.analyse(state.result, state.settings);
    renderFindings();
    renderDashboard();
    renderAdministrativeActivity();
    renderExplorer();
    updateWindowStatus();
  }


  function resetAll() {
    state.result = null;
    state.fileName = '';
    state.fileSize = 0;
    state.isDemo = false;
    state.analysis = null;

    if (dom['file-input']) dom['file-input'].value = '';
    setHidden(dom['parse-panel'], true);
    setHidden(dom['file-meta'], true);
    setHidden(dom['warning-region'], true);
    setHidden(dom['findings-panel'], true);
    setHidden(dom['settings-panel'], true);
    setHidden(dom['dashboard-panel'], true);
    setHidden(dom['admin-panel'], true);
    setHidden(dom['explorer-panel'], true);
    setWorkspaceEmpty(true);
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
    initTabs();
    bindUpload();

    if (dom['btn-open-events']) {
      dom['btn-open-events'].addEventListener('click', function () {
        selectTab('tab-events');
        const heading = dom['explorer-heading'];
        if (heading && typeof heading.focus === 'function') heading.focus();
      });
    }
    if (dom['btn-privacy-jump']) {
      dom['btn-privacy-jump'].addEventListener('click', function () { selectTab('tab-privacy'); });
    }
    if (dom['btn-goto-dashboard']) {
      dom['btn-goto-dashboard'].addEventListener('click', function () { selectTab('tab-dashboard'); });
    }

    if (dom['btn-reset']) dom['btn-reset'].addEventListener('click', resetAll);

    /* Filters. Applied as the user changes them, and never allowed to alter the
       analysis itself. */
    ['filter-eventid', 'filter-account', 'filter-severity', 'filter-ip', 'filter-category'].forEach(function (id) {
      if (dom[id]) dom[id].addEventListener('change', function () { readFilters(); renderExplorer(); });
    });
    if (dom['filter-search']) {
      dom['filter-search'].addEventListener('input', function () { readFilters(); renderExplorer(); });
    }
    if (dom['btn-clear-filters']) {
      dom['btn-clear-filters'].addEventListener('click', clearFilters);
    }

    /* Analysis settings. Applied on change and by the button, and re-run against
     * the data already in memory - the file is never read again. */
    state.settings = Core.defaultSettings();
    writeSettingsToForm(state.settings);

    ['setting-threshold', 'setting-window'].forEach(function (id) {
      if (dom[id]) dom[id].addEventListener('change', applySettings);
    });
    if (dom['setting-use-window']) dom['setting-use-window'].addEventListener('change', applySettings);
    if (dom['btn-apply-settings']) dom['btn-apply-settings'].addEventListener('click', applySettings);
    if (dom['btn-reset-settings']) {
      dom['btn-reset-settings'].addEventListener('click', function () {
        state.settings = Core.defaultSettings();
        writeSettingsToForm(state.settings);
        runAnalysis();
      });
    }

    // The version shown in the footer is taken from the engine, so the two can
    // never disagree.
    if (dom['footer-version']) {
      dom['footer-version'].textContent = 'Version ' + Core.VERSION
        + ' - educational SOC triage tool. Findings are a reason to investigate, not proof.';
    }

    // Before any data: show the invitation, and do not offer file details.
    setWorkspaceEmpty(true);

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




