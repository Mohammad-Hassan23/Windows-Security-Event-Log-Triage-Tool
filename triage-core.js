/*!
 * triage-core.js - Windows Security Event Log Triage Tool
 * ---------------------------------------------------------------------------
 * The "brain" of the tool. It contains NO user interface code.
 *
 * WHY THIS FILE IS SEPARATE FROM script.js
 *   A file that mixes parsing logic with on-screen rendering can only be tested
 *   by a human clicking buttons. This file is a pure engine: "give me CSV text,
 *   I return a report object". That means the analysis can be exercised
 *   automatically (see dev-tests/run-tests.mjs) and it keeps the
 *   security-critical parsing separate from the display layer.
 *
 * NON-NEGOTIABLE DESIGN RULES (keep these true when editing this file):
 *   1. NO DOM ACCESS.   Never touches document / window UI APIs.
 *   2. NO NETWORK.      No fetch calls, no XHR objects, no sockets, no beacons.
 *   3. NO STORAGE.      No localStorage, sessionStorage, IndexedDB, cookies.
 *   4. NO DEPENDENCIES. Plain JavaScript only - nothing to install.
 *
 * This file is loaded as a classic <script> in the browser (window.TriageCore)
 * and can also be require()d by Node for the automated tests.
 */
(function () {
  'use strict';

  const VERSION = '1.0.0-step1';

  /* ------------------------------------------------------------------------
   * Safety limits
   * ------------------------------------------------------------------------
   * A Windows Security log can be huge. These limits keep a large (or hostile)
   * file from freezing the browser tab. We never truncate silently - the user
   * is always told what happened.
   */
  const LIMITS = {
    maxFileBytes: 25 * 1024 * 1024, // 25 MB of text (roughly 150k-250k events)
    maxRows: 200000,                // maximum data rows analysed
    maxMessageChars: 20000,         // per-event message text kept in memory
    maxPreviewRows: 10              // rows shown in the parse-check preview table
  };

  /* ------------------------------------------------------------------------
   * Investigative severity vocabulary
   * ------------------------------------------------------------------------
   * IMPORTANT CONCEPT FOR READERS OF THIS CODE:
   * There are TWO different "levels" in this project and they must not be
   * mixed up.
   *
   *   1. rawLevel - the Windows level from the CSV ("Information",
   *                 "Audit Success", "Error" ...). This is what Windows wrote.
   *   2. severity - OUR INVESTIGATIVE PRIORITY ("Low", "Medium", "High").
   *                 Decided by the detection rules, never by the Windows level.
   *                 A single failed logon is an "Audit Failure" in Windows but
   *                 only informational priority for an analyst until it repeats.
   *
   * Severity is a triage hint, NOT a probability of compromise.
   */
  const SEVERITY = {
    INFORMATIONAL: 'Informational',
    LOW: 'Low',
    MEDIUM: 'Medium',
    HIGH: 'High'
  };

  const SEVERITY_RANK = {
    'Informational': 0,
    'Low': 1,
    'Medium': 2,
    'High': 3
  };

  function severityRank(severity) {
    return Object.prototype.hasOwnProperty.call(SEVERITY_RANK, severity)
      ? SEVERITY_RANK[severity]
      : -1;
  }

  /** Returns whichever of two severities is more serious. */
  function higherSeverity(a, b) {
    if (!a) return b;
    if (!b) return a;
    return severityRank(a) >= severityRank(b) ? a : b;
  }

  /* Windows "Level" column -> a normalised English label.
   * Windows is inconsistent here: the Level column may contain a number (0-5),
   * the word "Information", or "Audit Success" / "Audit Failure". */
  const RAW_LEVEL_MAP = {
    'information': 'Information',
    'informational': 'Information',
    'info': 'Information',
    'warning': 'Warning',
    'warn': 'Warning',
    'error': 'Error',
    'critical': 'Critical',
    'auditsuccess': 'Audit Success',
    'auditfailure': 'Audit Failure',
    'success': 'Audit Success',
    'failure': 'Audit Failure',
    '0': 'Information',
    '1': 'Error',
    '2': 'Warning',
    '3': 'Information',
    '4': 'Information',
    '5': 'Information'
  };

  /**
   * Normalise the Windows Level column into an English label.
   * @param {*} raw
   * @returns {string} '' when blank, else a label from RAW_LEVEL_MAP or 'Unknown'
   */
  function normalizeRawLevel(raw) {
    const key = String(raw == null ? '' : raw).trim().toLowerCase().replace(/[\s_-]+/g, '');
    if (!key) return '';
    return Object.prototype.hasOwnProperty.call(RAW_LEVEL_MAP, key)
      ? RAW_LEVEL_MAP[key]
      : 'Unknown';
  }

  /* ------------------------------------------------------------------------
   * Column-name tolerance
   * ------------------------------------------------------------------------
   * Event Viewer, PowerShell's Export-Csv and third-party exporters all produce
   * different header names, and a non-English Windows produces translated
   * headers that we deliberately do not try to guess.
   *
   * Headers are normalised before matching: BOM removed, wrapping quotes
   * removed, lower-cased, and every character that is not a-z/0-9 removed.
   * So "Event ID", "event_id", "EventID" and "Event-ID" all become "eventid".
   */
  function normalizeHeader(raw) {
    return String(raw == null ? '' : raw)
      .replace(/^\uFEFF/, '')          // byte-order mark added by Excel/Event Viewer
      .replace(/^["']+|["']+$/g, '')   // stray wrapping quotes
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');      // spaces, underscores, dots and dashes go
  }

  const COLUMN_ALIASES = {
    eventId: ['eventid', 'id', 'eventcode', 'eventidentifier', 'eventnumber'],
    timestamp: ['dateandtime', 'timecreated', 'timestamp', 'timestamps', 'datetime', 'date', 'time', 'logged', 'occurred', 'created'],
    level: ['level', 'leveldisplayname', 'leveldisplay', 'severity'],
    account: ['account', 'accountname', 'user', 'username', 'targetusername', 'subjectusername', 'targetuser', 'membername'],
    computer: ['computer', 'computername', 'machinename', 'hostname', 'workstation'],
    sourceIp: ['sourceip', 'sourcenetworkaddress', 'ipaddress', 'clientaddress', 'sourceaddress', 'sourceipaddress', 'remoteaddress', 'ip'],
    source: ['source', 'providername', 'provider', 'channel', 'logname'],
    taskCategory: ['taskcategory', 'taskdisplayname', 'task', 'category', 'opcode'],
    keywords: ['keywords', 'keywordsdisplaynames', 'keywordsdisplayname'],
    message: ['message', 'description', 'details', 'eventdata', 'messagebody', 'fullmessage']
  };

  /* Order matters for the "which columns were found / missing" report. */
  const CANONICAL_FIELDS = [
    'eventId', 'timestamp', 'level', 'account', 'computer',
    'sourceIp', 'source', 'taskCategory', 'keywords', 'message'
  ];

  const FIELD_LABELS = {
    eventId: 'Event ID',
    timestamp: 'Date / Time',
    level: 'Level',
    account: 'Account',
    computer: 'Computer',
    sourceIp: 'Source IP',
    source: 'Source',
    taskCategory: 'Task Category',
    keywords: 'Keywords',
    message: 'Message'
  };

  /* Reverse lookup: normalised alias -> canonical field name. First alias wins. */
  const ALIAS_INDEX = (function buildAliasIndex() {
    const index = {};
    CANONICAL_FIELDS.forEach(function (field) {
      (COLUMN_ALIASES[field] || []).forEach(function (alias) {
        if (!Object.prototype.hasOwnProperty.call(index, alias)) {
          index[alias] = field;
        }
      });
    });
    return index;
  })();

  /**
   * Work out which CSV column holds which piece of information.
   * Never throws: unknown columns are ignored, and any canonical field that
   * could not be found is listed in `missing` so we can explain the problem.
   *
   * @param {string[]} headers raw header cells from the CSV
   */
  function mapColumns(headers) {
    const list = Array.isArray(headers) ? headers : [];
    const mapping = {};
    const matched = [];
    const duplicates = [];

    list.forEach(function (header, index) {
      const field = ALIAS_INDEX[normalizeHeader(header)];
      if (!field) return;
      if (Object.prototype.hasOwnProperty.call(mapping, field)) {
        // e.g. both "User" and "Account Name" are present. Keep the first and
        // record the clash so the report can mention it.
        duplicates.push({ field: field, header: header, index: index });
        return;
      }
      mapping[field] = { index: index, header: header };
      matched.push(field);
    });

    const missing = CANONICAL_FIELDS.filter(function (field) {
      return !Object.prototype.hasOwnProperty.call(mapping, field);
    });

    return { mapping: mapping, matched: matched, missing: missing, duplicates: duplicates };
  }

  /* ------------------------------------------------------------------------
   * Text decoding (encoding handling)
   * ------------------------------------------------------------------------
   * Windows is not consistent about text encoding:
   *   - PowerShell 5.1 `Export-Csv` often writes UTF-16LE, or UTF-8 with a BOM.
   *   - Event Viewer's own save dialog usually writes UTF-8 or ANSI.
   *   - Older exports may be Windows-1252.
   * A UTF-16LE file read as UTF-8 comes out full of NUL characters, which would
   * otherwise look like a corrupt/binary file. So we sniff the byte-order mark
   * and fall back to a heuristic re-decode.
   */
  function decodeBytes(bytes) {
    let view;
    if (typeof Uint8Array !== 'undefined' && bytes instanceof Uint8Array) {
      view = bytes;
    } else if (typeof ArrayBuffer !== 'undefined' && bytes instanceof ArrayBuffer) {
      view = new Uint8Array(bytes);
    } else if (Array.isArray(bytes)) {
      view = new Uint8Array(bytes);
    } else {
      return { text: '', encoding: 'unknown', error: 'Unrecognised file content.' };
    }

    let encoding = 'utf-8';
    let start = 0;
    if (view.length >= 2 && view[0] === 0xFF && view[1] === 0xFE) {
      encoding = 'utf-16le'; start = 2;          // Windows PowerShell favourite
    } else if (view.length >= 2 && view[0] === 0xFE && view[1] === 0xFF) {
      encoding = 'utf-16be'; start = 2;
    } else if (view.length >= 3 && view[0] === 0xEF && view[1] === 0xBB && view[2] === 0xBF) {
      encoding = 'utf-8'; start = 3;             // UTF-8 BOM
    }

    const body = start ? view.subarray(start) : view;

    if (typeof TextDecoder === 'undefined') {
      // Very old browser: best effort ASCII/Latin-1 decode. Good enough for a
      // CSV, and we tell the caller which encoding we actually used.
      let out = '';
      for (let i = 0; i < body.length; i++) out += String.fromCharCode(body[i]);
      return { text: out, encoding: 'latin-1 (fallback)', error: null };
    }

    let text;
    try {
      if (encoding === 'utf-16le' || encoding === 'utf-16be') {
        text = new TextDecoder(encoding).decode(body);
      } else {
        text = new TextDecoder('utf-8').decode(body);
        const nulCount = (text.match(/\u0000/g) || []).length;
        if (nulCount > 0 && nulCount > text.length / 8) {
          const retry = new TextDecoder('utf-16le').decode(body);
          if ((retry.match(/\u0000/g) || []).length < nulCount) {
            text = retry;
            encoding = 'utf-16le (detected without BOM)';
          }
        }
      }
    } catch (err) {
      return { text: '', encoding: encoding, error: 'The file could not be decoded as text.' };
    }

    return { text: text, encoding: encoding, error: null };
  }

  /* ------------------------------------------------------------------------
   * Delimiter detection
   * ------------------------------------------------------------------------
   * Event Viewer may write comma separated values; a non-English Windows often
   * writes semicolons; the "Text (Tab delimited)" export writes tabs. Rather
   * than force the user to choose, we count candidates on the first few lines
   * while ignoring any character inside quotes.
   */
  const DELIMITERS = [
    { char: ',', label: 'comma' },
    { char: ';', label: 'semicolon' },
    { char: '\t', label: 'tab' },
    { char: '|', label: 'pipe' }
  ];

  function countOutsideQuotes(line, character) {
    let count = 0;
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') { inQuotes = !inQuotes; continue; }
      if (!inQuotes && ch === character) count++;
    }
    return count;
  }

  function detectDelimiter(text) {
    const lines = String(text || '').split(/\r?\n/).slice(0, 5).filter(function (l) {
      return l.trim() !== '';
    });
    if (!lines.length) return { char: ',', label: 'comma', confident: false, counts: {} };

    let best = null;
    const counts = {};

    DELIMITERS.forEach(function (candidate) {
      let total = 0;
      let consistent = true;
      let previous = null;

      lines.forEach(function (line) {
        const count = countOutsideQuotes(line, candidate.char);
        if (previous === null) previous = count;
        else if (count !== previous) consistent = false;
        total += count;
      });

      const firstLine = countOutsideQuotes(lines[0], candidate.char);
      counts[candidate.label] = firstLine;
      if (firstLine <= 0) return;

      const scored = {
        char: candidate.char,
        label: candidate.label,
        total: total,
        consistent: consistent,
        confident: consistent
      };

      if (!best || scored.total > best.total ||
          (scored.total === best.total && scored.consistent && !best.consistent)) {
        best = scored;
      }
    });

    if (!best) return { char: ',', label: 'comma', confident: false, counts: counts };
    return best;
  }

  /* ------------------------------------------------------------------------
   * The CSV reader itself
   * ------------------------------------------------------------------------
   * WHY NOT `line.split(',')`?
   * Every Windows event Message field contains text like
   *   "An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\tS-1-5-18"
   * and often commas, embedded XML tags and line breaks inside one quoted cell.
   * Splitting on commas shreds those rows and produces columns that appear
   * "missing". So we use a small state machine that follows the rules of RFC
   * 4180 and is tolerant of the sloppy files real exporters produce:
   *   - "..." protects any delimiter, quote-doubling ("") and newlines
   *   - a quote in the middle of an unquoted field is treated as a literal
   *   - CR or CRLF line endings both work
   *
   * @returns {{rows: Array<{cells: string[], line: number}>, unterminatedQuote: boolean}}
   */
  function parseDelimited(text, delimiter) {
    const src = String(text == null ? '' : text).replace(/^\uFEFF/, '');
    const rows = [];
    let cells = [];
    let field = '';
    let inQuotes = false;
    let line = 1;
    let rowStartLine = 1;
    let i = 0;
    const n = src.length;

    while (i < n) {
      const ch = src[i];

      if (inQuotes) {
        if (ch === '"') {
          if (src[i + 1] === '"') { field += '"'; i += 2; continue; } // doubled quote
          inQuotes = false; i++; continue;                            // end of quoted cell
        }
        if (ch === '\n') line++;
        field += ch; i++; continue;
      }

      if (ch === '"' && field === '') { inQuotes = true; i++; continue; }
      if (ch === delimiter) { cells.push(field); field = ''; i++; continue; }
      if (ch === '\r') { i++; continue; }        // part of CRLF, not data
      if (ch === '\n') {
        cells.push(field);
        rows.push({ cells: cells, line: rowStartLine });
        cells = []; field = '';
        line++; rowStartLine = line; i++; continue;
      }
      field += ch; i++;
    }

    if (field !== '' || cells.length > 0) {
      cells.push(field);
      rows.push({ cells: cells, line: rowStartLine });
    }

    // Drop rows that contain nothing at all (blank lines, trailing newline).
    const cleaned = rows.filter(function (row) {
      return row.cells.some(function (cell) { return String(cell).trim() !== ''; });
    });

    return { rows: cleaned, unterminatedQuote: inQuotes };
  }

  /* ------------------------------------------------------------------------
   * Timestamp parsing - deliberately honest about ambiguity
   * ------------------------------------------------------------------------
   * THIS IS THE MESSIEST PART OF ANY LOG TOOL, so it is worth understanding.
   * A CSV might contain "3/4/2026 2:22:11 PM". Is that 3 April or 4 March?
   * It depends on the regional settings of the machine that produced it, and
   * the file does not say.
   *
   * Our approach:
   *   1. Prefer formats that cannot be misread (2026-04-03, or 12.05.2021 which
   *      is day-first by the European convention that uses dots).
   *   2. If a date is ambiguous on its own, look at the WHOLE file: if any row
   *      has a first number greater than 12, the file is day-first; if any row
   *      has a second number greater than 12, it is month-first.
   *   3. If the file gives no clue at all, assume the Event Viewer English
   *      default (month/day) but record `confident: false` and warn the user,
   *      because we must never invent certainty we do not have.
   *
   * We never claim a timezone we were not given: when the export has no offset,
   * timestamps are interpreted in the local timezone, which is fine for ORDERING
   * events but is documented as a limitation in README.md.
   */
  const TIME_RE = /(\d{1,2}):(\d{2})(?::(\d{2}))?(?:[.,](\d{1,3}))?\s*([AaPp][Mm])?/;
  /* A timezone offset is only accepted when it directly follows a clock time.
     Otherwise "2026-04-03" would look like it ended in the offset "-03". */
  const OFFSET_RE = /(\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d{1,3})?)\s*(Z|[+-]\d{2}:?\d{2})\s*$/;

  function isValidDateParts(p) {
    if (!p) return false;
    if (!(p.year >= 1990 && p.year <= 2200)) return false;
    if (!(p.month >= 1 && p.month <= 12)) return false;
    if (!(p.day >= 1 && p.day <= 31)) return false;
    if (!(p.hour >= 0 && p.hour <= 23)) return false;
    if (!(p.minute >= 0 && p.minute <= 59)) return false;
    if (!(p.second >= 0 && p.second <= 60)) return false;
    // Reject impossible combinations such as 31 February.
    const probe = new Date(Date.UTC(p.year, p.month - 1, p.day));
    return probe.getUTCMonth() === p.month - 1 && probe.getUTCDate() === p.day;
  }

  function applyTimeParts(target, timeText) {
    const text = String(timeText == null ? '' : timeText);
    const tm = text.match(TIME_RE);
    if (!tm) {
      target.hour = 0; target.minute = 0; target.second = 0; target.ms = 0;
    } else {
      let hour = Number(tm[1]);
      const minute = Number(tm[2]);
      const second = tm[3] ? Number(tm[3]) : 0;
      const millis = tm[4] ? Number((tm[4] + '00').slice(0, 3)) : 0;
      const ampm = (tm[5] || '').toLowerCase();
      if (ampm === 'pm' && hour < 12) hour += 12;
      if (ampm === 'am' && hour === 12) hour = 0;
      target.hour = hour; target.minute = minute; target.second = second; target.ms = millis;
    }

    const offset = text.match(OFFSET_RE);
    if (offset) {
      const raw = offset[2];
      if (raw === 'Z') {
        target.offsetMinutes = 0;
      } else {
        const sign = raw[0] === '-' ? -1 : 1;
        const digits = raw.slice(1).replace(':', '');
        target.offsetMinutes = sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2, 4)));
      }
    }
    return true;
  }

  /**
   * Read one timestamp string and report what it contains, WITHOUT deciding how
   * to resolve genuine day/month ambiguity yet (that needs the whole file).
   */
  function analyzeTimestamp(raw) {
    const input = String(raw == null ? '' : raw).trim();
    if (!input) return null;

    const blank = { raw: input, kind: 'unknown', valid: false };
    let m;

    // 1. Year first: 2026-04-03T14:22:11Z / 2026/04/03 14:22:11
    m = input.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[T\s]+(.*))?$/);
    if (m) {
      const p = { raw: input, kind: 'iso', year: Number(m[1]), month: Number(m[2]), day: Number(m[3]), offsetMinutes: null };
      applyTimeParts(p, m[4] || '');
      p.valid = isValidDateParts(p);
      return p.valid ? p : blank;
    }

    // 2. Dotted dates are day-first by convention: 12.05.2021 15:22:11
    m = input.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})(?:[,\s]+(.*))?$/);
    if (m) {
      const p = { raw: input, kind: 'day-first', year: Number(m[3]), month: Number(m[2]), day: Number(m[1]), offsetMinutes: null };
      applyTimeParts(p, m[4] || '');
      p.valid = isValidDateParts(p);
      return p.valid ? p : blank;
    }

    // 3. Slash or dash dates - the ambiguous family: 3/4/2026, 03-04-26
    m = input.match(/^(\d{1,2})[\/-](\d{1,2})[\/-](\d{2,4})(?:[,\s]+(.*))?$/);
    if (m) {
      const first = Number(m[1]);
      const second = Number(m[2]);
      let year = Number(m[3]);
      if (year < 100) year += year < 70 ? 2000 : 1900;

      const p = { raw: input, kind: 'ambiguous', year: year, month: second, day: first, offsetMinutes: null };
      applyTimeParts(p, m[4] || '');

      if (first > 12 && second <= 12) {
        p.kind = 'day-first';                    // 25/12/2026 must be 25 December
      } else if (second > 12 && first <= 12) {
        p.kind = 'month-first';                  // 12/25/2026 must be 25 December
        p.month = first; p.day = second;
      }
      p.valid = isValidDateParts(p);
      return p.valid ? p : blank;
    }

    // 4. Something else entirely (e.g. "Fri Apr 3 2026"). Let the browser try,
    //    but only trust the result if it produced a real date.
    const fallback = Date.parse(input);
    if (!isNaN(fallback)) {
      const d = new Date(fallback);
      return {
        raw: input, kind: 'browser', valid: true,
        year: d.getFullYear(), month: d.getMonth() + 1, day: d.getDate(),
        hour: d.getHours(), minute: d.getMinutes(), second: d.getSeconds(), ms: d.getMilliseconds(),
        offsetMinutes: null, absoluteMs: fallback
      };
    }

    return blank;
  }

  /* ------------------------------------------------------------------------
   * Small value helpers
   * ------------------------------------------------------------------------
   * Windows writes placeholder text instead of leaving fields empty: "-",
   * "N/A", "None". Treating those as real account names would produce nonsense
   * findings ("account: -"), so we normalise them to an empty string and report
   * "not available" instead.
   */
  const BLANK_VALUES = [
    '', '-', '--', 'n/a', 'na', 'none', 'null', 'unknown',
    '(none)', 'not available', 'value not set'
  ];

  function cleanCell(value) {
    return String(value == null ? '' : value).trim();
  }

  function isBlankValue(value) {
    return BLANK_VALUES.indexOf(cleanCell(value).toLowerCase()) !== -1;
  }

  /**
   * Strip a Windows domain or machine prefix: "LAB\jsmith" -> "jsmith",
   * "CONTOSO/jsmith" -> "jsmith".
   *
   * The prefix must look like a real domain (it starts with a letter or digit
   * and contains no spaces), and something must remain after it. This matters:
   * an earlier version stripped at the first forward slash of ANY value, which
   * turned the harmless string "<script>alert(1)</script>" into "script>".
   * A parser must never quietly rewrite data it does not understand.
   */
  const DOMAIN_PREFIX_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}[\\/](?=\S)/;

  function normalizeAccount(raw) {
    const value = cleanCell(raw);
    if (isBlankValue(value)) return '';
    return value.replace(DOMAIN_PREFIX_RE, '');
  }

  /** Used for grouping/correlation: case-insensitive, trimmed. */
  function accountKeyOf(name) {
    return cleanCell(name).toLowerCase();
  }

  /**
   * Event IDs arrive as "4624", " 4624 ", "4624 (0x1210)" or "0x1210".
   * We take the first run of digits, and return null when there is none so the
   * caller can report the row instead of inventing an event.
   */
  function parseEventId(raw) {
    const value = cleanCell(raw);
    if (!value) return null;
    const match = value.match(/\d{1,6}/);
    if (!match) return null;
    const id = Number(match[0]);
    return isFinite(id) ? id : null;
  }

  function truncate(text, max) {
    const value = String(text == null ? '' : text);
    return value.length > max ? value.slice(0, max) + ' ... [shortened]' : value;
  }

  function labelForDelimiter(character) {
    for (let i = 0; i < DELIMITERS.length; i++) {
      if (DELIMITERS[i].char === character) return DELIMITERS[i].label;
    }
    return 'unknown';
  }

  /* ------------------------------------------------------------------------
   * Turning analysed timestamps into real moments in time
   * ------------------------------------------------------------------------ */

  /**
   * Decide, for the file as a whole, whether dates like 3/4/2026 are
   * day-first or month-first. See the long comment above analyzeTimestamp().
   */
  function resolveDateConvention(analyses) {
    let sawDayFirst = false;
    let sawMonthFirst = false;

    (analyses || []).forEach(function (a) {
      if (!a) return;
      if (a.kind === 'day-first') sawDayFirst = true;
      else if (a.kind === 'month-first') sawMonthFirst = true;
    });

    if (sawDayFirst && !sawMonthFirst) return { convention: 'day-first', confident: true, sawDayFirst: sawDayFirst, sawMonthFirst: sawMonthFirst };
    if (sawMonthFirst && !sawDayFirst) return { convention: 'month-first', confident: true, sawDayFirst: sawDayFirst, sawMonthFirst: sawMonthFirst };
    // Either no evidence at all, or two contradictory formats in one file.
    return { convention: 'month-first', confident: false, sawDayFirst: sawDayFirst, sawMonthFirst: sawMonthFirst };
  }

  function timestampToMs(parts) {
    if (!parts || !parts.valid) return null;
    if (typeof parts.absoluteMs === 'number') return parts.absoluteMs;
    if (!isValidDateParts(parts)) return null;
    if (parts.offsetMinutes === null || parts.offsetMinutes === undefined) {
      // No timezone in the export. Interpret it in the browser's local zone:
      // the absolute value may be off, but ORDERING is correct, and ordering is
      // what correlation needs. Documented in README.md.
      return new Date(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second, parts.ms || 0).getTime();
    }
    return Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second, parts.ms || 0)
      - parts.offsetMinutes * 60000;
  }

  /** Apply the file-wide convention to one analysed timestamp. */
  function finalizeTimestamp(analysis, convention) {
    if (!analysis) return null;
    const parts = Object.assign({}, analysis);

    if (parts.kind === 'ambiguous' && convention && convention.convention === 'day-first') {
      const swap = parts.day;
      parts.day = parts.month;
      parts.month = swap;
    }

    parts.ambiguous = analysis.kind === 'ambiguous';
    parts.ms = timestampToMs(parts);
    parts.valid = typeof parts.ms === 'number' && !isNaN(parts.ms);
    if (!parts.valid) parts.ms = null;
    return parts;
  }

  /** Human-readable, timezone-free representation for display. */
  function toIsoString(ms) {
    if (typeof ms !== 'number' || isNaN(ms)) return '';
    const d = new Date(ms);
    const pad = function (n) { return String(n).padStart(2, '0'); };
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' '
      + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  /** "1h 4m", "12m 30s", "45s" - used in reports and for time windows. */
  function formatDuration(ms) {
    if (typeof ms !== 'number' || isNaN(ms) || ms < 0) return '';
    const totalSeconds = Math.round(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (hours > 0) return hours + 'h ' + minutes + 'm';
    if (minutes > 0) return minutes + 'm ' + seconds + 's';
    return seconds + 's';
  }

  /* ------------------------------------------------------------------------
   * The main entry point: CSV text in, report-ready event list out
   * ------------------------------------------------------------------------
   * Everything above this point is a building block. This function is the one
   * the user interface calls, and the one the automated tests call.
   *
   * It NEVER throws. Any problem it cannot work around comes back as a result
   * object with ok:false and a plain-English explanation, because a crash tells
   * a beginner nothing.
   */
  function makeFailure(code, message, help, extra) {
    const result = {
      ok: false,
      version: VERSION,
      headers: [],
      ignoredColumns: [],
      mapping: {},
      matched: [],
      missing: CANONICAL_FIELDS.slice(),
      duplicates: [],
      events: [],
      skipped: [],
      warnings: [],
      errors: [{ code: code, message: message, help: help || '' }],
      dateConvention: null,
      delimiter: null,
      stats: null
    };
    if (extra) Object.assign(result, extra);
    return result;
  }

  function makeWarning(code, message) {
    return { code: code, message: message };
  }

  function parse(text, options) {
    const opts = options || {};
    const startedAt = Date.now();
    const rawText = String(text == null ? '' : text);

    /* --- Stage 0: is this even a text export we can read? --------------- */
    if (rawText.trim() === '') {
      return makeFailure('EMPTY_FILE',
        'That file appears to be empty - there is no text in it at all.',
        'Check that the export completed, and that you selected the file you expected.');
    }
    if (rawText.indexOf('ElfFile') === 0) {
      return makeFailure('EVTX_FILE',
        'That looks like a raw Windows event log file (.evtx), which this version cannot read.',
        'Export the events as CSV or tab-delimited text instead - see the export instructions at the top of this page. Raw .evtx support is listed as a future improvement, not something this version does.');
    }
    if (/\u0000/.test(rawText)) {
      return makeFailure('BINARY_FILE',
        'That file contains binary data, not readable text.',
        'This tool reads CSV or tab-delimited text exports. A raw .evtx file or a zipped log cannot be read here.');
    }

    /* --- Stage 1: work out the column separator ------------------------- */
    const delimiterInfo = opts.delimiter
      ? { char: opts.delimiter, label: labelForDelimiter(opts.delimiter), confident: true }
      : detectDelimiter(rawText);

    /* --- Stage 2: read the rows ----------------------------------------- */
    const parsed = parseDelimited(rawText, delimiterInfo.char);
    const rows = parsed.rows;

    if (!rows.length) {
      return makeFailure('NO_ROWS',
        'No rows could be read from that file.',
        'Check that it is really a delimited text file and that it is not corrupted.');
    }

    /* --- Stage 3: work out which column is which ------------------------ */
    const headers = rows[0].cells.map(cleanCell);
    const columnInfo = mapColumns(headers);

    if (!columnInfo.mapping.eventId) {
      // The Event ID is the one thing we genuinely cannot work without.
      const failure = makeFailure('MISSING_EVENT_ID_COLUMN',
        'The tool could not find an Event ID column, and that is the one column it cannot work without.',
        'Rename the column that holds the Windows Event ID to "Event ID" (or "Id" / "EventCode") and try again. The column names found in your file are listed below, so you can see what the tool saw.');
      failure.headers = headers;
      failure.mapping = columnInfo.mapping;
      failure.matched = columnInfo.matched;
      failure.missing = columnInfo.missing;
      failure.ignoredColumns = headers.filter(function (h) { return !ALIAS_INDEX[normalizeHeader(h)]; });
      failure.stats = { dataRows: Math.max(0, rows.length - 1), delimiterLabel: delimiterInfo.label };
      return failure;
    }

    /* --- Stage 4: turn every data row into an event ---------------------- */
    const events = [];
    const analyses = [];
    const skipped = [];
    const warnings = [];
    const dataRows = rows.slice(1);
    const rowLimit = Math.min(dataRows.length, LIMITS.maxRows);

    const valueOf = function (cells, field) {
      const column = columnInfo.mapping[field];
      if (!column) return '';
      return cleanCell(cells[column.index]);
    };

    for (let i = 0; i < rowLimit; i++) {
      const row = dataRows[i];
      const cells = row.cells;
      const eventIdRaw = valueOf(cells, 'eventId');
      const eventId = parseEventId(eventIdRaw);

      if (eventId === null) {
        skipped.push({
          line: row.line,
          reason: 'No usable Event ID in this row ("' + truncate(eventIdRaw, 30) + '")'
        });
        continue;
      }

      const accountRaw = valueOf(cells, 'account');
      const account = normalizeAccount(accountRaw);

      events.push({
        index: events.length,
        line: row.line,
        eventId: eventId,
        eventIdRaw: eventIdRaw,
        rawLevel: normalizeRawLevel(valueOf(cells, 'level')),
        rawLevelText: valueOf(cells, 'level'),
        account: account,
        accountRaw: accountRaw,
        accountKey: accountKeyOf(account),
        computer: valueOf(cells, 'computer'),
        sourceIpColumn: valueOf(cells, 'sourceIp'),
        source: valueOf(cells, 'source'),
        taskCategory: valueOf(cells, 'taskCategory'),
        keywords: valueOf(cells, 'keywords'),
        message: truncate(valueOf(cells, 'message'), LIMITS.maxMessageChars),
        timestamp: null,
        // Keeping every original cell would roughly double the memory used, so
        // it is off by default and only switched on by the automated tests.
        raw: opts.keepRaw ? cells.slice() : null
      });

      // Timestamps are collected in a parallel array so the indexes still line
      // up with `events` even when rows were skipped for having no Event ID.
      analyses.push(analyzeTimestamp(valueOf(cells, 'timestamp')));
    }

    /* Day/month order can only be judged with the whole file in hand, so the
     * timestamps are finalised after the loop, not during it. */
    const dateConvention = resolveDateConvention(analyses);
    events.forEach(function (event, i) {
      event.timestamp = finalizeTimestamp(analyses[i], dateConvention);
    });

    /* --- Stage 5: notes the user needs to know -------------------------- */
    const withTimestamp = events.filter(function (e) { return e.timestamp && e.timestamp.valid; }).length;
    const ambiguousCount = events.filter(function (e) { return e.timestamp && e.timestamp.ambiguous; }).length;

    if (columnInfo.missing.indexOf('timestamp') !== -1) {
      warnings.push(makeWarning('NO_TIMESTAMP_COLUMN',
        'No date/time column was found, so the timeline and any time-window correlation are switched off. The events themselves are still analysed.'));
    } else if (withTimestamp < events.length) {
      warnings.push(makeWarning('SOME_TIMESTAMPS_UNPARSED',
        (events.length - withTimestamp) + ' event(s) have a date/time the tool could not read. Those events are still analysed, but they cannot be placed on the timeline.'));
    }

    if (ambiguousCount > 0 && !dateConvention.confident) {
      warnings.push(makeWarning('AMBIGUOUS_DATES',
        'This file contains dates such as 03/04/2026, which could mean 3 April or 4 March depending on the regional settings of the machine that produced it, and the file gives no clue. The tool assumed US order (month/day). Time-window correlation is disabled for this file, because the order of events within a single day cannot be trusted.'));
    }
    if (columnInfo.missing.indexOf('message') !== -1) {
      warnings.push(makeWarning('NO_MESSAGE_COLUMN',
        'No message column was found. Events can still be listed, but details such as source IP address, logon type and group name cannot be read out of the message text.'));
    }
    if (columnInfo.missing.indexOf('account') !== -1) {
      warnings.push(makeWarning('NO_ACCOUNT_COLUMN',
        'No account column was found. Accounts are taken from the message text where possible; where they cannot be found, events are grouped as "unknown account", which weakens correlation.'));
    }
    if (parsed.unterminatedQuote) {
      warnings.push(makeWarning('UNBALANCED_QUOTES',
        'The file appears to end inside a quoted field, which suggests it was edited or truncated. Rows after that point may be wrong.'));
    }
    if (skipped.length) {
      warnings.push(makeWarning('SKIPPED_ROWS',
        skipped.length + ' row(s) were skipped because no usable Event ID could be read from them.'));
    }
    if (columnInfo.duplicates.length) {
      warnings.push(makeWarning('DUPLICATE_COLUMN',
        'More than one column looked like the same field (for example "User" and "Account Name"). The first one was used; the others were ignored.'));
    }
    if (dataRows.length > LIMITS.maxRows) {
      warnings.push(makeWarning('ROW_LIMIT_REACHED',
        'This file has ' + dataRows.length + ' data rows. Only the first ' + LIMITS.maxRows + ' were analysed, to keep the browser responsive.'));
    }
    if (!delimiterInfo.confident) {
      warnings.push(makeWarning('DELIMITER_UNCERTAIN',
        'The column separator could not be identified with complete confidence; ' + delimiterInfo.label + '-separated values were assumed. Check the preview below to confirm the columns line up.'));
    }

    /* --- Stage 6: statistics for the dashboard -------------------------- */
    let minMs = null;
    let maxMs = null;
    const eventIdCounts = {};

    events.forEach(function (e) {
      eventIdCounts[e.eventId] = (eventIdCounts[e.eventId] || 0) + 1;
      if (e.timestamp && e.timestamp.valid) {
        if (minMs === null || e.timestamp.ms < minMs) minMs = e.timestamp.ms;
        if (maxMs === null || e.timestamp.ms > maxMs) maxMs = e.timestamp.ms;
      }
    });

    // Time-based rules are only trustworthy when most events have a readable
    // time AND the day/month order is not a guess.
    const timelineReliable = withTimestamp > 0
      && withTimestamp >= events.length * 0.8
      && (ambiguousCount === 0 || dateConvention.confident);

    const stats = {
      dataRows: dataRows.length,
      rowsAnalysed: rowLimit,
      events: events.length,
      skipped: skipped.length,
      columnsFound: columnInfo.matched.length,
      columnsMissing: columnInfo.missing.length,
      delimiterLabel: delimiterInfo.label,
      delimiterConfident: delimiterInfo.confident,
      encoding: opts.encoding || 'utf-8',
      withTimestamp: withTimestamp,
      ambiguousTimestamps: ambiguousCount,
      timelineReliable: timelineReliable,
      timeRange: minMs === null ? null : { startMs: minMs, endMs: maxMs },
      distinctEventIds: Object.keys(eventIdCounts).length,
      eventIdCounts: eventIdCounts,
      elapsedMs: Date.now() - startedAt
    };

    return {
      ok: true,
      version: VERSION,
      headers: headers,
      ignoredColumns: headers.filter(function (h) { return !ALIAS_INDEX[normalizeHeader(h)]; }),
      mapping: columnInfo.mapping,
      matched: columnInfo.matched,
      missing: columnInfo.missing,
      duplicates: columnInfo.duplicates,
      events: events,
      skipped: skipped,
      warnings: warnings,
      errors: [],
      dateConvention: dateConvention,
      delimiter: delimiterInfo,
      stats: stats
    };
  }

  /* ------------------------------------------------------------------------
   * Convenience wrapper: raw bytes in, result out
   * ------------------------------------------------------------------------
   * The browser hands the page an ArrayBuffer, so the user interface calls this
   * instead of decodeBytes() + parse() separately.
   */
  function parseBytes(bytes, options) {
    const decoded = decodeBytes(bytes);
    if (decoded.error) {
      return makeFailure('DECODE_ERROR', decoded.error,
        'Try exporting the events again, or open the file in a text editor and save it as UTF-8.');
    }
    const opts = Object.assign({}, options || {}, { encoding: decoded.encoding });
    const result = parse(decoded.text, opts);
    result.encoding = decoded.encoding;
    if (result.stats) result.stats.encoding = decoded.encoding;
    return result;
  }

  /* ------------------------------------------------------------------------
   * Public surface
   * ------------------------------------------------------------------------
   * Everything the user interface (and the automated tests) are allowed to use.
   * Keeping this list explicit makes the contract obvious.
   */
  const TriageCore = {
    VERSION: VERSION,
    LIMITS: LIMITS,
    SEVERITY: SEVERITY,
    SEVERITY_RANK: SEVERITY_RANK,
    FIELD_LABELS: FIELD_LABELS,
    CANONICAL_FIELDS: CANONICAL_FIELDS,

    // Parsing
    parse: parse,
    parseBytes: parseBytes,
    decodeBytes: decodeBytes,
    parseDelimited: parseDelimited,
    detectDelimiter: detectDelimiter,
    mapColumns: mapColumns,
    normalizeHeader: normalizeHeader,
    normalizeRawLevel: normalizeRawLevel,
    normalizeAccount: normalizeAccount,
    accountKeyOf: accountKeyOf,
    isBlankValue: isBlankValue,
    parseEventId: parseEventId,
    truncate: truncate,

    // Timestamps
    analyzeTimestamp: analyzeTimestamp,
    resolveDateConvention: resolveDateConvention,
    finalizeTimestamp: finalizeTimestamp,
    toIsoString: toIsoString,
    formatDuration: formatDuration,

    // Severity
    severityRank: severityRank,
    higherSeverity: higherSeverity
  };

  /* Export for the browser, for Node (automated tests) and for globalThis. */
  if (typeof module !== 'undefined' && module && module.exports) module.exports = TriageCore;
  if (typeof window !== 'undefined') window.TriageCore = TriageCore;
  if (typeof globalThis !== 'undefined') globalThis.TriageCore = TriageCore;
})();









