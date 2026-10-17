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
   * than make the user choose, we test each candidate separator properly.
   *
   * HOW THIS WORKS, AND WHY IT IS NOT JUST COUNTING CHARACTERS
   * An earlier version counted separator characters on the first few physical
   * lines. That produced a false alarm on every realistic file, because a
   * Windows event Message is quoted text spanning several lines - the lines
   * inside it contain no commas at all, so the counts disagreed and the tool
   * claimed it was unsure. The correct approach is to actually parse the start
   * of the file with each candidate and see which one yields a consistent
   * number of columns per record.
   */
  const DELIMITERS = [
    { char: ',', label: 'comma' },
    { char: ';', label: 'semicolon' },
    { char: '\t', label: 'tab' },
    { char: '|', label: 'pipe' }
  ];

  function detectDelimiter(text) {
    const sample = String(text || '').slice(0, 20000);
    if (!sample.trim()) return { char: ',', label: 'comma', confident: false, counts: {} };

    const counts = {};
    let best = null;

    DELIMITERS.forEach(function (candidate) {
      const parsed = parseDelimited(sample, candidate.char);
      const columns = parsed.rows.slice(0, 5).map(function (record) { return record.cells.length; });
      const fields = columns.length ? columns[0] : 0;
      counts[candidate.label] = fields;

      // A usable separator produces more than one column, and every record it
      // reads should have the same shape.
      if (fields <= 1) return;

      const consistent = columns.every(function (count) { return count === fields; });
      const score = {
        char: candidate.char,
        label: candidate.label,
        fields: fields,
        consistent: consistent,
        confident: consistent
      };

      if (!best) { best = score; return; }
      // Prefer a separator that gives a consistent shape, then the one that
      // finds more columns (a comma file read as tab-separated would give one
      // column; a tab file read as comma-separated likewise).
      if (score.consistent !== best.consistent) {
        if (score.consistent) best = score;
        return;
      }
      if (score.fields > best.fields) best = score;
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
   * The Windows Event ID catalogue
   * ------------------------------------------------------------------------
   * The reference material for the ten events this version understands. Each
   * entry deliberately contains FIVE things:
   *
   *   description   what the event records, in plain English
   *   whyItMatters  what an analyst does with it
   *   baseSeverity  the INVESTIGATIVE priority of the event on its own
   *   benign        legitimate explanations, so a beginner does not assume the
   *                 worst
   *   nextSteps     what to go and check
   *
   * IMPORTANT: baseSeverity is about how much attention an event deserves, NOT
   * how likely it is to be an attack. No event ID here is "malicious", and the
   * code must never present one that way. Correlation may raise the priority of
   * a group of events later; a single event on its own does not.
   */
  const EVENT_CATALOGUE = {
    4624: {
      id: 4624,
      title: 'Successful logon',
      category: 'Authentication',
      description: 'A Windows account successfully signed in. The message records which account, the type of logon, and where it came from.',
      whyItMatters: 'On its own this is normal activity and should not be flagged. It is valuable as context: a success that follows a burst of failures tells a very different story, and a success on an account or device that should not be signing in is worth a look.',
      baseSeverity: 'Informational',
      benign: [
        'A person signing in to their own computer at the start of the day.',
        'A scheduled task or service account signing in automatically.',
        'An administrator connecting to a server to do legitimate work.'
      ],
      nextSteps: [
        'Check the logon type: 2 is someone at the keyboard, 10 is Remote Desktop.',
        'Check the source address, when the event contains one.',
        'Look for failures for the same account shortly before this success.',
        'Compare the time of day with what is normal for that account.'
      ]
    },
    4625: {
      id: 4625,
      title: 'Failed logon',
      category: 'Authentication',
      description: 'An attempt to sign in to a Windows account failed. The message records which account was tried and why it failed.',
      whyItMatters: 'One failure is ordinary and usually means somebody mistyped a password. A pattern of failures is more interesting, because it can be password guessing, a service using an old password, or simply a user who has forgotten theirs. The reason code in the message often explains which.',
      baseSeverity: 'Low',
      benign: [
        'A forgotten or mistyped password.',
        'A saved password on a phone, printer or backup job that has expired.',
        'A user signing in with an old cached credential or the wrong domain.',
        'An account that has been locked out after a password change.'
      ],
      nextSteps: [
        'Read the failure reason: "wrong password" and "no such user" mean different things.',
        'Count the failures for the same account, and over what period.',
        'Identify the source address or device the attempts came from.',
        'Check whether the failures were followed by a successful sign-in.',
        'Check whether other accounts were targeted from the same place.'
      ]
    },

    4688: {
      id: 4688,
      title: 'Process created',
      category: 'Process activity',
      description: 'A new process was started. When command-line auditing is switched on, the message also records the command that was run and the process that started it.',
      whyItMatters: 'This shows what actually ran on the machine. It is context rather than a warning: the same command can be routine administration or something worth reading. It is only recorded when process-creation auditing is enabled, so its absence proves nothing.',
      baseSeverity: 'Informational',
      benign: [
        'A user or application starting a program.',
        'An administrator running a script or a backup job.',
        'Windows or an installer starting its own components.'
      ],
      nextSteps: [
        'Read the full command line rather than just the program name.',
        'Check the parent process: what started it, and does that make sense?',
        'Note which account ran it and when.',
        'Compare it with what that account normally does.'
      ]
    },
    4720: {
      id: 4720,
      title: 'User account created',
      category: 'Account management',
      description: 'A new user account was created. The message names the new account and the account that created it.',
      whyItMatters: 'Creating accounts is normal administration, but it is also how an attacker gives themselves another way back in. The question is not "is this bad" but "was this expected, by whom, and is the account still needed".',
      baseSeverity: 'Medium',
      benign: [
        'A helpdesk or administrator onboarding a new employee.',
        'A temporary account created for a project or a test.',
        'An automated provisioning script doing its job.'
      ],
      nextSteps: [
        'Confirm with the team whether the account creation was requested and authorised.',
        'Identify the account that created it, and whether that account should be doing this.',
        'Check what the new account does next, and whether it is still needed.',
        'Look for privilege changes for the same account shortly afterwards.'
      ]
    },
    4726: {
      id: 4726,
      title: 'User account deleted',
      category: 'Account management',
      description: 'A user account was deleted. The message names the account that was removed and who removed it.',
      whyItMatters: 'Usually tidy administration, for example when somebody leaves. It can also be part of covering tracks, particularly when an account is created and deleted again within a short space of time.',
      baseSeverity: 'Low',
      benign: [
        'A leaver being offboarded.',
        'Clean-up of a temporary or test account.',
        'Removal of a duplicate account.'
      ],
      nextSteps: [
        'Check whether the account was expected to be removed.',
        'Look at what the account did before it was deleted.',
        'Check whether the same account was created recently, which is far more interesting.'
      ]
    },

    4728: {
      id: 4728,
      title: 'Member added to a global security group',
      category: 'Privilege change',
      description: 'An account was added to a global security group, such as Domain Admins. The message names the member, the group and who made the change.',
      whyItMatters: 'Group membership is how Windows grants power. Adding an account to a privileged group is a common step in privilege escalation and in keeping access, and it is also completely routine administration. The group name is the key detail.',
      baseSeverity: 'Medium',
      benign: [
        'A legitimate promotion, role change or project needing extra rights.',
        'An administrator adding a service account to a group it needs.',
        'A temporary grant that is documented and will be removed.'
      ],
      nextSteps: [
        'Identify the group: a privileged group deserves more attention than an ordinary one.',
        'Identify who made the change and whether it was authorised.',
        'Check whether the member account was created recently.',
        'Check what the member does next with the new rights.',
        'Confirm the membership is still required.'
      ]
    },
    4732: {
      id: 4732,
      title: 'Member added to a local security group',
      category: 'Privilege change',
      description: 'An account was added to a local security group on this computer, such as the local Administrators group. The message names the member, the group and who made the change.',
      whyItMatters: 'The same idea as a global group change, but local to one machine. Adding an account to local Administrators on a workstation is a well-known way to keep access to that machine, and it is also what happens when a helpdesk grants somebody admin rights.',
      baseSeverity: 'Medium',
      benign: [
        'A helpdesk granting local administrator rights to a user who needs them.',
        'Software installation that adds a service account to a local group.',
        'An administrator adding an account to Remote Desktop Users.'
      ],
      nextSteps: [
        'Identify the group: local Administrators is the one that matters most.',
        'Identify who made the change and whether it was requested.',
        'Check whether the member account was created recently.',
        'Check whether the member signs in afterwards and what it runs.',
        'Confirm the membership is still needed.'
      ]
    },

    1102: {
      id: 1102,
      title: 'Security audit log cleared',
      category: 'Defence evasion',
      description: 'The Windows Security audit log was cleared. The message names the account that cleared it.',
      whyItMatters: 'This event means the Security log was emptied. That can happen during legitimate maintenance, but clearing the log also destroys evidence, so attackers do it. Because the effect is to remove the record of other activity, this event normally deserves investigation even when nothing else looks wrong.',
      baseSeverity: 'High',
      benign: [
        'A technician clearing the log as part of a documented rebuild or handover.',
        'A lab machine being reset before an exercise.',
        'Log rotation or maintenance performed by a script.'
      ],
      nextSteps: [
        'Find out who cleared the log and whether they were authorised to.',
        'Check whether anything unusual happened shortly before the log was cleared.',
        'Check whether the same account did anything else of note in this data.',
        'Look for the same activity in another log or on another system, because this one has lost its history.'
      ]
    },
    4104: {
      id: 4104,
      title: 'PowerShell script block logged',
      category: 'Script activity',
      description: 'PowerShell recorded the text of a script block it executed. This requires PowerShell script block logging to be enabled.',
      whyItMatters: 'PowerShell script block logging can provide valuable visibility into commands and scripts executed on the endpoint. PowerShell itself is a normal administration tool, so this is not suspicious on its own; what matters is what the recorded script does. Where a script is encoded or heavily obfuscated it is worth reading closely, because that is often done to hide what a command does.',
      baseSeverity: 'Informational',
      benign: [
        'An administrator running a management or reporting script.',
        'A software deployment tool or monitoring agent using PowerShell internally.',
        'A signed vendor script doing routine maintenance.'
      ],
      nextSteps: [
        'Read the script text and work out what it actually does.',
        'If it is encoded or obfuscated, decode it before judging it.',
        'Check which account and which parent process ran it.',
        'Check whether the same script runs regularly on this machine.',
        'Note anything that downloads code or changes system settings.'
      ]
    },
    7045: {
      id: 7045,
      title: 'Service installed',
      category: 'Service installation',
      description: 'A new Windows service was installed. The message records the service name, the program it runs, and how it starts.',
      whyItMatters: 'Installing a service is how a lot of legitimate software makes itself start automatically, and it is also a classic way to make something start automatically when the machine boots. The detail that matters is what program the service points at, and where that program came from. Note that this event comes from the System log rather than the Security log.',
      baseSeverity: 'Medium',
      benign: [
        'Ordinary software installation, for example an agent or a printer driver.',
        'An approved monitoring or backup product being deployed.',
        'A Windows update or a feature being added.'
      ],
      nextSteps: [
        'Read the service file name: where does the program live, and does that folder look right?',
        'Check whether the software was installed by your team or by a user.',
        'Check when the service was installed relative to anything else unusual.',
        'Check whether the service is still present and what it runs as.'
      ]
    }
  };

  /** Look up an event ID, or return null when this version does not know it. */
  function getEventInfo(eventId) {
    return Object.prototype.hasOwnProperty.call(EVENT_CATALOGUE, String(eventId))
      ? EVENT_CATALOGUE[String(eventId)]
      : null;
  }

  /** True when this version has reference material for the event ID. */
  function isKnownEventId(eventId) {
    return getEventInfo(eventId) !== null;
  }

  /* ------------------------------------------------------------------------
   * Reading the event message, section by section
   * ------------------------------------------------------------------------
   * THIS IS THE PART THAT GETS ACCOUNT NAMES RIGHT, so it is worth explaining.
   *
   * A real Windows event message is structured text that looks like this:
   *
   *     An account was successfully logged on.
   *
   *     Subject:
   *      Security ID:  S-1-5-18
   *      Account Name: WIN10-LAB01$      <-- the COMPUTER account
   *
   *     New Logon:
   *      Account Name: jsmith            <-- the person who signed in
   *
   * Notice that "Account Name" appears twice and means two different things. A
   * tool that simply searches the message for the first "Account Name" reports
   * the computer's account instead of the user's. That is the most common
   * mistake in student-written log parsers, so the message is split into its
   * named blocks first and each value is then read from the block we want.
   *
   * Three views of the message are kept:
   *   sections[]   each named block with its own labels, in order
   *   labels{}     the FIRST occurrence of each label anywhere
   *   occurrences{} EVERY occurrence of each label, in order
   *
   * The first-occurrence view is convenient, but it is never used for account
   * names, for exactly the reason above.
   */
  function parseMessageSections(message) {
    const text = String(message == null ? '' : message);
    const result = { sections: [], labels: {}, occurrences: {}, notes: '', blank: true };
    if (!text.trim()) return result;

    result.blank = false;
    const intro = [];
    // Text before the first heading is kept as a section called "preamble",
    // because some events (4625, 4688) put useful lines there.
    let current = { name: 'preamble', labels: {}, lines: [] };
    result.sections.push(current);

    const push = function (store, key, value) {
      if (!Object.prototype.hasOwnProperty.call(store, key)) store[key] = value;
    };

    text.split(/\r\n|\r|\n/).forEach(function (line) {
      const trimmed = line.trim();
      if (!trimmed) return;

      // A heading is a label on a line by itself, for example "New Logon:".
      const heading = trimmed.match(/^([A-Za-z][A-Za-z0-9 ()\/\-,.']{2,58}):$/);
      if (heading) {
        current = { name: heading[1].trim(), labels: {}, lines: [] };
        result.sections.push(current);
        return;
      }

      // Otherwise it should be "Label: value".
      const pair = line.match(/^\s*([A-Za-z][A-Za-z0-9 ()\/\-,.']{0,48}?):\s*(.*)$/);
      if (pair) {
        const label = pair[1].trim();
        const value = pair[2].trim();
        const key = label.toLowerCase();
        push(current.labels, key, value);
        push(result.labels, key, value);
        if (!Object.prototype.hasOwnProperty.call(result.occurrences, key)) {
          result.occurrences[key] = [];
        }
        result.occurrences[key].push(value);
        return;
      }

      // Anything else (script text, remarks) is kept as free text.
      current.lines.push(trimmed);
      intro.push(trimmed);
    });

    result.notes = intro.join('\n');
    return result;
  }

  /** Find the first section whose name matches one of the given names. */
  function findSection(parsed, names) {
    if (!parsed || !parsed.sections) return null;
    const wanted = names.map(function (n) { return String(n).toLowerCase(); });
    for (let i = 0; i < parsed.sections.length; i++) {
      const section = parsed.sections[i];
      if (wanted.indexOf(section.name.toLowerCase()) !== -1) return section;
    }
    return null;
  }

  /**
   * Read a label from one of the named sections.
   * Returns '' when the section or the label is not present - never a guess.
   */
  function labelInSection(parsed, sectionNames, label) {
    const section = findSection(parsed, sectionNames);
    if (!section) return '';
    const key = String(label).toLowerCase();
    return Object.prototype.hasOwnProperty.call(section.labels, key) ? section.labels[key] : '';
  }

  /** Read the first occurrence of a label anywhere in the message. */
  function labelAnywhere(parsed, label) {
    if (!parsed || !parsed.labels) return '';
    const key = String(label).toLowerCase();
    return Object.prototype.hasOwnProperty.call(parsed.labels, key) ? parsed.labels[key] : '';
  }

  /**
   * Read the LAST occurrence of a label. Used only as a documented fallback for
   * older or unusual message formats where the expected section is missing. In
   * the standard formats the block we want comes after the Subject block, so the
   * last occurrence is the better guess - but it is still a fallback, and the
   * caller records that it had to use one.
   */
  function lastOccurrenceOf(parsed, label) {
    if (!parsed || !parsed.occurrences) return '';
    const list = parsed.occurrences[String(label).toLowerCase()];
    return list && list.length ? list[list.length - 1] : '';
  }

  /* ------------------------------------------------------------------------
   * Reference tables
   * ------------------------------------------------------------------------
   * These turn the numbers Windows writes into words a beginner can act on.
   * Nothing here changes a severity; it only explains what the number means.
   */
  const LOGON_TYPES = {
    '0': 'System (the operating system itself)',
    '2': 'Interactive (someone at the keyboard or console)',
    '3': 'Network (for example reaching a file share)',
    '4': 'Batch (a scheduled task)',
    '5': 'Service (a service starting under its own account)',
    '7': 'Unlock (a locked screen being unlocked)',
    '8': 'NetworkCleartext (the password was sent without encryption)',
    '9': 'NewCredentials (RunAs with saved credentials)',
    '10': 'RemoteInteractive (Remote Desktop / RDP)',
    '11': 'CachedInteractive (cached credentials, no domain controller reached)',
    '12': 'CachedRemoteInteractive (Remote Desktop using cached credentials)',
    '13': 'CachedUnlock (unlocking a screen with cached credentials)'
  };

  /* Windows writes these as "0xC000006A". The key is stored UPPERCASE because
   lookups are case-insensitive: a log may contain 0xc000006a, and an earlier
   version of this table used a lowercase "x" which never matched after the
   input was uppercased. */
  const FAILURE_CODES = {
    '0XC0000064': 'the account name does not exist',
    '0XC000006A': 'the password was wrong',
    '0XC000006D': 'the user name or password was wrong',
    '0XC000006E': 'an account restriction blocked the logon',
    '0XC000006F': 'the logon was outside the permitted hours',
    '0XC0000070': 'the logon came from a computer that is not permitted',
    '0XC0000071': 'the password has expired',
    '0XC0000072': 'the account is disabled',
    '0XC000015B': 'this account is not permitted to log on this way',
    '0XC000018B': 'the trust relationship with the domain failed',
    '0XC0000193': 'the account has expired',
    '0XC0000224': 'the user must change their password before signing in',
    '0XC0000234': 'the account is locked out'
  };

  function describeLogonType(raw) {
    const key = cleanCell(raw);
    if (!key) return '';
    return Object.prototype.hasOwnProperty.call(LOGON_TYPES, key) ? LOGON_TYPES[key] : '';
  }

  function describeFailureCode(raw) {
    // Lookups are case-insensitive: Windows writes "0xC000006A" and some tools
    // write "0xc000006a", and both should resolve to the same explanation.
    const key = cleanCell(raw).replace(/\s+/g, '').toUpperCase();
    if (!key) return '';
    return Object.prototype.hasOwnProperty.call(FAILURE_CODES, key) ? FAILURE_CODES[key] : '';
  }

  /**
   * Groups that normally carry real power in Windows.
   *
   * IMPORTANT: membership of one of these groups is not wrongdoing. It changes
   * how much attention a change deserves, which is a different thing. Names are
   * compared case-insensitively, and a group whose name contains "admin" is
   * treated as privileged as well. That last part is a heuristic, and findings
   * that rely on it say so instead of presenting it as a fact.
   */
  const PRIVILEGED_GROUPS = [
    'administrators',
    'domain admins',
    'enterprise admins',
    'schema admins',
    'account operators',
    'server operators',
    'backup operators',
    'print operators',
    'hyper-v administrators',
    'remote desktop users',
    'group policy creator owners',
    'protected users',
    'dnsadmins',
    'cert publishers',
    'domain controllers',
    'network configuration operators',
    'performance log users'
  ];

  function assessGroup(groupName) {
    const name = cleanCell(groupName);
    if (!name) {
      return { name: '', privileged: false, reason: 'the group name was not found in this event' };
    }
    const lower = name.toLowerCase();
    if (PRIVILEGED_GROUPS.indexOf(lower) !== -1) {
      return { name: name, privileged: true, reason: '"' + name + '" is a group that normally carries elevated rights' };
    }
    if (lower.indexOf('admin') !== -1) {
      return { name: name, privileged: true, reason: 'the group name contains "admin", so it probably carries elevated rights' };
    }
    return {
      name: name,
      privileged: false,
      reason: '"' + name + '" is not in this tool\'s list of groups that normally carry elevated rights'
    };
  }

  /**
   * Normalise a source address.
   *
   * Windows writes placeholders instead of empty values: "-", "::1", "127.0.0.1"
   * or "0.0.0.0". These are not addresses an analyst can investigate, and
   * treating them as one would create misleading findings, so each is labelled
   * for what it is.
   */
  function normalizeSourceIp(raw) {
    const value = cleanCell(raw).replace(/^\[|\]$/g, '');
    if (!value || isBlankValue(value)) {
      return { ip: '', kind: 'unavailable', label: 'not available in this event' };
    }
    if (value === '::1' || value === '127.0.0.1' || value === '::ffff:127.0.0.1') {
      return { ip: value, kind: 'local', label: 'the local computer (loopback address)' };
    }
    if (value === '0.0.0.0' || value === '::' || value === '*') {
      return { ip: value, kind: 'unspecified', label: 'not specified by Windows' };
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
      const parts = value.split('.').map(Number);
      const isPrivate = parts[0] === 10
        || (parts[0] === 192 && parts[1] === 168)
        || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31);
      return {
        ip: value,
        kind: isPrivate ? 'private' : 'routable',
        label: value + (isPrivate ? ' (a private network address)' : '')
      };
    }
    if (value.indexOf(':') !== -1 && /^[0-9a-fA-F:.]+$/.test(value)) {
      return { ip: value, kind: 'ipv6', label: value + ' (an IPv6 address)' };
    }
    return { ip: value, kind: 'unrecognised', label: value };
  }

  /* ------------------------------------------------------------------------
   * Hints in a PowerShell script block
   * ------------------------------------------------------------------------
   * PowerShell is a normal administration tool and this code must never claim
   * otherwise. What it does do is point out text an analyst would want to read
   * more closely, and explain WHY each one is worth reading. Every hint is
   * phrased as an observation about the text, not as a judgement about intent.
   */
  const SCRIPT_HINTS = [
    {
      pattern: /-enc(odedcommand)?\b/i,
      text: 'the command was supplied with -EncodedCommand, so the script text is a base64 blob rather than something readable'
    },
    {
      pattern: /frombase64string|\[convert\]\s*::/i,
      text: 'the script converts base64 text back into code while it runs'
    },
    {
      pattern: /[A-Za-z0-9+\/]{80,}={0,2}/,
      text: 'the script contains a long base64-looking string'
    },
    {
      pattern: /(^|[^a-z])(iex|invoke-expression)\b/i,
      text: 'the script builds a command from text and then runs it (Invoke-Expression)'
    },
    {
      pattern: /downloadstring|downloadfile|invoke-webrequest|start-bitstransfer|net\.webclient/i,
      text: 'the script can download content from the network'
    },
    {
      pattern: /-w(indowstyle)?\s+hidden|-nop(rofile)?\b|-exec(utionpolicy)?\s+bypass/i,
      text: 'the script was started with flags often used to run quietly or to bypass policy'
    },
    {
      pattern: /\[char\]\s*\d+|`[a-z]/i,
      text: 'the script builds its text in an unusual way, using character codes or escape characters'
    }
  ];

  /**
   * Return up to three plain-English observations about a script.
   * An empty list means nothing stood out - NOT that the script is safe.
   */
  function describeScriptHints(scriptText) {
    const text = String(scriptText == null ? '' : scriptText);
    if (!text.trim()) return [];
    const found = [];
    SCRIPT_HINTS.forEach(function (hint) {
      if (found.length >= 3) return;
      if (hint.pattern.test(text)) found.push(hint.text);
    });
    return found;
  }

  /* ------------------------------------------------------------------------
   * Per-event field extraction
   * ------------------------------------------------------------------------
   * For each event ID, the code below knows exactly which block holds which
   * value. When a value is not present the field is left EMPTY and its name is
   * added to `missing`, so a report can say "not present in this event" instead
   * of inventing something.
   *
   * `accountBlock` records WHICH block the account came from. It is the string
   * 'fallback' when the expected block was absent and the last occurrence had to
   * be used, so a report can be honest about how confident the extraction is.
   */
  function extractEventFields(event) {
    const parsed = parseMessageSections(event.message);
    const fields = {
      account: '',
      accountBlock: '',
      actor: '',
      targetAccount: '',
      memberAccount: '',
      groupName: '',
      groupDomain: '',
      groupIsPrivileged: false,
      groupReason: '',
      logonType: '',
      logonTypeText: '',
      failureReason: '',
      statusCode: '',
      statusText: '',
      subStatusCode: '',
      subStatusText: '',
      sourceIp: '',
      sourceIpKind: '',
      sourceIpLabel: '',
      workstation: '',
      process: '',
      parentProcess: '',
      processId: '',
      commandLine: '',
      serviceName: '',
      servicePath: '',
      serviceType: '',
      serviceStartType: '',
      serviceAccount: '',
      scriptText: '',
      scriptHints: [],
      missing: []
    };

    const id = event.eventId;

    /* ---- values that appear in several event types ---------------------- */
    fields.sourceIp = labelInSection(parsed, ['network information'], 'source network address')
      || labelAnywhere(parsed, 'source network address')
      || event.sourceIpColumn; // last resort: a dedicated column, if the export had one
    fields.workstation = labelInSection(parsed, ['network information'], 'workstation name')
      || labelAnywhere(parsed, 'workstation name');
    fields.logonType = labelInSection(parsed, ['logon information'], 'logon type')
      || labelAnywhere(parsed, 'logon type');
    fields.logonTypeText = describeLogonType(fields.logonType);

    /* ---- 4624 successful logon ------------------------------------------ */
    if (id === 4624) {
      // THE KEY RULE: the account is the one in "New Logon", never the machine
      // account in "Subject".
      const fromNewLogon = labelInSection(parsed, ['new logon'], 'account name');
      if (fromNewLogon) {
        fields.account = fromNewLogon;
        fields.accountBlock = 'New Logon';
      } else {
        const fallback = lastOccurrenceOf(parsed, 'account name');
        fields.account = fallback;
        fields.accountBlock = fallback ? 'fallback' : '';
      }
      fields.actor = fields.account;
    }

    /* ---- 4625 failed logon --------------------------------------------- */
    if (id === 4625) {
      const fromFailed = labelInSection(parsed, ['account for which logon failed'], 'account name');
      if (fromFailed) {
        fields.account = fromFailed;
        fields.accountBlock = 'Account For Which Logon Failed';
      } else {
        const fallback = lastOccurrenceOf(parsed, 'account name');
        fields.account = fallback;
        fields.accountBlock = fallback ? 'fallback' : '';
      }
      fields.actor = fields.account;
      fields.failureReason = labelInSection(parsed, ['failure information'], 'failure reason')
        || labelAnywhere(parsed, 'failure reason');
      fields.statusCode = labelInSection(parsed, ['failure information'], 'status')
        || labelAnywhere(parsed, 'status');
      fields.statusText = describeFailureCode(fields.statusCode);
      fields.subStatusCode = labelInSection(parsed, ['failure information'], 'sub status')
        || labelAnywhere(parsed, 'sub status');
      fields.subStatusText = describeFailureCode(fields.subStatusCode);
    }

    /* ---- 4688 process created ------------------------------------------- */
    if (id === 4688) {
      fields.process = labelAnywhere(parsed, 'new process name');
      fields.parentProcess = labelAnywhere(parsed, 'creator process name');
      fields.processId = labelAnywhere(parsed, 'new process id');
      fields.commandLine = labelAnywhere(parsed, 'process command line');
      const subject = labelInSection(parsed, ['subject'], 'account name');
      fields.actor = subject;
      fields.account = subject || labelAnywhere(parsed, 'account name');
      fields.accountBlock = subject ? 'Subject' : (fields.account ? 'fallback' : '');
    }

    /* ---- 4720 / 4726 account created / deleted --------------------------- */
    if (id === 4720 || id === 4726) {
      const target = labelInSection(parsed, ['new account', 'target account'], 'account name');
      if (target) {
        fields.targetAccount = target;
        fields.accountBlock = id === 4720 ? 'New Account' : 'Target Account';
      } else {
        fields.targetAccount = lastOccurrenceOf(parsed, 'account name');
        fields.accountBlock = fields.targetAccount ? 'fallback' : '';
      }
      fields.actor = labelInSection(parsed, ['subject'], 'account name');
      // Grouping uses the account that was created or deleted, because that is
      // what a later privilege change will refer to.
      fields.account = fields.targetAccount || fields.actor;
    }

    /* ---- 4728 / 4732 privilege changes ----------------------------------- */
    if (id === 4728 || id === 4732) {
      const member = labelInSection(parsed, ['member'], 'account name');
      if (member) {
        fields.memberAccount = member;
        fields.accountBlock = 'Member';
      } else {
        fields.memberAccount = lastOccurrenceOf(parsed, 'account name');
        fields.accountBlock = fields.memberAccount ? 'fallback' : '';
      }
      fields.groupName = labelInSection(parsed, ['group'], 'group name') || labelAnywhere(parsed, 'group name');
      fields.groupDomain = labelInSection(parsed, ['group'], 'group domain');
      fields.actor = labelInSection(parsed, ['subject'], 'account name');
      const assessment = assessGroup(fields.groupName);
      fields.groupIsPrivileged = assessment.privileged;
      fields.groupReason = assessment.reason;
      // Grouping uses the member account, so a "created then privileged"
      // correlation can line up with the matching 4720.
      fields.account = fields.memberAccount || fields.actor;
    }

    /* ---- 1102 audit log cleared ------------------------------------------ */
    if (id === 1102) {
      const subject = labelInSection(parsed, ['subject'], 'account name');
      fields.actor = subject;
      fields.account = subject || labelAnywhere(parsed, 'account name');
      fields.accountBlock = subject ? 'Subject' : (fields.account ? 'fallback' : '');
    }

    /* ---- 4104 PowerShell script block ------------------------------------ */
    if (id === 4104) {
      // The script itself is the free text of the "Creating Scriptblock text"
      // block. Anything that was not a "Label: value" line went there.
      const block = findSection(parsed, ['creating scriptblock text']) || findSection(parsed, ['scriptblock text']);
      const lines = block && block.lines && block.lines.length
        ? block.lines
        : (parsed.notes ? parsed.notes.split('\n') : []);
      fields.scriptText = lines.join('\n');
      fields.scriptHints = describeScriptHints(fields.scriptText);
      const subject = labelAnywhere(parsed, 'account name');
      fields.actor = subject;
      fields.account = subject;
      fields.accountBlock = subject ? 'Account Name' : '';
    }

    /* ---- 7045 service installed ------------------------------------------ */
    if (id === 7045) {
      fields.serviceName = labelAnywhere(parsed, 'service name');
      fields.servicePath = labelAnywhere(parsed, 'service file name');
      fields.serviceType = labelAnywhere(parsed, 'service type');
      fields.serviceStartType = labelAnywhere(parsed, 'service start type');
      fields.serviceAccount = labelAnywhere(parsed, 'service account name')
        || labelAnywhere(parsed, 'service account');
      // A 7045 comes from the System log and names no account in its message.
      // fields.account is therefore left EMPTY on purpose, so enrichEvent falls
      // back to the CSV column and reports accountSource as 'column'. Setting it
      // here would have made the report claim the column value came from the
      // message, which would be untrue.
      fields.actor = fields.serviceAccount;
    }

    /* ---- normalise the source address once, for every event type --------- */
    const address = normalizeSourceIp(fields.sourceIp);
    fields.sourceIpKind = address.kind;
    fields.sourceIpLabel = address.label;

    /* ---- what we looked for but could not find ---------------------------
     * This list lets a report say "the source address is not present in this
     * event" instead of showing a blank that looks like an oversight.
     */
    const wanted = {};
    if (id === 4624 || id === 4625) {
      wanted.logonType = 'logon type';
      wanted.sourceIp = 'source address';
      wanted.workstation = 'workstation name';
    }
    if (id === 4688) {
      wanted.process = 'process name';
      wanted.parentProcess = 'parent process';
      wanted.commandLine = 'command line (command-line auditing may be switched off)';
    }
    if (id === 4720 || id === 4726) {
      wanted.actor = 'account that made the change';
    }
    if (id === 4728 || id === 4732) {
      wanted.groupName = 'group name';
      wanted.actor = 'account that made the change';
    }
    if (id === 1102) {
      wanted.actor = 'account that cleared the log';
    }
    if (id === 4104) {
      wanted.scriptText = 'script text';
    }
    if (id === 7045) {
      wanted.serviceName = 'service name';
      wanted.servicePath = 'service file name';
    }

    Object.keys(wanted).forEach(function (key) {
      if (!fields[key]) fields.missing.push(wanted[key]);
    });
    if (!fields.account) fields.missing.push('account name');

    return { fields: fields, parsed: parsed };
  }

  /**
   * Attach the catalogue entry and the extracted fields to every event.
   *
   * This also decides which account an event should be GROUPED by. That choice
   * matters for correlation, and it is made per event type rather than by taking
   * whatever the User column happened to contain:
   *
   *   4624  the account that signed in (New Logon), not the computer
   *   4625  the account that was attempted, not the computer
   *   4720  the account that was CREATED
   *   4726  the account that was DELETED
   *   4728  the account ADDED to the group
   *   4732  the account ADDED to the group
   *   1102  the account that cleared the log
   *   4688  the account that ran the process
   *   4104  the account that ran the script
   *   7045  from the log itself, normally SYSTEM
   *
   * The original column value is kept as accountFromColumn, and accountSource
   * records whether the value came from the message, from the column, or from
   * neither, so nothing is hidden from the reader.
   */
  function enrichEvent(event) {
    const info = getEventInfo(event.eventId);
    const extracted = extractEventFields(event);
    const fields = extracted.fields;

    const fromColumn = normalizeAccount(event.accountRaw);
    const fromMessage = normalizeAccount(fields.account);

    event.catalogue = info;
    event.title = info ? info.title : 'Event ID ' + event.eventId + ' (not covered by this version)';
    event.category = info ? info.category : 'Unrecognised';
    event.recognised = !!info;
    event.baseSeverity = info ? info.baseSeverity : 'Informational';
    event.fields = fields;
    event.sectionsParsed = extracted.parsed.sections.length;
    event.sectionNames = extracted.parsed.sections.map(function (s) { return s.name; });

    event.accountFromColumn = fromColumn;
    if (fromMessage) {
      event.account = fromMessage;
      event.accountSource = 'message';
    } else if (fromColumn) {
      event.account = fromColumn;
      event.accountSource = 'column';
    } else {
      event.account = '';
      event.accountSource = 'none';
    }
    event.accountKey = accountKeyOf(event.account);

    // An unrecognised event still gets a reference object, so the interface and
    // the later rules never have to check for null in two different ways.
    if (!info) {
      event.catalogue = {
        id: event.eventId,
        title: 'Event ID ' + event.eventId,
        category: 'Unrecognised',
        description: 'This tool does not have reference material for this Event ID yet, so it is counted but not explained.',
        whyItMatters: 'Unknown events are kept in the totals so that nothing is hidden. They are never treated as suspicious simply because they are unfamiliar.',
        baseSeverity: 'Informational',
        benign: [],
        nextSteps: [
          'Look the Event ID up in Microsoft documentation if you need to know what it records.',
          'Version 1 of this tool only explains the ten Event IDs listed in the reference section.'
        ]
      };
    }

    return event;
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

    /* --- Stage 4b: recognise each event and read its details --------------
     * This is where the account names, logon types, source addresses, groups,
     * processes and service names are pulled out of the message text. */
    events.forEach(enrichEvent);

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

    /* Recognition summary: which known Event IDs appeared, and how often. Built
     * here rather than in the interface so the automated tests can check it. */
    let recognisedCount = 0;
    const recognised = [];
    const unrecognisedCounts = {};

    Object.keys(eventIdCounts).forEach(function (key) {
      const id = Number(key);
      const info = getEventInfo(id);
      if (info) {
        recognisedCount += eventIdCounts[key];
        recognised.push({
          eventId: id,
          count: eventIdCounts[key],
          title: info.title,
          category: info.category,
          baseSeverity: info.baseSeverity
        });
      } else {
        unrecognisedCounts[id] = eventIdCounts[key];
      }
    });

    recognised.sort(function (a, b) { return b.count - a.count || a.eventId - b.eventId; });

    // How many accounts could actually be identified? If the messages could not
    // be read, correlation quality drops and the report should say so.
    const withAccount = events.filter(function (e) { return !!e.account; }).length;
    const accountFromMessage = events.filter(function (e) { return e.accountSource === 'message'; }).length;

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
      recognisedEvents: recognisedCount,
      unrecognisedEvents: events.length - recognisedCount,
      recognisedEventIds: recognised,
      unrecognisedEventIds: unrecognisedCounts,
      eventsWithAccount: withAccount,
      accountsFoundInMessage: accountFromMessage,
      accountsFoundInColumn: events.filter(function (e) { return e.accountSource === 'column'; }).length,
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

    // Event recognition and field extraction
    EVENT_CATALOGUE: EVENT_CATALOGUE,
    getEventInfo: getEventInfo,
    isKnownEventId: isKnownEventId,
    parseMessageSections: parseMessageSections,
    findSection: findSection,
    labelInSection: labelInSection,
    labelAnywhere: labelAnywhere,
    lastOccurrenceOf: lastOccurrenceOf,
    extractEventFields: extractEventFields,
    enrichEvent: enrichEvent,
    describeLogonType: describeLogonType,
    describeFailureCode: describeFailureCode,
    describeScriptHints: describeScriptHints,
    assessGroup: assessGroup,
    normalizeSourceIp: normalizeSourceIp,
    LOGON_TYPES: LOGON_TYPES,
    FAILURE_CODES: FAILURE_CODES,
    PRIVILEGED_GROUPS: PRIVILEGED_GROUPS,

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









