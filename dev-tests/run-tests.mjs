/* ==========================================================================
   dev-tests/run-tests.mjs
   --------------------------------------------------------------------------
   Automated checks for the analysis engine and for the security promises this
   project makes. Run with:   node dev-tests/run-tests.mjs

   This file is NOT part of the application. It exists so the parsing rules can
   be proven to work without a human clicking around in a browser. There is no
   browser available in the development sandbox, so this is how the engine is
   validated.

   It requires nothing to be installed: plain Node, no packages.
   ========================================================================== */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');

const Core = require(path.join(root, 'triage-core.js'));

/* --------------------------------------------------------------------------
   Tiny test runner
   -------------------------------------------------------------------------- */
let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log('  \x1b[32mPASS\x1b[0m  ' + name);
  } catch (err) {
    failed++;
    failures.push({ name: name, error: err });
    console.log('  \x1b[31mFAIL\x1b[0m  ' + name + '\n        ' + err.message);
  }
}

function group(title) {
  console.log('\n\x1b[1m' + title + '\x1b[0m');
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Expected a truthy value');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error((message ? message + ' - ' : '') + 'expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
  }
}

function assertIncludes(haystack, needle, message) {
  const text = String(haystack == null ? '' : haystack);
  if (text.indexOf(needle) === -1) {
    throw new Error((message ? message + ' - ' : '') + 'expected to find ' + JSON.stringify(needle) + ' in ' + JSON.stringify(text.slice(0, 200)));
  }
}

function codesOf(list) {
  return (list || []).map(function (item) { return item.code; });
}

/* --------------------------------------------------------------------------
   Test fixtures
   --------------------------------------------------------------------------
   Written as strings rather than files so every awkward edge case lives next to
   the assertion that explains it.
   -------------------------------------------------------------------------- */

/* A realistic Event Viewer style export: comma separated, quoted, with a
   byte-order mark, CRLF line endings, an embedded comma, an escaped double
   quote and real newlines inside the Message cell. */
const COMMA_FIXTURE = '\uFEFF' + [
  '"Level","Date and Time","Source","Event ID","Task Category","User","Computer","Keywords","Message"',
  '"Information","2026-04-03T14:22:11","Microsoft-Windows-Security-Auditing","4624","Logon","LAB\\jsmith","WIN10-LAB01","Audit Success","An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\tS-1-5-18\n\tAccount Name:\tWIN10-LAB01$\n\nNew Logon:\n\tAccount Name:\tjsmith\n\tLogon Type:\t2\n\tSource Network Address:\t192.168.10.25\n\nHe said ""hello"", then left."',
  '"Information","2026-04-03T14:25:00","Microsoft-Windows-Security-Auditing","4625","Logon","LAB\\jsmith","WIN10-LAB01","Audit Failure","An account failed to log on, twice."',
  '"Information","2026-04-03T14:26:00","Microsoft-Windows-Security-Auditing","4634","Logoff","LAB\\jsmith","WIN10-LAB01","Audit Success","An account was logged off."'
].join('\r\n');

/* The "Text (Tab delimited)" export Event Viewer offers. The message contains
   commas on purpose, which would break a naive comma splitter. */
const TAB_FIXTURE = [
  ['Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'User', 'Computer', 'Message'].join('\t'),
  ['Information', '2026-04-03T09:00:00', 'Microsoft-Windows-Security-Auditing', '4624', 'Logon', 'LAB\\ajones', 'WIN10-LAB02', 'Logged on, from the console.'].join('\t'),
  ['Information', '2026-04-03T09:05:00', 'Microsoft-Windows-Security-Auditing', '4625', 'Logon', 'LAB\\ajones', 'WIN10-LAB02', 'Failed, password wrong.'].join('\t')
].join('\r\n');

/* A European style export: semicolons and dotted day-first dates. */
const SEMICOLON_FIXTURE = [
  '"Level";"Date and Time";"Source";"Event ID";"Task Category";"User";"Computer";"Keywords";"Message"',
  '"Information";"25.12.2026 09:15:00";"Microsoft-Windows-Security-Auditing";"4624";"Logon";"LAB\\bjones";"WIN10-LAB03";"Audit Success";"An account was successfully logged on."'
].join('\r\n');

/* No Event ID column at all: the one thing the tool cannot work without. */
const NO_EVENT_ID_FIXTURE = [
  '"Level","Date and Time","Source","Task Category","User","Computer","Keywords","Message"',
  '"Information","2026-04-03T14:22:11","Microsoft-Windows-Security-Auditing","Logon","LAB\\jsmith","WIN10-LAB01","Audit Success","An account was successfully logged on."'
].join('\r\n');

/* Deliberately messy: a non-numeric Event ID, an unreadable date, and a file
   that ends inside a quoted cell. */
const MALFORMED_FIXTURE = [
  '"Event ID","Date and Time","User","Message"',
  '"4624","2026-04-03T10:00:00","LAB\\jsmith","Good row"',
  '"abc","2026-04-03T10:01:00","LAB\\jsmith","Bad event id"',
  '"4625","not-a-date","LAB\\jsmith","Unreadable timestamp"',
  '"4625","2026-04-03T10:02:00","LAB\\jsmith","Unterminated quote'
].join('\r\n');

/* Hostile input: HTML and JavaScript inside CSV cells. It must be treated as
   data and never as markup. */
const XSS_FIXTURE = [
  '"Event ID","Date and Time","User","Computer","Message"',
  '"4625","2026-04-03T10:00:00","<script>alert(1)</script>","<img src=x onerror=alert(2)>","Failed logon from <b>attacker</b> "><script>alert(3)</script>"'
].join('\r\n');

/* Every date is genuinely ambiguous: 03/04 could be 3 April or 4 March. */
const AMBIGUOUS_DATES_FIXTURE = [
  '"Event ID","Date and Time","User"',
  '"4624","03/04/2026 09:00:00","LAB\\jsmith"',
  '"4625","03/04/2026 09:01:00","LAB\\jsmith"',
  '"4625","04/04/2026 09:02:00","LAB\\jsmith"'
].join('\r\n');

/* Here one row proves the file is month-first (12/25 cannot be day/month), so
   the ambiguous rows can be resolved with confidence. */
const MONTH_FIRST_CLUE_FIXTURE = [
  '"Event ID","Date and Time","User"',
  '"4624","12/25/2026 09:00:00","LAB\\jsmith"',
  '"4624","03/04/2026 09:05:00","LAB\\jsmith"'
].join('\r\n');

/* Both a "User" and an "Account Name" column: the clash must be reported. */
const DUPLICATE_COLUMN_FIXTURE = [
  '"Event ID","Date and Time","User","Account Name"',
  '"4624","2026-04-03T10:00:00","LAB\\jsmith","jsmith"'
].join('\r\n');

/* Blank placeholders that Windows writes instead of leaving a cell empty. */
const BLANK_ACCOUNT_FIXTURE = [
  '"Event ID","Date and Time","User","Computer"',
  '"4624","2026-04-03T10:00:00","-","WIN10-LAB01"',
  '"4624","2026-04-03T10:01:00","N/A","WIN10-LAB01"'
].join('\r\n');

/* A PowerShell `Get-WinEvent | Export-Csv` style export: different column
   names, ISO timestamps, and an "Account" column. */
const POWERSHELL_FIXTURE = [
  '"TimeCreated","Id","LevelDisplayName","ProviderName","TaskDisplayName","KeywordsDisplayNames","Account","Message"',
  '"2026-04-03T14:22:11","4624","Information","Microsoft-Windows-Security-Auditing","Logon","Audit Success","LAB\\jsmith","An account was successfully logged on."',
  '"2026-04-03T14:25:00","4625","Information","Microsoft-Windows-Security-Auditing","Logon","Audit Failure","LAB\\jsmith","An account failed to log on."'
].join('\r\n');

/* --------------------------------------------------------------------------
   Tests: reading the CSV
   -------------------------------------------------------------------------- */
group('CSV reading');

test('comma separated Event Viewer export is read correctly', function () {
  const result = Core.parse(COMMA_FIXTURE);
  assert(result.ok, 'parse should succeed');
  assertEqual(result.delimiter.label, 'comma');
  assertEqual(result.stats.dataRows, 3, 'three data rows');
  assertEqual(result.stats.events, 3, 'three events');
  assertEqual(result.events.map(function (e) { return e.eventId; }).join(','), '4624,4625,4634');
  assertEqual(result.stats.skipped, 0, 'nothing should be skipped');
});

test('a byte-order mark does not break the first column name', function () {
  const result = Core.parse(COMMA_FIXTURE);
  assertEqual(result.mapping.eventId.header, 'Event ID', 'the BOM must be stripped from the header');
  assertEqual(result.mapping.timestamp.header, 'Date and Time');
  assertEqual(result.mapping.message.header, 'Message');
});

test('quoted cells keep their commas, escaped quotes and line breaks', function () {
  const message = Core.parse(COMMA_FIXTURE).events[0].message;
  assertIncludes(message, 'He said "hello", then left.', 'escaped quotes must survive');
  assertIncludes(message, 'Account Name:\tWIN10-LAB01$', 'tabs inside a cell must survive');
  assertIncludes(message, '\n', 'newlines inside a cell must survive');
});

test('tab separated export is detected and parsed', function () {
  const result = Core.parse(TAB_FIXTURE);
  assert(result.ok);
  assertEqual(result.delimiter.label, 'tab');
  assertEqual(result.stats.events, 2);
  assertIncludes(result.events[0].message, 'Logged on, from the console.',
    'a comma inside a tab separated file must not split the row');
});

test('semicolon separated export is detected and parsed', function () {
  const result = Core.parse(SEMICOLON_FIXTURE);
  assert(result.ok);
  assertEqual(result.delimiter.label, 'semicolon');
  assertEqual(result.stats.events, 1);
});

test('PowerShell Export-Csv column names are understood', function () {
  const result = Core.parse(POWERSHELL_FIXTURE);
  assert(result.ok);
  assertEqual(result.mapping.eventId.header, 'Id');
  assertEqual(result.mapping.timestamp.header, 'TimeCreated');
  assertEqual(result.mapping.level.header, 'LevelDisplayName');
  assertEqual(result.mapping.source.header, 'ProviderName');
  assertEqual(result.mapping.taskCategory.header, 'TaskDisplayName');
  assertEqual(result.mapping.keywords.header, 'KeywordsDisplayNames');
  assertEqual(result.mapping.account.header, 'Account');
  assertEqual(result.stats.events, 2);
});

test('columns the tool does not need are listed as ignored, not treated as errors', function () {
  const result = Core.parse(['"Event ID","Something Else","Message"', '"4624","ignore me","text"'].join('\n'));
  assert(result.ok);
  assertEqual(result.ignoredColumns.length, 1);
  assertEqual(result.ignoredColumns[0], 'Something Else');
});

test('header name variants all map to Event ID', function () {
  ['Event ID', 'EventID', 'event_id', 'Event-ID', 'Event Code', 'Id'].forEach(function (name) {
    const info = Core.mapColumns([name, 'Message']);
    assert(info.mapping.eventId, '"' + name + '" should map to the Event ID field');
  });
});

test('a file with no recognisable headers does not throw', function () {
  const info = Core.mapColumns(['Totally Unrelated', 'Another One']);
  assertEqual(info.matched.length, 0);
  assertEqual(info.missing.length, Core.CANONICAL_FIELDS.length);
});

test('domain prefixes are stripped from account names', function () {
  assertEqual(Core.parse(COMMA_FIXTURE).events[0].account, 'jsmith', 'LAB\\jsmith is the account jsmith');
});

test('Windows blank placeholders do not become fake accounts', function () {
  const result = Core.parse(BLANK_ACCOUNT_FIXTURE);
  assertEqual(result.events[0].account, '', '"-" must not be treated as an account name');
  assertEqual(result.events[1].account, '', '"N/A" must not be treated as an account name');
  assertEqual(result.events[0].computer, 'WIN10-LAB01');
});

test('duplicate columns are detected and reported', function () {
  const result = Core.parse(DUPLICATE_COLUMN_FIXTURE);
  assertEqual(result.duplicates.length, 1, 'the second account-like column should be flagged');
  assert(codesOf(result.warnings).indexOf('DUPLICATE_COLUMN') !== -1, 'a DUPLICATE_COLUMN warning should be raised');
});

/* --------------------------------------------------------------------------
   Tests: timestamps
   -------------------------------------------------------------------------- */
group('Timestamps');

test('ISO timestamps are parsed', function () {
  const ts = Core.parse(COMMA_FIXTURE).events[0].timestamp;
  assert(ts.valid, 'the timestamp should be valid');
  assertIncludes(Core.toIsoString(ts.ms), '2026-04-03', 'the ISO date should be preserved');
});

test('dotted European dates are read day-first', function () {
  const result = Core.parse(SEMICOLON_FIXTURE);
  assert(result.dateConvention.confident, 'the dotted format should be recognised without ambiguity');
  assertEqual(Core.toIsoString(result.events[0].timestamp.ms).slice(0, 10), '2026-12-25', '25.12.2026 is 25 December');
});

test('slash dates with a value above 12 are resolved from that clue', function () {
  const dayFirst = Core.parse(['"Event ID","Date and Time"', '"4624","25/12/2026 09:00:00"'].join('\n'));
  assert(dayFirst.dateConvention.confident, 'day-first should be inferred from the 25');
  assertEqual(Core.toIsoString(dayFirst.events[0].timestamp.ms).slice(0, 10), '2026-12-25');

  const monthFirst = Core.parse(MONTH_FIRST_CLUE_FIXTURE);
  assertEqual(monthFirst.dateConvention.convention, 'month-first');
  assertEqual(Core.toIsoString(monthFirst.events[1].timestamp.ms).slice(0, 10), '2026-04-03',
    '03/04 in a month-first file is 3 April');
});

test('fully ambiguous dates are flagged and the timeline is marked unreliable', function () {
  const result = Core.parse(AMBIGUOUS_DATES_FIXTURE);
  assert(!result.dateConvention.confident, 'the convention must not be claimed as certain');
  assert(codesOf(result.warnings).indexOf('AMBIGUOUS_DATES') !== -1, 'an AMBIGUOUS_DATES warning is required');
  assertEqual(result.stats.timelineReliable, false, 'time-window correlation must be disabled');
});

test('AM/PM times are converted to 24-hour values', function () {
  const result = Core.parse(['"Event ID","Date and Time"', '"4624","2026-04-03 2:22:11 PM"'].join('\n'));
  assertIncludes(Core.toIsoString(result.events[0].timestamp.ms), '14:22:11', '2:22 PM is 14:22');
});

test('timezone offsets are honoured', function () {
  const result = Core.parse(['"Event ID","Date and Time"', '"4624","2026-04-03T14:22:11+02:00"'].join('\n'));
  const ts = result.events[0].timestamp;
  assert(ts.valid, 'a timestamp with an offset should parse');
  assertEqual(ts.offsetMinutes, 120, '+02:00 is 120 minutes');
});

test('impossible or unreadable dates are rejected rather than quietly accepted', function () {
  assertEqual(Core.analyzeTimestamp('2026-02-31T10:00:00').valid, false, '31 February does not exist');
  assertEqual(Core.analyzeTimestamp('not a date at all').valid, false);
});

/* --------------------------------------------------------------------------
   Tests: failing safely
   -------------------------------------------------------------------------- */
group('Failing safely');

test('an empty file is reported, not crashed on', function () {
  assertEqual(Core.parse('').errors[0].code, 'EMPTY_FILE');
  assertEqual(Core.parse('   \n\t \n').errors[0].code, 'EMPTY_FILE');
  assertEqual(Core.parse(null).ok, false);
  assertEqual(Core.parse(undefined).ok, false);
});

test('a file with no Event ID column explains exactly what is missing', function () {
  const result = Core.parse(NO_EVENT_ID_FIXTURE);
  assertEqual(result.ok, false);
  assertEqual(result.errors[0].code, 'MISSING_EVENT_ID_COLUMN');
  assert(result.errors[0].help.length > 20, 'the error must come with guidance');
  assertEqual(result.headers.length, 8, 'the columns that were found should be reported back');
  assert(result.missing.indexOf('eventId') !== -1, 'eventId must be listed as missing');
});

test('binary content is detected instead of being parsed as gibberish', function () {
  assertEqual(Core.parse('\u0000\u0000\u0000abc').errors[0].code, 'BINARY_FILE');
  const evtxMagic = new Uint8Array([0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00, 0x01]);
  assertEqual(Core.parseBytes(evtxMagic).errors[0].code, 'EVTX_FILE');
});

test('a malformed file is partly salvaged and every problem is explained', function () {
  const result = Core.parse(MALFORMED_FIXTURE);
  assert(result.ok, 'the readable rows should still be analysed');
  assertEqual(result.stats.skipped, 1, 'the non-numeric Event ID row should be skipped');
  assertEqual(result.stats.events, 3, 'the other three rows should become events');
  const codes = codesOf(result.warnings);
  assert(codes.indexOf('SKIPPED_ROWS') !== -1, 'skipped rows must be reported');
  assert(codes.indexOf('UNBALANCED_QUOTES') !== -1, 'the unterminated quote must be reported');
  assert(codes.indexOf('SOME_TIMESTAMPS_UNPARSED') !== -1, 'the unreadable date must be reported');
  assertEqual(result.skipped[0].line, 3, 'the skipped row should report its line number');
});

test('a missing timestamp column disables time-based analysis but not the parse', function () {
  const result = Core.parse(['"Event ID","User"', '"4624","jsmith"'].join('\n'));
  assert(result.ok);
  assert(codesOf(result.warnings).indexOf('NO_TIMESTAMP_COLUMN') !== -1);
  assertEqual(result.stats.timelineReliable, false);
});

test('a missing account column is reported as a weakness, not an error', function () {
  const result = Core.parse(['"Event ID","Date and Time"', '"4624","2026-04-03T10:00:00"'].join('\n'));
  assert(result.ok);
  assert(codesOf(result.warnings).indexOf('NO_ACCOUNT_COLUMN') !== -1);
});

test('UTF-16 files with a byte-order mark are decoded (PowerShell often writes these)', function () {
  const utf16 = Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from(COMMA_FIXTURE, 'utf16le')]);
  const result = Core.parseBytes(new Uint8Array(utf16));
  assert(result.ok, 'a UTF-16 file should parse');
  assertIncludes(result.stats.encoding, 'utf-16le', 'the encoding should be reported');
  assertEqual(result.stats.events, 3);
});

test('UTF-16 content without a byte-order mark is still detected', function () {
  const utf16 = Buffer.from(POWERSHELL_FIXTURE, 'utf16le');
  const result = Core.parseBytes(new Uint8Array(utf16));
  assert(result.ok, 'a BOM-less UTF-16 file should still parse');
  assertEqual(result.stats.events, 2);
  assertIncludes(result.stats.encoding, 'utf-16le', 'the guessed encoding should be reported honestly');
});

/* --------------------------------------------------------------------------
   Static source checks
   --------------------------------------------------------------------------
   Some of the most important promises in this project ("nothing leaves the
   browser", "uploaded text is never treated as HTML") cannot be proven by
   feeding the parser data. They are proven by reading the source and failing if
   a dangerous API ever appears. The patterns deliberately include a following
   character such as "(" or "." so that the words in the explanatory comments do
   not trip the check.
   -------------------------------------------------------------------------- */
function readSource(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function assertNoMatch(source, pattern, message) {
  const match = source.match(pattern);
  if (match) {
    throw new Error(message + ' (found: ' + JSON.stringify(match[0]) + ')');
  }
}

/* --------------------------------------------------------------------------
   Tests: hostile input
   -------------------------------------------------------------------------- */
group('Hostile input');

test('HTML and JavaScript inside CSV cells are kept as plain text', function () {
  const result = Core.parse(XSS_FIXTURE);
  assert(result.ok, 'a file containing HTML must still parse');
  assertIncludes(result.events[0].account, '<script>alert(1)</script>', 'the account should be stored verbatim as data');
  assertIncludes(result.events[0].message, '<script>alert(3)</script>', 'the message should be stored verbatim as data');
  assertEqual(result.stats.events, 1, 'the hostile row is still just one event');
});

test('only real domain prefixes are stripped from account names', function () {
  // Regression test: an earlier version stripped at the first forward slash of
  // any value, so "</script>" became "script>" and data was silently corrupted.
  assertEqual(Core.normalizeAccount('LAB\\jsmith'), 'jsmith');
  assertEqual(Core.normalizeAccount('CONTOSO/jsmith'), 'jsmith');
  assertEqual(Core.normalizeAccount('<script>alert(1)</script>'), '<script>alert(1)</script>');
  assertEqual(Core.normalizeAccount('a/b/c'), 'b/c');
  assertEqual(Core.normalizeAccount('just-a-name'), 'just-a-name');
  assertEqual(Core.normalizeAccount('LAB\\'), 'LAB\\', 'a prefix with nothing after it must not be stripped');
});

test('the user interface never inserts text as HTML', function () {
  const source = readSource('script.js');
  assertNoMatch(source, /\.innerHTML/, 'script.js must not use innerHTML');
  assertNoMatch(source, /\.outerHTML/, 'script.js must not use outerHTML');
  assertNoMatch(source, /insertAdjacentHTML/, 'script.js must not use insertAdjacentHTML');
  assertNoMatch(source, /document\.write/, 'script.js must not use document.write');
  assertNoMatch(source, /\beval\s*\(/, 'script.js must not use eval');
  assertNoMatch(source, /new Function\s*\(/, 'script.js must not build functions from strings');
});

test('the engine and the interface cannot make network requests', function () {
  ['triage-core.js', 'script.js'].forEach(function (file) {
    const source = readSource(file);
    assertNoMatch(source, /\bfetch\s*\(/, file + ' must not call fetch()');
    assertNoMatch(source, /XMLHttpRequest/, file + ' must not use XMLHttpRequest');
    assertNoMatch(source, /WebSocket\s*\(/, file + ' must not open a WebSocket');
    assertNoMatch(source, /sendBeacon\s*\(/, file + ' must not use sendBeacon');
    assertNoMatch(source, /EventSource\s*\(/, file + ' must not use EventSource');
  });
});

test('nothing is written to storage or to cookies', function () {
  ['triage-core.js', 'script.js'].forEach(function (file) {
    const source = readSource(file);
    assertNoMatch(source, /localStorage\s*[.\[]/, file + ' must not use localStorage');
    assertNoMatch(source, /sessionStorage\s*[.\[]/, file + ' must not use sessionStorage');
    assertNoMatch(source, /indexedDB\s*[.(]/, file + ' must not use IndexedDB');
    assertNoMatch(source, /document\.cookie/, file + ' must not set cookies');
  });
});

test('the page loads nothing from the internet', function () {
  const html = readSource('index.html');
  assertNoMatch(html, /<script[^>]+src=["']https?:/i, 'no remote script tags are allowed');
  assertNoMatch(html, /<link[^>]+href=["']https?:/i, 'no remote stylesheets are allowed');
  assertNoMatch(html, /<img[^>]+src=["']https?:/i, 'no remote images are allowed');
  const css = readSource('styles.css');
  assertNoMatch(css, /url\(\s*["']?https?:/i, 'the stylesheet must not load remote assets');
});

test('the page only loads the two local scripts it needs', function () {
  const html = readSource('index.html');
  const sources = Array.from(html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)).map(function (m) { return m[1]; });
  assertEqual(sources.join(','), 'triage-core.js,script.js', 'only the local engine and interface should load');
});

test('the content security policy blocks outbound connections', function () {
  const html = readSource('index.html');
  assertIncludes(html, "connect-src 'none'", 'connect-src must be none so no data can be sent anywhere');
  assertIncludes(html, "form-action 'none'", 'form submissions must be blocked');
  assertIncludes(html, "object-src 'none'", 'plugins must be blocked');
});

test('the privacy notice and the disclaimer are present on the page', function () {
  const html = readSource('index.html');
  assertIncludes(html, 'analysed locally in your browser', 'the privacy notice is required');
  assertIncludes(html, 'do not prove malicious behaviour', 'the disclaimer is required');
  assertIncludes(html, 'Only analyse logs from systems you own or are authorised to investigate', 'the authorisation notice is required');
});

/* --------------------------------------------------------------------------
   Tests: scale
   --------------------------------------------------------------------------
   A real Security log export can be tens of thousands of rows. This proves the
   parser stays usable at that size, and gives us a number to quote in the README.
   -------------------------------------------------------------------------- */
group('Scale');

test('a 20,000 event export is parsed completely and quickly', function () {
  const lines = ['"Event ID","Date and Time","User","Computer","Message"'];
  for (let i = 0; i < 20000; i++) {
    const id = i % 3 === 0 ? '4625' : '4624';
    const seconds = String(i % 60).padStart(2, '0');
    lines.push('"' + id + '","2026-04-03T10:' + seconds + ':00","LAB\\jsmith","WIN10-LAB01","Event number ' + i + ', with a comma inside the cell."');
  }

  const result = Core.parse(lines.join('\n'));

  assert(result.ok, 'the large file should parse');
  assertEqual(result.stats.events, 20000, 'every row should become an event');
  assert(result.stats.elapsedMs < 5000, 'parsing 20,000 events took ' + result.stats.elapsedMs + 'ms, which is too slow');
  console.log('        (20,000 events parsed in ' + result.stats.elapsedMs + 'ms)');
});

test('helpers behave as documented', function () {
  assertEqual(Core.higherSeverity('Low', 'High'), 'High');
  assertEqual(Core.higherSeverity('Informational', 'Low'), 'Low');
  assertEqual(Core.severityRank('High') > Core.severityRank('Medium'), true);
  assertEqual(Core.parseEventId('4624'), 4624);
  assertEqual(Core.parseEventId(' 4625 '), 4625);
  assertEqual(Core.parseEventId('4624 (0x1210)'), 4624);
  assertEqual(Core.parseEventId('nonsense'), null);
  assertEqual(Core.parseEventId(''), null);
  assertEqual(Core.normalizeHeader('Event-ID'), 'eventid');
  assertEqual(Core.normalizeHeader('\uFEFFEvent ID'), 'eventid');
  assertEqual(Core.formatDuration(90000), '1m 30s');
  assertEqual(Core.formatDuration(3600000), '1h 0m');
/* --------------------------------------------------------------------------
   Tests: page wiring
   --------------------------------------------------------------------------
   There is no browser in the development sandbox, so these checks stand in for
   a click-through:
     1. every element id that script.js looks for must exist in index.html
        (a typo would otherwise fail silently at runtime);
     2. script.js must load and initialise against a stubbed DOM without
        throwing, which catches missing functions and undefined variables.
   -------------------------------------------------------------------------- */
group('Page wiring');

test('every element id used by the interface exists in index.html', function () {
  const html = readSource('index.html');
  const js = readSource('script.js');

  const htmlIds = new Set(Array.from(html.matchAll(/\sid="([^"]+)"/g)).map(function (m) { return m[1]; }));

  // The ids are listed once, in cacheDom(), as a block of quoted strings.
  const cacheBlock = js.match(/function cacheDom\(\)\s*\{([\s\S]*?)\n  \}/);
  assert(cacheBlock, 'cacheDom() should be present in script.js');

  const wanted = Array.from(cacheBlock[1].matchAll(/'([a-z0-9-]+)'/g)).map(function (m) { return m[1]; });
  assert(wanted.length > 20, 'expected the interface to look for many elements, found ' + wanted.length);

  const missing = wanted.filter(function (id) { return !htmlIds.has(id); });
  assertEqual(missing.join(','), '', 'these ids are used by script.js but missing from index.html');

  // And the other way round: ids in the page that are never referenced anywhere
  // are usually leftovers. An id counts as used if script.js mentions it, or if
  // index.html refers to it a second time (for example via aria-labelledby).
  const unused = Array.from(htmlIds).filter(function (id) {
    if (id === 'main') return false;
    const occurrences = (html.match(new RegExp('"' + id + '"', 'g')) || []).length;
    const referencedInHtml = occurrences > 1;
    const referencedInJs = js.indexOf("'" + id + "'") !== -1 || js.indexOf('"' + id + '"') !== -1;
    return !referencedInHtml && !referencedInJs;
  });
  assertEqual(unused.join(','), '', 'these ids exist in index.html but are never used');
});

test('index.html has balanced section and table markup', function () {
  const html = readSource('index.html');
  ['section', 'table', 'tbody', 'thead', 'details', 'ul', 'ol', 'dl', 'div', 'pre'].forEach(function (tag) {
    const open = (html.match(new RegExp('<' + tag + '(?=[\\s>])', 'g')) || []).length;
    const close = (html.match(new RegExp('</' + tag + '>', 'g')) || []).length;
    assertEqual(open, close, '<' + tag + '> is unbalanced');
  });
});

test('script.js loads and initialises against a stubbed DOM without throwing', function () {
  const vm = require('node:vm');

  function stubElement(id) {
    return {
      id: id,
      className: '',
      textContent: '',
      colSpan: 0,
      firstChild: null,
      childNodes: [],
      files: null,
      value: '',
      classList: { add: function () {}, remove: function () {} },
      setAttribute: function () {},
      removeAttribute: function () {},
      appendChild: function () {},
      removeChild: function () {},
      addEventListener: function () {},
      querySelectorAll: function () { return []; }
    };
  }

  const elements = {};
  const documentStub = {
    readyState: 'complete',
    getElementById: function (id) {
      if (!Object.prototype.hasOwnProperty.call(elements, id)) elements[id] = stubElement(id);
      return elements[id];
    },
    createElement: function () { return stubElement('created'); },
    addEventListener: function () {},
    querySelectorAll: function () { return []; }
  };

  const sandbox = {
    document: documentStub,
    console: console,
    TextDecoder: TextDecoder,
    ArrayBuffer: ArrayBuffer,
    Uint8Array: Uint8Array,
    FileReader: function () {},
    // A real window object always has these two, so the stub must as well.
    addEventListener: function () {},
    removeEventListener: function () {}
  };
  sandbox.window = sandbox;

  const context = vm.createContext(sandbox);

  // Load the engine first, exactly as index.html does, then the interface.
  vm.runInContext(readSource('triage-core.js'), context, { filename: 'triage-core.js' });
  assert(sandbox.window.TriageCore, 'the engine should publish itself as window.TriageCore');

  let threw = null;
  try {
    vm.runInContext(readSource('script.js'), context, { filename: 'script.js' });
  } catch (err) {
    threw = err;
  }
  assertEqual(threw === null, true, 'script.js threw on load: ' + (threw && threw.message));

  // The status line should have been set by init(), proving the code really ran.
  assertIncludes(elements['status-region'].textContent, 'No file loaded yet', 'init() should have set the status message');
});


  assertEqual(Core.truncate('abcdef', 3), 'abc ... [shortened]');
});

/* --------------------------------------------------------------------------
   Summary
   -------------------------------------------------------------------------- */
console.log('\n' + '='.repeat(66));
if (failed === 0) {
  console.log('\x1b[32mAll ' + passed + ' checks passed.\x1b[0m');
} else {
  console.log('\x1b[31m' + failed + ' of ' + (passed + failed) + ' checks FAILED:\x1b[0m');
  failures.forEach(function (item) {
    console.log('  - ' + item.name + '\n      ' + item.error.message);
  });
}
console.log('='.repeat(66) + '\n');

process.exit(failed === 0 ? 0 : 1);







