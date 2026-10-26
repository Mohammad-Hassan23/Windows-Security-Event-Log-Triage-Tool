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

test('a file with only a header row explains that there is nothing to analyse', function () {
  const result = Core.parse('"Event ID","Date and Time","Message"');
  assert(result.ok, 'the header is still readable');
  assertEqual(result.stats.events, 0);
  assert(codesOf(result.warnings).indexOf('NO_DATA_ROWS') !== -1, 'the empty file should be explained');
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

test('the page only loads the local scripts it needs', function () {
  const html = readSource('index.html');
  const sources = Array.from(html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)).map(function (m) { return m[1]; });
  assertEqual(sources.join(','), 'triage-core.js,samples/sample-data.js,script.js',
    'only the local engine, the embedded demo data and the interface should load');
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
  assertEqual(Core.truncate('abcdef', 3), 'abc ... [shortened]');
});

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
  // Element ids are also referenced from the demo dataset definitions.
  const references = js + readSource('samples/sample-data.js');

  const htmlIds = new Set(Array.from(html.matchAll(/\sid="([^"]+)"/g)).map(function (m) { return m[1]; }));

  // The ids are listed once, in cacheDom(), as a block of quoted strings.
  const cacheBlock = js.match(/function cacheDom\(\)\s*\{([\s\S]*?)\n  \}/);
  assert(cacheBlock, 'cacheDom() should be present in script.js');

  const wanted = Array.from(cacheBlock[1].matchAll(/'([a-z0-9-]+)'/g)).map(function (m) { return m[1]; });
  assert(wanted.length > 20, 'expected the interface to look for many elements, found ' + wanted.length);

  const missing = wanted.filter(function (id) { return !htmlIds.has(id); });
  assertEqual(missing.join(','), '', 'these ids are used by script.js but missing from index.html');

  // And the other way round: ids in the page that are never referenced anywhere
  // are usually leftovers. An id counts as used if script.js mentions it, if it
  // is referenced through an attribute such as aria-labelledby, or if it is a
  // target of href="#..." (the inline SVG sprite works that way).
  const unused = Array.from(htmlIds).filter(function (id) {
    if (id === 'main') return false;
    const referencedInJs = references.indexOf("'" + id + "'") !== -1 || references.indexOf('"' + id + '"') !== -1;
    if (referencedInJs) return false;

    // Remove the definition itself, then look for the id anywhere else.
    const withoutDefinition = html.split('id="' + id + '"').join('');
    return withoutDefinition.indexOf(id) === -1;
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
      classList: { add: function () {}, remove: function () {}, toggle: function () {}, contains: function () { return false; } },
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

/* --------------------------------------------------------------------------
   A fuller page stub, used to actually CLICK the demo buttons.
   --------------------------------------------------------------------------
   This is the closest thing to a click-through test that is possible without a
   browser: the three real files are loaded in a sandbox, and the recorded click
   handlers are invoked exactly as a user's click would be.
   -------------------------------------------------------------------------- */
function loadPage() {
  const vm = require('node:vm');
  const elements = {};

  function makeElement(tagName) {
    const node = {
      tagName: tagName,
      id: '',
      className: '',
      textContent: '',
      colSpan: 0,
      value: '',
      disabled: false,
      children: [],
      attributes: {},
      listeners: {},
      classList: { add: function () {}, remove: function () {}, toggle: function () {}, contains: function () { return false; } },
      setAttribute: function (name, value) { node.attributes[name] = String(value); },
      getAttribute: function (name) { return node.attributes[name]; },
      removeAttribute: function (name) { delete node.attributes[name]; },
      appendChild: function (child) { node.children.push(child); return child; },
      removeChild: function (child) {
        node.children = node.children.filter(function (c) { return c !== child; });
        return child;
      },
      focus: function () {},
      addEventListener: function (type, fn) {
        node.listeners[type] = node.listeners[type] || [];
        node.listeners[type].push(fn);
      },
      querySelectorAll: function () { return []; },
      scrollIntoView: function () {},
      get firstChild() { return node.children[0] || null; },
      get childNodes() { return node.children; }
    };
    return node;
  }

  const documentStub = {
    readyState: 'complete',
    getElementById: function (id) {
      if (!Object.prototype.hasOwnProperty.call(elements, id)) {
        const node = makeElement('div');
        node.id = id;
        elements[id] = node;
      }
      return elements[id];
    },
    createElement: function (tagName) { return makeElement(tagName); },
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
    addEventListener: function () {},
    removeEventListener: function () {}
  };
  sandbox.window = sandbox;

  const context = vm.createContext(sandbox);
  // Loaded in the same order as index.html.
  vm.runInContext(readSource('triage-core.js'), context, { filename: 'triage-core.js' });
  vm.runInContext(readSource('samples/sample-data.js'), context, { filename: 'sample-data.js' });
  vm.runInContext(readSource('script.js'), context, { filename: 'script.js' });

  return { elements: elements, sandbox: sandbox };
}

/** setHidden() sets the attribute to an empty string, so check for presence. */
function isHidden(node) {
  return Object.prototype.hasOwnProperty.call(node.attributes, 'hidden');
}

test('the demo buttons are enabled once the sample data loads', function () {
  const page = loadPage();
  const sampleData = page.sandbox.window.TRIAGE_SAMPLE_DATA;
  assert(sampleData, 'the embedded demo data should be available to the page');

  Object.keys(sampleData).forEach(function (key) {
    const button = page.elements[sampleData[key].buttonId];
    assert(button, 'the page should have looked up the button for ' + key);
    assertEqual(button.disabled, false, 'the button for ' + key + ' should be enabled');
    assertEqual((button.listeners.click || []).length, 1, 'the button for ' + key + ' should have one click handler');
  });
});


test('clicking each demo button loads its dataset and labels it Demo Data', function () {
  const sampleData = require(path.join(root, 'samples/sample-data.js'));
  const page = loadPage();

  Object.keys(sampleData).forEach(function (key) {
    const dataset = sampleData[key];
    const button = page.elements[dataset.buttonId];
    const handler = (button.listeners.click || [])[0];
    assert(handler, 'the button for ' + key + ' should be clickable');

    handler(); // <-- the click

    const status = page.elements['status-region'].textContent;
    const expectedEvents = Core.parse(dataset.csv).stats.events;

    assertIncludes(status, 'Demo Data', key + ' must be labelled as Demo Data in the status line');
    assertIncludes(status, expectedEvents + ' events', key + ' should report its event count (' + expectedEvents + ')');
    assertIncludes(status, dataset.file, key + ' should name its file');

    assertEqual(page.elements['demo-chip'].attributes.hidden, undefined, 'the Demo Data chip should be visible for ' + key);
    assertEqual(page.elements['parse-panel'].attributes.hidden, undefined, 'the parse panel should be shown for ' + key);
    assert(page.elements['preview-body'].children.length > 0, 'the preview table should be filled for ' + key);
    assertEqual(page.elements['demo-info'].children.length, 3, 'the demo description should be shown for ' + key);
    assertEqual(page.elements['stat-events'].textContent, String(expectedEvents), 'the event counter should match for ' + key);
    assert(isHidden(page.elements['error-region']), 'no error should be shown for ' + key);
  });
});

/** Collects text from a stub node and its children, like a real browser does. */
function textOf(node) {
  let out = node.textContent || '';
  (node.children || []).forEach(function (child) { out += ' ' + textOf(child); });
  return out;
}

/**
 * The title of a finding card. Needed because a card's BODY can mention another
 * finding's name (the cross-references do exactly that), so searching the whole
 * card for a name would match more than the card that is actually about it.
 */
function cardTitle(card) {
  const header = (card.children || [])[0];
  const title = header && (header.children || [])[0];
  return title ? String(title.textContent) : '';
}

function cardsTitled(page, title) {
  return page.elements['findings-list'].children.filter(function (card) {
    return cardTitle(card) === title;
  });
}

test('the recognition table lists the Event IDs found, with their own priority', function () {
  const sampleData = require(path.join(root, 'samples/sample-data.js'));
  const page = loadPage();

  const handler = (page.elements[sampleData.mixed.buttonId].listeners.click || [])[0];
  handler();

  const rows = page.elements['recognition-body'].children;
  const result = Core.parse(sampleData.mixed.csv);
  assertEqual(rows.length, result.stats.recognisedEventIds.length,
    'one table row per recognised Event ID');

  const firstRowCells = rows[0].children;
  assertEqual(firstRowCells.length, 5, 'each row should have five cells');

  const texts = rows.map(function (row) { return textOf(row); }).join(' | ');
  assertIncludes(texts, 'Failed logon', 'the table should explain what a 4625 means');
  assertIncludes(texts, 'Security audit log cleared', 'the table should include the 1102 event');
  assertIncludes(texts, 'High', 'the 1102 priority should be shown');
  assertIncludes(texts, 'Informational', 'the informational priorities should be shown');

  // The unrecognised note stays hidden when every ID is understood.
  assert(isHidden(page.elements['unrecognised-note']), 'no unknown-ID note is needed for the mixed sample');
});

test('clearing the loaded data removes the Demo Data labelling', function () {
  const sampleData = require(path.join(root, 'samples/sample-data.js'));
  const page = loadPage();

  const demoHandler = (page.elements[sampleData.guessing.buttonId].listeners.click || [])[0];
  demoHandler();
  assertEqual(page.elements['demo-chip'].attributes.hidden, undefined, 'the chip should be visible after loading a demo');

  const resetHandler = (page.elements['btn-reset'].listeners.click || [])[0];
  assert(resetHandler, 'the clear button should be wired up');
  resetHandler();

  assert(isHidden(page.elements['demo-chip']), 'the chip should be hidden again');
  assert(isHidden(page.elements['parse-panel']), 'the parse panel should be hidden again');
  assertIncludes(page.elements['status-region'].textContent, 'No file loaded yet', 'the status should reset');
});


/* --------------------------------------------------------------------------
   Tests: the four demo datasets
   --------------------------------------------------------------------------
   These check the DATA itself: that it loads, that it matches the .csv files
   on disk, and that it contains the pattern each scenario exists to show. The
   findings those patterns should produce are asserted when the detection rules
   are built; at this stage the tool only parses and reports.
   -------------------------------------------------------------------------- */
group('Demo datasets');

const SAMPLES = require(path.join(root, 'samples/sample-data.js'));

function parseSample(csv) {
  const result = Core.parse(csv);
  assert(result.ok, 'the dataset should parse');
  return result;
}

function countId(events, id) {
  return events.filter(function (e) { return e.eventId === id; }).length;
}

function messageCount(events, id, needle) {
  return events.filter(function (e) {
    return e.eventId === id && e.message.indexOf(needle) !== -1;
  }).length;
}

test('all four demo datasets are present and named as documented', function () {
  assertEqual(Object.keys(SAMPLES).sort().join(','), 'guessing,mixed,normal,persistence');
  assertEqual(SAMPLES.normal.file, 'normal-windows-events.csv');
  assertEqual(SAMPLES.guessing.file, 'password-guessing.csv');
  assertEqual(SAMPLES.persistence.file, 'account-persistence.csv');
  assertEqual(SAMPLES.mixed.file, 'suspicious-admin-activity.csv');
});

test('the embedded demo data matches the .csv files on disk exactly', function () {
  Object.keys(SAMPLES).forEach(function (key) {
    const dataset = SAMPLES[key];
    const onDisk = fs.readFileSync(path.join(root, 'samples', dataset.file), 'utf8').replace(/\r\n/g, '\n');
    assertEqual(dataset.csv.replace(/\r\n/g, '\n'), onDisk,
      'samples/' + dataset.file + ' has drifted from the embedded copy - run: node dev-tests/build-samples.mjs');
  });
});

test('every dataset is labelled as demo data and has a working button', function () {
  const html = readSource('index.html');
  Object.keys(SAMPLES).forEach(function (key) {
    const dataset = SAMPLES[key];
    assert(dataset.buttonId, key + ' should declare a buttonId');
    assertIncludes(html, 'id="' + dataset.buttonId + '"', 'the button for ' + key + ' must exist in index.html');
    assert(dataset.label && dataset.summary && dataset.expectation, key + ' should describe itself for the user');
  });
});

test('every dataset parses cleanly, with nothing skipped and no warnings', function () {
  Object.keys(SAMPLES).forEach(function (key) {
    const result = parseSample(SAMPLES[key].csv);
    assertEqual(result.stats.skipped, 0, key + ' should have no skipped rows');
    assertEqual(result.warnings.length, 0,
      key + ' should produce no warnings, but produced: ' + codesOf(result.warnings).join(', '));
    assertEqual(result.stats.timelineReliable, true, key + ' should have a trustworthy timeline');
  });
});

test('the .csv files also work when uploaded by hand', function () {
  Object.keys(SAMPLES).forEach(function (key) {
    const dataset = SAMPLES[key];
    const fromDisk = Core.parse(fs.readFileSync(path.join(root, 'samples', dataset.file), 'utf8'));
    const embedded = Core.parse(dataset.csv);
    assertEqual(fromDisk.stats.events, embedded.stats.events,
      dataset.file + ' should parse to the same number of events either way');
    assertEqual(fromDisk.delimiter.label, 'comma', dataset.file + ' should be detected as comma separated');
    assertEqual(fromDisk.delimiter.confident, true, dataset.file + ' separator should be detected with confidence');
    assertEqual(fromDisk.stats.skipped, 0, dataset.file + ' should not lose rows when uploaded by hand');
  });
});

test('the normal dataset contains no high-priority activity', function () {
  const events = parseSample(SAMPLES.normal.csv).events;
  assertEqual(countId(events, 1102), 0, 'a normal day must not contain a cleared audit log');
  assertEqual(countId(events, 4720), 0, 'a normal day must not contain account creation');
  assertEqual(countId(events, 4726), 0, 'a normal day must not contain account deletion');
  assertEqual(countId(events, 4732) + countId(events, 4728), 0, 'a normal day must not contain privilege changes');
  assert(countId(events, 4624) >= 4, 'there should be several successful logons');
  assert(countId(events, 4688) >= 4, 'there should be process creation events');
  assertEqual(countId(events, 4625), 2, 'there should be exactly two failures, both below the threshold');
});

test('the normal dataset has no account anywhere near the failure threshold', function () {
  const events = parseSample(SAMPLES.normal.csv).events;
  const failures = events.filter(function (e) { return e.eventId === 4625; });

  // Both failures belong to mgrey, who mistyped a password and then signed in.
  // NOTE for readers of this test: the FIRST "Account Name" in a 4625 message is
  // the machine account (WIN10-LAB01$), not the user. Reading the wrong one is
  // the classic beginner mistake, which is why the engine reads message blocks.
  assertEqual(messageCount(failures, 4625, 'Account Name: mgrey'), 2, 'both failures should be for mgrey');
  assertEqual(messageCount(events, 4624, 'Account Name: mgrey'), 2, 'mgrey should have signed in twice');
  assert(failures.length < 5, 'two failures is far below the default threshold of five');
});

test('the password guessing dataset contains the pattern the rule will look for', function () {
  const events = parseSample(SAMPLES.guessing.csv).events;
  const failures = events.filter(function (e) { return e.eventId === 4625; });

  assertEqual(failures.length, 8, 'there should be eight failures');
  assertEqual(messageCount(failures, 4625, 'Account Name: jsmith'), 8, 'all eight failures should be for jsmith');
  assertEqual(countId(events, 4624), 1, 'there should be exactly one success');

  const success = events.filter(function (e) { return e.eventId === 4624; })[0];
  assertIncludes(success.message, 'Account Name: jsmith', 'the success should be for the same account');
  assertIncludes(success.message, '203.0.113.44', 'the success should come from the same address as the failures');
  assert(success.timestamp.ms > failures[failures.length - 1].timestamp.ms, 'the success should come after the failures');

  const span = success.timestamp.ms - failures[0].timestamp.ms;
  assert(span < 10 * 60 * 1000,
    'all attempts should fit inside the default ten minute window, but they span ' + Math.round(span / 1000) + ' seconds');
});

test('the persistence dataset contains creation followed by a privileged group change', function () {
  const events = parseSample(SAMPLES.persistence.csv).events;
  const created = events.filter(function (e) { return e.eventId === 4720; });
  const added = events.filter(function (e) { return e.eventId === 4732; });

  assertEqual(created.length, 1, 'there should be one account creation');
  assertEqual(added.length, 1, 'there should be one local group addition');
  assertIncludes(created[0].message, 'Account Name: temp-admin', 'temp-admin should be the account created');
  assertIncludes(added[0].message, 'Account Name: temp-admin', 'temp-admin should be the account added');
  assertIncludes(added[0].message, 'Group Name: Administrators', 'the group should be Administrators');
  assert(added[0].timestamp.ms > created[0].timestamp.ms, 'the group change should come after the creation');
  assert(countId(events, 4624) >= 1, 'the new account should be seen being used');
});

test('the mixed dataset contains every scenario at once', function () {
  const events = parseSample(SAMPLES.mixed.csv).events;
  const failures = events.filter(function (e) { return e.eventId === 4625; });

  assert(failures.length >= 5, 'there should be at least five failures');
  assertEqual(messageCount(failures, 4625, 'Account Name: svc-backup'), failures.length,
    'every failure should be for svc-backup');
  assertEqual(countId(events, 1102), 1, 'the log should be cleared once');
  assertEqual(countId(events, 4720), 1, 'one account should be created');
  assertEqual(countId(events, 4732), 1, 'one privileged group change should be present');
  assertEqual(countId(events, 4726), 1, 'one account should be deleted');
  assertEqual(countId(events, 7045), 1, 'one service installation should be present');
  assertEqual(countId(events, 4104), 1, 'one PowerShell script block should be present');

  assertIncludes(events.filter(function (e) { return e.eventId === 4104; })[0].message,
    '-EncodedCommand', 'the script block should show an encoded command');
  assertIncludes(events.filter(function (e) { return e.eventId === 1102; })[0].message,
    'Account Name: svc-backup', 'the log clearing should name the account');

  const successes = events.filter(function (e) {
    return e.eventId === 4624 && e.message.indexOf('Account Name: svc-backup') !== -1;
  });
  assertEqual(successes.length, 1, 'svc-backup should have exactly one success');
  assert(successes[0].timestamp.ms > failures[0].timestamp.ms, 'the success should come after the failures');
});

test('no demo dataset uses a real-world IP address', function () {
  Object.keys(SAMPLES).forEach(function (key) {
    const found = Array.from(SAMPLES[key].csv.matchAll(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g)).map(function (m) { return m[0]; });
    assert(found.length > 0, key + ' should contain at least one address to be realistic');
    found.forEach(function (address) {
      const parts = address.split('.').map(Number);
      const isPrivate = parts[0] === 10
        || (parts[0] === 192 && parts[1] === 168)
        || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31);
      const isDocumentation = (parts[0] === 203 && parts[1] === 0 && parts[2] === 113)
        || (parts[0] === 198 && parts[1] === 51 && parts[2] === 100);
      assert(isPrivate || isDocumentation, address + ' in ' + key + ' is not a private or documentation address');
    });
  });
/* --------------------------------------------------------------------------
   Tests: the Event ID catalogue
   --------------------------------------------------------------------------
   The catalogue is the reference material shown to the student. These checks
   keep it complete, keep the wording honest, and make sure severity is never
   used to imply that an event proves an attack.
   -------------------------------------------------------------------------- */
group('Event ID catalogue');

const CATALOGUE_IDS = [4624, 4625, 4688, 4720, 4726, 4728, 4732, 1102, 4104, 7045];

test('all ten specified Event IDs are in the catalogue', function () {
  CATALOGUE_IDS.forEach(function (id) {
    assert(Core.isKnownEventId(id), id + ' should be recognised');
    const info = Core.getEventInfo(id);
    assertEqual(info.id, id, 'the catalogue entry should carry its own ID');
  });
  assertEqual(Object.keys(Core.EVENT_CATALOGUE).length, 10, 'the catalogue should hold exactly ten entries');
});

test('the base severities are the ones the specification asks for', function () {
  const expected = {
    4624: 'Informational',
    4625: 'Low',
    4688: 'Informational',
    4720: 'Medium',
    4726: 'Low',
    4728: 'Medium',
    4732: 'Medium',
    1102: 'High',
    4104: 'Informational',
    7045: 'Medium'
  };
  Object.keys(expected).forEach(function (id) {
    assertEqual(Core.getEventInfo(Number(id)).baseSeverity, expected[id], 'severity for ' + id);
  });
});

test('every entry explains itself and offers legitimate explanations', function () {
  CATALOGUE_IDS.forEach(function (id) {
    const info = Core.getEventInfo(id);
    assert(info.title && info.title.length > 5, id + ' needs a plain-English title');
    assert(info.description && info.description.length > 40, id + ' needs a description');
    assert(info.whyItMatters && info.whyItMatters.length > 40, id + ' needs to explain why it matters');
    assert(info.benign && info.benign.length >= 2, id + ' needs at least two benign explanations');
    assert(info.nextSteps && info.nextSteps.length >= 3, id + ' needs at least three next steps');
    assert(info.category, id + ' needs a category');
  });
});

test('the catalogue never claims that an Event ID is malicious', function () {
  CATALOGUE_IDS.forEach(function (id) {
    const info = Core.getEventInfo(id);
    const text = [info.title, info.description, info.whyItMatters].join(' ').toLowerCase();

    ['malicious', 'compromised', 'is an attack', 'indicates an attack', 'definitely'].forEach(function (word) {
      assert(text.indexOf(word) === -1,
        'entry ' + id + ' should not use the phrase "' + word + '" about an event on its own');
    });

    // The word "prove" is only allowed in a negative construction such as
    // "its absence proves nothing", which is exactly the honest wording wanted.
    if (text.indexOf('prove') !== -1) {
      const negated = text.indexOf('proves nothing') !== -1
        || text.indexOf('does not prove') !== -1
        || text.indexOf('do not prove') !== -1
        || text.indexOf('not prove') !== -1;
      assert(negated, 'entry ' + id + ' uses "prove" without negating it');
    }
  });
});

test('severity vocabulary is limited to the four allowed levels', function () {
  CATALOGUE_IDS.forEach(function (id) {
    const severity = Core.getEventInfo(id).baseSeverity;
    assert(['Informational', 'Low', 'Medium', 'High'].indexOf(severity) !== -1,
      id + ' uses severity "' + severity + '", which is outside the agreed vocabulary');
  });
});

test('an unknown Event ID is recognised as unknown, not as suspicious', function () {
  assertEqual(Core.isKnownEventId(9999), false);
  const result = Core.parse(['"Event ID","Date and Time","Message"', '"9999","2026-04-03T10:00:00","Something happened."'].join('\n'));
  const event = result.events[0];
  assertEqual(event.recognised, false, 'the event should be marked unrecognised');
  assertIncludes(event.title, '9999', 'the title should name the unknown ID');
  assertEqual(event.category, 'Unrecognised');
  assertEqual(event.baseSeverity, 'Informational', 'an unfamiliar event must not be treated as serious');
  assertEqual(result.stats.unrecognisedEvents, 1);
  assertEqual(result.stats.recognisedEvents, 0);
});
/* --------------------------------------------------------------------------
   Tests: field extraction from real message formats
   --------------------------------------------------------------------------
   The fixtures below are written the way Windows actually writes them, including
   tabs, CRLF line endings, the duplicated "Account Name" label, and a machine
   account ending in "$".
   -------------------------------------------------------------------------- */
group('Field extraction');

/* Parses a single-event CSV and returns that event. */
function eventFrom(id, message, extra) {
  const header = '"Event ID","Date and Time","User","Computer","Message"';
  const row = '"' + id + '","2026-04-03T10:00:00","' + (extra && extra.user ? extra.user : '-')
    + '","WIN10-LAB01","' + String(message).replace(/"/g, '""') + '"';
  const result = Core.parse([header, row].join('\r\n'));
  assert(result.ok, 'the fixture should parse');
  assert(result.events[0], 'there should be one event');
  return result.events[0];
}

/* A faithful 4624: the machine account appears FIRST, in the Subject block. */
const MESSAGE_4624 =
  'An account was successfully logged on.\r\n' +
  '\r\n' +
  'Subject:\r\n' +
  '\tSecurity ID:\t\tS-1-5-18\r\n' +
  '\tAccount Name:\t\tWIN10-LAB01$\r\n' +
  '\tAccount Domain:\t\tLAB\r\n' +
  '\r\n' +
  'Logon Information:\r\n' +
  '\tLogon Type:\t\t10\r\n' +
  '\tRestricted Admin Mode:\tNo\r\n' +
  '\r\n' +
  'New Logon:\r\n' +
  '\tSecurity ID:\t\tS-1-5-21-1111-2222-3333-1105\r\n' +
  '\tAccount Name:\t\tjsmith\r\n' +
  '\tAccount Domain:\t\tLAB\r\n' +
  '\r\n' +
  'Network Information:\r\n' +
  '\tWorkstation Name:\tWIN10-LAB01\r\n' +
  '\tSource Network Address:\t192.168.10.25\r\n' +
  '\tSource Port:\t\t52341';

/* A faithful 4625, with the machine account in Subject and the real target in
   "Account For Which Logon Failed". */
const MESSAGE_4625 =
  'An account failed to log on.\r\n' +
  '\r\n' +
  'Subject:\r\n' +
  '\tSecurity ID:\t\tS-1-5-18\r\n' +
  '\tAccount Name:\t\tWIN10-LAB01$\r\n' +
  '\tAccount Domain:\t\tLAB\r\n' +
  '\r\n' +
  'Logon Type:\t\t\t3\r\n' +
  '\r\n' +
  'Account For Which Logon Failed:\r\n' +
  '\tSecurity ID:\t\tNULL SID\r\n' +
  '\tAccount Name:\t\tjsmith\r\n' +
  '\tAccount Domain:\t\tLAB\r\n' +
  '\r\n' +
  'Failure Information:\r\n' +
  '\tFailure Reason:\t\tUnknown user name or bad password.\r\n' +
  '\tStatus:\t\t\t0xC000006D\r\n' +
  '\tSub Status:\t\t0xC000006A\r\n' +
  '\r\n' +
  'Network Information:\r\n' +
  '\tWorkstation Name:\t-\r\n' +
  '\tSource Network Address:\t203.0.113.44';

test('4624 takes the account from New Logon, not from Subject', function () {
  const event = eventFrom(4624, MESSAGE_4624);
  assertEqual(event.account, 'jsmith', 'the account must be the person who signed in');
  assertEqual(event.fields.accountBlock, 'New Logon', 'the block used must be reported');
  assert(event.account !== 'WIN10-LAB01$', 'the machine account must never be used as the user');
  assertEqual(event.accountSource, 'message', 'the message is a better source than the column');
});

test('4624 extracts the logon type, source address and workstation', function () {
  const fields = eventFrom(4624, MESSAGE_4624).fields;
  assertEqual(fields.logonType, '10');
  assertIncludes(fields.logonTypeText, 'Remote Desktop', 'type 10 should be explained in plain English');
  assertEqual(fields.sourceIp, '192.168.10.25');
  assertEqual(fields.sourceIpKind, 'private', '192.168.x.x is a private address');
  assertEqual(fields.workstation, 'WIN10-LAB01');
});

test('4625 takes the account from "Account For Which Logon Failed"', function () {
  const event = eventFrom(4625, MESSAGE_4625);
  assertEqual(event.account, 'jsmith');
  assertEqual(event.fields.accountBlock, 'Account For Which Logon Failed');
  assert(event.account !== 'WIN10-LAB01$', 'the machine account must never be used as the target');
});

test('4625 explains the failure in plain English', function () {
  const fields = eventFrom(4625, MESSAGE_4625).fields;
  assertIncludes(fields.failureReason, 'Unknown user name or bad password', 'the reason should be kept verbatim');
  assertEqual(fields.statusCode, '0xC000006D');
  assertIncludes(fields.statusText, 'user name or password was wrong', 'the status should be translated');
  assertEqual(fields.subStatusCode, '0xC000006A');
  assertIncludes(fields.subStatusText, 'password was wrong', 'the sub status should be translated');
test('a machine account is never used as the account when blocks are missing', function () {
  // Older or unusual exports may have no New Logon block at all. The fallback
  // takes the LAST "Account Name", which is the user, and declares the fallback.
  const old = 'An account was successfully logged on.\n\nSubject:\n\tAccount Name:\tWIN10-LAB01$\n\nLogon Type:\t2\n\nAccount Name:\tmgrey';
  const event = eventFrom(4624, old);
  assertEqual(event.account, 'mgrey', 'the last account name should win over the machine account');
  assertEqual(event.fields.accountBlock, 'fallback', 'the fallback must be declared, not hidden');
});

test('extra spacing and letter case in labels do not matter', function () {
  const messy = 'Subject:\n  account name : labadmin\n\nNew Logon:\n   ACCOUNT NAME :   temp-admin  ';
  const fields = Core.extractEventFields({ eventId: 4624, message: messy, sourceIpColumn: '' }).fields;
  assertEqual(fields.account, 'temp-admin', 'label matching should ignore case and extra spaces');
});

test('unreadable logon type and status codes are left blank, never guessed', function () {
  assertEqual(Core.describeLogonType('99'), '', 'an unknown logon type must not be invented');
  assertEqual(Core.describeLogonType(''), '');
  assertEqual(Core.describeFailureCode('0xDEADBEEF'), '', 'an unknown status code must not be invented');
  assertEqual(Core.describeFailureCode(''), '');
  assertIncludes(Core.describeFailureCode('0xC0000234'), 'locked out', 'a known code should be explained');
});

test('source address placeholders are labelled rather than treated as addresses', function () {
  assertEqual(Core.normalizeSourceIp('-').kind, 'unavailable');
  assertEqual(Core.normalizeSourceIp('').kind, 'unavailable');
  assertEqual(Core.normalizeSourceIp('::1').kind, 'local');
  assertEqual(Core.normalizeSourceIp('127.0.0.1').kind, 'local');
  assertEqual(Core.normalizeSourceIp('0.0.0.0').kind, 'unspecified');
  assertEqual(Core.normalizeSourceIp('192.168.10.25').kind, 'private');
  assertEqual(Core.normalizeSourceIp('203.0.113.44').kind, 'routable');
  assertEqual(Core.normalizeSourceIp('2001:db8::1').kind, 'ipv6');
  assertEqual(Core.normalizeSourceIp('not-an-address').kind, 'unrecognised');
  assertIncludes(Core.normalizeSourceIp('::1').label, 'local computer', 'the label should explain the value');
});
  assertEqual(fields.logonType, '3');
  assertIncludes(fields.logonTypeText, 'Network', 'type 3 should be explained');
/* --------------------------------------------------------------------------
   Tests: account and privilege events
   -------------------------------------------------------------------------- */
group('Account and privilege extraction');

const MESSAGE_4720 =
  'A user account was created.\r\n\r\n' +
  'Subject:\r\n\tSecurity ID:\t\tS-1-5-21-1111-2222-3333-1103\r\n\tAccount Name:\t\tlabadmin\r\n\tAccount Domain:\t\tLAB\r\n\r\n' +
  'New Account:\r\n\tSecurity ID:\t\tS-1-5-21-1111-2222-3333-1150\r\n\tAccount Name:\t\ttemp-admin\r\n\tAccount Domain:\t\tLAB\r\n\r\n' +
  'Attributes:\r\n\tSAM Account Name:\ttemp-admin\r\n\tUser Account Control:\tAccount Enabled';

const MESSAGE_4726 =
  'A user account was deleted.\r\n\r\n' +
  'Subject:\r\n\tAccount Name:\t\tlabadmin\r\n\tAccount Domain:\t\tLAB\r\n\r\n' +
  'Target Account:\r\n\tAccount Name:\t\ttemp-admin\r\n\tAccount Domain:\t\tLAB';

function groupMessage(groupName, groupDomain, scope) {
  return 'A member was added to a security-enabled ' + scope + ' group.\r\n\r\n' +
    'Member:\r\n\tSecurity ID:\t\tS-1-5-21-1111-2222-3333-1150\r\n\tAccount Name:\t\ttemp-admin\r\n\tAccount Domain:\t\tLAB\r\n\r\n' +
    'Group:\r\n\tGroup Name:\t\t' + groupName + '\r\n\tGroup Domain:\t\t' + groupDomain + '\r\n\r\n' +
    'Subject:\r\n\tAccount Name:\t\tlabadmin\r\n\tAccount Domain:\t\tLAB';
}

test('4720 separates the new account from the account that created it', function () {
  const event = eventFrom(4720, MESSAGE_4720);
  assertEqual(event.account, 'temp-admin', 'the event is grouped by the account that was created');
  assertEqual(event.fields.targetAccount, 'temp-admin');
  assertEqual(event.fields.actor, 'labadmin', 'the actor is the account that made the change');
  assertEqual(event.fields.accountBlock, 'New Account');
  assertEqual(event.baseSeverity, 'Medium');
});

test('4726 separates the deleted account from the account that deleted it', function () {
  const event = eventFrom(4726, MESSAGE_4726);
  assertEqual(event.account, 'temp-admin');
  assertEqual(event.fields.targetAccount, 'temp-admin');
  assertEqual(event.fields.actor, 'labadmin');
  assertEqual(event.baseSeverity, 'Low');
});

test('4732 extracts the member and the local group', function () {
  const event = eventFrom(4732, groupMessage('Administrators', 'BUILTIN', 'local'));
  assertEqual(event.fields.memberAccount, 'temp-admin');
  assertEqual(event.account, 'temp-admin', 'grouping must use the member so a 4720 can be matched');
  assertEqual(event.fields.groupName, 'Administrators');
  assertEqual(event.fields.groupDomain, 'BUILTIN');
  assertEqual(event.fields.actor, 'labadmin');
  assertEqual(event.fields.groupIsPrivileged, true, 'Administrators is a privileged group');
});

test('4728 extracts the member and the global group', function () {
  const event = eventFrom(4728, groupMessage('Domain Admins', 'LAB', 'global'));
  assertEqual(event.fields.groupName, 'Domain Admins');
  assertEqual(event.fields.groupIsPrivileged, true);
  assertIncludes(event.fields.groupReason, 'elevated rights', 'the reason should be explained');
});

test('an ordinary group is not described as privileged', function () {
  const event = eventFrom(4732, groupMessage('Users', 'BUILTIN', 'local'));
  assertEqual(event.fields.groupIsPrivileged, false, 'the Users group must not be treated as privileged');
  assertIncludes(event.fields.groupReason, 'not in this tool', 'the reasoning should be stated');
});

test('a group name containing "admin" is flagged as a heuristic, not a fact', function () {
  const event = eventFrom(4732, groupMessage('LAB-Server-Admins', 'LAB', 'local'));
  assertEqual(event.fields.groupIsPrivileged, true);
  assertIncludes(event.fields.groupReason, 'contains "admin"', 'the heuristic must be visible in the wording');
});

test('1102 names the account that cleared the log', function () {
  const message = 'The audit log was cleared.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-1111-2222-3333-1107\r\n'
    + '\tAccount Name:\t\tsvc-backup\r\n\tAccount Domain:\t\tLAB\r\n\tLogon ID:\t\t0x1A2B3C';
  const event = eventFrom(1102, message);
  assertEqual(event.fields.actor, 'svc-backup');
  assertEqual(event.account, 'svc-backup');
  assertEqual(event.fields.accountBlock, 'Subject');
  assertEqual(event.baseSeverity, 'High', 'a cleared audit log is High priority on its own');
});
/* --------------------------------------------------------------------------
   Tests: process creation, PowerShell and services
   -------------------------------------------------------------------------- */
group('Process, script and service extraction');

test('4688 extracts the process, its parent, the command line and the account', function () {
  const message = 'A new process has been created.\r\n\r\n' +
    'New Process Name:\tC:\\Windows\\System32\\cmd.exe\r\n' +
    'Creator Process Name:\tC:\\Windows\\System32\\services.exe\r\n' +
    'Process Command Line:\tcmd.exe /c net user helpdesk-temp /add\r\n' +
    'New Process ID:\t0x1f4c\r\n\r\n' +
    'Subject:\r\n\tAccount Name:\t\tsvc-backup\r\n\tAccount Domain:\t\tLAB';
  const event = eventFrom(4688, message);
  assertIncludes(event.fields.process, 'cmd.exe', 'the process name should be extracted');
  assertIncludes(event.fields.parentProcess, 'services.exe', 'the parent process should be extracted');
  assertIncludes(event.fields.commandLine, 'net user helpdesk-temp /add', 'the command line should be extracted');
  assertEqual(event.fields.account, 'svc-backup');
  assertEqual(event.account, 'svc-backup', 'the process is attributed to the account that ran it');
  assertEqual(event.baseSeverity, 'Informational', 'process creation is context, not a warning');
});

test('4688 without command-line auditing says so instead of inventing a command', function () {
  const message = 'A new process has been created.\r\n\r\n' +
    'New Process Name:\tC:\\Windows\\System32\\notepad.exe\r\n\r\n' +
    'Subject:\r\n\tAccount Name:\t\tjsmith';
  const event = eventFrom(4688, message);
  assertEqual(event.fields.commandLine, '', 'a missing command line must stay empty');
  assertIncludes(event.fields.missing.join(', '), 'command line', 'the report should mention what was missing');
  assertIncludes(event.fields.process, 'notepad.exe', 'the process itself should still be extracted');
});

test('4104 extracts the script text and keeps PowerShell in proportion', function () {
  const message = 'Creating Scriptblock text (1 of 1):\r\n' +
    "Get-Service | Where-Object {$_.Status -eq 'Stopped'}\r\n\r\n" +
    'ScriptBlock ID: 11111111-2222-3333-4444-5555\r\n' +
    'Path:\r\n\r\nAccount Name: jsmith';
  const event = eventFrom(4104, message);
  assertIncludes(event.fields.scriptText, 'Get-Service', 'the script text should be captured');
  assertEqual(event.fields.scriptHints.length, 0, 'an ordinary script should not raise hints');
  assertEqual(event.account, 'jsmith');
  assertEqual(event.baseSeverity, 'Informational', 'PowerShell must not be treated as suspicious by itself');
  assertIncludes(event.catalogue.whyItMatters, 'normal administration tool', 'the wording must not blame PowerShell');
});

test('4104 points out encoded commands without calling them malicious', function () {
  const message = 'Creating Scriptblock text (1 of 1):\r\n' +
    'powershell.exe -EncodedCommand R2V0LVNlcnZpY2U=\r\n\r\n' +
    'ScriptBlock ID: 11111111-2222-3333-4444-6666\r\n' +
    'Path:\r\n\r\nAccount Name: svc-backup';
  const event = eventFrom(4104, message);
  assert(event.fields.scriptHints.length >= 1, 'an encoded command should raise a hint');
  assertIncludes(event.fields.scriptHints.join(' '), 'EncodedCommand', 'the hint should name the flag');
  event.fields.scriptHints.forEach(function (hint) {
    const text = hint.toLowerCase();
    assert(text.indexOf('malicious') === -1 && text.indexOf('attacker') === -1,
      'a hint must describe the text, not judge intent: ' + hint);
  });
  assertEqual(event.baseSeverity, 'Informational', 'a hint must not raise the severity on its own');
});

test('7045 extracts the service details', function () {
  const message = 'A service was installed in the system.\r\n\r\n' +
    'Service Name:  LabUpdaterSvc\r\n' +
    'Service File Name:  C:\\ProgramData\\LabUpdater\\updater.exe\r\n' +
    'Service Type:  user mode service\r\n' +
    'Service Start Type:  auto start\r\n' +
    'Service Account:  LocalSystem';
  const event = eventFrom(7045, message);
  assertEqual(event.fields.serviceName, 'LabUpdaterSvc');
  assertIncludes(event.fields.servicePath, 'updater.exe', 'the program the service runs should be extracted');
  assertEqual(event.fields.serviceType, 'user mode service');
  assertEqual(event.fields.serviceStartType, 'auto start');
  assertEqual(event.fields.serviceAccount, 'LocalSystem');
  assertEqual(event.baseSeverity, 'Medium');
});
/* --------------------------------------------------------------------------
   Tests: nothing is ever invented
   -------------------------------------------------------------------------- */
group('No invented values');

test('a message with no readable structure leaves every field empty', function () {
  const event = eventFrom(4624, 'An account was successfully logged on.');
  assertEqual(event.account, '', 'no account should be invented');
  assertEqual(event.accountSource, 'none');
  assertEqual(event.fields.logonType, '');
  assertEqual(event.fields.sourceIp, '');
  assertEqual(event.fields.sourceIpKind, 'unavailable');
  assertEqual(event.fields.workstation, '');
  assertIncludes(event.fields.missing.join(', '), 'account name', 'the gap should be reported');
});

test('an empty message does not break anything', function () {
  const event = eventFrom(4624, '');
  assertEqual(event.account, '');
  assertEqual(event.sectionsParsed, 0);
  assert(event.fields.missing.length > 0, 'missing fields should still be listed');
});

test('the account falls back to the CSV column only when the message has none', function () {
  const event = eventFrom(4720, 'A user account was created.', { user: 'LAB\\labadmin' });
  assertEqual(event.account, 'labadmin', 'the column is a valid fallback');
  assertEqual(event.accountSource, 'column', 'and the report should say where it came from');
  assertEqual(event.accountFromColumn, 'labadmin');
});

test('a source address is never read from an unrelated field', function () {
  const event = eventFrom(4720, MESSAGE_4720);
  assertEqual(event.fields.sourceIp, '', 'account creation events have no source address');
  assertEqual(event.fields.sourceIpKind, 'unavailable');
});

test('a dedicated source address column is used only as a last resort', function () {
  const header = '"Event ID","Date and Time","SourceIP","Message"';
  const row = '"4625","2026-04-03T10:00:00","203.0.113.9","An account failed to log on."';
  const event = Core.parse([header, row].join('\n')).events[0];
  assertEqual(event.fields.sourceIp, '203.0.113.9', 'the column should be used when the message has nothing');
  assertEqual(event.fields.sourceIpKind, 'routable');
});

test('message section parsing survives odd and hostile input', function () {
  assertEqual(Core.parseMessageSections('').sections.length, 0);
  assertEqual(Core.parseMessageSections(null).blank, true);
  assertEqual(Core.parseMessageSections('Subject:').sections.length, 2, 'a bare heading is still a section');
  const weird = Core.parseMessageSections(':  leading colon\nNoColonHere\nA: b: c');
  assert(weird.sections.length >= 1, 'odd lines must not throw');
  assertEqual(Core.labelAnywhere(weird, 'a'), 'b: c', 'only the first colon separates label from value');
});

test('every sample dataset resolves its accounts from the messages', function () {
  const expectations = {
    normal: { withMessage: 12, total: 15 },
    guessing: { withMessage: 9, total: 9 },
    persistence: { withMessage: 4, total: 4 },
    mixed: { withMessage: 14, total: 15 }
  };
  Object.keys(expectations).forEach(function (key) {
    const result = Core.parse(SAMPLES[key].csv);
    const expected = expectations[key];
    assertEqual(result.stats.accountsFoundInMessage, expected.withMessage,
      key + ' should resolve accounts from message text');
    assertEqual(result.stats.eventsWithAccount, expected.total,
      key + ' should end up with an account for every event');
  });
});

test('the mixed dataset extraction matches the story it is meant to tell', function () {
  const events = Core.parse(SAMPLES.mixed.csv).events;

  const created = events.filter(function (e) { return e.eventId === 4720; })[0];
  assertEqual(created.account, 'helpdesk-temp', 'the created account');
  assertEqual(created.fields.actor, 'svc-backup', 'the account that created it');

  const added = events.filter(function (e) { return e.eventId === 4732; })[0];
  assertEqual(added.account, 'helpdesk-temp', 'the same account must be used for correlation');
  assertEqual(added.fields.groupName, 'Administrators');
  assertEqual(added.fields.groupIsPrivileged, true);

  const cleared = events.filter(function (e) { return e.eventId === 1102; })[0];
  assertEqual(cleared.fields.actor, 'svc-backup');

  const service = events.filter(function (e) { return e.eventId === 7045; })[0];
  assertEqual(service.fields.serviceName, 'LabUpdaterSvc');

  const script = events.filter(function (e) { return e.eventId === 4104; })[0];
  assert(script.fields.scriptHints.length >= 1, 'the encoded script should be highlighted');

  const failures = events.filter(function (e) { return e.eventId === 4625; });
  failures.forEach(function (failure) {
    assertEqual(failure.account, 'svc-backup', 'every failure should name the same account');
    assertIncludes(failure.fields.logonTypeText, 'Network', 'the sample failures are network logons');
    assertEqual(failure.fields.sourceIp, '198.51.100.23');
  });
});
/* --------------------------------------------------------------------------
   Tests: RULE 1 - repeated failed logons
   --------------------------------------------------------------------------
   These are the checks the specification asks for: the password-guessing sample
   must trigger, the normal sample must stay quiet, and the settings must change
   the outcome in a predictable way.
   -------------------------------------------------------------------------- */
group('Rule 1: repeated failed logons');

function analyseSample(key, settings) {
  return Core.analyse(Core.parse(SAMPLES[key].csv), settings);
}

function findingsNamed(analysis, name) {
  return analysis.findings.filter(function (f) { return f.name === name; });
}

test('the password guessing sample triggers Repeated Failed Logons', function () {
  const analysis = analyseSample('guessing');
  const matches = findingsNamed(analysis, 'Repeated Failed Logons');
  assertEqual(matches.length, 1, 'exactly one finding for this sample');

  const finding = matches[0];
  assertEqual(finding.account, 'jsmith');
  assertEqual(finding.severity, 'Medium');
  assertEqual(finding.eventCount, 8, 'all eight failures should be reported');
  assertEqual(finding.eventIds.join(','), '4625');
  assertEqual(finding.sourceIps.join(','), '203.0.113.44', 'the source address should be reported');
  assertIncludes(finding.timeRangeText, '2026-04-07 02:14:02', 'the time range should be shown');
  assertIncludes(finding.durationText, '4m 13s', 'the duration should be shown');
});

test('the finding contains every section the specification asks for', function () {
  const finding = findingsNamed(analyseSample('guessing'), 'Repeated Failed Logons')[0];

  assert(finding.name, 'alert name');
  assert(finding.severity, 'severity');
  assert(finding.eventIds.length, 'Event IDs');
  assert(finding.account, 'account');
  assert(finding.timeRangeText, 'timestamp or time range');
  assert(finding.observedActivity.length > 40, 'observed activity');
  assert(finding.whyItMatters.length > 40, 'why this matters');
  assert(finding.benign.length > 40, 'a possible benign explanation');
  assert(finding.investigation.length >= 3, 'suggested investigation steps');
  assert(finding.score.factors.length >= 1, 'the score breakdown');
  assert(finding.severityReasons.length >= 1, 'why this priority was chosen');
});

test('the observed activity reads as plain English about the real values', function () {
  const finding = findingsNamed(analyseSample('guessing'), 'Repeated Failed Logons')[0];
  assertIncludes(finding.observedActivity, 'jsmith', 'the account should be named');
  assertIncludes(finding.observedActivity, '8 failed sign-in attempts', 'the count should be stated');
  assertIncludes(finding.observedActivity, '203.0.113.44', 'the source address should be stated');
  assertIncludes(finding.observedActivity, 'Network', 'the logon type should be explained');
});

test('the normal sample produces no failed logon finding at the default threshold', function () {
  const analysis = analyseSample('normal');
  assertEqual(findingsNamed(analysis, 'Repeated Failed Logons').length, 0,
    'two mistyped passwords must not be escalated');
  assertEqual(analysis.findings.length, 0, 'nothing at all should be escalated in the normal sample');
  assertEqual(analysis.stats.highestSeverity, '', 'there should be no highest severity');
});

test('the threshold is configurable and changes the outcome', function () {
  const normal = Core.parse(SAMPLES.normal.csv);

  // mgrey mistypes a password twice. At the default threshold of 5 that is
  // silent; if a student lowers it to 2 the tool should say something.
  assertEqual(Core.analyse(normal, { failedLogonThreshold: 5 }).findings.length, 0);
  const strict = Core.analyse(normal, { failedLogonThreshold: 2 });
  const repeated = findingsNamed(strict, 'Repeated Failed Logons');
  assertEqual(repeated.length, 1, 'a threshold of 2 should catch the two failures');
  assertEqual(repeated[0].account, 'mgrey');
  assertEqual(repeated[0].eventCount, 2);

  // And raising it above the sample's failure count silences the guessing sample.
  const guessing = Core.parse(SAMPLES.guessing.csv);
  assertEqual(findingsNamed(Core.analyse(guessing, { failedLogonThreshold: 9 }), 'Repeated Failed Logons').length, 0,
    'eight failures must not trigger a threshold of nine');
  assertEqual(findingsNamed(Core.analyse(guessing, { failedLogonThreshold: 8 }), 'Repeated Failed Logons').length, 1,
    'eight failures should trigger a threshold of exactly eight');
});

test('the time window is configurable and changes the outcome', function () {
  const guessing = Core.parse(SAMPLES.guessing.csv);

  // The eight attempts span 4 minutes 13 seconds, so a one-minute window finds no
  // burst at all: the tool should say so and lower the priority rather than
  // pretending a burst happened.
  const tight = findingsNamed(Core.analyse(guessing, { failedLogonWindowMinutes: 1 }), 'Repeated Failed Logons')[0];
  assertEqual(tight.severity, 'Low', 'a slow trickle is a lower priority than a burst');
  assertIncludes(tight.severityReasons.join(' '), 'spread out', 'the reason should be stated');

  // A five-minute window contains all eight attempts.
  const wide = findingsNamed(Core.analyse(guessing, { failedLogonWindowMinutes: 5 }), 'Repeated Failed Logons')[0];
  assertEqual(wide.severity, 'Medium');
  assertEqual(wide.eventCount, 8, 'all eight attempts fall inside five minutes');
});

test('switching the time window off counts failures together and says so', function () {
  const analysis = Core.analyse(Core.parse(SAMPLES.guessing.csv), {
    useTimeWindow: false,
    failedLogonWindowMinutes: 1
  });
  const finding = findingsNamed(analysis, 'Repeated Failed Logons')[0];
  assertEqual(finding.severity, 'Medium', 'with no window the count itself is the alert');
  assertIncludes(finding.severityReasons.join(' '), 'switched off', 'the reason must not be hidden');
  assertIncludes(finding.notes.join(' '), 'switched off in the settings', 'the finding should explain itself');
  assertEqual(analysis.stats.windowApplied, false, 'the analysis should record that no window was applied');
});

test('invalid or missing timestamps never stop the rule from working', function () {
  // Built from real lines rather than escaped ones, so the message has the same
  // shape as a genuine Windows event.
  const message = [
    'An account failed to log on.',
    '',
    'Logon Type: 3',
    '',
    'Account For Which Logon Failed:',
    ' Account Name: jsmith',
    '',
    'Network Information:',
    ' Source Network Address: 203.0.113.77'
  ].join('\n');

  const rows = ['"Event ID","Date and Time","User","Message"'];
  for (let i = 0; i < 6; i++) {
    rows.push('"4625","not-a-date-' + i + '","-","' + message + '"');
  }
  const result = Core.parse(rows.join('\n'));
  assert(result.ok, 'the file should still parse');

  const analysis = Core.analyse(result);
  assertEqual(analysis.findings.length, 1, 'the failures should still be reported');
  const finding = analysis.findings[0];
  assertEqual(finding.account, 'jsmith', 'the account is still readable from the message');
  assertEqual(finding.eventCount, 6);
  assertEqual(finding.firstMs, null, 'no time should be invented');
  assertIncludes(finding.timeRangeText, 'no readable timestamps', 'the report should say time is unavailable');
  assertIncludes(finding.notes.join(' '), 'not reliable enough', 'the finding should explain the missing window');
  assertEqual(finding.sourceIps.join(','), '203.0.113.77', 'the source address is still readable');
  assertEqual(analysis.stats.windowApplied, false);
});

test('failures with no account anywhere are counted but not grouped', function () {
  const rows = ['"Event ID","Date and Time","User","Message"'];
  for (let i = 0; i < 6; i++) {
    rows.push('"4625","2026-04-07T01:0' + i + ':00","-","An account failed to log on."');
  }
  const analysis = Core.analyse(Core.parse(rows.join('\n')));
  assertEqual(analysis.findings.length, 0, 'grouping unknown accounts together would invent a relationship');
  assertEqual(analysis.notes.length, 1, 'the limitation should be explained');
  assertIncludes(analysis.notes[0], 'could not be attributed to an account');
});

test('a single failed logon never produces a finding', function () {
  const rows = ['"Event ID","Date and Time","User","Message"',
    '"4625","2026-04-07T01:00:00","LAB\\jsmith","An account failed to log on."'];
  const analysis = Core.analyse(Core.parse(rows.join('\n')));
  assertEqual(analysis.findings.length, 0, 'one failure is ordinary');
});

test('two separate bursts are described once, not once per window', function () {
  const rows = ['"Event ID","Date and Time","User","Message"'];
  const addBurst = function (hour) {
    for (let i = 0; i < 5; i++) {
      rows.push('"4625","2026-04-07T' + hour + ':0' + i + ':00","LAB\\jsmith","An account failed to log on."');
    }
  };
  addBurst('01');
  addBurst('05');

  const analysis = Core.analyse(Core.parse(rows.join('\n')));
  assertEqual(analysis.findings.length, 1, 'the same activity must not be reported twice');
  assertEqual(analysis.findings[0].eventCount, 5, 'the busiest burst is reported');
  assertIncludes(analysis.findings[0].notes.join(' '), 'further burst', 'the other burst should still be mentioned');
  assertIncludes(analysis.findings[0].notes.join(' '), 'not duplicated', 'and the reader should be told why');
});

test('re-running the analysis with the same settings gives the same answer', function () {
  const result = Core.parse(SAMPLES.mixed.csv);
  const first = Core.analyse(result, Core.defaultSettings());
  const second = Core.analyse(result, Core.defaultSettings());
  assertEqual(second.findings.length, first.findings.length);
  assertEqual(second.findings[0].id, first.findings[0].id);
  assertEqual(second.stats.totalFindings, first.stats.totalFindings);
});

test('the rule can be switched off entirely', function () {
  const analysis = Core.analyse(Core.parse(SAMPLES.guessing.csv), {
    rules: { repeatedFailedLogons: false }
  });
  assertEqual(findingsNamed(analysis, 'Repeated Failed Logons').length, 0,
    'the disabled rule must not produce its finding');
  // The other authentication rule still runs, which is correct: switching one
  // detection off must not silently disable the rest.
  assertEqual(findingsNamed(analysis, 'Possible Password Guessing Followed By Success').length, 1,
    'the other rule should be unaffected');
});

test('settings are clamped so a typo cannot break the rule', function () {
  assertEqual(Core.normalizeSettings({ failedLogonThreshold: 0 }).failedLogonThreshold, 2);
  assertEqual(Core.normalizeSettings({ failedLogonThreshold: -10 }).failedLogonThreshold, 2);
  assertEqual(Core.normalizeSettings({ failedLogonThreshold: 99999 }).failedLogonThreshold, 1000);
  assertEqual(Core.normalizeSettings({ failedLogonThreshold: 5.6 }).failedLogonThreshold, 6);
  assertEqual(Core.normalizeSettings({ failedLogonThreshold: 'abc' }).failedLogonThreshold, 5,
    'unreadable input should fall back to the default');
  assertEqual(Core.normalizeSettings({ failedLogonWindowMinutes: 0 }).failedLogonWindowMinutes, 1);
  assertEqual(Core.normalizeSettings({}).useTimeWindow, true, 'the window is on by default');
});

test('garbage in the date column never becomes a timestamp', function () {
  // A real trap worth knowing about: the browser's own date parser reads
  // "abc-0" as the year 2000 and "abc-1" as 2001, because it treats the trailing
  // "-0" as a year. An unguarded fallback would invent timestamps out of rubbish,
  // and the time-window rules would then run on those invented times.
  ['abc-0', 'abc-1', 'not-a-date-0', 'garbage', '12345'].forEach(function (value) {
    const analysis = Core.analyzeTimestamp(value);
    assertEqual(analysis.valid, false, '"' + value + '" must not be turned into a date');
  });

  // Genuine text dates must still be understood.
  assertEqual(Core.analyzeTimestamp('Fri Apr 3 14:22:11 2026').valid, true, 'a written date should still parse');
  assertEqual(Core.analyzeTimestamp('Apr 3, 2026').valid, true, 'a month name should still parse');
});

test('unreadable dates in a real file leave the timeline unreliable', function () {
  const rows = ['"Event ID","Date and Time","User"'];
  for (let i = 0; i < 4; i++) {
    rows.push('"4624","abc-' + i + '","LAB\\jsmith"');
  }
  const result = Core.parse(rows.join('\n'));
  assertEqual(result.stats.withTimestamp, 0, 'no event should have a usable time');
  assertEqual(result.stats.timelineReliable, false, 'the timeline must be declared unreliable');
});

/* --------------------------------------------------------------------------
   Tests: the findings appear in the page, and settings re-run the analysis
   -------------------------------------------------------------------------- */
group('Findings in the page');

test('loading the guessing sample shows a Repeated Failed Logons card', function () {
  const sampleData = require(path.join(root, 'samples/sample-data.js'));
  const page = loadPage();

  (page.elements[sampleData.guessing.buttonId].listeners.click || [])[0]();

  assert(isHidden(page.elements['findings-panel']) === false, 'the findings panel should be shown');
  assert(isHidden(page.elements['settings-panel']) === false, 'the settings panel should be shown');

  const cards = cardsTitled(page, 'Repeated Failed Logons');
  assertEqual(cards.length, 1, 'the repeated-failed-logons card should be present exactly once');
  const text = textOf(cards[0]);
  assertIncludes(text, 'Repeated Failed Logons', 'the alert name');
  assertIncludes(text, 'Severity: Medium', 'the severity');
  assertIncludes(text, 'jsmith', 'the account');
  assertIncludes(text, '203.0.113.44', 'the source address');
  assertIncludes(text, 'Observed activity', 'the observed activity section');
  assertIncludes(text, 'Why this matters', 'the why-it-matters section');
  assertIncludes(text, 'Possible benign explanation', 'the benign explanation section');
  assertIncludes(text, 'Suggested investigation', 'the investigation section');
  assertIncludes(text, 'Investigation score', 'the score section');
  assertIncludes(text, '+10', 'the score contribution should be shown');
  assertIncludes(text, 'not a probability', 'the score must be described honestly');
  assertIncludes(page.elements['findings-summary'].textContent, '2 findings', 'the summary line counts both findings');
  assertIncludes(page.elements['findings-summary'].textContent, 'Highest priority: High', 'and reports the top priority');
});

test('the normal sample shows a calm empty state instead of findings', function () {
  const sampleData = require(path.join(root, 'samples/sample-data.js'));
  const page = loadPage();
  (page.elements[sampleData.normal.buttonId].listeners.click || [])[0]();

  const cards = page.elements['findings-list'].children;
  assertEqual(cards.length, 1, 'the empty state is shown as one block');
  const text = textOf(cards[0]);
  assertIncludes(text, 'Nothing to escalate', 'the empty state should reassure');
  assertIncludes(text, 'not proof that nothing happened', 'and it must not overclaim either way');
});

test('changing the threshold in the form re-runs the analysis immediately', function () {
  const sampleData = require(path.join(root, 'samples/sample-data.js'));
  const page = loadPage();

  (page.elements[sampleData.guessing.buttonId].listeners.click || [])[0]();
  assertEqual(cardsTitled(page, 'Repeated Failed Logons').length, 1,
    'one repeated-failed-logons finding at the default threshold');

  const applyHandler = (page.elements['btn-apply-settings'].listeners.click || [])[0];
  assert(applyHandler, 'the apply button should be wired up');

  // Raise the threshold above the eight failures.
  page.elements['setting-threshold'].value = '9';
  applyHandler();
  assertEqual(cardsTitled(page, 'Repeated Failed Logons').length, 0,
    'raising the threshold should clear that finding');

  // Lowering it again should bring the finding back.
  page.elements['setting-threshold'].value = '4';
  applyHandler();
  assertEqual(cardsTitled(page, 'Repeated Failed Logons').length, 1, 'the finding should return');
});

test('Reset Defaults restores the documented values', function () {
  const page = loadPage();

  page.elements['setting-threshold'].value = '42';
  page.elements['setting-window'].value = '3';
  page.elements['setting-use-window'].checked = false;
  (page.elements['btn-apply-settings'].listeners.click || [])[0]();

  (page.elements['btn-reset-settings'].listeners.click || [])[0]();
  assertEqual(page.elements['setting-threshold'].value, '5', 'threshold back to 5');
  assertEqual(page.elements['setting-window'].value, '10', 'window back to 10 minutes');
  assertEqual(page.elements['setting-use-window'].checked, true, 'the window is on again');
});

test('the window status explains whether the window can be applied', function () {
  const sampleData = require(path.join(root, 'samples/sample-data.js'));
  const page = loadPage();

  (page.elements[sampleData.guessing.buttonId].listeners.click || [])[0]();
  assertIncludes(page.elements['window-status'].textContent, 'look reliable', 'a clean file should say so');

  page.elements['setting-use-window'].checked = false;
  (page.elements['btn-apply-settings'].listeners.click || [])[0]();
  assertIncludes(page.elements['window-status'].textContent, 'switched off', 'the status should follow the setting');
});

/* --------------------------------------------------------------------------
   Tests: RULE 2 - failed logons followed by a successful sign-in
   --------------------------------------------------------------------------
   The synthetic files below are built from realistic message text so that each
   variation - matching address, different address, no address, no timestamps -
   can be tested on its own.
   -------------------------------------------------------------------------- */
group('Rule 2: failed logons followed by success');

function authMessage(kind, account, sourceIp, workstation, logonType) {
  if (kind === 'failed') {
    return [
      'An account failed to log on.',
      '',
      'Subject:',
      ' Account Name: WIN10-LAB01$',
      '',
      'Logon Type: ' + logonType,
      '',
      'Account For Which Logon Failed:',
      ' Account Name: ' + (account || ''),
      '',
      'Failure Information:',
      ' Failure Reason: Unknown user name or bad password.',
      ' Status: 0xC000006D',
      ' Sub Status: 0xC000006A',
      '',
      'Network Information:',
      ' Workstation Name: ' + (workstation || '-'),
      ' Source Network Address: ' + (sourceIp || '-')
    ].join('\n');
  }
  return [
    'An account was successfully logged on.',
    '',
    'Subject:',
    ' Account Name: WIN10-LAB01$',
    '',
    'Logon Information:',
    ' Logon Type: ' + logonType,
    '',
    'New Logon:',
    ' Account Name: ' + (account || ''),
    '',
    'Network Information:',
    ' Workstation Name: ' + (workstation || '-'),
    ' Source Network Address: ' + (sourceIp || '-')
  ].join('\n');
}

/**
 * Builds a CSV with a burst of failures and a later successful sign-in.
 * Every option has a default, so a test only states what it is changing.
 */
function buildAuthCsv(options) {
  const settings = options || {};
  const failureCount = settings.failures === undefined ? 6 : settings.failures;
  const account = settings.account === undefined ? 'jsmith' : settings.account;
  const failureIp = settings.failureIp === undefined ? '203.0.113.44' : settings.failureIp;
  const successIp = settings.successIp === undefined ? failureIp : settings.successIp;
  const failureWs = settings.failureWs === undefined ? '-' : settings.failureWs;
  const successWs = settings.successWs === undefined ? '-' : settings.successWs;
  const successTime = settings.successTime || '2026-04-07T02:08:00';
  const datePrefix = settings.datePrefix === undefined ? '2026-04-07T02:0' : settings.datePrefix;
  const successUser = settings.successUser === undefined ? account : settings.successUser;

  const rows = ['"Event ID","Date and Time","User","Message"'];
  for (let i = 0; i < failureCount; i++) {
    rows.push('"4625","' + datePrefix + i + ':00","-","' + authMessage('failed', account, failureIp, failureWs, '3') + '"');
  }
  if (successTime !== null) {
    rows.push('"4624","' + successTime + '","LAB\\' + (successUser || '') + '","'
      + authMessage('success', successUser, successIp, successWs, '10') + '"');
  }
  return rows.join('\n');
}

function rule2Findings(csv, settings) {
  const analysis = Core.analyse(Core.parse(csv), settings);
  return analysis.findings.filter(function (f) { return f.rule === 'failedLogonsFollowedBySuccess'; });
}

const RULE2_NAME = 'Possible Password Guessing Followed By Success';

test('the password guessing sample triggers the High severity finding', function () {
  const findings = rule2Findings(SAMPLES.guessing.csv);
  assertEqual(findings.length, 1, 'exactly one finding for this sample');

  const finding = findings[0];
  assertEqual(finding.name, RULE2_NAME);
  assertEqual(finding.severity, 'High');
  assertEqual(finding.account, 'jsmith');
  assertEqual(finding.eventCount, 9, 'eight failures and the successful sign-in');
  assertEqual(finding.eventIds.join(','), '4625,4624');
  assertIncludes(finding.sourceIps.join(','), '203.0.113.44');
});

test('the sequence is chronological, complete and timestamped', function () {
  const finding = rule2Findings(SAMPLES.guessing.csv)[0];
  assertEqual(finding.sequence.length, 9, 'eight failures then the success');
  assertEqual(finding.sequence[0].eventId, 4625, 'the sequence starts with a failure');
  assertEqual(finding.sequence[8].eventId, 4624, 'and ends with the successful sign-in');
  assertEqual(finding.sequence[0].iso, '2026-04-07 02:14:02');
  assertEqual(finding.sequence[8].iso, '2026-04-07 02:21:44');
  assertEqual(finding.sequence[8].kind, 'successful sign-in');

  for (let i = 1; i < finding.sequence.length; i++) {
    assert(finding.sequence[i].ms > finding.sequence[i - 1].ms,
      'sequence step ' + i + ' should be later than the previous one');
  }

  assertIncludes(finding.sequenceText, '4625 \u2192 4625', 'the arrow chain should be shown');
  assertIncludes(finding.sequenceText, '\u2192 4624', 'and should end with the success');
  assertIncludes(finding.observedActivity, '8 failed sign-in attempts', 'the failed count should be stated');
  assertIncludes(finding.observedActivity, '3m 29s after the last failed attempt', 'the gap should be stated');
});

test('a matching source address is reported as a match', function () {
  const finding = rule2Findings(buildAuthCsv({}))[0];
  const ip = finding.comparisons.filter(function (c) { return c.label === 'Source address'; })[0];
  assertEqual(ip.status, 'match');
  assertIncludes(ip.text, 'same source address', 'the wording should be plain');
  assertIncludes(ip.text, '203.0.113.44');
  assertEqual(finding.severity, 'High', 'a matching address is the stronger correlation');
});

test('differing source addresses are reported and the priority is lowered', function () {
  const finding = rule2Findings(buildAuthCsv({ failureIp: '203.0.113.44', successIp: '10.0.0.5' }))[0];
  const ip = finding.comparisons.filter(function (c) { return c.label === 'Source address'; })[0];
  assertEqual(ip.status, 'differ');
  assertIncludes(ip.text, 'do not match', 'the mismatch must be stated plainly');
  assertIncludes(ip.text, '203.0.113.44');
  assertIncludes(ip.text, '10.0.0.5');
  assertEqual(finding.severity, 'Medium', 'a mismatch must not be reported as the strongest correlation');
  assertIncludes(finding.severityReasons.join(' '), 'different address', 'the reason must be visible');
});

test('a missing source address is reported as undetermined, never as a match', function () {
  const finding = rule2Findings(buildAuthCsv({ failureIp: '', successIp: '' }))[0];
  const ip = finding.comparisons.filter(function (c) { return c.label === 'Source address'; })[0];
  assertEqual(ip.status, 'unknown');
  assertIncludes(ip.text, 'cannot be compared', 'the tool must not imply the sources matched');
  assertEqual(finding.sourceIps.length, 0, 'no address should be invented');
  assertIncludes(finding.severityReasons.join(' '), 'could not be compared', 'the limitation should be stated');
});

test('workstations are compared separately from addresses', function () {
  const finding = rule2Findings(buildAuthCsv({ failureWs: 'KALI-BOX', successWs: 'WIN10-LAB01' }))[0];
  const address = finding.comparisons.filter(function (c) { return c.label === 'Source address'; })[0];
  const workstation = finding.comparisons.filter(function (c) { return c.label === 'Workstation'; })[0];
  assertEqual(address.status, 'match', 'the addresses match in this fixture');
  assertEqual(workstation.status, 'differ', 'but the workstations do not');
  assertIncludes(workstation.text, 'KALI-BOX');
});
test('the normal sample stays free of this alert at the default settings', function () {
  assertEqual(rule2Findings(SAMPLES.normal.csv).length, 0,
    'two mistyped passwords followed by a success must not be escalated at the default threshold');
  assertEqual(rule2Findings(SAMPLES.persistence.csv).length, 0, 'and the privilege sample has no failures at all');

  // Lowering the threshold is the student's choice, and then it should fire -
  // that is the threshold doing its job, not a false positive.
  const strict = rule2Findings(SAMPLES.normal.csv, { failedLogonThreshold: 2 });
  assertEqual(strict.length, 1, 'at a threshold of 2 the two mgrey failures and the sign-in are correlated');
  assertEqual(strict[0].account, 'mgrey');
  assertEqual(strict[0].severity, 'High', 'the sources match in that sample');
});

test('too few failures are never correlated with a success', function () {
  assertEqual(rule2Findings(buildAuthCsv({ failures: 4 })).length, 0,
    'four failures are below the default threshold of five');
  assertEqual(rule2Findings(buildAuthCsv({ failures: 5 })).length, 1,
    'five failures reach the threshold');
});

test('a successful sign-in that comes BEFORE the failures is not correlated', function () {
  const rows = ['"Event ID","Date and Time","User","Message"',
    '"4624","2026-04-07T01:00:00","LAB\\jsmith","' + authMessage('success', 'jsmith', '203.0.113.44', '-', '10') + '"'];
  for (let i = 0; i < 6; i++) {
    rows.push('"4625","2026-04-07T02:0' + i + ':00","-","' + authMessage('failed', 'jsmith', '203.0.113.44', '-', '3') + '"');
  }
  assertEqual(rule2Findings(rows.join('\n')).length, 0,
    'the rule looks for failures followed by a success, not the other way round');
});

test('unrelated accounts are never correlated with each other', function () {
  // Five failures for alice, and a success for bob.
  const rows = ['"Event ID","Date and Time","User","Message"'];
  for (let i = 0; i < 5; i++) {
    rows.push('"4625","2026-04-07T02:0' + i + ':00","-","' + authMessage('failed', 'alice', '203.0.113.44', '-', '3') + '"');
  }
  rows.push('"4624","2026-04-07T02:08:00","LAB\\bob","' + authMessage('success', 'bob', '203.0.113.44', '-', '10') + '"');
  assertEqual(rule2Findings(rows.join('\n')).length, 0, 'a different account must never be paired up');

  // Three failures each for alice and bob, plus a success for alice: neither
  // account reaches the threshold, so there is nothing to correlate.
  const split = ['"Event ID","Date and Time","User","Message"'];
  ['alice', 'bob'].forEach(function (name) {
    for (let i = 0; i < 3; i++) {
      split.push('"4625","2026-04-07T02:0' + i + ':00","-","' + authMessage('failed', name, '203.0.113.44', '-', '3') + '"');
    }
  });
  split.push('"4624","2026-04-07T02:09:00","LAB\\alice","' + authMessage('success', 'alice', '203.0.113.44', '-', '10') + '"');
  assertEqual(rule2Findings(split.join('\n')).length, 0, 'three failures per account is below the threshold');
});

test('missing timestamps fall back to file order and say so', function () {
  const csv = buildAuthCsv({ datePrefix: 'not-a-date-', successTime: 'also-not-a-date' });
  const findings = rule2Findings(csv);
  assertEqual(findings.length, 1, 'the sequence should still be found from the order of the rows');

  const finding = findings[0];
  assertEqual(finding.firstMs, null, 'no time should be invented');
  assertEqual(finding.sequence[0].iso, '', 'sequence steps should have no invented time');
  // Without timestamps only the failures in the file are used, so the length is
  // not guaranteed to be 9; the sequence still has to END with the success.
  assertEqual(finding.sequence[finding.sequence.length - 1].eventId, 4624, 'the order still ends with the success');
  assertIncludes(finding.notes.join(' '), 'order of the rows', 'the assumption must be stated');
  assertEqual(finding.severity, 'Medium', 'without a time window the correlation is weaker');
  assertIncludes(finding.severityReasons.join(' '), 'could not be placed inside a single time window', 'the reason is shown');
});

test('a success with no account anywhere produces no correlation', function () {
  const rows = ['"Event ID","Date and Time","User","Message"'];
  for (let i = 0; i < 6; i++) {
    rows.push('"4625","2026-04-07T02:0' + i + ':00","-","An account failed to log on."');
  }
  rows.push('"4624","2026-04-07T02:09:00","-","An account was successfully logged on."');
  assertEqual(rule2Findings(rows.join('\n')).length, 0,
    'without an account there is nothing to correlate, and guessing would invent evidence');
});

test('two successful sign-ins after the failures are described once', function () {
  const rows = ['"Event ID","Date and Time","User","Message"'];
  for (let i = 0; i < 6; i++) {
    rows.push('"4625","2026-04-07T02:0' + i + ':00","-","' + authMessage('failed', 'jsmith', '203.0.113.44', '-', '3') + '"');
  }
  rows.push('"4624","2026-04-07T02:08:00","LAB\\jsmith","' + authMessage('success', 'jsmith', '203.0.113.44', '-', '10') + '"');
  rows.push('"4624","2026-04-07T02:09:30","LAB\\jsmith","' + authMessage('success', 'jsmith', '203.0.113.44', '-', '10') + '"');

  const findings = rule2Findings(rows.join('\n'));
  assertEqual(findings.length, 1, 'the same sequence must not be reported twice');
  assertEqual(findings[0].sequence[findings[0].sequence.length - 1].iso, '2026-04-07 02:08:00',
    'the earliest successful sign-in is the one described');
  assertIncludes(findings[0].notes.join(' '), 'further 1 successful sign-in', 'the other success is still mentioned');
});

test('the score is explainable and never presented as a probability', function () {
  const finding = rule2Findings(SAMPLES.guessing.csv)[0];
  assertEqual(finding.score.total, 30, 'ten for the repeated failures plus twenty for the success');
  assertEqual(finding.score.factors.length, 2, 'both contributions are itemised');
  assertEqual(finding.score.factors[0].points, 10);
  assertEqual(finding.score.factors[1].points, 20);
  assertIncludes(finding.score.factors[1].label, 'successful sign-in following the failures', 'the documented wording');

  const allText = [finding.observedActivity, finding.whyItMatters, finding.benign, finding.severityReasons.join(' ')].join(' ');
  assertEqual(allText.indexOf('%'), -1, 'no percentage should appear anywhere in the finding');
  assertEqual(allText.toLowerCase().indexOf('probability'), -1, 'and it must not be described as a probability');
  assertEqual(allText.toLowerCase().indexOf('malicious'), -1, 'and no event should be called malicious');
});

test('the finding explains itself, offers a benign explanation and next steps', function () {
  const finding = rule2Findings(SAMPLES.guessing.csv)[0];
  assertIncludes(finding.whyItMatters, 'guessed', 'the reason this pattern matters');
  assertIncludes(finding.whyItMatters, 'legitimate user', 'and the honest counter-possibility');
  assertIncludes(finding.benign, 'wrong password', 'the benign explanation should be concrete');
  assertIncludes(finding.benign, 'got it right', 'including the most likely everyday cause');
  assert(finding.investigation.length >= 5, 'several investigation steps');
  assertIncludes(finding.investigation.join(' '), 'source address', 'starting with the source address');
});

test('the two authentication findings point at each other', function () {
  const analysis = Core.analyse(Core.parse(SAMPLES.guessing.csv));
  const repeated = analysis.findings.filter(function (f) { return f.rule === 'repeatedFailedLogons'; })[0];
  const sequence = analysis.findings.filter(function (f) { return f.rule === 'failedLogonsFollowedBySuccess'; })[0];

  assertIncludes(sequence.crossReferences.join(' '), 'Repeated Failed Logons',
    'the sequence finding should reference the failure finding');
  assertIncludes(sequence.crossReferences.join(' '), 'same activity',
    'and should explain that the two describe the same activity');
  assertIncludes(repeated.crossReferences.join(' '), RULE2_NAME,
    'and the failure finding should reference the sequence finding');
});

test('the rule can be switched off on its own', function () {
  const analysis = Core.analyse(Core.parse(SAMPLES.guessing.csv), {
    rules: { failedLogonsFollowedBySuccess: false }
  });
  assertEqual(analysis.findings.filter(function (f) { return f.rule === 'failedLogonsFollowedBySuccess'; }).length, 0);
  assertEqual(analysis.findings.filter(function (f) { return f.rule === 'repeatedFailedLogons'; }).length, 1,
    'the other rule still runs');
});

test('the sequence finding is the highest priority one in the guessing sample', function () {
  const analysis = Core.analyse(Core.parse(SAMPLES.guessing.csv));
  assertEqual(analysis.findings[0].name, RULE2_NAME, 'sorted by severity, so High comes first');
  assertEqual(analysis.stats.highestSeverity, 'High');
  assertEqual(analysis.stats.bySeverity.High, 1);
  assertEqual(analysis.stats.bySeverity.Medium, 1);
});

test('the page shows the sequence and the source comparison', function () {
  const sampleData = require(path.join(root, 'samples/sample-data.js'));
  const page = loadPage();
  (page.elements[sampleData.guessing.buttonId].listeners.click || [])[0]();

  const cards = cardsTitled(page, RULE2_NAME);
  assertEqual(cards.length, 1, 'the sequence card should be present once');

  const text = textOf(cards[0]);
  assertIncludes(text, 'Severity: High', 'the High severity badge');
  assertIncludes(text, 'Sequence of events', 'the sequence section');
  assertIncludes(text, '4625 \u2192 4625', 'the arrow chain');
  assertIncludes(text, '2026-04-07 02:14:02', 'the timestamps');
  assertIncludes(text, 'Do the sources match?', 'the comparison section');
  assertIncludes(text, 'Same', 'the match badge');
  assertIncludes(text, 'same source address', 'the comparison explanation');
  assertIncludes(text, 'Related findings', 'the cross-reference section');
  assertIncludes(text, 'not a probability', 'the score disclaimer');
});
/* --------------------------------------------------------------------------
   Tests: RULE 3 - a new account granted privileges
   -------------------------------------------------------------------------- */
group('Rule 3: new account granted privileges');

function rule3Findings(csv, settings) {
  return Core.analyse(Core.parse(csv), settings).findings.filter(function (f) {
    return f.rule === 'accountCreatedThenPrivileged';
  });
}

function createdAndAdded(groupName, options) {
  const settings = options || {};
  const story = [
    'A user account was created.',
    '',
    'Subject:',
    ' Account Name: ' + (settings.creator || 'labadmin'),
    '',
    'New Account:',
    ' Account Name: ' + (settings.target || 'temp-admin')
  ].join('\n');

  const membership = [
    'A member was added to a security-enabled ' + (settings.scope || 'local') + ' group.',
    '',
    'Member:',
    ' Account Name: ' + (settings.target || 'temp-admin'),
    '',
    'Group:',
    ' Group Name: ' + groupName,
    ' Group Domain: BUILTIN',
    '',
    'Subject:',
    ' Account Name: ' + (settings.granter || settings.creator || 'labadmin')
  ].join('\n');

  const rows = ['"Event ID","Date and Time","User","Message"'];
  rows.push('"4624","2026-04-08T09:00:00","LAB\\' + (settings.creator || 'labadmin') + '","An account was successfully logged on."');
  rows.push('"4720","' + (settings.createdAt !== undefined ? settings.createdAt : '2026-04-08T09:02:00') + '","LAB\\'
    + (settings.creator || 'labadmin') + '","' + story + '"');
  rows.push('"' + (settings.scope === 'global' ? 4728 : 4732) + '","'
    + (settings.grantedAt !== undefined ? settings.grantedAt : '2026-04-08T09:04:00') + '","LAB\\'
    + (settings.granter || settings.creator || 'labadmin') + '","' + membership + '"');
  return rows.join('\n');
}

test('the persistence sample reports New Account Granted Privileges at High', function () {
  const findings = rule3Findings(SAMPLES.persistence.csv);
  assertEqual(findings.length, 1, 'exactly one finding');

  const finding = findings[0];
  assertEqual(finding.name, 'New Account Granted Privileges');
  assertEqual(finding.severity, 'High');
  assertEqual(finding.account, 'temp-admin', 'the account that was created');
  assertEqual(finding.actor, 'labadmin', 'the account that created it');
  assertEqual(finding.eventIds.join(','), '4720,4732');
  assertEqual(finding.sequenceText, '4720 \u2192 4732');
  assertIncludes(finding.observedActivity, 'Administrators', 'the group should be named');
  assertIncludes(finding.observedActivity, '1m 35s', 'the gap between the two events');
  assertEqual(finding.score.total, 50, 'created (+25) and privileged group change (+25)');
  assertEqual(finding.score.factors.length, 2);
});

test('the finding never claims the creation was unauthorised', function () {
  const finding = rule3Findings(SAMPLES.persistence.csv)[0];
  const text = [finding.observedActivity, finding.whyItMatters, finding.benign, finding.severityReasons.join(' ')].join(' ').toLowerCase();

  assert(text.indexOf('malicious') === -1, 'the tool must not call the activity malicious');
  assertIncludes(finding.benign, 'onboarding', 'the everyday explanation should be offered');
  assertIncludes(finding.whyItMatters, 'do not tell you which of those happened',
    'the finding should say plainly that the events cannot establish intent');
});

test('a privileged global group also produces a High finding', function () {
  const finding = rule3Findings(createdAndAdded('Domain Admins', { scope: 'global' }))[0];
  assertEqual(finding.severity, 'High');
  assertIncludes(finding.observedActivity, 'Domain Admins');
  assertEqual(finding.eventIds.join(','), '4720,4728');
});

test('an ordinary group is reported at Medium, not High', function () {
  const finding = rule3Findings(createdAndAdded('Users'))[0];
  assertEqual(finding.severity, 'Medium');
  assertIncludes(finding.severityReasons.join(' '), 'not one this tool treats as privileged');
  assertEqual(finding.score.total, 25, 'only the account-creation contribution');
});

test('a creation with no later privilege change produces no finding', function () {
  const rows = ['"Event ID","Date and Time","User","Message"',
    '"4720","2026-04-08T09:02:00","LAB\\labadmin","A user account was created.\n\nSubject:\n Account Name: labadmin\n\nNew Account:\n Account Name: temp-admin"'];
  assertEqual(rule3Findings(rows.join('\n')).length, 0);
});

test('a privilege change with no creation produces no finding', function () {
  const rows = ['"Event ID","Date and Time","User","Message"',
    '"4732","2026-04-08T09:04:00","LAB\\labadmin","A member was added to a security-enabled local group.\n\nMember:\n Account Name: temp-admin\n\nGroup:\n Group Name: Administrators\n\nSubject:\n Account Name: labadmin"'];
  assertEqual(rule3Findings(rows.join('\n')).length, 0,
    'Rule 3 is about a NEW account, so an existing one must not trigger it');
});

test('a privilege change for a different account is not correlated', function () {
  const csv = createdAndAdded('Administrators', { target: 'temp-admin' })
    .replace('Account Name: temp-admin\n\nGroup:', 'Account Name: someone-else\n\nGroup:');
  assertEqual(rule3Findings(csv).length, 0, 'the member account must match the created account');
});

test('different creators and granters are pointed out', function () {
  const finding = rule3Findings(createdAndAdded('Administrators', {
    creator: 'labadmin',
    granter: 'svc-backup'
  }))[0];
  assertIncludes(finding.notes.join(' '), 'Two different accounts were involved');
  assertIncludes(finding.notes.join(' '), 'labadmin');
  assertIncludes(finding.notes.join(' '), 'svc-backup');
});

test('missing timestamps do not stop the correlation, and are disclosed', function () {
  const csv = createdAndAdded('Administrators', {
    createdAt: 'not-a-date',
    grantedAt: 'also-not-a-date'
  });
  const finding = rule3Findings(csv)[0];
  assert(finding, 'the identity of the account still links the two events');
  assertIncludes(finding.notes.join(' '), 'cannot be measured');
  assertEqual(finding.firstMs, null, 'no time should be invented');
});

test('the mixed sample correlates helpdesk-temp with svc-backup', function () {
  const finding = rule3Findings(SAMPLES.mixed.csv)[0];
  assertEqual(finding.account, 'helpdesk-temp');
  assertEqual(finding.actor, 'svc-backup');
  assertEqual(finding.severity, 'High');
  assertIncludes(finding.observedActivity, 'Administrators');
});

/* --------------------------------------------------------------------------
   Tests: RULE 4 - the security audit log was cleared
   -------------------------------------------------------------------------- */
group('Rule 4: audit log cleared');

function rule4Findings(csv) {
  return Core.analyse(Core.parse(csv)).findings.filter(function (f) {
    return f.rule === 'securityLogCleared';
  });
}

test('the mixed sample reports the cleared log at High with the account named', function () {
  const findings = rule4Findings(SAMPLES.mixed.csv);
  assertEqual(findings.length, 1);

  const finding = findings[0];
  assertEqual(finding.name, 'Security Audit Log Cleared');
  assertEqual(finding.severity, 'High');
  assertEqual(finding.account, 'svc-backup');
  assertEqual(finding.eventIds.join(','), '1102');
  assertEqual(finding.score.total, 30);
});

test('the explanation matches what the specification asks for', function () {
  const finding = rule4Findings(SAMPLES.mixed.csv)[0];
  assertIncludes(finding.whyItMatters, 'can happen during legitimate maintenance');
  assertIncludes(finding.whyItMatters, 'remove evidence');
  assertIncludes(finding.benign, 'rebuild');
  assert(finding.investigation.length >= 4, 'several investigation steps');
});

test('the finding records how much other activity the file still holds', function () {
  const finding = rule4Findings(SAMPLES.mixed.csv)[0];
  assertIncludes(finding.notes.join(' '), 'came before the log was cleared');
  assertIncludes(finding.notes.join(' '), 'account, group or service change',
    'the administrative activity before the clearing should be mentioned');
});

test('a file with no 1102 produces no such finding', function () {
  assertEqual(rule4Findings(SAMPLES.normal.csv).length, 0);
  assertEqual(rule4Findings(SAMPLES.guessing.csv).length, 0);
});

test('a 1102 with no readable account still produces a finding that says so', function () {
  const rows = ['"Event ID","Date and Time","User","Message"',
    '"1102","2026-04-09T02:45:00","-","The audit log was cleared."'];
  const finding = rule4Findings(rows.join('\n'))[0];
  assertEqual(finding.severity, 'High', 'the event is serious even without an account');
  assertEqual(finding.account, '');
  assertIncludes(finding.severityReasons.join(' '), 'does not name the account');
});

/* --------------------------------------------------------------------------
   Tests: RULE 5 - administrative / privilege activity summary
   -------------------------------------------------------------------------- */
group('Rule 5: administrative activity summary');

function adminSummaryOf(key) {
  return Core.analyse(Core.parse(SAMPLES[key].csv)).administrativeActivity;
}

test('the mixed sample summarises its account, group, service and log changes', function () {
  const summary = adminSummaryOf('mixed');
  assert(summary, 'a summary should be produced');
  assertEqual(summary.total, 5, '4720, 4732, 7045, 4726 and 1102');
  assertEqual(summary.counts[4720], 1);
  assertEqual(summary.counts[4732], 1);
  assertEqual(summary.counts[7045], 1);
  assertEqual(summary.counts[4726], 1);
  assertEqual(summary.counts[1102], 1);
  assertEqual(summary.privilegedChanges, 1);
  assertEqual(summary.logCleared, 1);
  assertIncludes(summary.actors.map(function (a) { return a.name; }).join(','), 'svc-backup');
});

test('the summary does not claim the events are related', function () {
  const summary = adminSummaryOf('mixed');
  assertIncludes(summary.explanation, 'not assumed to be related');
  assertIncludes(summary.explanation, 'analyst');
  assertEqual(summary.severity, undefined, 'a summary must not carry a severity');
});

test('the summary is in chronological order and names each account', function () {
  const summary = adminSummaryOf('mixed');
  const times = summary.items.map(function (item) { return item.ms; }).filter(function (ms) { return ms !== null; });
  for (let i = 1; i < times.length; i++) {
    assert(times[i] >= times[i - 1], 'the summary should be in time order');
  }
  summary.items.forEach(function (item) {
    assert(item.title, 'each line should say what the event means');
    assert(item.account || item.actor, 'each line should name an account');
  });
});

test('a quiet file with no administrative events has no summary', function () {
  assertEqual(adminSummaryOf('normal'), null, 'the normal sample has no account or group changes');
  assertEqual(adminSummaryOf('guessing'), null, 'and neither does the guessing sample');
});

test('the persistence sample lists both of its administrative events', function () {
  const summary = adminSummaryOf('persistence');
  assertEqual(summary.total, 2, 'the creation and the group change');
  assertEqual(summary.privilegedChanges, 1);
  assertEqual(summary.actors[0].name, 'labadmin');
});

test('the summary creates no findings of its own', function () {
  const analysis = Core.analyse(Core.parse(SAMPLES.mixed.csv), {
    rules: {
      repeatedFailedLogons: false,
      failedLogonsFollowedBySuccess: false,
      accountCreatedThenPrivileged: false,
      securityLogCleared: false,
      administrativeActivitySummary: true
    }
  });
  assertEqual(analysis.findings.length, 0, 'the summary is a section, not an alert');
  assert(analysis.administrativeActivity, 'but the summary is still produced');
});

/* --------------------------------------------------------------------------
   Tests: the dashboard
   -------------------------------------------------------------------------- */
group('Dashboard');

function dashboardOf(key, settings) {
  return Core.analyse(Core.parse(SAMPLES[key].csv), settings).dashboard;
}

test('the dashboard counts everything the specification asks for', function () {
  const dashboard = dashboardOf('mixed');
  assertEqual(dashboard.totalEvents, 15);
  assertEqual(dashboard.successfulLogons, 2);
  assertEqual(dashboard.failedLogons, 6);
  assertEqual(dashboard.accountsCreated, 1);
  assertEqual(dashboard.accountsDeleted, 1);
  assertEqual(dashboard.privilegeChanges, 1);
  assertEqual(dashboard.logCleared, 1);
  assertEqual(dashboard.processCreations, 1);
  assertEqual(dashboard.serviceInstalls, 1);
  assert(dashboard.eventsRequiringInvestigation > 0, 'some events should need investigation');
});

test('the dashboard lists top accounts, top failures, common Event IDs and priorities', function () {
  const dashboard = dashboardOf('mixed');

  assertEqual(dashboard.topAccounts[0].account, 'svc-backup', 'the busiest account');
  assertEqual(dashboard.topAccounts[0].count, 10,
    'six failures, the success, the process, the script block and the log clearing');

  assertEqual(dashboard.topFailedAccounts[0].account, 'svc-backup');
  assertEqual(dashboard.topFailedAccounts[0].count, 6);

  assertEqual(dashboard.topEventIds[0].eventId, 4625, 'the most common Event ID');
  assertEqual(dashboard.topEventIds[0].count, 6);
  assertIncludes(dashboard.topEventIds[0].title, 'Failed logon', 'IDs should be explained');
});

test('the quiet sample needs no investigation', function () {
  const dashboard = dashboardOf('normal');
  assertEqual(dashboard.totalEvents, 15);
  assertEqual(dashboard.failedLogons, 2);
  assertEqual(dashboard.eventsRequiringInvestigation, 0, 'nothing should be escalated');
  assertEqual(dashboard.accountsCreated, 0);
  assertEqual(dashboard.bySeverity.High, 0);
  assertEqual(dashboard.bySeverity.Medium, 0);
});

test('the timeline is chronological and only holds noteworthy events', function () {
  const dashboard = dashboardOf('mixed');
  assert(dashboard.timelineAvailable, 'this sample has readable timestamps');
  assert(dashboard.timeline.length > 0, 'the timeline should not be empty');

  const times = dashboard.timeline.map(function (item) { return item.ms; }).filter(function (ms) { return ms !== null; });
  for (let i = 1; i < times.length; i++) {
    assert(times[i] >= times[i - 1], 'timeline entries should be in time order');
  }

  const reasons = dashboard.timeline.map(function (item) { return item.reason; }).join(' ');
  assertIncludes(reasons, 'New Account Granted Privileges', 'findings should be represented');
  assertIncludes(reasons, 'Administrative or privilege activity', 'and administrative events too');
});

test('the timeline says when timestamps are unavailable', function () {
  const rows = ['"Event ID","Date and Time","Message"',
    '"4625","not-a-date","An account failed to log on."',
    '"1102","also-not-a-date","The audit log was cleared."'];
  const dashboard = Core.analyse(Core.parse(rows.join('\n'))).dashboard;
  assertEqual(dashboard.timelineAvailable, false);
  assert(dashboard.timeline.length >= 1, 'the events still appear, in file order');
});

/* --------------------------------------------------------------------------
   Tests: the page renders the dashboard, the summary and the filters
   -------------------------------------------------------------------------- */
group('Dashboard and filters in the page');

test('loading the mixed sample fills the dashboard and the administrative table', function () {
  const page = loadPage();
  (page.elements[SAMPLES.mixed.buttonId].listeners.click || [])[0]();

  assert(isHidden(page.elements['dashboard-panel']) === false, 'the dashboard should be shown');
  assertEqual(page.elements['dash-total'].textContent, '15');
  assertEqual(page.elements['dash-failed'].textContent, '6');
  assertEqual(page.elements['dash-created'].textContent, '1');
  assertEqual(page.elements['dash-cleared'].textContent, '1');
  assert(Number(page.elements['dash-investigate'].textContent) > 0, 'events needing investigation');

  assert(page.elements['dash-top-accounts'].children.length > 0, 'top accounts should be listed');
  assert(page.elements['dash-top-failures'].children.length > 0, 'top failures should be listed');
  assert(page.elements['dash-top-ids'].children.length > 0, 'common Event IDs should be listed');
  assert(page.elements['dash-timeline-body'].children.length > 0, 'the timeline should have rows');

  assert(isHidden(page.elements['admin-panel']) === false, 'the administrative section should be shown');
  assertEqual(page.elements['admin-body'].children.length, 5, 'five administrative events');
  assertIncludes(page.elements['admin-explanation'].textContent, 'not assumed to be related',
    'the limitation must be visible');
});

test('the quiet sample shows a dashboard with nothing to investigate', function () {
  const page = loadPage();
  (page.elements[SAMPLES.normal.buttonId].listeners.click || [])[0]();

  assertEqual(page.elements['dash-investigate'].textContent, '0');
  assertEqual(page.elements['dash-failed'].textContent, '2');
  assert(isHidden(page.elements['admin-panel']), 'no administrative section for a quiet file');
});

test('the filter controls are filled from the loaded data', function () {
  const page = loadPage();
  (page.elements[SAMPLES.mixed.buttonId].listeners.click || [])[0]();

  assert(page.elements['filter-eventid'].children.length > 1, 'Event ID options');
  assert(page.elements['filter-account'].children.length > 1, 'account options');
  assert(page.elements['filter-ip'].children.length > 1, 'source address options');
  assert(page.elements['filter-category'].children.length > 1, 'event type options');

  const ids = page.elements['filter-eventid'].children.map(function (option) { return option.value; });
  assertIncludes(ids.join(','), '4625', 'Event ID 4625 should be selectable');
});

test('filtering by Event ID narrows the table and updates the count', function () {
  const page = loadPage();
  (page.elements[SAMPLES.mixed.buttonId].listeners.click || [])[0]();

  assertEqual(page.elements['events-body'].children.length, 15, 'all events are listed initially');
  assertIncludes(page.elements['filter-count'].textContent, 'No filters applied');

  page.elements['filter-eventid'].value = '4625';
  (page.elements['filter-eventid'].listeners.change || [])[0]();

  assertEqual(page.elements['events-body'].children.length, 6, 'only the six failures');
  assertIncludes(page.elements['filter-count'].textContent, 'Showing 6 of 15');
});

test('filtering by account, priority and source address all work together', function () {
  const page = loadPage();
  (page.elements[SAMPLES.mixed.buttonId].listeners.click || [])[0]();

  page.elements['filter-account'].value = 'svc-backup';
  (page.elements['filter-account'].listeners.change || [])[0]();
  assertEqual(page.elements['events-body'].children.length, 10, 'everything attributed to svc-backup');

  page.elements['filter-severity'].value = 'High';
  (page.elements['filter-severity'].listeners.change || [])[0]();
  const highRows = page.elements['events-body'].children.length;
  assert(highRows > 0 && highRows < 10, 'the High filter should narrow it further');

  page.elements['filter-ip'].value = '198.51.100.23';
  (page.elements['filter-ip'].listeners.change || [])[0]();
  assert(page.elements['events-body'].children.length > 0, 'the address filter should still match rows');
  assertIncludes(page.elements['filter-count'].textContent, 'after filtering');
});

test('the search box matches account, computer and message text', function () {
  const page = loadPage();
  (page.elements[SAMPLES.mixed.buttonId].listeners.click || [])[0]();

  page.elements['filter-search'].value = 'helpdesk-temp';
  (page.elements['filter-search'].listeners.input || [])[0]();
  assert(page.elements['events-body'].children.length >= 2, 'the created account appears in several events');

  page.elements['filter-search'].value = 'no-such-text-anywhere';
  (page.elements['filter-search'].listeners.input || [])[0]();
  assertIncludes(textOf(page.elements['events-body']), 'No events match');
});

test('clearing the filters restores the full list', function () {
  const page = loadPage();
  (page.elements[SAMPLES.mixed.buttonId].listeners.click || [])[0]();

  page.elements['filter-eventid'].value = '1102';
  (page.elements['filter-eventid'].listeners.change || [])[0]();
  assertEqual(page.elements['events-body'].children.length, 1);

  (page.elements['btn-clear-filters'].listeners.click || [])[0]();
  assertEqual(page.elements['events-body'].children.length, 15);
  assertEqual(page.elements['filter-eventid'].value, '');
});

test('filters never change the findings', function () {
  const page = loadPage();
  (page.elements[SAMPLES.mixed.buttonId].listeners.click || [])[0]();

  const findingsBefore = page.elements['findings-list'].children.length;

  page.elements['filter-eventid'].value = '4624';
  (page.elements['filter-eventid'].listeners.change || [])[0]();
  page.elements['filter-search'].value = 'nothing-matches-this';
  (page.elements['filter-search'].listeners.input || [])[0]();

  assertEqual(page.elements['findings-list'].children.length, findingsBefore,
    'the report must not change because the event table is filtered');
});
/* --------------------------------------------------------------------------
   Tests: accessibility and markup hygiene
   --------------------------------------------------------------------------
   These catch the problems you cannot see: a missing page heading, a label that
   points at nothing, a control with no label, or an ARIA reference to an id that
   does not exist.
   -------------------------------------------------------------------------- */
group('Accessibility and markup');

test('the page has exactly one top-level heading', function () {
  const html = readSource('index.html');
  const h1s = Array.from(html.matchAll(/<h1[\s>]/g));
  assertEqual(h1s.length, 1, 'a page should have exactly one h1');
});

test('no element id is defined twice', function () {
  const html = readSource('index.html');
  const ids = Array.from(html.matchAll(/\sid="([^"]+)"/g)).map(function (m) { return m[1]; });
  const seen = {};
  const duplicates = [];
  ids.forEach(function (id) {
    if (seen[id]) duplicates.push(id);
    seen[id] = true;
  });
  assertEqual(duplicates.join(','), '', 'duplicate ids break labels, focus and scripts');
});

test('every ARIA reference points at an element that exists', function () {
  const html = readSource('index.html');
  const ids = new Set(Array.from(html.matchAll(/\sid="([^"]+)"/g)).map(function (m) { return m[1]; }));
  const refs = Array.from(html.matchAll(/aria-(?:labelledby|describedby)="([^"]+)"/g))
    .flatMap(function (m) { return m[1].split(/\s+/); });
  assert(refs.length > 5, 'the page should be using aria-labelledby');
  const dangling = refs.filter(function (ref) { return !ids.has(ref); });
  assertEqual(dangling.join(','), '', 'these ARIA references point at missing ids');
});

test('every form control has a real label', function () {
  const html = readSource('index.html');
  const labels = new Set(Array.from(html.matchAll(/<label[^>]*for="([^"]+)"/g)).map(function (m) { return m[1]; }));
  const controls = Array.from(html.matchAll(/<(input|select|textarea)[^>]*id="([^"]+)"/g))
    .map(function (m) { return { tag: m[1], id: m[2] }; });

  assert(controls.length >= 8, 'the page has several controls to check');
  const unlabelled = controls.filter(function (control) { return !labels.has(control.id); });
  assertEqual(unlabelled.map(function (c) { return c.tag + '#' + c.id; }).join(','), '',
    'every control needs a label');
});

test('the page does not use inline event handlers', function () {
  const html = readSource('index.html');
  assertNoMatch(html, /\son(click|change|input|load|error|submit)\s*=/i,
    'inline event handlers are blocked by the CSP and are bad practice');
});

test('the upload control can be reached and its focus is visible', function () {
  const html = readSource('index.html');
  const css = readSource('styles.css');
  assertIncludes(html, 'for="file-input"', 'the file input needs a label to be clickable and readable');
  assertNoMatch(html, /id="file-input"[^>]*\shidden/, 'the input must stay focusable, not removed from the tab order');
  assertIncludes(css, '.drop-zone:focus-within', 'keyboard focus on the hidden input must be shown');
});

test('severity is never communicated by colour alone', function () {
  const js = readSource('script.js');
  assertIncludes(js, "'Severity: ' + finding.severity", 'the severity word must be printed, not just coloured');
  assertIncludes(js, 'severityClass(severity)', 'the colour class is used as well as the word');
});

test('the page uses headings, tables and lists rather than div soup', function () {
  const html = readSource('index.html');
  assert((html.match(/<h2/g) || []).length >= 6, 'sections should be h2 headings');
  assert((html.match(/<table/g) || []).length >= 5, 'data should be in tables');
  assert((html.match(/scope="col"/g) || []).length >= 20, 'table headers need a scope');
  assert((html.match(/<caption/g) || []).length >= 5, 'tables should be captioned');
  assertIncludes(html, 'aria-live="polite"', 'the status region should be announced politely');
  assertIncludes(html, 'role="alert"', 'hard errors should interrupt');
});


/* --------------------------------------------------------------------------
   Tests: the application shell (tabs, empty states, activity chart)
   -------------------------------------------------------------------------- */
group('Application shell');

test('the page has five tabs wired to five panels', function () {
  const html = readSource('index.html');
  ['dashboard', 'events', 'learn', 'export', 'privacy'].forEach(function (name) {
    assertIncludes(html, 'id="tab-' + name + '"', 'the ' + name + ' tab should exist');
    assertIncludes(html, 'id="panel-' + name + '"', 'the ' + name + ' panel should exist');
    assertIncludes(html, 'aria-controls="panel-' + name + '"', 'the tab should control its panel');
    assertIncludes(html, 'aria-labelledby="tab-' + name + '"', 'the panel should be labelled by its tab');
  });
  assertIncludes(html, 'role="tablist"', 'the tabs need a tablist role');
  assertEqual((html.match(/role="tab"/g) || []).length, 5, 'exactly five tabs');
  assertEqual((html.match(/role="tabpanel"/g) || []).length, 5, 'exactly five panels');
});

test('only the dashboard panel is visible on first load', function () {
  const page = loadPage();
  assertEqual(page.elements['panel-dashboard'].hidden, false, 'the dashboard is the landing tab');
  ['panel-events', 'panel-learn', 'panel-export', 'panel-privacy'].forEach(function (id) {
    assertEqual(page.elements[id].hidden, true, id + ' should start hidden');
  });
  assertEqual(page.elements['tab-dashboard'].getAttribute('aria-selected'), 'true');
  assertEqual(page.elements['tab-events'].getAttribute('aria-selected'), 'false');
});

test('clicking a tab switches the visible panel', function () {
  const page = loadPage();
  const eventsTab = page.elements['tab-events'];
  (eventsTab.listeners.click || [])[0]();

  assertEqual(page.elements['panel-events'].hidden, false, 'the events panel should be shown');
  assertEqual(page.elements['panel-dashboard'].hidden, true, 'the dashboard should be hidden');
  assertEqual(eventsTab.getAttribute('aria-selected'), 'true');
  assertEqual(page.elements['tab-dashboard'].getAttribute('aria-selected'), 'false');
});

test('the arrow keys move between tabs', function () {
  const page = loadPage();
  const keydown = (page.elements['tab-dashboard'].listeners.keydown || [])[0];
  assert(keydown, 'the tabs should handle arrow keys');

  let prevented = false;
  keydown({ key: 'ArrowRight', preventDefault: function () { prevented = true; } });

  assert(prevented, 'the default scroll behaviour should be prevented');
  assertEqual(page.elements['panel-events'].hidden, false, 'ArrowRight should move to Events');

  const eventsKeydown = (page.elements['tab-events'].listeners.keydown || [])[0];
  eventsKeydown({ key: 'ArrowLeft', preventDefault: function () {} });
  assertEqual(page.elements['panel-dashboard'].hidden, false, 'ArrowLeft should come back');
});


test('the header shortcuts jump to the right tab', function () {
  const page = loadPage();

  (page.elements['btn-privacy-jump'].listeners.click || [])[0]();
  assertEqual(page.elements['panel-privacy'].hidden, false, 'privacy shortcut');

  (page.elements['btn-goto-dashboard'].listeners.click || [])[0]();
  assertEqual(page.elements['panel-dashboard'].hidden, false, 'export page back-link');

  (page.elements['btn-open-events'].listeners.click || [])[0]();
  assertEqual(page.elements['panel-events'].hidden, false, 'findings to events shortcut');
});

test('the invitation empty state disappears when data loads', function () {
  const page = loadPage();
  assert(isHidden(page.elements['workspace-empty']) === false, 'the invitation is visible at first');
  assert(isHidden(page.elements['details-card']), 'file details are not offered before a file');

  (page.elements[SAMPLES.normal.buttonId].listeners.click || [])[0]();

  assert(isHidden(page.elements['workspace-empty']), 'the invitation goes away once data exists');
  assert(isHidden(page.elements['details-card']) === false, 'file details become available');
});

test('the activity chart is drawn from real event timestamps', function () {
  const page = loadPage();
  (page.elements[SAMPLES.mixed.buttonId].listeners.click || [])[0]();

  const bars = page.elements['dash-activity'].children.filter(function (node) {
    return String(node.className).indexOf('chart__bar') !== -1;
  });
  assert(bars.length > 0, 'the chart should have bars');
  bars.forEach(function (bar) {
    assert(bar.getAttribute('aria-label'), 'each bar needs an accessible label');
    assert(bar.getAttribute('title'), 'each bar needs a tooltip with the count');
  });
  assertIncludes(page.elements['dash-activity-range'].textContent, 'hourly', 'this sample spans hours');
});

test('the timeline holds only noteworthy events, not every row', function () {
  // Nine ordinary successful logons are not noteworthy on their own.
  const quiet = ['"Event ID","Date and Time","User","Message"'];
  for (let i = 0; i < 9; i++) {
    quiet.push('"4624","2026-01-01T10:0' + i + ':00","LAB\\jsmith","An account was successfully logged on."');
  }
  const quietDashboard = Core.analyse(Core.parse(quiet.join('\n'))).dashboard;
  assertEqual(quietDashboard.timeline.length, 0, 'nothing noteworthy, so an empty timeline');

  // A burst of failures is noteworthy, so it appears.
  const busy = ['"Event ID","Date and Time","User","Message"'];
  for (let i = 0; i < 6; i++) {
    busy.push('"4625","2026-01-01T10:0' + i + ':00","LAB\\jsmith","An account failed to log on."');
  }
  const busyDashboard = Core.analyse(Core.parse(busy.join('\n'))).dashboard;
  assert(busyDashboard.timeline.length >= 6, 'the failures should appear on the timeline');
});

test('long finding sections are collapsible but still present', function () {
  const page = loadPage();
  (page.elements[SAMPLES.mixed.buttonId].listeners.click || [])[0]();

  const cards = cardsTitled(page, 'New Account Granted Privileges');
  assertEqual(cards.length, 1);

  const details = [];
  (function walk(node) {
    if (String(node.className).indexOf('finding__details') !== -1) details.push(node);
    (node.children || []).forEach(walk);
  })(cards[0]);

  assert(details.length >= 1, 'the finding should use a details element');
  const text = textOf(details[0]);
  assertIncludes(text, 'Possible benign explanation', 'the benign explanation is still there');
  assertIncludes(text, 'Suggested investigation', 'and the investigation steps');
});


});
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







