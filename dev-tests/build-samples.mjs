/* ==========================================================================
   dev-tests/build-samples.mjs
   --------------------------------------------------------------------------
   Generates the four demo datasets.

   WHY THIS FILE EXISTS
   --------------------
   The demo data has to exist in two places:
     1. samples/*.csv            - real files a student can also upload by hand
     2. samples/sample-data.js   - the same data embedded, so the demo buttons
                                   work when index.html is opened by
                                   double-clicking it (browsers refuse to let a
                                   file:// page read other local files)
   Writing the data twice by hand guarantees that one day the two copies will
   disagree and the demo will be wrong. So the data is written ONCE, here, and
   this script emits both. run-tests.mjs then fails the build if the committed
   files ever drift from this source.

   Run after editing:   node dev-tests/build-samples.mjs

   All data is fictional: invented people, invented computers, and only
   private (RFC 1918) or documentation (RFC 5737) IP addresses.
   ========================================================================== */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const samplesDir = path.join(root, 'samples');

/* --------------------------------------------------------------------------
   CSV output helpers
   --------------------------------------------------------------------------
   Line endings: "\n". Real Event Viewer exports use CRLF and the parser handles
   both (there is a test for it); LF keeps the repository and the diff clean.
   -------------------------------------------------------------------------- */
const COLUMNS = [
  'Level', 'Date and Time', 'Source', 'Event ID',
  'Task Category', 'User', 'Computer', 'Keywords', 'Message'
];

function csvCell(value) {
  const text = String(value == null ? '' : value);
  // Quote a cell when it contains a quote, a comma or a line break, and double
  // any quote inside it - exactly what a correct exporter does.
  if (/[",\r\n]/.test(text)) return '"' + text.replace(/"/g, '""') + '"';
  return text;
}

function toCsv(rows) {
  const lines = [COLUMNS.join(',')];
  rows.forEach(function (r) {
    lines.push(COLUMNS.map(function (column) { return csvCell(r[column]); }).join(','));
  });
  return lines.join('\n') + '\n';
}

/** Builds one CSV row from friendly short field names. */
function row(spec) {
  return {
    'Level': spec.level || 'Information',
    'Date and Time': spec.time,
    'Source': spec.source || 'Microsoft-Windows-Security-Auditing',
    'Event ID': String(spec.id),
    'Task Category': spec.category || 'Logon',
    'User': spec.user || '-',
    'Computer': spec.computer || '-',
    'Keywords': spec.keywords === undefined ? 'Audit Success' : spec.keywords,
    'Message': spec.message
  };
}

/* --------------------------------------------------------------------------
   Message builders
   --------------------------------------------------------------------------
   Real Windows event messages are long and contain tab characters. These are
   condensed to the parts an analyst actually reads, and use single spaces
   instead of tabs for readability. The parser treats tabs and spaces the same
   way, and there is a test proving tabs work.

   NOTE ON BACKSLASHES: inside a JavaScript template literal, "C:\Windows"
   would silently lose its backslashes, so every path here is written with a
   doubled backslash ("C:\\Windows").
   -------------------------------------------------------------------------- */
function logonSuccess(spec) {
  return 'An account was successfully logged on.\n'
    + '\n'
    + 'Subject:\n'
    + ' Security ID: S-1-5-18\n'
    + ' Account Name: ' + spec.computer + '$\n'
    + '\n'
    + 'Logon Information:\n'
    + ' Logon Type: ' + spec.logonType + '\n'
    + '\n'
    + 'New Logon:\n'
    + ' Security ID: S-1-5-21-1111111111-2222222222-3333333333-' + spec.rid + '\n'
    + ' Account Name: ' + spec.account + '\n'
    + ' Account Domain: LAB\n'
    + '\n'
    + 'Network Information:\n'
    + ' Workstation Name: ' + spec.workstation + '\n'
    + ' Source Network Address: ' + spec.sourceIp + '\n'
    + ' Source Port: 0';
}

function logonFailure(spec) {
  return 'An account failed to log on.\n'
    + '\n'
    + 'Subject:\n'
    + ' Security ID: S-1-5-18\n'
    + ' Account Name: ' + spec.computer + '$\n'
    + '\n'
    + 'Logon Type: ' + spec.logonType + '\n'
    + '\n'
    + 'Account For Which Logon Failed:\n'
    + ' Security ID: NULL SID\n'
    + ' Account Name: ' + spec.account + '\n'
    + ' Account Domain: LAB\n'
    + '\n'
    + 'Failure Information:\n'
    + ' Failure Reason: ' + spec.reason + '\n'
    + ' Status: ' + spec.status + '\n'
    + ' Sub Status: ' + spec.subStatus + '\n'
    + '\n'
    + 'Network Information:\n'
    + ' Workstation Name: ' + spec.workstation + '\n'
    + ' Source Network Address: ' + spec.sourceIp;
}

function accountCreated(spec) {
  return 'A user account was created.\n'
    + '\n'
    + 'Subject:\n'
    + ' Account Name: ' + spec.actor + '\n'
    + ' Account Domain: LAB\n'
    + '\n'
    + 'New Account:\n'
    + ' Account Name: ' + spec.target + '\n'
    + ' Account Domain: LAB\n'
    + '\n'
    + 'Attributes:\n'
    + ' SAM Account Name: ' + spec.target + '\n'
    + ' User Account Control: Account Enabled';
}

function accountDeleted(spec) {
  return 'A user account was deleted.\n'
    + '\n'
    + 'Subject:\n'
    + ' Account Name: ' + spec.actor + '\n'
    + ' Account Domain: LAB\n'
    + '\n'
    + 'Target Account:\n'
    + ' Account Name: ' + spec.target + '\n'
    + ' Account Domain: LAB';
}

function memberAdded(spec) {
  return 'A member was added to a security-enabled ' + spec.scope + ' group.\n'
    + '\n'
    + 'Member:\n'
    + ' Security ID: S-1-5-21-1111111111-2222222222-3333333333-' + spec.rid + '\n'
    + ' Account Name: ' + spec.target + '\n'
    + ' Account Domain: LAB\n'
    + '\n'
    + 'Group:\n'
    + ' Group Name: ' + spec.group + '\n'
    + ' Group Domain: ' + spec.groupDomain + '\n'
    + '\n'
    + 'Subject:\n'
    + ' Account Name: ' + spec.actor + '\n'
    + ' Account Domain: LAB';
}

function auditLogCleared(spec) {
  return 'The audit log was cleared.\n'
    + '\n'
    + 'Subject:\n'
    + ' Security ID: S-1-5-21-1111111111-2222222222-3333333333-' + spec.rid + '\n'
    + ' Account Name: ' + spec.actor + '\n'
    + ' Account Domain: LAB\n'
    + ' Logon ID: ' + spec.logonId;
}

function processCreated(spec) {
  return 'A new process has been created.\n'
    + '\n'
    + 'New Process Name: ' + spec.process + '\n'
    + ' Creator Process Name: ' + spec.parent + '\n'
    + ' Process Command Line: ' + spec.commandLine + '\n'
    + '\n'
    + 'Subject:\n'
    + ' Account Name: ' + spec.account + '\n'
    + ' Account Domain: LAB';
}

function scriptBlock(spec) {
  return 'Creating Scriptblock text (1 of 1):\n'
    + spec.script + '\n'
    + '\n'
    + 'ScriptBlock ID: 11111111-2222-3333-4444-' + spec.blockId + '\n'
    + 'Path:\n'
    + '\n'
    + 'Account Name: ' + spec.account;
}

function serviceInstalled(spec) {
  return 'A service was installed in the system.\n'
    + '\n'
    + 'Service Name: ' + spec.service + '\n'
    + 'Service File Name: ' + spec.path + '\n'
    + 'Service Type: user mode service\n'
    + 'Service Start Type: auto start\n'
    + 'Service Account: ' + spec.account;
}

/* --------------------------------------------------------------------------
   Compact event helpers
   --------------------------------------------------------------------------
   These keep the datasets below short enough to read as a story, instead of
   pages of repeated boilerplate.
   -------------------------------------------------------------------------- */
const SRC = 'Microsoft-Windows-Security-Auditing';

function successLogon(time, account, computer, logonType, sourceIp, workstation) {
  return row({
    time: time, id: 4624, category: 'Logon', user: 'LAB\\' + account, computer: computer,
    message: logonSuccess({
      account: account, computer: computer, logonType: logonType,
      sourceIp: sourceIp, workstation: workstation, rid: '1105'
    })
  });
}

function failedLogon(time, account, computer, sourceIp, workstation, logonType) {
  return row({
    time: time, id: 4625, category: 'Logon', user: '-', computer: computer, keywords: 'Audit Failure',
    message: logonFailure({
      account: account, computer: computer, logonType: logonType || '3',
      reason: 'Unknown user name or bad password.',
      status: '0xC000006D', subStatus: '0xC000006A',
      sourceIp: sourceIp, workstation: workstation
    })
  });
}

function processStart(time, account, computer, process, parent, commandLine) {
  return row({
    time: time, id: 4688, category: 'Process Creation', user: 'LAB\\' + account, computer: computer,
    message: processCreated({
      account: account, process: process, parent: parent, commandLine: commandLine
    })
  });
}

function logoff(time, account, computer, logonType) {
  return row({
    time: time, id: 4634, category: 'Logoff', user: 'LAB\\' + account, computer: computer,
    message: 'An account was logged off.\n\nSubject:\n Account Name: ' + account
      + '\n Account Domain: LAB\n\nLogon Type: ' + logonType
  });
}

function accountCreatedEv(time, actor, target, computer) {
  return row({
    time: time, id: 4720, category: 'User Account Management',
    user: 'LAB\\' + actor, computer: computer,
    message: accountCreated({ actor: actor, target: target })
  });
}

function accountDeletedEv(time, actor, target, computer) {
  return row({
    time: time, id: 4726, category: 'User Account Management',
    user: 'LAB\\' + actor, computer: computer,
    message: accountDeleted({ actor: actor, target: target })
  });
}

function groupAddedEv(time, actor, target, computer, groupSpec) {
  return row({
    time: time, id: groupSpec.scope === 'local' ? 4732 : 4728,
    category: 'Security Group Management', user: 'LAB\\' + actor, computer: computer,
    message: memberAdded({
      target: target, actor: actor, scope: groupSpec.scope,
      group: groupSpec.group, groupDomain: groupSpec.groupDomain, rid: '1150'
    })
  });
}

function logClearedEv(time, actor, computer) {
  return row({
    time: time, id: 1102, category: 'Audit Policy Change', source: SRC,
    user: 'LAB\\' + actor, computer: computer, keywords: 'Audit Success',
    message: auditLogCleared({ actor: actor, rid: '1103', logonId: '0x1A2B3C' })
  });
}

function scriptBlockEv(time, account, computer, script, blockId) {
  return row({
    time: time, id: 4104, category: 'Execute a Remote Command',
    source: 'Microsoft-Windows-PowerShell', user: 'LAB\\' + account, computer: computer,
    keywords: '', message: scriptBlock({ account: account, script: script, blockId: blockId })
  });
}

function serviceInstalledEv(time, service, servicePath, account, computer) {
  return row({
    time: time, id: 7045, category: 'None', source: 'Service Control Manager',
    user: 'SYSTEM', computer: computer, keywords: '',
    message: serviceInstalled({ service: service, path: servicePath, account: account })
  });
}

const LOCAL_ADMIN = { group: 'Administrators', groupDomain: 'BUILTIN', scope: 'local' };

/* --------------------------------------------------------------------------
   Dataset 1 - a normal day
   --------------------------------------------------------------------------
   Expected result: mostly informational activity. The two mistyped passwords
   are below the default threshold of 5, so nothing should be escalated.
   -------------------------------------------------------------------------- */
const NORMAL = {
  key: 'normal',
  file: 'normal-windows-events.csv',
  label: 'Normal Windows activity',
  buttonId: 'btn-sample-normal',
  summary: 'A quiet Monday morning in a small lab: people signing in, opening applications, two mistyped passwords, and an administrator running a routine backup copy.',
  expectation: 'Mostly informational activity. The two mistyped passwords stay below the failure threshold, so nothing should be escalated.',
  rows: [
    successLogon('2026-04-06T08:41:12', 'jsmith', 'WIN10-LAB01', '2', '192.168.10.25', 'WIN10-LAB01'),
    processStart('2026-04-06T08:42:03', 'jsmith', 'WIN10-LAB01',
      'C:\\Windows\\explorer.exe', 'C:\\Windows\\System32\\userinit.exe', 'explorer.exe'),
    processStart('2026-04-06T08:42:44', 'jsmith', 'WIN10-LAB01',
      'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', 'C:\\Windows\\explorer.exe', '"OUTLOOK.EXE"'),
    successLogon('2026-04-06T08:45:19', 'mgrey', 'WIN10-LAB02', '2', '192.168.10.31', 'WIN10-LAB02'),
    failedLogon('2026-04-06T08:52:41', 'mgrey', 'WIN10-LAB02', '192.168.10.31', 'WIN10-LAB02', '2'),
    failedLogon('2026-04-06T08:52:58', 'mgrey', 'WIN10-LAB02', '192.168.10.31', 'WIN10-LAB02', '2'),
    successLogon('2026-04-06T08:53:20', 'mgrey', 'WIN10-LAB02', '2', '192.168.10.31', 'WIN10-LAB02'),
    successLogon('2026-04-06T09:05:11', 'bpatel', 'WIN10-LAB03', '2', '192.168.10.44', 'WIN10-LAB03'),
    processStart('2026-04-06T09:06:00', 'bpatel', 'WIN10-LAB03',
      'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', 'C:\\Windows\\explorer.exe', '"WINWORD.EXE" report.docx'),
    successLogon('2026-04-06T09:30:22', 'labadmin', 'WIN10-LAB01', '10', '192.168.10.5', 'ADMIN-PC'),
    processStart('2026-04-06T09:31:05', 'labadmin', 'WIN10-LAB01',
      'C:\\Windows\\System32\\robocopy.exe', 'C:\\Windows\\System32\\cmd.exe', 'robocopy \\\\FILESRV\\backup D:\\backup /MIR'),
    processStart('2026-04-06T10:15:33', 'bpatel', 'WIN10-LAB03',
      'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE', 'C:\\Windows\\explorer.exe', '"EXCEL.EXE" budget.xlsx'),
    logoff('2026-04-06T17:14:52', 'jsmith', 'WIN10-LAB01', '2'),
    logoff('2026-04-06T17:15:10', 'mgrey', 'WIN10-LAB02', '2'),
    logoff('2026-04-06T17:15:31', 'bpatel', 'WIN10-LAB03', '2')
  ]
};

/* --------------------------------------------------------------------------
   Dataset 2 - password guessing
   --------------------------------------------------------------------------
   Eight failures for one account from one address inside four minutes, then a
   success. Expected result: "Repeated Failed Logons" and "Possible Password
   Guessing Followed By Success".
   Note the User column is "-": that is exactly what a real 4625 contains, which
   is why the account has to be read out of the message text.
   -------------------------------------------------------------------------- */
const GUESSING = {
  key: 'guessing',
  file: 'password-guessing.csv',
  label: 'Password guessing against one account',
  buttonId: 'btn-sample-guessing',
  summary: 'At 02:14 in the morning, eight failed network logons for jsmith arrive from one documentation-range IP address, followed by a successful Remote Desktop logon.',
  expectation: 'A "Repeated Failed Logons" finding and a higher-priority "failed logons followed by a success" finding for jsmith.',
  rows: [
    failedLogon('2026-04-07T02:14:02', 'jsmith', 'WIN10-LAB01', '203.0.113.44', '-', '3'),
    failedLogon('2026-04-07T02:14:39', 'jsmith', 'WIN10-LAB01', '203.0.113.44', '-', '3'),
    failedLogon('2026-04-07T02:15:11', 'jsmith', 'WIN10-LAB01', '203.0.113.44', '-', '3'),
    failedLogon('2026-04-07T02:15:47', 'jsmith', 'WIN10-LAB01', '203.0.113.44', '-', '3'),
    failedLogon('2026-04-07T02:16:20', 'jsmith', 'WIN10-LAB01', '203.0.113.44', '-', '3'),
    failedLogon('2026-04-07T02:17:02', 'jsmith', 'WIN10-LAB01', '203.0.113.44', '-', '3'),
    failedLogon('2026-04-07T02:17:38', 'jsmith', 'WIN10-LAB01', '203.0.113.44', '-', '3'),
    failedLogon('2026-04-07T02:18:15', 'jsmith', 'WIN10-LAB01', '203.0.113.44', '-', '3'),
    successLogon('2026-04-07T02:21:44', 'jsmith', 'WIN10-LAB01', '10', '203.0.113.44', '-')
  ]
};

/* --------------------------------------------------------------------------
   Dataset 3 - account created then given privileges
   --------------------------------------------------------------------------
   Expected result: "New Account Granted Privileges" - a 4720 immediately
   followed by a 4732 into the local Administrators group, and then the new
   account is actually used.
   -------------------------------------------------------------------------- */
const PERSISTENCE = {
  key: 'persistence',
  file: 'account-persistence.csv',
  label: 'Account created then granted privileges',
  buttonId: 'btn-sample-privilege',
  summary: 'An administrator signs in, creates a new account called temp-admin, adds it to the local Administrators group two minutes later, and then that new account signs in.',
  expectation: 'A "New Account Granted Privileges" finding, raised to High because the group is Administrators.',
  rows: [
    successLogon('2026-04-08T09:00:12', 'labadmin', 'WIN10-LAB04', '2', '192.168.10.5', 'ADMIN-PC'),
    accountCreatedEv('2026-04-08T09:02:35', 'labadmin', 'temp-admin', 'WIN10-LAB04'),
    groupAddedEv('2026-04-08T09:04:10', 'labadmin', 'temp-admin', 'WIN10-LAB04', LOCAL_ADMIN),
    successLogon('2026-04-08T09:07:48', 'temp-admin', 'WIN10-LAB04', '2', '192.168.10.5', 'ADMIN-PC')
  ]
};

/* --------------------------------------------------------------------------
   Dataset 4 - the mixed overnight story
   --------------------------------------------------------------------------
   A service account fails to authenticate six times from an unusual address,
   succeeds, creates an account, gives it local administrator rights, installs
   a service, runs an encoded PowerShell command, deletes the account again and
   finally clears the security log.

   IMPORTANT: event 7045 comes from the System log, not the Security log. It is
   included here on purpose, because students are told to look at more than one
   log, and this tool reads whatever events are in the file it is given.
   -------------------------------------------------------------------------- */
const MIXED = {
  key: 'mixed',
  file: 'suspicious-admin-activity.csv',
  label: 'Mixed overnight administrative activity',
  buttonId: 'btn-sample-mixed',
  summary: 'Overnight, the svc-backup service account fails to authenticate six times from an unusual address, then succeeds and performs a chain of administrative actions - including clearing the security log.',
  expectation: 'Several correlated findings at once: repeated failures followed by a success, a new account granted privileges, a service installed, and a High-priority audit log cleared finding.',
  rows: [
    failedLogon('2026-04-09T01:09:58', 'svc-backup', 'FILESRV01', '198.51.100.23', '-', '3'),
    failedLogon('2026-04-09T01:10:31', 'svc-backup', 'FILESRV01', '198.51.100.23', '-', '3'),
    failedLogon('2026-04-09T01:11:04', 'svc-backup', 'FILESRV01', '198.51.100.23', '-', '3'),
    failedLogon('2026-04-09T01:11:39', 'svc-backup', 'FILESRV01', '198.51.100.23', '-', '3'),
    failedLogon('2026-04-09T01:12:15', 'svc-backup', 'FILESRV01', '198.51.100.23', '-', '3'),
    failedLogon('2026-04-09T01:12:51', 'svc-backup', 'FILESRV01', '198.51.100.23', '-', '3'),
    successLogon('2026-04-09T01:16:22', 'svc-backup', 'FILESRV01', '3', '198.51.100.23', '-'),
    processStart('2026-04-09T01:18:03', 'svc-backup', 'FILESRV01',
      'C:\\Windows\\System32\\cmd.exe', 'C:\\Windows\\System32\\services.exe',
      'cmd.exe /c net user helpdesk-temp /add'),
    accountCreatedEv('2026-04-09T01:25:40', 'svc-backup', 'helpdesk-temp', 'FILESRV01'),
    groupAddedEv('2026-04-09T01:27:15', 'svc-backup', 'helpdesk-temp', 'FILESRV01', LOCAL_ADMIN),
    serviceInstalledEv('2026-04-09T01:29:44', 'LabUpdaterSvc',
      'C:\\ProgramData\\LabUpdater\\updater.exe', 'LocalSystem', 'FILESRV01'),
    scriptBlockEv('2026-04-09T01:33:02', 'svc-backup', 'FILESRV01',
      'powershell.exe -EncodedCommand R2V0LVNlcnZpY2U=', '5555'),
    accountDeletedEv('2026-04-09T02:30:19', 'svc-backup', 'helpdesk-temp', 'FILESRV01'),
    logClearedEv('2026-04-09T02:45:07', 'svc-backup', 'FILESRV01'),
    successLogon('2026-04-09T09:02:11', 'labadmin', 'WIN10-LAB01', '2', '192.168.10.5', 'ADMIN-PC')
  ]
};

const DATASETS = [NORMAL, GUESSING, PERSISTENCE, MIXED];

/* --------------------------------------------------------------------------
   Output
   --------------------------------------------------------------------------
   Two artifacts from one source, so they can never disagree:
     samples/<file>.csv          - for uploading by hand
     samples/sample-data.js      - the same text embedded for the demo buttons
   -------------------------------------------------------------------------- */
function build() {
  fs.mkdirSync(samplesDir, { recursive: true });

  const embedded = {};
  let totalEvents = 0;

  DATASETS.forEach(function (dataset) {
    const csv = toCsv(dataset.rows);
    totalEvents += dataset.rows.length;

    fs.writeFileSync(path.join(samplesDir, dataset.file), csv, 'utf8');

    embedded[dataset.key] = {
      key: dataset.key,
      file: dataset.file,
      label: dataset.label,
      buttonId: dataset.buttonId,
      summary: dataset.summary,
      expectation: dataset.expectation,
      csv: csv
    };

    console.log('  samples/' + dataset.file + '  (' + dataset.rows.length + ' events)');
  });

  const banner = [
    '/*!',
    ' * samples/sample-data.js',
    ' * ---------------------------------------------------------------------',
    ' * GENERATED FILE - DO NOT EDIT BY HAND.',
    ' *',
    ' * Why this file exists: browsers refuse to let a page opened from a file://',
    ' * path read other local files, so the demo buttons cannot simply fetch the',
    ' * .csv files next to them. The demo data is therefore embedded here as text.',
    ' *',
    ' * The .csv files in this folder and the text below are both produced from',
    ' * dev-tests/build-samples.mjs. Edit that script and run:',
    ' *     node dev-tests/build-samples.mjs',
    ' * The test suite fails if the two ever drift apart.',
    ' *',
    ' * All data is fictional: invented people and computers, and only private',
    ' * (RFC 1918) or documentation (RFC 5737) IP addresses.',
    ' */',
    '(function () {',
    "  'use strict';",
    '',
    '  var DATA = ' + JSON.stringify(embedded, null, 2) + ';',
    '',
    '  if (typeof module !== "undefined" && module && module.exports) module.exports = DATA;',
    '  if (typeof window !== "undefined") window.TRIAGE_SAMPLE_DATA = DATA;',
    '  if (typeof globalThis !== "undefined") globalThis.TRIAGE_SAMPLE_DATA = DATA;',
    '})();',
    ''
  ].join('\n');

  fs.writeFileSync(path.join(samplesDir, 'sample-data.js'), banner, 'utf8');

  console.log('  samples/sample-data.js  (embedded copy of all ' + totalEvents + ' events)');
  console.log('\nDone. Now run the tests:  node dev-tests/run-tests.mjs\n');
}

build();





