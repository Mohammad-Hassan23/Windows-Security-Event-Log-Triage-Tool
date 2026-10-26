# Windows Security Event Log Triage Tool

**Security Log Triage Lab** &mdash; an educational, offline, browser-based triage tool for
Windows Security event logs exported to CSV.

Upload an Event Viewer or PowerShell export, and the tool explains what the events mean,
correlates the ones that belong together, and produces a SOC-style triage report that says
*why* each finding deserves investigation &mdash; including the innocent explanations.

> **Educational SOC triage tool. Findings indicate activity that may deserve investigation and
> do not prove malicious behaviour. Only analyse logs from systems you own or are authorised to
> investigate.**

---

## Contents

- [Quick start](#quick-start)
- [The interface](#the-interface)
- [Privacy: what happens to your logs](#privacy-what-happens-to-your-logs)
- [What this tool is, and what it is not](#what-this-tool-is-and-what-it-is-not)
- [Windows Event Logs in one page](#windows-event-logs-in-one-page)
- [What SOC triage means](#what-soc-triage-means)
- [How the analysis works](#how-the-analysis-works)
- [Supported Event IDs](#supported-event-ids)
- [Detection and correlation rules](#detection-and-correlation-rules)
- [Severity and the investigation score](#severity-and-the-investigation-score)
- [Settings](#settings)
- [Dashboard and filters](#dashboard-and-filters)
- [How to export your event data](#how-to-export-your-event-data)
- [Sample datasets and demo walkthrough](#sample-datasets-and-demo-walkthrough)
- [False positives](#false-positives)
- [Limitations](#limitations)
- [Security and accessibility](#security-and-accessibility)
- [Running the automated tests](#running-the-automated-tests)
- [Project structure](#project-structure)
- [Future improvements (not implemented)](#future-improvements-not-implemented)

---

## Quick start

Nothing needs to be installed. There is no build step, no server and no account.

1. Download or clone this repository.
2. **Double-click `index.html`.** It opens in your default browser (Edge, Chrome, Firefox).
3. Click one of the four **demo buttons** to see a complete report, or upload your own CSV.
4. Optionally adjust the thresholds in **Analysis settings**; the analysis re-runs immediately.

That is the whole installation. The tool works with no internet connection.

**Browser support:** any current version of Edge, Chrome, Firefox or Safari. It uses standard
browser APIs only (`FileReader`, `TextDecoder`), with no polyfills and no dependencies.

**Hosting it later:** because it is a set of static files, the folder can be published as-is to
GitHub Pages, Netlify, Cloudflare Pages or any static host. See
[Security and accessibility](#security-and-accessibility) for the stricter Content-Security-Policy
to use once it is served over HTTP rather than opened from disk.

---

## The interface

The application is a small SOC-style workspace with five tabs, not one long page.

| Tab | What is there |
|---|---|
| **Dashboard** | Upload and demo controls, summary tiles, the event-activity chart, findings, the administrative activity table, the timeline, and (collapsed) file details and analysis settings |
| **Events** | The filterable event explorer: every parsed event with Event ID, account, computer, source IP, priority and message |
| **Learn** | How to think like a SOC analyst, and a plain-English reference for the ten supported Event IDs |
| **Export data** | How to get a CSV out of Windows Event Viewer or PowerShell, with the caveats |
| **Privacy & limits** | The privacy architecture, the disclaimer, and what the tool cannot do |

The header carries the product name, a **Local analysis** indicator and a **100% offline** badge.
A slim privacy strip sits under it on every tab, with the full explanation one click away.

Before a file is loaded the dashboard shows an invitation, never placeholder numbers. Once data is
analysed the tiles, findings and charts appear. A findings card keeps the headline facts, the
observed activity and the score visible, and folds the benign explanation and the investigation
steps into a single expandable section so the report stays scannable.

The **event activity chart** is built from the file's own timestamps, with a bucket size chosen from
the span (minutes, hours, days or weeks). When the timestamps are missing or ambiguous it says so
instead of drawing a timeline it cannot trust.


---

## Privacy: what happens to your logs

**Your Windows security logs are analysed locally in your browser. Files are not uploaded or
transmitted anywhere.**

This is a structural guarantee, not a promise:

| Mechanism | How it is enforced |
|---|---|
| No upload | The only file API used is `FileReader`, which hands the bytes to the page. There is no upload endpoint, because there is no server. |
| No network calls | No `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon` or `EventSource` anywhere in the code. An automated test fails the build if one appears. |
| No external resources | No CDN fonts, scripts, images or analytics. The page loads three local files. A test fails the build if a remote `src` or `href` is added. |
| No storage of your data | Log data lives in JavaScript variables only. Nothing is written to `localStorage`, `sessionStorage`, IndexedDB or cookies. Close the tab and it is gone. A test enforces this. |
| No telemetry | There is no analytics, tracking, advertising or error reporting of any kind. |
| Defence in depth | The page sets a Content-Security-Policy that forbids outbound connections (`connect-src 'none'`), form submissions, plugins and frames. |

**Settings are session-only too.** The threshold and time window are held in memory. Your
configuration disappears when you close the tab, along with the log data. `localStorage` is
deliberately not used.

**Files are not retained.** The browser holds the file only while the page is open. Nothing is
written to disk by this tool.

---

## What this tool is, and what it is not

**It is** a teaching aid that helps you read Windows authentication, account and privilege
activity the way an analyst does: identify the event, understand the account and source, decide
whether it was expected, look for related events, and decide whether to escalate.

**It is not** an intrusion detection system, an EDR, a SIEM, or a verdict machine. It does not
score "how malicious" something is, and it never says a system has been compromised. It cannot
know whether an action was authorised, because that information is not in the log &mdash; it is in
your ticket system, your change calendar and the person sitting next to you.

Two sentences from the interface are worth repeating:

> One security event rarely tells the entire story. Analysts build context by correlating
> multiple events.

> A detection is a reason to investigate, not proof that an attacker is present.

---

## Windows Event Logs in one page

Windows keeps several event logs. The one this tool is built for is the **Security** log
(`Windows Logs &rarr; Security`), which records authentication, account changes, privilege changes
and audit-log operations. Event **7045** (service installed) comes from the **System** log, so a
combined export can include it too.

Each line in the log is an *event* with:

- an **Event ID** &mdash; a number identifying the type of activity (4624 = successful logon);
- a **timestamp**;
- a **level** (Information, Warning, Error, and for audit events "Audit Success/Failure");
- the **account** involved, and often the **computer**;
- a **message**: structured text with labelled blocks (`Subject:`, `New Logon:`, `Network
  Information:` ...). Most of the useful detail lives here, which is why this tool parses the
  message rather than only the columns.

A **logon type** is a number that says *how* somebody signed in: 2 is someone at the keyboard,
3 is a network logon (a file share), 5 is a service, 10 is Remote Desktop. This matters more than
the account name in many investigations.

---

## What SOC triage means

A Security Operations Centre is the team that watches an organisation's systems. *Triage* is the
first pass: deciding which alerts deserve a human's attention, and in what order.

Triage is not about being certain. It is about asking, for each event:

1. **Identify** the event. What is it?
2. **Understand** what happened: which account, from where, when.
3. **Identify the affected user or system.**
4. **Decide whether it is expected** for that account, at that hour, on that device.
5. **Look for related events.**
6. **Correlate** authentication and privilege activity.
7. **Gather additional evidence** (endpoint logs, VPN, MFA, the user).
8. **Decide whether to escalate**, and document what you ruled out.

The tool automates steps 1, 2 and 5&ndash;6 as far as a single file allows, and deliberately leaves
4, 7 and 8 to you.

---

## How the analysis works

```
CSV text -> decode -> detect separator -> read records -> map columns
                                                            |
                        +-----------------------------------+
                        v
     for each row: identify the Event ID, split the Message into its blocks,
     read the account from the CORRECT block, extract the useful fields
                        |
                        v
     detection rules (by event type) -> correlation rules (by account, over time)
                        |
                        v
     findings + administrative summary + dashboard figures
```

**Reading the message correctly is the hard part.** In a `4624` the label `Account Name` appears
twice: once in `Subject:` (the computer's account, e.g. `WIN10-LAB01$`) and once in `New Logon:`
(the person). A parser that takes the first match reports the computer as the user. This tool
splits the message into blocks first and reads from the block that actually holds the answer:

| Event | Value | Taken from |
|---|---|---|
| 4624 | account | `New Logon:` |
| 4625 | account | `Account For Which Logon Failed:` |
| 4720 | new account | `New Account:` |
| 4726 | deleted account | `Target Account:` |
| 4728 / 4732 | member and group | `Member:` and `Group:` |
| 1102, 4688 | account | `Subject:` |

When the expected block is missing &mdash; older or unusual formats &mdash; the tool falls back to the
last occurrence and records `accountBlock: "fallback"`, so the report never hides that it had to
guess. When a value is absent it stays empty and is listed in `missing`; nothing is invented.

---

## Supported Event IDs

| ID | Meaning | Priority on its own | What the tool extracts |
|---|---|---|---|
| **4624** | Successful logon | Informational | account (New Logon), logon type in plain English, source address, workstation |
| **4625** | Failed logon | Low | account (failed-logon block), logon type, failure reason, status and sub-status codes translated (e.g. `0xC000006A` = wrong password), source address, workstation |
| **4688** | Process created | Informational | process, parent process, command line, account |
| **4720** | User account created | Medium | new account, the account that created it |
| **4726** | User account deleted | Low | deleted account, the account that deleted it |
| **4728** | Added to a global security group | Medium | member, group, who granted it, whether the group is privileged |
| **4732** | Added to a local security group | Medium | member, group, who granted it, whether the group is privileged |
| **1102** | Security audit log cleared | **High** | the account that cleared it |
| **4104** | PowerShell script block logged | Informational | the script text, plus up to three observations about encoding or obfuscation |
| **7045** | Service installed | Medium | service name, program path, type, start type, service account |

Anything else is still counted and displayed as "not explained by this version". Unfamiliar
events are never treated as suspicious merely because they are unfamiliar.

Version 1 deliberately supports **ten** Event IDs. Hundreds more exist; adding them without
explanation would teach nothing.

---

## Detection and correlation rules

All rules run inside the browser on the whole file. Each finding carries the events that produced
it, so every claim can be traced back to specific rows in your file.

### Rule 1 &mdash; Repeated Failed Logons

Counts `4625` events per account.

- **Threshold** (default 5) and **time window** (default 10 minutes) are configurable.
- A **burst** inside the window &rarr; **Medium** (High if at least twice the threshold).
- Enough failures but never enough close together &rarr; **Low**, with an explanation that a slow
  trickle is weaker evidence.
- Window switched off, or timestamps unreliable &rarr; all failures counted together (Medium),
  and the finding says the window was not applied.
- **One finding per account**: a sliding window produces many overlapping groups of the same
  events, so the busiest is reported and any separate burst is mentioned by note.
- Failures that name no account anywhere are counted but **not grouped**, because grouping them
  would invent a relationship.

### Rule 2 &mdash; Possible Password Guessing Followed By Success

Finds a burst of `4625` failures for an account followed by a `4624` success for **the same
account** inside the window.

- **High** when the correlation is strong. The finding shows the sequence
  (`4625 &rarr; 4625 &rarr; ... &rarr; 4624`), each step's timestamp, the failed count, the gap
  between the last failure and the success, and the logon types involved.
- The **source address and workstation are compared** and reported as *Same*, *Different*,
  *Partly matches* or *Cannot be determined*. A match is never assumed. When the addresses
  differ, the priority drops to **Medium** and the reason is shown.
- Without usable timestamps the order comes from the row order in the file, and the finding says
  that this is an assumption.
- Unrelated accounts are never paired. Two successes after the burst are described once.

### Rule 3 &mdash; New Account Granted Privileges

Finds `4720` followed by `4728`/`4732` for the **same target account**.

- **High** when the group normally carries elevated rights (`Administrators`, `Domain Admins`,
  `Enterprise Admins`, `Schema Admins`, `Account Operators`, `Backup Operators`,
  `Remote Desktop Users`, and others &mdash; see `PRIVILEGED_GROUPS`), **Medium** otherwise.
- Names the account created, the account that created it, the account that granted the rights,
  the group, and the gap between the two events.
- Notes when the creator and the granter are different people, and when the gap is longer than
  the configured window. It never claims the creation was unauthorised.

### Rule 4 &mdash; Security Audit Log Cleared

Every `1102` is **High** on its own. This is the only event in the tool that is serious by
itself, and the reason is stated in the finding: clearing the log removes the record needed to
judge everything else, so the evidence has usually just been destroyed. The finding also records
how much other activity the file still holds before and after the clearing.

### Rule 5 &mdash; Administrative / Privilege Activity (summary, not a finding)

Lists `4720`, `4726`, `4728`, `4732`, `7045` and `1102` together, in time order, with the account
involved and who performed it.

It carries **no severity** and performs **no correlation**. Two unrelated administrators creating
two unrelated accounts are not a story, and the section says so explicitly. Deciding whether those
events form a narrative is the analyst's job.

### Cross-references

Rule 1 and Rule 2 can describe the same failures from different angles. Each finding links to the
other and states that they are two views of one piece of activity, not two separate incidents.

---

## Severity and the investigation score

Severity is **investigative priority, not certainty**. The vocabulary is Informational, Low,
Medium and High. "Critical" is not used.

The score is an educational way of putting findings in an order. It is shown as itemised
contributions, and the interface states wherever it appears that it is **not a probability**:

| Contribution | Points |
|---|---|
| Repeated failed logons | +10 |
| A successful sign-in following the failures | +20 |
| A new account granted privileges | +25 |
| A privileged group membership change | +25 |
| The security audit log being cleared | +30 |

Example, from the password-guessing demo:

```
repeated failed logons (8 attempts, threshold 5)          +10
a successful sign-in following the failures               +20
                                                          ---
Total                                                      30
```

There is no percentage anywhere in the tool, and a test asserts that no finding contains a `%`
sign or the word "probability".

---

## Settings

Both settings are editable in **Analysis settings** and apply immediately to the data already in
memory (the file is never read twice). **Reset Defaults** restores them.

| Setting | Default | Range | Meaning |
|---|---|---|---|
| Failed logon threshold | 5 | 2&ndash;1000 | How many failures for one account count as "repeated" |
| Failed logon time window | 10 minutes | 1&ndash;1440 | How close together the failures must be |
| Use the time window | on | &mdash; | When off, failures are counted together regardless of spacing |

A threshold below 2 is not allowed, because "one failure" is ordinary activity. Values outside
the range are clamped rather than trusted, and unreadable input falls back to the default.

> Security thresholds vary by environment. These values are educational defaults rather than
> universal SOC detection rules.

Settings are **not saved**. They are forgotten when the tab closes.

---

## Dashboard and filters

The dashboard shows: total events, successful logons, failed logons, accounts created, privilege
changes, audit-log clearings, process creation events and events requiring investigation, plus:

- top accounts by event count;
- accounts with the most failed logons;
- the most common Event IDs;
- events by priority;
- a chronological **timeline of noteworthy activity** (with a warning when timestamps are not
  readable, in which case the list follows file order).

The **event explorer** lists every event the tool read, with filters for Event ID, account,
priority, source address and event type, plus a free-text search over account, computer and
message text. The event count updates live.

Filters only change what is **displayed**. They never change the findings: the report was computed
from the whole file, and a test asserts that hiding rows cannot make a finding disappear. At most
500 rows are rendered at once, with a note when there are more.

---

## How to export your event data

The tool reads **CSV or delimited text**. It does not read raw `.evtx` files in this version.

### Option A &mdash; Windows Event Viewer

1. Press <kbd>Win</kbd>+<kbd>R</kbd>, type `eventvwr.msc`, press Enter.
2. Expand **Windows Logs** &rarr; click **Security**.
3. Optionally use **Filter Current Log&hellip;** to narrow the events, for example IDs
   `4624,4625,4720,4726,4728,4732,1102,4688`.
4. On the right, click **Save All Events As&hellip;** (or **Save Filtered Log File As&hellip;**).
5. Choose **Comma Separated Values (*.csv)** if your Windows build offers it.

**Be aware:** not every Windows 10/11 build shows a CSV option in that dialog. Some offer only
`.evtx`, `.txt` (tab delimited) and `.xml`. If yours offers only the tab-delimited text format,
that is fine &mdash; this tool detects tabs automatically. If yours offers no usable text format at
all, use Option B.

### Option B &mdash; PowerShell (recommended, always works)

Run **PowerShell as Administrator** (reading the Security log requires it):

```powershell
$ids = 4624,4625,4720,4726,4728,4732,1102,4688
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids} |
  Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, TaskDisplayName,
                KeywordsDisplayNames, Message |
  Export-Csv -Path "$env:USERPROFILE\Desktop\security-triage.csv" -NoTypeInformation -Encoding UTF8
```

Add `; StartTime=(Get-Date).AddDays(-1)` inside the filter hashtable to export only the last day.
Keep exports small while you are learning.

For service installations (Event ID 7045), export the System log as well and upload it separately,
or combine the two files yourself.

### Two things that will save you trouble

- **Do not open the CSV and re-save it in Excel.** Excel rewrites quoting and dates, which can
  break the file. Upload the export directly.
- **Keep the header row**, and try not to rename columns. The tool accepts many variations
  (`Event ID`, `EventID`, `event_id`, `Id`, `EventCode`; `Date and Time`, `TimeCreated`,
  `Timestamp`; and so on), but it needs an Event ID column to exist.

---

## Sample datasets and demo walkthrough

Four fictional datasets are built in and also provided as real CSV files in `samples/`. All names,
computers and addresses are invented; addresses come only from private ranges (`10.x`, `192.168.x`)
or documentation ranges (`203.0.113.x`, `198.51.100.x`).

| File | Events | Demonstrates |
|---|---|---|
| `normal-windows-events.csv` | 15 | A quiet day: logons, applications, two mistyped passwords, a backup copy |
| `password-guessing.csv` | 9 | Eight failures for `jsmith` from one address, then a Remote Desktop success |
| `account-persistence.csv` | 4 | `4720` creates `temp-admin`, `4732` adds it to local Administrators, then it signs in |
| `suspicious-admin-activity.csv` | 15 | Failures, success, process creation, account creation, privilege change, service install, encoded PowerShell, account deletion, log clearing |

Each demo is labelled **Demo Data** in the interface, and the load buttons describe what the
scenario is designed to show.

### A five-minute demonstration

| Step | Action | Expected result |
|---|---|---|
| 1 | **Load Normal Sample** | No findings, and an honest note that this is not proof nothing happened |
| 2 | **Load Password Guessing Sample** | *Repeated Failed Logons* (Medium, +10) |
| 3 | Same sample | *Possible Password Guessing Followed By Success* (High, +30) with `4625 x8 -> 4624` and a matching source address |
| 4 | **Load Privilege Escalation Sample** | *New Account Granted Privileges* (High, +50): `4720 -> 4732` into Administrators, 1m 35s apart |
| 5 | **Load Mixed SOC Sample** | Four findings at once, plus the Administrative / Privilege Activity section and a timeline |

Then explain: *"The individual events matter, but the real value comes from understanding how
they relate to one another."* Try raising the failed-logon threshold to 9 and watch the
password-guessing findings disappear &mdash; same data, a different judgement call.

The datasets are generated by `dev-tests/build-samples.mjs` so that the `.csv` files and the
embedded copies cannot disagree; a test fails if they drift.

---

## False positives

Every finding in this tool is a candidate for investigation, and most candidates are innocent.
The findings say so, and the reference section in the app lists the everyday explanations.

Common reasons a finding appears without anything wrong happening:

- **Mistyped passwords.** Two or three failures followed by a success is a person, not an attack.
- **A stale saved credential.** A phone, printer, scheduled task or backup job with an old
  password produces a steady trickle of failures, often at night.
- **Legitimate onboarding.** Creating an account and adding it to a group is what a helpdesk does.
- **Software installation.** A new service is how much ordinary software starts automatically.
- **Documented maintenance.** Clearing a log during a rebuild is normal, if it was planned.
- **Admin scripts.** PowerShell, `net.exe`, `cmd.exe` and `robocopy` are routine tools.
- **Remote Desktop.** Type 10 logons are how many people work, especially in a lab.
- **Clock and timezone differences** can make a sequence look tighter or looser than it was.

The tool deliberately keeps its thresholds conservative. A quiet result is not a clean bill of
health either: it means nothing in *this file* crossed *these* thresholds.

---

## Limitations

Documented honestly, because knowing what a tool cannot do is part of using it well.

**Input and parsing**

- CSV exports differ between Windows versions, languages and tools. Column names, date formats
  and encodings vary. The parser tolerates a lot, but a heavily customised export may need its
  headers renamed.
- **Message text is matched in English.** Extraction relies on labels such as `Account Name` and
  `Source Network Address`. A non-English Windows export will parse structurally, but those
  fields will not be extracted.
- `.evtx` files are not supported in this version. Neither are zipped exports.
- The bundled samples use single spaces where real exports use tab characters, for readability.
  The parser treats both the same way, and tabs are covered by tests.

**Time**

- `03/04/2026` is ambiguous: 3 April or 4 March, depending on the machine's regional settings. The
  tool infers the convention from the whole file when it can, prefers unambiguous formats, and
  otherwise says so and disables time-window correlation rather than guessing.
- Exports without a timezone are interpreted in your browser's local timezone. That is fine for
  ordering events relative to each other, but the absolute time may differ from the source.
- A small number of genuinely unreadable dates are reported, and those events are left out of
  time-window analysis.

**Evidence**

- **Not every event contains a source address.** Local and console logons legitimately have none,
  and Windows sometimes writes `-`. The tool reports "not available" rather than filling the gap.
- **The absence of an event proves nothing.** If process-creation or PowerShell logging was
  switched off, those events simply do not exist in the export.
- A log that has been cleared cannot be reconstructed. The tool says so in the finding.
- Accounts are correlated by name. If an export contains only security identifiers (SIDs), the
  tool cannot map them to names without a domain, and correlation quality drops.

**Analysis**

- This is single-file analysis. There is no cross-system correlation and no historical baseline,
  so the tool cannot know whether a sign-in is normal *for that person*.
- The rules look for a small, explainable set of patterns. They will not spot novel activity.
- Very large files are capped (25 MB / 200,000 rows) and the interface renders at most 500 rows
  at a time. Larger exports are refused with an explanation rather than freezing the tab.
- **Windows Event IDs alone cannot determine intent.** That is why every finding carries a benign
  explanation, and why nothing is scored as a probability.

**Scope**

- This is not an EDR, SIEM or professional SOC platform, and does not replace one. It is a
  teaching aid for reading a single export carefully.

---

## Security and accessibility

**Treating uploaded content as untrusted.** A CSV can contain anything, including HTML and
JavaScript. The rules the code follows, each enforced by an automated test:

- Every value that came from the file is written with `textContent`, never `innerHTML`. There is
  no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or `new Function`
  in the interface.
- The page loads only three local files, and a test fails if a remote `src` or `href` appears.
- The Content-Security-Policy forbids outbound connections, form submission, plugins, frames and
  `<base>` manipulation.
- Malformed files fail safely: the parser never throws, and every problem is reported in plain
  English with guidance.
- A malicious cell is displayed as text. It cannot execute.

**Hosting note.** `index.html` ships with a policy that blocks all network egress but deliberately
omits `style-src` and `script-src`. That is not an oversight: a directive such as
`style-src 'unsafe-inline'` (without `'self'`) **blocks the local `styles.css`**, which once made the
deployed site render completely unstyled, and `script-src 'self'` can stop local scripts loading from
a `file://` page. Every directive that actually prevents data leaving the page is still enforced.

If you host the tool over HTTP(S), where `'self'` resolves reliably, you can tighten it to:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
connect-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'
```

**If the page ever looks unstyled** (tiny text, giant icons, content pushed to the left), the
stylesheet is not loading. Check, in this order:

1. The browser console for `Refused to load the stylesheet ... Content Security Policy`.
2. That `styles.css` sits next to `index.html` and was deployed with it.
3. A hard refresh (<kbd>Ctrl</kbd>+<kbd>F5</kbd>), because GitHub Pages and browsers cache CSS
   aggressively after a deploy.

Two related pitfalls are also guarded by tests, because both caused real bugs here:

- A component that sets `display: flex/grid` overrides the HTML `hidden` attribute unless the
  stylesheet contains `[hidden] { display: none !important; }`. Without it, "empty state" panels
  appear on top of loaded data.
- Grid and flex children default to `min-width: auto`, so a wide table inside a scroll container can
  still stretch the whole page and create a horizontal scrollbar. `min-width: 0` on those children
  fixes it.


**Accessibility.** Semantic landmarks and headings; a skip link; real `<label>` elements for every
control; visible focus outlines; keyboard-operable file upload (drag and drop is an addition, not
the only route); `aria-live` status messages that do not interrupt a screen reader; tables with
captions and column scopes; severity always communicated by a text label as well as colour;
contrast checked against the dark theme; `prefers-reduced-motion` respected; print styles included.

Severity uses four levels and never relies on colour alone: the word and a coloured border always
appear together.

---

## Running the automated tests

The application itself needs nothing installed. The **test suite** needs Node.js 18 or newer,
because it runs the engine outside a browser.

```bash
node dev-tests/run-tests.mjs
```

At the time of writing this runs **188 checks**, covering:

- **CSV reading:** comma, semicolon and tab separated; byte-order marks; quoted cells with commas,
  doubled quotes and embedded newlines; PowerShell `Export-Csv` column names; UTF-16 with and
  without a BOM.
- **Timestamps:** ISO, dotted day-first, ambiguous slash dates resolved from the whole file, AM/PM,
  timezone offsets, impossible dates, and garbage values that must not become dates.
- **Field extraction:** `New Logon` vs `Subject`, `Account For Which Logon Failed`, target vs actor,
  member and group, process/parent/command line, service details, PowerShell script text and
  obfuscation hints, and the "never invent a value" guarantees.
- **Detection rules 1&ndash;5** against the four demo datasets and purpose-built edge cases
  (thresholds, windows, missing timestamps, missing accounts, unrelated accounts, duplicates).
- **The dashboard figures and the event filters**, including that filters cannot change findings.
- **Security and privacy:** no `fetch`/XHR/WebSocket/beacon, no storage or cookies, no `innerHTML`,
  no remote resources, CSP present, privacy text present.
- **Page wiring:** every element id the interface looks for exists, the markup is balanced, and
  `script.js` loads and initialises against a stubbed DOM without throwing.
- **Scale:** 20,000 events parse in roughly 160 ms.

To regenerate the sample datasets after editing them:

```bash
node dev-tests/build-samples.mjs
```

That rewrites both `samples/*.csv` and the embedded `samples/sample-data.js`, so the two always
match. A test fails if they ever drift.

---

## Project structure

```
index.html              the page: privacy notice, upload, dashboard, findings,
                        administrative summary, filters, settings, education
styles.css              dark theme, severity colours, focus styles, print styles
triage-core.js          the analysis engine: parsing, recognition, rules, scoring
                        (no DOM, no network, no storage, no dependencies)
script.js               the interface only: rendering, events, filters, settings
samples/
  normal-windows-events.csv
  password-guessing.csv
  account-persistence.csv
  suspicious-admin-activity.csv
  sample-data.js        the same four datasets embedded, so the demo buttons work
                        when index.html is opened from disk (generated)
dev-tests/
  run-tests.mjs         the automated test suite
  build-samples.mjs     generates the sample files and the embedded copy
README.md
```

`triage-core.js` is deliberately separate from the interface: it is a pure engine, which is why it
can be tested without a browser, and why the security-critical parsing is separate from rendering.

---

## Future improvements (not implemented)

These are deliberately **out of scope for Version 1**, and listed so the boundary is clear:

- raw `.evtx` parsing
- Sysmon support
- deeper PowerShell 4104 analysis
- process-tree visualisation
- MITRE ATT&CK mapping
- fuller timeline analysis
- login-time baselining
- dedicated service-creation detection
- scheduled-task monitoring
- Windows Defender event analysis
- an exportable incident report
- SIEM integration

There are no external APIs, no accounts and no API keys in this version, and none are planned for
the educational release.

---

## Educational use

This project exists to teach:

- how Windows records authentication, account, privilege and audit-log activity;
- why the same Event ID can be routine or interesting depending on its context;
- how correlation turns individual events into a story;
- how easily a plausible-looking pattern can have an innocent explanation;
- how to write down what you saw, what you ruled out, and what you would check next.

Use it on your own systems, or on the built-in fictional data. Do not use it on logs you are not
authorised to examine.

---

*Built as a static, dependency-free teaching tool. No tracking, no accounts, no external services.*






