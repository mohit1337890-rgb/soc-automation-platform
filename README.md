# SOC Automation Project

**Built by Mohit**

An automated Security Operations Center (SOC) pipeline that ingests security
logs, runs them through 9 independent threat-detection modules, correlates
related alerts into multi-stage incidents, and produces an executive report
with an AI-generated summary and MITRE ATT&CK mapping — all served through a
multi-tenant web dashboard.

> A full PDF version of the install/config/usage guide is also available at
> [`docs/SOC_Automation_Manual.pdf`](docs/SOC_Automation_Manual.pdf).

---

## Table of Contents

1. [What this project does](#what-this-project-does)
2. [Architecture](#architecture)
3. [Project structure](#project-structure)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
   - [Option A — Docker](#option-a--docker-recommended)
   - [Option B — Local Python](#option-b--local-python)
6. [Configuration](#configuration)
7. [Running it](#running-it)
   - [CLI](#cli)
   - [Web dashboard](#web-dashboard)
8. [Real (live) mode — your own Windows logs & email](#real-live-mode--your-own-windows-logs--email)
9. [Continuous operation — scheduling, alert history & triage](#continuous-operation--scheduling-alert-history--triage)
10. [Notifications (Slack / email)](#notifications-slack--email)
11. [How each detector works](#how-each-detector-works)
12. [How correlation works](#how-correlation-the-brain-works)
13. [How the AI report works](#how-the-ai-report-works)
14. [Multi-tenancy](#multi-tenancy--onboarding-a-new-client)
15. [Reading a report](#reading-a-report)
16. [Troubleshooting](#troubleshooting)
17. [Moving to full production](#moving-to-full-production)
18. [Known limitations](#known-limitations)

---

## What this project does

Real SOC teams get flooded with alerts from a dozen disconnected tools. This
project shows one way to automate the whole pipeline for a small set of high
value detections, end to end:

```
Raw logs  →  9 Detectors  →  Correlation Engine  →  AI Report + Dashboard
(email,      (each flags     (links alerts into      (executive summary,
 Windows      one threat      one "incident" if       MITRE mapping,
 events,      class)          they share a user/      IOCs, downloadable
 PowerShell,                  host/IP/IOC in a         HTML report)
 cloud auth)                  time window)
```

It ships with a **synthetic but realistic sample dataset** containing a full
attack chain (phishing → credential theft → lateral movement → ransomware)
plus an unrelated "impossible travel" case and background noise, so you can
see every module — and the correlation engine — fire correctly with zero
setup.

It can also run against **your own real data**: real Windows Security/Sysmon/
PowerShell event logs on the machine it runs on, a real Gmail/Outlook inbox
over IMAP, real cloud/AD sign-in logs (Azure AD, Okta, or Google Workspace),
and real GeoIP (via IPinfo) — see
[Real (live) mode](#real-live-mode--your-own-windows-logs--email). It can
also run **unattended**, on a schedule, with Slack/email notifications on
new findings and a triage workflow for acting on them — see
[Continuous operation](#continuous-operation--scheduling-alert-history--triage).

## Architecture

The system is organized into four layers, matching the original design:

| Layer | Folder | Responsibility |
|---|---|---|
| **Ingestion** | `ingestion/` | Normalizes every log source into one JSON event schema |
| **Detection** | `detectors/` | 9 independent modules, one per threat class |
| **Correlation** | `core/correlation.py` | Links related alerts across modules into "incidents" |
| **Reporting** | `reporting/` | Builds the HTML report + AI executive summary |

On top of that:

- **`core/`** — shared data models, the per-tenant SQLite database, the MITRE ATT&CK mapping table, and the pipeline orchestrator.
- **`dashboard/`** — the Streamlit web UI a client actually uses.
- **`config.yaml`** / **`config/tenants.yaml`** — all thresholds, API keys, and the client registry, so nothing is hardcoded in Python.

## Project structure

```
SOC-Automation-Project/
├── config.yaml                    # global thresholds, API keys, feature flags
├── config/tenants.yaml            # one entry per client
├── requirements.txt
├── main.py                        # CLI entry point
├── scheduler.py                   # always-on loop for unattended periodic scans
├── Dockerfile / docker-compose.yml
├── docs/
│   ├── generate_manual.py         # builds the PDF manual
│   └── SOC_Automation_Manual.pdf
│
├── core/
│   ├── models.py                  # Alert / Incident data classes
│   ├── database.py                # SQLite storage (one DB per tenant)
│   ├── mitre_mapper.py            # detector -> MITRE ATT&CK technique
│   ├── correlation.py             # "The Brain" - links alerts into incidents
│   ├── tenants.py                 # tenant registry + per-tenant file paths
│   └── pipeline.py                # orchestrates ingestion->detection->correlation->report
│
├── ingestion/
│   ├── sample_data_generator.py   # synthetic demo logs
│   ├── log_loader.py              # reads normalized JSONL events (sample mode)
│   ├── windows_event_log_reader.py# REAL Windows Security/Sysmon/PowerShell log reader
│   ├── email_ingestion.py         # REAL Gmail/Outlook IMAP inbox reader
│   ├── cloud_auth_ingestion.py    # REAL Azure AD / Okta / Google Workspace sign-in logs
│   └── geoip_lookup.py            # REAL IPinfo GeoIP resolution
│
├── detectors/                     # one file per detection module (see below)
│
├── reporting/
│   ├── report_generator.py        # renders the final HTML report
│   ├── genai_summary.py           # Claude-based executive summary + fallback
│   └── templates/report.html.j2
│
├── dashboard/
│   └── app.py                     # multi-tenant Streamlit dashboard (Settings, triage, all of it)
│
├── notifications/
│   └── notifier.py                # Slack webhook + email (SMTP) alerting on new findings
│
├── data/<tenant_id>/soc.db        # generated at runtime — one DB per client
├── sample_data/<tenant_id>/       # generated at runtime — that client's logs
└── reports/<tenant_id>/           # generated at runtime — that client's HTML reports
```

## Prerequisites

- **Docker path:** Docker Desktop (or Docker Engine + Compose plugin) only.
- **Local Python path:** Python 3.11+ (Windows/macOS/Linux).
- Optional, for real intelligence instead of offline fallbacks:
  - A [VirusTotal](https://www.virustotal.com/) API key.
  - An [Anthropic](https://console.anthropic.com/) API key (for the AI-written executive summary).
  - An [IPinfo](https://ipinfo.io/) API key (for real GeoIP on impossible-travel detection).
- Optional, for **Real (live) mode** on Windows: an elevated (Administrator)
  terminal to read the Security event log, [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
  installed for credential-dump/process/file/registry detection, and a
  Gmail/Outlook app password for live phishing scans — see
  [Real (live) mode](#real-live-mode--your-own-windows-logs--email).

None of these are required to run the project — every module has an
offline/sample-data fallback so the full pipeline works out of the box.

## Installation

### Option A — Docker (recommended)

```bash
docker compose up -d --build
```

This starts two containers: the **dashboard** (http://localhost:8501) and
an always-on **scheduler** (see [Continuous operation](#continuous-operation--scheduling-alert-history--triage))
that scans any tenant with scheduling enabled — it's harmless to leave
running even if no tenant has scheduling turned on yet.

To run the detection pipeline for one client from the command line instead
of the dashboard's "Run" button:

```bash
docker compose run --rm pipeline --tenant acme_corp
```

Data persists across rebuilds because `data/`, `sample_data/`, `reports/`,
and `config/` are mounted as volumes (see `docker-compose.yml`).

### Option B — Local Python

```powershell
# Windows PowerShell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

All detection thresholds/whitelists live in **`config.yaml`** — how many
failed logons count as brute force, which file extensions are risky
attachments, etc. You generally do not need to touch code to change
detection sensitivity.

### What you actually need — Demo vs Live

| | Demo mode | Live mode |
|---|---|---|
| Setup required | **None** | See table below |
| Command | `python main.py --tenant demo` | `python main.py --tenant mohit_live --source live` |
| Data | Synthetic, bundled | Your real PC's logs + (optionally) your real email |

Everything in the table below is **optional** — the pipeline runs with
whatever it has and reports a warning for anything missing, it never
crashes because a key is absent.

| Needed for | What | Where to get it | Where to enter it | Cost |
|---|---|---|---|---|
| Windows Security log (brute force, admin-share access, scheduled tasks) | An **elevated (Administrator)** terminal | Built into Windows | Launch PowerShell/the dashboard via "Run as administrator" | Free |
| LSASS-dump, ransomware, persistence, process-based lateral movement | **Sysmon** installed | [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Install command in [Real (live) mode](#real-live-mode--your-own-windows-logs--email) | Free |
| Real phishing email scanning | Gmail/Outlook **App Password** | Google/Microsoft account security settings (steps below) | Dashboard → **Settings** → Email address + App password | Free |
| Real hash/domain reputation | **VirusTotal** API key | [virustotal.com](https://www.virustotal.com/) (free sign-up) | Dashboard → **Settings** → VirusTotal API key | Free (4 req/min) |
| AI-written executive summary | **Anthropic** API key | [console.anthropic.com](https://console.anthropic.com/) | Dashboard → **Settings** → Anthropic (Claude) API key | Paid, pay-per-use |
| Real GeoIP for impossible-travel (Windows remote logons AND any cloud/AD provider below) | **IPinfo** API key | [ipinfo.io](https://ipinfo.io/) (free sign-up) | Dashboard → **Settings** → IPinfo API key | Free tier available |
| Real cloud/AD sign-in logs for impossible-travel | Okta API token, **or** Azure AD app registration, **or** Google Workspace service account | See [Real (live) mode](#real-live-mode--your-own-windows-logs--email) — setup differs a lot per provider | Dashboard → **Settings** → Cloud/AD sign-in logs | Okta: free · Azure AD: needs Premium P1/P2 · Google: needs Workspace |

Without VirusTotal/Anthropic/IPinfo keys: VT falls back to a small offline
blocklist, the executive summary uses a template instead of AI, and
impossible-travel only fires against the bundled sample `cloud_auth` data
and/or real Windows remote logons (not a real cloud/AD provider, unless
one is configured).

### Where credentials are stored

**From the dashboard (recommended)** — sign in, open the **Settings**
expander in the sidebar, fill in what you have, click **Save settings**.
Each organization's keys are stored in *that organization's own* isolated
database (`data/<tenant_id>/soc.db`, `settings` table) — nothing is shared
across tenants. This is plaintext in a local SQLite file, not an encrypted
vault - fine for local/demo use; for real production prefer environment
variables injected by your deployment platform, or a proper secrets manager.

**Environment variables / config.yaml (for CLI/Docker use)** — a
dashboard-saved setting always wins over these if both are present:

| Variable | Used by |
|---|---|
| `VT_API_KEY` | `detectors/virustotal_checker.py` |
| `ANTHROPIC_API_KEY` | `reporting/genai_summary.py` |
| `impossible_travel.ipinfo_api_key` (config.yaml) | `detectors/impossible_travel.py` |

```powershell
# PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
$env:VT_API_KEY = "your-vt-key"
```

```bash
# bash
export ANTHROPIC_API_KEY="sk-ant-..."
export VT_API_KEY="your-vt-key"
```

**Never commit real keys to source control.** `.gitignore` already excludes
`.env` and every tenant's runtime data (which now includes the `settings` table).

## Running it

### CLI

```bash
python main.py --list-tenants                 # see configured clients
python main.py --tenant demo                   # full run: ingest -> detect -> correlate -> report
python main.py --tenant demo --no-sample-data  # reuse previously ingested logs
python main.py --tenant demo --no-genai        # force the template-based summary
python main.py --tenant mohit_live --source live   # real Windows logs + real email inbox
```

> Every run replaces that tenant's alerts with the results of this run
> (`db.clear_alerts()`) — it's a fresh snapshot each time, not an
> ever-growing log, so re-running never produces duplicate-looking alerts.
> Correlated incidents are always rebuilt from whatever alerts currently
> exist.

Each run prints a summary like:

```
============================================================
  SOC PIPELINE COMPLETE - Demo Organization (demo)
============================================================
Alerts by detector:
  - phishing_detector      1
  - virustotal_checker     3
  - brute_force            1
  ...
Total alerts        : 16
Correlated incidents: 1
Report              : reports\demo\soc_report_20260919_145010.html
```

Open the generated HTML file in any browser — it's fully self-contained
(no internet connection needed to view it).

### Web dashboard

```bash
streamlit run dashboard/app.py
```

1. **Sign in** — pick your organization and enter its access code (see
   `config/tenants.yaml`; the `demo` tenant has no code).
2. **Settings** (sidebar expander) — optionally enter VirusTotal/Anthropic/
   IPinfo API keys and your email/app-password for live phishing scans.
3. **Run pipeline** (sidebar) — choose **Demo sample data** or **Live (real
   Windows logs + email)**, then click **Run detection pipeline now**.
4. **Overview** tab — KPI counts, severity/detector charts, alert timeline.
5. **Incidents** tab — correlated multi-stage attack chains with narratives.
6. **Alerts** tab — every individual alert, filterable.
7. **IOCs** tab — every indicator of compromise extracted so far.
8. **Reports** tab — download any previously generated HTML report.

> The dashboard's access-code screen is a lightweight demo gate, not
> enterprise authentication. For real multi-client production use, replace
> it with Streamlit's native `st.login()` backed by your identity
> provider (SSO/OIDC).

## Real (live) mode — your own Windows logs & email

Selecting **Live (real Windows logs + email)** as the data source (dashboard
sidebar, or `--source live` on the CLI) makes `core/pipeline.py` call:

- `ingestion/windows_event_log_reader.py` — reads the **Security**,
  **Microsoft-Windows-Sysmon/Operational**, and
  **Microsoft-Windows-PowerShell/Operational** event channels on the machine
  it runs on, using the modern Windows Eventing API (`win32evtlog.EvtQuery`),
  and maps them into the exact same event shape the synthetic data uses — no
  detector code changes needed.
- `ingestion/email_ingestion.py` — logs into a real Gmail/Outlook inbox over
  IMAP with an app password, reads recent messages, and extracts the
  SPF/DKIM/DMARC verdicts, URLs, and attachment names `phishing_detector.py`
  needs.

Any source that fails (channel missing, access denied, bad email
credentials) is reported as a **warning**, not a crash — the pipeline still
runs on whatever it *could* read, and every warning is shown in both the CLI
output and the dashboard.

### Setting it up

**1. Windows Security log (brute force, scheduled tasks, admin-share access):**
requires the dashboard/CLI to be launched from an **elevated (Administrator)**
terminal — this is an OS-level restriction, nothing in the app can bypass it.
Regular users, even local admin accounts running non-elevated, get an
"Access is denied" warning instead of data.

```powershell
# Right-click PowerShell/Windows Terminal -> "Run as administrator", then:
streamlit run dashboard/app.py
```

**2. Sysmon (LSASS/credential-dump, process, file, registry events):** not
installed by default on Windows. Install it (also requires an elevated
terminal) from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon):

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
& "$env:TEMP\Sysmon\Sysmon64.exe" -i -accepteula
```

**3. PowerShell Script Block Logging (EID 4104):** usually on by default on
modern Windows; if `powershell_analyzer` never fires, enable it via Group
Policy or:
```powershell
New-Item "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
```

**4. Email inbox:** generate an **app password** (never use your real
account password):
- **Gmail:** Google Account → Security → 2-Step Verification (must be ON) →
  App passwords → generate one for "Mail".
- **Outlook.com:** [account.live.com/proofs/AppPassword](https://account.live.com/proofs/AppPassword)
  (also requires 2-step verification).

Enter the address + app password in the dashboard's **Settings** panel (or
`EMAIL_ADDRESS`/`EMAIL_APP_PASSWORD` for your own scripts).

**5. Impossible travel (real data) — two independent real sources:**

- **Real Windows remote logons** — EID 4624 with logon type 3 (network) or
  10 (RemoteInteractive/RDP) — resolved via IPinfo. Needs nothing but an
  IPinfo key; works the moment you have real remote logons on this machine.
- **Real cloud/AD sign-in logs** — Azure AD (Microsoft Entra ID), Okta, or
  Google Workspace, configured in the dashboard's **Settings** panel under
  "Cloud/AD sign-in logs". Pick a provider and fill in its credentials:

  | Provider | What you need | Cost / effort |
  |---|---|---|
  | **Okta** | Free developer org at [developer.okta.com](https://developer.okta.com/) → Security → API → Tokens → Create Token. Enter the domain (e.g. `dev-12345678.okta.com`) and token. | Free — easiest to actually test yourself |
  | **Azure AD / Entra ID** | App registration (Azure Portal → Entra ID → App registrations) with `AuditLog.Read.All` (admin-consented) → Tenant ID, Client ID, Client Secret. | Requires **Azure AD Premium P1/P2** on the tenant — a Microsoft licensing requirement for the sign-ins API, not something this code can bypass |
  | **Google Workspace** | A Google Cloud service account with domain-wide delegation for scope `admin.reports.audit.readonly`, authorized in Workspace Admin console. Upload the service account's JSON key file + the delegated admin's email. | Requires a Workspace (business) domain — a personal `@gmail.com` account can't be used this way |

  Every provider is mapped into the same `cloud_auth` event shape the
  sample data uses, so `detectors/impossible_travel.py` needed **zero
  changes** to support real sign-in logs from any of them. An IPinfo key
  is still required (same one used for Windows remote logons) since none
  of these APIs return a ready city/lat/lon for an IP.

Both sources feed the same detector at once — real Windows remote logons
and a real cloud/AD sign-in log can even be correlated together if the same
user shows up in both within the plausible-travel window.

> **Tip:** use a separate tenant for real testing (e.g. the bundled
> `mohit_live` in `config/tenants.yaml`) instead of `demo`, so your real
> scan history and the synthetic showcase incident never sit side by side
> in the same dashboard view.

## Continuous operation — scheduling, alert history & triage

A dashboard nobody is watching is not a SOC. These three pieces work
together to make the tool usable unattended, not just as a manual demo.

### Alert history persists — nothing is silently wiped

Every `Alert` gets a **deterministic id** derived from its own content
(`detector` + entity + title + timestamp — see `core/models.py`). Re-scanning
and seeing the *same* real-world event again just refreshes that one row;
a genuinely *new* event gets a new row. Nothing is ever bulk-deleted at the
start of a run. Practically:

- Running the pipeline twice against the same data never creates duplicates.
- Alerts from an earlier scan are never lost because a later scan's lookback
  window didn't happen to include them again.
- If an event is re-detected after an analyst already triaged it, its
  **status is left untouched** — re-detection can never silently un-resolve
  something.

### Scheduling — run automatically instead of clicking a button

`scheduler.py` is a small always-on loop: every 30 seconds it checks each
tenant's Settings (dashboard → Settings → **Scheduling**) and runs the
pipeline for any tenant whose configured interval has elapsed.

```bash
python scheduler.py        # runs in the foreground; Ctrl+C to stop
```

To actually run unattended, either:
- **Windows:** leave it running in a terminal, or wire it up as a
  [Scheduled Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
  that launches `python scheduler.py` at logon (use an elevated task if you
  want it to also read the Security event log).
- **Docker:** it's already a service in `docker-compose.yml` and starts
  automatically with `docker compose up -d` (see caveat below).

Per tenant, in **Settings**: tick **Enable scheduled scanning**, set the
interval in minutes, and choose the scan source (`live` or `sample`). It's
off by default for every tenant — the scheduler process itself is harmless
to leave running even with nothing enabled.

> **Docker caveat:** `pywin32` only works on Windows, so the `scheduler`
> Docker service (Linux container) can schedule real **email** scans but
> not real **Windows Event Log** scans. For scheduled Windows log scanning,
> run `python scheduler.py` directly on the Windows host instead.

### Triage workflow — alerts have a lifecycle

Every alert has a `status`: `new` → `acknowledged` / `resolved` /
`false_positive`. In the dashboard's **Alerts** tab, edit the **Status**
column directly in the table and click **Save status changes**. Resolved
and false-positive alerts are hidden by default (tick **Show resolved /
false-positive alerts** to bring them back) — nothing is deleted, so there's
always an audit trail of what was found and what was done about it.

## Notifications (Slack / email)

Configured per-tenant in the dashboard's **Settings** panel, under
**Notifications**. Every pipeline run (manual, scheduled, or CLI) compares
the alerts it just found against what already existed and sends a
notification for anything **new** at or above your chosen minimum severity
— so a critical ransomware alert doesn't just sit in the dashboard until
someone happens to open it.

- **Slack:** paste an [Incoming Webhook URL](https://api.slack.com/messaging/webhooks)
  (Slack → your workspace → Apps → Incoming Webhooks → Add to Slack).
- **Email:** reuses the Gmail/Outlook credentials already configured for
  live phishing scanning (sent via SMTP instead of IMAP) — only Gmail/Outlook
  are supported as the *sender* today; use Slack for anything else.

Both are optional and independent; a failed send is reported as a pipeline
warning, never a crash.

## How each detector works

| Detector | Logic | MITRE |
|---|---|---|
| `phishing_detector.py` | SPF/DKIM/DMARC failure **AND** a risky URL (shortener/suspicious TLD) or attachment (`.js`, `.exe`, `.hta`, ...). Either signal alone is too noisy; both together is a strong signal. | T1566 |
| `virustotal_checker.py` | Extracts hashes/domains from events, checks reputation via VT API (rate-limited + SQLite-cached) or an offline blocklist. | T1204 |
| `brute_force.py` | Counts EID 4625 failures per (user, host) in a sliding window; escalates to *critical* if a 4624 success follows shortly after (credentials were likely compromised). | T1110 |
| `lsass_mimikatz.py` | Sysmon EID 10 where the target process is `lsass.exe` and the access mask or source process name matches known credential-dumping patterns. | T1003.001 |
| `powershell_analyzer.py` | Scans EID 4104 script blocks for suspicious keywords (`-enc`, `IEX`, `DownloadString`, ...) and **decodes Base64 `-EncodedCommand` payloads** so the real command is visible in the alert. | T1059.001 |
| `ransomware.py` | Three independent signals: shadow-copy/backup deletion commands, a burst of file-create events on one host, and known ransomware file extensions. | T1486 / T1490 |
| `persistence.py` | Scheduled tasks (EID 4698) or registry Run keys (Sysmon EID 13) pointing at a user-writable path or invoking PowerShell. | T1053.005 / T1547.001 |
| `lateral_movement.py` | Admin-share access (EID 5140) followed by a PsExec service process on the same host, or one account touching admin shares on 3+ hosts within minutes. | T1021 |
| `impossible_travel.py` | Haversine distance between two consecutive sign-in locations, divided by elapsed time — flags implied travel speeds faster than a commercial flight. Works on sample `cloud_auth` data, and on real Windows remote logons (EID 4624, RDP/network) resolved via IPinfo. | T1078 |

Every detector is a plain function: `run(events, config, db) -> list[Alert]`.
They are fully independent of each other — you can delete or add a module
without touching anything else.

## How correlation ("The Brain") works

Individually, "5 failed logons" is a low-value alert. The correlation
engine (`core/correlation.py`) uses a **Union-Find** structure to link two
alerts whenever they share a non-null `entity_user`, `entity_host`,
`entity_ip`, or IOC value **and** occurred within `correlation.max_gap_minutes`
of each other (default 180). Every connected group that contains alerts from
2 or more different detectors becomes an **Incident** with:

- A combined severity (the highest severity among its alerts).
- An ordered MITRE ATT&CK technique chain.
- A step-by-step narrative stitching every alert into one story.

In the bundled demo data, this successfully links **15 alerts from 8
different detectors** — phishing, malicious PowerShell, brute force, LSASS
dumping, persistence, lateral movement, and ransomware — into a single
incident, while correctly leaving the unrelated "impossible travel" alert
standalone.

## How the AI report works

`reporting/genai_summary.py` hands Claude a **structured** summary of the
findings (severity counts, incident narratives, MITRE techniques, IOCs —
never raw logs) and asks it to write a plain-English executive summary plus
recommended actions, aimed at a non-technical leadership audience.

If `ANTHROPIC_API_KEY` is missing, the SDK call fails, or the response is
empty for any reason, it **automatically and silently falls back** to a
deterministic template-based summary — so report generation can never break
because of an AI/network issue. The report's "Executive Summary" section
always shows which one was used (`AI-Generated (Claude)` vs
`Template-Based`).

## Multi-tenancy — onboarding a new client

Every client gets a **physically separate SQLite database**
(`data/<tenant_id>/soc.db`), not a shared table with a `tenant_id` column —
there is no missing `WHERE` clause that could ever leak one client's alerts
into another's dashboard.

To add a client, add one entry to `config/tenants.yaml`. For a **real**
client, hash the access code instead of writing it in plaintext:

```bash
python -c "from core.tenants import hash_access_code; print(hash_access_code('their-code'))"
```

```yaml
tenants:
  - id: "new_client"
    name: "New Client Ltd"
    access_code_hash: "<digest printed above>"
    access_code_salt: "<salt printed above>"
```

(Plain `access_code: "..."` still works and is fine for local/demo tenants
like `demo`/`acme_corp` — it just isn't hashed.)

That's it — the next pipeline run or dashboard login for `new_client`
automatically creates its own isolated database, sample-data folder,
reports folder, and Settings (API keys/email credentials).

The bundled registry also has a `mohit_live` tenant, kept separate from
`demo` specifically so real/live test runs never mix with the synthetic
showcase data (see [Real (live) mode](#real-live-mode--your-own-windows-logs--email)).

## Reading a report

- **Severity:** `critical` (act now) > `high` (same-day triage) > `medium`
  (normal triage) > `low` (informational).
- **Incidents vs. standalone alerts:** an incident means 2+ *different*
  detection methods agreed something is wrong on the same entity — much
  higher confidence than any single alert.
- **MITRE ATT&CK table:** shows which stages of a real attack lifecycle
  (Initial Access, Credential Access, Persistence, Lateral Movement,
  Impact, ...) were actually observed.
- **IOCs:** IPs, domains, hashes, and URLs — feed these into your
  firewall/EDR/email gateway blocklists.

## Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| Executive summary says "Template-Based" | No Anthropic key (Settings tab or `ANTHROPIC_API_KEY`), or the API call failed — check the key/network. The report still generates correctly either way. |
| No VirusTotal alerts appear | No VT key configured — only indicators in the offline blocklist (`config.yaml`) are flagged. Expected in demo mode. |
| Live mode: "Access denied reading 'Security'" | The dashboard/CLI isn't running elevated. Close it and reopen from an **administrator** terminal. |
| Live mode: "Channel ... was not found" | Sysmon (or the log in question) isn't installed on this machine — see [Real (live) mode](#real-live-mode--your-own-windows-logs--email) for the install command. |
| Live mode: "IMAP login failed" | Wrong address/app password, or you used your real password instead of an app password. Regenerate the app password and re-enter it in Settings. |
| Re-running looks duplicated | It shouldn't — every run clears and rebuilds this tenant's alerts. If you still see stale-looking data, confirm you're looking at the right tenant. |
| Docker dashboard loses data after rebuild | Confirm `data/`, `sample_data/`, `reports/`, `config/` are mounted as volumes in `docker-compose.yml` (they are by default). |
| `ModuleNotFoundError` running the dashboard directly | Run it from the project root (`streamlit run dashboard/app.py`), not from inside `dashboard/`. |

## Moving to full production

Everything downstream of the ingestion layer only cares about the JSON
event schema, not where it came from — detectors, correlation, and
reporting never need to change. Current status per source:

- **Email (IMAP):** ✅ done — `ingestion/email_ingestion.py`.
- **Windows Security / Sysmon / PowerShell:** ✅ done — `ingestion/windows_event_log_reader.py`.
- **Impossible travel on real Windows remote logons:** ✅ done — resolves
  real source IPs via IPinfo (`ingestion/geoip_lookup.py`).
- **Cloud/AD sign-ins (impossible travel):** ✅ done — `ingestion/cloud_auth_ingestion.py`
  supports Azure AD, Okta, and Google Workspace. Okta has been unit-tested
  (mocked API); Azure AD and Google Workspace are implemented against their
  documented APIs but not yet exercised against a real tenant (none was
  available to test against) — verify once against your actual tenant.

Beyond that, for a real multi-client deployment: replace the dashboard's
access-code gate with `st.login()`/OIDC (see Multi-tenancy), and move API
keys/email credentials from the per-tenant SQLite `settings` table to a
proper secrets manager if you're deploying at scale.

## Known limitations

- **Docker has still not been build/run-tested** — there is no Docker
  installed on the machine this was built on, so the Dockerfile/compose
  setup (including the `scheduler` service) is written to a standard,
  well-known pattern but unverified end-to-end. Verify it once before
  relying on it. `pywin32` (needed for live Windows log reading) only
  installs on Windows; it's skipped automatically inside the Linux image.
- The dashboard's tenant login supports **hashed** access codes now
  (`access_code_hash`/`access_code_salt` — see Multi-tenancy), which is a
  real improvement over a plaintext shared secret, but it is still a
  shared-secret gate, not per-user enterprise authentication (SSO/OIDC).
- Settings (API keys, email app password, Slack webhook) are stored as
  plaintext in the tenant's local SQLite file — fine for local/demo use,
  not a secrets vault.
- VirusTotal's free tier is limited to 4 requests/minute; results are
  cached in SQLite (`vt_cache` table) to respect this.
- Cloud/AD sign-in log support (Azure AD/Okta/Google Workspace) is
  implemented and, for Okta, unit-tested against a mocked API - Azure AD and
  Google Workspace are correct against their documented request/response
  shapes but haven't been exercised against a real tenant. Azure AD
  specifically also requires an Azure AD Premium P1/P2 license on the
  target tenant (Microsoft's requirement, not this tool's).
- The Google Workspace service account JSON key is stored the same way as
  every other setting (plaintext in the tenant's local SQLite file) - it's
  a comparatively high-value secret, so treat that database file with
  extra care if you configure this provider.
- **Detection thresholds are unvalidated against any real environment.**
  The values in `config.yaml` (e.g. 5 failed logons = brute force) are
  reasonable starting points, not tuned against your actual traffic — this
  can't be solved in code; budget time to watch what fires in your first
  week live and adjust thresholds/whitelists accordingly.
- The scheduler is a simple polling loop (checks every 30s), not a
  distributed job queue — fine for the number of tenants a small team
  would realistically run, not built for hundreds of tenants on one process.
