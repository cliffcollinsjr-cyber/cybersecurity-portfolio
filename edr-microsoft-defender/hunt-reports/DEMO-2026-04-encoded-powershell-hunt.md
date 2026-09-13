# Threat Hunt Report — Encoded / Download-Cradle PowerShell

| Field | Value |
|-------|-------|
| **Classification** | `[DEMO]` — synthetic lab narrative |
| **Hunt ID** | `HUNT-DEMO-2026-04-006` |
| **Analyst** | Cliff Collins Jr |
| **Date** | 2026-04-06 |
| **Environment** | Microsoft Defender for Endpoint (lab tenant) |
| **Status** | Closed — custom detection idea drafted |

---

## 1. Hypothesis

Adversaries and some legit tools launch PowerShell with **encoded commands** (`-enc` / `-EncodedCommand`) or **remote download cradles** (`IEX`, `DownloadString`, `Invoke-WebRequest`). A hunt over Advanced Hunting process events can surface unusual parents and rare command-line patterns before a signatured alert fires.

**Why now:** Gap analysis after reviewing Defender malware-alert triage playbook — several lab red-team sims used encoded PS without immediate “malware blocked” alerts.

## 2. Scope & data sources

| Table / API | Use |
|-------------|-----|
| `DeviceProcessEvents` | PowerShell launches + command lines |
| `DeviceNetworkEvents` | Optional: child network to rare hosts |
| `DeviceFileEvents` | Optional: script drop near execution |

**Time range:** `ago(7d)`.  
**Out of scope:** Running attack tools; disabling AV; production policy change without change control.

## 3. Hunt methodology

1. Baseline query for encoded / cradle keywords (see KQL).
2. Cluster by `InitiatingProcessFileName`, `AccountName`, `DeviceName`.
3. Exclude known package managers / SCCM / Intune script hosts where documented.
4. Pivot remaining to network + file events.
5. Propose custom detection with suppression guidance.

## 4. Primary query (KQL)

Canonical copy: [`../kql/suspicious_powershell.kql`](../kql/suspicious_powershell.kql)

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "DownloadString", "Invoke-WebRequest", "IEX")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| top 100 by Timestamp desc
```

**Follow-up pivot `[DEMO]`:** for each interesting `DeviceId`, join `DeviceNetworkEvents` within ±5 minutes for rare remote IPs.

## 5. Findings `[DEMO]`

| Device | Account | Parent | Notes | Verdict |
|--------|---------|--------|-------|---------|
| `DEMO-LAPTOP-12` | `jsmith` | `code.exe` | Dev encoded helper script | **Benign** — engineering exception |
| `DEMO-FINANCE-03` | `apayroll` | `winword.exe` | Macro → encoded PS cradle | **True positive** — phishing chain; isolated per playbook |
| `DEMO-JUMP-01` | `svc_backup` | `services.exe` | Scheduled encoded task | **Suspicious** — unexpected; ticket to sysadmin + IR |

**Impact (lab):** Finance workstation contained; user password reset / session revoke simulated; mailbox rule check completed.

## 6. False positives & tuning

| FP class | Mitigation |
|----------|------------|
| IDE / build tools spawning PS | Suppress when parent in allowlist *and* unsigned script path absent |
| IT automation (`IEX` from approved share) | Path + code-signing + change ticket tag |
| `Invoke-WebRequest` for package restore | Require non-user context or known CDN destinations |

**Custom detection idea:** Alert when encoded PS **and** parent is Office/browser **or** first-seen parent on that device in 30 days. See also [`../detections/custom-detection-ideas.md`](../detections/custom-detection-ideas.md).

## 7. Outcomes & follow-ups

- [x] Hypothesis validated in lab tenant
- [x] One phishing-driven TP documented
- [x] Detection idea written for engineering review
- [ ] Live custom detection enablement — **not applicable** (DEMO only)

## 8. Lessons learned

Command-line keyword hunts are high-volume; **parent process + user role** cut noise more than growing deny lists. Encoded PS from Office remains a high-signal combo for phishing-led intrusion in this lab.
