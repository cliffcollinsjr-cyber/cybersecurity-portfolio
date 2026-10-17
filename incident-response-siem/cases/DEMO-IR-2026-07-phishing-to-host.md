# IR Case Deep-Dive — Phishing Click to Host Compromise

| Field | Value |
|-------|-------|
| **Classification** | `[DEMO]` — synthetic incident narrative |
| **Case ID** | `IR-DEMO-2026-07-019` |
| **Analyst / Author** | Cliff Collins Jr |
| **Opened** | 2026-07-09 14:22 UTC |
| **Closed** | 2026-07-10 18:05 UTC |
| **Severity** | High |
| **Environment** | Lab SIEM (Splunk) + CrowdStrike Falcon + Entra ID + email gateway |
| **Related hunt** | Escalation path similar to [`../hunt-reports/DEMO-2026-03-dns-beacon-hunt.md`](../hunt-reports/DEMO-2026-03-dns-beacon-hunt.md) host findings |

> All hosts, users, domains, hashes, and ticket IDs below are **fictional `[DEMO]` data**. No live production telemetry.

---

## 1. Executive summary

A workforce user clicked a credential-themed phishing URL, entered credentials on a lookalike site, and later executed a second-stage lure from email. Lab EDR then flagged encoded PowerShell on `lab-win10-19`. The case walked **detection → triage → containment → eradication → recovery**, with detection follow-ups into Splunk SPL and Falcon IOC handling.

## 2. Detection

| Signal | Source | Time (UTC) `[DEMO]` |
|--------|--------|---------------------|
| URL rewrite / phishing category | Secure email gateway | 2026-07-09 14:05 |
| Proxy hit to `login-acme-sso.example` (lab sinkhole category) | Web proxy → Splunk | 14:08 |
| Successful IdP sign-in from unusual ASN shortly after click | Entra / Okta-style auth → Splunk | 14:11 |
| CrowdStrike detection: suspicious PowerShell (`-EncodedCommand`) | Falcon | 15:47 |
| SOC ticket auto-opened | SOAR / ticketing stub | 15:50 |

**Primary correlation used:** pattern aligned with [`../splunk-queries/phishing_click_to_auth.spl`](../splunk-queries/phishing_click_to_auth.spl) (proxy click → auth within 30 minutes).

## 3. Triage (first 30 minutes)

Playbook followed: [`../playbooks/phishing-response.md`](../playbooks/phishing-response.md).

1. Confirmed user `jordan.lee@[DEMO].lab` reported the message *after* clicking (awareness still helped for mailbox sweep).
2. Captured subject, purported sender, rewritten URL, and attachment hash (hash only — not executed on analyst workstation).
3. Determined actions: **clicked + credential entry + later attachment open**.
4. Raised severity to **High**; linked Falcon host `lab-win10-19` / `10.20.12.19`.
5. Checked for sibling messages (same campaign ID / similar subject) — three additional recipients, **no clicks** in lab logs.

**Initial hypothesis:** credential theft + possible malware execution on one endpoint; no confirmed lateral movement yet.

## 4. Timeline `[DEMO]`

| Time (UTC) | Event |
|------------|-------|
| 14:02 | Phishing message delivered to `jordan.lee` |
| 14:08 | User clicks URL via proxy |
| 14:09–14:10 | Credentials submitted on lookalike page (inferred from user interview + auth anomaly) |
| 14:11 | Successful sign-in from atypical geo/ASN; MFA satisfied (fatigue / approval — lab scenario) |
| 14:25 | SOC blocks URL/domain at proxy & gateway (L2) |
| 14:28 | Force password reset + session revoke initiated (IAM) |
| 15:40 | Second email with “invoice” attachment opened on `lab-win10-19` |
| 15:47 | Falcon alerts on encoded PowerShell child of office process |
| 15:55 | Host isolation approved (IR lead) — see [`../crowdstrike-runbooks/isolate-host.md`](../crowdstrike-runbooks/isolate-host.md) |
| 16:10–17:30 | RTR-style evidence collection (high-level only) — [`../crowdstrike-runbooks/rtr-high-level.md`](../crowdstrike-runbooks/rtr-high-level.md) |
| 17:45 | IOC package drafted — [`../crowdstrike-runbooks/ioc-hunting.md`](../crowdstrike-runbooks/ioc-hunting.md) |
| Jul 10 11:00 | Reimage decision; user restored to clean baseline |
| Jul 10 18:05 | Case closed — lessons + detection tickets filed |

Template kinship: [`../templates/incident-timeline-DEMO.md`](../templates/incident-timeline-DEMO.md).

## 5. Containment

| Action | Owner | Approval | Result |
|--------|-------|----------|--------|
| Block phishing URL/domain | SOC L2 | Per phishing playbook | Done |
| Password reset + revoke sessions / refresh tokens | IAM | SOC L2 + IAM | Done |
| Isolate `lab-win10-19` via Falcon | IR | IR lead | Done |
| Tenant-wide search & purge of campaign messages | Messaging | Authorized lab admin | Done |
| Disable suspected malicious OAuth grants (none found) | Identity | — | N/A this case |

Related host playbook: [`../playbooks/compromised-host.md`](../playbooks/compromised-host.md) and [`../playbooks/malware-response.md`](../playbooks/malware-response.md).

## 6. Eradication

- Removed malicious mail copies; confirmed no inbox rules planted (lab check).
- Host treated as untrusted after encoded PowerShell — **reimaged** rather than “clean in place.”
- Verified no persistence in Run keys / scheduled tasks on forensic snapshot (DEMO checklist only).
- Pushed DEMO IOCs (domain, URL path, file hash placeholder) to Falcon IOC management for org-wide hunt.

## 7. Recovery

- User returned on known-good image; MFA re-enrollment completed.
- Access restored after IAM attestation; mailbox monitored 72h (lab policy).
- Business validation: no evidence of data staging to external storage in proxy logs for this host (DEMO).

## 8. Lessons learned

1. **Click → auth correlation** caught identity risk before EDR; keep SPL join windows tuned (30m worked; consider 60m for slow MFA).
2. MFA approval alone did not stop session abuse — pair with Continuous Access Evaluation / risk-based blocks where available.
3. Second-stage attachment arrived **after** password reset — identity containment ≠ host containment; run both tracks in parallel.
4. Users who report *late* still unlock campaign scope (mailbox search) — keep reporting friction low.

### Lessons / what I'd do differently

Still a `[DEMO]` narrative — reflecting on the process I'd tighten next time, not claiming a live tenant win.

- **Open identity and host tracks together.** I sequenced password reset before host isolation in the first draft timeline; in a real case I'd push both in parallel as soon as click + encoded PowerShell lined up, and document the approval gates explicitly so nobody waits on the other track.
- **Widen the auth join, then prove it.** Thirty minutes caught this story; I'd also run a 60–90m window and measure noise before promoting the SPL. Slow MFA and deferred “invoice” opens are exactly where short joins go blind.
- **Treat MFA-satisfied risk as a first-class signal.** Lab “fatigue / approval” was convenient for the plot; operationally I'd want risk-based Conditional Access or CAE-style session invalidation in the playbook, not only a password reset checkbox.
- **Pre-stage mailbox campaign search.** Sibling recipients with zero clicks still matter for scope. I'd keep the SOAR/ticketing stub's campaign-ID search as a mandatory early step, not a nice-to-have after isolation.
- **Detection follow-ups as tickets, not footnotes.** The SPL / KQL / detection-as-code links below are the durable value of the case. Next time I'd file them as numbered follow-ups with owners before closing, even in lab.

## 9. Detection follow-ups

| Follow-up | Link / artifact | Owner idea |
|-----------|-----------------|------------|
| Retain / tune phishing→auth SPL | [`../splunk-queries/phishing_click_to_auth.spl`](../splunk-queries/phishing_click_to_auth.spl) | Detection eng |
| Rare parent/child process hunt | [`../splunk-queries/rare_process_parent_child.spl`](../splunk-queries/rare_process_parent_child.spl) | Threat hunt |
| Encoded PowerShell KQL parity | [`../../edr-microsoft-defender/kql/suspicious_powershell.kql`](../../edr-microsoft-defender/kql/suspicious_powershell.kql) | EDR content |
| Detection-as-code samples (YAML + fixture tests) | [`../../detection-as-code/`](../../detection-as-code/) | Det eng / portfolio |
| DNS beaconing hunt if C2 suspected later | [`../hunt-reports/DEMO-2026-03-dns-beacon-hunt.md`](../hunt-reports/DEMO-2026-03-dns-beacon-hunt.md) | Hunt team |
| SOAR phishing triage design | [`../../splunk-soar/playbooks/phishing_triage.yaml`](../../splunk-soar/playbooks/phishing_triage.yaml) | SOAR |

## 10. Evidence checklist (completed in lab)

- [x] Original email metadata retained (DEMO)
- [x] URL / attachment hash recorded (placeholders)
- [x] Auth logs around click time
- [x] Host process tree / Falcon detection id
- [x] Isolation ticket + timeline updated
- [x] Lessons filed; no production push (DEMO only)

---

**Ethics:** Authorized lab narrative only — see [`../../LAB-ETHICS.md`](../../LAB-ETHICS.md). No exploit code or phishing kits in this repository.
