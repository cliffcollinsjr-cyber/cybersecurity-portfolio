# CrowdStrike Falcon — Real Time Response (RTR) High-Level Runbook

**Classification:** [TEMPLATE]  
**Scope:** Authorized IR use only. This document describes **process**, not a command cookbook for abuse.

## Purpose

Collect triage artifacts and perform approved remediations on a live endpoint via Falcon RTR.

## Access & permissions

- RTR operator role (org-defined)
- Session recording / audit enabled
- Dual control recommended for write/remediate commands

## Session workflow

1. **Authorize** — ticket + severity + host confirmation.
2. **Connect** — start RTR session; verify correct AID/hostname.
3. **Read-first** — gather process list, network connections, persistence views, file hashes of interest.
4. **Package** — request official triage/collection package per org playbook.
5. **Remediate (if approved)** — kill malicious process, quarantine file, delete persistence — only after IR lead approval.
6. **Close** — end session; attach session ID and summary to ticket.

## Explicitly out of scope for this portfolio

- Credential dumping
- Offensive lateral movement via RTR
- Bypass of security controls for unauthorized access

## Evidence to capture

- Session ID, start/end times, operator
- Commands category (get vs put vs run) summary
- Hashes and paths of collected files
