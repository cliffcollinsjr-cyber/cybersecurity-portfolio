# [DEMO] Sample Incident Timeline — Credential Phishing → Host Isolate

> **DEMO DATA ONLY.** Hosts, users, IPs, and ticket IDs are fictional. Not a real production incident.

| UTC Time | Event | Source | Notes |
|----------|-------|--------|-------|
| 2026-03-10 14:02 | User `jdoe_demo` receives phishing email | Email gateway | Subject: "Invoice 88421 — action required" |
| 2026-03-10 14:07 | User clicks URL `https://login-demo.example/secure` | Proxy | Category: newly observed |
| 2026-03-10 14:08 | Possible credential submit | IdP risk | Impossible travel flag **not** present |
| 2026-03-10 14:15 | Successful SSO from IP `203.0.113.50` | Okta/Entra [DEMO] | Same user |
| 2026-03-10 14:22 | Falcon medium severity: suspicious PowerShell | CrowdStrike | Host `WS-DEMO-042` |
| 2026-03-10 14:30 | SOC L2 isolates host via Falcon | Falcon | Ticket `IR-DEMO-2026-0310` |
| 2026-03-10 15:10 | Password reset + session revoke | IAM | MFA re-register required |
| 2026-03-10 17:45 | Host rebuilt from gold image | IT | Containment lifted after validation |

## Outcome (demo narrative)

Attack chain interrupted at host containment; no evidence of data exfiltration in demo dataset. Detections tuned for similar URL patterns.
