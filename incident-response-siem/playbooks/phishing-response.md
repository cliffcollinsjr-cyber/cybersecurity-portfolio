# Playbook: Phishing Response

**Classification:** [TEMPLATE] / [DEMO]-ready  
**Systems:** Email gateway, Splunk, CrowdStrike Falcon, ticketing  
**Severity mapping:** Low (single user, no click) → Critical (credential harvest + lateral movement)

## 1. Trigger conditions

- User report of suspicious email
- Secure email gateway / URL rewrite alert
- Splunk correlation: mail delivery + unusual auth shortly after

## 2. Triage (15 minutes)

1. Capture message headers, subject, sender, URLs/attachments (hash only — do not open).
2. Search mailbox / SIEM for similar messages (`from`, subject similarity, campaign ID).
3. Determine user action: opened / clicked / entered credentials / reported only.
4. Assign severity and create ticket with `[DEMO]` fields if training.

## 3. Containment

| Condition | Action | Approval |
|-----------|--------|----------|
| Malicious URL clicked | Block URL/domain at proxy & email gateway | SOC L2 |
| Credentials entered | Force password reset + revoke sessions (IdP) | SOC L2 + IAM |
| Attachment executed | Isolate host via EDR (see CrowdStrike isolate runbook) | SOC L2 / IR lead |
| Lateral movement suspected | Escalate to IR lead; preserve evidence | IR lead |

## 4. Eradication & recovery

- Remove malicious mail from mailboxes (tenant-wide search & purge where authorized).
- Confirm MFA re-enrollment if identity compromise.
- Reimage only if host integrity cannot be trusted.

## 5. Lessons learned

- Update SPL detections for campaign TTPs.
- Feed IOCs to Falcon IOC management (high-level — see runbook).
- User awareness follow-up if social engineering succeeded.

## Evidence checklist

- [ ] Original email / EML retained
- [ ] URL/attachment hashes recorded
- [ ] Auth logs around click time
- [ ] Host process tree if execution
- [ ] Ticket ID and timeline updated
