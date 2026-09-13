# Change-Management Runbook — Palo Alto NGFW

**Classification:** [TEMPLATE]

## Change types

| Type | Examples | CAB? |
|------|----------|------|
| Standard | Add FQDN object already reviewed | Pre-approved |
| Normal | New app allow between zones | CAB as required |
| Emergency | Block active IOC / C2 | Emergency CAB after |

## Workflow

1. Ticket with business justification, risk, rollback.
2. Peer review of candidate rule (source/dest/app/service/user/profile).
3. Stage in lab / non-prod panorama device-group when available.
4. Implement during window; commit with descriptive comment.
5. Validate traffic logs / test plan.
6. Monitor for 24–72h; close with evidence.

## Commit hygiene

- One logical change per commit when practical.
- Never commit unreviewed `any/any/any` allows.
- Include ticket ID in commit description.
