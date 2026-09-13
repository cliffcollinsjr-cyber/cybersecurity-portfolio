# CrowdStrike Falcon — Host Isolation Runbook

**Classification:** [TEMPLATE] — high-impact action; requires approval  
**Skill:** EDR containment operations

## Preconditions

- Valid Falcon console access with containment privileges
- Ticket ID and documented justification
- Confirm host identity (hostname, AID, last user)

## Procedure (high-level)

1. Open Falcon console → Host management / detection linked host.
2. Verify sensor online and last seen timestamp.
3. Request / apply **Network Containment** (isolate).
4. Confirm status shows Contained; note timestamp in ticket.
5. Notify asset owner / IT that host is offline for business apps.
6. Continue investigation via RTR (read-only first) or offline imaging per policy.

## Lift isolation

1. Confirm eradication/recovery complete and IR lead approval.
2. Lift containment; verify connectivity and sensor health.
3. Document lift time and validator name.

## Safety notes

- Isolation can break production services — check criticality tags first.
- Some environments require change ticket before isolate outside critical severity.
