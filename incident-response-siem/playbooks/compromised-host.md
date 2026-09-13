# Playbook: Compromised Host

**Classification:** [TEMPLATE]  
**Scope:** Endpoint suspected of unauthorized access or control

## Indicators of compromise (examples — [DEMO] patterns)

- Unexpected RDP/SSH from unusual geo
- New local admin account
- EDR sensor tampering alerts
- Beacon-like periodic outbound connections

## Response phases

### Identify

- Correlate Falcon detections + Splunk auth + network telemetry.
- Establish first-seen vs last-seen of suspicious activity.

### Contain

1. Falcon network containment (isolate) — see `crowdstrike-runbooks/isolate-host.md`.
2. Disable risky accounts at IdP if identity linked.
3. Snapshot / preserve volatile evidence per org policy **before** major remediation when legal requires it.

### Eradicate

- Remove persistence; prefer rebuild for high-confidence compromise.
- Hunt sister hosts with same IOCs.

### Recover

- Reimage, restore from trusted backup, rejoin domain/IdP policies.
- Validate patch level and EDR health.

### Lessons learned

- Root cause (phishing, vuln exploit, supply chain, insider).
- Control gaps and detection improvements.
