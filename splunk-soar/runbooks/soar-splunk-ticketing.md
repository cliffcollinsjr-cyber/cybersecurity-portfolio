# Runbook: SOAR ↔ Splunk ↔ Ticketing

**Classification:** [TEMPLATE]

## Integration map

| Hop | Purpose | Failure mode |
|-----|---------|--------------|
| Splunk → SOAR | Notable / webhook triggers playbook | Queue backlog; duplicate artifacts |
| SOAR → Splunk | Run supporting SPL for prevalence | Query timeout; RBAC |
| SOAR → Ticketing | Create/update incidents | Auth expiry; field mapping drift |
| SOAR → Chat | Analyst notification | Wrong channel / noisy |

## Operational checklist

- [ ] Playbook active in SOAR; pinned version documented
- [ ] Splunk saved searches that trigger SOAR tagged `soar-enabled`
- [ ] Ticket project / severity mapping agreed with SOC lead
- [ ] Approval tasks for containment tested in lab
- [ ] Runbook owners and on-call contact listed

## Example happy path (phishing)

1. Splunk notable fires → SOAR artifact created  
2. Enrichment custom function + Splunk prevalence query  
3. Ticket opened with enriched fields  
4. Approval for purge/block if malicious  
5. Chat notify + case comment  
