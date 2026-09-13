# CrowdStrike Falcon — IOC Hunting Runbook

**Classification:** [TEMPLATE] / [DEMO] examples  

## Objective

Search Falcon telemetry for indicators of compromise obtained from trusted intel, phishing analysis, or sibling incidents.

## IOC types commonly hunted

| Type | Example [DEMO] | Notes |
|------|----------------|-------|
| File SHA256 | `aaaabbbbccccdddd...` (placeholder) | Prefer hash over filename |
| Domain | `update-service-demo.example` | Corroborate with DNS/proxy |
| IPv4 | `203.0.113.50` (TEST-NET) | RFC 5737 documentation range |
| Filename | `invoice_demo_update.exe` | High FP — combine with path/hash |

## Workflow

1. Normalize IOCs; tag source and confidence.
2. Search Falcon IOC Management / Host search / detections.
3. Pivot to process tree and network events for hits.
4. Scope blast radius (users, OUs, geographies).
5. Add high-confidence IOCs to custom IOCs with appropriate action (detect vs prevent) per change control.
6. Sync critical IOCs to Splunk notable lookups if used.

## Documentation template

- IOC value / type / confidence / first seen / source
- Hosts hit / clean
- Actions taken (monitor, prevent, isolate)
