# [DEMO] Splunk + CrowdStrike detection enrichment pattern

## Goal
Join Falcon detection events with asset inventory and recent auth for analyst context.

## Example SPL (placeholders)

```
index=crowdstrike sourcetype=crowdstrike:detections
| rename computer_name as host
| lookup asset_inventory host OUTPUT owner, business_unit, criticality
| join type=left host [
    search index=auth earliest=-24h
    | stats latest(_time) as last_auth, values(src_ip) as recent_ips by host, user
]
| table _time, detection_name, severity, host, owner, business_unit, criticality, user, recent_ips
| sort - severity, -_time
```

## Analyst notes
- Prefer CIM-compliant field names when available.
- Add notable event creation only after tuning FP rate in lab.
