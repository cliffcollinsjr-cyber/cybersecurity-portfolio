# Troubleshooting Playbook — NGFW Connectivity / Security

**Classification:** [TEMPLATE]

## Symptom → checks

1. **User cannot reach app**
   - Session browser / traffic logs for deny vs no session
   - Policy order hit
   - Route / NAT / DNS
   - Security profile (AV/spyware/URL) block reason
2. **Intermittent drops**
   - Session timeouts, asymmetric routing, HA failover events
3. **High CPU / session table**
   - Top talkers, flood signatures, logging overhead

## Evidence to collect

- Rule UUID / name hitting
- Source user (User-ID)
- App-ID vs service port mismatch
- Threat log ID if profile blocked

## Escalation

Escalate to network eng if routing/HA; to IR if threat logs indicate compromise.
