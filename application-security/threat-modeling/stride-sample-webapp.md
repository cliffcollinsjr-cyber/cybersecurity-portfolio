# STRIDE Threat Modeling Worksheet — Sample Web App

**Classification:** [DEMO]  
**System:** Demo Customer Portal (fictional)  
**Author:** Cliff Collins Jr

## System overview

Browser → TLS → Web App (app tier) → API → PostgreSQL; IdP for SSO; object storage for uploads.

## Trust boundaries

1. Internet → Edge / WAF  
2. App tier → Database  
3. App tier → Object storage  
4. App tier → Corporate IdP  

## STRIDE worksheet

| Element | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation |
|---------|----------|-----------|-------------|-----------------|-----|-----------|
| Login | Session fixation / stolen token | — | Missing auth logs | User enumeration | Login flooding | Broken role checks |
| Uploads | — | Malware in file | No audit of deletes | Public bucket ACL | Large upload | Upload to admin path |
| API | Forged JWT | Param tampering | No request IDs | Excessive data in errors | Expensive queries | IDOR |
| DB | — | SQLi | Weak DB audit | Backup exposure | Connection exhaustion | App role over-privileged |

## Top mitigations

1. SSO + MFA; short-lived tokens; secure cookies  
2. Server-side authZ on every object (no IDOR)  
3. Parameterized queries; least-privilege DB role  
4. Private buckets; malware scanning on upload  
5. WAF + rate limits; structured audit logs to SIEM  
