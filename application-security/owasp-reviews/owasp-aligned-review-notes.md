# OWASP-Aligned Review & Remediation Notes

**Classification:** [TEMPLATE] / [DEMO] examples  
Mapped loosely to OWASP Top 10 themes.

| Theme | Review question | Remediation example |
|-------|-----------------|---------------------|
| Broken Access Control | Can user A access user B object by ID? | Central authZ library; deny-by-default |
| Cryptographic Failures | Is TLS enforced? Are secrets at rest encrypted? | HSTS; KMS-backed secrets |
| Injection | Are queries parameterized? | ORM bind params; allowlists |
| Insecure Design | Were abuse cases modeled? | STRIDE before build |
| Security Misconfig | Defaults hardened? Debug off in prod? | Baseline IaC + CIS |
| Vulnerable Components | SCA in CI? | Gate on High/Critical |
| Auth Failures | MFA? Brute-force protections? | IdP policies; lockout/backoff |
| Software/Data Integrity | Signed artifacts? Protected main branch? | Sigstore/signing; branch protection |
| Logging Failures | AuthZ failures logged? | SIEM detections on spikes |
| SSRF | URL fetch allowlists? | Block link-local/metadata IPs |

## Sample remediation write-up ([DEMO])

**Finding:** API returns full account records on search without role filter.  
**Risk:** Medium — confidentiality of PII among authenticated users.  
**Remediation:** Enforce field-level responses by role; add integration tests for negative authZ; add detection for bulk enumeration patterns.
