# CIS-Aligned Checklist — Azure (Selected Controls)

**Classification:** [TEMPLATE]

| Area | Check | Evidence ideas |
|------|-------|----------------|
| Identity | MFA for admins; privileged access reviews | Entra reports |
| Identity | Block legacy auth | Conditional Access |
| Logging | Activity logs → Log Analytics | Diagnostic settings |
| Storage | Secure transfer required; public access disabled | Storage properties |
| Network | NSGs default deny; JIT where used | NSG rules |
| Key Vault | Soft delete + purge protection | Key Vault props |
| Defender | Defender for Cloud plans for critical resources | Pricing tier |
| SQL / PaaS | TDE on; firewall deny public if private endpoint | Resource blades |
