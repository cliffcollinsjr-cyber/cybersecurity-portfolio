# CIS-Aligned Checklist — GCP (Selected Controls)

**Classification:** [TEMPLATE]

| Area | Check | Evidence ideas |
|------|-------|----------------|
| IAM | No user-managed keys for privileged SAs if avoidable | IAM recommendations |
| IAM | MFA / 2SV for console users | Workspace / Cloud Identity |
| Logging | Admin Activity + Data Access sinks retained | Cloud Logging |
| Network | VPC firewall least privilege; no 0.0.0.0/0 ssh unless justified | Firewall rules |
| Storage | Uniform bucket-level access; no public IAM | GCS |
| KMS | CMEK for sensitive buckets; rotation | KMS |
| Compute | OS Login; shielded VM where applicable | Instance metadata |
| Security | Security Command Center enabled | SCC |
