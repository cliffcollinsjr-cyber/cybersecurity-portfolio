# CIS-Aligned Checklist — AWS (Selected Controls)

**Classification:** [TEMPLATE] — aligned in spirit to CIS AWS Foundations; not a certified audit.

| Area | Check | Evidence ideas |
|------|-------|----------------|
| IAM | Root account MFA; no access keys on root | IAM credential report |
| IAM | MFA for privileged users | Console / IdP |
| Logging | CloudTrail enabled multi-Region | Trail status |
| Logging | CloudTrail logs to encrypted S3 + retention | Bucket policy / KMS |
| Config | AWS Config recorder enabled | Config console |
| Network | No 0.0.0.0/0 on admin ports (22/3389) | Security groups |
| Storage | S3 Block Public Access | Account BPA |
| Encryption | EBS / S3 default encryption | EC2 / S3 settings |
| Monitoring | Security Hub / GuardDuty enabled | Service consoles |
