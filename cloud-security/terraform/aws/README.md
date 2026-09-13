# AWS Terraform Security Baseline ([DEMO])

Illustrates: KMS rotation + key policy, S3 encryption + public access block + versioning + access logging + lifecycle, VPC flow logs, locked default SG, lean IAM policy document.

CI: `terraform fmt -check` + `init -backend=false` + `validate` (no AWS credentials). See [`../../../iac-cicd-security/`](../../../iac-cicd-security/).

```bash
# dry planning only — requires AWS creds you own
terraform init
terraform plan
```
