# GCP Terraform Security Baseline ([DEMO])

Uniform bucket access, public-access prevention, versioning, access logging to a sink bucket, illustrative deny-ingress firewall rule. Replace `project_id` with a lab project you own.

CI: `terraform fmt -check` + `init -backend=false` + `validate` (no GCP credentials).
