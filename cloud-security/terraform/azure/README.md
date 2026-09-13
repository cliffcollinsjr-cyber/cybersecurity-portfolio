# Azure Terraform Security Baseline ([DEMO])

Log Analytics (90-day retention), storage TLS 1.2, HTTPS-only, no public network/blob access, GRS, infrastructure encryption, queue logging, SAS expiration, blob soft-delete, restrictive NSG starter.

CI: `terraform fmt -check` + `init -backend=false` + `validate` (no Azure credentials).
