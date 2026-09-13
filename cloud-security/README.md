# Cloud Security — AWS · Azure · GCP

**Skills proven:** Terraform security baselines, CIS-aligned checklists, read-only misconfiguration review helpers, landing-zone architecture notes.

Sample modules emphasize encryption, logging, network controls, and IAM least privilege.

CI (`terraform fmt -check`, `init -backend=false`, `validate`, Checkov, Trivy) runs from [`.github/workflows/security-gates.yml`](../.github/workflows/security-gates.yml). Repo hardening and OIDC deploy patterns: [`../iac-cicd-security/`](../iac-cicd-security/).
