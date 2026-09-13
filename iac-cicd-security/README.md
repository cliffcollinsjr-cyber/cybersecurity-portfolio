# IaC + CI/CD Security

**Skills proven:** GitHub Actions least-privilege workflows, Terraform `fmt`/`validate` gates, Checkov + Trivy IaC scanning, Dependabot, CODEOWNERS, OIDC-to-cloud deploy patterns (no long-lived keys), remote-state/branch-protection hardening.

All cloud IDs, tenants, and repo names in this folder are **`[DEMO]` placeholders**. Nothing here is wired to a live account. See [`../LAB-ETHICS.md`](../LAB-ETHICS.md).

## Open first

| Artifact | Path |
|----------|------|
| Live security gates (canonical) | [`../.github/workflows/security-gates.yml`](../.github/workflows/security-gates.yml) |
| Portfolio lint/test/build CI | [`../.github/workflows/ci-portfolio.yml`](../.github/workflows/ci-portfolio.yml) |
| Dependabot | [`../.github/dependabot.yml`](../.github/dependabot.yml) |
| CODEOWNERS (DEMO) | [`../CODEOWNERS`](../CODEOWNERS) |
| Checkov config + skips | [`../.checkov.yml`](../.checkov.yml) |
| OIDC → AWS / Azure | [`oidc-cloud-deploy.md`](./oidc-cloud-deploy.md) |
| Terraform repo hardening | [`terraform-repo-hardening.md`](./terraform-repo-hardening.md) |
| Pipeline hardening checklist | [`pipeline-hardening-checklist.md`](./pipeline-hardening-checklist.md) |
| Sample trust policy / federated ID | [`examples/`](./examples/) |

## What the live gates enforce

On pull request and push to `main`:

1. `terraform fmt -check` + `init -backend=false` + `validate` for AWS, Azure, and GCP modules
2. Checkov (Terraform) with a documented DEMO skip list
3. Trivy config / misconfig scan (`CRITICAL`/`HIGH`)
4. GitHub Dependency Review on PRs (fail on High+)
5. Light app SAST: `pip-audit` on the Python enrichment requirements

`continue-on-error: false` on every gate. Scanners are configured so current DEMO Terraform hard-fails cleanly — no soft-fail for empty modules.

The older sample workflow [`../application-security/ci/github-actions-security.yml`](../application-security/ci/github-actions-security.yml) remains as a **template** (Semgrep + pip-audit). It is **not** the running workflow.

## Skill map

| Skill | Evidence |
|-------|----------|
| Least-privilege GITHUB_TOKEN | Workflow- and job-level `permissions:` in both workflows |
| Action pinning hygiene | Major-version tags + comments that production must pin SHAs |
| IaC quality gate | `hashicorp/setup-terraform` fmt/validate matrix |
| IaC policy-as-code | Checkov + Trivy + `.checkov.yml` / `.trivyignore` justifications |
| Keyless cloud deploy | OIDC trust policy JSON + Azure federated-credential notes |
| Change control | CODEOWNERS, branch protection, environment approval (docs) |
| Supply-chain hygiene | Dependabot (github-actions + pip), dependency-review job |
