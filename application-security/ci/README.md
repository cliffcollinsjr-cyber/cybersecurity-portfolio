# CI Security Gates

**Canonical running workflow:** [`.github/workflows/security-gates.yml`](../../.github/workflows/security-gates.yml)

That workflow is what GitHub Actions executes on pull requests and pushes to `main` (Terraform fmt/validate, Checkov, Trivy config, dependency-review, pip-audit).

This folder keeps a **template** you can copy into other application repos:

- Sample workflow: [`github-actions-security.yml`](./github-actions-security.yml) (Semgrep SAST + dependency-review + pip-audit)

Gates illustrated (template + live):

- Dependency review on PRs (fail on High+)
- Semgrep SAST (template only)
- pip-audit when Python requirements exist
- IaC scanners on Terraform (live workflow)

Tune severities and waive with documented risk acceptance in real orgs.
