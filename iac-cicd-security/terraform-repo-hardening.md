# Terraform repository hardening ([TEMPLATE])

Checklist for any repo that stores the DEMO modules under `cloud-security/terraform/{aws,azure,gcp}` — or a real landing-zone fork.

## Remote state + lock

- [ ] Backend is remote (S3 + DynamoDB lock, Azure Storage + blob lease, GCS + prefix). **Not** git-tracked `.tfstate`.
- [ ] State bucket: encryption (CMK/CMEK where required), versioning, public-access block, access logging.
- [ ] State lock table / lease prevents concurrent apply.
- [ ] Backend config via `-backend-config` or CI environment — **no access keys in `.tf` files**.
- [ ] State file is treated as secret (may contain resource IDs and data-source output).

This portfolio uses `terraform init -backend=false` in CI so validate works without a live backend.

## No secrets in Terraform

- [ ] No `*.tfvars` with credentials committed (see `.gitignore`).
- [ ] No hardcoded tokens, private keys, or connection strings.
- [ ] Sensitive outputs marked `sensitive = true`.
- [ ] Provider credentials come from OIDC / environment / vault — not `AWS_ACCESS_KEY_ID` in repo secrets if OIDC is available.

## CODEOWNERS + branch protection

- [ ] [`../CODEOWNERS`](../CODEOWNERS) covers `.github/`, `cloud-security/terraform/`, and this folder.
- [ ] Default branch: require PR, require CODEOWNERS review, dismiss stale reviews.
- [ ] Require status checks: `terraform-fmt-validate (*)`, `iac-checkov`, `iac-trivy-config`, `lint-test-build`.
- [ ] No direct pushes to `main` except break-glass (logged).
- [ ] Restrict who can change workflow files (CODEOWNERS + `/.github/`).

## Plan on PR, apply with environment approval

```
PR opened
  → fmt -check + validate + Checkov + Trivy + dependency-review
  → terraform plan (OIDC, read-only role) posted as PR comment
PR merged to main
  → apply job uses GitHub Environment "production"
  → required reviewers + optional wait timer
  → apply role is separate from plan role (write vs read)
```

- [ ] Plan role cannot apply; apply role cannot be assumed from feature-branch workflows (`sub` condition).
- [ ] `terraform plan -out=tfplan` artifact is integrity-protected (see provenance blurb in the pipeline checklist).
- [ ] Destroy / unlock are manual, dual-control runbooks.

## fmt / validate locally

```bash
for cloud in aws azure gcp; do
  (cd cloud-security/terraform/$cloud && terraform fmt -check && terraform init -backend=false && terraform validate)
done
```
