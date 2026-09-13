# Pipeline hardening checklist ([TEMPLATE])

Use this when reviewing GitHub Actions in this repo or a fork.

## Permissions

- [ ] Workflow-level `permissions:` is the **minimum** (usually `contents: read`).
- [ ] Jobs that need more (`id-token: write`, `security-events: write`, `pull-requests: write`) grant it **only on that job**.
- [ ] No `permissions: write-all` / default permissive token.
- [ ] `GITHUB_TOKEN` not passed into untrusted PRs with write scopes (fork PRs).
- [ ] OIDC `id-token: write` only on deploy/plan jobs that assume a cloud role.

## Pin actions

- [ ] Production pins `owner/action@<40-char-SHA>` and comments the version tag.
- [ ] This DEMO pins **major versions** (`@v4`, `@v3`, `@v12`, `@v0.36.0`) plus a reminder comment.
- [ ] Dependabot `github-actions` ecosystem enabled (weekly).
- [ ] Review action source before bumping; prefer verified creators.

## No long-lived keys

- [ ] Cloud access via OIDC / federated credentials (see `oidc-cloud-deploy.md`).
- [ ] Existing access-key secrets have an expiry ticket and an OIDC migration date.
- [ ] Fine-grained PATs (if unavoidable) are org-owned, scoped, and rotated.
- [ ] `pull_request_target` is not used unless the job is fully isolated from untrusted checkout.

## Environments

- [ ] `production` (and `lab`) GitHub Environments exist.
- [ ] Required reviewers on `production`; optional wait timer.
- [ ] Environment secrets / vars — not repository-wide secrets — for deploy.
- [ ] Deployment branches restricted (`main` only for apply).

## Required reviewers

- [ ] Branch protection: CODEOWNERS on `.github/` and Terraform paths.
- [ ] Apply environment: different human than the PR author when possible.
- [ ] Break-glass documented; not the default path.

## Artifact provenance (blurb)

Build and plan artifacts should be **attributable**:

- Record `github.sha`, workflow run ID, and actor on every plan/apply log.
- Prefer SLSA / GitHub Artifact Attestations (`actions/attest-build-provenance`) for release binaries.
- Do not promote an unsigned `tfplan` or container image across environments.
- Retain plan/apply logs for the same retention as change tickets.

This portfolio's Go notifier is a local `make build-go` binary (gitignored). A real release pipeline would sign and attest it.

## Other gates already illustrated

| Control | Where |
|---------|--------|
| Dependency review (High+) | `.github/workflows/security-gates.yml` |
| pip-audit | `security-gates.yml` job `sast-light` |
| Checkov + Trivy | `security-gates.yml` |
| Semgrep template | `application-security/ci/github-actions-security.yml` |
| Weekly dep bumps | `.github/dependabot.yml` |
