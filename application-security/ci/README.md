# CI Security Gates

Sample workflow: [`github-actions-security.yml`](./github-actions-security.yml)

Gates illustrated:

- Dependency review on PRs (fail on High+)
- Semgrep SAST
- pip-audit when Python requirements exist

Tune severities and waive with documented risk acceptance in real orgs.
