# Application Security — Secure SDLC, CI Gates, Threat Modeling

**Skills proven:** Secure SDLC checklist authorship, CI SAST/dependency scanning gates (GitHub Actions), STRIDE threat modeling, OWASP-aligned review & remediation notes, **professional finding write-ups** (authZ / IDOR).

**Live gates** (this repo): [`.github/workflows/security-gates.yml`](../.github/workflows/security-gates.yml)  
**Template** (copy into an app repo): [`ci/github-actions-security.yml`](./ci/github-actions-security.yml)  
**IaC / OIDC / pipeline hardening:** [`../iac-cicd-security/`](../iac-cicd-security/)

## Open first

| Artifact | Path |
|----------|------|
| DEMO finding — IDOR on export API | [`findings/DEMO-2026-06-idor-export-api.md`](./findings/DEMO-2026-06-idor-export-api.md) |
| Findings index | [`findings/`](./findings/) |
| Secure SDLC checklist | [`sdlc/secure-sdlc-checklist.md`](./sdlc/secure-sdlc-checklist.md) |
| STRIDE sample | [`threat-modeling/stride-sample-webapp.md`](./threat-modeling/stride-sample-webapp.md) |
| OWASP-aligned review notes | [`owasp-reviews/owasp-aligned-review-notes.md`](./owasp-reviews/owasp-aligned-review-notes.md) |
| CI SAST/deps template | [`ci/github-actions-security.yml`](./ci/github-actions-security.yml) |

All finding content is **`[DEMO]`** lab material — see [`../LAB-ETHICS.md`](../LAB-ETHICS.md).
