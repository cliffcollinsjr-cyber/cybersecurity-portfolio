# Secure SDLC Checklist

**Classification:** [TEMPLATE]

## Requirements / design

- [ ] Security requirements & data classification documented
- [ ] STRIDE / abuse cases reviewed for new features
- [ ] Privacy impact considered (PII minimization)

## Implementation

- [ ] Secrets not in source; use vault/CI secrets
- [ ] AuthZ checks server-side; least privilege roles
- [ ] Input validation & output encoding standards followed
- [ ] Dependencies pinned; SCA clean for Critical/High SLA

## Verification

- [ ] SAST gate in CI (no Critical without waiver)
- [ ] Dependency scanning gate
- [ ] Unit/integration tests for authZ negative cases
- [ ] Manual review for high-risk changes

## Release / operate

- [ ] Change ticket & rollback plan
- [ ] Security logging & alerts defined
- [ ] Incident contact & runbook link
- [ ] Post-release vulnerability SLA tracking
