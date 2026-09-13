# Finding — IDOR on Account Export API

| Field | Value |
|-------|-------|
| **Classification** | `[DEMO]` — fictional sample web app assessment |
| **Finding ID** | `APPSEC-DEMO-2026-06-003` |
| **Author** | Cliff Collins Jr |
| **Date** | 2026-06-18 |
| **Severity** | **High** (CVSS-style narrative below) |
| **CWE** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) Authorization Bypass Through User-Controlled Key; related [CWE-284](https://cwe.mitre.org/data/definitions/284.html) Improper Access Control |
| **Status** | Remediation proposed — lab only |

---

## Title

Insecure Direct Object Reference (IDOR) on authenticated export endpoint allows cross-tenant data download.

## Affected component `[DEMO]`

| Item | Detail |
|------|--------|
| Application | Sample internal “Acme Reports” web app (lab) |
| Endpoint | `GET /api/v1/exports/{export_id}` |
| AuthN | Session cookie / bearer token (user is authenticated) |
| AuthZ gap | Object ownership / tenant membership **not** enforced on export retrieval |

The export API issues a UUID `export_id` when a user requests a CSV of their account activity. Retrieval only checked that the caller was logged in — not that the `export_id` belonged to them or their org.

## Severity narrative (CVSS-style)

Framed qualitatively for hiring-manager readability (not a formal Vector String from a live scan):

| Factor | Assessment |
|--------|------------|
| Attack vector | Network (authenticated API) |
| Privileges required | Low (any valid user session) |
| User interaction | None |
| Confidentiality | High — export may include PII, transaction metadata, or internal IDs of **other** tenants |
| Integrity / Availability | Low for this finding alone |
| **Overall** | **High** — broken object-level authorization on a data-exfiltration-friendly endpoint |

Comparable theme: OWASP API1 / Broken Object Level Authorization (BOLA).

## Reproduction (high level — no exploit payloads)

*Authorized lab assessment only. Steps describe the class of test, not a weaponized script.*

1. Authenticate as User A; request a legitimate export; note `export_id` from the response or UI.
2. Authenticate as User B (different tenant or sibling account in the lab).
3. Request the same export resource by substituting User A’s `export_id` in the path.
4. Observe: API returns HTTP 200 and User A’s export content to User B.

**Not included in this repo:** raw request dumps with secrets, Burp project files, or automation that mass-enumerates IDs.

## Impact `[DEMO]`

- Cross-account / cross-tenant **confidentiality** loss for anyone who can obtain or guess export IDs (UUIDs reduce guessing risk but do not replace authorization).
- Shared or leaked links become a silent exfil channel if authZ is absent.
- Compliance exposure (PII access without business need) in a real deployment of the same pattern.

## Root cause

Authorization was implemented at the **route** level (“must be logged in”) but not at the **object** level (“must own this export / share the same tenant”). The data layer keyed solely on `export_id` with no `owner_id` / `tenant_id` predicate in the query.

## Remediations

1. **Enforce object-level authZ** — every export fetch must filter by authenticated principal (and tenant): e.g. `WHERE id = :export_id AND owner_id = :current_user_id` (or equivalent tenant membership check).
2. **Deny by default** — return 404 (not 403 with enumeration hints) when the object is missing *or* not owned, per product privacy preference.
3. **Centralize authZ** — shared library / policy middleware so new export-like endpoints cannot skip the check.
4. **Tests** — negative integration tests: User B must not retrieve User A’s `export_id`; add to CI.
5. **Defense in depth** — short-lived signed download URLs scoped to owner; audit log export access (who, which id, outcome).
6. **Optional** — rate-limit bulk export retrieval patterns; alert on cross-tenant denial spikes in SIEM.

## Verification steps

- [ ] Negative test: User B requesting User A’s export receives non-success (404/403 per design) and empty body.
- [ ] Positive test: owner still retrieves own export.
- [ ] Code review confirms query includes owner/tenant predicate (or equivalent policy engine decision).
- [ ] Access denials appear in application logs with correlation id (no PII in log body beyond what policy allows).

## Lessons / what I'd do differently

`[DEMO]` assessment framing — practitioner notes on how I'd run the next review, not a claim about a production breach.

- **Test object-level authZ before fancy scanners.** The interesting failure here was “logged in ⇒ allowed,” not a missing header. I'd put negative cross-tenant/export-id cases in the first hour of an authorized API review, alongside the happy path.
- **Ask for the data-layer predicate in code review, not only a middleware diagram.** Route-level “must be authenticated” looks fine on a whiteboard and still ships BOLA. I'd require the `owner_id` / `tenant_id` filter (or equivalent policy decision) visible in the query or shared library.
- **Prefer 404 over chatty 403 for cross-tenant misses** when product privacy allows — and still log denials with a correlation id for SOC. Severity narrative stays High either way if exports carry PII.
- **Bake negative tests into CI before calling it remediated.** The verification checklist below is the bar I'd insist on; a one-off manual retest is too easy to skip on the next export-like endpoint.
- **Defense in depth is not a substitute for authZ.** Short-lived signed URLs and audit logs help, but I'd still fail the finding until object ownership is enforced server-side.

## References (internal portfolio)

- OWASP-aligned notes: [`../owasp-reviews/owasp-aligned-review-notes.md`](../owasp-reviews/owasp-aligned-review-notes.md)
- Secure SDLC checklist: [`../sdlc/secure-sdlc-checklist.md`](../sdlc/secure-sdlc-checklist.md)
- Lab ethics: [`../../LAB-ETHICS.md`](../../LAB-ETHICS.md)
