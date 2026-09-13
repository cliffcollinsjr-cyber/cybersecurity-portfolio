# Personal Lab Log — Cliff Collins Jr

This is my owned lab workbook for the cybersecurity portfolio at
[`cliffcollinsjr-cyber/cybersecurity-portfolio`](https://github.com/cliffcollinsjr-cyber/cybersecurity-portfolio).
Entities, timelines, and IOCs marked `[DEMO]` are synthetic. The engineering
practices — playbooks, queries, IaC, tests, CI — are intentional work I built
and validated here in mid-September 2026.

Ethics baseline: [LAB-ETHICS.md](./LAB-ETHICS.md). Paste-ready bullets:
[RESUME-BULLETS.md](./RESUME-BULLETS.md).

---

## What I actually ran / validated (this portfolio)

Concrete checks against **this** repo — not claims about tooling against real
customer tenants I do not operate.

### Publish & GitHub hygiene
- Published the portfolio to GitHub: **`cliffcollinsjr-cyber/cybersecurity-portfolio`**
- Enabled **Dependabot** + the **dependency graph**
- Set repository **topics** for discoverability
- Confirmed GitHub Actions **`ci-portfolio`** and **`security-gates`** are green on `main` (see README badges)

### Local / Makefile validation
- `make lint` — structure guards, Python `py_compile`, `gofmt` check
- `make test-python` — SOC alert-enrichment pytest **and** detection-as-code suite
- `make build-go` — Go notifier CLI builds clean

### IaC
- Terraform **`fmt -check`** + **`init -backend=false`** + **`validate`** for AWS, Azure, and GCP under `cloud-security/terraform/`
- **Checkov** clean on that tree with documented skips in `.checkov.yml` (and two inline skips noted there: `CKV_GCP_62`, `CKV_AZURE_33`)

### Script / workflow sanity
- PowerShell **Parser** checks on the Defender/M365 helper scripts under `soc-automation/powershell/`
- YAML parse of `.github/workflows/*.yml` and `.github/dependabot.yml`

### What this does *not* claim
- No live Splunk / Defender / Falcon / Entra tenant runs against employer or customer data
- No fake CVEs, no invented production incidents, no exploit kits

---

## Lab evidence still to attach

Redacted screenshots from **my own** lab / vendor sandboxes when I have them.
Blank checkboxes on purpose — nothing fabricated.

- [ ] Splunk search UI — phishing→auth or DNS-beacon style SPL (redact indexes / org)
- [ ] Microsoft Defender / Advanced Hunting — KQL result grid (redact device / UPN)
- [ ] Azure portal — storage / identity control from the DEMO Terraform baseline (redact subscription IDs)
- [ ] CrowdStrike Falcon console — isolate / detection detail from a **lab** host only
- [ ] GitHub Actions run page — green `ci-portfolio` + `security-gates` on `main`
- [ ] Checkov / Trivy job logs excerpt (no secrets)

When attaching: strip tickets, employee IDs, real IOCs, and customer names. Prefer
`[LAB]` captions over marketing screenshots.

---

## How to read DEMO labels

| What you see | What it means |
|--------------|---------------|
| `[DEMO]` hosts, users, domains, hashes, ticket IDs | **Synthetic entities** for narrative and hiring review |
| Playbooks, SPL/KQL, Terraform, pytest, Actions | **Real methods** I wrote, structured, and CI-tested in this repo |
| `[TEMPLATE]` | Fill-in for authorized future work — not a completed engagement |
| `[LAB]` / `[READ-ONLY]` | Safe for controlled environments; prefer non-mutating helpers |

**Short version:** the story data is fake; the craft is not. If a write-up says
DEMO, treat names and telemetry as placeholders and judge the process, detections,
and remediations instead.

See also [LAB-ETHICS.md](./LAB-ETHICS.md) for the full authorized-use rules.
