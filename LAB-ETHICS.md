# Lab Ethics & Authorized Use

**Owner:** Cliff Collins Jr  
**Purpose:** Owned lab workbook / hiring portfolio. Engineering practices here are
intentional portfolio work; incident entities and telemetry labeled `[DEMO]` are
**synthetic**.

**Quick read:** [PERSONAL-LAB.md](./PERSONAL-LAB.md) (what was actually validated) ·
[RESUME-BULLETS.md](./RESUME-BULLETS.md) (paste-ready, lab-scoped bullets).

## Clarification: DEMO vs. the craft

| | |
|--|--|
| **`[DEMO]`** | Synthetic data and entities (hosts, users, domains, hashes, timelines, ticket IDs). Not production telemetry, not real employer/customer incidents, not fake CVEs. |
| **Engineering practices** | Playbooks, SPL/KQL, Terraform baselines, detection YAML + tests, SOAR designs, CI gates, AppSec/IR write-up *structure* — intentional work by Cliff building and validating this repo. |

Judge process and remediations; treat DEMO names as placeholders.

## Non-negotiable rules

1. **Authorized environments only** — Techniques, queries, scripts, and playbooks are intended for systems you own, operate under written authorization, or use in sanctioned training labs (vendor sandboxes, CTF platforms with explicit rules, employer-provided ranges).
2. **Demo / sample data only** — Every incident timeline, IOC list, alert sample, and metric in this repo is **fictional or anonymized DEMO data**. Nothing here represents live production telemetry, real customer incidents, or real credentials.
3. **No offensive weaponization** — Excludes exploit code, weaponized payloads, credential-dumping tooling, and attack step-by-step instructions against systems. Pentesting materials cover **methodology, scoping, reporting, and remediation** only.
4. **Least privilege & auditability** — Automation and scripts are read-heavy triage helpers with documented permission requirements. Destructive or containment actions are high-level runbook steps with human approval gates.
5. **Responsible disclosure mindset** — Findings from authorized assessments go through agreed channels with severity, evidence, and remediations — never shared publicly without permission.

## Labeling convention

| Label | Meaning |
|-------|---------|
| `[DEMO]` | Synthetic sample data / entities for illustration |
| `[TEMPLATE]` | Fill-in document for real authorized work |
| `[LAB]` | Safe for controlled lab use only |
| `[READ-ONLY]` | Query/script intended not to mutate state |

## If you fork this repo

- Strip any organization-specific data before sharing.
- Do not paste real IOCs, employee identifiers, or ticket IDs into public forks.
- Re-validate all cloud/IaC examples against your org’s compliance requirements before use.

## Contact

Portfolio attribution: **Cliff Collins Jr** — cybersecurity / SOC / cloud security candidate materials.

## Security research case studies

DEMO research notes under `security-research/` describe **misconfigurations and abuse of intended features** in owned lab environments. They do not include exploit code, phishing kits, or instructions for attacking third-party tenants.

## IaC / CI examples

OIDC trust policies, IAM roles, and Azure federated-credential snippets under `iac-cicd-security/` use **placeholder** account IDs, tenant IDs, subscription IDs, and repo names. They are not wired to a live cloud account. GitHub Actions in this repo run `terraform fmt` / `validate` / IaC scanners with **no cloud secrets** (`terraform init -backend=false`).

## AppSec findings & IR cases

Write-ups under `application-security/findings/` and `incident-response-siem/cases/` are **`[DEMO]`** narratives for hiring review. They describe classes of issues (e.g., missing object-level authorization) and IR process at a high level. They do **not** include exploit payloads, phishing kits, or instructions for attacking third-party systems.

## Detection-as-code samples

YAML detections and JSON fixtures under `detection-as-code/` use synthetic process command lines for unit tests only. They are not production correlation searches and must be tuned and authorized before any deployment.
