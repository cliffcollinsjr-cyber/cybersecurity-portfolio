# Lab Ethics & Authorized Use

**Owner:** Cliff Collins Jr  
**Purpose:** Hiring portfolio demonstrating cybersecurity engineering skills using **authorized lab, demo, and sample data only**.

## Non-negotiable rules

1. **Authorized environments only** — All techniques, queries, scripts, and playbooks in this repository are intended for systems you own, operate under written authorization, or use in sanctioned training labs (e.g., vendor sandboxes, CTF platforms with explicit rules, employer-provided ranges).
2. **Demo / sample data only** — Every incident timeline, IOC list, alert sample, and metric in this repo is **fictional or anonymized DEMO data**. Nothing here represents live production telemetry, real customer incidents, or real credentials.
3. **No offensive weaponization** — This portfolio intentionally excludes exploit code, weaponized payloads, credential-dumping tooling, and attack step-by-step instructions against systems. Pentesting materials cover **methodology, scoping, reporting, and remediation** only.
4. **Least privilege & auditability** — Automation and scripts are designed as read-heavy triage helpers with documented permission requirements. Destructive or containment actions are described as high-level runbook steps requiring human approval gates.
5. **Responsible disclosure mindset** — Findings discovered in authorized assessments should be reported through agreed channels with clear severity, evidence, and remediations — never shared publicly without permission.

## Labeling convention

| Label | Meaning |
|-------|---------|
| `[DEMO]` | Fictional sample data for illustration |
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
