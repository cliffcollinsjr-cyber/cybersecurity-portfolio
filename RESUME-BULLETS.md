# Resume / LinkedIn bullets — lab & portfolio scoped

**Cliff Collins Jr** — paste-ready lines. Every bullet is scoped to **this**
portfolio / owned lab work (synthetic DEMO data where noted). Do not imply
production tenant access or employer incidents that did not happen.

Source map: root [README.md](./README.md) skill table · validation log:
[PERSONAL-LAB.md](./PERSONAL-LAB.md) · ethics: [LAB-ETHICS.md](./LAB-ETHICS.md).

---

1. Built and published a multi-domain cybersecurity portfolio
   (`cliffcollinsjr-cyber/cybersecurity-portfolio`) covering IR/SIEM, EDR hunting,
   AppSec, multi-cloud IaC, detection-as-code, and SOC automation — with clear
   `[DEMO]` labeling for synthetic entities.

2. Implemented GitHub Actions **`ci-portfolio`** and **`security-gates`** (lint,
   Python tests, Go build, Terraform fmt/validate, Checkov, Trivy, pip-audit,
   dependency-review) and kept both workflows green on `main`.

3. Authored Terraform security baselines for **AWS, Azure, and GCP**; validated
   with `terraform fmt` / `init -backend=false` / `validate` and Checkov (documented
   skips only — no silent soft-fails on real misconfigs).

4. Designed detection-as-code samples (Splunk-style + Defender/KQL YAML) with
   fixture-driven **pytest** checks wired into `make test-python` / `make test-dac`.

5. Built a Python SOC **alert-enrichment** helper with unit tests and a small
   **Go** notifier CLI (`make build-go`) to show triage-oriented automation without
   destructive defaults.

6. Wrote hypothesis-driven **threat hunt** reports (DEMO): DNS beaconing in Splunk
   SPL and encoded PowerShell hunts in Microsoft Defender KQL, including follow-up
   detection ideas.

7. Documented an end-to-end **IR case** (DEMO): phishing click → identity abuse →
   host compromise, with containment/eradication/recovery and links into playbooks,
   Falcon isolate/RTR/IOC runbooks, and SOAR triage design.

8. Produced an AppSec **finding write-up** (DEMO) for IDOR/BOLA on an export API
   (CWE-639), with high-level reproduction, remediations, and verification steps —
   no exploit payloads.

9. Packaged Microsoft Defender / M365 **PowerShell** analyst helpers as read-oriented
   templates with documented Graph permissions, plus Parser validation in the lab
   workbook checklist.

10. Captured Palo Alto NGFW **ops** artifacts: change-management runbook, zone/App-ID
    least-privilege notes, backup/upgrade checklists, and policy-as-code YAML samples.

11. Added IaC/CI hardening guidance: OIDC deploy patterns (placeholder trust policies),
    CODEOWNERS, Dependabot, pipeline + Terraform repo hardening checklists — no
    long-lived cloud secrets in Actions.

12. Authored security-research **case studies** (DEMO) on Entra illicit consent and
    multi-cloud toxic combinations, focused on misconfiguration / feature abuse in
    owned-lab framing — not third-party exploitation.
