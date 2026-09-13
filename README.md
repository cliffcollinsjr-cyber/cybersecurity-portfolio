# Cybersecurity Portfolio — Cliff Collins Jr

[![ci-portfolio](https://github.com/cliffcollinsjr-cyber/cybersecurity-portfolio/actions/workflows/ci-portfolio.yml/badge.svg)](https://github.com/cliffcollinsjr-cyber/cybersecurity-portfolio/actions/workflows/ci-portfolio.yml)
[![security-gates](https://github.com/cliffcollinsjr-cyber/cybersecurity-portfolio/actions/workflows/security-gates.yml/badge.svg)](https://github.com/cliffcollinsjr-cyber/cybersecurity-portfolio/actions/workflows/security-gates.yml)

## About

I'm Cliff Collins Jr. This is the security work I'd walk someone through in an interview — hunts, IR writeups, AppSec findings, cloud/IaC controls, and a bit of automation you can run yourself. I'm looking at security engineering, SOC/IR, AppSec, and cloud or research-adjacent roles.

Everything here is lab / `[DEMO]` material, not production data or exploit kits. Ground rules: [LAB-ETHICS.md](./LAB-ETHICS.md).

## Skill map

| Domain / skill | Folder | Evidence (artifacts) |
|----------------|--------|----------------------|
| Security research (identity + cloud paths) | [`security-research/`](./security-research/) | DEMO case studies: Entra illicit consent; multi-cloud toxic combination (Wiz-style) |
| Threat hunting (hypothesis-driven) | [`incident-response-siem/hunt-reports/`](./incident-response-siem/hunt-reports/) + [`edr-microsoft-defender/hunt-reports/`](./edr-microsoft-defender/hunt-reports/) | DEMO hunt reports: DNS beaconing (Splunk) + encoded PowerShell (Defender KQL) |
| Incident response & SIEM (Splunk + CrowdStrike) | [`incident-response-siem/`](./incident-response-siem/) | Phishing/malware/host playbooks; SPL hunts; **DEMO IR case** (phishing→host); **DEMO threat hunt report**; Falcon isolate/RTR/IOC runbooks |
| Authorized pentesting process & reporting | [`pentesting/`](./pentesting/) | Methodology, RoE/scoping templates, professional report template, lab notes structure, hardening recommendations (**no exploits**) |
| SOC automation (Python, Go, PowerShell) | [`soc-automation/`](./soc-automation/) | Python alert enrichment + tests; Go CLI notifier; Defender/M365 helper scripts; Mermaid architecture |
| Detection-as-code (lite) | [`detection-as-code/`](./detection-as-code/) | Splunk-style + Defender/KQL detection YAML; sample event fixture; pytest keyword/condition checks (`make test-dac`) |
| Microsoft Defender / EDR hunting | [`edr-microsoft-defender/`](./edr-microsoft-defender/) | KQL advanced hunting; **DEMO threat hunt report**; response playbooks; custom detection ideas + investigation checklist |
| Palo Alto NGFW operations | [`firewall-palo-alto-ngfw/`](./firewall-palo-alto-ngfw/) | Change-mgmt runbook; zone/App-ID design; backup/upgrade checklists; troubleshooting; policy-as-code YAML |
| Multi-cloud security baselines | [`cloud-security/`](./cloud-security/) | Terraform AWS/Azure/GCP baselines; CIS checklists; read-only review helpers; landing-zone notes |
| IaC + CI/CD security | [`iac-cicd-security/`](./iac-cicd-security/) | Live GitHub Actions gates (fmt/validate/Checkov/Trivy); OIDC deploy patterns; pipeline + Terraform repo hardening; CODEOWNERS; Dependabot |
| Splunk SOAR playbooks & integration | [`splunk-soar/`](./splunk-soar/) | Phishing/malware/containment playbook designs; safe Python stubs; SOAR↔Splunk↔ticketing runbook |
| Application security / Secure SDLC | [`application-security/`](./application-security/) | Secure SDLC checklist; GitHub Actions SAST/deps **template**; STRIDE worksheet; OWASP review notes; **DEMO finding** (IDOR on export API) |

## Quick start

```bash
cd cybersecurity-portfolio
make help          # available targets
make test-python   # Python enrichment + detection-as-code tests
make test-dac      # detection-as-code pytest only
make build-go      # build Go notifier CLI
make lint          # lightweight checks
```

Live CI (no secrets): [`.github/workflows/security-gates.yml`](./.github/workflows/security-gates.yml) and [`.github/workflows/ci-portfolio.yml`](./.github/workflows/ci-portfolio.yml).

## Design principles

- **Defend & detect first** — detections, playbooks, remediations, least privilege.
- **Human-in-the-loop** — containment and high-impact actions documented as approval-gated steps.
- **Evidence over buzzwords** — runnable tests, real SPL/KQL patterns, IaC examples, report templates.
- **Hiring-manager readable** — each domain README states *what skill it proves* and *what to open first*.

## Repository layout

```
cybersecurity-portfolio/
├── README.md                 # this file
├── LAB-ETHICS.md
├── BUILD_SUMMARY.md
├── CODEOWNERS                # DEMO — @cliffcollinsjr-cyber
├── Makefile
├── .gitignore
├── .checkov.yml
├── .trivyignore
├── .github/workflows/        # live security-gates + ci-portfolio
├── scripts/
├── security-research/
├── incident-response-siem/   # includes cases/ DEMO IR deep-dive
├── pentesting/
├── soc-automation/
├── detection-as-code/        # YAML detections + fixture tests
├── edr-microsoft-defender/
├── firewall-palo-alto-ngfw/
├── cloud-security/
├── iac-cicd-security/
├── splunk-soar/
└── application-security/     # includes findings/ DEMO write-up
```

## Attribution

**Cliff Collins Jr** — this portfolio backs conversations for security engineering, SOC/IR, AppSec, and cloud / research-adjacent roles. Lab and DEMO evidence only.
