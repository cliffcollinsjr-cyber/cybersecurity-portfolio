# Cybersecurity Portfolio — Cliff Collins Jr

Hiring-ready portfolio demonstrating **security engineering**, **SOC/IR**, **cloud security**, **EDR/SIEM**, **firewall operations**, **SOAR automation**, and **application security** skills.

> All content is **lab / DEMO / template** material. See [LAB-ETHICS.md](./LAB-ETHICS.md). No live production data. No offensive exploit code.

## Skill map

| Domain / skill | Folder | Evidence (artifacts) |
|----------------|--------|----------------------|
| Threat hunting (hypothesis-driven) | [`incident-response-siem/hunt-reports/`](./incident-response-siem/hunt-reports/) + [`edr-microsoft-defender/hunt-reports/`](./edr-microsoft-defender/hunt-reports/) | DEMO hunt reports: DNS beaconing (Splunk) + encoded PowerShell (Defender KQL) |
| Incident response & SIEM (Splunk + CrowdStrike) | [`incident-response-siem/`](./incident-response-siem/) | Phishing/malware/host playbooks; SPL hunt queries; **DEMO threat hunt report**; Falcon isolate/RTR/IOC runbooks; incident timeline + case notes |
| Authorized pentesting process & reporting | [`pentesting/`](./pentesting/) | Methodology, RoE/scoping templates, professional report template, lab notes structure, hardening recommendations (**no exploits**) |
| SOC automation (Python, Go, PowerShell) | [`soc-automation/`](./soc-automation/) | Python alert enrichment + tests; Go CLI notifier; Defender/M365 helper scripts; Mermaid architecture |
| Microsoft Defender / EDR hunting | [`edr-microsoft-defender/`](./edr-microsoft-defender/) | KQL advanced hunting; **DEMO threat hunt report**; response playbooks; custom detection ideas + investigation checklist |
| Palo Alto NGFW operations | [`firewall-palo-alto-ngfw/`](./firewall-palo-alto-ngfw/) | Change-mgmt runbook; zone/App-ID design; backup/upgrade checklists; troubleshooting; policy-as-code YAML |
| Multi-cloud security baselines | [`cloud-security/`](./cloud-security/) | Terraform AWS/Azure/GCP baselines; CIS checklists; read-only review helpers; landing-zone notes |
| Splunk SOAR playbooks & integration | [`splunk-soar/`](./splunk-soar/) | Phishing/malware/containment playbook designs; safe Python stubs; SOAR↔Splunk↔ticketing runbook |
| Application security / Secure SDLC | [`application-security/`](./application-security/) | Secure SDLC checklist; GitHub Actions SAST/deps gates; STRIDE worksheet; OWASP review notes |

## Quick start

```bash
cd cybersecurity-portfolio
make help          # available targets
make test-python   # run Python enrichment tests (creates venv if needed)
make build-go      # build Go notifier CLI
make lint          # lightweight checks
```

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
├── Makefile
├── .gitignore
├── scripts/
├── incident-response-siem/
├── pentesting/
├── soc-automation/
├── edr-microsoft-defender/
├── firewall-palo-alto-ngfw/
├── cloud-security/
├── splunk-soar/
└── application-security/
```

## Attribution

**Cliff Collins Jr** — cybersecurity portfolio for SOC analyst / security engineer / cloud security roles.
