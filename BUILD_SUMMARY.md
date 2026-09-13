# Build Summary

**Portfolio:** `/workspace/cybersecurity-portfolio`  
**Owner attribution:** Cliff Collins Jr  
**Content class:** lab / DEMO / template only — see LAB-ETHICS.md

## Domains delivered (10/10)

1. `security-research/` — DEMO case studies (Entra illicit consent; multi-cloud toxic combination)
2. `incident-response-siem/` — Splunk + CrowdStrike IR (+ DEMO hunt reports)
3. `pentesting/` — lab-safe methodology & reporting (no exploits)
4. `soc-automation/` — Python + Go + PowerShell
5. `edr-microsoft-defender/` — KQL + playbooks + detections (+ DEMO hunt reports)
6. `firewall-palo-alto-ngfw/` — ops runbooks + policy-as-code
7. `cloud-security/` — Terraform AWS/Azure/GCP + CIS + scripts
8. `splunk-soar/` — playbook designs + custom function stubs
9. `application-security/` — SDLC, CI gates, STRIDE, OWASP
10. `iac-cicd-security/` — live GHA gates, OIDC patterns, pipeline/Terraform hardening

## Root files

- `README.md` — skill-map table
- `LAB-ETHICS.md`
- `CODEOWNERS` — DEMO `@cliffcollinsjr-cyber`
- `.gitignore`
- `.checkov.yml` / `.trivyignore`
- `Makefile`
- `scripts/`
- `.github/workflows/` — `security-gates.yml`, `ci-portfolio.yml`
- `.github/dependabot.yml`
- `BUILD_SUMMARY.md`

## Major files created

- `.github/workflows/security-gates.yml`
- `.github/workflows/ci-portfolio.yml`
- `.github/dependabot.yml`
- `.checkov.yml`
- `.trivyignore`
- `CODEOWNERS`
- `iac-cicd-security/README.md`
- `iac-cicd-security/oidc-cloud-deploy.md`
- `iac-cicd-security/terraform-repo-hardening.md`
- `iac-cicd-security/pipeline-hardening-checklist.md`
- `iac-cicd-security/examples/README.md`
- `iac-cicd-security/examples/github-oidc-aws-trust-policy.json`
- `iac-cicd-security/examples/azure-federated-identity-notes.md`
- `.gitignore`
- `LAB-ETHICS.md`
- `Makefile`
- `README.md`
- `application-security/README.md`
- `application-security/ci/README.md`
- `application-security/ci/github-actions-security.yml`
- `application-security/owasp-reviews/owasp-aligned-review-notes.md`
- `application-security/sdlc/secure-sdlc-checklist.md`
- `application-security/threat-modeling/stride-sample-webapp.md`
- `cloud-security/README.md`
- `cloud-security/architecture/landing-zone-notes.md`
- `cloud-security/cis-checklists/aws-cis-aligned.md`
- `cloud-security/cis-checklists/azure-cis-aligned.md`
- `cloud-security/cis-checklists/gcp-cis-aligned.md`
- `cloud-security/scripts/README.md`
- `cloud-security/scripts/aws_read_only_review.py`
- `cloud-security/scripts/sample_sg_export_DEMO.json`
- `cloud-security/terraform/aws/README.md`
- `cloud-security/terraform/aws/main.tf`
- `cloud-security/terraform/azure/README.md`
- `cloud-security/terraform/azure/main.tf`
- `cloud-security/terraform/gcp/README.md`
- `cloud-security/terraform/gcp/main.tf`
- `edr-microsoft-defender/README.md`
- `edr-microsoft-defender/hunt-reports/README.md`
- `edr-microsoft-defender/hunt-reports/DEMO-2026-04-encoded-powershell-hunt.md`
- `edr-microsoft-defender/detections/custom-detection-ideas.md`
- `edr-microsoft-defender/detections/investigation-checklist.md`
- `edr-microsoft-defender/kql/README.md`
- `edr-microsoft-defender/kql/impossible_travel_signin_join.kql`
- `edr-microsoft-defender/kql/rare_lsass_access.kql`
- `edr-microsoft-defender/kql/suspicious_powershell.kql`
- `edr-microsoft-defender/kql/usb_exfil_suspect.kql`
- `edr-microsoft-defender/playbooks/device-isolation.md`
- `edr-microsoft-defender/playbooks/identity-compromise.md`
- `edr-microsoft-defender/playbooks/malware-alert-triage.md`
- `firewall-palo-alto-ngfw/README.md`
- `firewall-palo-alto-ngfw/checklists/backup-restore.md`
- `firewall-palo-alto-ngfw/checklists/upgrade-checklist.md`
- `firewall-palo-alto-ngfw/policy-as-code/README.md`
- `firewall-palo-alto-ngfw/policy-as-code/sample-rules.yaml`
- `firewall-palo-alto-ngfw/policy-design/zone-appid-least-privilege.md`
- `firewall-palo-alto-ngfw/runbooks/change-management.md`
- `firewall-palo-alto-ngfw/runbooks/troubleshooting.md`
- `incident-response-siem/README.md`
- `incident-response-siem/hunt-reports/README.md`
- `incident-response-siem/hunt-reports/DEMO-2026-03-dns-beacon-hunt.md`
- `incident-response-siem/crowdstrike-runbooks/ioc-hunting.md`
- `incident-response-siem/crowdstrike-runbooks/isolate-host.md`
- `incident-response-siem/crowdstrike-runbooks/rtr-high-level.md`
- `incident-response-siem/playbooks/compromised-host.md`
- `incident-response-siem/playbooks/malware-response.md`
- `incident-response-siem/playbooks/phishing-response.md`
- `incident-response-siem/splunk-queries/README.md`
- `incident-response-siem/splunk-queries/crowdstrike_detection_enrich.md`
- `incident-response-siem/splunk-queries/dns_beacon_suspect.spl`
- `incident-response-siem/splunk-queries/failed_then_success_auth.spl`
- `incident-response-siem/splunk-queries/phishing_click_to_auth.spl`
- `incident-response-siem/splunk-queries/rare_process_parent_child.spl`
- `incident-response-siem/templates/case-notes-template.md`
- `incident-response-siem/templates/incident-timeline-DEMO.md`
- `pentesting/README.md`
- `pentesting/hardening/linux-baseline-recommendations.md`
- `pentesting/hardening/web-app-hardening.md`
- `pentesting/hardening/windows-workstation-hardening.md`
- `pentesting/lab-notes/README.md`
- `pentesting/lab-notes/YYYY-MM-DD-sample-lab/00-scope.md`
- `pentesting/methodology/methodology.md`
- `pentesting/methodology/scoping-checklist.md`
- `pentesting/templates/pentest-report-template.md`
- `pentesting/templates/rules-of-engagement.md`
- `security-research/README.md`
- `security-research/case-studies/DEMO-entra-illicit-consent-grant.md`
- `security-research/case-studies/DEMO-multicloud-toxic-combination.md`
- `scripts/build_go.sh`
- `scripts/check_structure.sh`
- `scripts/lint.sh`
- `scripts/test_python.sh`
- `soc-automation/README.md`
- `soc-automation/go-notifier/README.md`
- `soc-automation/go-notifier/go.mod`
- `soc-automation/go-notifier/main.go`
- `soc-automation/powershell/Export-DemoDeviceHealth.ps1`
- `soc-automation/powershell/Get-DemoDefenderAlerts.ps1`
- `soc-automation/powershell/Get-DemoRiskySignIns.ps1`
- `soc-automation/powershell/README.md`
- `soc-automation/python-alert-enrichment/README.md`
- `soc-automation/python-alert-enrichment/conftest.py`
- `soc-automation/python-alert-enrichment/examples/demo_alert.json`
- `soc-automation/python-alert-enrichment/requirements.txt`
- `soc-automation/python-alert-enrichment/src/__init__.py`
- `soc-automation/python-alert-enrichment/src/__main__.py`
- `soc-automation/python-alert-enrichment/src/enrich.py`
- `soc-automation/python-alert-enrichment/src/mocks.py`
- `soc-automation/python-alert-enrichment/tests/test_enrich.py`
- `splunk-soar/README.md`
- `splunk-soar/custom-functions/README.md`
- `splunk-soar/custom-functions/enrich_iocs.py`
- `splunk-soar/playbooks/malware_enrichment.yaml`
- `splunk-soar/playbooks/phishing_triage.yaml`
- `splunk-soar/playbooks/user_containment.yaml`
- `splunk-soar/runbooks/soar-splunk-ticketing.md`

**Total source/docs files (excl. venv/binary):** ~135

## Verification

- `make check-structure` — required domains include `security-research` and `iac-cicd-security`
- `make test-python` / `scripts/test_python.sh` — pytest (6 passed)
- `make build-go` / `scripts/build_go.sh` — `go build` succeeds
- `make lint` / `scripts/lint.sh` — structure/syntax/gofmt guards
- Terraform `fmt -check` + `init -backend=false` + `validate` for aws/azure/gcp
- Checkov on `cloud-security/terraform` — 81 passed, 0 failed, 2 inline skips (`CKV_GCP_62`, `CKV_AZURE_33`); see `.checkov.yml`
- YAML parse of `.github/workflows/*.yml` and `.github/dependabot.yml`

