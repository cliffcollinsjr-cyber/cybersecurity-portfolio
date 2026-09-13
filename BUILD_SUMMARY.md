# Build Summary

**Portfolio:** `/workspace/cybersecurity-portfolio`  
**Owner attribution:** Cliff Collins Jr  
**Content class:** lab / DEMO / template only — see LAB-ETHICS.md

## Domains delivered (8/8)

1. `incident-response-siem/` — Splunk + CrowdStrike IR
2. `pentesting/` — lab-safe methodology & reporting (no exploits)
3. `soc-automation/` — Python + Go + PowerShell
4. `edr-microsoft-defender/` — KQL + playbooks + detections
5. `firewall-palo-alto-ngfw/` — ops runbooks + policy-as-code
6. `cloud-security/` — Terraform AWS/Azure/GCP + CIS + scripts
7. `splunk-soar/` — playbook designs + custom function stubs
8. `application-security/` — SDLC, CI gates, STRIDE, OWASP

## Root files

- `README.md` — skill-map table
- `LAB-ETHICS.md`
- `.gitignore`
- `Makefile`
- `scripts/`
- `BUILD_SUMMARY.md`

## Major files created

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

**Total source/docs files (excl. venv/binary):** 96

## Verification

- `make test-python` / `scripts/test_python.sh` — pytest (6 passed)
- `make build-go` / `scripts/build_go.sh` — `go build` succeeds
- `make lint` / `scripts/lint.sh` — structure/syntax/gofmt guards

