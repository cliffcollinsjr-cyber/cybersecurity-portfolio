#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REQUIRED=(
  incident-response-siem
  pentesting
  soc-automation
  edr-microsoft-defender
  firewall-palo-alto-ngfw
  cloud-security
  splunk-soar
  application-security
  security-research
  iac-cicd-security
  detection-as-code
  LAB-ETHICS.md
  README.md
)
missing=0
for item in "${REQUIRED[@]}"; do
  if [[ ! -e "$ROOT/$item" ]]; then
    echo "MISSING: $item"
    missing=1
  fi
done
if [[ "$missing" -ne 0 ]]; then
  exit 1
fi
echo "Structure OK: all required domains and root files present."
