# Python Alert Enrichment / Triage Helper

**Classification:** [DEMO] — uses mock APIs by default  
**Skill:** SOC automation, enrichment pipelines, testable Python

## What it does

Given a JSON alert, enriches with:

- Mock threat-intel reputation for IPs/domains/hashes
- Mock CMDB asset ownership / criticality
- Simple triage recommendation (escalate / monitor / close-as-benign)

## Run tests

```bash
# from repo root
make test-python

# or locally
cd soc-automation/python-alert-enrichment
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

## Demo CLI

```bash
python -m src.enrich --alert examples/demo_alert.json
```

Permissions: none required (offline mocks). In production, document API scopes for TI/CMDB only — no destructive actions.
