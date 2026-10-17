# Detection-as-Code (lite)

**Skills proven:** A Sigma rule tested by running its logic. pySigma converts it to Splunk SPL (sysmon pipeline), and the suite evaluates the rule, the generated SPL and the Defender KQL twin against labelled Sysmon-style fixtures (malicious variants and benign near misses), all without a live SIEM.

## Open first

| Artifact | Path |
|----------|------|
| Sigma rule (source of truth) | [`sigma/proc_creation_win_powershell_encoded_command.yml`](./sigma/proc_creation_win_powershell_encoded_command.yml) |
| ADS (Palantir format) | [`sigma/proc_creation_win_powershell_encoded_command.ads.md`](./sigma/proc_creation_win_powershell_encoded_command.ads.md) |
| Generated SPL snapshot | [`sigma/expected/`](./sigma/expected/) |
| Splunk-style YAML (superseded; carries generated SPL) | [`detections/splunk_encoded_powershell.yml`](./detections/splunk_encoded_powershell.yml) |
| Defender / KQL detection YAML | [`detections/defender_encoded_powershell.yml`](./detections/defender_encoded_powershell.yml) |
| LSASS access rule (T1003.001) + ADS | [`sigma/proc_access_win_lsass_memory_access.yml`](./sigma/proc_access_win_lsass_memory_access.yml), [`sigma/proc_access_win_lsass_memory_access.ads.md`](./sigma/proc_access_win_lsass_memory_access.ads.md), KQL twin [`../edr-microsoft-defender/kql/rare_lsass_access.kql`](../edr-microsoft-defender/kql/rare_lsass_access.kql), tests [`tests/test_sigma_lsass.py`](./tests/test_sigma_lsass.py) |
| Sample events fixture | [`fixtures/sample_events.json`](./fixtures/sample_events.json) |
| Tests | [`tests/test_sigma_rules.py`](./tests/test_sigma_rules.py), [`tests/test_detections.py`](./tests/test_detections.py) |
| Evaluators (Sigma / narrow SPL) | [`src/sigma_eval.py`](./src/sigma_eval.py), [`src/spl_eval.py`](./src/spl_eval.py) |

## Run tests

```bash
# from repo root (deps: requirements.txt incl. pySigma + splunk backend + sysmon pipeline)
make test-dac   # or: bash scripts/test_dac.sh

# also pulled in by (CI)
make test-python

# regenerate the SPL snapshot after an intended rule change (needs sigma-cli)
sigma check sigma/
sigma convert -t splunk -p sysmon sigma/proc_creation_win_powershell_encoded_command.yml
```

All content is **`[DEMO]`**. Related KQL: [`../edr-microsoft-defender/kql/suspicious_powershell.kql`](../edr-microsoft-defender/kql/suspicious_powershell.kql). Ethics: [`../LAB-ETHICS.md`](../LAB-ETHICS.md).
