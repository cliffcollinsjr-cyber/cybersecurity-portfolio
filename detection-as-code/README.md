# Detection-as-Code (lite)

**Skills proven:** Writing portable detection definitions (Splunk-style + Defender/KQL YAML), sample event fixtures, and a tiny pytest suite that asserts keyword/condition helpers — without needing a live SIEM.

## Open first

| Artifact | Path |
|----------|------|
| Splunk-style detection YAML | [`detections/splunk_encoded_powershell.yml`](./detections/splunk_encoded_powershell.yml) |
| Defender / KQL detection YAML | [`detections/defender_encoded_powershell.yml`](./detections/defender_encoded_powershell.yml) |
| Sample events fixture | [`fixtures/sample_events.json`](./fixtures/sample_events.json) |
| Tests | [`tests/test_detections.py`](./tests/test_detections.py) |

## Run tests

```bash
# from repo root
make test-dac

# also pulled in by
make test-python
```

All content is **`[DEMO]`**. Related KQL: [`../edr-microsoft-defender/kql/suspicious_powershell.kql`](../edr-microsoft-defender/kql/suspicious_powershell.kql). Ethics: [`../LAB-ETHICS.md`](../LAB-ETHICS.md).
