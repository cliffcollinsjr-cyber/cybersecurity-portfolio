"""Unit tests for detection-as-code lite — [DEMO] fixtures only.

The keyword checks here are legacy smoke tests for the original four fixtures.
Real rule logic is executed in tests/test_sigma_rules.py.
"""

from pathlib import Path

import pytest

# Allow `python -m pytest` from detection-as-code/ or repo via Makefile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.helpers import event_matches_keywords, load_detection, load_fixture

REQUIRED_FIELDS = {"id", "title", "platform", "severity", "condition_keywords"}


def test_splunk_detection_loads():
    det = load_detection("splunk_encoded_powershell.yml")
    assert REQUIRED_FIELDS <= set(det)
    assert det["platform"] == "splunk"
    assert det["id"].startswith("DET-")
    assert "-enc" in " ".join(det["condition_keywords"]).lower() or any(
        "enc" in k.lower() for k in det["condition_keywords"]
    )
    # Sysmon field name, not the old fixture-only `command_line`
    assert "CommandLine" in det["search"]
    assert "command_line" not in det["search"]


def test_defender_detection_loads():
    det = load_detection("defender_encoded_powershell.yml")
    assert REQUIRED_FIELDS <= set(det)
    assert det["platform"] == "microsoft_defender"
    assert "kql" in det
    assert "DeviceProcessEvents" in det["kql"]


def test_fixture_labeled_demo():
    fix = load_fixture()
    assert "[DEMO]" in fix.get("label", "")
    assert len(fix["events"]) >= 3


@pytest.mark.parametrize("det_name", [
    "splunk_encoded_powershell.yml",
    "defender_encoded_powershell.yml",
])
def test_fixture_events_match_keywords(det_name):
    det = load_detection(det_name)
    keywords = det["condition_keywords"]
    legacy = [e for e in load_fixture()["events"] if e.get("legacy")]
    assert len(legacy) == 4
    for event in legacy:
        expected = event["label"] == "malicious"
        matched = event_matches_keywords(event["CommandLine"], keywords)
        assert matched is expected, (
            f"{event['event_id']} expected {event['label']} got matched={matched} for {det_name}"
        )


def test_benign_powershell_file_does_not_match():
    det = load_detection("splunk_encoded_powershell.yml")
    assert not event_matches_keywords(
        "powershell.exe -NoProfile -File C:\\Scripts\\backup.ps1",
        det["condition_keywords"],
    )
