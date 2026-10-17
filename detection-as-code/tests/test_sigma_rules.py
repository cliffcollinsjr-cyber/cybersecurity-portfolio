"""Sigma rule tests — [DEMO] fixtures only.

These tests execute real detection logic instead of keyword lists:
  * pySigma parses and validates the rule (same validators `sigma check` uses)
  * pySigma's Splunk backend + sysmon pipeline convert it (same as
    `sigma convert -t splunk -p sysmon`); output must match a reviewed snapshot
  * the Sigma rule (raw and after the sysmon pipeline) is evaluated against every
    fixture with src/sigma_eval.py
  * the generated SPL is evaluated with the narrow src/spl_eval.py interpreter
    (not Splunk; see that module's docstring)
  * the Defender KQL rule shares the Sigma regex and its predicates are evaluated
    with a hand translation (not Kusto)
"""

from __future__ import annotations

import ntpath
import re
import sys
import uuid
from datetime import date
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sigma.backends.splunk import SplunkBackend  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.pipelines.sysmon import sysmon_pipeline  # noqa: E402
from sigma.validation import SigmaValidator  # noqa: E402
from sigma.validators.core import validators  # noqa: E402

from src.helpers import SIGMA_DIR, load_detection, load_fixture  # noqa: E402
from src.sigma_eval import load_rule, rule_fields, rule_matches  # noqa: E402
from src.spl_eval import compile_spl, split_query  # noqa: E402

RULE_PATH = SIGMA_DIR / "proc_creation_win_powershell_encoded_command.yml"
SPL_SNAPSHOT = SIGMA_DIR / "expected" / "proc_creation_win_powershell_encoded_command.splunk_sysmon.spl"
RULE_ID = "bb2386f8-201e-4542-9f98-16d53b45f2e8"
DEFENDER_ID = "DET-DEFENDER-DEMO-001"

EVENTS = load_fixture()["events"]
EVENT_IDS = [e["event_id"] for e in EVENTS]


def _raw_rule_yaml() -> dict:
    return yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))


def _sigma_regex() -> str:
    return _raw_rule_yaml()["detection"]["selection_cli"]["CommandLine|re"]


def _expected_fire(event: dict, rule_id: str) -> bool:
    return rule_id in event["expected_rules"]


def _convert_splunk() -> str:
    collection = SigmaCollection.from_yaml(RULE_PATH.read_text(encoding="utf-8"))
    queries = SplunkBackend(sysmon_pipeline()).convert(collection)
    assert len(queries) == 1, queries
    return queries[0]


# --- rule metadata / validity -------------------------------------------------

def test_rule_metadata_complete():
    r = _raw_rule_yaml()
    for key in ("title", "id", "status", "description", "author", "date", "level",
                "logsource", "detection", "tags", "falsepositives", "references"):
        assert r.get(key), f"missing {key}"
    assert str(uuid.UUID(r["id"])) == r["id"] == RULE_ID
    assert r["status"] == "experimental"
    assert r["logsource"] == {"product": "windows", "category": "process_creation"}
    assert isinstance(r["date"], (date, str))
    assert "condition" in r["detection"]
    assert {"attack.execution", "attack.t1059.001", "attack.t1027.010"} <= set(r["tags"])


def test_rule_parses_and_passes_sigma_validators():
    collection = SigmaCollection.from_yaml(RULE_PATH.read_text(encoding="utf-8"))
    errors = [e for rule in collection.rules for e in rule.errors]
    assert not errors, errors
    # Same validator set `sigma check` runs by default.
    issues = SigmaValidator(validators.values()).validate_rules(collection)
    assert not issues, [str(i) for i in issues]


def test_regex_compiles_and_is_case_insensitive():
    rx = re.compile(_sigma_regex())
    assert rx.flags & re.IGNORECASE


# --- conversion -----------------------------------------------------------------

def test_splunk_conversion_matches_snapshot():
    spl = _convert_splunk()
    assert spl == SPL_SNAPSHOT.read_text(encoding="utf-8").rstrip("\n"), (
        "Generated SPL changed. If intended, regenerate sigma/expected/*.spl "
        "and detections/splunk_encoded_powershell.yml.\n" + spl
    )


def test_spl_shape_and_regex_roundtrip():
    spl = _convert_splunk()
    base, cmds = split_query(spl)
    assert "EventID=1" in base  # sysmon pipeline mapped process_creation
    assert cmds == [("CommandLine", "=", _sigma_regex())], cmds


def test_superseded_splunk_yaml_carries_generated_spl():
    det = load_detection("splunk_encoded_powershell.yml")
    assert det["status"] == "deprecated"
    assert det["superseded_by"] == RULE_ID
    assert det["search"].rstrip("\n") == _convert_splunk()


# --- fixtures -----------------------------------------------------------------

def test_fixture_schema():
    labels = {e["label"] for e in EVENTS}
    assert labels == {"malicious", "benign"}
    for e in EVENTS:
        assert "command_line" not in e, "use Sysmon field names (CommandLine)"
        for f in ("event_id", "EventID", "Image", "OriginalFileName", "CommandLine",
                  "ParentImage", "expected_rules", "description"):
            assert f in e, f"{e.get('event_id')} missing {f}"
        if e["label"] == "malicious":
            assert e["expected_rules"], e["event_id"]
        else:
            assert e["expected_rules"] == [], e["event_id"]
    assert len(EVENT_IDS) == len(set(EVENT_IDS))


def test_rule_fields_exist_in_fixtures():
    """Guards against the old CommandLine vs command_line mismatch."""
    for pipeline in (None, sysmon_pipeline()):
        fields = rule_fields(load_rule(RULE_PATH, pipeline))
        for e in EVENTS:
            assert fields <= set(e), (e["event_id"], fields - set(e))


# --- execution against fixtures ---------------------------------------------------

@pytest.fixture(scope="module")
def raw_rule():
    return load_rule(RULE_PATH)


@pytest.fixture(scope="module")
def sysmon_rule():
    return load_rule(RULE_PATH, sysmon_pipeline())


@pytest.fixture(scope="module")
def spl_matcher():
    return compile_spl(_convert_splunk())


@pytest.mark.parametrize("event", EVENTS, ids=EVENT_IDS)
def test_sigma_rule_on_fixture(event, raw_rule, sysmon_rule):
    expected = _expected_fire(event, RULE_ID)
    assert rule_matches(raw_rule, event) is expected, event["description"]
    assert rule_matches(sysmon_rule, event) is expected, event["description"]


@pytest.mark.parametrize("event", EVENTS, ids=EVENT_IDS)
def test_generated_spl_on_fixture(event, spl_matcher):
    assert spl_matcher(event) is _expected_fire(event, RULE_ID), event["description"]


def test_sigma_rule_requires_eventid_1_after_pipeline(sysmon_rule):
    mal = next(e for e in EVENTS if e["label"] == "malicious")
    assert rule_matches(sysmon_rule, mal)
    assert not rule_matches(sysmon_rule, {**mal, "EventID": 3})


# --- Defender KQL parity --------------------------------------------------------

_KQL_REGEX = re.compile(r'matches regex @"((?:[^"]|"")*)"')


def _kql_regex() -> str:
    det = load_detection("defender_encoded_powershell.yml")
    m = _KQL_REGEX.search(det["kql"])
    assert m, "KQL must use `matches regex @\"...\"`"
    return m.group(1).replace('""', '"')


def test_defender_kql_regex_identical_to_sigma():
    assert _kql_regex() == _sigma_regex()


@pytest.mark.parametrize("event", EVENTS, ids=EVENT_IDS)
def test_defender_kql_logic_on_fixture(event):
    """Hand translation of the KQL where-clauses (Python re stands in for RE2)."""
    to_mde = {
        "FileName": ntpath.basename(event["Image"]),
        "ProcessVersionInfoOriginalFileName": event["OriginalFileName"],
        "ProcessCommandLine": event["CommandLine"],
    }
    is_ps = (to_mde["FileName"].lower() in ("powershell.exe", "pwsh.exe")
             or to_mde["ProcessVersionInfoOriginalFileName"].lower() in ("powershell.exe", "pwsh.dll"))
    fired = is_ps and re.search(_kql_regex(), to_mde["ProcessCommandLine"]) is not None
    assert fired is _expected_fire(event, DEFENDER_ID), event["description"]
