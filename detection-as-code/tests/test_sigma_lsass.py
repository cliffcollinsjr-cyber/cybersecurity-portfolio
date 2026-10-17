"""LSASS memory-access Sigma rule tests — [DEMO] fixtures only.

Same approach as tests/test_sigma_rules.py:
  * pySigma parses/validates the rule (validators used by `sigma check`)
  * Splunk backend + sysmon pipeline conversion (= `sigma convert -t splunk -p sysmon`)
    must equal the reviewed snapshot in sigma/expected/
  * the rule (raw and after the sysmon pipeline) is evaluated on EVERY fixture
    (process-creation fixtures must not fire it)
  * the generated SPL runs through src/spl_eval.py (narrow interpreter, not Splunk)
  * the Defender KQL (edr-microsoft-defender/kql/rare_lsass_access.kql) is checked by a
    hand translation whose allowlists are parsed from the .kql file itself (not Kusto)
"""

from __future__ import annotations

import ast
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

from src.helpers import SIGMA_DIR, load_fixture  # noqa: E402
from src.sigma_eval import load_rule, rule_fields, rule_matches  # noqa: E402
from src.spl_eval import compile_spl  # noqa: E402

RULE_PATH = SIGMA_DIR / "proc_access_win_lsass_memory_access.yml"
SPL_SNAPSHOT = SIGMA_DIR / "expected" / "proc_access_win_lsass_memory_access.splunk_sysmon.spl"
KQL_PATH = ROOT.parent / "edr-microsoft-defender" / "kql" / "rare_lsass_access.kql"
RULE_ID = "d76f8bfa-378b-4735-8d64-6b08a570d754"
KQL_ID = "DET-DEFENDER-LSASS-001"

EVENTS = load_fixture()["events"]
EVENT_IDS = [e["event_id"] for e in EVENTS]
ACCESS_EVENTS = [e for e in EVENTS if e["EventID"] == 10]


def _raw() -> dict:
    return yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))


def _convert() -> str:
    queries = SplunkBackend(sysmon_pipeline()).convert(
        SigmaCollection.from_yaml(RULE_PATH.read_text(encoding="utf-8")))
    assert len(queries) == 1, queries
    return queries[0]


# --- metadata / validity ---------------------------------------------------------

def test_rule_metadata_complete():
    r = _raw()
    for key in ("title", "id", "status", "description", "author", "date", "level",
                "logsource", "detection", "tags", "falsepositives", "references"):
        assert r.get(key), f"missing {key}"
    assert str(uuid.UUID(r["id"])) == r["id"] == RULE_ID
    assert r["status"] == "experimental" and r["level"] == "high"
    assert r["author"] == "Cliff Collins Jr"
    assert isinstance(r["date"], (date, str))
    assert r["logsource"] == {"product": "windows", "category": "process_access"}
    assert {"attack.credential-access", "attack.t1003.001"} <= set(r["tags"])
    cond = r["detection"]["condition"]
    assert "selection_target" in cond and "not 1 of filter_*" in cond


def test_rule_passes_sigma_validators():
    collection = SigmaCollection.from_yaml(RULE_PATH.read_text(encoding="utf-8"))
    assert not [e for r in collection.rules for e in r.errors]
    issues = SigmaValidator(validators.values()).validate_rules(collection)
    assert not issues, [str(i) for i in issues]


def test_filters_are_path_scoped_not_filename_only():
    det = _raw()["detection"]
    for name, body in det.items():
        if not name.startswith("filter_"):
            continue
        paths = [v for k, vals in body.items() if k.startswith("SourceImage")
                 for v in ([vals] if isinstance(vals, str) else vals)]
        assert paths, name
        assert any(re.match(r"(?i)^[a-z]:\\", p) for p in paths), (name, paths)


@pytest.mark.parametrize("mask,has_read", [
    ("0x10", True), ("0x1010", True), ("0x1410", True), ("0x1438", True),
    ("0x143a", True), ("0x143A", True), ("0x1fffff", True), ("0x1f1fff", True),
    ("0x1f3fff", True), ("0x1f0fff", True),
    ("0x1000", False), ("0x1400", False), ("0x40", False), ("0x1fffef", False),
    ("0x2", False), ("0x100000", False),
])
def test_vm_read_regex_is_the_bitmask(mask, has_read):
    rx = _raw()["detection"]["selection_access"][0]["GrantedAccess|re"]
    assert (re.search(rx, mask) is not None) is has_read
    assert bool(int(mask, 16) & 0x10) is has_read


# --- conversion ------------------------------------------------------------------

def test_splunk_conversion_matches_snapshot():
    spl = _convert()
    assert spl == SPL_SNAPSHOT.read_text(encoding="utf-8").rstrip("\n"), spl


def test_spl_scoped_to_sysmon_eid10():
    assert _convert().startswith('EventID=10 TargetImage="*\\\\lsass.exe"')


# --- fixtures ----------------------------------------------------------------------

def test_access_fixture_schema():
    assert len(ACCESS_EVENTS) >= 12
    for e in ACCESS_EVENTS:
        for f in ("SourceImage", "TargetImage", "GrantedAccess", "CallTrace", "SourceUser",
                  "label", "expected_rules", "description"):
            assert f in e, (e["event_id"], f)
        assert (e["label"] == "malicious") is bool(e["expected_rules"]), e["event_id"]
    labels = {e["label"] for e in ACCESS_EVENTS}
    assert labels == {"malicious", "benign"}


def test_rule_fields_exist_in_access_fixtures():
    for pipeline in (None, sysmon_pipeline()):
        fields = rule_fields(load_rule(RULE_PATH, pipeline))
        for e in ACCESS_EVENTS:
            assert fields <= set(e), (e["event_id"], fields - set(e))


@pytest.fixture(scope="module")
def raw_rule():
    return load_rule(RULE_PATH)


@pytest.fixture(scope="module")
def sysmon_rule():
    return load_rule(RULE_PATH, sysmon_pipeline())


@pytest.fixture(scope="module")
def spl_matcher():
    return compile_spl(_convert())


@pytest.mark.parametrize("event", EVENTS, ids=EVENT_IDS)
def test_sigma_rule_on_fixture(event, raw_rule, sysmon_rule):
    expected = RULE_ID in event["expected_rules"]
    assert rule_matches(raw_rule, event) is expected, event["description"]
    assert rule_matches(sysmon_rule, event) is expected, event["description"]


@pytest.mark.parametrize("event", EVENTS, ids=EVENT_IDS)
def test_generated_spl_on_fixture(event, spl_matcher):
    assert spl_matcher(event) is (RULE_ID in event["expected_rules"]), event["description"]


def test_sysmon_rule_requires_eventid_10(sysmon_rule):
    mal = ACCESS_EVENTS[0]
    assert rule_matches(sysmon_rule, mal)
    assert not rule_matches(sysmon_rule, {**mal, "EventID": 1})


# --- Defender KQL --------------------------------------------------------------------

def _kql() -> str:
    return KQL_PATH.read_text(encoding="utf-8")


def _kql_let(name: str) -> str:
    m = re.search(rf"^let {name} = (.+?);", _kql(), re.M | re.S)
    assert m, f"let {name} missing"
    return m.group(1).strip()


def _kql_str(lit: str) -> str:
    assert lit.startswith('@"') and lit.endswith('"'), lit
    return lit[2:-1]


def _kql_model():
    paths = re.findall(r'@"([^"]*)"', _kql_let("AllowedSourcePaths"))
    return {
        "vm_read": ast.literal_eval(_kql_let("VmRead")),
        "dup_only": ast.literal_eval(_kql_let("DupHandleOnly")),
        "allowed": {p.lower() for p in paths},
        "svchost": _kql_str(_kql_let("SvchostPath")).lower(),
        "svchost_access": ast.literal_eval(_kql_let("SvchostAllowedAccess")),
        "defender_prefix": _kql_str(_kql_let("DefenderPlatformPrefix")).lower(),
        # Target filter read from the query body, so deleting it changes the outcome.
        "targets": [t.lower() for t in re.findall(r'^\| where FileName =~ "([^"]+)"', _kql(), re.M)],
    }


def test_kql_structure():
    k = _kql()
    assert "T1003.001" in k and "DET-DEFENDER-LSASS-001" in k and RULE_ID in k
    assert 'ActionType == "OpenProcessApiCall"' in k
    assert 'FileName =~ "lsass.exe"' in k
    assert "binary_and(DesiredAccess, VmRead) == VmRead" in k
    code = "\n".join(l for l in k.splitlines() if not l.lstrip().startswith("//"))
    assert "\\Temp\\" not in code, "bare \\Temp\\ trigger must stay removed"


def test_kql_allowlist_mirrors_sigma():
    det = _raw()["detection"]
    sigma_paths = {p.lower() for p in det["filter_main_windows"]["SourceImage"]}
    sigma_paths.add(det["filter_optional_vmtools"]["SourceImage"].lower())
    m = _kql_model()
    assert m["allowed"] == sigma_paths
    assert m["svchost"] == det["filter_main_svchost"]["SourceImage"].lower()
    assert m["svchost_access"] == int(det["filter_main_svchost"]["GrantedAccess"], 16)
    assert m["defender_prefix"] == det["filter_main_defender"]["SourceImage|startswith"].lower()


def _kql_fires(event: dict) -> bool:
    """Hand translation of the KQL where-clauses over the Sysmon->MDE field mapping."""
    if event["EventID"] != 10:  # only OpenProcessApiCall rows reach this query
        return False
    m = _kql_model()
    file_name = ntpath.basename(event["TargetImage"])
    access = int(event["GrantedAccess"], 16)
    src = event["SourceImage"].lower()
    if any(file_name.lower() != t for t in m["targets"]):
        return False
    if not ((access & m["vm_read"]) == m["vm_read"] or access == m["dup_only"]):
        return False
    if src in m["allowed"]:
        return False
    if src == m["svchost"] and access == m["svchost_access"]:
        return False
    if src.startswith(m["defender_prefix"]) and src.endswith("\\msmpeng.exe"):
        return False
    return True


@pytest.mark.parametrize("event", EVENTS, ids=EVENT_IDS)
def test_defender_kql_logic_on_fixture(event):
    assert _kql_fires(event) is (KQL_ID in event["expected_rules"]), event["description"]


def test_cross_rule_isolation():
    """Encoded-PowerShell fixtures never expect LSASS rules and vice versa."""
    ps_ids = {"bb2386f8-201e-4542-9f98-16d53b45f2e8", "DET-DEFENDER-DEMO-001"}
    for e in EVENTS:
        if e["EventID"] == 1:
            assert not ({RULE_ID, KQL_ID} & set(e["expected_rules"])), e["event_id"]
        else:
            assert not (ps_ids & set(e["expected_rules"])), e["event_id"]
