"""Unit tests for alert enrichment — [DEMO] mocks only."""

from src.enrich import enrich_alert, recommend_triage
from src import mocks


def test_lookup_bad_ip():
    result = mocks.lookup_ip("203.0.113.50")
    assert result["disposition"] == "malicious"
    assert result["confidence"] >= 80


def test_lookup_unknown_ip():
    result = mocks.lookup_ip("203.0.113.99")
    assert result["disposition"] == "unknown"


def test_cmdb_hit():
    asset = mocks.lookup_asset("WS-DEMO-042")
    assert asset["found"] is True
    assert asset["business_unit"] == "Finance"


def test_enrich_escalates_on_malicious_high():
    alert = {
        "alert_id": "ALERT-DEMO-1",
        "severity": "high",
        "hostname": "WS-DEMO-042",
        "iocs": {"ips": ["203.0.113.50"], "domains": [], "hashes": []},
    }
    out = enrich_alert(alert)
    assert out["triage"]["action"] == "escalate"
    assert out["label"].startswith("[DEMO]")


def test_enrich_monitor_when_clean():
    alert = {
        "alert_id": "ALERT-DEMO-2",
        "severity": "low",
        "hostname": "WS-DEMO-042",
        "iocs": {"ips": ["203.0.113.99"], "domains": [], "hashes": []},
    }
    out = enrich_alert(alert)
    assert out["triage"]["action"] == "monitor"


def test_recommend_investigate_high_asset():
    enrichment = {
        "alert_severity": "medium",
        "threat_intel": {"ips": [], "domains": [], "hashes": []},
        "asset": {"criticality": "high"},
    }
    rec = recommend_triage(enrichment)
    assert rec["action"] == "investigate"
