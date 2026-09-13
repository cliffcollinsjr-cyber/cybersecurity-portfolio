"""Enrich SOC alerts with mock TI + CMDB context and triage advice."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import mocks


def _collect_iocs(alert: dict[str, Any]) -> dict[str, list[str]]:
    iocs = alert.get("iocs") or {}
    return {
        "ips": list(iocs.get("ips") or []),
        "domains": list(iocs.get("domains") or []),
        "hashes": list(iocs.get("hashes") or []),
    }


def recommend_triage(enrichment: dict[str, Any]) -> dict[str, str]:
    """Return a simple triage recommendation based on enrichment."""
    dispositions = []
    for section in ("ips", "domains", "hashes"):
        for item in enrichment.get("threat_intel", {}).get(section, []):
            dispositions.append(item.get("disposition"))

    asset = enrichment.get("asset") or {}
    criticality = (asset.get("criticality") or "low").lower()
    severity = (enrichment.get("alert_severity") or "medium").lower()

    if "malicious" in dispositions and severity in {"high", "critical"}:
        action = "escalate"
        rationale = "Malicious IOC matched with high/critical alert severity."
    elif "malicious" in dispositions:
        action = "investigate"
        rationale = "Malicious IOC matched; confirm host activity before containment."
    elif criticality == "high" and severity in {"medium", "high", "critical"}:
        action = "investigate"
        rationale = "High-criticality asset with non-benign alert — prioritize review."
    else:
        action = "monitor"
        rationale = "No high-confidence malicious IOCs in mock TI; continue monitoring."

    return {"action": action, "rationale": rationale}


def enrich_alert(alert: dict[str, Any]) -> dict[str, Any]:
    iocs = _collect_iocs(alert)
    ti = {
        "ips": [mocks.lookup_ip(ip) for ip in iocs["ips"]],
        "domains": [mocks.lookup_domain(d) for d in iocs["domains"]],
        "hashes": [mocks.lookup_hash(h) for h in iocs["hashes"]],
    }
    hostname = alert.get("hostname") or alert.get("host") or ""
    asset = mocks.lookup_asset(hostname) if hostname else {"found": False}

    enrichment = {
        "alert_id": alert.get("alert_id", "unknown"),
        "alert_severity": alert.get("severity", "medium"),
        "title": alert.get("title", ""),
        "threat_intel": ti,
        "asset": asset,
        "label": "[DEMO] mock enrichment — not live production data",
    }
    enrichment["triage"] = recommend_triage(enrichment)
    return enrichment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enrich a SOC alert JSON ([DEMO] mocks)")
    parser.add_argument("--alert", required=True, help="Path to alert JSON")
    args = parser.parse_args(argv)

    path = Path(args.alert)
    alert = json.loads(path.read_text(encoding="utf-8"))
    result = enrich_alert(alert)
    json.dump(result, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
