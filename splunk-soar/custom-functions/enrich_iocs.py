"""[DEMO] Safe SOAR custom function stub — IOC enrichment with mocks."""

from __future__ import annotations

from typing import Any

_MOCK_BAD = {
    "203.0.113.50",
    "login-demo.example",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}


def enrich_iocs(iocs: list[str], ioc_type: str = "auto") -> dict[str, Any]:
    """Return mock dispositions for a list of IOCs."""
    results = []
    for ioc in iocs:
        bad = ioc.lower() in _MOCK_BAD
        results.append(
            {
                "ioc": ioc,
                "type": ioc_type,
                "disposition": "malicious" if bad else "unknown",
                "source": "mock-ti",
            }
        )
    return {
        "results": results,
        "any_malicious": any(r["disposition"] == "malicious" for r in results),
        "label": "[DEMO] mock enrichment",
    }


def cmdb_lookup(hostname: str) -> dict[str, Any]:
    demo = {
        "WS-DEMO-042": {"owner": "jane.doe_demo", "criticality": "medium"},
        "WS-DEMO-007": {"owner": "john.smith_demo", "criticality": "high"},
    }
    hit = demo.get(hostname)
    if not hit:
        return {"hostname": hostname, "found": False, "label": "[DEMO]"}
    return {"hostname": hostname, "found": True, "label": "[DEMO]", **hit}
