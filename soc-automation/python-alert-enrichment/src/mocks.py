"""Mock threat intel and CMDB backends — [DEMO] data only."""

from __future__ import annotations

from typing import Any

# RFC documentation / example indicators only
DEMO_BAD_IPS = {"203.0.113.50", "198.51.100.23"}
DEMO_BAD_DOMAINS = {"login-demo.example", "update-service-demo.example"}
DEMO_BAD_HASHES = {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}

DEMO_CMDB = {
    "WS-DEMO-042": {
        "owner": "jane.doe_demo",
        "business_unit": "Finance",
        "criticality": "medium",
        "edr": "crowdstrike",
    },
    "WS-DEMO-007": {
        "owner": "john.smith_demo",
        "business_unit": "Engineering",
        "criticality": "high",
        "edr": "defender",
    },
}


def lookup_ip(ip: str) -> dict[str, Any]:
    malicious = ip in DEMO_BAD_IPS
    return {
        "indicator": ip,
        "type": "ip",
        "disposition": "malicious" if malicious else "unknown",
        "confidence": 85 if malicious else 10,
        "source": "mock-ti",
    }


def lookup_domain(domain: str) -> dict[str, Any]:
    malicious = domain.lower() in DEMO_BAD_DOMAINS
    return {
        "indicator": domain,
        "type": "domain",
        "disposition": "malicious" if malicious else "unknown",
        "confidence": 80 if malicious else 10,
        "source": "mock-ti",
    }


def lookup_hash(file_hash: str) -> dict[str, Any]:
    malicious = file_hash.lower() in DEMO_BAD_HASHES
    return {
        "indicator": file_hash,
        "type": "sha256",
        "disposition": "malicious" if malicious else "unknown",
        "confidence": 90 if malicious else 5,
        "source": "mock-ti",
    }


def lookup_asset(hostname: str) -> dict[str, Any]:
    asset = DEMO_CMDB.get(hostname)
    if not asset:
        return {
            "hostname": hostname,
            "found": False,
            "source": "mock-cmdb",
        }
    return {"hostname": hostname, "found": True, "source": "mock-cmdb", **asset}
