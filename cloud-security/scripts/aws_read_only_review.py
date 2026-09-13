#!/usr/bin/env python3
"""[READ-ONLY] [DEMO] Local helper that reviews exported AWS JSON inventories.

Does not call AWS APIs. Pass files produced by your own authorized `aws` CLI exports.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def review_security_groups(path: Path) -> list[str]:
    findings: list[str] = []
    data = json.loads(path.read_text(encoding="utf-8"))
    groups = data if isinstance(data, list) else data.get("SecurityGroups", [])
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            for r in perm.get("IpRanges", []):
                if r.get("CidrIp") == "0.0.0.0/0" and from_port in (22, 3389):
                    findings.append(
                        f"[HIGH] {sg_id} allows 0.0.0.0/0 on admin port {from_port}"
                    )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only review of exported AWS SG JSON")
    parser.add_argument("--sg-json", required=True, help="Path to SecurityGroups JSON export")
    args = parser.parse_args()
    findings = review_security_groups(Path(args.sg_json))
    print("[DEMO] Read-only misconfig review — input file analysis only")
    if not findings:
        print("No demo findings for admin-port world-open rules.")
        return 0
    for f in findings:
        print(f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
