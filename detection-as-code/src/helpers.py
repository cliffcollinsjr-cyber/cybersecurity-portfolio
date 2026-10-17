"""Simple helpers for detection YAML + fixture matching — [DEMO]."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = ROOT / "detections"
FIXTURES_DIR = ROOT / "fixtures"


def load_detection(name: str) -> dict[str, Any]:
    """Load a detection YAML by filename (with or without .yml)."""
    path = DETECTIONS_DIR / name
    if not path.suffix:
        path = path.with_suffix(".yml")
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Detection {name} must be a mapping")
    return data


def load_fixture(name: str = "sample_events.json") -> dict[str, Any]:
    path = FIXTURES_DIR / name
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def event_matches_keywords(command_line: str, keywords: list[str]) -> bool:
    """
    Return True if the command line looks like encoded PowerShell abuse
    for our DEMO detections: must mention powershell/pwsh AND an encode switch.
    """
    cl = (command_line or "").lower()
    kw = [k.lower() for k in keywords]

    has_ps = ("powershell" in cl) or ("pwsh" in cl) or any(
        k in cl for k in kw if "powershell" in k or "pwsh" in k
    )
    # Prefer explicit encode switches from the detection keyword list
    encode_keys = [k for k in kw if "enc" in k]
    if not encode_keys:
        encode_keys = ["-enc", "-encodedcommand"]
    has_enc = any(k in cl for k in encode_keys)
    return bool(has_ps and has_enc)
