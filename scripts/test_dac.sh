#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/detection-as-code"
cd "$DIR"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# (Re)install whenever requirements.txt changes, so an existing local .venv picks up
# new deps (pySigma, Splunk backend, sysmon pipeline) instead of failing on import.
REQ_HASH="$(sha256sum requirements.txt | cut -d' ' -f1)"
if [[ "$(cat .venv/.requirements.sha256 2>/dev/null || true)" != "$REQ_HASH" ]]; then
  .venv/bin/pip install -q -r requirements.txt
  echo "$REQ_HASH" > .venv/.requirements.sha256
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pytest -q
