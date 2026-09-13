#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/soc-automation/go-notifier"
cd "$DIR"
go build -o go-notifier .
echo "Built: $DIR/go-notifier"
./go-notifier --help || true
