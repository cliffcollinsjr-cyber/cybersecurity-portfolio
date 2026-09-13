#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
errors=0

# Fail if obvious secret-like filenames sneak in (exclude venv/cache)
while IFS= read -r f; do
  echo "WARN potential secret filename: $f"
  errors=1
done < <(find "$ROOT" -type f \( -name '*.pem' -o -name '*.pfx' -o -name '.env' -o -name 'id_rsa' \) \
  -not -path '*/.venv/*' -not -path '*/.git/*' 2>/dev/null || true)

# Python syntax check if available
if command -v python3 >/dev/null; then
  while IFS= read -r py; do
    python3 -m py_compile "$py" || errors=1
  done < <(find "$ROOT/soc-automation/python-alert-enrichment" -name '*.py' -not -path '*/.venv/*')
fi

# Go fmt check
if command -v go >/dev/null && [[ -d "$ROOT/soc-automation/go-notifier" ]]; then
  bad=$(cd "$ROOT/soc-automation/go-notifier" && gofmt -l .)
  if [[ -n "$bad" ]]; then
    echo "Go files need gofmt: $bad"
    errors=1
  fi
fi

# No exploit-ish filenames as a soft guard (docs mentioning the word in content OK; filenames not)
if find "$ROOT" \( -iname '*exploit*' -o -iname '*payload*' -o -iname '*shellcode*' \) -not -path '*/.venv/*' | grep -q .; then
  echo "ERROR: offensive artifact naming detected"
  errors=1
fi

if [[ "$errors" -ne 0 ]]; then
  echo "Lint completed with issues."
  exit 1
fi
echo "Lint OK."
