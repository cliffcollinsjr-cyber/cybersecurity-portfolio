# Go Notifier / Ticket-Sync Stub

**Classification:** [DEMO]  
**Skill:** Small Go CLIs for SOC notification workflows

## What it does

CLI that accepts enriched alert JSON and prints a **dry-run** notification payload for Slack webhook / ticketing systems. No real network calls unless `--post` is set (still defaults to dry-run URL).

## Build & run

```bash
# from repo root
make build-go

cd soc-automation/go-notifier
go build -o go-notifier .
./go-notifier --alert ../python-alert-enrichment/examples/demo_alert.json
./go-notifier --help
```

## Design notes

- Fail closed: missing alert file → non-zero exit
- Never logs secrets; webhook URL redacted in output
- Intended as a sync/notify stub for SOAR or cron wrappers
