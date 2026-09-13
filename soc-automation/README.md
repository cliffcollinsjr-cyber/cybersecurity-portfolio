# SOC Automation — Python · Go · PowerShell

**Skills proven:** Alert enrichment/triage automation, API integration with mocks, unit testing, small Go CLIs for notification/ticket sync stubs, PowerShell Defender/M365 helpers (read-heavy), architecture documentation.

## Architecture

```mermaid
flowchart LR
  subgraph ingest [Alert Sources]
    SIEM[Splunk Notable]
    EDR[CrowdStrike / Defender]
  end
  subgraph enrich [Enrichment Layer]
    PY[Python Triage Helper]
    MOCK[Mock Threat Intel / CMDB APIs]
  end
  subgraph notify [Notification / Ticketing]
    GO[Go Notifier CLI]
    TICKET[Ticket Sync Stub]
  end
  subgraph ops [Analyst Ops]
    PS[PowerShell SOC Helpers]
    M365[M365 / Defender Read APIs]
  end
  SIEM --> PY
  EDR --> PY
  PY --> MOCK
  PY --> GO
  GO --> TICKET
  PS --> M365
  PY -.->|enriched context| ops
```

## Components

| Component | Path | Purpose |
|-----------|------|---------|
| Python enrichment | [`python-alert-enrichment/`](./python-alert-enrichment/) | Triage helper with mock APIs + pytest |
| Go notifier | [`go-notifier/`](./go-notifier/) | CLI stub for Slack/webhook/ticket notify |
| PowerShell | [`powershell/`](./powershell/) | Defender/M365 read-oriented helpers |

All external calls default to **mocks** — safe for portfolio demos.
