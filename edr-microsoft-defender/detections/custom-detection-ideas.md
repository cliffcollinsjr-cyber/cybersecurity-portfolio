# Custom Detection Ideas (Defender)

**Classification:** [DEMO] ideas — not enabled rules

| Idea | Data | Logic sketch | Noise notes |
|------|------|--------------|-------------|
| Encoded PowerShell from Office parent | DeviceProcessEvents | WinWord/Excel → powershell -enc | Macro-heavy orgs need allowlists |
| New service installed by non-admin tooling | DeviceEvents | Service install + unusual Image | Packagers may FP |
| Browser → scripting host chain | DeviceProcessEvents | chrome/msedge → wscript/cscript | Software deployment FP |
| Sudden sensor unhealthy | DeviceInfo | SensorHealthState != Active | Patch windows |

Promote to custom detection only after lab validation and stakeholder review.
