# PowerShell SOC Helpers (Defender / M365)

**Classification:** [READ-ONLY] oriented templates  
**Skill:** Microsoft SOC scripting, documenting Graph/Defender permissions

> Scripts are written for analyst workstations with appropriate modules. They default to **WhatIf / dry-run commentary** and avoid destructive mailbox or host actions.

## Permissions to document (examples)

| Script | API / Role | Access level |
|--------|------------|--------------|
| `Get-DemoDefenderAlerts.ps1` | Microsoft Defender for Endpoint API or `Microsoft.Graph` Security | Read alerts |
| `Get-DemoRiskySignIns.ps1` | Entra ID Identity Protection / Sign-in logs | Read |
| `Export-DemoDeviceHealth.ps1` | Defender device inventory | Read |

Required Graph application permissions (lab): `SecurityEvents.Read.All`, `IdentityRiskEvent.Read.All`, `DeviceManagementManagedDevices.Read.All` (adjust to least privilege).

Never commit client secrets — use device code / managed identity in real deployments.
