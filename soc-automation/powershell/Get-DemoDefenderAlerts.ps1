<#
.SYNOPSIS
  [DEMO] Read-oriented helper to list recent Defender alerts (mock mode by default).

.NOTES
  Permissions: SecurityEvents.Read.All (Graph) or MDE Alert.Read.All
  This script does NOT isolate devices or take response actions.
#>
[CmdletBinding()]
param(
    [int]$Top = 10,
    [switch]$UseMock = $true
)

Write-Host "[DEMO] Get-DemoDefenderAlerts — read-only triage helper" -ForegroundColor Cyan

if ($UseMock) {
    $alerts = @(
        [pscustomobject]@{ Id = "ALERT-DEMO-2001"; Title = "Suspicious PowerShell"; Severity = "Medium"; Device = "WS-DEMO-042" },
        [pscustomobject]@{ Id = "ALERT-DEMO-2002"; Title = "Uncommon RDP behavior"; Severity = "Low"; Device = "WS-DEMO-007" }
    ) | Select-Object -First $Top
    $alerts | Format-Table -AutoSize
    return $alerts
}

# Authorized lab only — requires Graph connection
# Connect-MgGraph -Scopes "SecurityEvents.Read.All"
# Get-MgSecurityAlert -Top $Top | Select-Object Id, Title, Severity, CreatedDateTime
Write-Warning "Live mode not implemented in portfolio stub. Use -UseMock (default)."
