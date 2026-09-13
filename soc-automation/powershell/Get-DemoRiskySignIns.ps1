<#
.SYNOPSIS
  [DEMO] Summarize risky sign-ins for SOC triage (mock by default).

.NOTES
  Permissions: IdentityRiskEvent.Read.All / AuditLog.Read.All
  Read-heavy — no session revocation in this script.
#>
[CmdletBinding()]
param(
    [string]$UserPrincipalName,
    [switch]$UseMock = $true
)

Write-Host "[DEMO] Get-DemoRiskySignIns" -ForegroundColor Cyan

if ($UseMock) {
    $rows = @(
        [pscustomobject]@{ User = "jdoe_demo@contoso.example"; Risk = "high"; IP = "203.0.113.50"; City = "Demo City" },
        [pscustomobject]@{ User = "asmith_demo@contoso.example"; Risk = "medium"; IP = "198.51.100.23"; City = "Labville" }
    )
    if ($UserPrincipalName) {
        $rows = $rows | Where-Object { $_.User -eq $UserPrincipalName }
    }
    $rows | Format-Table -AutoSize
    return $rows
}

Write-Warning "Live Graph queries omitted from public portfolio. Document permissions in README."
