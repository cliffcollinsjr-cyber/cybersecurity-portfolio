<#
.SYNOPSIS
  [DEMO] Export a simple device health snapshot for handoff notes.

.NOTES
  Permissions: Device read in Defender / Intune as applicable.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./device-health-demo.csv",
    [switch]$UseMock = $true
)

if ($UseMock) {
    $devices = @(
        [pscustomobject]@{ Device = "WS-DEMO-042"; Sensor = "Active"; OS = "Windows 11"; Risk = "Medium"; LastSeen = "2026-03-10T14:22:00Z" },
        [pscustomobject]@{ Device = "WS-DEMO-007"; Sensor = "Active"; OS = "Windows 11"; Risk = "Low"; LastSeen = "2026-03-10T13:01:00Z" }
    )
    $devices | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "[DEMO] Wrote $OutputPath"
    return $devices
}

Write-Warning "Live export not implemented in portfolio stub."
