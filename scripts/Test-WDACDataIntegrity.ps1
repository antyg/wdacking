#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Validates cross-source data integrity across WDAC module functions.

.DESCRIPTION
    Calls the 5 module functions that produce overlapping data and compares
    the 7 shared fields across their sources. This confirms that the module's
    tiered detection strategies (CPUID > NtApi > WMI > Registry) produce
    consistent results.

    Overlapping field comparisons:
      VBS Status       — DeviceSecurity vs HypervisorDetail vs PolicyStatus
      HVCI Running     — DeviceSecurity vs HypervisorDetail vs PolicyStatus
      SecureBoot       — DeviceSecurity vs PolicyStatus
      UEFI             — DeviceSecurity vs FirmwareSecurity
      UMCI             — DeviceSecurity vs PolicyStatus
      Enforcement Mode — WDACEnforcement vs PolicyStatus
      System Mfr       — FirmwareSecurity vs HypervisorDetail

.PARAMETER OutputJson
    If specified, writes the comparison results as JSON to this file path.

.EXAMPLE
    .\Test-WDACDataIntegrity.ps1
    Runs all comparisons and displays results as a console table.

.EXAMPLE
    .\Test-WDACDataIntegrity.ps1 -OutputJson C:\Reports\integrity.json
    Runs all comparisons and writes results as JSON.
#>
[CmdletBinding()]
param(
    [string]$OutputJson
)

# ---------------------------------------------------------------------------
# Module import — resolve relative path to absolute at runtime
# ---------------------------------------------------------------------------
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$moduleManifest = Join-Path (Split-Path $scriptDir -Parent) 'src\antyg-wdacking.psd1'

if (-not (Test-Path $moduleManifest)) {
    Write-Error "Module manifest not found at: $moduleManifest"
    exit 1
}

Write-Host "`n  antyg-wdacking Data Integrity Validation" -ForegroundColor Cyan
Write-Host "  =========================================" -ForegroundColor Cyan
Write-Host "  Module: $moduleManifest" -ForegroundColor DarkGray
Write-Host "  Time:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  Host:   $env:COMPUTERNAME" -ForegroundColor DarkGray
Write-Host ""

Import-Module $moduleManifest -Force -ErrorAction Stop
Write-Host "  Module loaded: antyg-wdacking v$((Get-Module antyg-wdacking).Version)" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Collect data from the 5 overlapping source functions
# ---------------------------------------------------------------------------
$sources = [ordered]@{}
$functionMap = [ordered]@{
    DeviceSecurity = 'Get-WDACDeviceSecurity'
    HypervisorDetail = 'Get-WDACHypervisorDetail'
    PolicyStatus = 'Get-WDACPolicyStatus'
    FirmwareSecurity = 'Get-WDACFirmwareSecurity'
    WDACEnforcement = 'Test-WDACEnforcement'
}

foreach ($key in $functionMap.Keys) {
    $fn = $functionMap[$key]
    Write-Host "  [$key] Calling $fn..." -ForegroundColor Yellow -NoNewline
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $sources[$key] = & $fn
        $sw.Stop()
        Write-Host " OK ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Green
    }
    catch {
        $sw.Stop()
        Write-Host " FAILED ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Red
        Write-Host "    $($_.Exception.Message)" -ForegroundColor DarkRed
        $sources[$key] = $null
    }
}

# ---------------------------------------------------------------------------
# Helper — normalise a value for semantic comparison
# ---------------------------------------------------------------------------
function Normalize-ComparisonValue {
    param($Value)
    if ($null -eq $Value) { return '<null>' }
    if ($Value -is [bool]) { return $Value.ToString().ToLower() }
    return "$Value".Trim()
}

# ---------------------------------------------------------------------------
# Build comparison table
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  --- Cross-Source Comparisons ---" -ForegroundColor Cyan
Write-Host ""

$devSec     = $sources['DeviceSecurity']
$hypervisor = $sources['HypervisorDetail']
$polStatus  = $sources['PolicyStatus']
$firmware   = $sources['FirmwareSecurity']
$enforce    = $sources['WDACEnforcement']

$comparisons = @(
    # VBS Status — 3 sources
    [PSCustomObject]@{
        Field   = 'VBS Status'
        Source1 = 'DeviceSecurity.VBSStatus'
        Value1  = $devSec.VBSStatus
        Source2 = 'HypervisorDetail.VBSStatus'
        Value2  = $hypervisor.VBSStatus
    },
    [PSCustomObject]@{
        Field   = 'VBS Status'
        Source1 = 'DeviceSecurity.VBSStatus'
        Value1  = $devSec.VBSStatus
        Source2 = 'PolicyStatus.VirtualizationBasedSecurity'
        Value2  = $polStatus.VirtualizationBasedSecurity
    },

    # HVCI Running — 3 sources
    [PSCustomObject]@{
        Field   = 'HVCI Running'
        Source1 = 'DeviceSecurity.HVCIRunning'
        Value1  = $devSec.HVCIRunning
        Source2 = 'HypervisorDetail.HVCIEnabled'
        Value2  = $hypervisor.HVCIEnabled
    },
    [PSCustomObject]@{
        Field   = 'HVCI Running'
        Source1 = 'DeviceSecurity.HVCIRunning'
        Value1  = $devSec.HVCIRunning
        Source2 = 'PolicyStatus.HVCIRunning'
        Value2  = $polStatus.HVCIRunning
    },

    # SecureBoot — 2 sources
    [PSCustomObject]@{
        Field   = 'SecureBoot'
        Source1 = 'DeviceSecurity.SecureBootEnabled'
        Value1  = $devSec.SecureBootEnabled
        Source2 = 'PolicyStatus.SecureBootEnabled'
        Value2  = $polStatus.SecureBootEnabled
    },

    # UEFI — 2 sources (bool vs string — semantic comparison)
    [PSCustomObject]@{
        Field   = 'UEFI'
        Source1 = 'DeviceSecurity.UEFIEnabled'
        Value1  = $devSec.UEFIEnabled
        Source2 = 'FirmwareSecurity.UEFIMode'
        Value2  = $firmware.UEFIMode
    },

    # UMCI — 2 sources
    [PSCustomObject]@{
        Field   = 'UMCI'
        Source1 = 'DeviceSecurity.HVCIUMCIEnabled'
        Value1  = $devSec.HVCIUMCIEnabled
        Source2 = 'PolicyStatus.UMCIEnabled'
        Value2  = $polStatus.UMCIEnabled
    },

    # Enforcement Mode — 2 sources
    [PSCustomObject]@{
        Field   = 'Enforcement'
        Source1 = 'WDACEnforcement.EnforcementMode'
        Value1  = $enforce.EnforcementMode
        Source2 = 'PolicyStatus.EnforcementMode'
        Value2  = $polStatus.EnforcementMode
    },

    # System Manufacturer — 2 sources
    [PSCustomObject]@{
        Field   = 'System Mfr'
        Source1 = 'FirmwareSecurity.SystemManufacturer'
        Value1  = $firmware.SystemManufacturer
        Source2 = 'HypervisorDetail.SystemManufacturer'
        Value2  = $hypervisor.SystemManufacturer
    }
)

# Add normalised values and match result
foreach ($c in $comparisons) {
    $norm1 = Normalize-ComparisonValue $c.Value1
    $norm2 = Normalize-ComparisonValue $c.Value2
    $c | Add-Member -NotePropertyName 'Norm1' -NotePropertyValue $norm1
    $c | Add-Member -NotePropertyName 'Norm2' -NotePropertyValue $norm2
    $c | Add-Member -NotePropertyName 'Match' -NotePropertyValue ($norm1 -eq $norm2)
}

# ---------------------------------------------------------------------------
# Display results
# ---------------------------------------------------------------------------
$comparisons | Format-Table -Property @(
    @{ Label = 'Field'; Expression = { $_.Field }; Width = 14 },
    @{ Label = 'Source 1'; Expression = { $_.Source1 }; Width = 38 },
    @{ Label = 'Value 1'; Expression = { Normalize-ComparisonValue $_.Value1 }; Width = 20 },
    @{ Label = 'Source 2'; Expression = { $_.Source2 }; Width = 42 },
    @{ Label = 'Value 2'; Expression = { Normalize-ComparisonValue $_.Value2 }; Width = 20 },
    @{ Label = 'Match'; Expression = { if ($_.Match) { 'YES' } else { 'NO' } }; Width = 6 }
) -Wrap

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$matchCount   = @($comparisons | Where-Object { $_.Match }).Count
$mismatchCount = $comparisons.Count - $matchCount

Write-Host "  --- Summary ---" -ForegroundColor Cyan
Write-Host "  Comparisons: $($comparisons.Count) total, $matchCount matched, $mismatchCount mismatched" -ForegroundColor $(if ($mismatchCount -eq 0) { 'Green' } else { 'Yellow' })

if ($mismatchCount -gt 0) {
    Write-Host ""
    Write-Host "  Mismatched fields:" -ForegroundColor Yellow
    $comparisons | Where-Object { -not $_.Match } | ForEach-Object {
        Write-Host "    $($_.Field): $($_.Source1)=$($_.Norm1) vs $($_.Source2)=$($_.Norm2)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Optional JSON output
# ---------------------------------------------------------------------------
if ($OutputJson) {
    $jsonData = [ordered]@{
        GeneratedAt  = (Get-Date -Format 'o')
        ComputerName = $env:COMPUTERNAME
        TotalComparisons = $comparisons.Count
        Matched      = $matchCount
        Mismatched   = $mismatchCount
        Comparisons  = @($comparisons | ForEach-Object {
            [ordered]@{
                Field   = $_.Field
                Source1 = $_.Source1
                Value1  = (Normalize-ComparisonValue $_.Value1)
                Source2 = $_.Source2
                Value2  = (Normalize-ComparisonValue $_.Value2)
                Match   = $_.Match
            }
        })
    }
    $json = $jsonData | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($OutputJson, $json, [System.Text.UTF8Encoding]::new($false))
    Write-Host "`n  Results written to: $OutputJson" -ForegroundColor Green
}

Write-Host "`n  Validation complete.`n" -ForegroundColor Cyan

# Return comparison results for pipeline use
$comparisons
