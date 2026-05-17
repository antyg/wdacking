#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Generates a comprehensive WDAC endpoint security status report.

.DESCRIPTION
    Force-imports the antyg-wdacking module and invokes Get-WDACSecurityPosture
    to produce a consolidated, aggregated report covering: platform identity,
    boot chain, hardware security, virtualisation, CPU mitigations, exploit
    protections, endpoint protection, WDAC policy state, trust tokens, and
    recent event log entries.

.PARAMETER HoursBack
    How many hours of event log history to include. Defaults to 24.

.PARAMETER MaxEvents
    Maximum CI event log entries to return. Defaults to 25.

.PARAMETER OutputJson
    If specified, outputs the report as JSON to this file path.

.EXAMPLE
    .\Get-EndpointSecurityReport.ps1
    Runs the full audit and displays results to the console.

.EXAMPLE
    .\Get-EndpointSecurityReport.ps1 -OutputJson C:\Reports\endpoint.json
    Runs the full audit and writes the report as JSON.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 8760)]
    [int]$HoursBack = 24,

    [ValidateRange(1, 1000)]
    [int]$MaxEvents = 25,

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

Write-Host "`n  antyg-wdacking Endpoint Security Report" -ForegroundColor Cyan
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "  Module: $moduleManifest" -ForegroundColor DarkGray
Write-Host "  Time:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  Host:   $env:COMPUTERNAME" -ForegroundColor DarkGray
Write-Host ""

Import-Module $moduleManifest -Force -ErrorAction Stop
Write-Host "  Module loaded: antyg-wdacking v$((Get-Module antyg-wdacking).Version)" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Helper — recursively convert objects to JSON-safe form (ISO 8601 dates)
# ---------------------------------------------------------------------------
function ConvertTo-Serializable {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        # Normalise Unspecified Kind to Local so .ToString('o') always includes timezone
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) {
            $Value = [System.DateTime]::SpecifyKind($Value, [System.DateTimeKind]::Local)
        }
        return $Value.ToString('o')
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $ht = [ordered]@{}
        $Value.PSObject.Properties | ForEach-Object { $ht[$_.Name] = (ConvertTo-Serializable $_.Value) }
        return $ht
    }
    if ($Value -is [hashtable] -or $Value -is [System.Collections.Specialized.OrderedDictionary]) {
        $ht = [ordered]@{}
        foreach ($k in $Value.Keys) { $ht[$k] = (ConvertTo-Serializable $Value[$k]) }
        return $ht
    }
    if ($Value -is [array]) {
        # Use foreach statement (not ForEach-Object cmdlet) to avoid pipeline
        # swallowing empty arrays or unwrapping single-element arrays.
        # Unary comma prevents PowerShell from unwrapping the result on return.
        $items = @(foreach ($item in $Value) { ConvertTo-Serializable $item })
        return ,$items
    }
    return $Value
}

# ---------------------------------------------------------------------------
# Helper — consistent 2-space JSON indent (bypasses PS 5.1 right-align style)
# ---------------------------------------------------------------------------
function Format-JsonIndent {
    param([string]$Compressed)
    $sb = [System.Text.StringBuilder]::new($Compressed.Length * 2)
    $indent = 0; $inString = $false; $escaped = $false
    for ($i = 0; $i -lt $Compressed.Length; $i++) {
        $c = $Compressed[$i]
        if ($escaped)            { [void]$sb.Append($c); $escaped = $false; continue }
        if ($c -eq '\' -and $inString) { [void]$sb.Append($c); $escaped = $true; continue }
        if ($c -eq '"')          { [void]$sb.Append($c); $inString = -not $inString; continue }
        if ($inString)           { [void]$sb.Append($c); continue }
        switch ($c) {
            '{' { [void]$sb.Append("{`n"); $indent++; [void]$sb.Append((' ' * ($indent * 2))) }
            '}' { $indent--; [void]$sb.Append("`n").Append((' ' * ($indent * 2))).Append('}') }
            '[' { [void]$sb.Append("[`n"); $indent++; [void]$sb.Append((' ' * ($indent * 2))) }
            ']' { $indent--; [void]$sb.Append("`n").Append((' ' * ($indent * 2))).Append(']') }
            ',' { [void]$sb.Append(",`n").Append((' ' * ($indent * 2))) }
            ':' { [void]$sb.Append(': ') }
            default { [void]$sb.Append($c) }
        }
    }
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
# Collect aggregated security posture
# ---------------------------------------------------------------------------
Write-Host "  Collecting security posture..." -ForegroundColor Yellow -NoNewline
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$posture = Get-WDACSecurityPosture -HoursBack $HoursBack -MaxEvents $MaxEvents -Verbose:$VerbosePreference
$sw.Stop()
Write-Host " OK ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Build report
# ---------------------------------------------------------------------------
$report = [ordered]@{
    ReportMetadata = [ordered]@{
        GeneratedAt   = (Get-Date -Format 'o')
        ComputerName  = $env:COMPUTERNAME
        UserName      = "$env:USERDOMAIN\$env:USERNAME"
        OSVersion     = [System.Environment]::OSVersion.VersionString
        PSEdition     = $PSVersionTable.PSEdition
        PSVersion     = $PSVersionTable.PSVersion.ToString()
        ModuleVersion = (Get-Module antyg-wdacking).Version.ToString()
        Duration      = "$($sw.ElapsedMilliseconds)ms"
    }
    Platform           = $posture.Platform
    SecurityPosture    = $posture.SecurityPosture
    ApplicationControl = $posture.ApplicationControl
    Verdicts           = $posture.Verdicts
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if ($OutputJson) {
    $jsonReport = ConvertTo-Serializable $report
    $json = Format-JsonIndent ($jsonReport | ConvertTo-Json -Depth 10 -Compress)
    [System.IO.File]::WriteAllText($OutputJson, $json, [System.Text.UTF8Encoding]::new($false))
    Write-Host "`n  Report written to: $OutputJson" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "  === Platform ===" -ForegroundColor Cyan
    $posture.Platform | Format-List

    Write-Host "  === Boot Chain ===" -ForegroundColor Cyan
    $posture.SecurityPosture.BootChain | Format-List

    Write-Host "  === Hardware Security ===" -ForegroundColor Cyan
    $posture.SecurityPosture.HardwareSecurity | Format-List

    Write-Host "  === Virtualisation ===" -ForegroundColor Cyan
    $posture.SecurityPosture.Virtualisation | Format-List

    Write-Host "  === CPU Mitigations ===" -ForegroundColor Cyan
    if ($posture.SecurityPosture.CPUMitigations) {
        $posture.SecurityPosture.CPUMitigations | Format-List
    } else {
        Write-Host "    (unavailable)`n" -ForegroundColor DarkGray
    }

    Write-Host "  === Exploit Protection ===" -ForegroundColor Cyan
    if ($posture.SecurityPosture.ExploitProtection) {
        $posture.SecurityPosture.ExploitProtection | Format-List
    } else {
        Write-Host "    (unavailable)`n" -ForegroundColor DarkGray
    }

    Write-Host "  === Endpoint Protection ===" -ForegroundColor Cyan
    if ($posture.SecurityPosture.EndpointProtection) {
        $posture.SecurityPosture.EndpointProtection | Format-List
    } else {
        Write-Host "    (unavailable)`n" -ForegroundColor DarkGray
    }

    Write-Host "  === Application Control — Enforcement ===" -ForegroundColor Cyan
    $posture.ApplicationControl.Enforcement | Format-List

    Write-Host "  === Application Control — Policies ===" -ForegroundColor Cyan
    $ac = $posture.ApplicationControl.Policies
    Write-Host "    Total: $($ac.TotalCount)  Enforced: $($ac.EnforcedCount)  Audit: $($ac.AuditCount)" -ForegroundColor White
    Write-Host ""

    # Policy hierarchy tree
    if ($ac.Hierarchy -and $ac.Hierarchy.Count -gt 0) {
        foreach ($base in $ac.Hierarchy) {
            $baseName = if ($base.FriendlyName) { $base.FriendlyName } else { $base.PolicyId }
            Write-Host "    Base: $baseName ($($base.EnforcementMode)) v$($base.Version)" -ForegroundColor White
            if ($base.Supplements -and $base.Supplements.Count -gt 0) {
                for ($i = 0; $i -lt $base.Supplements.Count; $i++) {
                    $supp = $base.Supplements[$i]
                    $suppName = if ($supp.FriendlyName) { $supp.FriendlyName } else { $supp.PolicyId }
                    $connector = if ($i -eq $base.Supplements.Count - 1) { [char]0x2514 } else { [char]0x251C }
                    Write-Host "    $($connector)── $suppName ($($supp.EnforcementMode)) v$($supp.Version)" -ForegroundColor DarkGray
                }
                if (-not $base.EnforcementConsistent) {
                    Write-Host "    $(([char]0x26A0)) Mixed enforcement modes in policy family" -ForegroundColor Yellow
                }
            } else {
                Write-Host "    (no supplements)" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
    } elseif ($ac.TotalCount -eq 0) {
        Write-Host "    No CI policies deployed" -ForegroundColor DarkGray
        Write-Host ""
    }

    # Orphaned supplementals warning
    if ($ac.OrphanedSupplementals -and $ac.OrphanedSupplementals.Count -gt 0) {
        Write-Host "    $(([char]0x26A0)) Orphaned Supplementals (base policy not deployed):" -ForegroundColor Yellow
        foreach ($orphan in $ac.OrphanedSupplementals) {
            $orphanName = if ($orphan.FriendlyName) { $orphan.FriendlyName } else { $orphan.PolicyId }
            Write-Host "    $([char]0x2502) $orphanName ($($orphan.EnforcementMode)) -> base: $($orphan.BasePolicyId)" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    if ($posture.ApplicationControl.TrustTokens) {
        Write-Host "  === Application Control — Trust Tokens ===" -ForegroundColor Cyan
        $posture.ApplicationControl.TrustTokens | Format-Table -AutoSize
    }

    if ($posture.ApplicationControl.RecentEvents) {
        Write-Host "  === Application Control — Recent Events ===" -ForegroundColor Cyan
        $posture.ApplicationControl.RecentEvents | Format-Table -Property EventId, EventType, TimeCreated, ProcessName -AutoSize
    }

    Write-Host "  === Verdicts ===" -ForegroundColor Cyan
    $posture.Verdicts | Format-List
}

Write-Host "  Report complete.`n" -ForegroundColor Cyan

# Return the report object for pipeline use
$report
