#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnostic: import E8MVT CIPolicyParser.psm1 and report whether CodeIntegrity.* types
    register in the AppDomain. Used to disambiguate "Import-Module silently failed" vs
    "types loaded under a different name" vs "Set-StrictMode at module scope blocked load".
#>
param(
    [string]$E8MvtParserPath = 'D:\antyg\Work\dfsdscs\E8\Tools\E8 Maturity Verification Tool Oct 2025\Resources\Scripts\CIPolicyParser.psm1'
)

$ErrorActionPreference = 'Continue'

Write-Host '--- Pre-import state ---' -ForegroundColor Cyan
$pre = 'CodeIntegrity.SIPolicy' -as [Type]
Write-Host "CodeIntegrity.SIPolicy resolves before import: $($null -ne $pre)"

Write-Host '' ; Write-Host '--- Attempting Import-Module ---' -ForegroundColor Cyan
try {
    Import-Module $E8MvtParserPath -Force -DisableNameChecking -Verbose -ErrorAction Stop 4>&1 | Select-Object -First 8
    Write-Host "Import-Module completed without throwing." -ForegroundColor Green
}
catch {
    Write-Host "Import-Module threw: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Type: $($_.Exception.GetType().FullName)"
    Write-Host "Position: $($_.InvocationInfo.PositionMessage)"
}

Write-Host '' ; Write-Host '--- Post-import type resolution ---' -ForegroundColor Cyan
$post = 'CodeIntegrity.SIPolicy' -as [Type]
Write-Host "CodeIntegrity.SIPolicy resolves after import: $($null -ne $post)"
if ($null -ne $post) {
    Write-Host "Assembly: $($post.Assembly.FullName)" -ForegroundColor Green
}

Write-Host '' ; Write-Host '--- All CodeIntegrity.* types in AppDomain ---' -ForegroundColor Cyan
$assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
$ciTypes = @()
foreach ($asm in $assemblies) {
    try {
        $types = $asm.GetTypes()
    }
    catch {
        continue
    }
    foreach ($t in $types) {
        if ($t.FullName -like 'CodeIntegrity.*') {
            $ciTypes += $t.FullName
        }
    }
}
Write-Host "Total CodeIntegrity.* types found: $($ciTypes.Count)"
$ciTypes | Sort-Object | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
if ($ciTypes.Count -gt 20) {
    Write-Host "  ... ($($ciTypes.Count - 20) more)" -ForegroundColor DarkGray
}

Write-Host '' ; Write-Host '--- Loaded modules ---' -ForegroundColor Cyan
Get-Module | Where-Object { $_.Name -like '*CIPolicy*' -or $_.Path -like '*CIPolicyParser*' } |
    Format-Table Name, Version, Path -AutoSize
