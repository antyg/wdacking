#Requires -Version 5.1
<#
.SYNOPSIS
    Decode dfsdscs E8 evidence .cip binaries to canonical .cip.xml sidecars using the
    aligned ConvertFrom-WDACBinary (Priority 1 + 2 + 3 emit policy).

.DESCRIPTION
    Replaces the .cip.xml sidecars in the specified row folder of the dfsdscs E8
    application-control evidence packet with output from the canonical decoder.

    Authored 2026-05-17 per user direction reversing the Round 2 deferral of E8 evidence
    packet regeneration (see docs/ci-binary-format-reference.md § "Canonical Decoder
    Alignment / Round 2 / E8 audit-packet co-existence" for the original deferral).

    The input .cip binaries are read-only; only the .cip.xml sidecars are replaced.
    Sibling row folders (ISM-1657, ISM-1870) are NOT touched by default. Pass a different
    -EvidenceRoot to extend.

    For each policy, the script reports:
      - Allow / Deny / FileAttrib rule counts emitted
      - SupplementalPolicySigners count (V6 emission)
      - Old vs new XML byte size with delta percentage

.PARAMETER EvidenceRoot
    The row folder to regenerate. Defaults to ISM-0843_workstations per user direction
    of 2026-05-17.
#>
param(
    [string]$EvidenceRoot = 'D:\antyg\Work\dfsdscs\E8\evidence\application-control\ISM-0843_workstations'
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleDir = Split-Path -Parent $scriptDir
$modulePsd1 = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($moduleDir, 'src', 'antyg-wdacking.psd1'))
Import-Module $modulePsd1 -Force

if (-not (Test-Path $EvidenceRoot)) {
    throw "EvidenceRoot not found: $EvidenceRoot"
}

$cipFiles = @(Get-ChildItem -Path $EvidenceRoot -Filter '*.cip' -File | Sort-Object Name)

Write-Host ''
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host "Canonical decoder regen against E8 evidence packet" -ForegroundColor Cyan
Write-Host "EvidenceRoot: $EvidenceRoot" -ForegroundColor DarkGray
Write-Host "Discovered .cip binaries: $($cipFiles.Count)" -ForegroundColor DarkGray
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host ''

$summary = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($cipFile in $cipFiles) {
    $xmlPath = "$($cipFile.FullName).xml"
    $oldSize = if (Test-Path $xmlPath) { (Get-Item $xmlPath).Length } else { 0 }

    Write-Host "Decoding $($cipFile.Name)" -ForegroundColor White

    try {
        $xml = ConvertFrom-WDACBinary -Path $cipFile.FullName

        $ns = [System.Xml.XmlNamespaceManager]::new($xml.NameTable)
        $ns.AddNamespace('s', 'urn:schemas-microsoft-com:sipolicy')

        $allows      = @($xml.SelectNodes('//s:FileRules/s:Allow', $ns))
        $denies      = @($xml.SelectNodes('//s:FileRules/s:Deny', $ns))
        $fileAttribs = @($xml.SelectNodes('//s:FileRules/s:FileAttrib', $ns))

        $sps      = $xml.SelectSingleNode('//s:SupplementalPolicySigners', $ns)
        $spsCount = if ($null -ne $sps) { @($sps.ChildNodes).Count } else { 0 }

        # Count rules by discriminator class (which attribute is present on the FileRule)
        $allRules = @($xml.SelectNodes('//s:FileRules/*', $ns))
        $byFilePath = @($allRules | Where-Object { $_.HasAttribute('FilePath') }).Count
        $byHash     = @($allRules | Where-Object { $_.HasAttribute('Hash') }).Count
        $byPkgFam   = @($allRules | Where-Object { $_.HasAttribute('PackageFamilyName') }).Count
        $byFileName = @($allRules | Where-Object { $_.HasAttribute('FileName') -and -not $_.HasAttribute('FilePath') -and -not $_.HasAttribute('Hash') -and -not $_.HasAttribute('PackageFamilyName') }).Count

        # Write canonical XML with indented formatting
        $settings = [System.Xml.XmlWriterSettings]::new()
        $settings.Indent = $true
        $settings.IndentChars = '    '
        $settings.Encoding = [System.Text.Encoding]::UTF8

        $writer = [System.Xml.XmlWriter]::Create($xmlPath, $settings)
        try {
            $xml.Save($writer)
        }
        finally {
            $writer.Dispose()
        }

        $newSize = (Get-Item $xmlPath).Length
        $delta   = if ($oldSize -gt 0) { [Math]::Round((($newSize - $oldSize) / $oldSize) * 100, 1) } else { 0 }

        Write-Host ("  Rules: Allow={0,6}  Deny={1,5}  FileAttrib={2,3}  | by discriminator: FilePath={3,5} Hash={4,5} Pkg={5,3} FileName={6,5}" `
            -f $allows.Count, $denies.Count, $fileAttribs.Count, $byFilePath, $byHash, $byPkgFam, $byFileName) -ForegroundColor Green
        Write-Host ("  SupplementalSigners: {0}  |  XML bytes: {1:N0} -> {2:N0} ({3:+0.0;-0.0}%)" `
            -f $spsCount, $oldSize, $newSize, $delta) -ForegroundColor DarkGray

        $summary.Add([PSCustomObject]@{
            Policy       = ($cipFile.Name -replace 'evidence-01-wdac-policy-_', '' -replace '_-\d{14}\.cip$', '')
            AllowCount   = $allows.Count
            DenyCount    = $denies.Count
            FileAttrib   = $fileAttribs.Count
            FilePath     = $byFilePath
            Hash         = $byHash
            PkgFam       = $byPkgFam
            FileName     = $byFileName
            SuppSigners  = $spsCount
            OldBytes     = $oldSize
            NewBytes     = $newSize
            DeltaPct     = $delta
            Status       = 'OK'
        })
    }
    catch {
        Write-Host "  DECODE ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $summary.Add([PSCustomObject]@{
            Policy       = ($cipFile.Name -replace 'evidence-01-wdac-policy-_', '' -replace '_-\d{14}\.cip$', '')
            AllowCount   = $null
            DenyCount    = $null
            FileAttrib   = $null
            FilePath     = $null
            Hash         = $null
            PkgFam       = $null
            FileName     = $null
            SuppSigners  = $null
            OldBytes     = $oldSize
            NewBytes     = $null
            DeltaPct     = $null
            Status       = $_.Exception.Message
        })
    }
    Write-Host ''
}

Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host 'Summary' -ForegroundColor Cyan
Write-Host ('=' * 100) -ForegroundColor DarkCyan
$summary | Format-Table -AutoSize
