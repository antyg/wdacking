#Requires -Version 5.1
<#
.SYNOPSIS
    Verify whether E8MVT's own decoded XML output round-trips via Microsoft's
    ConvertFrom-CIPolicy.

.DESCRIPTION
    A round-trip soundness probe with a different intent than Test-RoundTripFileAttrib.ps1.
    That earlier script validated the WORKSPACE's regenerated XML. This script validates
    E8MVT's own output against Microsoft's compiler. If E8MVT's XML fails ConvertFrom-CIPolicy,
    then E8MVT's typed-model output is not a viable import for downstream tooling that uses
    Microsoft's compile cmdlet.

    Specific hypothesis under test (Round 6 finding 2026-05-17): E8MVT's `CodeIntegrity.OptionType`
    enum at line 214 of CIPolicyParser.psm1 has a TYPO — `"Enabled: Revoked Expired As Unsigned"`
    with a space after the colon. The XSD canonical value (cipolicy.xsd line 128) has no space.
    Because E8MVT serialises through its typed model, its XML output carries the typo. We
    predict that Microsoft's ConvertFrom-CIPolicy XSD-validates the input and rejects this
    value, producing a compile failure.
#>
param()

$ErrorActionPreference = 'Stop'

$samples = @(
    @{ Label = 'E8MVT 1283AC0F (645 Denies + Revoked-Expired option)'; Path = 'D:\antyg\Work\dfsdscs\E8\output\WdacDecodeCompare\20260517173637\evidence-01-wdac-policy-_1283AC0F-FFF1-49AE-ADA1-8A933130CAD6_-20260515094737-e8mvt.cip.xml' },
    @{ Label = 'E8MVT 4FD367C7 (22,279 rules + Revoked-Expired option)'; Path = 'D:\antyg\Work\dfsdscs\E8\output\WdacDecodeCompare\20260517173637\evidence-01-wdac-policy-_4FD367C7-8F78-4528-B2A0-4F46951692F3_-20260515094737-e8mvt.cip.xml' },
    @{ Label = 'E8MVT 1939ED82 (Supplemental, no Revoked-Expired)';    Path = 'D:\antyg\Work\dfsdscs\E8\output\WdacDecodeCompare\20260517173637\evidence-01-wdac-policy-_1939ED82-BFD5-4D32-B58E-D31D3C49715A_-20260515094737-e8mvt.cip.xml' }
)

Write-Host ''
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host 'E8MVT-output round-trip viability against Microsoft ConvertFrom-CIPolicy' -ForegroundColor Cyan
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host ''

foreach ($sample in $samples) {
    Write-Host ('-' * 100) -ForegroundColor DarkGray
    Write-Host "  $($sample.Label)" -ForegroundColor White
    if (-not (Test-Path $sample.Path)) {
        Write-Host "    SKIPPED — file not found: $($sample.Path)" -ForegroundColor Yellow
        continue
    }

    $tempCip = [System.IO.Path]::Combine($env:TEMP, "e8mvt-roundtrip-$(Get-Random).cip")
    try {
        ConvertFrom-CIPolicy -XmlFilePath $sample.Path -BinaryFilePath $tempCip -ErrorAction Stop | Out-Null
        $bytes = (Get-Item $tempCip).Length
        Write-Host "    COMPILE OK — $bytes bytes" -ForegroundColor Green
    }
    catch {
        Write-Host "    COMPILE FAILED" -ForegroundColor Red
        Write-Host "      $($_.Exception.Message)" -ForegroundColor DarkRed
    }
    finally {
        if (Test-Path $tempCip) { Remove-Item $tempCip -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host ''
