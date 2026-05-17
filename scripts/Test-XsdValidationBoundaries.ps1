#Requires -Version 5.1
<#
.SYNOPSIS
    Empirically test what ConvertFrom-CIPolicy enforces vs accepts during XML→binary compile.

.DESCRIPTION
    Authors four near-identical XML policies — one baseline + three variants with deliberate
    XSD-edge-case conditions — and reports which compile cleanly. The four variants:

      A. Baseline       — known-good content, no edge cases
      B. WithComment    — XML comment inside <Rules> (XML-lexical, not part of XSD infoset)
      C. WithBadOption  — Option value not in OptionType enum (XSD enum violation)
      D. WithUnknownAttr — unknown attribute on <Allow> element (XSD content-model violation)

    Expected per spec:
      A: COMPILE OK
      B: COMPILE OK (comments are XSD-transparent)
      C: COMPILE FAIL (enum violation)
      D: COMPILE FAIL (unknown attribute on closed type)

    The empirical result establishes the workspace's transparency-comment proposal's viability.
#>
param()

$ErrorActionPreference = 'Stop'

$tempDir = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($env:TEMP, "wdacking-xsd-test-$(Get-Random)"))
[System.IO.Directory]::CreateDirectory($tempDir) | Out-Null

$baseGuid = '{FADE0007-FADE-FADE-FADE-FADE0007FADE}'
$platformId = '{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}'

function New-PolicyXml {
    param([string]$RulesInner, [string]$AllowInner)
    @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>$platformId</PlatformID>
  <PolicyID>$baseGuid</PolicyID>
  <BasePolicyID>$baseGuid</BasePolicyID>
  <Rules>
$RulesInner
  </Rules>
  <EKUs />
  <FileRules>
    $AllowInner
  </FileRules>
  <Signers>
    <Signer ID="ID_SIGNER_S_1" Name="Signer1">
      <CertRoot Type="Wellknown" Value="03" />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario ID="ID_SIGNINGSCENARIO_DRIVERS" Value="131" FriendlyName="Drivers">
      <ProductSigners />
    </SigningScenario>
    <SigningScenario ID="ID_SIGNINGSCENARIO_USERMODE" Value="12" FriendlyName="User">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <HvciOptions>0</HvciOptions>
</SiPolicy>
"@
}

$baselineRules = @"
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
    <Rule><Option>Enabled:UMCI</Option></Rule>
"@

$variants = @(
    @{
        Label  = 'A. Baseline (control case)'
        Rules  = $baselineRules
        Allow  = '<Allow ID="ID_ALLOW_A_1" FileName="ctrl.dll" />'
    }
    @{
        Label  = 'B. WithComment inside <Rules>'
        Rules  = @"
    <!-- This is a probe comment inside Rules — XSD-transparent per spec -->
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
    <Rule><Option>Enabled:UMCI</Option></Rule>
"@
        Allow  = '<Allow ID="ID_ALLOW_A_1" FileName="commented.dll" />'
    }
    @{
        Label  = 'C. WithBadOption (enum violation)'
        Rules  = @"
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
    <Rule><Option>Enabled:DefinitelyNotARealOption</Option></Rule>
"@
        Allow  = '<Allow ID="ID_ALLOW_A_1" FileName="badopt.dll" />'
    }
    @{
        Label  = 'D. WithUnknownAttr on <Allow>'
        Rules  = $baselineRules
        Allow  = '<Allow ID="ID_ALLOW_A_1" FileName="unknownattr.dll" UnknownAttribute="test" />'
    }
)

Write-Host ''
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host 'ConvertFrom-CIPolicy XSD-validation boundary test' -ForegroundColor Cyan
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host ''

foreach ($v in $variants) {
    Write-Host ('-' * 100) -ForegroundColor DarkGray
    Write-Host "  $($v.Label)" -ForegroundColor White

    $xml = New-PolicyXml -RulesInner $v.Rules -AllowInner $v.Allow
    $xmlPath = [System.IO.Path]::Combine($tempDir, "$($v.Label.Substring(0, 1)).xml")
    $cipPath = [System.IO.Path]::Combine($tempDir, "$($v.Label.Substring(0, 1)).cip")

    [System.IO.File]::WriteAllText($xmlPath, $xml, [System.Text.UTF8Encoding]::new($true))

    try {
        ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cipPath -ErrorAction Stop | Out-Null
        $bytes = (Get-Item $cipPath).Length
        Write-Host "    COMPILE OK — $bytes bytes" -ForegroundColor Green
    }
    catch {
        Write-Host "    COMPILE FAILED" -ForegroundColor Red
        Write-Host "      $($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

# Cleanup
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
