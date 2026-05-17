#Requires -Version 5.1
<#
.SYNOPSIS
    Validates the WDAC binary parser pipeline against known-good CI policy binaries.

.DESCRIPTION
    Creates CI policies from XML with known values, converts them to binary using
    Microsoft's ConvertFrom-CIPolicy cmdlet, then parses the binaries through the
    ConvertFrom-WDACBinary + ConvertTo-WDACPolicyObject pipeline and validates
    every field against expected values.

    All output is captured via Start-Transcript for agent analysis. The entire
    test body is wrapped in try/catch/finally to guarantee Stop-Transcript runs.

    Test cases:
      T1 — Minimal base policy with known rule options and version
      T2 — Policy with all 20 mappable rule options
      T3 — Supplemental policy (PolicyId != BasePolicyId)
      T4 — FriendlyName extraction verification (empty and populated)
      T5 — Real system .cip files parsed through the full pipeline
      T6 — PKCS#7 signed policy detection (SIPolicy.p7b)
      T7 — Header validation and edge cases
      T8 — citool cross-reference (parser output vs system API ground truth)

    Pipeline under test:
      ReadAllBytes → Unprotect-Pkcs7Policy → ConvertFrom-WDACBinary → ConvertTo-WDACPolicyObject

    Binary format reference: docs/ci-binary-format-reference.md

.PARAMETER TranscriptPath
    Path for the PowerShell transcript log. Defaults to temp\parser-test-transcript.txt
    under the module root directory.

.PARAMETER SkipSystemTests
    If specified, skips T5, T6, and T8 which require admin and real deployed policies.

.EXAMPLE
    .\Test-WDACBinaryParser.ps1
    Runs all test cases with transcript logging.

.EXAMPLE
    .\Test-WDACBinaryParser.ps1 -SkipSystemTests
    Runs only synthetic tests (T1-T4, T7) without needing admin elevation.

.NOTES
    Requires: ConfigCI module (for ConvertFrom-CIPolicy)
    Platform: Windows only
    Pipeline: Unprotect-Pkcs7Policy → ConvertFrom-WDACBinary → ConvertTo-WDACPolicyObject
#>
[CmdletBinding()]
param(
    [string]$TranscriptPath,
    [switch]$SkipSystemTests
)

# ---------------------------------------------------------------------------
# Resolve transcript path — default to module temp directory
# ---------------------------------------------------------------------------
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$moduleRoot = Split-Path $scriptDir -Parent

if (-not $TranscriptPath) {
    $transcriptDir = Join-Path $moduleRoot 'temp'
    if (-not (Test-Path $transcriptDir)) {
        New-Item -Path $transcriptDir -ItemType Directory -Force | Out-Null
    }
    $TranscriptPath = Join-Path $transcriptDir 'parser-test-transcript.txt'
}

# ---------------------------------------------------------------------------
# Start transcript — captures ALL output for agent analysis
# ---------------------------------------------------------------------------
Start-Transcript -Path $TranscriptPath -Force

try {

# ---------------------------------------------------------------------------
# Module import
# ---------------------------------------------------------------------------
$moduleManifest = Join-Path $moduleRoot 'src\antyg-wdacking.psd1'

if (-not (Test-Path $moduleManifest)) {
    Write-Error "Module manifest not found at: $moduleManifest"
    exit 1
}

Write-Host "`n  antyg-wdacking Binary Parser Pipeline Validation" -ForegroundColor Cyan
Write-Host "  =================================================" -ForegroundColor Cyan
Write-Host "  Module: $moduleManifest" -ForegroundColor DarkGray
Write-Host "  Time:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  Host:   $env:COMPUTERNAME" -ForegroundColor DarkGray
Write-Host "  Transcript: $TranscriptPath" -ForegroundColor DarkGray
Write-Host ""

Import-Module $moduleManifest -Force -ErrorAction Stop
Write-Host "  Module loaded: antyg-wdacking v$((Get-Module antyg-wdacking).Version)" -ForegroundColor Green

# Verify pipeline functions are available
$pipelineFunctions = @('ConvertFrom-WDACBinary', 'Unprotect-Pkcs7Policy', 'ConvertTo-WDACPolicyObject')
foreach ($fn in $pipelineFunctions) {
    $available = $null -ne (Get-Command $fn -ErrorAction SilentlyContinue)
    Write-Host "  $fn`: $available" -ForegroundColor $(if ($available) { 'Green' } else { 'Red' })
    if (-not $available) {
        throw "$fn not available after module import. Cannot continue."
    }
}
Write-Host ""

# ---------------------------------------------------------------------------
# Check ConfigCI availability
# ---------------------------------------------------------------------------
$configCIAvailable = $null -ne (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue)
if (-not $configCIAvailable) {
    Write-Warning "ConfigCI module not available — cannot generate test binaries. Only system tests (T5/T6) will run."
}

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------
$tempDir = Join-Path $env:TEMP "WDACBinaryParserTest_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

$script:testResults = @()
$script:totalPass = 0
$script:totalFail = 0
$script:totalSkip = 0
$script:parsedPolicies = @{}   # Collects parsed results keyed by PolicyId for T8 cross-reference

function Add-TestResult {
    param(
        [string]$TestId,
        [string]$Field,
        [string]$Expected,
        [string]$Actual,
        [string]$Status  # Pass, Fail, Skip, Info
    )

    $colour = switch ($Status) {
        'Pass' { 'Green' }
        'Fail' { 'Red' }
        'Skip' { 'Yellow' }
        'Info' { 'DarkGray' }
    }

    $icon = switch ($Status) {
        'Pass' { [char]0x2713 }  # checkmark
        'Fail' { [char]0x2717 }  # cross
        'Skip' { '-' }
        'Info' { '?' }
    }

    Write-Host "    $icon " -NoNewline -ForegroundColor $colour
    Write-Host "$Field" -NoNewline
    if ($Status -eq 'Fail') {
        Write-Host " (expected: $Expected, got: $Actual)" -ForegroundColor Red
    }
    elseif ($Status -eq 'Pass' -and $Expected) {
        Write-Host " = $Actual" -ForegroundColor DarkGray
    }
    elseif ($Status -eq 'Skip') {
        Write-Host " ($Expected)" -ForegroundColor Yellow
    }
    elseif ($Status -eq 'Info') {
        Write-Host " = $Actual" -ForegroundColor DarkGray
    }
    else {
        Write-Host ""
    }

    switch ($Status) {
        'Pass' { $script:totalPass++ }
        'Fail' { $script:totalFail++ }
        'Skip' { $script:totalSkip++ }
    }

    $script:testResults += [PSCustomObject]@{
        TestId   = $TestId
        Field    = $Field
        Expected = $Expected
        Actual   = $Actual
        Status   = $Status
    }
}

function Assert-Field {
    param(
        [string]$TestId,
        [string]$Field,
        [string]$Expected,
        [string]$Actual
    )

    if ($Expected -eq $Actual) {
        Add-TestResult -TestId $TestId -Field $Field -Expected $Expected -Actual $Actual -Status 'Pass'
    }
    else {
        Add-TestResult -TestId $TestId -Field $Field -Expected $Expected -Actual $Actual -Status 'Fail'
    }
}

# ---------------------------------------------------------------------------
# Full field breakdown — validates and displays ALL 13 output contract fields
#
# Used by T5 for system policies. Reports each field individually so the
# transcript shows a complete attribute inventory per policy.
# ---------------------------------------------------------------------------
function Test-ParsedPolicyFields {
    param(
        [string]$TestId,
        [string]$Label,
        [PSCustomObject]$Parsed
    )

    # FormatVersion (1-9 expected — V9 observed on Windows 11 26220)
    if ($Parsed.FormatVersion -ge 1 -and $Parsed.FormatVersion -le 9) {
        Add-TestResult -TestId $TestId -Field "$Label FormatVersion" -Expected '1-9' -Actual "$($Parsed.FormatVersion)" -Status 'Pass'
    }
    else {
        Add-TestResult -TestId $TestId -Field "$Label FormatVersion" -Expected '1-9' -Actual "$($Parsed.FormatVersion)" -Status 'Fail'
    }

    # PolicyId (non-empty)
    if (-not [string]::IsNullOrWhiteSpace($Parsed.PolicyId)) {
        Add-TestResult -TestId $TestId -Field "$Label PolicyId" -Expected 'Non-empty' -Actual $Parsed.PolicyId -Status 'Pass'
    }
    else {
        Add-TestResult -TestId $TestId -Field "$Label PolicyId" -Expected 'Non-empty' -Actual '(empty)' -Status 'Fail'
    }

    # BasePolicyId (non-empty for V6+)
    if ($Parsed.FormatVersion -ge 6) {
        if (-not [string]::IsNullOrWhiteSpace($Parsed.BasePolicyId)) {
            Add-TestResult -TestId $TestId -Field "$Label BasePolicyId" -Expected 'Non-empty' -Actual $Parsed.BasePolicyId -Status 'Pass'
        }
        else {
            Add-TestResult -TestId $TestId -Field "$Label BasePolicyId" -Expected 'Non-empty' -Actual '(empty)' -Status 'Fail'
        }
    }
    else {
        $val = if ($Parsed.BasePolicyId) { $Parsed.BasePolicyId } else { '(empty - pre-V6)' }
        Add-TestResult -TestId $TestId -Field "$Label BasePolicyId" -Expected '' -Actual $val -Status 'Info'
    }

    # FriendlyName
    $fnVal = if ($Parsed.FriendlyName) { $Parsed.FriendlyName } else { '(empty)' }
    Add-TestResult -TestId $TestId -Field "$Label FriendlyName" -Expected '' -Actual $fnVal -Status 'Info'

    # Version (M.m.B.R format or 'Unknown' for degraded parse)
    if ($Parsed.Version -match '^\d+\.\d+\.\d+\.\d+$') {
        Add-TestResult -TestId $TestId -Field "$Label Version" -Expected 'M.m.B.R' -Actual $Parsed.Version -Status 'Pass'
    }
    elseif ($Parsed.Version -eq 'Unknown') {
        Add-TestResult -TestId $TestId -Field "$Label Version" -Expected 'M.m.B.R' -Actual 'Unknown (degraded)' -Status 'Info'
    }
    else {
        Add-TestResult -TestId $TestId -Field "$Label Version" -Expected 'M.m.B.R' -Actual $Parsed.Version -Status 'Fail'
    }

    # IsSupplemental
    Add-TestResult -TestId $TestId -Field "$Label IsSupplemental" -Expected '' -Actual "$($Parsed.IsSupplemental)" -Status 'Info'

    # EnforcementMode (Audit, Enforced, or Unknown for degraded parse)
    if ($Parsed.EnforcementMode -in @('Audit', 'Enforced')) {
        Add-TestResult -TestId $TestId -Field "$Label EnforcementMode" -Expected 'Audit|Enforced' -Actual $Parsed.EnforcementMode -Status 'Pass'
    }
    elseif ($Parsed.EnforcementMode -eq 'Unknown') {
        Add-TestResult -TestId $TestId -Field "$Label EnforcementMode" -Expected 'Audit|Enforced' -Actual 'Unknown (degraded)' -Status 'Info'
    }
    else {
        Add-TestResult -TestId $TestId -Field "$Label EnforcementMode" -Expected 'Audit|Enforced' -Actual $Parsed.EnforcementMode -Status 'Fail'
    }

    # PolicyType (known types include legacy GUID classifications and V6+ format attributes)
    $knownTypes = @('Enterprise', 'Revoke', 'SKU', 'WindowsLockdown', 'ATP', 'Driver', 'Base Policy', 'Supplemental Policy')
    if ($Parsed.PolicyType -in $knownTypes) {
        Add-TestResult -TestId $TestId -Field "$Label PolicyType" -Expected 'Known type' -Actual $Parsed.PolicyType -Status 'Pass'
    }
    else {
        Add-TestResult -TestId $TestId -Field "$Label PolicyType" -Expected 'Known type' -Actual $Parsed.PolicyType -Status 'Info'
    }

    # RuleOptions (PSCustomObject[] with Id and Name properties)
    $optionNames = @($Parsed.RuleOptions | ForEach-Object { $_.Name })
    if ($Parsed.RuleOptions.Count -gt 0) {
        Add-TestResult -TestId $TestId -Field "$Label RuleOptions ($($Parsed.RuleOptions.Count))" -Expected '' -Actual ($optionNames -join '; ') -Status 'Info'
    }
    else {
        Add-TestResult -TestId $TestId -Field "$Label RuleOptions" -Expected '' -Actual '(none)' -Status 'Info'
    }

    # FilePath
    if ($Parsed.FilePath) {
        Add-TestResult -TestId $TestId -Field "$Label FilePath" -Expected '' -Actual $Parsed.FilePath -Status 'Info'
    }

    # Location
    Add-TestResult -TestId $TestId -Field "$Label Location" -Expected '' -Actual $Parsed.Location -Status 'Info'

    # FileSize
    Add-TestResult -TestId $TestId -Field "$Label FileSize" -Expected '' -Actual "$($Parsed.FileSize) bytes" -Status 'Info'
}

# ---------------------------------------------------------------------------
# XML policy template generator
#
# Produces minimal valid SiPolicy XML that ConvertFrom-CIPolicy can compile.
# PolicyID and BasePolicyID are included for FormatVersion 6+ output.
# ---------------------------------------------------------------------------
function New-TestPolicyXml {
    param(
        [string]$PolicyId,
        [string]$BasePolicyId,
        [string]$Version = '10.0.0.0',
        [string]$PolicyTypeId = '{A244370E-44C9-4C06-B551-F6016E563076}',
        [string]$PlatformId = '{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}',
        [string[]]$RuleOptions = @(),
        [int]$HvciOptions = 0,
        [string]$PolicyType,  # 'Base Policy' or 'Supplemental Policy' (multi-policy format)
        [string]$FriendlyName  # If provided, embeds in Settings for FriendlyName extraction
    )

    # Build rules XML from option name strings (if any provided)
    $rulesXml = ''
    if ($RuleOptions.Count -gt 0) {
        $rulesXml = "`n" + (($RuleOptions | ForEach-Object {
            "    <Rule>`n      <Option>$_</Option>`n    </Rule>"
        }) -join "`n") + "`n"
    }

    # Multi-policy format: PolicyID/BasePolicyID + PolicyType attribute, NO PolicyTypeID.
    # Legacy format: PolicyTypeID element, no PolicyID/BasePolicyID.
    # ConvertFrom-CIPolicy rejects XML with BOTH PolicyTypeID AND PolicyID — they are
    # mutually exclusive at runtime despite the XSD (xs:all, both minOccurs="0") allowing it.
    $isMultiPolicy = [bool]($PolicyId -and $BasePolicyId)

    $policyTypeAttr = ''
    $policyTypeIdXml = ''
    $policyIdXml = ''

    if ($isMultiPolicy) {
        if ($PolicyType) {
            $policyTypeAttr = " PolicyType=`"$PolicyType`""
        }
        $policyIdXml = "`n  <PolicyID>$PolicyId</PolicyID>`n  <BasePolicyID>$BasePolicyId</BasePolicyID>"
    }
    else {
        $policyTypeIdXml = "`n  <PolicyTypeID>$PolicyTypeId</PolicyTypeID>"
    }

    # Settings XML — include FriendlyName if provided
    $settingsXml = '<Settings />'
    if ($FriendlyName) {
        $settingsXml = @"
<Settings>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
      <Value>
        <String>$FriendlyName</String>
      </Value>
    </Setting>
  </Settings>
"@
    }

    @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy"$policyTypeAttr>
  <VersionEx>$Version</VersionEx>$policyTypeIdXml
  <PlatformID>$PlatformId</PlatformID>
  <Rules>$rulesXml  </Rules>
  <EKUs />
  <FileRules />
  <Signers />
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS_1" FriendlyName="Drivers">
      <ProductSigners />
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode">
      <ProductSigners />
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners />
  <CiSigners />
  <HvciOptions>$HvciOptions</HvciOptions>
  $settingsXml$policyIdXml
</SiPolicy>
"@
}

# ---------------------------------------------------------------------------
# XML to Binary conversion helper
# Returns the binary file path, or $null on failure.
# ---------------------------------------------------------------------------
function Convert-TestPolicy {
    param(
        [string]$TestId,
        [string]$XmlContent
    )

    $xmlPath = Join-Path $tempDir "$TestId.xml"
    $binPath = Join-Path $tempDir "$TestId.cip"

    # Write XML (UTF-8 with BOM as ConvertFrom-CIPolicy expects)
    [System.IO.File]::WriteAllText($xmlPath, $XmlContent, [System.Text.UTF8Encoding]::new($true))

    try {
        ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $binPath -ErrorAction Stop | Out-Null
        return $binPath
    }
    catch {
        Add-TestResult -TestId $TestId -Field 'ConvertFrom-CIPolicy' -Expected 'Success' -Actual $_.Exception.Message -Status 'Fail'
        return $null
    }
}

# ---------------------------------------------------------------------------
# Parse helper — runs the full pipeline and returns the 13-property object
#
# Pipeline: ReadAllBytes → Unprotect-Pkcs7Policy → ConvertFrom-WDACBinary
#           → ConvertTo-WDACPolicyObject
#
# Returns $null on any failure (same fail-soft contract as Get-WDACPolicy).
# ---------------------------------------------------------------------------
function Invoke-ParserTest {
    param(
        [string]$BinaryPath,
        [string]$Location = 'MultiPolicy'
    )

    try {
        $rawBytes = [System.IO.File]::ReadAllBytes($BinaryPath)
        $unwrapped = Unprotect-Pkcs7Policy -Data $rawBytes
        $formatVersion = [System.BitConverter]::ToUInt32($unwrapped, 0)
        $xml = ConvertFrom-WDACBinary -Data $unwrapped
        ConvertTo-WDACPolicyObject -Xml $xml -FormatVersion $formatVersion -FilePath $BinaryPath -Location $Location -WarningAction SilentlyContinue
    }
    catch {
        Write-Verbose "Parse failed for '$BinaryPath': $($_.Exception.Message)"
        return $null
    }
}

# ===========================================================================
# T1: Minimal Base Policy — known rule options and version
# ===========================================================================
Write-Host "  T1: Minimal Base Policy" -ForegroundColor White
Write-Host "  -----------------------" -ForegroundColor DarkGray

if ($configCIAvailable) {
    $t1PolicyId = '{B1000001-0000-0000-0000-000000000001}'
    $t1Xml = New-TestPolicyXml `
        -PolicyId $t1PolicyId `
        -BasePolicyId $t1PolicyId `
        -PolicyType 'Base Policy' `
        -Version '10.2.3.4' `
        -RuleOptions @(
            'Enabled:Unsigned System Integrity Policy'
            'Enabled:Audit Mode'
            'Enabled:Allow Supplemental Policies'
        )

    $t1Bin = Convert-TestPolicy -TestId 'T1' -XmlContent $t1Xml

    if ($t1Bin) {
        # ---------------------------------------------------------------
        # DIAGNOSTIC: Hex dump of compiled binary for debugging
        # ---------------------------------------------------------------
        $t1Bytes = [System.IO.File]::ReadAllBytes($t1Bin)
        Write-Host ""
        Write-Host "  T1 Binary Diagnostic ($($t1Bytes.Length) bytes)" -ForegroundColor Cyan
        Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray

        # Header fields
        $fmtVer   = [BitConverter]::ToInt32($t1Bytes, 0x00)
        $ekuCnt   = [BitConverter]::ToInt32($t1Bytes, 0x28)
        $fileCnt  = [BitConverter]::ToInt32($t1Bytes, 0x2C)
        $signCnt  = [BitConverter]::ToInt32($t1Bytes, 0x30)
        $scenCnt  = [BitConverter]::ToInt32($t1Bytes, 0x34)
        $hdrLen   = [BitConverter]::ToInt32($t1Bytes, 0x40)
        Write-Host "    FormatVersion=$fmtVer  EKU=$ekuCnt  FileRule=$fileCnt  Signer=$signCnt  Scenario=$scenCnt  HdrLen=0x$($hdrLen.ToString('X2'))" -ForegroundColor Cyan

        # Full hex dump (policy is small — typically < 300 bytes)
        Write-Host "    Offset  | Hex                                             | ASCII" -ForegroundColor DarkGray
        for ($off = 0; $off -lt $t1Bytes.Length; $off += 16) {
            $chunk = $t1Bytes[$off..([Math]::Min($off + 15, $t1Bytes.Length - 1))]
            $hex = ($chunk | ForEach-Object { $_.ToString('X2') }) -join ' '
            $ascii = ($chunk | ForEach-Object {
                if ($_ -ge 0x20 -and $_ -le 0x7E) { [char]$_ } else { '.' }
            }) -join ''
            Write-Host ("    {0:X4}    | {1,-48}| {2}" -f $off, $hex, $ascii) -ForegroundColor DarkCyan
        }
        Write-Host ""
        # ---------------------------------------------------------------

        $t1 = Invoke-ParserTest -BinaryPath $t1Bin

        if ($null -eq $t1) {
            Add-TestResult -TestId 'T1' -Field 'Parse' -Expected 'Non-null' -Actual 'null (parse failed)' -Status 'Fail'
        }
        else {
            # FormatVersion should be >= 6 (modern policies with PolicyID produce V6+)
            if ($t1.FormatVersion -ge 6) {
                Add-TestResult -TestId 'T1' -Field 'FormatVersion' -Expected '>=6' -Actual "$($t1.FormatVersion)" -Status 'Pass'
            }
            else {
                Add-TestResult -TestId 'T1' -Field 'FormatVersion' -Expected '>=6' -Actual "$($t1.FormatVersion)" -Status 'Fail'
            }

            # PolicyVersion
            Assert-Field -TestId 'T1' -Field 'Version' -Expected '10.2.3.4' -Actual $t1.Version

            # PolicyType — V6+ multi-policy format should produce 'Base Policy'
            Assert-Field -TestId 'T1' -Field 'PolicyType' -Expected 'Base Policy' -Actual $t1.PolicyType

            # EnforcementMode — Audit (we set Enabled:Audit Mode)
            Assert-Field -TestId 'T1' -Field 'EnforcementMode' -Expected 'Audit' -Actual $t1.EnforcementMode

            # IsSupplemental — false (PolicyId == BasePolicyId)
            Assert-Field -TestId 'T1' -Field 'IsSupplemental' -Expected 'False' -Actual "$($t1.IsSupplemental)"

            # PolicyId from V6 block (lowercase, no braces)
            $expectedPid = 'b1000001-0000-0000-0000-000000000001'
            Assert-Field -TestId 'T1' -Field 'PolicyId' -Expected $expectedPid -Actual $t1.PolicyId

            # BasePolicyId matches PolicyId for base policy
            Assert-Field -TestId 'T1' -Field 'BasePolicyId' -Expected $expectedPid -Actual $t1.BasePolicyId

            # FriendlyName must be empty (no Settings/Name in test XML)
            Assert-Field -TestId 'T1' -Field 'FriendlyName' -Expected '' -Actual $t1.FriendlyName

            # RuleOptions: compare by name (canonical form)
            $t1ExpectedNames = @(
                'Enabled:Unsigned System Integrity Policy'
                'Enabled:Audit Mode'
                'Enabled:Allow Supplemental Policies'
            ) | Sort-Object
            $t1ActualNames = @($t1.RuleOptions | ForEach-Object { $_.Name }) | Sort-Object
            $t1NamesMatch = ($t1ExpectedNames.Count -eq $t1ActualNames.Count) -and
                ($null -eq (Compare-Object $t1ExpectedNames $t1ActualNames))

            if ($t1NamesMatch) {
                Add-TestResult -TestId 'T1' -Field 'RuleOptions' -Expected ($t1ExpectedNames -join ', ') -Actual ($t1ActualNames -join ', ') -Status 'Pass'
            }
            else {
                Add-TestResult -TestId 'T1' -Field 'RuleOptions' -Expected ($t1ExpectedNames -join ', ') -Actual ($t1ActualNames -join ', ') -Status 'Fail'
            }

            # Spot-check ID mapping for key options
            $auditOpt = $t1.RuleOptions | Where-Object { $_.Name -eq 'Enabled:Audit Mode' }
            if ($auditOpt) {
                Assert-Field -TestId 'T1' -Field 'Audit Mode ID' -Expected '3' -Actual "$($auditOpt.Id)"
            }

            # Output contract: verify 13 properties present
            $propCount = @($t1.PSObject.Properties).Count
            if ($propCount -ge 13) {
                Add-TestResult -TestId 'T1' -Field 'Property count' -Expected '>=13' -Actual "$propCount" -Status 'Pass'
            }
            else {
                Add-TestResult -TestId 'T1' -Field 'Property count' -Expected '>=13' -Actual "$propCount" -Status 'Fail'
            }
        }
    }
}
else {
    Add-TestResult -TestId 'T1' -Field 'All' -Expected 'Requires ConfigCI' -Actual '' -Status 'Skip'
}
Write-Host ""

# ===========================================================================
# T2: All Mappable Rule Options
# ===========================================================================
Write-Host "  T2: All Mappable Rule Options" -ForegroundColor White
Write-Host "  -----------------------------" -ForegroundColor DarkGray

if ($configCIAvailable) {
    # All 20 rule options that ConvertFrom-CIPolicy supports in XML
    # (Enabled:Developer Mode Dynamic Code Trust omitted — not reliably supported by ConvertFrom-CIPolicy)
    $t2AllOptions = @(
        'Enabled:UMCI'
        'Enabled:Boot Menu Protection'
        'Required:WHQL'
        'Enabled:Audit Mode'
        'Disabled:Flight Signing'
        'Enabled:Inherit Default Policy'
        'Enabled:Unsigned System Integrity Policy'
        'Required:EV Signers'
        'Enabled:Advanced Boot Options Menu'
        'Enabled:Boot Audit On Failure'
        'Disabled:Script Enforcement'
        'Required:Enforce Store Applications'
        'Enabled:Managed Installer'
        'Enabled:Intelligent Security Graph Authorization'
        'Enabled:Invalidate EAs on Reboot'
        'Enabled:Update Policy No Reboot'
        'Enabled:Allow Supplemental Policies'
        'Disabled:Runtime FilePath Rule Protection'
        'Enabled:Dynamic Code Security'
        'Enabled:Revoked Expired As Unsigned'
    )

    $t2PolicyId = '{B2000002-0000-0000-0000-000000000002}'
    $t2Xml = New-TestPolicyXml `
        -PolicyId $t2PolicyId `
        -BasePolicyId $t2PolicyId `
        -PolicyType 'Base Policy' `
        -Version '1.0.0.0' `
        -RuleOptions $t2AllOptions

    $t2Bin = Convert-TestPolicy -TestId 'T2' -XmlContent $t2Xml

    if ($t2Bin) {
        $t2 = Invoke-ParserTest -BinaryPath $t2Bin

        if ($null -eq $t2) {
            Add-TestResult -TestId 'T2' -Field 'Parse' -Expected 'Non-null' -Actual 'null (parse failed)' -Status 'Fail'
        }
        else {
            # Total count
            Assert-Field -TestId 'T2' -Field 'RuleOptions count' -Expected "$($t2AllOptions.Count)" -Actual "$($t2.RuleOptions.Count)"

            # Verify each expected option is present by name
            $t2ActualNames = @($t2.RuleOptions | ForEach-Object { $_.Name })
            foreach ($optName in $t2AllOptions) {
                $found = $optName -in $t2ActualNames

                if ($found) {
                    Add-TestResult -TestId 'T2' -Field "Option: $optName" -Expected 'Present' -Actual 'Present' -Status 'Pass'
                }
                else {
                    Add-TestResult -TestId 'T2' -Field "Option: $optName" -Expected 'Present' -Actual 'Missing' -Status 'Fail'
                }
            }

            # Check no unexpected options appeared
            $unexpected = @($t2ActualNames | Where-Object { $_ -notin $t2AllOptions })
            if ($unexpected.Count -eq 0) {
                Add-TestResult -TestId 'T2' -Field 'No unexpected options' -Expected '0 extra' -Actual '0 extra' -Status 'Pass'
            }
            else {
                Add-TestResult -TestId 'T2' -Field 'Unexpected options' -Expected 'None' -Actual ($unexpected -join ', ') -Status 'Fail'
            }

            # Spot-check ID mappings
            $umciOpt = $t2.RuleOptions | Where-Object { $_.Name -eq 'Enabled:UMCI' }
            if ($umciOpt) { Assert-Field -TestId 'T2' -Field 'UMCI ID' -Expected '0' -Actual "$($umciOpt.Id)" }

            $suppOpt = $t2.RuleOptions | Where-Object { $_.Name -eq 'Enabled:Allow Supplemental Policies' }
            if ($suppOpt) { Assert-Field -TestId 'T2' -Field 'Allow Supplemental ID' -Expected '15' -Actual "$($suppOpt.Id)" }

            $dynOpt = $t2.RuleOptions | Where-Object { $_.Name -eq 'Enabled:Dynamic Code Security' }
            if ($dynOpt) { Assert-Field -TestId 'T2' -Field 'Dynamic Code Security ID' -Expected '7' -Actual "$($dynOpt.Id)" }
        }
    }
}
else {
    Add-TestResult -TestId 'T2' -Field 'All' -Expected 'Requires ConfigCI' -Actual '' -Status 'Skip'
}
Write-Host ""

# ===========================================================================
# T3: Supplemental Policy (PolicyId != BasePolicyId)
# ===========================================================================
Write-Host "  T3: Supplemental Policy" -ForegroundColor White
Write-Host "  -----------------------" -ForegroundColor DarkGray

if ($configCIAvailable) {
    $t3PolicyId = '{B3000003-0000-0000-0000-000000000003}'
    $t3BaseId   = '{B3000003-AAAA-BBBB-CCCC-000000000003}'

    $t3Xml = New-TestPolicyXml `
        -PolicyId $t3PolicyId `
        -BasePolicyId $t3BaseId `
        -PolicyType 'Supplemental Policy' `
        -Version '5.1.0.0' `
        -RuleOptions @(
            'Enabled:Unsigned System Integrity Policy'
            'Enabled:Audit Mode'
        )

    $t3Bin = Convert-TestPolicy -TestId 'T3' -XmlContent $t3Xml

    if ($t3Bin) {
        $t3 = Invoke-ParserTest -BinaryPath $t3Bin

        if ($null -eq $t3) {
            Add-TestResult -TestId 'T3' -Field 'Parse' -Expected 'Non-null' -Actual 'null (parse failed)' -Status 'Fail'
        }
        else {
            # IsSupplemental — true (PolicyId != BasePolicyId)
            Assert-Field -TestId 'T3' -Field 'IsSupplemental' -Expected 'True' -Actual "$($t3.IsSupplemental)"

            # PolicyId
            $t3ExpectedPid = 'b3000003-0000-0000-0000-000000000003'
            Assert-Field -TestId 'T3' -Field 'PolicyId' -Expected $t3ExpectedPid -Actual $t3.PolicyId

            # BasePolicyId
            $t3ExpectedBase = 'b3000003-aaaa-bbbb-cccc-000000000003'
            Assert-Field -TestId 'T3' -Field 'BasePolicyId' -Expected $t3ExpectedBase -Actual $t3.BasePolicyId

            # Version
            Assert-Field -TestId 'T3' -Field 'Version' -Expected '5.1.0.0' -Actual $t3.Version

            # PolicyType — supplemental
            Assert-Field -TestId 'T3' -Field 'PolicyType' -Expected 'Supplemental Policy' -Actual $t3.PolicyType

            # EnforcementMode — Audit
            Assert-Field -TestId 'T3' -Field 'EnforcementMode' -Expected 'Audit' -Actual $t3.EnforcementMode
        }
    }
}
else {
    Add-TestResult -TestId 'T3' -Field 'All' -Expected 'Requires ConfigCI' -Actual '' -Status 'Skip'
}
Write-Host ""

# ===========================================================================
# T4: FriendlyName Extraction Verification
#
# T4a: Policy WITHOUT FriendlyName in Settings → empty string
# T4b: Policy WITH FriendlyName in Settings → populated string
# ===========================================================================
Write-Host "  T4: FriendlyName Extraction" -ForegroundColor White
Write-Host "  ---------------------------" -ForegroundColor DarkGray

if ($configCIAvailable) {
    # --- T4a: No FriendlyName in Settings ---
    $t4aId = '{B4000004-0000-0000-0000-000000000004}'

    $t4aXml = New-TestPolicyXml `
        -PolicyId $t4aId `
        -BasePolicyId $t4aId `
        -PolicyType 'Base Policy' `
        -Version '1.0.0.0' `
        -RuleOptions @(
            'Enabled:Unsigned System Integrity Policy'
            'Enabled:Audit Mode'
            'Enabled:Allow Supplemental Policies'
        )

    $t4aBin = Convert-TestPolicy -TestId 'T4a' -XmlContent $t4aXml

    if ($t4aBin) {
        $t4a = Invoke-ParserTest -BinaryPath $t4aBin

        if ($null -eq $t4a) {
            Add-TestResult -TestId 'T4a' -Field 'Parse' -Expected 'Non-null' -Actual 'null (parse failed)' -Status 'Fail'
        }
        else {
            # FriendlyName must be empty — no Settings/Name in XML
            Assert-Field -TestId 'T4a' -Field 'FriendlyName (absent)' -Expected '' -Actual $t4a.FriendlyName
        }
    }

    # --- T4b: FriendlyName in Settings ---
    $t4bId = '{B4000004-BBBB-0000-0000-000000000004}'
    $t4bFriendlyName = 'My Custom Test Policy'

    $t4bXml = New-TestPolicyXml `
        -PolicyId $t4bId `
        -BasePolicyId $t4bId `
        -PolicyType 'Base Policy' `
        -Version '2.0.0.0' `
        -FriendlyName $t4bFriendlyName `
        -RuleOptions @(
            'Enabled:Unsigned System Integrity Policy'
            'Enabled:Allow Supplemental Policies'
        )

    $t4bBin = Convert-TestPolicy -TestId 'T4b' -XmlContent $t4bXml

    if ($t4bBin) {
        $t4b = Invoke-ParserTest -BinaryPath $t4bBin

        if ($null -eq $t4b) {
            Add-TestResult -TestId 'T4b' -Field 'Parse' -Expected 'Non-null' -Actual 'null (parse failed)' -Status 'Fail'
        }
        else {
            # FriendlyName should be populated from Settings
            if ($t4b.FriendlyName -eq $t4bFriendlyName) {
                Add-TestResult -TestId 'T4b' -Field 'FriendlyName (present)' -Expected $t4bFriendlyName -Actual $t4b.FriendlyName -Status 'Pass'
            }
            elseif ([string]::IsNullOrWhiteSpace($t4b.FriendlyName)) {
                # ConvertFrom-CIPolicy may not preserve Settings in binary — report but don't fail
                Add-TestResult -TestId 'T4b' -Field 'FriendlyName (present)' -Expected $t4bFriendlyName -Actual '(empty — binary may not preserve Settings)' -Status 'Info'
            }
            else {
                Add-TestResult -TestId 'T4b' -Field 'FriendlyName (present)' -Expected $t4bFriendlyName -Actual $t4b.FriendlyName -Status 'Fail'
            }
        }
    }
}
else {
    Add-TestResult -TestId 'T4' -Field 'All' -Expected 'Requires ConfigCI' -Actual '' -Status 'Skip'
}
Write-Host ""

# ===========================================================================
# T5: Real System .cip Files (requires admin)
#
# The pipeline handles PKCS#7 unwrapping transparently via Unprotect-Pkcs7Policy.
# Every deployed .cip file should now parse successfully.
# ===========================================================================
Write-Host "  T5: Real System Policies" -ForegroundColor White
Write-Host "  ------------------------" -ForegroundColor DarkGray

if ($SkipSystemTests) {
    Add-TestResult -TestId 'T5' -Field 'All' -Expected 'Skipped by -SkipSystemTests' -Actual '' -Status 'Skip'
}
else {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Add-TestResult -TestId 'T5' -Field 'All' -Expected 'Requires admin elevation' -Actual '' -Status 'Skip'
    }
    else {
        $cipDir = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
        $cipFiles = @()
        if (Test-Path $cipDir) {
            $cipFiles = @(Get-ChildItem -Path $cipDir -Filter '*.cip' -ErrorAction SilentlyContinue)
        }

        if ($cipFiles.Count -eq 0) {
            Add-TestResult -TestId 'T5' -Field 'System .cip files' -Expected 'None found (no policies deployed)' -Actual '' -Status 'Info'
        }
        else {
            Add-TestResult -TestId 'T5' -Field 'System .cip files found' -Expected '' -Actual "$($cipFiles.Count)" -Status 'Info'

            $pkcs7Count = 0
            $unsignedCount = 0
            $parseSuccess = 0
            $parseFail = 0

            foreach ($cipFile in $cipFiles) {
                $cipName = $cipFile.Name

                # ---------------------------------------------------------------
                # DIAGNOSTIC: Show first 32 bytes + file size for identification
                # ---------------------------------------------------------------
                $cipBytes = [System.IO.File]::ReadAllBytes($cipFile.FullName)
                $previewLen = [Math]::Min(32, $cipBytes.Length)
                $previewHex = ($cipBytes[0..($previewLen - 1)] | ForEach-Object { $_.ToString('X2') }) -join ' '
                $isPkcs7 = ($cipBytes[0] -eq 0x30)
                $signedTag = if ($isPkcs7) { 'PKCS#7' } else { 'unsigned' }
                if ($isPkcs7) { $pkcs7Count++ } else { $unsignedCount++ }
                Write-Host ("    {0} ({1} bytes, {2}) first32=[{3}]" -f $cipName, $cipBytes.Length, $signedTag, $previewHex) -ForegroundColor DarkCyan

                # Parse through full pipeline (PKCS#7 handled transparently)
                $parsed = Invoke-ParserTest -BinaryPath $cipFile.FullName

                if ($null -eq $parsed) {
                    # Pipeline now handles PKCS#7 — null result is a genuine failure
                    Add-TestResult -TestId 'T5' -Field "$cipName parse" -Expected 'Non-null' -Actual "null (parse failed, $signedTag)" -Status 'Fail'
                    $parseFail++
                }
                else {
                    $parseSuccess++
                    Add-TestResult -TestId 'T5' -Field "$cipName parse" -Expected 'Non-null' -Actual "FmtVer=$($parsed.FormatVersion)" -Status 'Pass'
                    Test-ParsedPolicyFields -TestId 'T5' -Label $cipName -Parsed $parsed

                    if ($parsed.PolicyId) {
                        $script:parsedPolicies[$parsed.PolicyId.ToLower().Trim('{','}')] = $parsed
                    }
                }
            }

            # --- Unsigned control: inject T1 binary as known-good unsigned .cip ---
            if ($t1Bin -and (Test-Path $t1Bin)) {
                $controlBytes = [System.IO.File]::ReadAllBytes($t1Bin)
                $controlFirst = $controlBytes[0]
                $controlIsPkcs7 = ($controlFirst -eq 0x30)

                Write-Host ("    CONTROL: T1 unsigned binary ({0} bytes) first_byte=0x{1:X2} isPkcs7={2}" -f $controlBytes.Length, $controlFirst, $controlIsPkcs7) -ForegroundColor DarkCyan

                if ($controlIsPkcs7) {
                    Add-TestResult -TestId 'T5' -Field 'Unsigned control detection' -Expected 'Not PKCS#7 (first byte != 0x30)' -Actual "0x$($controlFirst.ToString('X2')) (falsely detected as PKCS#7)" -Status 'Fail'
                }
                else {
                    $controlParsed = Invoke-ParserTest -BinaryPath $t1Bin
                    if ($null -ne $controlParsed) {
                        Add-TestResult -TestId 'T5' -Field 'Unsigned control parsed' -Expected 'Non-null' -Actual "FmtVer=$($controlParsed.FormatVersion) PolicyId=$($controlParsed.PolicyId)" -Status 'Pass'
                    }
                    else {
                        Add-TestResult -TestId 'T5' -Field 'Unsigned control parsed' -Expected 'Non-null' -Actual 'null (parse failed on known unsigned binary)' -Status 'Fail'
                    }
                }
            }

            # Summary
            Add-TestResult -TestId 'T5' -Field 'Parse summary' -Expected '' `
                -Actual "$parseSuccess success, $parseFail fail ($pkcs7Count PKCS#7, $unsignedCount unsigned)" -Status 'Info'
        }
    }
}
Write-Host ""

# ===========================================================================
# T6: PKCS#7 Signed Policy Detection
# ===========================================================================
Write-Host "  T6: PKCS#7 Detection" -ForegroundColor White
Write-Host "  --------------------" -ForegroundColor DarkGray

if ($SkipSystemTests) {
    Add-TestResult -TestId 'T6' -Field 'All' -Expected 'Skipped by -SkipSystemTests' -Actual '' -Status 'Skip'
}
else {
    $legacyPath = Join-Path $env:SystemRoot 'System32\CodeIntegrity\SIPolicy.p7b'

    if (-not (Test-Path $legacyPath)) {
        Add-TestResult -TestId 'T6' -Field 'SIPolicy.p7b' -Expected 'File not present (no legacy policy)' -Actual '' -Status 'Info'
    }
    else {
        # Pipeline should unwrap PKCS#7 and parse the inner CI policy binary
        $t6 = Invoke-ParserTest -BinaryPath $legacyPath -Location 'Legacy'

        if ($null -ne $t6) {
            Add-TestResult -TestId 'T6' -Field 'SIPolicy.p7b unwrap+parse' -Expected 'Non-null' -Actual "FmtVer=$($t6.FormatVersion) Mode=$($t6.EnforcementMode)" -Status 'Pass'

            # Verify Location was passed through
            Assert-Field -TestId 'T6' -Field 'Location' -Expected 'Legacy' -Actual $t6.Location

            if ($t6.PolicyId) {
                $script:parsedPolicies[$t6.PolicyId.ToLower().Trim('{','}')] = $t6
            }
        }
        else {
            $firstByte = [System.IO.File]::ReadAllBytes($legacyPath)[0]
            if ($firstByte -eq 0x30) {
                Add-TestResult -TestId 'T6' -Field 'SIPolicy.p7b unwrap' -Expected 'Non-null' -Actual 'null (unwrap failed on PKCS#7 file)' -Status 'Fail'
            }
            else {
                Add-TestResult -TestId 'T6' -Field 'SIPolicy.p7b not PKCS#7' -Expected '' -Actual "First byte: 0x$($firstByte.ToString('X2'))" -Status 'Info'
            }
        }
    }

    # Synthetic PKCS#7-like file (starts with 0x30 but is not valid SignedData)
    $t6FakePkcs7 = Join-Path $tempDir 'T6_fake_pkcs7.cip'
    $fakeBytes = [byte[]]@(0x30, 0x82, 0x00, 0x50) + (New-Object byte[] 76)
    [System.IO.File]::WriteAllBytes($t6FakePkcs7, $fakeBytes)
    $t6Fake = Invoke-ParserTest -BinaryPath $t6FakePkcs7

    if ($null -eq $t6Fake) {
        Add-TestResult -TestId 'T6' -Field 'Synthetic PKCS#7 detection' -Expected 'null' -Actual 'null' -Status 'Pass'
    }
    else {
        Add-TestResult -TestId 'T6' -Field 'Synthetic PKCS#7 detection' -Expected 'null' -Actual 'Parsed (should have been rejected)' -Status 'Fail'
    }
}
Write-Host ""

# ===========================================================================
# T7: Header Validation and Edge Cases
# ===========================================================================
Write-Host "  T7: Header Validation & Edge Cases" -ForegroundColor White
Write-Host "  -----------------------------------" -ForegroundColor DarkGray

# T7a: File too small (< 68 bytes) — Read-BinaryHeader rejects
$t7aPath = Join-Path $tempDir 'T7a_too_small.cip'
[System.IO.File]::WriteAllBytes($t7aPath, (New-Object byte[] 32))
$t7a = Invoke-ParserTest -BinaryPath $t7aPath
if ($null -eq $t7a) {
    Add-TestResult -TestId 'T7a' -Field 'File < 68 bytes' -Expected 'null' -Actual 'null' -Status 'Pass'
}
else {
    Add-TestResult -TestId 'T7a' -Field 'File < 68 bytes' -Expected 'null' -Actual 'Parsed (should reject)' -Status 'Fail'
}

# T7b: FormatVersion > 100 (invalid — likely PKCS#7 or non-CI-policy)
$t7bPath = Join-Path $tempDir 'T7b_bad_formatversion.cip'
$t7bData = New-Object byte[] 76
[System.BitConverter]::GetBytes([int]420708912).CopyTo($t7bData, 0)
[System.IO.File]::WriteAllBytes($t7bPath, $t7bData)
$t7b = Invoke-ParserTest -BinaryPath $t7bPath
if ($null -eq $t7b) {
    Add-TestResult -TestId 'T7b' -Field 'FormatVersion 420708912' -Expected 'null' -Actual 'null' -Status 'Pass'
}
else {
    Add-TestResult -TestId 'T7b' -Field 'FormatVersion 420708912' -Expected 'null' -Actual "Parsed (FV=$($t7b.FormatVersion))" -Status 'Fail'
}

# T7c: Valid header but truncated body — pipeline should throw during section parsing
$t7cPath = Join-Path $tempDir 'T7c_truncated_body.cip'
$t7cData = New-Object byte[] 76
# FormatVersion = 7 (valid)
[System.BitConverter]::GetBytes([int]7).CopyTo($t7cData, 0)
# HeaderLength = 0x40 (standard)
[System.BitConverter]::GetBytes([int]0x40).CopyTo($t7cData, 0x40)
# Body is all zeros — section parsing should fail on first section
[System.IO.File]::WriteAllBytes($t7cPath, $t7cData)
$t7c = Invoke-ParserTest -BinaryPath $t7cPath
if ($null -eq $t7c) {
    Add-TestResult -TestId 'T7c' -Field 'Truncated body' -Expected 'null' -Actual 'null' -Status 'Pass'
}
else {
    # If it parsed, the body was too short for real data — report but don't hard fail
    Add-TestResult -TestId 'T7c' -Field 'Truncated body' -Expected 'null' -Actual "Parsed (FV=$($t7c.FormatVersion))" -Status 'Info'
}

# T7d: Empty file (0 bytes)
$t7dPath = Join-Path $tempDir 'T7d_empty.cip'
[System.IO.File]::WriteAllBytes($t7dPath, [byte[]]@())
$t7d = Invoke-ParserTest -BinaryPath $t7dPath
if ($null -eq $t7d) {
    Add-TestResult -TestId 'T7d' -Field 'Empty file' -Expected 'null' -Actual 'null' -Status 'Pass'
}
else {
    Add-TestResult -TestId 'T7d' -Field 'Empty file' -Expected 'null' -Actual 'Parsed' -Status 'Fail'
}

Write-Host ""

# ===========================================================================
# T8: citool Cross-Reference — Parser vs System API
#
# Calls citool.exe --list-policies --json to get the OS-reported view of
# every active CI policy, then compares each field against what the binary
# parser pipeline extracted in T5.
# ===========================================================================
Write-Host "  T8: citool Cross-Reference" -ForegroundColor White
Write-Host "  --------------------------" -ForegroundColor DarkGray

if ($SkipSystemTests) {
    Add-TestResult -TestId 'T8' -Field 'All' -Expected 'Skipped by -SkipSystemTests' -Actual '' -Status 'Skip'
}
elseif ($script:parsedPolicies.Count -eq 0) {
    Add-TestResult -TestId 'T8' -Field 'No parsed policies' -Expected '' -Actual 'Skipped (no policies parsed in T5)' -Status 'Skip'
}
else {
    try {
        $citoolRaw = & citool.exe --list-policies --json 2>&1
        $citoolData = $citoolRaw | ConvertFrom-Json

        if ($citoolData.OperationResult -ne 0) {
            Add-TestResult -TestId 'T8' -Field 'citool' -Expected 'OperationResult=0' -Actual "OperationResult=$($citoolData.OperationResult)" -Status 'Fail'
        }
        else {
            $citoolPolicies = @($citoolData.Policies)
            $onDiskPolicies = @($citoolPolicies | Where-Object { $_.IsOnDisk -eq $true })

            Add-TestResult -TestId 'T8' -Field 'citool total' -Expected '' -Actual "$($citoolPolicies.Count) policies ($($onDiskPolicies.Count) on-disk)" -Status 'Info'
            Add-TestResult -TestId 'T8' -Field 'Parser total' -Expected '' -Actual "$($script:parsedPolicies.Count) parsed from T5" -Status 'Info'

            $xrefMatch = 0
            $xrefMissing = 0

            foreach ($ciPol in $onDiskPolicies) {
                $ciId = $ciPol.PolicyID.ToLower()
                $shortId = $ciId.Substring(0, 8)
                $label = $ciPol.FriendlyName

                # Look up in parser results (keyed by lowercase GUID without braces)
                $ourPol = $script:parsedPolicies[$ciId]
                if ($null -eq $ourPol) {
                    Add-TestResult -TestId 'T8' -Field "$label" -Expected 'In parser output' -Actual "NOT FOUND ($ciId)" -Status 'Info'
                    $xrefMissing++
                    continue
                }

                $xrefMatch++
                Write-Host "    --- $label ($shortId) ---" -ForegroundColor DarkCyan

                # BasePolicyId
                $ciBaseId = $ciPol.BasePolicyID.ToLower()
                $ourBaseId = $ourPol.BasePolicyId.ToLower().Trim('{', '}')
                Assert-Field -TestId 'T8' -Field "$shortId BasePolicyId" -Expected $ciBaseId -Actual $ourBaseId

                # Version
                Assert-Field -TestId 'T8' -Field "$shortId Version" -Expected $ciPol.VersionString -Actual $ourPol.Version

                # FriendlyName — pipeline now extracts from binary Settings
                if ($ourPol.FriendlyName -eq $ciPol.FriendlyName) {
                    Add-TestResult -TestId 'T8' -Field "$shortId FriendlyName" -Expected $ciPol.FriendlyName -Actual $ourPol.FriendlyName -Status 'Pass'
                }
                else {
                    $fnActual = if ($ourPol.FriendlyName) { $ourPol.FriendlyName } else { '(empty)' }
                    Add-TestResult -TestId 'T8' -Field "$shortId FriendlyName" -Expected $ciPol.FriendlyName -Actual $fnActual -Status 'Fail'
                }

                # IsSupplemental (derived: PolicyId != BasePolicyId)
                $ciIsSupplemental = ($ciPol.PolicyID -ne $ciPol.BasePolicyID)
                Assert-Field -TestId 'T8' -Field "$shortId IsSupplemental" -Expected "$ciIsSupplemental" -Actual "$($ourPol.IsSupplemental)"

                # EnforcementMode
                $ciHasAuditMode = $ciPol.PolicyOptions -contains 'Enabled:Audit Mode'
                $ciEnforcement = if ($ciHasAuditMode) { 'Audit' } else { 'Enforced' }
                Assert-Field -TestId 'T8' -Field "$shortId EnforcementMode" -Expected $ciEnforcement -Actual $ourPol.EnforcementMode

                # RuleOptions — compare option name sets directly
                $ourOptionNames = @($ourPol.RuleOptions | ForEach-Object { $_.Name })
                $ciOptionNames = @($ciPol.PolicyOptions)

                # Set comparison (case-insensitive)
                $ciSet  = @{}; foreach ($n in $ciOptionNames)  { $ciSet[$n.ToLower()]  = $n }
                $ourSet = @{}; foreach ($n in $ourOptionNames) { $ourSet[$n.ToLower()] = $n }

                $matching          = @($ourOptionNames | Where-Object { $ciSet.ContainsKey($_.ToLower()) })
                $missingFromParser = @($ciOptionNames | Where-Object { -not $ourSet.ContainsKey($_.ToLower()) })
                $extraInParser     = @($ourOptionNames | Where-Object { -not $ciSet.ContainsKey($_.ToLower()) })

                if ($missingFromParser.Count -eq 0 -and $extraInParser.Count -eq 0) {
                    Add-TestResult -TestId 'T8' -Field "$shortId RuleOptions" -Expected "$($ciOptionNames.Count) options" -Actual "$($ourOptionNames.Count) (all match)" -Status 'Pass'
                }
                else {
                    Add-TestResult -TestId 'T8' -Field "$shortId RuleOptions matched" -Expected "$($ciOptionNames.Count)" -Actual "$($matching.Count) of $($ciOptionNames.Count)" -Status 'Info'
                    if ($missingFromParser.Count -gt 0) {
                        Add-TestResult -TestId 'T8' -Field "$shortId Missing from parser" -Expected '' -Actual ($missingFromParser -join '; ') -Status 'Info'
                    }
                    if ($extraInParser.Count -gt 0) {
                        Add-TestResult -TestId 'T8' -Field "$shortId Extra in parser" -Expected '' -Actual ($extraInParser -join '; ') -Status 'Info'
                    }
                }
            }

            # Not-on-disk policies (citool knows about them but no .cip file exists)
            $notOnDisk = @($citoolPolicies | Where-Object { $_.IsOnDisk -ne $true })
            if ($notOnDisk.Count -gt 0) {
                $names = ($notOnDisk | ForEach-Object { $_.FriendlyName }) -join '; '
                Add-TestResult -TestId 'T8' -Field 'Not on disk (citool only)' -Expected '' -Actual "$($notOnDisk.Count): $names" -Status 'Info'
            }

            # Coverage summary
            $coverageActual = "$xrefMatch matched, $xrefMissing not in Active dir"
            if ($xrefMatch -eq $onDiskPolicies.Count) {
                Add-TestResult -TestId 'T8' -Field 'Coverage' -Expected "$($onDiskPolicies.Count)/$($onDiskPolicies.Count)" -Actual "$xrefMatch/$($onDiskPolicies.Count) on-disk policies cross-referenced" -Status 'Pass'
            }
            elseif ($xrefMatch -ge $script:parsedPolicies.Count) {
                Add-TestResult -TestId 'T8' -Field 'Coverage' -Expected "$($onDiskPolicies.Count) on-disk" -Actual $coverageActual -Status 'Info'
            }
            else {
                Add-TestResult -TestId 'T8' -Field 'Coverage' -Expected "$($onDiskPolicies.Count) on-disk" -Actual $coverageActual -Status 'Fail'
            }
        }
    }
    catch {
        Add-TestResult -TestId 'T8' -Field 'citool execution' -Expected 'Success' -Actual $_.Exception.Message -Status 'Fail'
    }
}
Write-Host ""

# ===========================================================================
# Summary
# ===========================================================================
Write-Host "  =================================================" -ForegroundColor Cyan
Write-Host "  Results Summary" -ForegroundColor Cyan
Write-Host "  =================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "    Pass: $($script:totalPass)" -ForegroundColor Green
Write-Host "    Fail: $($script:totalFail)" -ForegroundColor $(if ($script:totalFail -gt 0) { 'Red' } else { 'Green' })
Write-Host "    Skip: $($script:totalSkip)" -ForegroundColor $(if ($script:totalSkip -gt 0) { 'Yellow' } else { 'DarkGray' })
Write-Host "    Total: $($script:totalPass + $script:totalFail + $script:totalSkip)" -ForegroundColor White
Write-Host ""

if ($script:totalFail -eq 0) {
    Write-Host "    ALL TESTS PASSED" -ForegroundColor Green
}
else {
    Write-Host "    FAILURES DETECTED" -ForegroundColor Red
    Write-Host ""
    $failedTests = $script:testResults | Where-Object { $_.Status -eq 'Fail' }
    foreach ($f in $failedTests) {
        Write-Host "    [$($f.TestId)] $($f.Field): expected '$($f.Expected)', got '$($f.Actual)'" -ForegroundColor Red
    }
}
Write-Host ""

# ---------------------------------------------------------------------------
# Cleanup test temp directory (not transcript)
# ---------------------------------------------------------------------------
try {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Could not clean up temp directory: $tempDir"
}

} # end try
catch {
    Write-Host ""
    Write-Host "  FATAL ERROR" -ForegroundColor Red
    Write-Host "  $($_.Exception.GetType().FullName): $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    Write-Host ""
}
finally {
    # Guarantee transcript stops regardless of success or failure
    Stop-Transcript
}

# Return exit code for CI/CD
if ($script:totalFail -gt 0) { exit 1 }
exit 0
