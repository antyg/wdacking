#Requires -Version 5.1
<#
.SYNOPSIS
    Multi-config KPT variant analysis for V7 wire-shape disambiguation and V6 trailing investigation.

.DESCRIPTION
    Tests multiple policy configurations to determine:
    1. The correct V7 wire shape — 2x uint32 per FileRule (workspace original hypothesis) vs
       per-FileRule Get-BinaryString + V8 marker (E8MVT canonical reading).
    2. Whether V6 trailing uint32 varies between base and supplemental policies.

    Each configuration generates a minimal CI policy XML, converts to binary via
    ConvertFrom-CIPolicy, then measures V7 data size and V6 trailing value. V7 is parsed
    under BOTH hypotheses (dual-shape Measure) and the shape whose byte budget lands exactly
    on the V8 marker offset is reported.

    Test matrix (additive — configs 1-6 preserved as FileName-branch regression; configs 7-11
    added 2026-05-17 to break the empty-FilePath-string coincidence):

      FileName-branch (V7 expected to look like 8 bytes per FR — empty FilePath strings):
        Config 1: 3 signers, 1 FR, supplemental, FileName template (baseline)
        Config 2: 5 signers, 1 FR, supplemental, FileName template (V7: signer elimination)
        Config 3: 1 signer,  1 FR, supplemental, FileName template (V7: minimum signer)
        Config 4: 3 signers, 1 FR, base policy,  FileName template (V6: trailing with base)
        Config 5: 3 signers, 3 FR, supplemental, FileName template (V7: FileRule test)
        Config 6: 3 signers, 5 FR, supplemental, FileName template (V7: FileRule test)

      FilePath-branch (V7 expected to carry non-empty strings — breaks 8-bytes-per-FR coincidence):
        Config 7:  3 signers, 2 FR, supplemental, FilePath-literal       (e.g., C:\Program Files\...)
        Config 8:  3 signers, 2 FR, supplemental, FilePath-OSDRIVE-macro (e.g., %OSDRIVE%\Users\*\...)
        Config 9:  3 signers, 2 FR, supplemental, FilePath-wildcard-multi (e.g., *\Program Files (x86)\...)
        Config 10: 3 signers, 2 FR, supplemental, FilePath-mixed-case    (case-preservation regression)
        Config 11: 3 signers, 2 FR, supplemental, FilePath-Hash-mix      (alternating FilePath/Hash per FR)

    Observations expected (Round 3 hypothesis):
      - Configs 1-6: V7 = 8 bytes per FR (empty FilePath strings = 4 length-zero + 4 null-terminator)
      - Configs 7-11: V7 > 8 bytes per FR (non-empty FilePath strings consume length + data + padding + null)
      - Dual-shape parse: string-shape lands exactly at V8 marker for ALL configs; uint32-shape lands
        at V8 only for empty-FilePath configs (1-6) and overruns for configs 7-11.

.NOTES
    Uses ONLY Microsoft's ConfigCI module — no antyg-wdacking code.
    Run from an elevated PowerShell 5.1 or pwsh 7+ session.
    Output: temp\kpt-variant-transcript.txt

    Round 3 extension authored 2026-05-17 per decoder-canonical-fieldset alignment work;
    see docs\ci-binary-format-reference.md § "Canonical Decoder Alignment" for context.
#>
param()

$ErrorActionPreference = 'Stop'
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleDir  = Split-Path -Parent $scriptDir
$tempDir    = Join-Path $moduleDir 'temp'

if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }

$transcriptPath = Join-Path $tempDir 'kpt-variant-transcript.txt'

# ============================================================================
# Logging
# ============================================================================
$script:output = [System.Collections.Generic.List[string]]::new()

function Log {
    param([string]$Message)
    $script:output.Add($Message)
    Write-Host $Message
}

function LogSection {
    param([string]$Title)
    Log ''
    Log ('=' * 80)
    Log "  $Title"
    Log ('=' * 80)
}

# ============================================================================
# Configuration Matrix
# ============================================================================
# Each config varies one dimension from the baseline to isolate effects.
# FileRuleTemplate selects which Get-FileRuleXml branch authors the FileRule XML.
$configs = @(
    @{
        Name             = '3sig-1fr-supplemental (baseline)'
        SignerCount      = 3
        FileRuleCount    = 1
        IsSupplemental   = $true
        FileRuleTemplate = 'FileName'
    }
    @{
        Name             = '5sig-1fr-supplemental (V7 signer test)'
        SignerCount      = 5
        FileRuleCount    = 1
        IsSupplemental   = $true
        FileRuleTemplate = 'FileName'
    }
    @{
        Name             = '1sig-1fr-supplemental (V7 minimum)'
        SignerCount      = 1
        FileRuleCount    = 1
        IsSupplemental   = $true
        FileRuleTemplate = 'FileName'
    }
    @{
        Name             = '3sig-1fr-base (V6 trailing test)'
        SignerCount      = 3
        FileRuleCount    = 1
        IsSupplemental   = $false
        FileRuleTemplate = 'FileName'
    }
    @{
        Name             = '3sig-3fr-supplemental (V7 FR test)'
        SignerCount      = 3
        FileRuleCount    = 3
        IsSupplemental   = $true
        FileRuleTemplate = 'FileName'
    }
    @{
        Name             = '3sig-5fr-supplemental (V7 FR test)'
        SignerCount      = 3
        FileRuleCount    = 5
        IsSupplemental   = $true
        FileRuleTemplate = 'FileName'
    }
    # ---- FilePath-branch (Round 3 additions, 2026-05-17) ----
    @{
        Name             = '3sig-2fr-supplemental (FilePath-literal)'
        SignerCount      = 3
        FileRuleCount    = 2
        IsSupplemental   = $true
        FileRuleTemplate = 'FilePath-literal'
    }
    @{
        Name             = '3sig-2fr-supplemental (FilePath-OSDRIVE-macro)'
        SignerCount      = 3
        FileRuleCount    = 2
        IsSupplemental   = $true
        FileRuleTemplate = 'FilePath-OSDRIVE-macro'
    }
    @{
        Name             = '3sig-2fr-supplemental (FilePath-wildcard-multi)'
        SignerCount      = 3
        FileRuleCount    = 2
        IsSupplemental   = $true
        FileRuleTemplate = 'FilePath-wildcard-multi'
    }
    @{
        Name             = '3sig-2fr-supplemental (FilePath-mixed-case)'
        SignerCount      = 3
        FileRuleCount    = 2
        IsSupplemental   = $true
        FileRuleTemplate = 'FilePath-mixed-case'
    }
    @{
        Name             = '3sig-2fr-supplemental (FilePath-Hash-mix)'
        SignerCount      = 3
        FileRuleCount    = 2
        IsSupplemental   = $true
        FileRuleTemplate = 'FilePath-Hash-mix'
    }
    @{
        Name             = '3sig-2fr-supplemental (AppIDs-attribute)'
        SignerCount      = 3
        FileRuleCount    = 2
        IsSupplemental   = $true
        FileRuleTemplate = 'AppIDs-attribute'
    }
    # ---- All-OptionType-enum-values variant (Round 7 — KPT-variant per enum value) ----
    # Single-fixture exhaustive coverage of every XSD-canonical OptionType enumeration
    # (cipolicy.xsd lines 119-143). Round-trip drops any option the workspace decoder's
    # bitToOptionName table doesn't know how to emit; the verification probe surfaces gaps.
    @{
        Name             = '3sig-1fr-base (AllOptions-exhaustive)'
        SignerCount      = 3
        FileRuleCount    = 1
        IsSupplemental   = $false       # base policy — Options are typically authored on base
        FileRuleTemplate = 'FileName'
        AllOptions       = $true        # signal to New-VariantPolicyXml to emit all 24 Options
    }
)

# ============================================================================
# FileRule XML Templates
# ============================================================================
# Returns one <Allow> element per call; template selects discriminator shape.
# Hash template uses 32-byte (SHA-256-sized) hash with per-index distinctive pattern.
function Get-FileRuleXml {
    param(
        [int]$Index,
        [string]$Template
    )

    switch ($Template) {
        'FileName' {
            return "    <Allow ID=`"ID_ALLOW_A_$Index`" FriendlyName=`"Allow$Index`" FileName=`"TestFile$Index.dll`" MinimumFileVersion=`"1.0.0.0`" />"
        }
        'FilePath-literal' {
            return "    <Allow ID=`"ID_ALLOW_A_$Index`" FriendlyName=`"Allow$Index`" FilePath=`"C:\Program Files\Vendor\TestApp$Index.exe`" />"
        }
        'FilePath-OSDRIVE-macro' {
            return "    <Allow ID=`"ID_ALLOW_A_$Index`" FriendlyName=`"Allow$Index`" FilePath=`"%OSDRIVE%\Users\*\AppData\Local\Vendor$Index\*`" />"
        }
        'FilePath-wildcard-multi' {
            return "    <Allow ID=`"ID_ALLOW_A_$Index`" FriendlyName=`"Allow$Index`" FilePath=`"*\Program Files (x86)\Vendor\Plugins\$Index\*`" />"
        }
        'FilePath-mixed-case' {
            return "    <Allow ID=`"ID_ALLOW_A_$Index`" FriendlyName=`"Allow$Index`" FilePath=`"c:\Windows\System32\Tool$Index.Exe`" />"
        }
        'FilePath-Hash-mix' {
            # Alternate FilePath (odd index) and Hash (even index) per FR
            if ($Index % 2 -eq 1) {
                return "    <Allow ID=`"ID_ALLOW_A_$Index`" FriendlyName=`"Allow$Index`" FilePath=`"D:\Apps\Vendor$Index\*`" />"
            }
            else {
                $hashByte = '{0:X2}' -f ($Index + 16)
                $hashHex  = ($hashByte + 'EE' + $hashByte + 'FF') * 8  # 32 bytes
                return "    <Allow ID=`"ID_ALLOW_A_$Index`" FriendlyName=`"Allow$Index`" Hash=`"$hashHex`" />"
            }
        }
        'AppIDs-attribute' {
            # AppIDs attribute per XSD AppIdType (line 103-116 of cipolicy.xsd):
            #   non-`$`-starting plain string OR macro form `$(MacroId)` (concatenated).
            # Use plain string form to avoid <Macros> element dependency in the test policy.
            return "    <Allow ID=`"ID_ALLOW_A_$Index`" FriendlyName=`"Allow$Index`" FileName=`"App$Index.exe`" AppIDs=`"AppTag$Index`" />"
        }
        default {
            throw "Unknown FileRule template: $Template"
        }
    }
}

# ============================================================================
# XML Generation
# ============================================================================
function New-VariantPolicyXml {
    param(
        [int]$SignerCount,
        [int]$FileRuleCount = 1,
        [bool]$IsSupplemental,
        [string]$FileRuleTemplate = 'FileName',
        [bool]$AllOptions = $false
    )

    # Complete XSD-canonical OptionType enumeration per cipolicy.xsd lines 119-143.
    # Used by the AllOptions-exhaustive variant to exercise every Option round-trip.
    # NOTE: `Enabled:Windows Lockdown Trial Mode` is intentionally omitted — it exists in
    # the binary bitmask (bit 6) but is NOT declared in the current XSD's OptionType enum,
    # so including it in an XML input would cause ConvertFrom-CIPolicy to reject the policy.
    $xsdCanonicalOptions = @(
        'Enabled:UMCI'
        'Enabled:Boot Menu Protection'
        'Enabled:Intelligent Security Graph Authorization'
        'Enabled:Invalidate EAs on Reboot'
        'Required:WHQL'
        'Enabled:Developer Mode Dynamic Code Trust'
        'Enabled:Allow Supplemental Policies'
        'Disabled:Runtime FilePath Rule Protection'
        'Enabled:Revoked Expired As Unsigned'
        'Enabled:Audit Mode'
        'Disabled:Flight Signing'
        'Enabled:Inherit Default Policy'
        'Enabled:Unsigned System Integrity Policy'
        'Enabled:Dynamic Code Security'
        'Required:EV Signers'
        'Enabled:Boot Audit On Failure'
        'Enabled:Advanced Boot Options Menu'
        'Disabled:Script Enforcement'
        'Required:Enforce Store Applications'
        'Enabled:Secure Setting Policy'
        'Enabled:Managed Installer'
        'Enabled:Update Policy No Reboot'
        'Enabled:Conditional Windows Lockdown Policy'
        'Disabled:Default Windows Certificate Remapping'
    )

    $policyId     = '{FADE0001-FADE-FADE-FADE-FADE0001FADE}'
    # Base policy: PolicyID == BasePolicyID. Supplemental: different GUIDs.
    $basePolicyId = if ($IsSupplemental) { '{BACE0003-BACE-BACE-BACE-BACE0003BACE}' } else { $policyId }
    $platformId   = '{CAFE0002-CAFE-CAFE-CAFE-CAFE0002CAFE}'
    $policyType   = if ($IsSupplemental) { 'Supplemental Policy' } else { 'Base Policy' }

    # Build signer elements — each with a unique TBS hash
    $signerLines = [System.Collections.Generic.List[string]]::new()
    for ($i = 1; $i -le $SignerCount; $i++) {
        # 32-byte TBS hash: distinctive per-signer pattern
        $tbsByte = '{0:X2}' -f $i
        $tbsHex  = ($tbsByte + 'AA' + $tbsByte + 'BB') * 8  # 32 bytes
        $signerLines.Add("    <Signer ID=`"ID_SIGNER_S_$i`" Name=`"Signer_$i`">")
        $signerLines.Add("      <CertRoot Type=`"TBS`" Value=`"$tbsHex`" />")
        $signerLines.Add("      <CertPublisher Value=`"Publisher_$i`" />")
        $signerLines.Add("    </Signer>")
    }
    $signersXml = $signerLines -join "`n"

    # Build FileRule elements via template selector
    $fileRuleLines = [System.Collections.Generic.List[string]]::new()
    for ($i = 1; $i -le $FileRuleCount; $i++) {
        $fileRuleLines.Add((Get-FileRuleXml -Index $i -Template $FileRuleTemplate))
    }
    $fileRulesXml = $fileRuleLines -join "`n"

    # `<SupplementalPolicySigners>` is constrained to BASE policies by ConvertFrom-CIPolicy
    # (Microsoft validation rule: "Only base policies can have SupplementalSigners"). Build the
    # block conditionally so the same XML template produces valid binaries for both branches.
    $supplementalSignersBlock = if (-not $IsSupplemental) {
        @"
  <SupplementalPolicySigners>
    <SupplementalPolicySigner SignerId="ID_SIGNER_S_1" />
  </SupplementalPolicySigners>
"@
    }
    else { '' }

    # Two standard scenarios: Drivers (131) and UserMode (12)
    # Both reference Signer 1 (always present regardless of SignerCount)
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="$policyType">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>$platformId</PlatformID>
  <Rules>
$(if ($AllOptions) {
    ($xsdCanonicalOptions | ForEach-Object {
        "    <Rule><Option>$_</Option></Rule>"
    }) -join "`n"
}
else {
    '    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>'
})
  </Rules>
  <EKUs>
    <EKU ID="ID_EKU_VARIANT" FriendlyName="EKU1" Value="010A2B0601040182370A0306" />
  </EKUs>
  <FileRules>
$fileRulesXml
  </FileRules>
  <Signers>
$signersXml
  </Signers>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS" FriendlyName="Drivers">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_USERMODE" FriendlyName="UserMode">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners>
    <UpdatePolicySigner SignerId="ID_SIGNER_S_1" />
  </UpdatePolicySigners>
  <CiSigners>
    <CiSigner SignerId="ID_SIGNER_S_1" />
  </CiSigners>
$supplementalSignersBlock  <HvciOptions>2</HvciOptions>
  <PolicyID>$policyId</PolicyID>
  <BasePolicyID>$basePolicyId</BasePolicyID>
</SiPolicy>
"@
    return $xml
}

# ============================================================================
# Binary String Reader (E8MVT-canonical wire shape)
# ============================================================================
# Mirrors the on-wire encoding documented in ci-binary-format-reference.md
# § "String Encoding": [uint32 byte count][UTF-16LE data][padding to 4][uint32 null terminator].
# $Offset is updated in-place via [ref]; caller passes [ref]$cursor.
function Read-BinaryStringAt {
    param(
        [byte[]]$Data,
        [ref]$Offset
    )
    if ($Offset.Value + 4 -gt $Data.Length) {
        throw "Read-BinaryStringAt: stream truncated at offset 0x$($Offset.Value.ToString('X8')); cannot read length prefix"
    }

    $len = [BitConverter]::ToUInt32($Data, $Offset.Value)
    $Offset.Value += 4

    $str = ''
    if ($len -gt 0) {
        if ($Offset.Value + $len -gt $Data.Length) {
            throw "Read-BinaryStringAt: stream truncated; cannot read $len bytes at offset 0x$($Offset.Value.ToString('X8'))"
        }
        $str = [System.Text.Encoding]::Unicode.GetString($Data, $Offset.Value, $len)
        $Offset.Value += $len
        # Padding to 4-byte boundary
        $padding = (4 - ($len % 4)) -band 3
        $Offset.Value += $padding
    }
    # Null terminator (always present, even for empty strings)
    if ($Offset.Value + 4 -gt $Data.Length) {
        throw "Read-BinaryStringAt: stream truncated; cannot read null terminator at offset 0x$($Offset.Value.ToString('X8'))"
    }
    $Offset.Value += 4

    return $str
}

# ============================================================================
# Binary Analysis — measure V7 (dual-shape) and V6
# ============================================================================
function Measure-V7V6 {
    param([byte[]]$Data)

    $result = @{
        FormatVer              = [BitConverter]::ToInt32($Data, 0x00)
        HeaderGuid             = "{$([System.Guid]::new([byte[]]($Data[0x04..0x13])))}"
        FileRuleCount          = [BitConverter]::ToInt32($Data, 0x2C)
        SignerCount            = [BitConverter]::ToInt32($Data, 0x30)
        ScenarioCount          = [BitConverter]::ToInt32($Data, 0x34)
        FileSize               = $Data.Length
        V6PolicyID             = ''
        V6BasePID              = ''
        V6Trailing             = -1
        V7DataSize             = -1
        V7Words                = @()
        V7Strings              = @()
        V7StringShapeValid     = $false
        V7StringShapeEndsAtV8  = $false
        V7StringBudget         = -1
        V9Offset               = -1
        V8Offset               = -1
        V7Offset               = -1
        V6Offset               = -1
    }

    # Sequential end-probing: older format versions may lack V9, V8, or V7.
    # Probe from the tail inward — each step adjusts the cursor only when the
    # expected marker is positively found. Degrades gracefully for partial sets:
    #   FormatVer 8+ → expect V3-V9 (full set)
    #   FormatVer 7  → expect V3-V7 (no V8/V9)
    #   FormatVer 6  → expect V3-V6 (no V7/V8/V9)
    #   FormatVer <6 → V6 absent, cannot extract PolicyID/BasePolicyID from V-blocks
    $cursor = $Data.Length

    # Probe for V9 (end sentinel): marker only, 4 bytes, always last if present
    if ($cursor -ge 4) {
        $val = [BitConverter]::ToUInt32($Data, $cursor - 4)
        if ($val -eq 9) {
            $result.V9Offset = $cursor - 4
            $cursor = $result.V9Offset
        }
    }

    # Probe for V8: marker(4) + uint32(4) = 8 bytes, immediately before cursor
    if ($cursor -ge 8 -and ($cursor - 8) -ge 0x44) {
        $val = [BitConverter]::ToUInt32($Data, $cursor - 8)
        if ($val -eq 8) {
            $result.V8Offset = $cursor - 8
            $cursor = $result.V8Offset
        }
    }

    # Scan backward from cursor for V7 marker (uint32 == 7)
    for ($off = $cursor - 4; $off -ge 0x44; $off -= 4) {
        $val = [BitConverter]::ToUInt32($Data, $off)
        if ($val -eq 7) {
            $result.V7Offset = $off
            $v7DataStart = $off + 4
            $result.V7DataSize = $cursor - $v7DataStart

            # ----- Shape 1: 2 x uint32 per FileRule (workspace original hypothesis) -----
            $words = [System.Collections.Generic.List[uint32]]::new()
            for ($w = $v7DataStart; $w -lt $cursor; $w += 4) {
                $words.Add([BitConverter]::ToUInt32($Data, $w))
            }
            $result.V7Words = $words.ToArray()

            # ----- Shape 2: per-FileRule Get-BinaryString (E8MVT canonical) -----
            $stringShapeValid    = $true
            $stringShapeEndsAtV8 = $false
            $strings = [System.Collections.Generic.List[string]]::new()
            $stringCursor = $v7DataStart
            try {
                for ($i = 0; $i -lt $result.FileRuleCount; $i++) {
                    if ($stringCursor -gt $cursor) {
                        # Overran V7 region — string shape can't fit
                        $stringShapeValid = $false
                        break
                    }
                    $stringCursorRef = $stringCursor
                    $s = Read-BinaryStringAt -Data $Data -Offset ([ref]$stringCursorRef)
                    $strings.Add($s)
                    $stringCursor = $stringCursorRef
                }
                if ($stringShapeValid) {
                    # E8MVT canonical shape: V7 data is followed by V8RuleSupport uint32 marker.
                    # The string shape's cursor should land exactly at the V8 marker offset.
                    $stringShapeEndsAtV8 = ($stringCursor -eq $cursor)
                    $result.V7StringBudget = $stringCursor - $v7DataStart
                }
            }
            catch {
                $stringShapeValid    = $false
                $stringShapeEndsAtV8 = $false
            }
            $result.V7Strings             = $strings.ToArray()
            $result.V7StringShapeValid    = $stringShapeValid
            $result.V7StringShapeEndsAtV8 = $stringShapeEndsAtV8

            $cursor = $off
            break
        }
    }

    # Scan backward from cursor for V6 marker (uint32 == 6) with GUID validation
    for ($off = $cursor - 4; $off -ge 0x44; $off -= 4) {
        $val = [BitConverter]::ToUInt32($Data, $off)
        if ($val -eq 6) {
            # Validate: bytes [off+4..off+19] should be a GUID matching our KPT pattern
            if ($off + 36 -lt $Data.Length) {
                $testGuid = [System.Guid]::new([byte[]]($Data[($off + 4)..($off + 19)]))
                $testStr  = "{$testGuid}".ToUpper()
                if ($testStr -match 'FADE0001|BACE0003') {
                    $result.V6Offset   = $off
                    $result.V6PolicyID = $testStr
                    $bpGuid = [System.Guid]::new([byte[]]($Data[($off + 20)..($off + 35)]))
                    $result.V6BasePID  = "{$bpGuid}".ToUpper()
                    $result.V6Trailing = [BitConverter]::ToUInt32($Data, $off + 36)
                    break
                }
            }
        }
    }

    return $result
}

# ============================================================================
# Main — test each configuration
# ============================================================================
LogSection 'KPT Variant Analysis — V7 Wire-Shape Disambiguation & V6 Trailing'

Log "Test matrix: $($configs.Count) configurations ($(($configs | Where-Object { $_.FileRuleTemplate -eq 'FileName' }).Count) FileName-branch + $(($configs | Where-Object { $_.FileRuleTemplate -ne 'FileName' }).Count) FilePath-branch)"
Log 'Hypothesis: FileName-branch (configs 1-6) produces V7 = 8 bytes/FR via empty FilePath strings.'
Log '            FilePath-branch (configs 7-11) produces V7 > 8 bytes/FR via non-empty FilePath strings.'
Log '            String-shape parse lands exactly at V8 marker for ALL configs;'
Log '            uint32-shape parse lands at V8 only for configs with empty FilePaths.'
Log ''

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($cfg in $configs) {
    Log "--- Config: $($cfg.Name) [$($cfg.FileRuleTemplate)] ---"

    $safeName = $cfg.Name -replace '[^a-zA-Z0-9]', '-'
    $xmlPath = Join-Path $tempDir "KPT-Variant-$safeName.xml"
    $binPath = Join-Path $tempDir "KPT-Variant-$safeName.cip"

    $xml = New-VariantPolicyXml `
        -SignerCount $cfg.SignerCount `
        -FileRuleCount $cfg.FileRuleCount `
        -IsSupplemental $cfg.IsSupplemental `
        -FileRuleTemplate $cfg.FileRuleTemplate `
        -AllOptions ([bool]$cfg.AllOptions)
    [System.IO.File]::WriteAllText($xmlPath, $xml, [System.Text.UTF8Encoding]::new($true))

    try {
        ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $binPath -ErrorAction Stop | Out-Null
        $data = [System.IO.File]::ReadAllBytes($binPath)
        Log "  Binary: $($data.Length) bytes"

        $m = Measure-V7V6 -Data $data
        Log "  Format version: $($m.FormatVer)"
        Log "  Header GUID:    $($m.HeaderGuid)"
        Log "  FileRule count: $($m.FileRuleCount), Signer count: $($m.SignerCount), Scenario count: $($m.ScenarioCount)"
        Log "  V7 data size:   $($m.V7DataSize) bytes ($($m.V7DataSize / 4) words)"
        if ($m.V7DataSize -gt 0 -and $m.FileRuleCount -gt 0) {
            Log "    bytes per FileRule: $([Math]::Round($m.V7DataSize / $m.FileRuleCount, 2))"
        }
        Log "  V7 dual-shape parse:"
        Log "    uint32-shape words:        [$($m.V7Words -join ', ')]"
        Log "    string-shape valid:        $($m.V7StringShapeValid)"
        Log "    string-shape ends at V8:   $($m.V7StringShapeEndsAtV8)"
        Log "    string-shape budget:       $($m.V7StringBudget) bytes (V7 size $($m.V7DataSize))"
        if ($m.V7Strings.Count -gt 0) {
            for ($si = 0; $si -lt $m.V7Strings.Count; $si++) {
                $s = $m.V7Strings[$si]
                $display = if ([string]::IsNullOrEmpty($s)) { '<empty>' } else { "`"$s`"" }
                Log "      FR[$si]: $display"
            }
        }
        $v6Hex = if ($m.V6Offset -ge 0) { '0x' + $m.V6Offset.ToString('X4') } else { 'absent' }
        $v7Hex = if ($m.V7Offset -ge 0) { '0x' + $m.V7Offset.ToString('X4') } else { 'absent' }
        $v8Hex = if ($m.V8Offset -ge 0) { '0x' + $m.V8Offset.ToString('X4') } else { 'absent' }
        $v9Hex = if ($m.V9Offset -ge 0) { '0x' + $m.V9Offset.ToString('X4') } else { 'absent' }
        Log "  V-block offsets: V6=$v6Hex  V7=$v7Hex  V8=$v8Hex  V9=$v9Hex"
        Log "  V6 PolicyID:    $($m.V6PolicyID)"
        Log "  V6 BasePolicyID: $($m.V6BasePID)"
        Log "  V6 Trailing:    $($m.V6Trailing)"

        $results.Add([PSCustomObject]@{
            Config             = $cfg.Name
            Template           = $cfg.FileRuleTemplate
            FileRules          = $m.FileRuleCount
            Signers            = $m.SignerCount
            Scenarios          = $m.ScenarioCount
            Supplemental       = $cfg.IsSupplemental
            V7Bytes            = $m.V7DataSize
            V7Words            = $m.V7DataSize / 4
            V7PerFR            = if ($m.FileRuleCount -gt 0) { $m.V7DataSize / $m.FileRuleCount } else { -1 }
            V7StringShapeValid    = $m.V7StringShapeValid
            V7StringShapeEndsAtV8 = $m.V7StringShapeEndsAtV8
            V7Strings          = $m.V7Strings
            V6Trailing         = $m.V6Trailing
            V6PID              = $m.V6PolicyID
            V6BPID             = $m.V6BasePID
            Error              = $null
        })
    }
    catch {
        Log "  ERROR: $($_.Exception.Message)"
        $results.Add([PSCustomObject]@{
            Config             = $cfg.Name
            Template           = $cfg.FileRuleTemplate
            FileRules          = $cfg.FileRuleCount
            Signers            = $cfg.SignerCount
            Scenarios          = 0
            Supplemental       = $cfg.IsSupplemental
            V7Bytes            = $null
            V7Words            = $null
            V7PerFR            = $null
            V7StringShapeValid    = $null
            V7StringShapeEndsAtV8 = $null
            V7Strings          = @()
            V6Trailing         = $null
            V6PID              = ''
            V6BPID             = ''
            Error              = $_.Exception.Message
        })
    }
    Log ''
}

# ============================================================================
# Comparison Table
# ============================================================================
LogSection 'Comparison Table'

Log '  Config                                              Template                  FR  Sig  V7bytes  V7/FR  StrValid  StrEndsV8  V6trail'
Log '  --------------------------------------------------  ------------------------  --  ---  -------  -----  --------  ---------  -------'
foreach ($r in $results) {
    $v7b      = if ($null -ne $r.V7Bytes)               { '{0,7}' -f $r.V7Bytes }               else { ' ERROR ' }
    $v7fr     = if ($null -ne $r.V7PerFR)               { '{0,5}' -f $r.V7PerFR }               else { '  ERR' }
    $strV     = if ($null -ne $r.V7StringShapeValid)    { '{0,8}' -f $r.V7StringShapeValid }    else { '   ERROR' }
    $strE     = if ($null -ne $r.V7StringShapeEndsAtV8) { '{0,9}' -f $r.V7StringShapeEndsAtV8 } else { '    ERROR' }
    $v6t      = if ($null -ne $r.V6Trailing)            { '{0,7}' -f $r.V6Trailing }            else { ' ERROR ' }
    Log ('  {0,-50}  {1,-24}  {2,2}  {3,3}  {4}  {5}  {6}  {7}  {8}' -f $r.Config, $r.Template, $r.FileRules, $r.Signers, $v7b, $v7fr, $strV, $strE, $v6t)
}

# ============================================================================
# V7 Wire-Shape Disambiguation
# ============================================================================
LogSection 'V7 Wire-Shape Disambiguation'

$validResults = $results | Where-Object { $null -ne $_.V7Bytes }
$fileNameBranch = $validResults | Where-Object { $_.Template -eq 'FileName' }
$filePathBranch = $validResults | Where-Object { $_.Template -ne 'FileName' }

# String-shape end-at-V8 evidence: should be true for ALL configs if E8MVT shape is canonical
$allEndAtV8       = ($validResults | Where-Object { -not $_.V7StringShapeEndsAtV8 }).Count -eq 0
$allStringsValid  = ($validResults | Where-Object { -not $_.V7StringShapeValid }).Count -eq 0
$fnPerFRConstant  = (($fileNameBranch | Select-Object -ExpandProperty V7PerFR | Sort-Object -Unique).Count -eq 1) -and (($fileNameBranch | Select-Object -ExpandProperty V7PerFR | Sort-Object -Unique)[0] -eq 8)
$fpExceeds8       = ($filePathBranch | Where-Object { $_.V7PerFR -gt 8 }).Count -gt 0

Log "  Result-set sizes: FileName-branch=$($fileNameBranch.Count); FilePath-branch=$($filePathBranch.Count)"
Log ''
Log "  Evidence checks:"
Log "    String-shape parse VALID for all configs:           $allStringsValid"
Log "    String-shape ENDS-AT-V8 for all configs:            $allEndAtV8"
Log "    FileName-branch V7/FR constant at 8:                $fnPerFRConstant"
Log "    FilePath-branch V7/FR exceeds 8:                    $fpExceeds8"
Log ''

if ($allStringsValid -and $allEndAtV8 -and $fnPerFRConstant -and $fpExceeds8) {
    Log "  CONCLUSION: V7 wire shape is E8MVT-canonical (per-FileRule Get-BinaryString + V8 marker)."
    Log "    The earlier 8-bytes-per-FileRule observation was a coincidence of empty-string encoding."
    Log "    Empty FilePath strings consume 4 (length=0) + 0 (data) + 0 (padding) + 4 (null) = 8 bytes,"
    Log "    byte-identical to two zero uint32s — the FileName-only KPT corpus could not distinguish."
    Log "    Workspace 'Read-BinaryVBlocks.ps1:188-209' must be rewritten to per-FR Get-BinaryString."
}
elseif ($allStringsValid -and $allEndAtV8) {
    Log "  PARTIAL CONFIRMATION: String shape valid and ends at V8 marker, but ratio evidence is mixed."
    Log "    Manual review of per-config V7 strings and budgets required."
}
elseif ($fnPerFRConstant -and -not $fpExceeds8) {
    Log "  CONFLICTING EVIDENCE: FileName-branch shows 8/FR constant, but FilePath-branch does NOT exceed."
    Log "    Either ConvertFrom-CIPolicy did not encode the FilePath attribute (unlikely) or"
    Log "    V7 has a more complex structure than either pure uint32 or pure string."
    Log "    Hex-dump the FilePath configs' V7 region for manual inspection."
}
else {
    Log "  AMBIGUOUS: Dual-shape evidence does not converge on either hypothesis."
    Log "    Manual hex-dump and per-config inspection required."
}

Log ''
Log "  Per-template V7 byte-budget breakdown:"
$templateGroups = $validResults | Group-Object Template
foreach ($g in $templateGroups) {
    $sizes = ($g.Group | Select-Object -ExpandProperty V7Bytes | Sort-Object -Unique) -join ', '
    $perFR = ($g.Group | Select-Object -ExpandProperty V7PerFR | Sort-Object -Unique) -join ', '
    Log "    $($g.Name): V7 sizes=[$sizes] bytes; V7/FR=[$perFR]"
}

# ============================================================================
# V6 Trailing Analysis
# ============================================================================
LogSection 'V6 Trailing Analysis'

$validV6 = $results | Where-Object { $null -ne $_.V6Trailing }
foreach ($r in $validV6) {
    $pType    = if ($r.Supplemental) { 'supplemental' } else { 'base' }
    $pidMatch = if ($r.V6PID -eq $r.V6BPID) { 'PID==BPID' } else { 'PID!=BPID' }
    Log "  $($r.Config): trailing=$($r.V6Trailing) ($pType, $pidMatch)"
}

$trailingValues = ($validV6 | Select-Object -ExpandProperty V6Trailing | Sort-Object -Unique) -join ', '
Log ''
Log "  Distinct trailing values: $trailingValues"
if (($validV6 | Select-Object -ExpandProperty V6Trailing | Sort-Object -Unique).Count -eq 1) {
    Log "  V6 trailing uint32 is CONSTANT across base and supplemental policies"
}
else {
    Log "  V6 trailing uint32 VARIES — investigate conditions"
}

# ============================================================================
# Write transcript
# ============================================================================
Log ''
Log ('=' * 80)
Log '  Variant analysis complete.'
Log ('=' * 80)
Log "  Report: $transcriptPath"

$script:output | Out-File -FilePath $transcriptPath -Encoding utf8
Write-Host ''
Write-Host "Transcript written to: $transcriptPath" -ForegroundColor Green
