#Requires -Version 5.1
<#
.SYNOPSIS
    Known-Plaintext Binary Format Analysis for CI Policy.

.DESCRIPTION
    Generates a comprehensive CI policy XML with known, distinctive marker values
    (KPT_ prefix strings, distinctive GUIDs, known version numbers), converts to
    unsigned binary using Microsoft's ConvertFrom-CIPolicy, then performs exhaustive
    byte-level analysis to map every header field, body section boundary, binary
    string format, and V-block structure.

    This is a "Rosetta Stone" approach: since we control the XML input and know
    every value, we can search for those values in the binary output to determine
    the exact byte layout that ConvertFrom-CIPolicy produces.

.NOTES
    Uses ONLY Microsoft's ConfigCI module — no antyg-wdacking code.
    Run from an elevated PowerShell 5.1 or pwsh 7+ session.
    Output: temp\kpt-analysis-transcript.txt + temp\KPT-Comprehensive.cip
#>
param()

$ErrorActionPreference = 'Stop'
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleDir  = Split-Path -Parent $scriptDir
$tempDir    = Join-Path $moduleDir 'temp'

if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }

$transcriptPath = Join-Path $tempDir 'kpt-analysis-transcript.txt'

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
# Helper Functions
# ============================================================================

function ConvertTo-GuidBytes {
    param([string]$GuidString)
    [System.Guid]::Parse($GuidString).ToByteArray()
}

function ConvertTo-Utf16Bytes {
    param([string]$Text)
    [System.Text.Encoding]::Unicode.GetBytes($Text)
}

function Find-BytePattern {
    param(
        [byte[]]$Data,
        [byte[]]$Pattern,
        [int]$MaxResults = 20
    )
    $results = [System.Collections.Generic.List[int]]::new()
    $limit = $Data.Length - $Pattern.Length
    for ($i = 0; $i -le $limit; $i++) {
        $found = $true
        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) { $found = $false; break }
        }
        if ($found) {
            $results.Add($i)
            if ($results.Count -ge $MaxResults) { break }
        }
    }
    $results.ToArray()
}

function Format-HexDump {
    param(
        [byte[]]$Data,
        [int]$Offset = 0,
        [int]$Length = -1,
        [int]$BytesPerLine = 16
    )
    if ($Length -lt 0) { $Length = $Data.Length - $Offset }
    $end = [Math]::Min($Offset + $Length, $Data.Length)
    $lines = [System.Collections.Generic.List[string]]::new()
    for ($i = $Offset; $i -lt $end; $i += $BytesPerLine) {
        $hex = ''
        $ascii = ''
        for ($j = 0; $j -lt $BytesPerLine; $j++) {
            if (($i + $j) -lt $end) {
                $b = $Data[$i + $j]
                $hex += $b.ToString('X2') + ' '
                $ascii += if ($b -ge 0x20 -and $b -le 0x7E) { [char]$b } else { '.' }
            } else {
                $hex += '   '
                $ascii += ' '
            }
            if ($j -eq 7) { $hex += ' ' }
        }
        $lines.Add(('{0:X6}  {1} |{2}|' -f $i, $hex, $ascii))
    }
    $lines.ToArray()
}

function Search-KnownValue {
    param(
        [byte[]]$Data,
        [string]$Label,
        [byte[]]$Pattern
    )
    $offsets = Find-BytePattern -Data $Data -Pattern $Pattern
    $hexPat = ($Pattern | ForEach-Object { $_.ToString('X2') }) -join ' '
    if ($offsets.Count -gt 0) {
        foreach ($off in $offsets) {
            Log ("  FOUND: {0,-40} at 0x{1:X4} ({1,5})  [{2}]" -f $Label, $off, $hexPat)
        }
    } else {
        Log ("  NOT FOUND: {0,-36} [{1}]" -f $Label, $hexPat)
    }
    $offsets
}

# Read a binary string at a position, return value + bytes consumed
function Read-BinaryString {
    param(
        [byte[]]$Data,
        [int]$Position
    )
    $strLen = [BitConverter]::ToUInt32($Data, $Position)
    $consumed = 4
    $value = '(empty)'
    if ($strLen -gt 0) {
        $strPad = [int]((4 - ($strLen % 4)) -band 3)
        $value = [System.Text.Encoding]::Unicode.GetString($Data, $Position + 4, [int]$strLen)
        $consumed += [int]$strLen + $strPad
    }
    $consumed += 4  # null terminator always present
    [PSCustomObject]@{
        Value    = $value
        Length   = [int]$strLen
        Consumed = $consumed
    }
}

# ============================================================================
# STEP 1: Generate Known-Plaintext CI Policy XML
# ============================================================================
LogSection 'STEP 1: Generate Known-Plaintext CI Policy XML'

# --- Known Values Registry ---
# Every value here is distinctive and searchable in the binary output.
# This is a COMPREHENSIVE test: every XML capability is exercised.

# GUIDs (use hex patterns that are easy to spot in dumps)
# BASE POLICY with SupplementalPolicySigners — tests SEC6 body section
$policyId    = '{FADE0001-FADE-FADE-FADE-FADE0001FADE}'
$basePolicyId = $policyId  # SAME = base policy (SupplementalPolicySigners requires base)
$platformId  = '{CAFE0002-CAFE-CAFE-CAFE-CAFE0002CAFE}'

# Version: 7.3.42.99 (Major.Minor.Build.Revision)
# In binary header at 0x38: stored as uint16 LE: Rev=99, Build=42, Minor=3, Major=7
$version = '7.3.42.99'

# Rule Options — 6 explicit options (base policy with supplemental signer trust)
# Explicit bits: bit2 | bit15 | bit16 | bit19 | bit23 | bit28
# Auto-set bits: bit31 (always)
# Expected OptionFlags: 0x80000000 | 0x00000004 | 0x00008000 | 0x00010000 | 0x00080000 | 0x00800000 | 0x10000000
#   = 0x90898004
# NOTE: bit 30 (0x40000000) is NOT set — that is only auto-injected for supplemental policies.
$ruleOptions = @(
    'Enabled:UMCI'                               # bit 2  → 0x00000004
    'Enabled:Allow Supplemental Policies'        # bit 15 → 0x00008000
    'Enabled:Audit Mode'                         # bit 16 → 0x00010000
    'Enabled:Unsigned System Integrity Policy'   # bit 19 → 0x00080000
    'Enabled:Advanced Boot Options Menu'         # bit 23 → 0x00800000
    'Enabled:Update Policy No Reboot'            # bit 28 → 0x10000000
)
$expectedOptionFlags = 0x90898004

# EKU Values (hex-encoded DER — 3 EKUs to test count > 2)
$eku1Hex = '010A2B0601040182370A0306'   # Windows System Component Verification
$eku2Hex = '010A2B0601040182370A0315'   # Early Launch Antimalware Driver
$eku3Hex = '010A2B0601040182370A030C'   # Windows Store (distinctive 3rd EKU)

# FileRule FileNames (KPT_ prefix for easy UTF-16LE search)
$fileName1 = 'KPT_ALLOWED.dll'     # Allow rule  — enriched with V3/V4/V5 metadata
$fileName2 = 'KPT_DENIED.exe'      # Deny rule   — filename-based
$fileName3 = 'KPT_ATTRIB.sys'      # FileAttrib  — baseline (minimal)

# FileRule metadata for V4 blocks (InternalName, FileDescription, ProductName)
$internalName1 = 'KPT_InternalAllowed'
$fileDesc1     = 'KPT_FileDescAllowed'
$productName1  = 'KPT_ProductAllowed'

# FileRule hash for binary hash field testing (distinctive SHA256)
$fileHash2 = 'AA11BB22CC33DD44AA11BB22CC33DD44AA11BB22CC33DD44AA11BB22CC33DD44'  # 32 bytes

# FileRule PackageFamilyName for V5 block testing
$pkgFamily1 = 'KPT_PackageFamily'

# Signer CertRoot TBS hash values (distinctive byte patterns)
$tbs1 = 'DEADBEEF01020304DEADBEEF01020304DEADBEEF01020304DEADBEEF01020304'  # 32 bytes
$tbs2 = 'CAFECAFE01020304CAFECAFE01020304CAFECAFE01020304CAFECAFE01020304'  # 32 bytes
$tbs3 = 'FACE1234FACE1234FACE1234FACE1234FACE1234FACE1234FACE1234FACE1234'  # 32 bytes (3rd signer)

# Signer CertPublisher values
$pub1 = 'KPT_PUBLISHER_ALPHA'
$pub2 = 'KPT_PUBLISHER_BETA'
$pub3 = 'KPT_PUBLISHER_GAMMA'

# Signer CertOemID (tests String2 in binary signer structure)
$oemId1 = 'KPT_OEM_DELTA'

# FriendlyName test (should NOT appear in compiled binary — compilation is lossy)
$friendlyNameTest = 'KPT_FriendlyName_ShouldNotAppear'

# Settings — ALL 4 value types (Boolean, DWord, String, Binary)
$settingsProvider  = 'KPT_SettingsProvider'
$settingsKey1      = 'KPT_BoolKey'
$settingsValue1    = 'KPT_BoolValue'
$settingsKey2      = 'KPT_DWordKey'
$settingsValue2    = 'KPT_DWordValue'
$settingsKey3      = 'KPT_StringKey'
$settingsValue3    = 'KPT_StringValueName'
$settingsStringVal = 'KPT_TheActualStringContent'
$settingsKey4      = 'KPT_BinaryKey'
$settingsValue4    = 'KPT_BinaryValue'
$settingsBinHex    = 'DEAD0099DEAD0099'  # 8 bytes

# Expected header section counts
$expectedCounts = @{
    EKU      = 3     # 3 EKUs
    FileRule = 3     # Allow + Deny + FileAttrib
    Signer   = 3     # 3 signers (incl. one for DeniedSigner)
    Scenario = 2     # Drivers + UserMode
    UpdSign  = 2     # 2 update policy signers (body-prefixed)
    CISign   = 1     # 1 CI signer (body-prefixed)
    SuppSign = 1     # 1 supplemental policy signer (body-prefixed)
}

# Build the XML
$rulesXml = ($ruleOptions | ForEach-Object { "    <Rule><Option>$_</Option></Rule>" }) -join "`n"

$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>$version</VersionEx>
  <PlatformID>$platformId</PlatformID>
  <Rules>
$rulesXml
  </Rules>
  <EKUs>
    <EKU ID="ID_EKU_WINDOWS" FriendlyName="Windows System Component Verification" Value="$eku1Hex" />
    <EKU ID="ID_EKU_ELAM" FriendlyName="Early Launch AM Driver" Value="$eku2Hex" />
    <EKU ID="ID_EKU_STORE" FriendlyName="Windows Store" Value="$eku3Hex" />
  </EKUs>
  <FileRules>
    <Allow ID="ID_ALLOW_A_1" FriendlyName="$friendlyNameTest" FileName="$fileName1" MinimumFileVersion="1.2.3.4" InternalName="$internalName1" FileDescription="$fileDesc1" ProductName="$productName1" PackageFamilyName="$pkgFamily1" />
    <Deny ID="ID_DENY_D_1" FriendlyName="$friendlyNameTest" FileName="$fileName2" MinimumFileVersion="5.6.7.8" />
    <FileAttrib ID="ID_FILEATTRIB_F_1" FriendlyName="$friendlyNameTest" FileName="$fileName3" MinimumFileVersion="9.10.11.12" MaximumFileVersion="99.88.77.66" />
  </FileRules>
  <Signers>
    <Signer ID="ID_SIGNER_S_1" Name="KPT_Signer_One">
      <CertRoot Type="TBS" Value="$tbs1" />
      <CertEKU ID="ID_EKU_WINDOWS" />
      <CertPublisher Value="$pub1" />
      <CertOemID Value="$oemId1" />
      <FileAttribRef RuleID="ID_FILEATTRIB_F_1" />
    </Signer>
    <Signer ID="ID_SIGNER_S_2" Name="KPT_Signer_Two">
      <CertRoot Type="TBS" Value="$tbs2" />
      <CertEKU ID="ID_EKU_ELAM" />
      <CertEKU ID="ID_EKU_STORE" />
      <CertPublisher Value="$pub2" />
    </Signer>
    <Signer ID="ID_SIGNER_S_3" Name="KPT_Signer_Three">
      <CertRoot Type="TBS" Value="$tbs3" />
      <CertPublisher Value="$pub3" />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS" FriendlyName="KPT_Scenario_Drivers">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1">
            <ExceptDenyRule DenyRuleID="ID_DENY_D_1" />
          </AllowedSigner>
        </AllowedSigners>
        <DeniedSigners>
          <DeniedSigner SignerId="ID_SIGNER_S_3">
            <ExceptAllowRule AllowRuleID="ID_ALLOW_A_1" />
          </DeniedSigner>
        </DeniedSigners>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_USERMODE" FriendlyName="KPT_Scenario_UserMode">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_2" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners>
    <UpdatePolicySigner SignerId="ID_SIGNER_S_1" />
    <UpdatePolicySigner SignerId="ID_SIGNER_S_2" />
  </UpdatePolicySigners>
  <CiSigners>
    <CiSigner SignerId="ID_SIGNER_S_2" />
  </CiSigners>
  <SupplementalPolicySigners>
    <SupplementalPolicySigner SignerId="ID_SIGNER_S_3" />
  </SupplementalPolicySigners>
  <HvciOptions>2</HvciOptions>
  <Settings>
    <Setting Provider="$settingsProvider" Key="$settingsKey1" ValueName="$settingsValue1">
      <Value><Boolean>true</Boolean></Value>
    </Setting>
    <Setting Provider="$settingsProvider" Key="$settingsKey2" ValueName="$settingsValue2">
      <Value><DWord>42</DWord></Value>
    </Setting>
    <Setting Provider="$settingsProvider" Key="$settingsKey3" ValueName="$settingsValue3">
      <Value><String>$settingsStringVal</String></Value>
    </Setting>
    <Setting Provider="$settingsProvider" Key="$settingsKey4" ValueName="$settingsValue4">
      <Value><Binary>$settingsBinHex</Binary></Value>
    </Setting>
  </Settings>
  <PolicyID>$policyId</PolicyID>
  <BasePolicyID>$basePolicyId</BasePolicyID>
</SiPolicy>
"@

Log "XML Policy generated with known marker values (BASE — with SupplementalPolicySigners):"
Log "  PolicyID:        $policyId"
Log "  BasePolicyID:    $basePolicyId  (SAME — base policy)"
Log "  PlatformID:      $platformId"
Log "  Version:         $version"
Log "  PolicyType:      Base Policy"
Log "  RuleOptions:     $($ruleOptions.Count) (expected OptionFlags=0x$($expectedOptionFlags.ToString('X8')))"
Log "  EKUs:            $($expectedCounts.EKU) (incl. Windows Store for 3rd EKU test)"
Log "  FileRules:       $($expectedCounts.FileRule) (Allow+V4meta+PkgFamily, Deny+FileName, Attrib+MaxVer)"
Log "  Signers:         $($expectedCounts.Signer) (S1:TBS+EKU+Pub+OemID+FA, S2:TBS+2EKU+Pub, S3:TBS+Pub+DeniedSigner)"
Log "  Scenarios:       $($expectedCounts.Scenario) (Drivers=131 w/AllowedSigner+DeniedSigner, UserMode=12)"
Log "  UpdateSigners:   $($expectedCounts.UpdSign) (body count-prefixed)"
Log "  CISigners:       $($expectedCounts.CISign) (body count-prefixed)"
Log "  SuppSigners:     $($expectedCounts.SuppSign) (body count-prefixed — SupplementalPolicySigners)"
Log "  HVCI:            2"
Log "  Settings:        4 (Boolean=true, DWord=42, String='$settingsStringVal', Binary=$settingsBinHex)"
Log "  FriendlyName:    '$friendlyNameTest' (should NOT appear in binary)"

# ============================================================================
# STEP 2: Convert XML to Binary
# ============================================================================
LogSection 'STEP 2: Convert to Binary via ConvertFrom-CIPolicy'

$xmlPath = Join-Path $tempDir 'KPT-Comprehensive.xml'
$binPath = Join-Path $tempDir 'KPT-Comprehensive.cip'

[System.IO.File]::WriteAllText($xmlPath, $xml, [System.Text.UTF8Encoding]::new($true))
Log "XML written to: $xmlPath"

try {
    ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $binPath -ErrorAction Stop | Out-Null
    Log "Binary written to: $binPath"
} catch {
    Log "ERROR: ConvertFrom-CIPolicy failed: $($_.Exception.Message)"
    Log ''
    Log 'This may indicate an issue with the XML structure.'
    Log 'Check the XML and retry.'
    $script:output | Out-File -FilePath $transcriptPath -Encoding utf8
    return
}

$data = [System.IO.File]::ReadAllBytes($binPath)
Log "Binary size: $($data.Length) bytes (0x$($data.Length.ToString('X4')))"

# ============================================================================
# STEP 3: Full Hex Dump
# ============================================================================
LogSection 'STEP 3: Full Hex Dump'

$hexLines = Format-HexDump -Data $data
foreach ($line in $hexLines) { Log $line }

# ============================================================================
# STEP 4: Header Analysis (first 0x44 bytes = 68 bytes)
# ============================================================================
LogSection 'STEP 4: Header Analysis (0x00 - 0x43)'

# Read header fields at our assumed offsets
$fmtVer      = [BitConverter]::ToInt32($data, 0x00)
$hdrPTIDBytes = $data[0x04..0x13]
$hdrPTIDGuid  = [System.Guid]::new([byte[]]$hdrPTIDBytes)
$hdrPlatBytes = $data[0x14..0x23]
$hdrPlatGuid  = [System.Guid]::new([byte[]]$hdrPlatBytes)
$optFlags     = [BitConverter]::ToUInt32($data, 0x24)
$ekuC         = [BitConverter]::ToInt32($data, 0x28)
$frC          = [BitConverter]::ToInt32($data, 0x2C)
$sigC         = [BitConverter]::ToInt32($data, 0x30)
$scnC         = [BitConverter]::ToInt32($data, 0x34)
$vRev         = [BitConverter]::ToUInt16($data, 0x38)
$vBuild       = [BitConverter]::ToUInt16($data, 0x3A)
$vMinor       = [BitConverter]::ToUInt16($data, 0x3C)
$vMajor       = [BitConverter]::ToUInt16($data, 0x3E)
$hdrLen       = [BitConverter]::ToInt32($data, 0x40)

Log "  Offset  Value"
Log "  ------  -----"
Log "  0x00    FormatVersion         = $fmtVer"
Log "  0x04    PolicyTypeID/BasePID  = {$hdrPTIDGuid}"
Log "  0x14    PlatformID            = {$hdrPlatGuid}"
Log ('  0x24    OptionFlags           = 0x{0:X8} ({0})' -f $optFlags)
Log "  0x28    EKUCount              = $ekuC"
Log "  0x2C    FileRuleCount         = $frC"
Log "  0x30    SignerCount           = $sigC"
Log "  0x34    ScenarioCount         = $scnC"
Log "  0x38    Version               = $vMajor.$vMinor.$vBuild.$vRev  (Rev=$vRev Build=$vBuild Minor=$vMinor Major=$vMajor)"
Log ('  0x40    HeaderLength          = 0x{0:X4} ({0})' -f $hdrLen)

Log ''
Log '  --- HEADER VALIDATION against expected values ---'
$validations = @(
    @{ Field = 'FormatVersion';     Offset = 0x00; Expected = '>=6';       Actual = "$fmtVer";         Match = ($fmtVer -ge 6) },
    @{ Field = 'PolicyTypeID';      Offset = 0x04; Expected = $basePolicyId; Actual = "{$hdrPTIDGuid}"; Match = ("{$hdrPTIDGuid}" -eq $basePolicyId) },
    @{ Field = 'PlatformID';        Offset = 0x14; Expected = $platformId;  Actual = "{$hdrPlatGuid}";  Match = ("{$hdrPlatGuid}" -eq $platformId) },
    @{ Field = 'OptionFlags';       Offset = 0x24; Expected = ('0x{0:X8}' -f $expectedOptionFlags); Actual = ('0x{0:X8}' -f $optFlags); Match = (('0x{0:X8}' -f $optFlags) -eq ('0x{0:X8}' -f $expectedOptionFlags)) },
    @{ Field = 'EKUCount';          Offset = 0x28; Expected = "$($expectedCounts.EKU)";      Actual = "$ekuC";  Match = ($ekuC -eq $expectedCounts.EKU) },
    @{ Field = 'FileRuleCount';     Offset = 0x2C; Expected = "$($expectedCounts.FileRule)";  Actual = "$frC";   Match = ($frC -eq $expectedCounts.FileRule) },
    @{ Field = 'SignerCount';       Offset = 0x30; Expected = "$($expectedCounts.Signer)";    Actual = "$sigC";  Match = ($sigC -eq $expectedCounts.Signer) },
    @{ Field = 'ScenarioCount';     Offset = 0x34; Expected = "$($expectedCounts.Scenario)";  Actual = "$scnC";  Match = ($scnC -eq $expectedCounts.Scenario) },
    @{ Field = 'Version';           Offset = 0x38; Expected = $version;    Actual = "$vMajor.$vMinor.$vBuild.$vRev"; Match = ("$vMajor.$vMinor.$vBuild.$vRev" -eq $version) },
    @{ Field = 'HeaderLength';      Offset = 0x40; Expected = '0x0040';    Actual = ('0x{0:X4}' -f $hdrLen); Match = ($hdrLen -eq 0x40) }
)
# NOTE: UpdateSignerCount and CISignerCount are NOT in the header.
# They are count-prefixed in the body between Signers and Scenarios.

$headerPass = 0
$headerFail = 0
foreach ($v in $validations) {
    $status = if ($v.Match) { $headerPass++; 'OK' } else { $headerFail++; '** MISMATCH **' }
    Log ('  0x{0:X2}  {1,-22} Expected={2,-20} Actual={3,-20} [{4}]' -f $v.Offset, $v.Field, $v.Expected, $v.Actual, $status)
}
Log ''
Log "  Header validation: $headerPass OK, $headerFail MISMATCH"

# If header doesn't match at ALL, try alternate header layouts
if ($headerFail -gt 4) {
    Log ''
    Log '  *** MANY HEADER MISMATCHES — scanning for known GUIDs anywhere in first 256 bytes ***'
    $pidBytes = ConvertTo-GuidBytes $policyId
    $platBytes = ConvertTo-GuidBytes $platformId
    for ($off = 0; $off -lt [Math]::Min(256, $data.Length - 16); $off += 4) {
        $testGuid = [System.Guid]::new([byte[]]($data[$off..($off+15)]))
        if ("{$testGuid}" -eq $basePolicyId) {
            Log "  BasePolicyID GUID found at offset 0x$($off.ToString('X2'))"
        }
        if ("{$testGuid}" -eq $platformId) {
            Log "  PlatformID GUID found at offset 0x$($off.ToString('X2'))"
        }
    }
}

# ============================================================================
# STEP 5: Known Value Search (find all marker values in the binary)
# ============================================================================
LogSection 'STEP 5: Known Value Search'

Log '  --- GUIDs (16-byte .NET binary format) ---'
Search-KnownValue -Data $data -Label 'PolicyID GUID'     -Pattern (ConvertTo-GuidBytes $policyId)
Search-KnownValue -Data $data -Label 'BasePolicyID GUID' -Pattern (ConvertTo-GuidBytes $basePolicyId)
Search-KnownValue -Data $data -Label 'PlatformID GUID'   -Pattern (ConvertTo-GuidBytes $platformId)

Log ''
Log '  --- Strings (UTF-16LE encoded) ---'
$searchStrings = @(
    @{ Label = 'FileName: KPT_ALLOWED.dll';      Value = $fileName1 }
    @{ Label = 'FileName: KPT_DENIED.exe';       Value = $fileName2 }
    @{ Label = 'FileName: KPT_ATTRIB.sys';       Value = $fileName3 }
    @{ Label = 'Publisher: KPT_PUBLISHER_ALPHA';  Value = $pub1 }
    @{ Label = 'Publisher: KPT_PUBLISHER_BETA';   Value = $pub2 }
    @{ Label = 'Publisher: KPT_PUBLISHER_GAMMA';  Value = $pub3 }
    @{ Label = 'OemID: KPT_OEM_DELTA';           Value = $oemId1 }
    @{ Label = 'V4 InternalName: KPT_Internal';  Value = $internalName1 }
    @{ Label = 'V4 FileDesc: KPT_FileDesc';      Value = $fileDesc1 }
    @{ Label = 'V4 ProductName: KPT_Product';    Value = $productName1 }
    @{ Label = 'V5 PkgFamily: KPT_PackageFamily'; Value = $pkgFamily1 }
    @{ Label = 'Setting: KPT_SettingsProvider';  Value = $settingsProvider }
    @{ Label = 'Setting: KPT_BoolKey';           Value = $settingsKey1 }
    @{ Label = 'Setting: KPT_DWordKey';          Value = $settingsKey2 }
    @{ Label = 'Setting: KPT_StringKey';         Value = $settingsKey3 }
    @{ Label = 'Setting: KPT_BinaryKey';         Value = $settingsKey4 }
    @{ Label = 'Setting: KPT_TheActualString';   Value = $settingsStringVal }
    @{ Label = 'FriendlyName: KPT_FriendlyName'; Value = $friendlyNameTest }
    @{ Label = 'Scenario: KPT_Scenario_Drivers'; Value = 'KPT_Scenario_Drivers' }
    @{ Label = 'Scenario: KPT_Scenario_UserMode'; Value = 'KPT_Scenario_UserMode' }
)
foreach ($s in $searchStrings) {
    Search-KnownValue -Data $data -Label $s.Label -Pattern (ConvertTo-Utf16Bytes $s.Value)
}
Log ''
Log '  --- FriendlyName Verdict ---'
$fnBytes = ConvertTo-Utf16Bytes $friendlyNameTest
$fnOffsets = Find-BytePattern -Data $data -Pattern $fnBytes
if ($fnOffsets.Count -eq 0) {
    Log '  CONFIRMED: FriendlyName is NOT in the binary — compilation is lossy (as expected)'
} else {
    Log "  SURPRISE: FriendlyName FOUND at $($fnOffsets.Count) location(s)!"
}

Log ''
Log '  --- Raw Byte Patterns ---'
# TBS cert hash markers (distinctive 8-byte prefix of each 32-byte hash)
Search-KnownValue -Data $data -Label 'TBS1 hash: DEADBEEF...' -Pattern ([byte[]]@(0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04))
Search-KnownValue -Data $data -Label 'TBS2 hash: CAFECAFE...' -Pattern ([byte[]]@(0xCA,0xFE,0xCA,0xFE,0x01,0x02,0x03,0x04))
Search-KnownValue -Data $data -Label 'TBS3 hash: FACE1234...' -Pattern ([byte[]]@(0xFA,0xCE,0x12,0x34,0xFA,0xCE,0x12,0x34))

# File hash on Deny rule (SHA256 = 32 bytes)
Search-KnownValue -Data $data -Label 'FileHash2: AA11BB22...' -Pattern ([byte[]]@(0xAA,0x11,0xBB,0x22,0xCC,0x33,0xDD,0x44))

# Settings binary value
Search-KnownValue -Data $data -Label 'SettingsBin: DEAD0099...' -Pattern ([byte[]]@(0xDE,0xAD,0x00,0x99,0xDE,0xAD,0x00,0x99))

# EKU OID byte patterns (the DER OID content, not including tag/length)
$eku1Bytes = [byte[]]@(0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x03,0x06)
$eku2Bytes = [byte[]]@(0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x03,0x15)
$eku3Bytes = [byte[]]@(0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x03,0x0C)
Search-KnownValue -Data $data -Label 'EKU1 OID: 2B0601..0306'   -Pattern $eku1Bytes
Search-KnownValue -Data $data -Label 'EKU2 OID: 2B0601..0315'   -Pattern $eku2Bytes
Search-KnownValue -Data $data -Label 'EKU3 OID: 2B0601..030C'   -Pattern $eku3Bytes

# Full EKU hex as raw bytes (the complete Value attribute, decoded from hex)
$eku1Full = [byte[]]($eku1Hex -replace '..', '0x$& ' -split ' ' | Where-Object { $_ } | ForEach-Object { [byte]$_ })
$eku2Full = [byte[]]($eku2Hex -replace '..', '0x$& ' -split ' ' | Where-Object { $_ } | ForEach-Object { [byte]$_ })
$eku3Full = [byte[]]($eku3Hex -replace '..', '0x$& ' -split ' ' | Where-Object { $_ } | ForEach-Object { [byte]$_ })
Search-KnownValue -Data $data -Label 'EKU1 full hex value'       -Pattern $eku1Full
Search-KnownValue -Data $data -Label 'EKU2 full hex value'       -Pattern $eku2Full
Search-KnownValue -Data $data -Label 'EKU3 full hex value'       -Pattern $eku3Full

Log ''
Log '  --- V-Block Markers (int32 at 4-byte aligned body offsets) ---'
foreach ($m in @(3, 4, 5, 6, 7, 8, 9)) {
    $pattern = [BitConverter]::GetBytes([int]$m)
    $offsets = Find-BytePattern -Data $data -Pattern $pattern
    $bodyAligned = $offsets | Where-Object { $_ -ge 0x44 -and ($_ % 4) -eq 0 }
    if ($bodyAligned.Count -gt 0) {
        $offsetsStr = ($bodyAligned | ForEach-Object { '0x{0:X4}' -f $_ }) -join ', '
        Log "  V$m marker candidates (int32=$m, body, aligned): $offsetsStr"
    }
}

# ============================================================================
# STEP 6: Body Traversal with Full Annotation
# ============================================================================
LogSection 'STEP 6: Body Traversal (structural walk)'

# Track section boundaries for summary
$sectionMap = [ordered]@{}
$pos = 0x44
$traversalOK = $true

Log "  Body starts at 0x$($pos.ToString('X4')) (after $($pos)-byte header)"
Log ''

# --- Section 1: EKU Rules ---
$sec1Start = $pos
Log "  SEC1: EKU Rules (count=$ekuC from header 0x28)"
for ($i = 0; $i -lt $ekuC; $i++) {
    if ($pos + 4 -gt $data.Length) { Log "    OVERRUN at EKU[$i]"; $traversalOK = $false; break }
    $ekuLen = [BitConverter]::ToUInt32($data, $pos)
    $ekuPad = [int]((4 - ($ekuLen % 4)) -band 3)
    $ekuTotal = 4 + [int]$ekuLen + $ekuPad
    $ekuHex = if ($ekuLen -gt 0) { ($data[($pos+4)..($pos+3+[int]$ekuLen)] | ForEach-Object { $_.ToString('X2') }) -join '' } else { '(empty)' }
    Log "    EKU[$i] at 0x$($pos.ToString('X4')): len=$ekuLen pad=$ekuPad total=$ekuTotal hex=$ekuHex"
    $pos += $ekuTotal
}
$sectionMap['Sec1_EKU'] = @{ Start = $sec1Start; End = $pos; Count = $ekuC }
Log "  SEC1 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $sec1Start) bytes)"
Log ''

# --- Section 2: File Rules ---
$sec2Start = $pos
Log "  SEC2: File Rules (count=$frC from header 0x2C)"
for ($i = 0; $i -lt $frC; $i++) {
    if ($pos + 4 -gt $data.Length) { Log "    OVERRUN at FileRule[$i]"; $traversalOK = $false; break }
    $ruleType = [BitConverter]::ToInt32($data, $pos)
    $ruleTypeName = switch ($ruleType) { 0 { 'Deny' }; 1 { 'Allow' }; 2 { 'FileAttrib' }; default { "Unknown($ruleType)" } }
    Log "    FileRule[$i] at 0x$($pos.ToString('X4')): type=$ruleType ($ruleTypeName)"
    $pos += 4

    # FileName (binary string)
    $str = Read-BinaryString -Data $data -Position $pos
    Log "      FileName: len=$($str.Length) consumed=$($str.Consumed) value='$($str.Value)'"
    $pos += $str.Consumed

    # MinimumFileVersion (8 bytes = 4 x uint16, stored Rev,Build,Minor,Major)
    $vr2 = [BitConverter]::ToUInt16($data, $pos)
    $vb2 = [BitConverter]::ToUInt16($data, $pos + 2)
    $vm2 = [BitConverter]::ToUInt16($data, $pos + 4)
    $vj2 = [BitConverter]::ToUInt16($data, $pos + 6)
    Log "      MinFileVer: $vj2.$vm2.$vb2.$vr2 at 0x$($pos.ToString('X4'))"
    $pos += 8

    # Hash
    $hashLen = [BitConverter]::ToUInt32($data, $pos)
    $hashPad = if ($hashLen -gt 0) { [int]((4 - ($hashLen % 4)) -band 3) } else { 0 }
    Log "      Hash: len=$hashLen at 0x$($pos.ToString('X4'))"
    $pos += 4
    if ($hashLen -gt 0) { $pos += [int]$hashLen + $hashPad }
}
$sectionMap['Sec2_FileRule'] = @{ Start = $sec2Start; End = $pos; Count = $frC }
Log "  SEC2 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $sec2Start) bytes)"
Log ''

# --- Section 3: Signer Rules ---
$sec3Start = $pos
Log "  SEC3: Signer Rules (count=$sigC from header 0x30)"
for ($i = 0; $i -lt $sigC; $i++) {
    if ($pos + 4 -gt $data.Length) { Log "    OVERRUN at Signer[$i]"; $traversalOK = $false; break }
    $certRootType = [BitConverter]::ToInt32($data, $pos)
    $crtName = if ($certRootType -eq 0) { 'TBS' } else { "WellKnown($certRootType)" }
    Log "    Signer[$i] at 0x$($pos.ToString('X4')): CertRootType=$certRootType ($crtName)"
    $pos += 4

    if ($certRootType -eq 0) {
        # TBS: [len:4][hash+pad]
        $crtLen = [BitConverter]::ToUInt32($data, $pos)
        $crtPad = [int]((4 - ($crtLen % 4)) -band 3)
        $crtHex = if ($crtLen -gt 0 -and ($pos + 4 + [int]$crtLen) -le $data.Length) {
            ($data[($pos+4)..($pos+3+[int]$crtLen)] | ForEach-Object { $_.ToString('X2') }) -join ''
        } else { '(error)' }
        Log "      TBS hash: len=$crtLen pad=$crtPad hex=$crtHex"
        $pos += 4 + [int]$crtLen + $crtPad
    } else {
        # WellKnown: [value:4]
        $wkVal = [BitConverter]::ToUInt32($data, $pos)
        Log "      WellKnown value: $wkVal"
        $pos += 4
    }

    # EKU reference count + indices
    $ekuRefC = [BitConverter]::ToUInt32($data, $pos)
    Log "      EKU refs: count=$ekuRefC at 0x$($pos.ToString('X4'))"
    $pos += 4
    for ($j = 0; $j -lt [int]$ekuRefC; $j++) {
        $idx = [BitConverter]::ToUInt32($data, $pos)
        Log "        EKU[$j] -> index $idx"
        $pos += 4
    }

    # 3 binary strings (we'll discover what each one maps to)
    $stringLabels = @('String0 (CertIssuer?)', 'String1 (CertPublisher?)', 'String2 (CertOemID?)')
    for ($s = 0; $s -lt 3; $s++) {
        $str = Read-BinaryString -Data $data -Position $pos
        Log "      $($stringLabels[$s]): len=$($str.Length) consumed=$($str.Consumed) value='$($str.Value)'"
        $pos += $str.Consumed
    }

    # FileAttrib reference count + indices
    $faRefC = [BitConverter]::ToUInt32($data, $pos)
    Log "      FileAttrib refs: count=$faRefC at 0x$($pos.ToString('X4'))"
    $pos += 4
    for ($j = 0; $j -lt [int]$faRefC; $j++) {
        $idx = [BitConverter]::ToUInt32($data, $pos)
        Log "        FA[$j] -> index $idx"
        $pos += 4
    }
}
$sectionMap['Sec3_Signer'] = @{ Start = $sec3Start; End = $pos; Count = $sigC }
Log "  SEC3 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $sec3Start) bytes)"
Log ''

# --- Section 4: UpdatePolicy Signers (count-prefixed in body) ---
$sec4Start = $pos
$upsC = [BitConverter]::ToUInt32($data, $pos)
Log "  SEC4: UpdatePolicy Signers (count=$upsC from body at 0x$($pos.ToString('X4')))"
$pos += 4
for ($i = 0; $i -lt [int]$upsC; $i++) {
    $idx = [BitConverter]::ToUInt32($data, $pos)
    Log "    UpdSigner[$i] at 0x$($pos.ToString('X4')): -> signer index $idx"
    $pos += 4
}
$sectionMap['Sec4_UpdSign'] = @{ Start = $sec4Start; End = $pos; Count = [int]$upsC }
Log "  SEC4 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $sec4Start) bytes)"
Log ''

# --- Section 5: CI Signers (count-prefixed in body) ---
$sec5Start = $pos
$cisC = [BitConverter]::ToUInt32($data, $pos)
Log "  SEC5: CI Signers (count=$cisC from body at 0x$($pos.ToString('X4')))"
$pos += 4
for ($i = 0; $i -lt [int]$cisC; $i++) {
    $idx = [BitConverter]::ToUInt32($data, $pos)
    Log "    CISigner[$i] at 0x$($pos.ToString('X4')): -> signer index $idx"
    $pos += 4
}
$sectionMap['Sec5_CISign'] = @{ Start = $sec5Start; End = $pos; Count = [int]$cisC }
Log "  SEC5 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $sec5Start) bytes)"
Log ''

# --- Section 6: Supplemental Policy Signers (PROBE — may not exist as body section) ---
$sec6Start = $pos
$probeVal = [BitConverter]::ToUInt32($data, $pos)
if ($probeVal -le 10) {
    # Plausible count for supplemental policy signers (small uint32)
    $spsC = $probeVal
    Log "  SEC6: SupplementalPolicy Signers (count=$spsC from body at 0x$($pos.ToString('X4')))"
    $pos += 4
    for ($i = 0; $i -lt [int]$spsC; $i++) {
        $idx = [BitConverter]::ToUInt32($data, $pos)
        Log "    SuppSigner[$i] at 0x$($pos.ToString('X4')): -> signer index $idx"
        $pos += 4
    }
    $sectionMap['Sec6_SuppSign'] = @{ Start = $sec6Start; End = $pos; Count = [int]$spsC }
    Log "  SEC6 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $sec6Start) bytes)"
} else {
    Log "  SEC6: SupplementalPolicy Signers — NOT PRESENT as body section"
    Log "    Probe value at 0x$($pos.ToString('X4')): $probeVal (0x$($probeVal.ToString('X8'))) — too large for a count"
    Log "    SupplementalPolicySigners may be stored in V-blocks, or not preserved in binary (lossy)"
    $sectionMap['Sec6_SuppSign'] = @{ Start = $sec6Start; End = $sec6Start; Count = 0 }
}
Log ''

# --- Section 7: Signing Scenarios ---
$sec7Start = $pos
Log "  SEC7: Signing Scenarios (count=$scnC from header 0x34)"
$catNames = @('Product', 'Test', 'TestSigning')
for ($i = 0; $i -lt $scnC; $i++) {
    if ($pos + 4 -gt $data.Length) { Log "    OVERRUN at Scenario[$i]"; $traversalOK = $false; break }
    $scenVal = [BitConverter]::ToUInt32($data, $pos)
    $scenName = switch ($scenVal -band 0xFF) { 131 { 'Drivers' }; 12 { 'UserMode' }; default { 'Unknown' } }
    Log "    Scenario[$i] at 0x$($pos.ToString('X4')): value=$scenVal ($scenName)"
    $pos += 4

    $inhC = [BitConverter]::ToUInt32($data, $pos)
    Log "      Inherited: count=$inhC at 0x$($pos.ToString('X4'))"
    $pos += 4
    for ($j = 0; $j -lt [int]$inhC; $j++) { $pos += 4 }

    $minHash = [BitConverter]::ToUInt32($data, $pos)
    Log "      MinHashAlgo: $minHash at 0x$($pos.ToString('X4'))"
    $pos += 4

    for ($cat = 0; $cat -lt 3; $cat++) {
        # Allowed signers
        $allowC = [BitConverter]::ToUInt32($data, $pos)
        Log "      $($catNames[$cat]) Allowed: $allowC at 0x$($pos.ToString('X4'))"
        $pos += 4
        for ($j = 0; $j -lt [int]$allowC; $j++) {
            $sigIdx = [BitConverter]::ToUInt32($data, $pos); $pos += 4
            $exDenyC = [BitConverter]::ToUInt32($data, $pos); $pos += 4
            Log "        Allow[$j]: signer=$sigIdx exceptDeny=$exDenyC"
            for ($k = 0; $k -lt [int]$exDenyC; $k++) {
                $denyIdx = [BitConverter]::ToUInt32($data, $pos); $pos += 4
                Log "          exceptDeny[$k] -> $denyIdx"
            }
        }
        # Denied signers
        $denyC = [BitConverter]::ToUInt32($data, $pos)
        Log "      $($catNames[$cat]) Denied: $denyC at 0x$($pos.ToString('X4'))"
        $pos += 4
        for ($j = 0; $j -lt [int]$denyC; $j++) {
            $sigIdx = [BitConverter]::ToUInt32($data, $pos); $pos += 4
            $exAllowC = [BitConverter]::ToUInt32($data, $pos); $pos += 4
            Log "        Deny[$j]: signer=$sigIdx exceptAllow=$exAllowC"
            for ($k = 0; $k -lt [int]$exAllowC; $k++) {
                $allowIdx = [BitConverter]::ToUInt32($data, $pos); $pos += 4
                Log "          exceptAllow[$k] -> $allowIdx"
            }
        }
        # FileRule refs
        $frRefC = [BitConverter]::ToUInt32($data, $pos)
        Log "      $($catNames[$cat]) FileRuleRefs: $frRefC at 0x$($pos.ToString('X4'))"
        $pos += 4
        for ($j = 0; $j -lt [int]$frRefC; $j++) {
            $frIdx = [BitConverter]::ToUInt32($data, $pos); $pos += 4
            Log "        FileRuleRef[$j] -> $frIdx"
        }
    }
}
$sectionMap['Sec7_Scenario'] = @{ Start = $sec7Start; End = $pos; Count = $scnC }
Log "  SEC7 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $sec7Start) bytes)"
Log ''

# --- Section 8: HVCI Options ---
$sec8Start = $pos
$hvciVal = [BitConverter]::ToUInt32($data, $pos)
Log "  SEC8: HVCI Options at 0x$($pos.ToString('X4')): value=$hvciVal (expected=2)"
$pos += 4
$sectionMap['Sec8_HVCI'] = @{ Start = $sec8Start; End = $pos; Count = 1 }
Log "  SEC8 end: 0x$($pos.ToString('X4'))  (consumed 4 bytes)"
Log ''

# --- Section 9: Secure Settings ---
$sec9Start = $pos
$ssCount = [BitConverter]::ToUInt32($data, $pos)
Log "  SEC9: Secure Settings (count=$ssCount at 0x$($pos.ToString('X4')))"
$pos += 4
for ($i = 0; $i -lt [int]$ssCount; $i++) {
    Log "    Setting[$i] at 0x$($pos.ToString('X4')):"
    foreach ($fn in @('Provider', 'Key', 'ValueName')) {
        $str = Read-BinaryString -Data $data -Position $pos
        Log "      $fn`: len=$($str.Length) consumed=$($str.Consumed) value='$($str.Value)'"
        $pos += $str.Consumed
    }
    # Value type + value
    $valType = [BitConverter]::ToUInt32($data, $pos)
    $vtName = switch ($valType) { 0 { 'Boolean' }; 1 { 'UInt32' }; 2 { 'Binary' }; 3 { 'String' }; default { "Unknown($valType)" } }
    Log "      ValueType: $vtName ($valType) at 0x$($pos.ToString('X4'))"
    $pos += 4
    switch ($valType) {
        { $_ -in @(0, 1) } {
            $dword = [BitConverter]::ToUInt32($data, $pos)
            Log "      Value: $dword"
            $pos += 4
        }
        2 {
            $baLen = [BitConverter]::ToUInt32($data, $pos)
            $baPad = [int]((4 - ($baLen % 4)) -band 3)
            Log "      Binary: len=$baLen pad=$baPad"
            $pos += 4 + [int]$baLen + $baPad
        }
        3 {
            $str = Read-BinaryString -Data $data -Position $pos
            Log "      String: value='$($str.Value)'"
            $pos += $str.Consumed
        }
    }
}
$sectionMap['Sec9_Settings'] = @{ Start = $sec9Start; End = $pos; Count = [int]$ssCount }
Log "  SEC9 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $sec9Start) bytes)"
Log ''

# ============================================================================
# STEP 7: V-Block Parsing
# ============================================================================
LogSection 'STEP 7: V-Block Parsing'

$remaining = $data.Length - $pos
Log "  Remaining bytes after base sections: $remaining (from 0x$($pos.ToString('X4')) to 0x$($data.Length.ToString('X4')))"
Log ''

if ($remaining -gt 0) {
    Log '  Hex dump of all remaining V-block data:'
    $vHex = Format-HexDump -Data $data -Offset $pos -Length $remaining
    foreach ($line in $vHex) { Log "  $line" }
    Log ''
}

# Parse each V-block by marker
for ($v = 3; $v -le 9; $v++) {
    if ($pos -ge $data.Length - 3) { break }

    $marker = [BitConverter]::ToUInt32($data, $pos)
    if ($marker -ne $v) {
        if ($v -le $fmtVer) {
            Log "  ** Expected V$v marker at 0x$($pos.ToString('X4')), got $marker — MISMATCH **"
            Log '     Hex context:'
            $ctxLen = [Math]::Min(64, $data.Length - $pos)
            $ctxHex = Format-HexDump -Data $data -Offset $pos -Length $ctxLen
            foreach ($line in $ctxHex) { Log "     $line" }
            $traversalOK = $false
        }
        break
    }

    $vStart = $pos
    Log "  V$v block: marker found at 0x$($pos.ToString('X4'))"
    $pos += 4

    switch ($v) {
        3 {
            # Per FileRule: MaximumFileVersion (8 bytes) + MacroCount + Macros
            for ($i = 0; $i -lt $frC; $i++) {
                $vr3 = [BitConverter]::ToUInt16($data, $pos)
                $vb3 = [BitConverter]::ToUInt16($data, $pos + 2)
                $vm3 = [BitConverter]::ToUInt16($data, $pos + 4)
                $vj3 = [BitConverter]::ToUInt16($data, $pos + 6)
                $pos += 8
                $macroC = [BitConverter]::ToUInt32($data, $pos)
                $pos += 4
                Log "    V3 FileRule[$i]: MaxVer=$vj3.$vm3.$vb3.$vr3 Macros=$macroC"
                for ($j = 0; $j -lt [int]$macroC; $j++) {
                    $str = Read-BinaryString -Data $data -Position $pos
                    Log "      Macro[$j]: '$($str.Value)'"
                    $pos += $str.Consumed
                }
            }
            # Per Signer: SignTimeAfter (int64)
            for ($i = 0; $i -lt $sigC; $i++) {
                $sta = [BitConverter]::ToInt64($data, $pos)
                $pos += 8
                Log "    V3 Signer[$i]: SignTimeAfter=$sta"
            }
            $sectionMap["V3"] = @{ Start = $vStart; End = $pos }
            Log "  V3 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $vStart) bytes)"
        }
        4 {
            # Per FileRule: InternalName, FileDescription, ProductName (3 binary strings)
            for ($i = 0; $i -lt $frC; $i++) {
                $names = @()
                foreach ($fn in @('InternalName', 'FileDescription', 'ProductName')) {
                    $str = Read-BinaryString -Data $data -Position $pos
                    $names += "'$($str.Value)'"
                    Log "    V4 FileRule[$i] $fn`: '$($str.Value)' (len=$($str.Length))"
                    $pos += $str.Consumed
                }
            }
            $sectionMap["V4"] = @{ Start = $vStart; End = $pos }
            Log "  V4 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $vStart) bytes)"
        }
        5 {
            # Per FileRule: PackageFamilyName (binstr) + PackageVersion (8 bytes)
            for ($i = 0; $i -lt $frC; $i++) {
                $str = Read-BinaryString -Data $data -Position $pos
                $pos += $str.Consumed
                $pkgVer = [BitConverter]::ToUInt64($data, $pos)
                $pos += 8
                Log "    V5 FileRule[$i]: PkgFamilyName='$($str.Value)' PkgVer=$pkgVer"
            }
            $sectionMap["V5"] = @{ Start = $vStart; End = $pos }
            Log "  V5 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $vStart) bytes)"
        }
        6 {
            # PolicyID (GUID 16 bytes) + BasePolicyID (GUID 16 bytes) + trailing uint32
            $v6PidGuid  = [System.Guid]::new([byte[]]($data[$pos..($pos+15)]))
            $pos += 16
            $v6BpidGuid = [System.Guid]::new([byte[]]($data[$pos..($pos+15)]))
            $pos += 16
            # Mystery trailing uint32 discovered in first run (4 bytes between V6 data and V7 marker)
            $v6Trailing = [BitConverter]::ToUInt32($data, $pos)
            $pos += 4
            Log "    V6 PolicyID:     {$v6PidGuid}"
            Log "    V6 BasePolicyID: {$v6BpidGuid}"
            Log "    V6 Trailing:     $v6Trailing  (unknown purpose — 0 for base, changes for supplemental?)"
            $pidMatch  = ("{$v6PidGuid}".ToUpper()  -eq $policyId.ToUpper())
            $bpidMatch = ("{$v6BpidGuid}".ToUpper() -eq $basePolicyId.ToUpper())
            Log "    PolicyID matches XML:     $pidMatch"
            Log "    BasePolicyID matches XML: $bpidMatch"
            if ($policyId.ToUpper() -ne $basePolicyId.ToUpper()) {
                Log "    ** SUPPLEMENTAL POLICY: PolicyID ≠ BasePolicyID — V6 stores both independently **"
                # Check which GUID the header stores at 0x04
                $hdrGuidUpper = "{$hdrPTIDGuid}".ToUpper()
                if ($hdrGuidUpper -eq $basePolicyId.ToUpper()) {
                    Log "    ** Header 0x04 = BasePolicyID (CONFIRMED) **"
                } elseif ($hdrGuidUpper -eq $policyId.ToUpper()) {
                    Log "    ** Header 0x04 = PolicyID (UNEXPECTED — not BasePolicyID!) **"
                } else {
                    Log "    ** Header 0x04 = NEITHER PolicyID nor BasePolicyID — investigate! **"
                }
            }
            $sectionMap["V6"] = @{ Start = $vStart; End = $pos }
            Log "  V6 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $vStart) bytes)"
        }
        7 {
            # V7: Structure UNKNOWN — do NOT assume per-signer.
            # Observed: 24 data bytes with both 2 signers and 3 signers.
            # Probe forward for V8 marker to measure exact data size.
            $v7DataSize = 0
            for ($probe = $pos; $probe -lt $data.Length - 3; $probe += 4) {
                $probeVal = [BitConverter]::ToUInt32($data, $probe)
                if ($probeVal -eq 8) { $v7DataSize = $probe - $pos; break }
            }
            if ($v7DataSize -eq 0) { $v7DataSize = $data.Length - $pos }

            Log "    V7 data: $v7DataSize bytes total"
            Log "    Diagnostic ratios:"
            Log "      bytes/signer:   $v7DataSize / $sigC = $(if ($sigC -gt 0) { $v7DataSize / $sigC } else { 'N/A' })"
            Log "      bytes/scenario: $v7DataSize / $scnC = $(if ($scnC -gt 0) { $v7DataSize / $scnC } else { 'N/A' })"
            $v7WordCount = $v7DataSize / 4
            Log "      uint32 words:   $v7WordCount"

            # Dump all data as uint32 values
            for ($i = 0; $i -lt [int]$v7WordCount; $i++) {
                $wordOff = $pos + ($i * 4)
                $wordVal = [BitConverter]::ToUInt32($data, $wordOff)
                Log "    V7 word[$i] at 0x$($wordOff.ToString('X4')): $wordVal (0x$($wordVal.ToString('X8')))"
            }
            $pos += $v7DataSize
            $sectionMap["V7"] = @{ Start = $vStart; End = $pos }
            Log "  V7 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $vStart) bytes)"
        }
        8 {
            # V8: Previous run showed 4 bytes of zero data (single uint32)
            $v8Val = [BitConverter]::ToUInt32($data, $pos)
            Log "    V8 value: $v8Val at 0x$($pos.ToString('X4'))"
            $pos += 4
            $sectionMap["V8"] = @{ Start = $vStart; End = $pos }
            Log "  V8 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $vStart) bytes)"
        }
        9 {
            # V9: Marker only, no data (end-of-blocks sentinel)
            Log "    V9: end-of-blocks marker (no data)"
            $sectionMap["V9"] = @{ Start = $vStart; End = $pos }
            Log "  V9 end: 0x$($pos.ToString('X4'))  (consumed $($pos - $vStart) bytes)"
        }
        default {
            # Unknown V-block — dump hex for analysis
            Log "    V${v}: UNKNOWN block structure — hex dump of next 128 bytes:"
            $unkLen = [Math]::Min(128, $data.Length - $pos)
            $unkHex = Format-HexDump -Data $data -Offset $pos -Length $unkLen
            foreach ($line in $unkHex) { Log "    $line" }
            Log "    (cannot parse V$v — stopping traversal)"
            $sectionMap["V$v"] = @{ Start = $vStart; End = $pos }
            $pos = $data.Length  # stop
        }
    }
    Log ''
}

# ============================================================================
# STEP 8: Final Accounting
# ============================================================================
LogSection 'STEP 8: Final Position & Accounting'

$leftover = $data.Length - $pos
Log "  Final position:  0x$($pos.ToString('X4')) ($pos)"
Log "  Binary length:   0x$($data.Length.ToString('X4')) ($($data.Length))"
if ($leftover -eq 0) {
    Log '  PERFECT: All bytes accounted for by traversal!'
} elseif ($leftover -gt 0) {
    Log "  WARNING: $leftover unaccounted bytes remain (0x$($pos.ToString('X4')) - 0x$(($data.Length - 1).ToString('X4')))"
    $uhex = Format-HexDump -Data $data -Offset $pos -Length $leftover
    foreach ($line in $uhex) { Log "  $line" }
} else {
    Log "  ERROR: Traversal overread by $([Math]::Abs($leftover)) bytes!"
}
Log ''
Log "  Traversal status: $(if ($traversalOK) { 'SUCCESS — all sections parsed cleanly' } else { 'FAILED — see errors above' })"

# ============================================================================
# STEP 9: Structure Map Summary
# ============================================================================
LogSection 'STEP 9: Structure Map Summary'

Log '  Section           Start      End        Size     Items'
Log '  ---------------   ---------  ---------  -------  -----'
Log ('  {0,-18} 0x{1:X4}     0x{2:X4}     {3,5}    (fixed)' -f 'Header', 0x00, 0x44, 0x44)
foreach ($sec in $sectionMap.GetEnumerator()) {
    $size = $sec.Value.End - $sec.Value.Start
    $count = if ($sec.Value.ContainsKey('Count')) { "$($sec.Value.Count)" } else { '-' }
    Log ('  {0,-18} 0x{1:X4}     0x{2:X4}     {3,5}    {4}' -f $sec.Key, $sec.Value.Start, $sec.Value.End, $size, $count)
}
$totalMapped = 0x44
foreach ($sec in $sectionMap.Values) { $totalMapped += ($sec.End - $sec.Start) }
Log ''
Log "  Total mapped: $totalMapped / $($data.Length) bytes ($([Math]::Round($totalMapped / $data.Length * 100, 1))%)"

# ============================================================================
# STEP 10: Comparison with Parser Assumptions
# ============================================================================
LogSection 'STEP 10: Parser Assumption Validation'

Log '  This step compares what ConvertFrom-CIPolicy actually produced against'
Log '  the layout our Get-WDACPolicy.ps1 parser assumes.'
Log ''

# Check if section counts match
$parserAssumptions = @(
    "Header size:       0x44 (68 bytes)  — 11 fields, last is HeaderLength at 0x40"
    "Sec1 EKU:          [len:4][data+pad] * count  — count from header 0x28, no body count prefix"
    "Sec2 FileRule:     [type:4][name:binstr][minver:8][hashlen:4][hash+pad] * count  — count from header 0x2C"
    "Sec3 Signer:       [certRootType:4] + TBS/WellKnown + [ekuRefC:4][refs] + 3 binstrings + [faRefC:4][refs]  — count from header 0x30"
    "Sec4 UpdSigners:   [count:4][signerIdx:4 * count]  — count-prefixed in BODY (not header!)"
    "Sec5 CISigners:    [count:4][signerIdx:4 * count]  — count-prefixed in BODY (not header!)"
    "Sec6 SuppSigners:  [count:4][signerIdx:4 * count]  — count-prefixed in BODY (not header!)"
    "Sec7 Scenario:     [value:4][inhC:4][inhs...][minHash:4] + 3 categories x [allowC][deniedC][frRefC]  — count from header 0x34"
    "Sec8 HVCI:         single [uint32] value"
    "Sec9 Settings:     [count:4], then per entry: 3 binstrings + [valType:4] + value"
    "V3-V9 blocks:      [marker:4] then per-format data"
    "FriendlyName:      XML attribute — NOT preserved in binary (lossy compilation)"
)
foreach ($a in $parserAssumptions) { Log "  $a" }

Log ''
Log '  Key findings from this analysis:'
if ($headerFail -eq 0) {
    Log '  [OK] All header offsets match — header layout is CORRECT'
} else {
    Log "  [!!] $headerFail header offset(s) MISMATCHED — header layout needs fixing"
}

if ($traversalOK) {
    Log '  [OK] Full body traversal completed without overrun or mismatch'
} else {
    Log '  [!!] Body traversal FAILED — see section details above'
}

if ($leftover -eq 0) {
    Log '  [OK] All bytes accounted for — no unknown data'
} elseif ($leftover -gt 0) {
    Log "  [!!] $leftover bytes unaccounted for — possible unknown sections or V-blocks"
}

# ============================================================================
# Write transcript
# ============================================================================
Log ''
Log ('=' * 80)
Log '  Analysis complete.'
Log ('=' * 80)
Log "  Binary: $binPath"
Log "  XML:    $xmlPath"
Log "  Report: $transcriptPath"

$script:output | Out-File -FilePath $transcriptPath -Encoding utf8
Write-Host ''
Write-Host "Transcript written to: $transcriptPath" -ForegroundColor Green
