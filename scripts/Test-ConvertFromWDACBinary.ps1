#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnostic script for ConvertFrom-WDACBinary — validates binary parsing round-trip.

.DESCRIPTION
    Creates a CI policy from XML with known values, compiles to binary via
    ConvertFrom-CIPolicy, then parses the binary with ConvertFrom-WDACBinary
    and validates every field.

    All output is captured via Start-Transcript for agent analysis.

    Test cases:
      D1 — Binary header inspection (raw byte analysis)
      D2 — ConvertFrom-WDACBinary round-trip (minimal policy)
      D3 — ConvertFrom-WDACBinary round-trip (policy with signers/filerules/settings)

.PARAMETER TranscriptPath
    Path for the transcript log. Defaults to temp\converter-diag-transcript.txt.
#>
[CmdletBinding()]
param(
    [string]$TranscriptPath
)

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$moduleRoot = Split-Path $scriptDir -Parent

if (-not $TranscriptPath) {
    $transcriptDir = Join-Path $moduleRoot 'temp'
    if (-not (Test-Path $transcriptDir)) {
        New-Item -Path $transcriptDir -ItemType Directory -Force | Out-Null
    }
    $TranscriptPath = Join-Path $transcriptDir 'converter-diag-transcript.txt'
}

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

Import-Module $moduleManifest -Force -ErrorAction Stop
Write-Host "Module imported successfully from: $moduleManifest"

# Check ConfigCI availability
$hasCIPolicy = $null -ne (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue)
Write-Host "ConvertFrom-CIPolicy available: $hasCIPolicy"

if (-not $hasCIPolicy) {
    Write-Error "ConvertFrom-CIPolicy not available — ConfigCI module required"
    exit 1
}

# ---------------------------------------------------------------------------
# Helper: Write test result
# ---------------------------------------------------------------------------
function Write-TestResult {
    param([string]$Test, [string]$Status, [string]$Detail)
    $icon = switch ($Status) {
        'Pass' { '[PASS]' }
        'Fail' { '[FAIL]' }
        'Info' { '[INFO]' }
        'Error' { '[ERR ]' }
    }
    Write-Host "$icon $Test — $Detail"
}

# ---------------------------------------------------------------------------
# Temp directory for test artefacts
# ---------------------------------------------------------------------------
$testDir = Join-Path $moduleRoot 'temp' 'converter-diag'
if (-not (Test-Path $testDir)) {
    New-Item -Path $testDir -ItemType Directory -Force | Out-Null
}

# ═══════════════════════════════════════════════════════════════════════════
# D1 — Binary Header Inspection (minimal policy)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "`n========== D1: Binary Header Inspection =========="

$d1Xml = @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>10.0.5.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</PolicyID>
  <BasePolicyID>{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:Audit Mode</Option></Rule>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
  </Rules>
  <EKUs />
  <FileRules />
  <Signers />
  <SigningScenarios>
    <SigningScenario ID="ID_SIGNINGSCENARIO_DRIVERS" Value="131" FriendlyName="Drivers"><ProductSigners /></SigningScenario>
    <SigningScenario ID="ID_SIGNINGSCENARIO_USERMODE" Value="12" FriendlyName="UserMode"><ProductSigners /></SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners />
  <CiSigners />
  <HvciOptions>0</HvciOptions>
</SiPolicy>
'@

$d1XmlPath = Join-Path $testDir 'd1-minimal.xml'
$d1CipPath = Join-Path $testDir 'd1-minimal.cip'
Set-Content -Path $d1XmlPath -Value $d1Xml -Encoding UTF8

try {
    ConvertFrom-CIPolicy -XmlFilePath $d1XmlPath -BinaryFilePath $d1CipPath -ErrorAction Stop | Out-Null
    Write-TestResult 'D1.1' 'Pass' "ConvertFrom-CIPolicy compiled successfully"

    $bytes = Get-Content -Path $d1CipPath -AsByteStream -Raw
    Write-TestResult 'D1.2' 'Info' "Binary size: $($bytes.Length) bytes"

    $fmtVer = [BitConverter]::ToInt32($bytes, 0)
    Write-TestResult 'D1.3' 'Info' "FormatVersion: $fmtVer"

    $optFlags = [BitConverter]::ToUInt32($bytes, 0x24)
    Write-TestResult 'D1.4' 'Info' "OptionFlags: 0x$($optFlags.ToString('X8'))"

    $ekuCount = [BitConverter]::ToInt32($bytes, 0x28)
    $frCount = [BitConverter]::ToInt32($bytes, 0x2C)
    $sigCount = [BitConverter]::ToInt32($bytes, 0x30)
    $scenCount = [BitConverter]::ToInt32($bytes, 0x34)
    Write-TestResult 'D1.5' 'Info' "EKU=$ekuCount  FileRule=$frCount  Signer=$sigCount  Scenario=$scenCount"

    $hdrLen = [BitConverter]::ToInt32($bytes, 0x40)
    Write-TestResult 'D1.6' 'Info' "HeaderLength: 0x$($hdrLen.ToString('X4')) ($hdrLen decimal)"
    Write-TestResult 'D1.7' 'Info' "BodyOffset: 0x$(($hdrLen + 4).ToString('X4')) ($($hdrLen + 4) decimal)"

    # Dump first 72 bytes as hex for analysis
    $hexDump = ($bytes[0..([Math]::Min(71, $bytes.Length - 1))] | ForEach-Object { $_.ToString('X2') }) -join ' '
    Write-TestResult 'D1.8' 'Info' "First 72 bytes: $hexDump"

    # Dump bytes around OptionFlags for detailed analysis
    $flagBytes = ($bytes[0x24..0x27] | ForEach-Object { $_.ToString('X2') }) -join ' '
    Write-TestResult 'D1.9' 'Info' "OptionFlags bytes (0x24-0x27): $flagBytes"
}
catch {
    Write-TestResult 'D1' 'Error' "Failed: $_"
}

# ═══════════════════════════════════════════════════════════════════════════
# D2 — ConvertFrom-WDACBinary Round-Trip (minimal policy)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "`n========== D2: ConvertFrom-WDACBinary Round-Trip (Minimal) =========="

try {
    $result = ConvertFrom-WDACBinary -Path $d1CipPath -ErrorAction Stop
    if ($null -eq $result) {
        Write-TestResult 'D2.1' 'Fail' "ConvertFrom-WDACBinary returned NULL"
    }
    else {
        Write-TestResult 'D2.1' 'Pass' "Result type: $($result.GetType().FullName)"
        Write-TestResult 'D2.2' 'Info' "Root element: $($result.DocumentElement.LocalName)"
        Write-TestResult 'D2.3' 'Info' "Namespace: $($result.DocumentElement.NamespaceURI)"

        $nsm = [System.Xml.XmlNamespaceManager]::new($result.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        $versionNode = $result.SelectSingleNode('//ns:VersionEx', $nsm)
        Write-TestResult 'D2.4' 'Info' "VersionEx: $($versionNode.InnerText)"

        $policyType = $result.DocumentElement.GetAttribute('PolicyType')
        Write-TestResult 'D2.5' 'Info' "PolicyType attribute: '$policyType'"

        $policyIdNode = $result.SelectSingleNode('//ns:PolicyID', $nsm)
        Write-TestResult 'D2.6' 'Info' "PolicyID: $($policyIdNode.InnerText)"

        $rules = $result.SelectNodes('//ns:Rules/ns:Rule/ns:Option', $nsm)
        Write-TestResult 'D2.7' 'Info' "Rule Options count: $($rules.Count)"
        foreach ($rule in $rules) {
            Write-TestResult 'D2.7a' 'Info' "  Option: $($rule.InnerText)"
        }

        $scenarios = $result.SelectNodes('//ns:SigningScenarios/ns:SigningScenario', $nsm)
        Write-TestResult 'D2.8' 'Info' "SigningScenario count: $($scenarios.Count)"

        $hvci = $result.SelectSingleNode('//ns:HvciOptions', $nsm)
        Write-TestResult 'D2.9' 'Info' "HvciOptions: $($hvci.InnerText)"

        # Dump the full XML for manual inspection
        Write-Host "`n--- D2 Full XML Output ---"
        $sw = [System.IO.StringWriter]::new()
        $xw = [System.Xml.XmlTextWriter]::new($sw)
        $xw.Formatting = [System.Xml.Formatting]::Indented
        $result.WriteTo($xw)
        $xw.Flush()
        Write-Host $sw.ToString()
        $xw.Close()
        $sw.Close()
    }
}
catch {
    Write-TestResult 'D2' 'Error' "Exception: $_"
    Write-Host "Stack trace: $($_.ScriptStackTrace)"
}

# ═══════════════════════════════════════════════════════════════════════════
# D3 — ConvertFrom-WDACBinary Round-Trip (full policy with signers/settings)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "`n========== D3: ConvertFrom-WDACBinary Round-Trip (Full) =========="

$d3Xml = @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>10.0.5.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{B1000001-0001-0001-0001-000000000001}</PolicyID>
  <BasePolicyID>{B1000001-0001-0001-0001-000000000001}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:Audit Mode</Option></Rule>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
    <Rule><Option>Enabled:Allow Supplemental Policies</Option></Rule>
  </Rules>
  <EKUs>
    <EKU ID="ID_EKU_E_1" Value="010A2B0601040182370A0305" FriendlyName="Code Signing" />
  </EKUs>
  <FileRules>
    <Allow ID="ID_ALLOW_A_1" FriendlyName="AllowTest" FileName="TestAllow.dll" MinimumFileVersion="0.0.0.0" />
    <Deny ID="ID_DENY_D_1" FriendlyName="DenyTest" FileName="TestDeny.exe" MinimumFileVersion="0.0.0.0" />
  </FileRules>
  <Signers>
    <Signer ID="ID_SIGNER_S_1" Name="TestSigner">
      <CertRoot Type="Wellknown" Value="03" />
      <CertPublisher Value="TestPublisher" />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario ID="ID_SIGNINGSCENARIO_DRIVERS_1" Value="131" FriendlyName="Drivers">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario ID="ID_SIGNINGSCENARIO_USERMODE_1" Value="12" FriendlyName="User Mode">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1" />
        </AllowedSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_A_1" />
        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners>
    <UpdatePolicySigner SignerId="ID_SIGNER_S_1" />
  </UpdatePolicySigners>
  <CiSigners>
    <CiSigner SignerId="ID_SIGNER_S_1" />
  </CiSigners>
  <HvciOptions>0</HvciOptions>
  <Settings>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
      <Value><String>Pester Round-Trip Test</String></Value>
    </Setting>
  </Settings>
</SiPolicy>
'@

$d3XmlPath = Join-Path $testDir 'd3-full.xml'
$d3CipPath = Join-Path $testDir 'd3-full.cip'
Set-Content -Path $d3XmlPath -Value $d3Xml -Encoding UTF8

try {
    ConvertFrom-CIPolicy -XmlFilePath $d3XmlPath -BinaryFilePath $d3CipPath -ErrorAction Stop | Out-Null
    Write-TestResult 'D3.0' 'Pass' "ConvertFrom-CIPolicy compiled full policy"

    $bytes = Get-Content -Path $d3CipPath -AsByteStream -Raw
    Write-TestResult 'D3.1' 'Info' "Binary size: $($bytes.Length) bytes"
    Write-TestResult 'D3.2' 'Info' "FormatVersion: $([BitConverter]::ToInt32($bytes, 0))"

    $hexDump = ($bytes[0..([Math]::Min(71, $bytes.Length - 1))] | ForEach-Object { $_.ToString('X2') }) -join ' '
    Write-TestResult 'D3.3' 'Info' "First 72 bytes: $hexDump"
}
catch {
    Write-TestResult 'D3.0' 'Error' "Compilation failed: $_"
}

try {
    $result3 = ConvertFrom-WDACBinary -Path $d3CipPath -ErrorAction Stop
    if ($null -eq $result3) {
        Write-TestResult 'D3.4' 'Fail' "ConvertFrom-WDACBinary returned NULL"
    }
    else {
        Write-TestResult 'D3.4' 'Pass' "Result type: $($result3.GetType().FullName)"

        $nsm = [System.Xml.XmlNamespaceManager]::new($result3.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        $ekus = $result3.SelectNodes('//ns:EKUs/ns:EKU', $nsm)
        Write-TestResult 'D3.5' 'Info' "EKU count: $($ekus.Count)"

        $frs = $result3.SelectNodes('//ns:FileRules/*', $nsm)
        Write-TestResult 'D3.6' 'Info' "FileRule count: $($frs.Count)"
        foreach ($fr in $frs) {
            Write-TestResult 'D3.6a' 'Info' "  $($fr.LocalName) ID=$($fr.GetAttribute('ID')) FileName=$($fr.GetAttribute('FileName'))"
        }

        $signers = $result3.SelectNodes('//ns:Signers/ns:Signer', $nsm)
        Write-TestResult 'D3.7' 'Info' "Signer count: $($signers.Count)"
        foreach ($sig in $signers) {
            $certPub = $sig.SelectSingleNode('ns:CertPublisher', $nsm)
            Write-TestResult 'D3.7a' 'Info' "  Signer ID=$($sig.GetAttribute('ID')) CertPublisher=$($certPub.GetAttribute('Value'))"
        }

        $upd = $result3.SelectNodes('//ns:UpdatePolicySigners/ns:UpdatePolicySigner', $nsm)
        Write-TestResult 'D3.8' 'Info' "UpdatePolicySigner count: $($upd.Count)"

        $ci = $result3.SelectNodes('//ns:CiSigners/ns:CiSigner', $nsm)
        Write-TestResult 'D3.9' 'Info' "CiSigner count: $($ci.Count)"

        $settings = $result3.SelectNodes('//ns:Settings/ns:Setting', $nsm)
        Write-TestResult 'D3.10' 'Info' "Settings count: $($settings.Count)"
        foreach ($s in $settings) {
            $strVal = $s.SelectSingleNode('ns:Value/ns:String', $nsm)
            Write-TestResult 'D3.10a' 'Info' "  $($s.GetAttribute('Key'))/$($s.GetAttribute('ValueName')): $($strVal.InnerText)"
        }

        # Dump the full XML
        Write-Host "`n--- D3 Full XML Output ---"
        $sw = [System.IO.StringWriter]::new()
        $xw = [System.Xml.XmlTextWriter]::new($sw)
        $xw.Formatting = [System.Xml.Formatting]::Indented
        $result3.WriteTo($xw)
        $xw.Flush()
        Write-Host $sw.ToString()
        $xw.Close()
        $sw.Close()
    }
}
catch {
    Write-TestResult 'D3.4' 'Error' "Exception: $_"
    Write-Host "Stack trace: $($_.ScriptStackTrace)"
}

# ═══════════════════════════════════════════════════════════════════════════
# D4 — Duplicate File Investigation (live CiPolicies\Active)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "`n========== D4: CiPolicies\Active File Inventory =========="

$activeDir = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
if (Test-Path $activeDir) {
    $cipFiles = Get-ChildItem -Path $activeDir -Filter '*.cip' -File
    Write-TestResult 'D4.1' 'Info' "Total .cip files: $($cipFiles.Count)"

    foreach ($f in $cipFiles | Sort-Object Name) {
        Write-TestResult 'D4.2' 'Info' "  $($f.Name)  Size=$($f.Length)  Modified=$($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    }

    # Detect duplicates: files with same GUID but different filenames (e.g., " (1)" suffix)
    $guidGroups = $cipFiles | Group-Object { ($_.BaseName -replace ' \(\d+\)$', '').Trim('{}').ToLowerInvariant() }
    $dupes = $guidGroups | Where-Object { $_.Count -gt 1 }
    Write-TestResult 'D4.3' 'Info' "Duplicate GUID groups: $($dupes.Count)"
    foreach ($group in $dupes) {
        Write-TestResult 'D4.3a' 'Info' "  GUID: $($group.Name) — $($group.Count) files"
        foreach ($member in $group.Group) {
            $sameSize = ($group.Group | Where-Object Length -eq $member.Length).Count -eq $group.Count
            Write-TestResult 'D4.3b' 'Info' "    $($member.Name)  Size=$($member.Length)  SameSize=$sameSize"
        }
    }
}
else {
    Write-TestResult 'D4.1' 'Info' "Directory not found: $activeDir"
}

# ═══════════════════════════════════════════════════════════════════════════
# D5 — V7 Marker Mismatch Investigation
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "`n========== D5: V7 Marker Mismatch Investigation =========="

$d5TargetGuid = '60FD87F8-4593-44A0-91B0-2E0DA022F248'
$d5Path = Join-Path $activeDir "{$d5TargetGuid}.cip"

if (Test-Path $d5Path) {
    $d5RawBytes = Get-Content -Path $d5Path -AsByteStream -Raw
    Write-TestResult 'D5.1' 'Info' "Raw file size: $($d5RawBytes.Length) bytes"

    # Unwrap PKCS#7 first — all analysis must use unwrapped bytes
    $d5Bytes = Unprotect-Pkcs7Policy -Data $d5RawBytes
    $d5IsPkcs7 = $d5Bytes.Length -ne $d5RawBytes.Length
    Write-TestResult 'D5.2' 'Info' "PKCS#7 wrapped: $d5IsPkcs7 (unwrapped: $($d5Bytes.Length) bytes)"

    # Header fields from UNWRAPPED binary
    $d5FmtVer = [BitConverter]::ToUInt32($d5Bytes, 0)
    $d5OptFlags = [BitConverter]::ToUInt32($d5Bytes, 0x24)
    $d5EkuCount = [BitConverter]::ToInt32($d5Bytes, 0x28)
    $d5FrCount = [BitConverter]::ToInt32($d5Bytes, 0x2C)
    $d5SigCount = [BitConverter]::ToInt32($d5Bytes, 0x30)
    $d5ScenCount = [BitConverter]::ToInt32($d5Bytes, 0x34)
    $d5UpdSigCount = [BitConverter]::ToInt32($d5Bytes, 0x44)
    $d5CiSigCount = [BitConverter]::ToInt32($d5Bytes, 0x48)
    Write-TestResult 'D5.3' 'Info' "FormatVersion: $d5FmtVer"
    Write-TestResult 'D5.4' 'Info' "OptionFlags: 0x$($d5OptFlags.ToString('X8'))"
    Write-TestResult 'D5.5' 'Info' "EKU=$d5EkuCount  FileRule=$d5FrCount  Signer=$d5SigCount  Scenario=$d5ScenCount  UpdSigner=$d5UpdSigCount  CiSigner=$d5CiSigCount"

    # Version from UNWRAPPED binary
    $d5Rev = [BitConverter]::ToUInt16($d5Bytes, 0x38)
    $d5Build = [BitConverter]::ToUInt16($d5Bytes, 0x3A)
    $d5Minor = [BitConverter]::ToUInt16($d5Bytes, 0x3C)
    $d5Major = [BitConverter]::ToUInt16($d5Bytes, 0x3E)
    Write-TestResult 'D5.6' 'Info' "Version: $d5Major.$d5Minor.$d5Build.$d5Rev"

    # Full header hex dump (0x00-0x4B)
    Write-TestResult 'D5.7' 'Info' "Full header hex (unwrapped, 0x00-0x4B):"
    for ($i = 0; $i -lt 0x4C; $i += 16) {
        $lineEnd = [Math]::Min($i + 15, 0x4B)
        $hex = ($d5Bytes[$i..$lineEnd] | ForEach-Object { $_.ToString('X2') }) -join ' '
        Write-Host ("  0x{0:X4}: {1}" -f $i, $hex)
    }

    # Hex dump around the V7 marker failure point (0x15F8) in UNWRAPPED data
    $errorPos = 0x15F8
    if ($errorPos -lt $d5Bytes.Length) {
        $dumpStart = [Math]::Max(0, $errorPos - 64)
        $dumpEnd = [Math]::Min($d5Bytes.Length, $errorPos + 64)
        Write-TestResult 'D5.8' 'Info' "Unwrapped hex dump around V7 failure (0x$($errorPos.ToString('X4'))), total=$($d5Bytes.Length) bytes:"
        for ($i = $dumpStart; $i -lt $dumpEnd; $i += 16) {
            $lineEnd = [Math]::Min($i + 15, $dumpEnd - 1)
            $hex = ($d5Bytes[$i..$lineEnd] | ForEach-Object { $_.ToString('X2') }) -join ' '
            $marker = if ($i -le $errorPos -and $errorPos -le $lineEnd) { ' <-- V7 expected here' } else { '' }
            Write-Host ("  0x{0:X4}: {1}{2}" -f $i, $hex, $marker)
        }
    }
    else {
        Write-TestResult 'D5.8' 'Info' "Error position 0x$($errorPos.ToString('X4')) exceeds unwrapped size $($d5Bytes.Length)"
    }

    # Scan for V-block markers in the unwrapped binary (look for 03,04,05,06,07,08 as uint32)
    Write-TestResult 'D5.9' 'Info' "Scanning for V-block markers (uint32 values 3-8) in unwrapped binary:"
    for ($pos = 0x4C; $pos -lt ($d5Bytes.Length - 3); $pos += 4) {
        $val = [BitConverter]::ToUInt32($d5Bytes, $pos)
        if ($val -ge 3 -and $val -le 8) {
            $context = ($d5Bytes[([Math]::Max(0,$pos-4))..([Math]::Min($pos+7, $d5Bytes.Length-1))] | ForEach-Object { $_.ToString('X2') }) -join ' '
            Write-Host ("  0x{0:X4}: marker candidate = {1}  context: {2}" -f $pos, $val, $context)
        }
    }

    # Attempt parse to capture full error
    Write-TestResult 'D5.10' 'Info' "Attempting ConvertFrom-WDACBinary on unwrapped data:"
    try {
        $d5Xml = ConvertFrom-WDACBinary -Data $d5Bytes -ErrorAction Stop
        Write-TestResult 'D5.10a' 'Pass' "Parse succeeded (unexpected!)"
    }
    catch {
        Write-TestResult 'D5.10a' 'Fail' "Parse failed: $($_.Exception.Message)"
        Write-Host "  Stack trace:`n$($_.ScriptStackTrace)"
    }

    # Dump last 128 bytes of unwrapped data (tail — where V6/V7/V8 blocks live)
    $tailStart = [Math]::Max(0, $d5Bytes.Length - 128)
    Write-TestResult 'D5.11' 'Info' "Tail of unwrapped binary (last 128 bytes):"
    for ($i = $tailStart; $i -lt $d5Bytes.Length; $i += 16) {
        $lineEnd = [Math]::Min($i + 15, $d5Bytes.Length - 1)
        $hex = ($d5Bytes[$i..$lineEnd] | ForEach-Object { $_.ToString('X2') }) -join ' '
        Write-Host ("  0x{0:X4}: {1}" -f $i, $hex)
    }
}
else {
    Write-TestResult 'D5.1' 'Info' "Target file not found: $d5Path"
}

# ═══════════════════════════════════════════════════════════════════════════
# D6 — VersionEx Investigation (live policies)
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "`n========== D6: VersionEx Investigation (Live Policies) =========="

if (Test-Path $activeDir) {
    $d6Files = Get-ChildItem -Path $activeDir -Filter '*.cip' -File |
        Where-Object { $_.Name -notlike '* (*)*' } |   # skip " (1)" duplicates
        Select-Object -First 5                          # sample 5 unique policies

    foreach ($d6File in $d6Files) {
        $d6Label = $d6File.BaseName
        Write-Host "`n--- $d6Label ---"

        try {
            $d6RawBytes = Get-Content -Path $d6File.FullName -AsByteStream -Raw
            $d6Unwrapped = Unprotect-Pkcs7Policy -Data $d6RawBytes

            # Raw header version bytes
            $d6Rev = [BitConverter]::ToUInt16($d6Unwrapped, 0x38)
            $d6Build = [BitConverter]::ToUInt16($d6Unwrapped, 0x3A)
            $d6Minor = [BitConverter]::ToUInt16($d6Unwrapped, 0x3C)
            $d6Major = [BitConverter]::ToUInt16($d6Unwrapped, 0x3E)
            $d6HeaderVer = "$d6Major.$d6Minor.$d6Build.$d6Rev"
            Write-TestResult 'D6.1' 'Info' "Header version (0x38): $d6HeaderVer"

            # Parse and check XML VersionEx
            $d6Xml = ConvertFrom-WDACBinary -Data $d6Unwrapped -ErrorAction Stop
            $d6nsm = [System.Xml.XmlNamespaceManager]::new($d6Xml.NameTable)
            $d6nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
            $d6VerNode = $d6Xml.SelectSingleNode('//ns:VersionEx', $d6nsm)

            if ($null -ne $d6VerNode) {
                Write-TestResult 'D6.2' 'Info' "XML VersionEx: '$($d6VerNode.InnerText)'"
                if ($d6VerNode.InnerText -eq $d6HeaderVer) {
                    Write-TestResult 'D6.3' 'Pass' "Header version matches XML VersionEx"
                }
                else {
                    Write-TestResult 'D6.3' 'Fail' "MISMATCH: Header=$d6HeaderVer XML=$($d6VerNode.InnerText)"
                }
            }
            else {
                Write-TestResult 'D6.2' 'Fail' "No VersionEx node in XML output"
            }

            # Also check what ConvertTo-WDACPolicyObject produces
            $d6FmtVer = [BitConverter]::ToUInt32($d6Unwrapped, 0)
            $d6Obj = ConvertTo-WDACPolicyObject -Xml $d6Xml -FormatVersion $d6FmtVer -FilePath $d6File.FullName -Location 'MultiPolicy'
            Write-TestResult 'D6.4' 'Info' "Final output Version: '$($d6Obj.Version)' FriendlyName: '$($d6Obj.FriendlyName)'"
        }
        catch {
            Write-TestResult 'D6.E' 'Error' "Failed: $($_.Exception.Message)"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════
Write-Host "`n========== Diagnostics Complete =========="
Write-Host "Transcript saved to: $TranscriptPath"

}
finally {
    Stop-Transcript
}
