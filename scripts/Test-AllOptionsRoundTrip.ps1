#Requires -Version 5.1
<#
.SYNOPSIS
    Verify the workspace decoder emits every XSD-canonical OptionType enumeration value.
    Bonus: empirically identify the OptionFlags bit position for any option whose bit
    the workspace doesn't currently know.

.DESCRIPTION
    The AllOptions-exhaustive KPT variant (config 13 added 2026-05-17) compiles an XML
    that carries all 24 XSD-canonical OptionType values into a binary policy via Microsoft's
    ConvertFrom-CIPolicy. This script:

      1. Decodes the resulting binary via ConvertFrom-WDACBinary.
      2. Compares the emitted <Option> values to the expected 24-element list.
      3. Reports: round-tripped, dropped, and unexpected.
      4. For dropped options, reads the binary's OptionFlags bitmap and compares to the
         workspace's emit logic to identify which bit corresponds to the dropped value.

    A clean run (24 round-tripped, 0 dropped) proves the workspace decoder emits every
    XSD enum. A gap (e.g. `Disabled:Default Windows Certificate Remapping` dropped because
    bit position unknown) is surfaced with the empirical bit position to enable a follow-on
    workspace decoder update.
#>
param()

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleDir = Split-Path -Parent $scriptDir
$tempDir   = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($moduleDir, 'temp'))

$modulePsd1 = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($moduleDir, 'src', 'antyg-wdacking.psd1'))
Import-Module $modulePsd1 -Force

# The fixture name encodes the variant name with non-alphanumerics replaced by '-'
$fixtureCip = Join-Path $tempDir 'KPT-Variant-3sig-1fr-base--AllOptions-exhaustive-.cip'
$fixtureXml = Join-Path $tempDir 'KPT-Variant-3sig-1fr-base--AllOptions-exhaustive-.xml'

if (-not (Test-Path $fixtureCip)) { throw "Fixture not found: $fixtureCip — run Invoke-KnownPlaintextVariants.ps1 first" }
if (-not (Test-Path $fixtureXml)) { throw "Source XML not found: $fixtureXml" }

# Expected XSD-canonical OptionType enum values per cipolicy.xsd lines 119-143
$expected = @(
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

Write-Host ''
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host 'OptionType round-trip exhaustive test' -ForegroundColor Cyan
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host ''
Write-Host "  Fixture binary: $fixtureCip" -ForegroundColor DarkGray
Write-Host "  Fixture XML:    $fixtureXml" -ForegroundColor DarkGray
Write-Host "  Expected options: $($expected.Count) (XSD-canonical)" -ForegroundColor DarkGray
Write-Host ''

# Decode the fixture
$xml = ConvertFrom-WDACBinary -Path $fixtureCip
$ns = [System.Xml.XmlNamespaceManager]::new($xml.NameTable)
$ns.AddNamespace('s', 'urn:schemas-microsoft-com:sipolicy')
$emittedOptions = @($xml.SelectNodes('//s:Rules/s:Rule/s:Option', $ns) | ForEach-Object { $_.InnerText })

$emittedSet  = [System.Collections.Generic.HashSet[string]]::new([string[]]$emittedOptions, [System.StringComparer]::Ordinal)
$expectedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$expected, [System.StringComparer]::Ordinal)

$dropped    = @($expected   | Where-Object { -not $emittedSet.Contains($_) })
$unexpected = @($emittedOptions | Where-Object { -not $expectedSet.Contains($_) })
$preserved  = @($expected   | Where-Object {       $emittedSet.Contains($_) })

Write-Host "  Round-trip results:" -ForegroundColor White
Write-Host ("    Preserved: {0}/{1}" -f $preserved.Count, $expected.Count) -ForegroundColor Green
Write-Host ("    Dropped:   {0}" -f $dropped.Count) -ForegroundColor $(if ($dropped.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ("    Unexpected: {0}" -f $unexpected.Count) -ForegroundColor $(if ($unexpected.Count -gt 0) { 'Red' } else { 'Green' })

if ($dropped.Count -gt 0) {
    Write-Host ''
    Write-Host "  Dropped options (workspace decoder lacks emit support):" -ForegroundColor Yellow
    $dropped | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
}

if ($unexpected.Count -gt 0) {
    Write-Host ''
    Write-Host "  Unexpected options (workspace emitted something not in XSD canonical list):" -ForegroundColor Red
    $unexpected | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkRed }
}

# Bonus diagnostic: read the binary header's OptionFlags directly and compare against the
# bits the workspace decoder knows about. If a bit is set in the binary but not emitted in
# XML, that bit corresponds to a dropped option — empirical discovery of the unknown bit.
Write-Host ''
Write-Host "  Empirical OptionFlags analysis:" -ForegroundColor White
$bytes = [System.IO.File]::ReadAllBytes($fixtureCip)
$optionFlags = [BitConverter]::ToUInt32($bytes, 0x24)
$ruleFlags   = $optionFlags -band 0x3FFFFFFF

Write-Host ("    Raw OptionFlags (offset 0x24):  0x{0:X8}" -f $optionFlags) -ForegroundColor DarkGray
Write-Host ("    Rule bits (after 0x3FFFFFFF):   0x{0:X8}" -f $ruleFlags) -ForegroundColor DarkGray

# Workspace's known bit positions per ConvertFrom-WDACBinary.ps1 lines 58-82
$knownBits = @(2, 3, 4, 5, 7, 8, 10, 11, 13, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29)

$setBits = @()
for ($b = 0; $b -lt 30; $b++) {
    if (($ruleFlags -band (1 -shl $b)) -ne 0) { $setBits += $b }
}
$unknownSetBits = @($setBits | Where-Object { $_ -notin $knownBits })

Write-Host ("    All bits set in rule flags:     {0}" -f ($setBits -join ', ')) -ForegroundColor DarkGray
Write-Host ("    Bits set but NOT known to workspace decoder: {0}" -f ($unknownSetBits -join ', ')) `
    -ForegroundColor $(if ($unknownSetBits.Count -gt 0) { 'Yellow' } else { 'Green' })

if ($unknownSetBits.Count -gt 0 -and $dropped.Count -gt 0) {
    Write-Host ''
    Write-Host "  EMPIRICAL FINDING: bit position(s) {0} correspond to dropped option(s):" -ForegroundColor Yellow
    $unknownSetBits | ForEach-Object { Write-Host ("    bit {0} (0x{1:X8})" -f $_, (1 -shl $_)) -ForegroundColor DarkYellow }
    Write-Host "  These bits should be added to the workspace's bitToOptionName table at" -ForegroundColor DarkYellow
    Write-Host "  ConvertFrom-WDACBinary.ps1 lines 58-82, paired with the dropped option string(s)." -ForegroundColor DarkYellow
}

Write-Host ''
Write-Host ('=' * 100) -ForegroundColor DarkCyan
if ($dropped.Count -eq 0 -and $unexpected.Count -eq 0) {
    Write-Host 'OPTION ROUND-TRIP COMPLETE: all 24 XSD-canonical OptionType values preserved.' -ForegroundColor Green
}
else {
    Write-Host 'OPTION ROUND-TRIP INCOMPLETE — see findings above.' -ForegroundColor Yellow
}
Write-Host ('=' * 100) -ForegroundColor DarkCyan
