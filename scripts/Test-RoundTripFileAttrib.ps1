#Requires -Version 5.1
<#
.SYNOPSIS
    Round-trip soundness probe for FileAttrib rule emission.

.DESCRIPTION
    Takes the workspace-regenerated `{4FD367C7}.cip.xml` (which carries 37 FileAttrib rules,
    2 of which are referenced from Signers via <FileAttribRef>), and verifies the
    full round-trip:

      1. Compile the canonical XML via Microsoft's ConvertFrom-CIPolicy → binary
      2. Decode the compiled binary via ConvertFrom-WDACBinary → XML pass 2
      3. Compare FileAttrib structure between pass 1 (workspace-canonical) and pass 2
         (round-tripped through Microsoft compile + workspace decode)

    The two FileAttrib rules under focus:
      <FileAttrib ID="ID_FILEATTRIB_F_0001" FileName="*" MinimumFileVersion="4.16.2.92" />
      <FileAttrib ID="ID_FILEATTRIB_F_0002" FileName="*" MinimumFileVersion="7.10.3077.0" />

    Referenced from S_717 (WalkMe Ltd) and S_720 (Microsoft Corporation) respectively.

    Authored 2026-05-17 to validate FileAttrib round-trip per user direction. Output
    artefacts are written under temp/roundtrip-fileattrib/ for inspection.
#>
param(
    [string]$SourceXml = 'D:\antyg\Work\dfsdscs\E8\evidence\application-control\ISM-0843_workstations\evidence-01-wdac-policy-_4FD367C7-8F78-4528-B2A0-4F46951692F3_-20260515094737.cip.xml'
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleDir = Split-Path -Parent $scriptDir
$tempDir   = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($moduleDir, 'temp', 'roundtrip-fileattrib'))
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
}

$modulePsd1 = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($moduleDir, 'src', 'antyg-wdacking.psd1'))
Import-Module $modulePsd1 -Force

if (-not (Test-Path $SourceXml)) { throw "Source XML not found: $SourceXml" }

$compiledCip = [System.IO.Path]::Combine($tempDir, 'roundtrip-4FD367C7.cip')
$decodedXml  = [System.IO.Path]::Combine($tempDir, 'roundtrip-4FD367C7-pass2.xml')

Write-Host ''
Write-Host ('=' * 80) -ForegroundColor DarkCyan
Write-Host 'FileAttrib round-trip soundness probe' -ForegroundColor Cyan
Write-Host ('=' * 80) -ForegroundColor DarkCyan
Write-Host ''

Write-Host "Step 1: ConvertFrom-CIPolicy compile of workspace-canonical XML..." -ForegroundColor White
$swCompile = [System.Diagnostics.Stopwatch]::StartNew()
ConvertFrom-CIPolicy -XmlFilePath $SourceXml -BinaryFilePath $compiledCip -ErrorAction Stop | Out-Null
$swCompile.Stop()
$compiledSize = (Get-Item $compiledCip).Length
Write-Host ("  Compiled binary: {0:N0} bytes in {1:N0} ms" -f $compiledSize, $swCompile.ElapsedMilliseconds) -ForegroundColor Green

Write-Host ''
Write-Host "Step 2: ConvertFrom-WDACBinary decode of the compiled binary..." -ForegroundColor White
$swDecode = [System.Diagnostics.Stopwatch]::StartNew()
$xml2 = ConvertFrom-WDACBinary -Path $compiledCip
$swDecode.Stop()

$settings = [System.Xml.XmlWriterSettings]::new()
$settings.Indent = $true
$settings.IndentChars = '    '
$settings.Encoding = [System.Text.Encoding]::UTF8
$writer = [System.Xml.XmlWriter]::Create($decodedXml, $settings)
try { $xml2.Save($writer) } finally { $writer.Dispose() }
$decodedSize = (Get-Item $decodedXml).Length
Write-Host ("  Decoded XML: {0:N0} bytes in {1:N0} ms" -f $decodedSize, $swDecode.ElapsedMilliseconds) -ForegroundColor Green

Write-Host ''
Write-Host "Step 3: Loading pass-1 (source) and pass-2 (round-tripped) XML..." -ForegroundColor White
$xml1 = New-Object System.Xml.XmlDocument
$xml1.Load($SourceXml)
$ns1 = [System.Xml.XmlNamespaceManager]::new($xml1.NameTable)
$ns1.AddNamespace('s', 'urn:schemas-microsoft-com:sipolicy')
$ns2 = [System.Xml.XmlNamespaceManager]::new($xml2.NameTable)
$ns2.AddNamespace('s', 'urn:schemas-microsoft-com:sipolicy')

$pass1FileAttribs = @($xml1.SelectNodes('//s:FileRules/s:FileAttrib', $ns1))
$pass2FileAttribs = @($xml2.SelectNodes('//s:FileRules/s:FileAttrib', $ns2))
$pass1Refs = @($xml1.SelectNodes('//s:Signers/s:Signer/s:FileAttribRef', $ns1))
$pass2Refs = @($xml2.SelectNodes('//s:Signers/s:Signer/s:FileAttribRef', $ns2))

Write-Host ''
Write-Host "Step 4: Structural comparison..." -ForegroundColor White
Write-Host ('  {0,-40} {1,-12} {2,-12}' -f 'Metric', 'Pass 1', 'Pass 2')
Write-Host ('  ' + ('-' * 64))
Write-Host ('  {0,-40} {1,-12} {2,-12}' -f 'FileAttrib count', $pass1FileAttribs.Count, $pass2FileAttribs.Count)
Write-Host ('  {0,-40} {1,-12} {2,-12}' -f 'FileAttribRef references count', $pass1Refs.Count, $pass2Refs.Count)

$allowCount1 = @($xml1.SelectNodes('//s:FileRules/s:Allow', $ns1)).Count
$allowCount2 = @($xml2.SelectNodes('//s:FileRules/s:Allow', $ns2)).Count
$denyCount1  = @($xml1.SelectNodes('//s:FileRules/s:Deny',  $ns1)).Count
$denyCount2  = @($xml2.SelectNodes('//s:FileRules/s:Deny',  $ns2)).Count
$signerCount1 = @($xml1.SelectNodes('//s:Signers/s:Signer', $ns1)).Count
$signerCount2 = @($xml2.SelectNodes('//s:Signers/s:Signer', $ns2)).Count

Write-Host ('  {0,-40} {1,-12} {2,-12}' -f 'Allow count', $allowCount1, $allowCount2)
Write-Host ('  {0,-40} {1,-12} {2,-12}' -f 'Deny count', $denyCount1, $denyCount2)
Write-Host ('  {0,-40} {1,-12} {2,-12}' -f 'Signer count', $signerCount1, $signerCount2)

Write-Host ''
Write-Host "Step 5: Graph-isomorphic comparison via Signer→FileAttrib edges..." -ForegroundColor White
Write-Host "  (Positional comparison is misleading — ConvertFrom-CIPolicy reorders FileAttribs" -ForegroundColor DarkGray
Write-Host "   during compile. The correct test is: every signer-referenced FileAttrib in pass 1" -ForegroundColor DarkGray
Write-Host "   has a counterpart in pass 2 with identical attribute content, reachable via the" -ForegroundColor DarkGray
Write-Host "   same Signer's FileAttribRef edge.)" -ForegroundColor DarkGray
Write-Host ''

# Build (FileAttrib ID → attribute-set) maps for both passes
function Get-AttribKey {
    param([System.Xml.XmlElement]$Rule)
    $parts = foreach ($n in @('FileName', 'InternalName', 'FileDescription', 'ProductName',
                              'PackageFamilyName', 'PackageVersion', 'MinimumFileVersion',
                              'MaximumFileVersion', 'Hash', 'AppIDs', 'FilePath')) {
        "$n=$($Rule.GetAttribute($n))"
    }
    return ($parts -join '|')
}

$pass1FaById = @{}
foreach ($r in $pass1FileAttribs) { $pass1FaById[$r.GetAttribute('ID')] = (Get-AttribKey $r) }
$pass2FaById = @{}
foreach ($r in $pass2FileAttribs) { $pass2FaById[$r.GetAttribute('ID')] = (Get-AttribKey $r) }

# For each Signer in pass 1 that has FileAttribRef(s), find the same Signer (by CertRoot+CertPublisher
# composite identity) in pass 2 and verify each FileAttribRef resolves to an identical attribute set.
$pass1Signers = @($xml1.SelectNodes('//s:Signers/s:Signer', $ns1))
$pass2Signers = @($xml2.SelectNodes('//s:Signers/s:Signer', $ns2))

function Get-SignerKey {
    param([System.Xml.XmlElement]$Signer, [System.Xml.XmlNamespaceManager]$Ns)
    $cr = $Signer.SelectSingleNode('s:CertRoot', $Ns)
    $cp = $Signer.SelectSingleNode('s:CertPublisher', $Ns)
    $crVal = if ($cr) { "$($cr.GetAttribute('Type')):$($cr.GetAttribute('Value'))" } else { '' }
    $cpVal = if ($cp) { $cp.GetAttribute('Value') } else { '' }
    return "$crVal|$cpVal"
}

# Multiset edge comparison: collect every (SignerKey, resolved-FileAttrib-key) edge in each
# pass, sort, and compare. This avoids the signer-key collision issue (multiple signers
# sharing CertRoot+CertPublisher would alias in a dictionary lookup); the multiset captures
# graph-isomorphism at the bipartite-edge level without needing per-signer uniqueness.
function Get-Edges {
    param(
        $Signers,
        [System.Xml.XmlNamespaceManager]$Ns,
        [hashtable]$FaById
    )
    $edges = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $Signers) {
        $sk = Get-SignerKey -Signer $s -Ns $Ns
        foreach ($r in $s.SelectNodes('s:FileAttribRef', $Ns)) {
            $id = $r.GetAttribute('RuleID')
            if ($FaById.ContainsKey($id)) {
                $edges.Add("$sk||$($FaById[$id])")
            }
        }
    }
    return , $edges
}

$pass1Edges = Get-Edges -Signers $pass1Signers -Ns $ns1 -FaById $pass1FaById
$pass2Edges = Get-Edges -Signers $pass2Signers -Ns $ns2 -FaById $pass2FaById
$pass1EdgesSorted = @($pass1Edges) | Sort-Object
$pass2EdgesSorted = @($pass2Edges) | Sort-Object

$edgeDivergences = 0
if ($pass1Edges.Count -ne $pass2Edges.Count) {
    Write-Host ("  Edge count diverges: pass1={0}  pass2={1}" -f $pass1Edges.Count, $pass2Edges.Count) -ForegroundColor Red
    $edgeDivergences++
}
else {
    for ($i = 0; $i -lt $pass1EdgesSorted.Count; $i++) {
        if ($pass1EdgesSorted[$i] -ne $pass2EdgesSorted[$i]) {
            $edgeDivergences++
            if ($edgeDivergences -le 3) {
                Write-Host ("  Edge[$i] diverge:") -ForegroundColor Red
                Write-Host ("    Pass1: $($pass1EdgesSorted[$i])") -ForegroundColor DarkRed
                Write-Host ("    Pass2: $($pass2EdgesSorted[$i])") -ForegroundColor DarkRed
            }
        }
    }
}

Write-Host ("  Total (Signer→FileAttrib) edges in pass 1: {0}" -f $pass1Edges.Count)
Write-Host ("  Total (Signer→FileAttrib) edges in pass 2: {0}" -f $pass2Edges.Count)
Write-Host ("  Multiset-equivalent edges: {0}" -f ($pass1Edges.Count - $edgeDivergences))
Write-Host ("  Edge divergences: {0}" -f $edgeDivergences)

Write-Host ''
Write-Host "Step 6: FileAttribRef wiring fidelity (referenced FileAttrib IDs resolve)..." -ForegroundColor White
$pass1RefIds = @($pass1Refs | ForEach-Object { $_.GetAttribute('RuleID') })
$pass2RefIds = @($pass2Refs | ForEach-Object { $_.GetAttribute('RuleID') })
$pass1FileAttribIds = @($pass1FileAttribs | ForEach-Object { $_.GetAttribute('ID') })
$pass2FileAttribIds = @($pass2FileAttribs | ForEach-Object { $_.GetAttribute('ID') })

$unresolved1 = $pass1RefIds | Where-Object { $_ -notin $pass1FileAttribIds }
$unresolved2 = $pass2RefIds | Where-Object { $_ -notin $pass2FileAttribIds }
Write-Host ("  Pass 1 unresolved FileAttribRefs: {0}" -f @($unresolved1).Count)
Write-Host ("  Pass 2 unresolved FileAttribRefs: {0}" -f @($unresolved2).Count)

Write-Host ''
Write-Host "Step 7: FileAttrib set equivalence (pass 1 set === pass 2 set)..." -ForegroundColor White
$pass1Set = [System.Collections.Generic.HashSet[string]]::new()
foreach ($r in $pass1FileAttribs) { [void]$pass1Set.Add((Get-AttribKey $r)) }
$pass2Set = [System.Collections.Generic.HashSet[string]]::new()
foreach ($r in $pass2FileAttribs) { [void]$pass2Set.Add((Get-AttribKey $r)) }
$setsEqual = $pass1Set.SetEquals($pass2Set)
Write-Host ("  Pass 1 distinct FileAttrib attribute-sets: {0}" -f $pass1Set.Count)
Write-Host ("  Pass 2 distinct FileAttrib attribute-sets: {0}" -f $pass2Set.Count)
Write-Host ("  Sets equal: {0}" -f $setsEqual)

Write-Host ''
Write-Host ('=' * 80) -ForegroundColor DarkCyan
if ($pass1FileAttribs.Count -eq $pass2FileAttribs.Count `
    -and $pass1Refs.Count -eq $pass2Refs.Count `
    -and @($unresolved1).Count -eq 0 -and @($unresolved2).Count -eq 0 `
    -and $edgeDivergences -eq 0 `
    -and $setsEqual) {
    Write-Host 'ROUND-TRIP SOUND: FileAttrib emission is a viable import for ConvertFrom-CIPolicy.' -ForegroundColor Green
    Write-Host '  - All FileAttrib rules preserved across compile + decode cycle (set equivalence)' -ForegroundColor DarkGray
    Write-Host '  - All Signer→FileAttribRef→FileAttrib edges resolve to identical attribute sets' -ForegroundColor DarkGray
    Write-Host '  - Graph-isomorphic equivalence proven; positional reordering by ConvertFrom-CIPolicy' -ForegroundColor DarkGray
    Write-Host '    is benign (references track new positions)' -ForegroundColor DarkGray
}
else {
    Write-Host 'ROUND-TRIP FAILURE: see divergences above.' -ForegroundColor Red
}
Write-Host ('=' * 80) -ForegroundColor DarkCyan
Write-Host ''
Write-Host "Artefacts retained at:" -ForegroundColor DarkGray
Write-Host "  Compiled binary: $compiledCip"
Write-Host "  Pass-2 XML:      $decodedXml"
