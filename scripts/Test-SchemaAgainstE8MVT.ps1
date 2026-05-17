#Requires -Version 5.1
<#
.SYNOPSIS
    Validate workspace-generated .cip.xml files against E8MVT's typed CodeIntegrity.SIPolicy
    schema using System.Xml.Serialization.XmlSerializer.

.DESCRIPTION
    E8MVT's CIPolicyParser.psm1 registers a complete C# class hierarchy under the
    `CodeIntegrity` namespace via inline Add-Type. Those classes carry [XmlAttribute] /
    [XmlElement] decorations that make them a near-perfect reflection of cipolicy.xsd.

    This script:
      1. Imports CIPolicyParser.psm1 (PS 5.1 only — pwsh 7+ fails on Add-Type assembly
         resolution). The import registers all CodeIntegrity.* types as side-effect.
      2. For each .cip.xml under the supplied directory, attempts to deserialise into
         [CodeIntegrity.SIPolicy] via XmlSerializer.
      3. Hooks the serialiser's UnknownAttribute/UnknownElement/UnknownNode events so
         schema mismatches surface as audit findings (not silent drops).
      4. Walks the deserialised object tree and prints key dimensions (rule counts,
         signer counts, scenarios, settings) for visual sanity-check against the
         workspace's own decode output.

    A clean run (zero Unknown* events, successful deserialisation, dimensions matching
    the source XML) proves the workspace decoder's output is consumable by the
    CodeIntegrity typed model — i.e., any downstream tool that consumes E8MVT's typed
    objects can also consume workspace output without changes.

    The strict-mode crash in CIPolicyParser at line 2608 occurs during ConvertTo-CIPolicy's
    parsing of certain EKU sections. We do NOT call ConvertTo-CIPolicy — only the type
    definitions are needed. Module import itself succeeds under strict-mode-off scope.

.PARAMETER EvidenceRoot
    Folder containing the .cip.xml files to validate. Defaults to ISM-0843_workstations.
#>
param(
    [string]$EvidenceRoot = 'D:\antyg\Work\dfsdscs\E8\evidence\application-control\ISM-0843_workstations',

    [string]$E8MvtParserPath = 'D:\antyg\Work\dfsdscs\E8\Tools\E8 Maturity Verification Tool Oct 2025\Resources\Scripts\CIPolicyParser.psm1'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $E8MvtParserPath)) { throw "E8MVT parser not found: $E8MvtParserPath" }
if (-not (Test-Path $EvidenceRoot))    { throw "EvidenceRoot not found: $EvidenceRoot" }

Write-Host ''
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host "Schema validation against E8MVT typed CodeIntegrity.SIPolicy model" -ForegroundColor Cyan
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host ''

# Load CodeIntegrity types. The `Add-Type -TypeDefinition $TypeDef` call lives INSIDE the
# ConvertTo-CIPolicy function body (not at module scope), so just importing the module is
# insufficient — we must invoke ConvertTo-CIPolicy once to trigger type registration.
# Pick a known-safe policy that doesn't trip the strict-mode bug at line 2608 of
# CIPolicyParser (the `if ($OID.FriendlyName)` crash on policies with unusual EKU OID shapes,
# like {60FD87F8}). The 645-rule {1283AC0F} LOLBin policy decodes cleanly.
$primingCip = 'D:\antyg\Work\dfsdscs\E8\evidence\application-control\ISM-0843_workstations\evidence-01-wdac-policy-_1283AC0F-FFF1-49AE-ADA1-8A933130CAD6_-20260515094737.cip'
if (-not (Test-Path $primingCip)) { throw "Priming .cip not found: $primingCip" }

Write-Host "  Priming CodeIntegrity type registration via E8MVT ConvertTo-CIPolicy..." -ForegroundColor DarkGray
& {
    Set-StrictMode -Off
    Import-Module $E8MvtParserPath -Force -DisableNameChecking -ErrorAction Stop
    # ConvertTo-CIPolicy returns the [CodeIntegrity.SIPolicy] object directly; discard
    # the output, we only want the side effect of types being registered via Add-Type.
    $null = ConvertTo-CIPolicy -BinaryFilePath $primingCip -ErrorAction Stop
}

# Confirm types loaded
$siPolicyType = 'CodeIntegrity.SIPolicy' -as [Type]
if ($null -eq $siPolicyType) {
    throw "Failed to load CodeIntegrity.SIPolicy type after priming ConvertTo-CIPolicy. Check E8MVT module compatibility."
}
Write-Host "  Loaded type: $($siPolicyType.FullName)" -ForegroundColor Green
Write-Host "  Type assembly: $($siPolicyType.Assembly.FullName)" -ForegroundColor DarkGray
Write-Host ''

# Enumerate the SIPolicy type's properties for visibility
Write-Host "  CodeIntegrity.SIPolicy declared properties:" -ForegroundColor DarkGray
$siPolicyType.GetProperties() | ForEach-Object {
    $typeName = $_.PropertyType.Name
    if ($_.PropertyType.IsArray) { $typeName = "$($_.PropertyType.GetElementType().Name)[]" }
    Write-Host ("    {0,-30} {1}" -f $typeName, $_.Name) -ForegroundColor DarkGray
}
Write-Host ''

# Collect .cip.xml files
$xmlFiles = @(Get-ChildItem -Path $EvidenceRoot -Filter '*.cip.xml' -File | Sort-Object Name)
Write-Host "  Found $($xmlFiles.Count) .cip.xml files to validate" -ForegroundColor DarkGray
Write-Host ''

# Build a serialiser keyed to SIPolicy's expected namespace
$serializer = [System.Xml.Serialization.XmlSerializer]::new($siPolicyType)

$summary = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($xmlFile in $xmlFiles) {
    $shortName = ($xmlFile.Name -replace 'evidence-01-wdac-policy-_', '' -replace '_-\d{14}\.cip\.xml$', '')
    Write-Host ('-' * 100) -ForegroundColor DarkGray
    Write-Host "  $shortName" -ForegroundColor White

    $unknownAttrs = [System.Collections.Generic.List[string]]::new()
    $unknownElems = [System.Collections.Generic.List[string]]::new()
    $unknownNodes = [System.Collections.Generic.List[string]]::new()

    $attrHandler = [System.Xml.Serialization.XmlAttributeEventHandler]{
        param($sender, $e)
        $unknownAttrs.Add("$($e.Attr.Name) on $($e.ObjectBeingDeserialized.GetType().Name)")
    }
    $elemHandler = [System.Xml.Serialization.XmlElementEventHandler]{
        param($sender, $e)
        $unknownElems.Add("$($e.Element.LocalName) on $($e.ObjectBeingDeserialized.GetType().Name)")
    }
    $nodeHandler = [System.Xml.Serialization.XmlNodeEventHandler]{
        param($sender, $e)
        $unknownNodes.Add("$($e.LocalName) (type $($e.NodeType))")
    }

    $serializer.add_UnknownAttribute($attrHandler)
    $serializer.add_UnknownElement($elemHandler)
    $serializer.add_UnknownNode($nodeHandler)

    $deserialized = $null
    $deserError = $null
    try {
        $reader = [System.IO.StreamReader]::new($xmlFile.FullName)
        try {
            $deserialized = $serializer.Deserialize($reader)
        }
        finally {
            $reader.Dispose()
        }
    }
    catch {
        $deserError = $_.Exception.Message
    }
    finally {
        $serializer.remove_UnknownAttribute($attrHandler)
        $serializer.remove_UnknownElement($elemHandler)
        $serializer.remove_UnknownNode($nodeHandler)
    }

    if ($null -ne $deserError) {
        Write-Host "    DESERIALISE ERROR: $deserError" -ForegroundColor Red
        $summary.Add([PSCustomObject]@{
            Policy        = $shortName
            Status        = 'ERROR'
            EKUs          = $null
            FileRules     = $null
            Signers       = $null
            Scenarios     = $null
            Settings      = $null
            SuppSigners   = $null
            UnknownAttrs  = 0
            UnknownElems  = 0
            UnknownNodes  = 0
        })
        continue
    }

    # Walk the typed object tree
    $ekuCount      = if ($deserialized.EKUs)              { @($deserialized.EKUs).Count }              else { 0 }
    $signerCount   = if ($deserialized.Signers)           { @($deserialized.Signers).Count }           else { 0 }
    $scenarioCount = if ($deserialized.SigningScenarios)  { @($deserialized.SigningScenarios).Count }  else { 0 }
    $settingsCount = if ($deserialized.Settings)          { @($deserialized.Settings).Count }          else { 0 }

    # FileRules: union of Allow + Deny + FileAttrib (the typed model has these as separate
    # properties or as Items in a choice element — we use reflection to find any FileRule-like
    # collection regardless of how the schema models it)
    $fileRuleCount = 0
    foreach ($prop in $deserialized.GetType().GetProperties()) {
        if ($prop.Name -in @('FileRules', 'Items') -and $null -ne $prop.GetValue($deserialized)) {
            $val = $prop.GetValue($deserialized)
            if ($val -is [array]) { $fileRuleCount += $val.Count }
        }
    }
    # SIPolicy might expose FileRules differently; probe via reflection
    $fileRulesProp = $deserialized.GetType().GetProperty('FileRules')
    if ($null -ne $fileRulesProp) {
        $fr = $fileRulesProp.GetValue($deserialized)
        if ($null -ne $fr -and $fr.Items) {
            $fileRuleCount = @($fr.Items).Count
        }
    }

    $suppSignerCount = 0
    $sspProp = $deserialized.GetType().GetProperty('SupplementalPolicySigners')
    if ($null -ne $sspProp) {
        $ssp = $sspProp.GetValue($deserialized)
        if ($null -ne $ssp) { $suppSignerCount = @($ssp).Count }
    }

    $hasUnknowns = ($unknownAttrs.Count + $unknownElems.Count + $unknownNodes.Count) -gt 0
    $statusColor = if ($hasUnknowns) { 'Yellow' } else { 'Green' }
    $statusText  = if ($hasUnknowns) { 'OK (with unknowns)' } else { 'CLEAN' }

    Write-Host ("    Status: {0}" -f $statusText) -ForegroundColor $statusColor
    Write-Host ("    EKUs={0}  FileRules={1}  Signers={2}  Scenarios={3}  Settings={4}  SuppSigners={5}" `
        -f $ekuCount, $fileRuleCount, $signerCount, $scenarioCount, $settingsCount, $suppSignerCount) -ForegroundColor DarkGray

    if ($unknownAttrs.Count -gt 0) {
        Write-Host ("    Unknown attributes ({0}):" -f $unknownAttrs.Count) -ForegroundColor Yellow
        $unknownAttrs | Select-Object -Unique -First 10 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkYellow }
        if ($unknownAttrs.Count -gt 10) { Write-Host "      ... ($($unknownAttrs.Count - 10) more)" -ForegroundColor DarkYellow }
    }
    if ($unknownElems.Count -gt 0) {
        Write-Host ("    Unknown elements ({0}):" -f $unknownElems.Count) -ForegroundColor Yellow
        $unknownElems | Select-Object -Unique -First 10 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkYellow }
        if ($unknownElems.Count -gt 10) { Write-Host "      ... ($($unknownElems.Count - 10) more)" -ForegroundColor DarkYellow }
    }
    if ($unknownNodes.Count -gt 0) {
        Write-Host ("    Unknown nodes ({0}):" -f $unknownNodes.Count) -ForegroundColor Yellow
        $unknownNodes | Select-Object -Unique -First 10 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkYellow }
    }

    $summary.Add([PSCustomObject]@{
        Policy        = $shortName
        Status        = if ($hasUnknowns) { 'OK-unknowns' } else { 'CLEAN' }
        EKUs          = $ekuCount
        FileRules     = $fileRuleCount
        Signers       = $signerCount
        Scenarios     = $scenarioCount
        Settings      = $settingsCount
        SuppSigners   = $suppSignerCount
        UnknownAttrs  = $unknownAttrs.Count
        UnknownElems  = $unknownElems.Count
        UnknownNodes  = $unknownNodes.Count
    })
}

Write-Host ''
Write-Host ('=' * 100) -ForegroundColor DarkCyan
Write-Host 'Validation summary' -ForegroundColor Cyan
Write-Host ('=' * 100) -ForegroundColor DarkCyan
$summary | Format-Table -AutoSize

$cleanCount  = @($summary | Where-Object { $_.Status -eq 'CLEAN' }).Count
$dirtyCount  = @($summary | Where-Object { $_.Status -eq 'OK-unknowns' }).Count
$errorCount  = @($summary | Where-Object { $_.Status -eq 'ERROR' }).Count

Write-Host ''
Write-Host ("  Clean (zero unknown nodes/attrs/elems):     {0}/{1}" -f $cleanCount, $summary.Count) -ForegroundColor Green
if ($dirtyCount -gt 0) {
    Write-Host ("  Deserialised with unknowns:                  {0}/{1}" -f $dirtyCount, $summary.Count) -ForegroundColor Yellow
}
if ($errorCount -gt 0) {
    Write-Host ("  Deserialise errors:                          {0}/{1}" -f $errorCount, $summary.Count) -ForegroundColor Red
}
Write-Host ''
