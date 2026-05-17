function Read-BinaryFileRule {
    <#
    .SYNOPSIS
        Reads File Rule entries from the CI policy binary body.

    .DESCRIPTION
        Each File Rule entry:
          [4 bytes: RuleType (uint32) — 0=Deny, 1=Allow, 2=FileAttrib]
          [String: FileName]
          [8 bytes: MinimumFileVersion — Revision(u16), Build(u16), Minor(u16), Major(u16)]
          [4 bytes: HashLength (uint32)]
          [N bytes: Hash data + padding (if HashLength > 0)]

        Binary file rules are sorted by type (Deny → Allow → FileAttrib),
        not by original XML document order.

    .PARAMETER Reader
        BinaryReader positioned at the start of the File Rules section.

    .PARAMETER Count
        Number of File Rule entries to read (from header offset 0x2C).

    .OUTPUTS
        PSCustomObject[] — array of file rule objects with Index, RuleType,
        RuleTypeName, FileName, MinimumFileVersion, Hash, etc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.BinaryReader]$Reader,

        [Parameter(Mandatory)]
        [int]$Count
    )

    $rules = [System.Collections.Generic.List[PSCustomObject]]::new($Count)
    $ruleTypeMap = @{ 0 = 'Deny'; 1 = 'Allow'; 2 = 'FileAttrib' }

    for ($i = 0; $i -lt $Count; $i++) {
        $ruleType = $Reader.ReadInt32()
        $fileName = Read-BinaryString -Reader $Reader

        # MinimumFileVersion: stored as Revision, Build, Minor, Major (reverse order)
        $mvRevision = $Reader.ReadUInt16()
        $mvBuild = $Reader.ReadUInt16()
        $mvMinor = $Reader.ReadUInt16()
        $mvMajor = $Reader.ReadUInt16()

        $hashLength = $Reader.ReadUInt32()
        $hashBytes = $null
        if ($hashLength -gt 0) {
            $hashBytes = $Reader.ReadBytes([int]$hashLength)
            $padding = (4 - ($hashLength % 4)) -band 3
            if ($padding -gt 0) {
                [void]$Reader.ReadBytes([int]$padding)
            }
        }

        $hashHex = if ($null -ne $hashBytes -and $hashBytes.Length -gt 0) {
            ($hashBytes | ForEach-Object { $_.ToString('X2') }) -join ''
        }
        else { $null }

        $typeName = if ($ruleTypeMap.ContainsKey($ruleType)) {
            $ruleTypeMap[$ruleType]
        }
        else { "Unknown($ruleType)" }

        $rules.Add([PSCustomObject]@{
            Index              = $i
            RuleType           = $ruleType
            RuleTypeName       = $typeName
            FileName           = $fileName
            MinimumFileVersion = "$mvMajor.$mvMinor.$mvBuild.$mvRevision"
            HashLength         = [int]$hashLength
            Hash               = $hashHex
        })
    }

    return , $rules.ToArray()
}
