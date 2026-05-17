function Read-BinaryHeader {
    <#
    .SYNOPSIS
        Reads the CI policy binary header (0x44 bytes / 68 bytes).

    .DESCRIPTION
        Parses the fixed-size header at the start of a CI policy binary.
        Returns a structured object with all header fields.

        Header layout (KPT-confirmed):
          0x00: FormatVersion (int32)
          0x04: HeaderGuid (GUID, 16 bytes) — BasePolicyID (V6+) or PolicyTypeID (legacy)
          0x14: PlatformID (GUID, 16 bytes)
          0x24: OptionFlags (uint32, bitmask — bit 31 must be set)
          0x28: EKUCount (int32)
          0x2C: FileRuleCount (int32)
          0x30: SignerCount (int32)
          0x34: ScenarioCount (int32)
          0x38: Version — Revision(u16), Build(u16), Minor(u16), Major(u16)
          0x40: HeaderLength (int32, always 0x40 = 64)

        Body starts at HeaderLength + 4 = 0x44.

    .PARAMETER Data
        Raw byte array of the CI policy binary (must be at least 68 bytes).

    .OUTPUTS
        PSCustomObject with all header fields.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Data
    )

    if ($Data.Length -lt 0x44) {
        throw "Data too short for CI policy header: $($Data.Length) bytes (minimum 68 required)"
    }

    $formatVersion = [BitConverter]::ToInt32($Data, 0x00)
    if ($formatVersion -lt 1 -or $formatVersion -gt 100) {
        throw "Invalid FormatVersion: $formatVersion (expected 1-9)"
    }

    # GUID at offset 0x04: BasePolicyID (V6+) or PolicyTypeID (legacy)
    $guidBytes = [byte[]]::new(16)
    [Array]::Copy($Data, 0x04, $guidBytes, 0, 16)
    $headerGuid = [guid]::new($guidBytes)

    # PlatformID at offset 0x14
    $platformBytes = [byte[]]::new(16)
    [Array]::Copy($Data, 0x14, $platformBytes, 0, 16)
    $platformId = [guid]::new($platformBytes)

    # OptionFlags at offset 0x24
    $optionFlags = [BitConverter]::ToUInt32($Data, 0x24)

    # Section counts
    $ekuCount = [BitConverter]::ToInt32($Data, 0x28)
    $fileRuleCount = [BitConverter]::ToInt32($Data, 0x2C)
    $signerCount = [BitConverter]::ToInt32($Data, 0x30)
    $scenarioCount = [BitConverter]::ToInt32($Data, 0x34)

    # Version (stored in reverse order: Revision, Build, Minor, Major)
    $vRevision = [BitConverter]::ToUInt16($Data, 0x38)
    $vBuild = [BitConverter]::ToUInt16($Data, 0x3A)
    $vMinor = [BitConverter]::ToUInt16($Data, 0x3C)
    $vMajor = [BitConverter]::ToUInt16($Data, 0x3E)

    # HeaderLength at offset 0x40 (should equal 0x40 = 64)
    $headerLength = [BitConverter]::ToInt32($Data, 0x40)

    [PSCustomObject]@{
        FormatVersion   = [int]$formatVersion
        HeaderGuid      = $headerGuid
        PlatformID      = $platformId
        OptionFlags     = $optionFlags
        EKUCount        = $ekuCount
        FileRuleCount   = $fileRuleCount
        SignerCount     = $signerCount
        ScenarioCount   = $scenarioCount
        VersionMajor    = [int]$vMajor
        VersionMinor    = [int]$vMinor
        VersionBuild    = [int]$vBuild
        VersionRevision = [int]$vRevision
        Version         = "$vMajor.$vMinor.$vBuild.$vRevision"
        HeaderLength    = $headerLength
        BodyOffset      = $headerLength + 4
    }
}
