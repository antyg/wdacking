function Read-BinaryEKU {
    <#
    .SYNOPSIS
        Reads EKU rule entries from the CI policy binary body.

    .DESCRIPTION
        Each EKU entry:
          [4 bytes: OID byte length (uint32)]
          [N bytes: DER-encoded ASN.1 OID]
          [0-3 bytes: padding to 4-byte boundary]

        The OID bytes are DER-encoded ASN.1 Object Identifiers. The Value
        property contains the hex-encoded OID bytes for direct use in XML
        EKU elements.

    .PARAMETER Reader
        BinaryReader positioned at the start of the EKU section (offset 0x44).

    .PARAMETER Count
        Number of EKU entries to read (from header offset 0x28).

    .OUTPUTS
        PSCustomObject[] — array of EKU objects with Index, OIDBytes, Value (hex string).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.BinaryReader]$Reader,

        [Parameter(Mandatory)]
        [int]$Count
    )

    $ekus = [System.Collections.Generic.List[PSCustomObject]]::new($Count)

    for ($i = 0; $i -lt $Count; $i++) {
        $oidLength = $Reader.ReadUInt32()
        $oidBytes = if ($oidLength -gt 0) {
            $Reader.ReadBytes([int]$oidLength)
        }
        else {
            [byte[]]@()
        }

        $padding = (4 - ($oidLength % 4)) -band 3
        if ($padding -gt 0) {
            [void]$Reader.ReadBytes([int]$padding)
        }

        # Hex-encode OID bytes for XML Value attribute
        $oidHex = if ($oidBytes.Length -gt 0) {
            ($oidBytes | ForEach-Object { $_.ToString('X2') }) -join ''
        }
        else { '' }

        $ekus.Add([PSCustomObject]@{
            Index    = $i
            OIDBytes = $oidBytes
            Value    = $oidHex
        })
    }

    return , $ekus.ToArray()
}
