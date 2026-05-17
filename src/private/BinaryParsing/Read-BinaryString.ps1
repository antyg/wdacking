function Read-BinaryString {
    <#
    .SYNOPSIS
        Reads a length-prefixed UTF-16LE binary string from a BinaryReader.

    .DESCRIPTION
        CI policy binary string format:
          [4 bytes: UTF-16 byte count (uint32)]
          [N bytes: UTF-16LE string data]
          [0-3 bytes: zero padding to 4-byte boundary]
          [4 bytes: null terminator (0x00000000 — always present)]

        Empty strings: length=0, no data, null terminator only → 8 bytes total.

        Padding formula: paddingBytes = (4 - (length % 4)) & 3

    .PARAMETER Reader
        A System.IO.BinaryReader positioned at the start of the string field.

    .OUTPUTS
        [string] The decoded string value (empty string if length is 0).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.IO.BinaryReader]$Reader
    )

    $length = $Reader.ReadUInt32()

    if ($length -gt 0) {
        $padding = (4 - ($length % 4)) -band 3
        $bytes = $Reader.ReadBytes([int]$length)
        if ($padding -gt 0) {
            [void]$Reader.ReadBytes([int]$padding)
        }
        $value = [System.Text.Encoding]::Unicode.GetString($bytes)
    }
    else {
        $value = [string]::Empty
    }

    # Null terminator — always present (4 bytes of 0x00)
    [void]$Reader.ReadInt32()

    return $value
}
