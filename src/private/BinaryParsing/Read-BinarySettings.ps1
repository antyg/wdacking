function Read-BinarySettings {
    <#
    .SYNOPSIS
        Reads Secure Settings entries from the CI policy binary body.

    .DESCRIPTION
        The settings section is count-prefixed (uint32 count as first field in body).

        Per entry:
          [String: Provider]
          [String: Key]
          [String: ValueName]
          [4 bytes: ValueType (uint32) — 0=Boolean, 1=UInt32, 2=Binary, 3=String]
          [Value data based on type:]
            Boolean: [4 bytes: uint32, 0 or 1]
            UInt32:  [4 bytes: uint32]
            Binary:  [4 bytes: length] [N bytes: data + padding]
            String:  [String: value]

        Settings are sorted alphabetically by Key in the binary
        (compiler-determined order, not XML document order).

    .PARAMETER Reader
        BinaryReader positioned at the start of the Settings section
        (the count uint32 is the first field read).

    .OUTPUTS
        PSCustomObject[] — array of setting objects with Provider, Key,
        ValueName, ValueType, ValueTypeName, and Value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.BinaryReader]$Reader
    )

    # Count is the first uint32 in the section (count-prefixed)
    $count = [int]$Reader.ReadUInt32()
    $settings = [System.Collections.Generic.List[PSCustomObject]]::new($count)

    for ($i = 0; $i -lt $count; $i++) {
        $provider = Read-BinaryString -Reader $Reader
        $key = Read-BinaryString -Reader $Reader
        $valueName = Read-BinaryString -Reader $Reader

        $valueType = $Reader.ReadUInt32()  # 0=Bool, 1=UInt32, 2=Binary, 3=String
        $value = $null
        $valueTypeName = 'Unknown'

        switch ($valueType) {
            0 {
                $valueTypeName = 'Boolean'
                $value = $Reader.ReadUInt32() -ne 0
            }
            1 {
                $valueTypeName = 'DWord'
                $value = $Reader.ReadUInt32()
            }
            2 {
                $valueTypeName = 'Binary'
                $binaryLength = $Reader.ReadUInt32()
                if ($binaryLength -gt 0) {
                    $value = $Reader.ReadBytes([int]$binaryLength)
                    $padding = (4 - ($binaryLength % 4)) -band 3
                    if ($padding -gt 0) {
                        [void]$Reader.ReadBytes([int]$padding)
                    }
                }
                else {
                    $value = [byte[]]@()
                }
            }
            3 {
                $valueTypeName = 'String'
                $value = Read-BinaryString -Reader $Reader
            }
        }

        $settings.Add([PSCustomObject]@{
            Index         = $i
            Provider      = $provider
            Key           = $key
            ValueName     = $valueName
            ValueType     = [int]$valueType
            ValueTypeName = $valueTypeName
            Value         = $value
        })
    }

    return , $settings.ToArray()
}
