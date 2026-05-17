function Read-BinarySigner {
    <#
    .SYNOPSIS
        Reads Signer Rule entries from the CI policy binary body.

    .DESCRIPTION
        Each Signer entry:
          [4 bytes: CertRootType (uint32) — 0=TBS, 1=WellKnown]
          [Variable: CertRoot data (TBS: length-prefixed + padding; WellKnown: 4 bytes)]
          [4 bytes: EKU reference count]
          [N x 4 bytes: EKU index references]
          [String: CertIssuer]       (String field 0)
          [String: CertPublisher]    (String field 1)
          [String: CertOemID]        (String field 2)
          [4 bytes: FileAttrib reference count]
          [N x 4 bytes: FileAttrib index references]

        String field order confirmed by KPT analysis: CertIssuer, CertPublisher, CertOemID.

    .PARAMETER Reader
        BinaryReader positioned at the start of the Signer Rules section.

    .PARAMETER Count
        Number of Signer entries to read (from header offset 0x30).

    .OUTPUTS
        PSCustomObject[] — array of signer objects with CertRoot, EKU refs,
        string fields, and FileAttrib refs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.BinaryReader]$Reader,

        [Parameter(Mandatory)]
        [int]$Count
    )

    $signers = [System.Collections.Generic.List[PSCustomObject]]::new($Count)

    for ($i = 0; $i -lt $Count; $i++) {
        $certRootType = $Reader.ReadInt32()  # 0=TBS, 1=WellKnown

        $certRootValue = $null
        if ($certRootType -eq 0) {
            # TBS: length-prefixed byte array + padding
            $certRootLength = $Reader.ReadUInt32()
            $certRootBytes = $Reader.ReadBytes([int]$certRootLength)
            $padding = (4 - ($certRootLength % 4)) -band 3
            if ($padding -gt 0) {
                [void]$Reader.ReadBytes([int]$padding)
            }
            $certRootValue = ($certRootBytes | ForEach-Object { $_.ToString('X2') }) -join ''
        }
        else {
            # WellKnown: 4-byte uint32 value → hex string for XML
            $wellKnownId = $Reader.ReadUInt32()
            $certRootValue = $wellKnownId.ToString('X2')
        }

        # EKU index references
        $ekuRefCount = [int]$Reader.ReadUInt32()
        $ekuRefs = @(for ($j = 0; $j -lt $ekuRefCount; $j++) {
            $Reader.ReadInt32()
        })

        # Three string fields (KPT-confirmed order)
        $certIssuer = Read-BinaryString -Reader $Reader
        $certPublisher = Read-BinaryString -Reader $Reader
        $certOemID = Read-BinaryString -Reader $Reader

        # FileAttrib index references
        $fileAttribRefCount = [int]$Reader.ReadUInt32()
        $fileAttribRefs = @(for ($j = 0; $j -lt $fileAttribRefCount; $j++) {
            $Reader.ReadInt32()
        })

        $certRootTypeName = switch ($certRootType) {
            0 { 'TBS' }
            1 { 'Wellknown' }
            default { "Unknown($certRootType)" }
        }

        $signers.Add([PSCustomObject]@{
            Index            = $i
            CertRootType     = $certRootType
            CertRootTypeName = $certRootTypeName
            CertRootValue    = $certRootValue
            EKURefs          = $ekuRefs
            CertIssuer       = $certIssuer
            CertPublisher    = $certPublisher
            CertOemID        = $certOemID
            FileAttribRefs   = $fileAttribRefs
        })
    }

    return , $signers.ToArray()
}
