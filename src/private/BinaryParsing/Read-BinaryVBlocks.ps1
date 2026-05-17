function Read-BinaryVBlocks {
    <#
    .SYNOPSIS
        Reads versioned V-blocks (V3-V9) from the tail of a CI policy binary.

    .DESCRIPTION
        V-blocks appear sequentially after the Settings section, each starting
        with a 4-byte marker (uint32 equal to the version number).

        V3: Per-FileRule MaximumFileVersion + AppID macros; Per-Signer SignTimeAfter
        V4: Per-FileRule InternalName, FileDescription, ProductName
        V5: Per-FileRule PackageFamilyName, PackageVersion
        V6: PolicyID (GUID) + BasePolicyID (GUID) + count-prefixed uint32 index array
            (count is the SupplementalPolicySigner index array length: 0 for supplemental
             policies, N for base policies authorising N supplemental signers)
        V7: Per-FileRule FilePath string (variable length; empty when rule keys on FileName/
            Hash/PackageFamilyName; non-empty when rule keys on path)
        V8: Single uint32 value
        V9: End sentinel (marker only)

        Blocks are conditionally present based on FormatVersion.

    .PARAMETER Reader
        BinaryReader positioned immediately after the Settings section.

    .PARAMETER FormatVersion
        The policy's FormatVersion from the header (determines which V-blocks exist).

    .PARAMETER FileRuleCount
        Number of file rules (for V3/V4/V5/V7 per-FileRule data).

    .PARAMETER SignerCount
        Number of signers (for V3 per-Signer data).

    .OUTPUTS
        PSCustomObject with V3, V4, V5, V6, V7, V8, V9Present properties.
        Each V-block property is $null if not present in this FormatVersion.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.BinaryReader]$Reader,

        [Parameter(Mandatory)]
        [int]$FormatVersion,

        [Parameter(Mandatory)]
        [int]$FileRuleCount,

        [Parameter(Mandatory)]
        [int]$SignerCount
    )

    $result = [PSCustomObject]@{
        V3        = $null
        V4        = $null
        V5        = $null
        V6        = $null
        V7        = $null
        V8        = $null
        V9Present = $false
    }

    # --- V3 block (FormatVersion >= 3) ---
    if ($FormatVersion -ge 3) {
        $marker = $Reader.ReadUInt32()
        if ($marker -ne 3) {
            throw "V3 marker mismatch: expected 3, got $marker at stream position 0x$(($Reader.BaseStream.Position - 4).ToString('X4'))"
        }

        # Per FileRule: MaximumFileVersion(8 bytes) + MacroCount(4) + MacroStrings
        $v3FileRules = [System.Collections.Generic.List[PSCustomObject]]::new($FileRuleCount)
        for ($i = 0; $i -lt $FileRuleCount; $i++) {
            $mvRevision = $Reader.ReadUInt16()
            $mvBuild = $Reader.ReadUInt16()
            $mvMinor = $Reader.ReadUInt16()
            $mvMajor = $Reader.ReadUInt16()

            $macroCount = [int]$Reader.ReadUInt32()
            $macros = @(for ($j = 0; $j -lt $macroCount; $j++) {
                Read-BinaryString -Reader $Reader
            })

            $v3FileRules.Add([PSCustomObject]@{
                MaximumFileVersion = "$mvMajor.$mvMinor.$mvBuild.$mvRevision"
                AppIDs             = $macros
            })
        }

        # Per Signer: SignTimeAfter (int64 FileTime)
        $v3Signers = [System.Collections.Generic.List[PSCustomObject]]::new($SignerCount)
        for ($i = 0; $i -lt $SignerCount; $i++) {
            $fileTime = $Reader.ReadInt64()
            $signTimeAfter = if ($fileTime -gt 0) {
                [datetime]::FromFileTimeUtc($fileTime)
            }
            else { $null }

            $v3Signers.Add([PSCustomObject]@{
                SignTimeAfterRaw = $fileTime
                SignTimeAfter    = $signTimeAfter
            })
        }

        $result.V3 = [PSCustomObject]@{
            FileRuleExtensions = $v3FileRules.ToArray()
            SignerExtensions   = $v3Signers.ToArray()
        }
    }

    # --- V4 block (FormatVersion >= 4) ---
    if ($FormatVersion -ge 4) {
        $marker = $Reader.ReadUInt32()
        if ($marker -ne 4) {
            throw "V4 marker mismatch: expected 4, got $marker at stream position 0x$(($Reader.BaseStream.Position - 4).ToString('X4'))"
        }

        # Per FileRule: InternalName, FileDescription, ProductName
        $v4FileRules = [System.Collections.Generic.List[PSCustomObject]]::new($FileRuleCount)
        for ($i = 0; $i -lt $FileRuleCount; $i++) {
            $internalName = Read-BinaryString -Reader $Reader
            $fileDescription = Read-BinaryString -Reader $Reader
            $productName = Read-BinaryString -Reader $Reader

            $v4FileRules.Add([PSCustomObject]@{
                InternalName    = $internalName
                FileDescription = $fileDescription
                ProductName     = $productName
            })
        }

        $result.V4 = [PSCustomObject]@{
            FileRuleExtensions = $v4FileRules.ToArray()
        }
    }

    # --- V5 block (FormatVersion >= 5) ---
    if ($FormatVersion -ge 5) {
        $marker = $Reader.ReadUInt32()
        if ($marker -ne 5) {
            throw "V5 marker mismatch: expected 5, got $marker at stream position 0x$(($Reader.BaseStream.Position - 4).ToString('X4'))"
        }

        # Per FileRule: PackageFamilyName (string) + PackageVersion (8 bytes)
        $v5FileRules = [System.Collections.Generic.List[PSCustomObject]]::new($FileRuleCount)
        for ($i = 0; $i -lt $FileRuleCount; $i++) {
            $pkgFamilyName = Read-BinaryString -Reader $Reader
            $pvRevision = $Reader.ReadUInt16()
            $pvBuild = $Reader.ReadUInt16()
            $pvMinor = $Reader.ReadUInt16()
            $pvMajor = $Reader.ReadUInt16()

            $v5FileRules.Add([PSCustomObject]@{
                PackageFamilyName = $pkgFamilyName
                PackageVersion    = "$pvMajor.$pvMinor.$pvBuild.$pvRevision"
            })
        }

        $result.V5 = [PSCustomObject]@{
            FileRuleExtensions = $v5FileRules.ToArray()
        }
    }

    # --- V6 block (FormatVersion >= 6) ---
    if ($FormatVersion -ge 6) {
        $marker = $Reader.ReadUInt32()
        if ($marker -ne 6) {
            throw "V6 marker mismatch: expected 6, got $marker at stream position 0x$(($Reader.BaseStream.Position - 4).ToString('X4'))"
        }

        $policyIdBytes = $Reader.ReadBytes(16)
        $basePolicyIdBytes = $Reader.ReadBytes(16)

        # Count-prefixed uint32 index array: SupplementalPolicySigner indices.
        # Per E8MVT CIPolicyParser.psm1:3214-3227 the count is SupplementalPolicySignerRuleEntryCount;
        # each index points into the Signers array, identifying signers permitted to author
        # supplemental policies for this base policy. Empirically (KPT probe 2026-05-17):
        #   - Supplemental policies: count = 0 (supplementals cannot authorise other supplementals)
        #   - Base policies: count = N (N signers authorised to issue supplementals)
        # All entries must be consumed to keep the stream aligned for V7+.
        $supplementalSignerCount = $Reader.ReadUInt32()
        $supplementalSignerIndices = [uint32[]]::new($supplementalSignerCount)
        for ($i = 0; $i -lt $supplementalSignerCount; $i++) {
            $supplementalSignerIndices[$i] = $Reader.ReadUInt32()
        }

        $result.V6 = [PSCustomObject]@{
            PolicyID                   = [guid]::new($policyIdBytes)
            BasePolicyID               = [guid]::new($basePolicyIdBytes)
            SupplementalSignerCount    = $supplementalSignerCount
            SupplementalSignerIndices  = $supplementalSignerIndices
            # Legacy alias properties — kept for backwards compatibility with consumers that
            # haven't been updated. New code should prefer SupplementalSigner* names.
            IndexCount                 = $supplementalSignerCount
            Indices                    = $supplementalSignerIndices
        }
    }

    # --- V7 block (FormatVersion >= 7) ---
    # Per-FileRule FilePath string. Probe-verified wire shape (2026-05-17 — see
    # docs/ci-binary-format-reference.md § "V7 Wire-Shape Disambiguation Evidence").
    # Empty FilePath strings (rule keys on FileName/Hash/PackageFamilyName) consume
    # exactly 8 bytes (4 length-zero + 4 null-terminator) — byte-identical to two zero
    # uint32s, which was the source of an earlier misreading. Non-empty strings consume
    # 4 + N + padding + 4 bytes. The V8 marker follows immediately.
    if ($FormatVersion -ge 7) {
        $marker = $Reader.ReadUInt32()
        if ($marker -ne 7) {
            throw "V7 marker mismatch: expected 7, got $marker at stream position 0x$(($Reader.BaseStream.Position - 4).ToString('X4'))"
        }

        $v7FileRules = [System.Collections.Generic.List[PSCustomObject]]::new($FileRuleCount)
        for ($i = 0; $i -lt $FileRuleCount; $i++) {
            $filePath = Read-BinaryString -Reader $Reader
            $v7FileRules.Add([PSCustomObject]@{
                FilePath = $filePath
            })
        }

        $result.V7 = [PSCustomObject]@{
            FileRuleExtensions = $v7FileRules.ToArray()
        }
    }

    # --- V8 block (FormatVersion >= 8) ---
    if ($FormatVersion -ge 8) {
        $marker = $Reader.ReadUInt32()
        if ($marker -ne 8) {
            throw "V8 marker mismatch: expected 8, got $marker at stream position 0x$(($Reader.BaseStream.Position - 4).ToString('X4'))"
        }

        $v8Value = $Reader.ReadUInt32()
        $result.V8 = [PSCustomObject]@{
            Value = $v8Value
        }
    }

    # --- V9 sentinel (FormatVersion >= 8) ---
    if ($FormatVersion -ge 8) {
        $marker = $Reader.ReadUInt32()
        if ($marker -eq 9) {
            $result.V9Present = $true
        }
    }

    return $result
}
