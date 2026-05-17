function ConvertFrom-WDACBinary {
    <#
    .SYNOPSIS
        Converts a CI policy binary (.cip/.p7b) to an XSD-compliant SiPolicy XmlDocument.

    .DESCRIPTION
        Parses a Windows Defender Application Control (WDAC) Code Integrity policy
        binary and reconstructs a full SiPolicy XML document that conforms to the
        cipolicy.xsd schema (namespace: urn:schemas-microsoft-com:sipolicy).

        Handles all binary features:
        - Header parsing (0x44 bytes, FormatVersion 1-9)
        - All 8 body sections in KPT-confirmed order
        - Versioned V-blocks (V3-V9) for extended FileRule/Signer metadata
        - PKCS#7 SignedData unwrapping for signed .p7b and .cip files
        - OptionFlags bitmask → XML Rule Option translation
        - Synthetic ID generation (ID_ALLOW_A_N, ID_SIGNER_S_N, etc.)

        The XML→binary compilation by ConvertFrom-CIPolicy is lossy:
        FriendlyName, ID attributes, and Signer Name are not stored in binary.
        This function generates synthetic replacements for those fields.

    .PARAMETER Data
        Raw byte array of the CI policy binary.

    .PARAMETER Path
        File path to a .cip or .p7b CI policy file.

    .OUTPUTS
        [System.Xml.XmlDocument] — XSD-compliant SiPolicy XML document.

    .EXAMPLE
        $xml = ConvertFrom-WDACBinary -Path 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{GUID}.cip'
        $xml.Save('policy.xml')

    .EXAMPLE
        $bytes = [System.IO.File]::ReadAllBytes('policy.cip')
        $xml = ConvertFrom-WDACBinary -Data $bytes
        $xml.SiPolicy.Rules.Rule | ForEach-Object { $_.Option }
    #>
    [CmdletBinding(DefaultParameterSetName = 'FromData')]
    [OutputType([System.Xml.XmlDocument])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'FromData', Position = 0)]
        [byte[]]$Data,

        [Parameter(Mandatory, ParameterSetName = 'FromPath')]
        [ValidateScript({ Test-Path $_ })]
        [string]$Path
    )

    # ================================================================
    # OptionFlags bitmask → XML Rule Option Name mapping
    # ================================================================
    # Two registry classes:
    #
    #   Class A — XSD-canonical bits. Value is the OptionType enum string. Emit as
    #             <Rule><Option>$value</Option></Rule>. Round-trips through the
    #             Microsoft ConvertFrom-CIPolicy public compiler.
    #
    #   Class B — Binary-only bits. Value is prefixed with the __BINARYONLY__:
    #             sentinel. Emit as an XML transparency comment inside <Rules>.
    #             These bits have no element in the public cipolicy.xsd but are
    #             documented in independent reverse-engineering sources. The
    #             transparency comment preserves the bit's existence for
    #             documentation but is stripped by ConvertFrom-CIPolicy on
    #             re-compile (XML comments are not part of the post-schema-
    #             validation infoset, verified empirically 2026-05-17 via
    #             Test-XsdValidationBoundaries.ps1). This asymmetry is inherent to
    #             the read/write contract — see ci-binary-format-reference.md for the
    #             OptionFlags transparency-comment mechanism section.
    #
    # Bits 30 (supplemental marker) and 31 (validation) are not rule options and
    # are filtered out by the 0x3FFFFFFF mask in the emission loop.
    #
    # Unregistered bits set in source binaries trigger a positional transparency
    # comment from the emission loop ("bit N (0xHEX) — unregistered"), preserving
    # forward compatibility with future Microsoft bit additions.
    $bitToOptionName = @{
        # ---- Class A: XSD-canonical ----
        2  = 'Enabled:UMCI'
        3  = 'Enabled:Boot Menu Protection'
        4  = 'Enabled:Intelligent Security Graph Authorization'
        5  = 'Enabled:Invalidate EAs on Reboot'
        7  = 'Required:WHQL'
        8  = 'Enabled:Developer Mode Dynamic Code Trust'
        10 = 'Enabled:Allow Supplemental Policies'
        11 = 'Disabled:Runtime FilePath Rule Protection'
        13 = 'Enabled:Revoked Expired As Unsigned'
        16 = 'Enabled:Audit Mode'
        17 = 'Disabled:Flight Signing'
        18 = 'Enabled:Inherit Default Policy'
        19 = 'Enabled:Unsigned System Integrity Policy'
        20 = 'Enabled:Dynamic Code Security'
        21 = 'Required:EV Signers'
        22 = 'Enabled:Boot Audit On Failure'
        23 = 'Enabled:Advanced Boot Options Menu'
        24 = 'Disabled:Script Enforcement'
        25 = 'Required:Enforce Store Applications'
        26 = 'Enabled:Secure Setting Policy'
        27 = 'Enabled:Managed Installer'
        28 = 'Enabled:Update Policy No Reboot'
        29 = 'Enabled:Conditional Windows Lockdown Policy'

        # ---- Class B: binary-only (sentinel prefix triggers comment emission) ----
        # Bit 6 — Windows Lockdown Trial Mode. Documented in the E8MVT bit-to-option
        # table (Matt Graeber, CIPolicyParser.psm1) from reverse engineering of
        # Microsoft-shipped system policies. Not present in the public cipolicy.xsd
        # OptionType enumeration; Microsoft's public ConvertFrom-CIPolicy compiler
        # cannot encode this bit.
        6  = '__BINARYONLY__:Enabled:Windows Lockdown Trial Mode'
    }

    # ================================================================
    # 1. Input handling
    # ================================================================
    if ($PSCmdlet.ParameterSetName -eq 'FromPath') {
        $Data = [System.IO.File]::ReadAllBytes((Resolve-Path $Path).Path)
    }

    # ================================================================
    # 2. PKCS#7 unwrapping (transparent — returns original if not signed)
    # ================================================================
    $Data = Unprotect-Pkcs7Policy -Data $Data

    # ================================================================
    # 3. Header parsing (0x44 bytes)
    # ================================================================
    $header = Read-BinaryHeader -Data $Data

    # ================================================================
    # 4. Sequential body section reading (KPT-confirmed order)
    #    EKU → FileRules → Signers → UpdSign → CISign → Scenarios → HVCI → Settings → V-blocks
    # ================================================================
    $stream = [System.IO.MemoryStream]::new($Data)
    $reader = [System.IO.BinaryReader]::new($stream)
    try {
        $stream.Position = $header.BodyOffset

        # Section 1: EKU Rules (count from header 0x28)
        $ekus = Read-BinaryEKU -Reader $reader -Count $header.EKUCount

        # Section 2: File Rules (count from header 0x2C)
        $fileRules = Read-BinaryFileRule -Reader $reader -Count $header.FileRuleCount

        # Section 3: Signer Rules (count from header 0x30)
        $signers = Read-BinarySigner -Reader $reader -Count $header.SignerCount

        # Section 4: Update Policy Signers (count-prefixed in body — NOT in header)
        $updateSignerCount = [int]$reader.ReadUInt32()
        $updateSignerIndices = @(for ($i = 0; $i -lt $updateSignerCount; $i++) {
            $reader.ReadInt32()
        })

        # Section 5: CI Signers (count-prefixed in body — NOT in header)
        $ciSignerCount = [int]$reader.ReadUInt32()
        $ciSignerIndices = @(for ($i = 0; $i -lt $ciSignerCount; $i++) {
            $reader.ReadInt32()
        })

        # Section 6: Signing Scenarios (count from header 0x34)
        $scenarios = Read-BinaryScenario -Reader $reader -Count $header.ScenarioCount

        # Section 7: HVCI Options (single uint32)
        $hvciOptions = $reader.ReadUInt32()

        # Section 8: Secure Settings (count-prefixed in body)
        $settings = Read-BinarySettings -Reader $reader

        # V-blocks (V3-V9, presence determined by FormatVersion)
        $vblocks = Read-BinaryVBlocks -Reader $reader `
            -FormatVersion $header.FormatVersion `
            -FileRuleCount $header.FileRuleCount `
            -SignerCount $header.SignerCount
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }

    # ================================================================
    # 5. Generate ID maps (binary positional index → XML element ID)
    # ================================================================

    # EKU IDs: ID_EKU_E_1, ID_EKU_E_2, ...
    $ekuIdMap = @{}
    for ($i = 0; $i -lt $ekus.Count; $i++) {
        $ekuIdMap[$i] = "ID_EKU_E_$($i + 1)"
    }

    # FileRule IDs: separate counters per type (binary sorts: Deny → Allow → FileAttrib),
    # formatted as 4-digit uppercase hex per WDAC ecosystem convention (matches E8MVT
    # CIPolicyParser idiom; see docs/ci-binary-format-reference.md § "Per-Field Emit Policy").
    $fileRuleIdMap = @{}
    $allowCounter = 0; $denyCounter = 0; $fileAttribCounter = 0
    for ($i = 0; $i -lt $fileRules.Count; $i++) {
        switch ($fileRules[$i].RuleType) {
            0 { $denyCounter++;       $fileRuleIdMap[$i] = 'ID_DENY_D_{0:X4}' -f $denyCounter }
            1 { $allowCounter++;      $fileRuleIdMap[$i] = 'ID_ALLOW_A_{0:X4}' -f $allowCounter }
            2 { $fileAttribCounter++; $fileRuleIdMap[$i] = 'ID_FILEATTRIB_F_{0:X4}' -f $fileAttribCounter }
            default { $fileRuleIdMap[$i] = 'ID_FILERULE_{0:X4}' -f ($i + 1) }
        }
    }

    # Signer IDs: ID_SIGNER_S_1, ID_SIGNER_S_2, ...
    $signerIdMap = @{}
    for ($i = 0; $i -lt $signers.Count; $i++) {
        $signerIdMap[$i] = "ID_SIGNER_S_$($i + 1)"
    }

    # ================================================================
    # 6. Build XSD-compliant SiPolicy XmlDocument
    # ================================================================
    $ns = 'urn:schemas-microsoft-com:sipolicy'
    $xml = [System.Xml.XmlDocument]::new()
    $decl = $xml.CreateXmlDeclaration('1.0', 'utf-8', $null)
    [void]$xml.AppendChild($decl)

    $siPolicy = $xml.CreateElement('SiPolicy', $ns)

    # PolicyType attribute (V6+ multi-policy format only)
    if ($null -ne $vblocks.V6) {
        $isSupplemental = $vblocks.V6.PolicyID -ne $vblocks.V6.BasePolicyID
        $policyTypeAttr = if ($isSupplemental) { 'Supplemental Policy' } else { 'Base Policy' }
        $siPolicy.SetAttribute('PolicyType', $policyTypeAttr)
    }

    [void]$xml.AppendChild($siPolicy)

    # ------ VersionEx ------
    $versionElem = $xml.CreateElement('VersionEx', $ns)
    $versionElem.InnerText = $header.Version
    [void]$siPolicy.AppendChild($versionElem)

    # ------ PlatformID ------
    $platformElem = $xml.CreateElement('PlatformID', $ns)
    $platformElem.InnerText = "{$($header.PlatformID)}"
    [void]$siPolicy.AppendChild($platformElem)

    # ------ PolicyTypeID / PolicyID / BasePolicyID ------
    if ($null -ne $vblocks.V6) {
        # V6+ multi-policy format
        $pIdElem = $xml.CreateElement('PolicyID', $ns)
        $pIdElem.InnerText = "{$($vblocks.V6.PolicyID)}"
        [void]$siPolicy.AppendChild($pIdElem)

        $bpIdElem = $xml.CreateElement('BasePolicyID', $ns)
        $bpIdElem.InnerText = "{$($vblocks.V6.BasePolicyID)}"
        [void]$siPolicy.AppendChild($bpIdElem)
    }
    else {
        # Legacy format — header 0x04 contains PolicyTypeID
        $ptIdElem = $xml.CreateElement('PolicyTypeID', $ns)
        $ptIdElem.InnerText = "{$($header.HeaderGuid)}"
        [void]$siPolicy.AppendChild($ptIdElem)
    }

    # ------ Rules (OptionFlags bitmask → Rule/Option elements + transparency comments) ------
    # Iterate the full 30-bit range so any bit set in the source binary is accounted for —
    # XSD-canonical bits emit as <Rule><Option>, binary-only bits emit as <!-- comments -->,
    # and bits not in the registry at all emit as positional transparency comments
    # (preserving forward compatibility with future Microsoft additions).
    $rulesElem = $xml.CreateElement('Rules', $ns)
    $ruleFlags = $header.OptionFlags -band 0x3FFFFFFF  # mask off bits 30-31

    for ($bit = 0; $bit -lt 30; $bit++) {
        if (($ruleFlags -band (1 -shl $bit)) -eq 0) { continue }

        $mapped = $bitToOptionName[$bit]
        if ($null -ne $mapped -and -not $mapped.StartsWith('__BINARYONLY__:')) {
            # Class A — XSD-canonical option string
            $ruleElem = $xml.CreateElement('Rule', $ns)
            $optionElem = $xml.CreateElement('Option', $ns)
            $optionElem.InnerText = $mapped
            [void]$ruleElem.AppendChild($optionElem)
            [void]$rulesElem.AppendChild($ruleElem)
        }
        else {
            # Class B — binary-only or unregistered bit. Emit transparency comment.
            $description = if ($null -ne $mapped) {
                $mapped.Substring('__BINARYONLY__:'.Length)
            } else {
                'unregistered (not in workspace bit map as of 2026-05-17)'
            }
            $hex = '0x{0:X8}' -f (1 -shl $bit)
            $commentNode = $xml.CreateComment(" BinaryOnly: bit $bit ($hex) — $description ")
            [void]$rulesElem.AppendChild($commentNode)
        }
    }
    [void]$siPolicy.AppendChild($rulesElem)

    # ------ EKUs ------
    $ekusElem = $xml.CreateElement('EKUs', $ns)
    foreach ($eku in $ekus) {
        $ekuElem = $xml.CreateElement('EKU', $ns)
        $ekuElem.SetAttribute('ID', $ekuIdMap[$eku.Index])
        $ekuElem.SetAttribute('Value', $eku.Value)
        $ekuElem.SetAttribute('FriendlyName', "EKU $($eku.Index + 1)")
        [void]$ekusElem.AppendChild($ekuElem)
    }
    [void]$siPolicy.AppendChild($ekusElem)

    # ------ FileRules (with V3/V4/V5/V7 extensions merged) ------
    # Conditional attribute emission per the Round 3 per-field emit policy
    # (extended 2026-05-17 to unify version-sentinel suppression across all three
    # version attributes — see docs/ci-binary-format-reference.md § "Per-Field Emit Policy
    # Summary" for the runtime-semantics argument that justifies the unification):
    #
    #   - FriendlyName: suppressed entirely (binary doesn't carry one; honest representation)
    #   - FileName: emit only when binary value is non-empty
    #   - Hash: emit only when non-null
    #   - InternalName/FileDescription/ProductName (V4): emit only when non-empty
    #   - PackageFamilyName (V5): emit only when non-empty
    #   - FilePath (V7): emit only when non-empty (added 2026-05-17 per Priority 1)
    #   - MinimumFileVersion (FileRule entry) / MaximumFileVersion (V3) / PackageVersion (V5):
    #     emit only when value is NOT one of the version sentinels. Both '0.0.0.0' and
    #     '65535.65535.65535.65535' reduce to "no constraint" at WDAC runtime enforcement
    #     (0.0.0.0 is Microsoft's "absent" encoding; 65535... is the type's representational
    #     max which evaluates as "always matches" for upper bounds and "never matches" =
    #     redundant for lower bounds). Suppressing both preserves functional-import
    #     equivalence while dropping bytes that carry no semantic content.
    $versionSentinels = @('0.0.0.0', '65535.65535.65535.65535')
    $fileRulesElem = $xml.CreateElement('FileRules', $ns)
    foreach ($fr in $fileRules) {
        $frElem = $xml.CreateElement($fr.RuleTypeName, $ns)
        $frElem.SetAttribute('ID', $fileRuleIdMap[$fr.Index])

        if (-not [string]::IsNullOrEmpty($fr.FileName)) {
            $frElem.SetAttribute('FileName', $fr.FileName)
        }
        if ($fr.MinimumFileVersion -notin $versionSentinels) {
            $frElem.SetAttribute('MinimumFileVersion', $fr.MinimumFileVersion)
        }
        if ($null -ne $fr.Hash) {
            $frElem.SetAttribute('Hash', $fr.Hash)
        }

        # V3 extension: MaximumFileVersion + AppIDs attribute
        if ($null -ne $vblocks.V3) {
            $v3ext = $vblocks.V3.FileRuleExtensions[$fr.Index]
            if ($v3ext.MaximumFileVersion -notin $versionSentinels) {
                $frElem.SetAttribute('MaximumFileVersion', $v3ext.MaximumFileVersion)
            }
            # AppIDs: emit as attribute per SiPolicy XSD (AppIdType, single string).
            # Matches E8MVT CIPolicyParser.psm1:3120-3130 semantics — single macro emitted
            # as-is; multiple macros concatenated with no separator (allowed under XSD
            # pattern: ((\$\([a-zA-Z_][a-zA-Z_0-9.]*\))+) which supports adjacent macros).
            if ($null -ne $v3ext.AppIDs -and $v3ext.AppIDs.Count -gt 0) {
                $appIdValue = if ($v3ext.AppIDs.Count -eq 1) {
                    $v3ext.AppIDs[0]
                } else {
                    -join $v3ext.AppIDs
                }
                if (-not [string]::IsNullOrEmpty($appIdValue)) {
                    $frElem.SetAttribute('AppIDs', $appIdValue)
                }
            }
        }

        # V4 extension: InternalName, FileDescription, ProductName
        if ($null -ne $vblocks.V4) {
            $v4ext = $vblocks.V4.FileRuleExtensions[$fr.Index]
            if (-not [string]::IsNullOrEmpty($v4ext.InternalName)) {
                $frElem.SetAttribute('InternalName', $v4ext.InternalName)
            }
            if (-not [string]::IsNullOrEmpty($v4ext.FileDescription)) {
                $frElem.SetAttribute('FileDescription', $v4ext.FileDescription)
            }
            if (-not [string]::IsNullOrEmpty($v4ext.ProductName)) {
                $frElem.SetAttribute('ProductName', $v4ext.ProductName)
            }
        }

        # V5 extension: PackageFamilyName, PackageVersion
        if ($null -ne $vblocks.V5) {
            $v5ext = $vblocks.V5.FileRuleExtensions[$fr.Index]
            if (-not [string]::IsNullOrEmpty($v5ext.PackageFamilyName)) {
                $frElem.SetAttribute('PackageFamilyName', $v5ext.PackageFamilyName)
            }
            if ($v5ext.PackageVersion -notin $versionSentinels) {
                $frElem.SetAttribute('PackageVersion', $v5ext.PackageVersion)
            }
        }

        # V7 extension: FilePath (per-FR string; empty when rule doesn't key on path)
        if ($null -ne $vblocks.V7) {
            $v7ext = $vblocks.V7.FileRuleExtensions[$fr.Index]
            if (-not [string]::IsNullOrEmpty($v7ext.FilePath)) {
                $frElem.SetAttribute('FilePath', $v7ext.FilePath)
            }
        }

        [void]$fileRulesElem.AppendChild($frElem)
    }
    [void]$siPolicy.AppendChild($fileRulesElem)

    # ------ Signers (with V3 SignTimeAfter merged) ------
    $signersElem = $xml.CreateElement('Signers', $ns)
    foreach ($signer in $signers) {
        $signerElem = $xml.CreateElement('Signer', $ns)
        $signerElem.SetAttribute('ID', $signerIdMap[$signer.Index])
        $signerElem.SetAttribute('Name', "Signer $($signer.Index + 1)")

        # CertRoot (always present)
        $certRootElem = $xml.CreateElement('CertRoot', $ns)
        $certRootElem.SetAttribute('Type', $signer.CertRootTypeName)
        $certRootElem.SetAttribute('Value', $signer.CertRootValue)
        [void]$signerElem.AppendChild($certRootElem)

        # CertEKU references
        foreach ($ekuRef in $signer.EKURefs) {
            if ($ekuIdMap.ContainsKey($ekuRef)) {
                $certEkuElem = $xml.CreateElement('CertEKU', $ns)
                $certEkuElem.SetAttribute('ID', $ekuIdMap[$ekuRef])
                [void]$signerElem.AppendChild($certEkuElem)
            }
        }

        # CertPublisher (with optional V3 SignTimeAfter attribute)
        $emitCertPub = (-not [string]::IsNullOrEmpty($signer.CertPublisher))
        $signTimeAfter = $null
        if ($null -ne $vblocks.V3) {
            $v3signer = $vblocks.V3.SignerExtensions[$signer.Index]
            if ($null -ne $v3signer.SignTimeAfter) {
                $signTimeAfter = $v3signer.SignTimeAfter
                $emitCertPub = $true  # force emit if SignTimeAfter is set
            }
        }
        if ($emitCertPub) {
            $certPubElem = $xml.CreateElement('CertPublisher', $ns)
            $certPubElem.SetAttribute('Value', $signer.CertPublisher)
            if ($null -ne $signTimeAfter) {
                $certPubElem.SetAttribute('SignTimeAfter', $signTimeAfter.ToString('o'))
            }
            [void]$signerElem.AppendChild($certPubElem)
        }

        # CertIssuer (only if non-empty)
        if (-not [string]::IsNullOrEmpty($signer.CertIssuer)) {
            $certIssuerElem = $xml.CreateElement('CertIssuer', $ns)
            $certIssuerElem.SetAttribute('Value', $signer.CertIssuer)
            [void]$signerElem.AppendChild($certIssuerElem)
        }

        # CertOemID (only if non-empty)
        if (-not [string]::IsNullOrEmpty($signer.CertOemID)) {
            $certOemElem = $xml.CreateElement('CertOemID', $ns)
            $certOemElem.SetAttribute('Value', $signer.CertOemID)
            [void]$signerElem.AppendChild($certOemElem)
        }

        # FileAttribRef references
        foreach ($faRef in $signer.FileAttribRefs) {
            if ($fileRuleIdMap.ContainsKey($faRef)) {
                $faRefElem = $xml.CreateElement('FileAttribRef', $ns)
                $faRefElem.SetAttribute('RuleID', $fileRuleIdMap[$faRef])
                [void]$signerElem.AppendChild($faRefElem)
            }
        }

        [void]$signersElem.AppendChild($signerElem)
    }
    [void]$siPolicy.AppendChild($signersElem)

    # ------ SigningScenarios ------
    # SigningScenario IDs must match the XSD SigningScenarioIDType pattern
    # `ID_SIGNINGSCENARIO_[A-Z][_A-Z0-9]*` (cipolicy.xsd line 377) — the suffix MUST start
    # with a capital letter, then uppercase alphanumerics/underscores. Use semantic suffixes
    # for the well-known scenario values (131 = DRIVERS, 12 = USERMODE per WDAC convention)
    # and a `V<value>` letter-prefixed fallback for arbitrary values. A per-base-id seen
    # counter disambiguates the rare case of two scenarios sharing the same value.
    $scenariosElem = $xml.CreateElement('SigningScenarios', $ns)
    $scenarioIdSeen = @{}
    for ($si = 0; $si -lt $scenarios.Count; $si++) {
        $scenario = $scenarios[$si]
        $scenarioElem = $xml.CreateElement('SigningScenario', $ns)

        $scenarioIdBase = switch ($scenario.ScenarioValue) {
            131     { 'DRIVERS' }
            12      { 'USERMODE' }
            default { "V$($scenario.ScenarioValue)" }
        }
        if ($scenarioIdSeen.ContainsKey($scenarioIdBase)) {
            $scenarioIdSeen[$scenarioIdBase]++
            $scenarioIdSuffix = "${scenarioIdBase}_$($scenarioIdSeen[$scenarioIdBase])"
        }
        else {
            $scenarioIdSeen[$scenarioIdBase] = 1
            $scenarioIdSuffix = $scenarioIdBase
        }
        $scenarioElem.SetAttribute('ID', "ID_SIGNINGSCENARIO_$scenarioIdSuffix")
        $scenarioElem.SetAttribute('Value', $scenario.ScenarioValue.ToString())

        $scenarioFriendly = switch ($scenario.ScenarioValue) {
            131     { 'Driver Mode' }
            12      { 'User Mode' }
            default { "Scenario $($scenario.ScenarioValue)" }
        }
        $scenarioElem.SetAttribute('FriendlyName', $scenarioFriendly)

        if ($scenario.MinimumHashAlgorithm -gt 0) {
            $scenarioElem.SetAttribute('MinimumHashAlgorithm', $scenario.MinimumHashAlgorithm.ToString())
        }

        foreach ($catName in @('ProductSigners', 'TestSigners', 'TestSigningSigners')) {
            $cat = $scenario.Categories[$catName]
            $catElem = $xml.CreateElement($catName, $ns)

            # AllowedSigners
            if ($cat.AllowedSigners.Count -gt 0) {
                $allowedElem = $xml.CreateElement('AllowedSigners', $ns)
                foreach ($as in $cat.AllowedSigners) {
                    if ($signerIdMap.ContainsKey($as.SignerIndex)) {
                        $asElem = $xml.CreateElement('AllowedSigner', $ns)
                        $asElem.SetAttribute('SignerId', $signerIdMap[$as.SignerIndex])
                        foreach ($excDeny in $as.ExceptDenyRules) {
                            if ($fileRuleIdMap.ContainsKey($excDeny)) {
                                $excElem = $xml.CreateElement('ExceptDenyRule', $ns)
                                $excElem.SetAttribute('DenyRuleID', $fileRuleIdMap[$excDeny])
                                [void]$asElem.AppendChild($excElem)
                            }
                        }
                        [void]$allowedElem.AppendChild($asElem)
                    }
                }
                [void]$catElem.AppendChild($allowedElem)
            }

            # DeniedSigners
            if ($cat.DeniedSigners.Count -gt 0) {
                $deniedElem = $xml.CreateElement('DeniedSigners', $ns)
                foreach ($ds in $cat.DeniedSigners) {
                    if ($signerIdMap.ContainsKey($ds.SignerIndex)) {
                        $dsElem = $xml.CreateElement('DeniedSigner', $ns)
                        $dsElem.SetAttribute('SignerId', $signerIdMap[$ds.SignerIndex])
                        foreach ($excAllow in $ds.ExceptAllowRules) {
                            if ($fileRuleIdMap.ContainsKey($excAllow)) {
                                $excElem = $xml.CreateElement('ExceptAllowRule', $ns)
                                $excElem.SetAttribute('AllowRuleID', $fileRuleIdMap[$excAllow])
                                [void]$dsElem.AppendChild($excElem)
                            }
                        }
                        [void]$deniedElem.AppendChild($dsElem)
                    }
                }
                [void]$catElem.AppendChild($deniedElem)
            }

            # FileRulesRef
            if ($cat.FileRulesRefs.Count -gt 0) {
                $frRefElem = $xml.CreateElement('FileRulesRef', $ns)
                foreach ($frRef in $cat.FileRulesRefs) {
                    if ($fileRuleIdMap.ContainsKey($frRef)) {
                        $frRefItem = $xml.CreateElement('FileRuleRef', $ns)
                        $frRefItem.SetAttribute('RuleID', $fileRuleIdMap[$frRef])
                        [void]$frRefElem.AppendChild($frRefItem)
                    }
                }
                [void]$catElem.AppendChild($frRefElem)
            }

            [void]$scenarioElem.AppendChild($catElem)
        }

        [void]$scenariosElem.AppendChild($scenarioElem)
    }
    [void]$siPolicy.AppendChild($scenariosElem)

    # ------ UpdatePolicySigners ------
    $updateSignersElem = $xml.CreateElement('UpdatePolicySigners', $ns)
    foreach ($idx in $updateSignerIndices) {
        if ($signerIdMap.ContainsKey($idx)) {
            $upsElem = $xml.CreateElement('UpdatePolicySigner', $ns)
            $upsElem.SetAttribute('SignerId', $signerIdMap[$idx])
            [void]$updateSignersElem.AppendChild($upsElem)
        }
    }
    [void]$siPolicy.AppendChild($updateSignersElem)

    # ------ CiSigners ------
    $ciSignersElem = $xml.CreateElement('CiSigners', $ns)
    foreach ($idx in $ciSignerIndices) {
        if ($signerIdMap.ContainsKey($idx)) {
            $cisElem = $xml.CreateElement('CiSigner', $ns)
            $cisElem.SetAttribute('SignerId', $signerIdMap[$idx])
            [void]$ciSignersElem.AppendChild($cisElem)
        }
    }
    [void]$siPolicy.AppendChild($ciSignersElem)

    # ------ SupplementalPolicySigners (V6 — base policies authorising supplementals) ------
    # XSD declares <SupplementalPolicySigners> as an optional top-level SiPolicy child element
    # (cipolicy.xsd line 924). The V6 block carries the signer indices per E8MVT canonical
    # reading. Base policies typically carry N >= 1; supplemental policies carry 0 indices.
    if ($null -ne $vblocks.V6 -and $vblocks.V6.SupplementalSignerCount -gt 0) {
        $suppSignersElem = $xml.CreateElement('SupplementalPolicySigners', $ns)
        foreach ($idx in $vblocks.V6.SupplementalSignerIndices) {
            if ($signerIdMap.ContainsKey([int]$idx)) {
                $suppSignerElem = $xml.CreateElement('SupplementalPolicySigner', $ns)
                $suppSignerElem.SetAttribute('SignerId', $signerIdMap[[int]$idx])
                [void]$suppSignersElem.AppendChild($suppSignerElem)
            }
        }
        [void]$siPolicy.AppendChild($suppSignersElem)
    }

    # ------ HvciOptions ------
    $hvciElem = $xml.CreateElement('HvciOptions', $ns)
    $hvciElem.InnerText = $hvciOptions.ToString()
    [void]$siPolicy.AppendChild($hvciElem)

    # ------ Settings ------
    if ($settings.Count -gt 0) {
        $settingsElem = $xml.CreateElement('Settings', $ns)
        foreach ($setting in $settings) {
            $settingElem = $xml.CreateElement('Setting', $ns)
            $settingElem.SetAttribute('Provider', $setting.Provider)
            $settingElem.SetAttribute('Key', $setting.Key)
            $settingElem.SetAttribute('ValueName', $setting.ValueName)

            $valueElem = $xml.CreateElement('Value', $ns)

            switch ($setting.ValueTypeName) {
                'Boolean' {
                    $childElem = $xml.CreateElement('Boolean', $ns)
                    $childElem.InnerText = if ($setting.Value) { 'true' } else { 'false' }
                    [void]$valueElem.AppendChild($childElem)
                }
                'DWord' {
                    $childElem = $xml.CreateElement('DWord', $ns)
                    $childElem.InnerText = $setting.Value.ToString()
                    [void]$valueElem.AppendChild($childElem)
                }
                'Binary' {
                    $childElem = $xml.CreateElement('Binary', $ns)
                    if ($setting.Value.Length -gt 0) {
                        $childElem.InnerText = ($setting.Value | ForEach-Object { $_.ToString('X2') }) -join ''
                    }
                    [void]$valueElem.AppendChild($childElem)
                }
                'String' {
                    $childElem = $xml.CreateElement('String', $ns)
                    $childElem.InnerText = $setting.Value
                    [void]$valueElem.AppendChild($childElem)
                }
            }

            [void]$settingElem.AppendChild($valueElem)
            [void]$settingsElem.AppendChild($settingElem)
        }
        [void]$siPolicy.AppendChild($settingsElem)
    }

    return $xml
}
