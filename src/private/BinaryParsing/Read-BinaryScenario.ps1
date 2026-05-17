function Read-BinaryScenario {
    <#
    .SYNOPSIS
        Reads Signing Scenario entries from the CI policy binary body.

    .DESCRIPTION
        Each Signing Scenario entry:
          [4 bytes: ScenarioValue (uint32 & 0xFF) — 131=Drivers, 12=UserMode]
          [4 bytes: InheritedScenario count]
          [N x 4 bytes: InheritedScenario indices]
          [4 bytes: MinimumHashAlgorithm (uint16 from uint32)]
          [3 x Signer category (Product, Test, TestSigning), each:]
            [4 bytes: AllowedSigner count]
            [Per signer: index(4) + ExceptDenyRule count(4) + indices(N x 4)]
            [4 bytes: DeniedSigner count]
            [Per signer: index(4) + ExceptAllowRule count(4) + indices(N x 4)]
            [4 bytes: FileRulesRef count]
            [N x 4 bytes: FileRulesRef indices]

        FriendlyName is NOT stored in binary — it is discarded during compilation.

    .PARAMETER Reader
        BinaryReader positioned at the start of the Signing Scenarios section.

    .PARAMETER Count
        Number of Signing Scenario entries to read (from header offset 0x34).

    .OUTPUTS
        PSCustomObject[] — array of scenario objects with nested signer categories.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.BinaryReader]$Reader,

        [Parameter(Mandatory)]
        [int]$Count
    )

    $categoryNames = @('ProductSigners', 'TestSigners', 'TestSigningSigners')
    $scenarios = [System.Collections.Generic.List[PSCustomObject]]::new($Count)

    for ($i = 0; $i -lt $Count; $i++) {
        $scenarioValue = $Reader.ReadUInt32() -band 0xFF  # 131=Drivers, 12=UserMode

        $inheritedCount = [int]$Reader.ReadUInt32()
        $inheritedScenarios = @(for ($j = 0; $j -lt $inheritedCount; $j++) {
            $Reader.ReadInt32()
        })

        $minHashAlgorithm = $Reader.ReadUInt32() -band 0xFFFF  # uint16 from uint32

        $categories = [ordered]@{}

        for ($cat = 0; $cat -lt 3; $cat++) {
            $catName = $categoryNames[$cat]

            # Allowed signers
            $allowedCount = [int]$Reader.ReadUInt32()
            $allowedSigners = [System.Collections.Generic.List[PSCustomObject]]::new()
            for ($j = 0; $j -lt $allowedCount; $j++) {
                $signerIndex = $Reader.ReadInt32()
                $exceptDenyCount = [int]$Reader.ReadUInt32()
                $exceptDenyRules = @(for ($k = 0; $k -lt $exceptDenyCount; $k++) {
                    $Reader.ReadInt32()
                })
                $allowedSigners.Add([PSCustomObject]@{
                    SignerIndex     = $signerIndex
                    ExceptDenyRules = $exceptDenyRules
                })
            }

            # Denied signers
            $deniedCount = [int]$Reader.ReadUInt32()
            $deniedSigners = [System.Collections.Generic.List[PSCustomObject]]::new()
            for ($j = 0; $j -lt $deniedCount; $j++) {
                $signerIndex = $Reader.ReadInt32()
                $exceptAllowCount = [int]$Reader.ReadUInt32()
                $exceptAllowRules = @(for ($k = 0; $k -lt $exceptAllowCount; $k++) {
                    $Reader.ReadInt32()
                })
                $deniedSigners.Add([PSCustomObject]@{
                    SignerIndex      = $signerIndex
                    ExceptAllowRules = $exceptAllowRules
                })
            }

            # FileRulesRef indices
            $fileRulesRefCount = [int]$Reader.ReadUInt32()
            $fileRulesRefs = @(for ($j = 0; $j -lt $fileRulesRefCount; $j++) {
                $Reader.ReadInt32()
            })

            $categories[$catName] = [PSCustomObject]@{
                AllowedSigners = $allowedSigners.ToArray()
                DeniedSigners  = $deniedSigners.ToArray()
                FileRulesRefs  = $fileRulesRefs
            }
        }

        $scenarios.Add([PSCustomObject]@{
            Index                = $i
            ScenarioValue        = [int]$scenarioValue
            InheritedScenarios   = $inheritedScenarios
            MinimumHashAlgorithm = [int]$minHashAlgorithm
            Categories           = $categories
        })
    }

    return , $scenarios.ToArray()
}
