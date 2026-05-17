function Get-WDACSecurityPosture {
    <#
    .SYNOPSIS
        Aggregates all WDAC security telemetry into a unified security posture object.

    .DESCRIPTION
        Calls all 12 existing Get-*/Test-* functions and returns a single PSCustomObject
        organised into semantic domains: Platform, SecurityPosture, ApplicationControl,
        and Verdicts.

        Overlapping fields are deduplicated using tiered authority:
        CPUID (tier 1) > NtApi (tier 2) > WMI (tier 3) > Registry (tier 4) > Heuristic (tier 5)

        If any source function fails, its fields become $null in the output. The posture
        object is always returned with whatever data succeeded.

    .PARAMETER HoursBack
        How many hours of event log history to include. Defaults to 24.

    .PARAMETER MaxEvents
        Maximum CI event log entries to return. Defaults to 25.

    .EXAMPLE
        Get-WDACSecurityPosture

        Returns the full aggregated security posture for the local endpoint.

    .EXAMPLE
        Get-WDACSecurityPosture -HoursBack 48 -MaxEvents 100

        Returns posture with 48 hours of event history and up to 100 events.

    .EXAMPLE
        $posture = Get-WDACSecurityPosture
        $posture.SecurityPosture.BootChain

        Returns just the boot chain security assessment.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 8760)]
        [int]$HoursBack = 24,

        [ValidateRange(1, 1000)]
        [int]$MaxEvents = 25
    )

    # ---------------------------------------------------------------------------
    # Data collection — call all 12 source functions with per-function isolation
    # ---------------------------------------------------------------------------

    # Telemetry tier 1 — CPUID-based (highest authority for hardware facts)
    try { $memEnc = Get-WDACMemoryEncryption }
    catch { $memEnc = $null; Write-Verbose "MemoryEncryption failed: $_" }

    try { $hypervisor = Get-WDACHypervisorDetail }
    catch { $hypervisor = $null; Write-Verbose "HypervisorDetail failed: $_" }

    # Telemetry tier 2 — NtApi-based
    try { $devSec = Get-WDACDeviceSecurity }
    catch { $devSec = $null; Write-Verbose "DeviceSecurity failed: $_" }

    try { $specMit = Get-WDACSpeculationMitigation }
    catch { $specMit = $null; Write-Verbose "SpeculationMitigation failed: $_" }

    # Telemetry tier 2-4 — Win32 API / Registry
    try { $exploit = Get-WDACExploitProtection }
    catch { $exploit = $null; Write-Verbose "ExploitProtection failed: $_" }

    # Telemetry tier 3 — WMI-based
    try { $firmware = Get-WDACFirmwareSecurity }
    catch { $firmware = $null; Write-Verbose "FirmwareSecurity failed: $_" }

    try { $defender = Get-WDACDefenderStatus }
    catch { $defender = $null; Write-Verbose "DefenderStatus failed: $_" }

    # Policy functions — NtApi / WLDP API
    try { $enforcement = Test-WDACEnforcement }
    catch { $enforcement = $null; Write-Verbose "WDACEnforcement failed: $_" }

    try { $policies = Get-WDACPolicy }
    catch { $policies = $null; Write-Verbose "WDACPolicy failed: $_" }

    try { $policyStatus = Get-WDACPolicyStatus }
    catch { $policyStatus = $null; Write-Verbose "WDACPolicyStatus failed: $_" }

    # Token management
    try { $tokens = Get-WDACToken }
    catch { $tokens = $null; Write-Verbose "WDACToken failed: $_" }

    # Event log
    try { $events = Get-WDACEventLog -HoursBack $HoursBack -MaxEvents $MaxEvents }
    catch { $events = $null; Write-Verbose "WDACEventLog failed: $_" }

    # ---------------------------------------------------------------------------
    # Policy computed fields
    # ---------------------------------------------------------------------------
    $policyItems = if ($policies) { @($policies) } else { @() }
    $enforcedCount = @($policyItems | Where-Object { $_.EnforcementMode -eq 'Enforced' }).Count
    $auditCount    = @($policyItems | Where-Object { $_.EnforcementMode -eq 'Audit' }).Count
    $unknownCount  = @($policyItems | Where-Object { $_.EnforcementMode -eq 'Unknown' }).Count
    $basePolicyIds = @($policyItems | ForEach-Object { $_.BasePolicyId } | Select-Object -Unique)

    # ---------------------------------------------------------------------------
    # Policy hierarchy — group supplementals under their base policies
    # ---------------------------------------------------------------------------
    $basePolicyItems  = @($policyItems | Where-Object { -not $_.IsSupplemental })
    $supplementalItems = @($policyItems | Where-Object { $_.IsSupplemental })

    $policyHierarchy = @($basePolicyItems | ForEach-Object {
        $base = $_
        $children = @($supplementalItems | Where-Object { $_.BasePolicyId -eq $base.PolicyId })
        $allModes = @($base.EnforcementMode) + @($children | ForEach-Object { $_.EnforcementMode })
        $uniqueModes = @($allModes | Select-Object -Unique)

        [PSCustomObject]@{
            PolicyId              = $base.PolicyId
            FriendlyName          = $base.FriendlyName
            EnforcementMode       = $base.EnforcementMode
            PolicyType            = $base.PolicyType
            Version               = $base.Version
            Supplements           = @($children | ForEach-Object {
                [PSCustomObject]@{
                    PolicyId        = $_.PolicyId
                    FriendlyName    = $_.FriendlyName
                    EnforcementMode = $_.EnforcementMode
                    Version         = $_.Version
                }
            })
            SupplementCount       = $children.Count
            EnforcementConsistent = ($uniqueModes.Count -le 1)
        }
    })

    # Orphaned supplementals — base policy not deployed on this endpoint
    $deployedBaseIds = @($basePolicyItems | ForEach-Object { $_.PolicyId })
    $orphanedSupplementals = @($supplementalItems | Where-Object {
        $deployedBaseIds -notcontains $_.BasePolicyId
    } | ForEach-Object {
        [PSCustomObject]@{
            PolicyId        = $_.PolicyId
            FriendlyName    = $_.FriendlyName
            EnforcementMode = $_.EnforcementMode
            BasePolicyId    = $_.BasePolicyId
            Version         = $_.Version
        }
    })

    # Null guards — pipeline can yield $null instead of @() on PS 5.1
    if ($null -eq $policyHierarchy)       { $policyHierarchy = @() }
    if ($null -eq $orphanedSupplementals) { $orphanedSupplementals = @() }

    # ---------------------------------------------------------------------------
    # Build aggregated posture object
    #
    # Tiered authority deduplication (7 overlapping fields):
    #   VBSStatus         ← DeviceSecurity (NtApi, tier 2)  over HypervisorDetail
    #   HVCIRunning       ← DeviceSecurity (NtApi, tier 2)  over HypervisorDetail
    #   SecureBootEnabled ← DeviceSecurity (NtApi, tier 2)  over PolicyStatus
    #   UEFIEnabled       ← DeviceSecurity (NtApi, tier 2)  over FirmwareSecurity
    #   HVCIUMCIEnabled   ← DeviceSecurity (NtApi, tier 2)  over PolicyStatus
    #   EnforcementMode   ← WDACEnforcement (NtApi, tier 2) over PolicyStatus
    #   SystemIdentity    ← FirmwareSecurity (WMI direct BIOS query, tier 3)
    # ---------------------------------------------------------------------------
    [PSCustomObject]@{

        # --- Platform identity ---
        Platform = [PSCustomObject]@{
            CPUVendor          = $memEnc.CPUVendor
            CPUName            = $memEnc.CPUName
            SystemManufacturer = $firmware.SystemManufacturer
            SystemModel        = $firmware.SystemProductName
            BIOSVendor         = $firmware.BIOSVendor
            BIOSVersion        = $firmware.BIOSVersion
            BIOSReleaseDate    = $firmware.BIOSReleaseDate
            SMBIOSVersion      = $firmware.SMBIOSVersion
            SerialNumber       = $firmware.SerialNumber
        }

        # --- Security posture (6 semantic domains) ---
        SecurityPosture = [PSCustomObject]@{

            BootChain = [PSCustomObject]@{
                SecureBootEnabled     = $devSec.SecureBootEnabled
                SecureBootCapable     = $devSec.SecureBootCapable
                UEFIEnabled           = $devSec.UEFIEnabled
                FirmwareType          = $firmware.FirmwareType
                SecureLaunchSupported = $firmware.SecureLaunchSupported
            }

            HardwareSecurity = [PSCustomObject]@{
                TPMPresent           = $devSec.TPMPresent
                TPMReady             = $devSec.TPMReady
                TPMVersion           = $devSec.TPMVersion
                DMAProtectionEnabled = $devSec.DMAProtectionEnabled
                MemoryEncryption     = if ($memEnc) {
                    [PSCustomObject]@{
                        SEVSupported         = $memEnc.SEVSupported
                        SEVEnabled           = $memEnc.SEVEnabled
                        SEVESSupported       = $memEnc.SEVESSupported
                        SEVSNPSupported      = $memEnc.SEVSNPSupported
                        TMESupported         = $memEnc.TMESupported
                        TMEEnabled           = $memEnc.TMEEnabled
                        MKTMESupported       = $memEnc.MKTMESupported
                        MKTMEKeyCount        = $memEnc.MKTMEKeyCount
                        EncryptionAlgorithm  = $memEnc.EncryptionAlgorithm
                        DetectionLimitations = $memEnc.DetectionLimitations
                    }
                } else { $null }
            }

            Virtualisation = [PSCustomObject]@{
                VBSStatus                   = $devSec.VBSStatus
                HVCIRunning                 = $devSec.HVCIRunning
                HVCIUMCIEnabled             = $devSec.HVCIUMCIEnabled
                CredentialGuardRunning      = $devSec.CredentialGuardRunning
                UEFILockEnabled             = $devSec.UEFILockEnabled
                KernelStackProtection       = $devSec.KernelStackProtection
                HypervisorPresent           = $hypervisor.HypervisorPresent
                HypervisorVendor            = $hypervisor.HypervisorVendor
                HypervisorInterfaceId       = $hypervisor.HypervisorInterfaceId
                NestedVirtualizationEnabled = $hypervisor.NestedVirtualizationEnabled
                SecurityServicesConfigured  = $devSec.SecurityServicesConfigured
                SecurityServicesRunning     = $devSec.SecurityServicesRunning
            }

            CPUMitigations = if ($specMit) {
                [PSCustomObject]@{
                    SpectreV2BpbEnabled       = $specMit.SpectreV2BpbEnabled
                    SpectreV2EnhancedIBRS     = $specMit.SpectreV2EnhancedIBRS
                    SpectreV2RetpolineEnabled = $specMit.SpectreV2RetpolineEnabled
                    IbrsPresent               = $specMit.IbrsPresent
                    StibpPresent              = $specMit.StibpPresent
                    SpecCtrlEnumerated        = $specMit.SpecCtrlEnumerated
                    MeltdownKvaShadowEnabled  = $specMit.MeltdownKvaShadowEnabled
                    MeltdownKvaShadowRequired = $specMit.MeltdownKvaShadowRequired
                    MeltdownPcidEnabled       = $specMit.MeltdownPcidEnabled
                    SSBDAvailable             = $specMit.SSBDAvailable
                    SSBDEnabledSystemWide     = $specMit.SSBDEnabledSystemWide
                    L1TFFlushSupported        = $specMit.L1TFFlushSupported
                    L1TFFlushEnabled          = $specMit.L1TFFlushEnabled
                    L1TFMitigationPresent     = $specMit.L1TFMitigationPresent
                    MDSHardwareProtected      = $specMit.MDSHardwareProtected
                    MDSMbClearEnabled         = $specMit.MDSMbClearEnabled
                    TAAHardwareProtected      = $specMit.TAAHardwareProtected
                    SmepPresent               = $specMit.SmepPresent
                }
            } else { $null }

            ExploitProtection = if ($exploit) {
                [PSCustomObject]@{
                    DEPPolicy                 = $exploit.DEPPolicy
                    ASLRForceRelocateImages   = $exploit.ASLRForceRelocateImages
                    ASLRBottomUpRandomization = $exploit.ASLRBottomUpRandomization
                    ASLRHighEntropy           = $exploit.ASLRHighEntropy
                    CFGEnabled                = $exploit.CFGEnabled
                    CETUserShadowStack        = $exploit.CETUserShadowStack
                    KernelShadowStackEnabled  = $exploit.KernelShadowStackEnabled
                    StrictHandleCheck         = $exploit.StrictHandleCheck
                    DisableWin32kSystemCalls  = $exploit.DisableWin32kSystemCalls
                    ProcessOverrideCount      = $exploit.ProcessOverrideCount
                    ProcessOverrides          = $exploit.ProcessOverrides
                }
            } else { $null }

            EndpointProtection = if ($defender) {
                [PSCustomObject]@{
                    DefenderPresent                 = $defender.DefenderPresent
                    AMRunningMode                   = $defender.AMRunningMode
                    AMServiceEnabled                = $defender.AMServiceEnabled
                    AntivirusEnabled                = $defender.AntivirusEnabled
                    AntispywareEnabled              = $defender.AntispywareEnabled
                    RealTimeProtectionEnabled       = $defender.RealTimeProtectionEnabled
                    BehaviorMonitorEnabled          = $defender.BehaviorMonitorEnabled
                    IoavProtectionEnabled           = $defender.IoavProtectionEnabled
                    NISEnabled                      = $defender.NISEnabled
                    OnAccessProtectionEnabled       = $defender.OnAccessProtectionEnabled
                    TamperProtectionSource          = $defender.TamperProtectionSource
                    AntivirusSignatureVersion       = $defender.AntivirusSignatureVersion
                    AntivirusSignatureLastUpdated   = $defender.AntivirusSignatureLastUpdated
                    AntispywareSignatureLastUpdated = $defender.AntispywareSignatureLastUpdated
                    QuickScanAge                    = $defender.QuickScanAge
                    FullScanAge                     = $defender.FullScanAge
                    ComputerState                   = $defender.ComputerState
                    DefenderProductStatus           = $defender.DefenderProductStatus
                }
            } else { $null }
        }

        # --- Application Control ---
        ApplicationControl = [PSCustomObject]@{

            Enforcement = [PSCustomObject]@{
                IsEnforced           = $enforcement.IsEnforced
                EnforcementMode      = $enforcement.EnforcementMode
                CodeIntegrityEnabled = $policyStatus.CodeIntegrityEnabled
                UMCIEnabled          = $policyStatus.UMCIEnabled
                PolicyOptions        = $policyStatus.PolicyOptions
            }

            Policies = [PSCustomObject]@{
                TotalCount             = $policyItems.Count
                EnforcedCount          = $enforcedCount
                AuditCount             = $auditCount
                UnknownCount           = $unknownCount
                BasePolicyIds          = $basePolicyIds
                Hierarchy              = $policyHierarchy
                OrphanedSupplementals  = $orphanedSupplementals
                Items                  = $policyItems
            }

            TrustTokens  = $tokens
            RecentEvents = $events
        }

        # --- Verdict stubs (Phase 2 scoring) ---
        Verdicts = [PSCustomObject]@{
            BootChain          = 'NotEvaluated'
            HardwareSecurity   = 'NotEvaluated'
            Virtualisation     = 'NotEvaluated'
            CPUMitigations     = 'NotEvaluated'
            ExploitProtection  = 'NotEvaluated'
            EndpointProtection = 'NotEvaluated'
            ApplicationControl = 'NotEvaluated'
        }
    }
}
