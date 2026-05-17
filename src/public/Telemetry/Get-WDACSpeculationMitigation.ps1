function Get-WDACSpeculationMitigation {
    <#
    .SYNOPSIS
        Queries CPU speculation control mitigations using NT API calls.

    .DESCRIPTION
        Retrieves detailed information about CPU-level speculation vulnerability mitigations
        including Spectre, Meltdown, L1TF, MDS, and TAA protections. Uses direct
        NtQuerySystemInformation API calls to query SystemSpeculationControlInformation
        and SystemKernelVaShadowInformation.

        Returns comprehensive status for:
        - Spectre v2 (Branch Target Injection) - BPB, IBRS, STIBP, Enhanced IBRS, Retpoline
        - Spectre v4 (Speculative Store Bypass) - SSBD
        - Meltdown (Rogue Data Cache Load) - KVA Shadow (KPTI), PCID
        - L1TF (L1 Terminal Fault) - L1D flush, mitigation presence
        - MDS (Microarchitectural Data Sampling) - Hardware protection, MbClear
        - TAA (TSX Asynchronous Abort) - Hardware protection
        - SMEP (Supervisor Mode Execution Prevention)

    .OUTPUTS
        PSCustomObject with properties:
            - SpectreV2BpbEnabled         [bool]     Branch Prediction Barrier enabled
            - SpectreV2EnhancedIBRS       [bool]     Enhanced IBRS (hardware mitigation)
            - SpectreV2RetpolineEnabled   [bool]     Retpoline (software mitigation)
            - IbrsPresent                 [bool]     IBRS MSR available
            - StibpPresent                [bool]     STIBP MSR available
            - MeltdownKvaShadowEnabled    [bool]     Kernel VA Shadow (KPTI) active
            - MeltdownKvaShadowRequired   [bool]     KVA Shadow required for system
            - MeltdownPcidEnabled         [bool]     PCID optimization active
            - SSBDAvailable               [bool]     Speculative Store Bypass Disable available
            - SSBDEnabledSystemWide       [bool]     SSBD enabled system-wide
            - L1TFFlushSupported          [bool]     L1D cache flush supported
            - L1TFFlushEnabled            [bool]     Hypervisor L1D flush enabled
            - L1TFMitigationPresent       [bool]     L1 Terminal Fault mitigation present
            - MDSHardwareProtected        [bool]     MDS hardware-level protection
            - MDSMbClearEnabled           [bool]     MDS MbClear mitigation enabled
            - TAAHardwareProtected        [bool]     TAA hardware-level protection
            - SmepPresent                 [bool]     SMEP feature present
            - SpecCtrlEnumerated          [bool]     Speculation control MSRs enumerated by hardware
            - QuerySuccess                [bool]     All NT API queries succeeded

    .EXAMPLE
        Get-WDACSpeculationMitigation
        Returns full CPU speculation mitigation status.

    .EXAMPLE
        (Get-WDACSpeculationMitigation).SpectreV2EnhancedIBRS
        Check if Enhanced IBRS is active (recommended for modern CPUs).

    .EXAMPLE
        Get-WDACSpeculationMitigation | Format-List
        Display all mitigation properties in list format.

    .EXAMPLE
        $mitig = Get-WDACSpeculationMitigation
        if (-not $mitig.MeltdownKvaShadowEnabled -and $mitig.MeltdownKvaShadowRequired) {
            Write-Warning 'Meltdown mitigation required but not enabled!'
        }

    .NOTES
        Requires: Administrator elevation
        Platform: Windows 10+
    #>
    [CmdletBinding()]
    param()

    if (-not ([System.Management.Automation.PSTypeName]'WDACSpeculationMitigationReader').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class WDACSpeculationMitigationReader
{
    // NtQuerySystemInformation info classes
    private const uint SystemSpeculationControlInformation = 201;  // 0xC9
    private const uint SystemKernelVaShadowInformation = 196;      // 0xC4

    // NTSTATUS codes
    private const uint STATUS_SUCCESS = 0x00000000;

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(
        uint SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        out uint ReturnLength);

    public static void EnsureElevated()
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            var principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException(
                    "This operation requires Administrator elevation. Run PowerShell as Administrator.");
        }
    }

    /// <summary>
    /// Queries SystemSpeculationControlInformation (0xC9) - 8 bytes (two ULONG bitfields)
    /// Returns [flags1, flags2] or [0, 0] on failure
    /// </summary>
    private static uint[] QuerySpeculationControl()
    {
        uint returnLength;
        IntPtr buffer = Marshal.AllocHGlobal(8);

        try
        {
            uint status = NtQuerySystemInformation(
                SystemSpeculationControlInformation,
                buffer, 8, out returnLength);

            if (status == STATUS_SUCCESS && returnLength >= 8)
            {
                uint flags1 = (uint)Marshal.ReadInt32(buffer, 0);
                uint flags2 = (uint)Marshal.ReadInt32(buffer, 4);
                return new uint[] { flags1, flags2 };
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return new uint[] { 0, 0 };
    }

    /// <summary>
    /// Queries SystemKernelVaShadowInformation (0xC4) - 4 bytes (one ULONG bitfield)
    /// Returns flags or 0 on failure
    /// </summary>
    private static uint QueryKernelVaShadow()
    {
        uint returnLength;
        IntPtr buffer = Marshal.AllocHGlobal(4);

        try
        {
            uint status = NtQuerySystemInformation(
                SystemKernelVaShadowInformation,
                buffer, 4, out returnLength);

            if (status == STATUS_SUCCESS && returnLength >= 4)
            {
                return (uint)Marshal.ReadInt32(buffer, 0);
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return 0;
    }

    /// <summary>
    /// Tests if a bit is set in a bitfield
    /// </summary>
    private static bool IsBitSet(uint value, int bit)
    {
        return (value & (1u << bit)) != 0;
    }

    /// <summary>
    /// Queries comprehensive CPU speculation mitigation information.
    /// Returns object[] with 19 boolean values representing all mitigation states.
    /// </summary>
    public static object[] Query()
    {
        EnsureElevated();

        // Query both NT API information classes
        uint[] specControl = QuerySpeculationControl();
        uint kvaShadow = QueryKernelVaShadow();

        uint specFlags1 = specControl[0];
        uint specFlags2 = specControl[1];

        bool querySuccess = (specFlags1 != 0 || specFlags2 != 0) && kvaShadow != 0;

        // Parse SystemSpeculationControlInformation Flags1 (bits 0-31)
        bool bpbEnabled                     = IsBitSet(specFlags1, 0);
        bool specCtrlEnumerated             = IsBitSet(specFlags1, 3);
        bool ibrsPresent                    = IsBitSet(specFlags1, 5);
        bool stibpPresent                   = IsBitSet(specFlags1, 6);
        bool smepPresent                    = IsBitSet(specFlags1, 7);
        bool ssbdAvailable                  = IsBitSet(specFlags1, 8);
        bool ssbdSystemWide                 = IsBitSet(specFlags1, 10);
        bool retpolineEnabled               = IsBitSet(specFlags1, 14);
        bool enhancedIbrs                   = IsBitSet(specFlags1, 16);
        bool hvL1dFlushSupported            = IsBitSet(specFlags1, 17);
        bool hvL1dFlushEnabled              = IsBitSet(specFlags1, 18);

        // Parse SystemSpeculationControlInformation Flags2 (bits 0-31)
        bool mdsHwProtected                 = IsBitSet(specFlags2, 0);
        bool mbClearEnabled                 = IsBitSet(specFlags2, 1);
        bool taaHwProtected                 = IsBitSet(specFlags2, 3);

        // Parse SystemKernelVaShadowInformation (bits 0-31)
        bool kvaShadowEnabled               = IsBitSet(kvaShadow, 0);
        bool kvaShadowPcid                  = IsBitSet(kvaShadow, 2);
        bool kvaShadowRequired              = IsBitSet(kvaShadow, 4);
        bool l1TerminalFaultMitigation      = IsBitSet(kvaShadow, 13);

        // Return all values as object array
        return new object[] {
            bpbEnabled,                     // 0  - SpectreV2BpbEnabled
            enhancedIbrs,                   // 1  - SpectreV2EnhancedIBRS
            retpolineEnabled,               // 2  - SpectreV2RetpolineEnabled
            ibrsPresent,                    // 3  - IbrsPresent
            stibpPresent,                   // 4  - StibpPresent
            kvaShadowEnabled,               // 5  - MeltdownKvaShadowEnabled
            kvaShadowRequired,              // 6  - MeltdownKvaShadowRequired
            kvaShadowPcid,                  // 7  - MeltdownPcidEnabled
            ssbdAvailable,                  // 8  - SSBDAvailable
            ssbdSystemWide,                 // 9  - SSBDEnabledSystemWide
            hvL1dFlushSupported,            // 10 - L1TFFlushSupported
            hvL1dFlushEnabled,              // 11 - L1TFFlushEnabled
            l1TerminalFaultMitigation,      // 12 - L1TFMitigationPresent
            mdsHwProtected,                 // 13 - MDSHardwareProtected
            mbClearEnabled,                 // 14 - MDSMbClearEnabled
            taaHwProtected,                 // 15 - TAAHardwareProtected
            smepPresent,                    // 16 - SmepPresent
            specCtrlEnumerated,             // 17 - SpecCtrlEnumerated
            querySuccess                    // 18 - QuerySuccess
        };
    }
}
'@ -ReferencedAssemblies $CIRefBase
    }

    Write-Verbose 'Querying CPU speculation control mitigations...'

    $result = [WDACSpeculationMitigationReader]::Query()

    [PSCustomObject]@{
        SpectreV2BpbEnabled       = [bool]$result[0]
        SpectreV2EnhancedIBRS     = [bool]$result[1]
        SpectreV2RetpolineEnabled = [bool]$result[2]
        IbrsPresent               = [bool]$result[3]
        StibpPresent              = [bool]$result[4]
        MeltdownKvaShadowEnabled  = [bool]$result[5]
        MeltdownKvaShadowRequired = [bool]$result[6]
        MeltdownPcidEnabled       = [bool]$result[7]
        SSBDAvailable             = [bool]$result[8]
        SSBDEnabledSystemWide     = [bool]$result[9]
        L1TFFlushSupported        = [bool]$result[10]
        L1TFFlushEnabled          = [bool]$result[11]
        L1TFMitigationPresent     = [bool]$result[12]
        MDSHardwareProtected      = [bool]$result[13]
        MDSMbClearEnabled         = [bool]$result[14]
        TAAHardwareProtected      = [bool]$result[15]
        SmepPresent               = [bool]$result[16]
        SpecCtrlEnumerated        = [bool]$result[17]
        QuerySuccess              = [bool]$result[18]
    }
}
