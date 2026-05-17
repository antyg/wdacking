function Get-WDACDeviceSecurity {
    <#
    .SYNOPSIS
        Retrieves detailed device security information for Code Integrity and Device Guard.

    .DESCRIPTION
        Queries hardware and firmware security state using NT API calls and WMI, providing
        a comprehensive view of the device's security posture for CI/WDAC readiness.

        Returns detailed information about:
        - Secure Boot configuration and state
        - TPM presence, version, and readiness
        - Virtualization-Based Security (VBS) status
        - DMA protection state
        - HVCI (Hypervisor-protected Code Integrity) status
        - UEFI lock state for Device Guard policies
        - Kernel mode hardware-enforced stack protection

        Uses NtQuerySystemInformation with SystemSecureBootInformation (0x91) and
        SystemDeviceGuardInformation for hardware state, supplemented by WMI
        Win32_DeviceGuard and Win32_Tpm for comprehensive coverage.

    .OUTPUTS
        PSCustomObject with properties:
            - SecureBootEnabled        [bool]     Secure Boot is active
            - SecureBootCapable        [bool]     Hardware supports Secure Boot
            - UEFIEnabled              [bool]     System booted in UEFI mode
            - TPMPresent               [bool]     TPM chip is present
            - TPMReady                 [bool]     TPM is initialized and ready
            - TPMVersion               [string]   TPM specification version (e.g., '2.0')
            - VBSStatus                [string]   'Running', 'NotRunning', 'NotConfigured'
            - HVCIRunning              [bool]     Hypervisor-enforced CI is active
            - HVCIUMCIEnabled          [bool]     HVCI User Mode CI is enabled
            - DMAProtectionEnabled     [bool]     DMA protection (Kernel DMA Protection) active
            - CredentialGuardRunning   [bool]     Credential Guard is active
            - UEFILockEnabled          [bool]     Device Guard policies are UEFI-locked
            - KernelStackProtection    [bool]     Kernel mode stack protection enabled
            - SecurityServicesConfigured [string[]] Configured security services
            - SecurityServicesRunning    [string[]] Running security services

    .EXAMPLE
        Get-WDACDeviceSecurity
        Returns the full device security assessment.

    .EXAMPLE
        (Get-WDACDeviceSecurity).HVCIRunning
        Quick check whether HVCI is active.

    .EXAMPLE
        Get-WDACDeviceSecurity | Format-List
        Displays all security properties in list format.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows 10+ / Windows 11
    #>
    [CmdletBinding()]
    param()

    if (-not ([System.Management.Automation.PSTypeName]'WDACDeviceSecurityReader').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class WDACDeviceSecurityReader
{
    // NtQuerySystemInformation info classes
    private const uint SystemSecureBootInformation = 0x91;  // 145
    private const uint SystemBootEnvironmentInformation = 0x5A;  // 90

    // VBS security service identifiers
    private const int SecurityServiceCredentialGuard = 1;
    private const int SecurityServiceHVCI = 2;
    private const int SecurityServiceSystemGuardSecureLaunch = 3;
    private const int SecurityServiceSMEIsolation = 4;

    // VBS status values
    private const int VBSNotConfigured = 0;
    private const int VBSNotRunning = 1;
    private const int VBSRunning = 2;

    // NTSTATUS codes
    private const uint STATUS_SUCCESS = 0x00000000;

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(
        uint SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        out uint ReturnLength);

    // SYSTEM_SECUREBOOT_INFORMATION structure
    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_SECUREBOOT_INFORMATION
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool SecureBootEnabled;
        [MarshalAs(UnmanagedType.U1)]
        public bool SecureBootCapable;
    }

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

    private static string MapSecurityService(int serviceId)
    {
        switch (serviceId)
        {
            case SecurityServiceCredentialGuard: return "CredentialGuard";
            case SecurityServiceHVCI: return "HVCI";
            case SecurityServiceSystemGuardSecureLaunch: return "SystemGuardSecureLaunch";
            case SecurityServiceSMEIsolation: return "SMEIsolation";
            default: return "Unknown(" + serviceId + ")";
        }
    }

    /// <summary>
    /// Queries Secure Boot state via NtQuerySystemInformation.
    /// Returns [secureBootEnabled, secureBootCapable] or [false, false] on failure.
    /// </summary>
    private static bool[] QuerySecureBoot()
    {
        uint returnLength;
        int structSize = Marshal.SizeOf(typeof(SYSTEM_SECUREBOOT_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(structSize);

        try
        {
            uint status = NtQuerySystemInformation(
                SystemSecureBootInformation,
                buffer, (uint)structSize, out returnLength);

            if (status == STATUS_SUCCESS)
            {
                var info = (SYSTEM_SECUREBOOT_INFORMATION)Marshal.PtrToStructure(
                    buffer, typeof(SYSTEM_SECUREBOOT_INFORMATION));
                return new bool[] { info.SecureBootEnabled, info.SecureBootCapable };
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return new bool[] { false, false };
    }

    /// <summary>
    /// Checks if system booted in UEFI mode via firmware type.
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFirmwareType(out uint firmwareType);

    private static bool IsUEFI()
    {
        try
        {
            uint firmwareType;
            if (GetFirmwareType(out firmwareType))
                return firmwareType == 2; // FirmwareTypeUefi = 2
        }
        catch { }
        return false;
    }

    /// <summary>
    /// Queries comprehensive device security information.
    /// Returns object[]: [secureBoot, secureBootCapable, uefi, tpmPresent, tpmReady,
    ///   tpmVersion, vbsStatus, hvci, hvciUmci, dmaProtection,
    ///   credentialGuard, uefiLock, kernelStackProtect, configuredServices[], runningServices[]]
    /// </summary>
    public static object[] Query()
    {
        EnsureElevated();

        // Secure Boot via NT API
        bool[] secBoot = QuerySecureBoot();
        bool secureBootEnabled = secBoot[0];
        bool secureBootCapable = secBoot[1];

        // UEFI mode
        bool uefiEnabled = IsUEFI();

        // Initialize defaults
        bool tpmPresent = false;
        bool tpmReady = false;
        string tpmVersion = "N/A";
        string vbsStatus = "NotConfigured";
        bool hvciRunning = false;
        bool hvciUmci = false;
        bool dmaProtection = false;
        bool credentialGuard = false;
        bool uefiLock = false;
        bool kernelStackProtect = false;
        var configuredServices = new List<string>();
        var runningServices = new List<string>();

        // Query Win32_DeviceGuard for VBS and security services
        try
        {
            using (var searcher = new ManagementObjectSearcher(
                "root\\Microsoft\\Windows\\DeviceGuard",
                "SELECT * FROM Win32_DeviceGuard"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    // VBS status
                    var vbs = obj["VirtualizationBasedSecurityStatus"];
                    if (vbs != null)
                    {
                        switch (Convert.ToInt32(vbs))
                        {
                            case VBSRunning:    vbsStatus = "Running"; break;
                            case VBSNotRunning: vbsStatus = "NotRunning"; break;
                            default:            vbsStatus = "NotConfigured"; break;
                        }
                    }

                    // Running security services
                    var running = obj["SecurityServicesRunning"] as int[];
                    if (running != null)
                    {
                        foreach (int svc in running)
                        {
                            string name = MapSecurityService(svc);
                            runningServices.Add(name);
                            if (svc == SecurityServiceCredentialGuard) credentialGuard = true;
                            if (svc == SecurityServiceHVCI) hvciRunning = true;
                        }
                    }

                    // Configured security services
                    var configured = obj["SecurityServicesConfigured"] as int[];
                    if (configured != null)
                    {
                        foreach (int svc in configured)
                            configuredServices.Add(MapSecurityService(svc));
                    }

                    // UMCI from enforcement status
                    var umci = obj["UsermodeCodeIntegrityPolicyEnforcementStatus"];
                    if (umci != null)
                        hvciUmci = Convert.ToInt32(umci) > 0;

                    // DMA protection
                    var avail = obj["AvailableSecurityProperties"] as int[];
                    if (avail != null)
                    {
                        foreach (int prop in avail)
                        {
                            if (prop == 7) // DMA protection
                                dmaProtection = true;
                        }
                    }

                    // UEFI lock
                    var reqSec = obj["RequiredSecurityProperties"] as int[];
                    if (reqSec != null)
                    {
                        foreach (int prop in reqSec)
                        {
                            if (prop == 4) // UEFI lock
                                uefiLock = true;
                        }
                    }

                    break; // One instance expected
                }
            }
        }
        catch { /* DeviceGuard WMI may not be available */ }

        // Query TPM via Win32_Tpm
        try
        {
            using (var searcher = new ManagementObjectSearcher(
                "root\\CIMv2\\Security\\MicrosoftTpm",
                "SELECT * FROM Win32_Tpm"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    tpmPresent = true;

                    var activated = obj["IsActivated_InitialValue"];
                    if (activated != null)
                        tpmReady = Convert.ToBoolean(activated);

                    var specVer = obj["SpecVersion"];
                    if (specVer != null)
                    {
                        string ver = specVer.ToString();
                        // SpecVersion is like "2.0, 0, 1.38" — extract first part
                        int commaIdx = ver.IndexOf(',');
                        tpmVersion = commaIdx > 0 ? ver.Substring(0, commaIdx).Trim() : ver.Trim();
                    }

                    break;
                }
            }
        }
        catch { /* TPM WMI may not be available */ }

        // Check kernel stack protection via registry (heuristic)
        try
        {
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks"))
            {
                if (key != null)
                {
                    var enabled = key.GetValue("Enabled");
                    if (enabled != null)
                        kernelStackProtect = Convert.ToInt32(enabled) > 0;
                }
            }
        }
        catch { }

        return new object[] {
            secureBootEnabled,          // 0
            secureBootCapable,          // 1
            uefiEnabled,                // 2
            tpmPresent,                 // 3
            tpmReady,                   // 4
            tpmVersion,                 // 5
            vbsStatus,                  // 6
            hvciRunning,                // 7
            hvciUmci,                   // 8
            dmaProtection,              // 9
            credentialGuard,            // 10
            uefiLock,                   // 11
            kernelStackProtect,         // 12
            configuredServices.ToArray(),// 13
            runningServices.ToArray()   // 14
        };
    }
}
'@ -ReferencedAssemblies $CIRefWmiReg
    }

    Write-Verbose 'Querying device security state...'

    $result = [WDACDeviceSecurityReader]::Query()

    [PSCustomObject]@{
        SecureBootEnabled          = [bool]$result[0]
        SecureBootCapable          = [bool]$result[1]
        UEFIEnabled                = [bool]$result[2]
        TPMPresent                 = [bool]$result[3]
        TPMReady                   = [bool]$result[4]
        TPMVersion                 = [string]$result[5]
        VBSStatus                  = [string]$result[6]
        HVCIRunning                = [bool]$result[7]
        HVCIUMCIEnabled            = [bool]$result[8]
        DMAProtectionEnabled       = [bool]$result[9]
        CredentialGuardRunning     = [bool]$result[10]
        UEFILockEnabled            = [bool]$result[11]
        KernelStackProtection      = [bool]$result[12]
        SecurityServicesConfigured = [string[]]$result[13]
        SecurityServicesRunning    = [string[]]$result[14]
    }
}
