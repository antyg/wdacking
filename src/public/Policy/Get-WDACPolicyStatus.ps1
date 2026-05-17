function Get-WDACPolicyStatus {
    <#
    .SYNOPSIS
        Queries the current Windows Code Integrity and Device Guard enforcement status.

    .DESCRIPTION
        Uses native Win32 API calls to retrieve the current state of Code Integrity (CI) policy
        enforcement, including HVCI (Hypervisor-protected Code Integrity), User Mode Code Integrity
        (UMCI), and overall Device Guard configuration. Returns a structured object with typed properties.

        Internally calls WMI Win32_DeviceGuard via .NET ManagementObjectSearcher for comprehensive
        status, supplemented by direct registry reads for additional CI configuration state.

    .OUTPUTS
        PSCustomObject with properties:
            - CodeIntegrityEnabled          [bool]
            - UMCIEnabled                   [bool]
            - HVCIRunning                   [bool]
            - SecureBootEnabled             [bool]
            - EnforcementMode               [string] ('Enforced', 'Audit', 'Off')
            - PolicyOptions                 [uint32]
            - VirtualizationBasedSecurity   [string] ('Running', 'NotRunning', 'NotConfigured')

    .EXAMPLE
        Get-WDACPolicyStatus
        Returns the current CI policy enforcement status.

    .EXAMPLE
        (Get-WDACPolicyStatus).EnforcementMode
        Returns just the enforcement mode string ('Enforced', 'Audit', or 'Off').

    .NOTES
        Requires: Administrator elevation
        Platform: Windows only
    #>
    [CmdletBinding()]
    param()

    if (-not ([System.Management.Automation.PSTypeName]'WDACPolicyStatusReader').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class WDACPolicyStatusReader
{
    // VBS SecurityServicesRunning values
    private const int CredentialGuard = 1;
    private const int HypervisorEnforcedCI = 2;

    // CodeIntegrityPolicyEnforcementStatus values
    private const int EnforcementOff = 0;
    private const int EnforcementAudit = 1;
    private const int EnforcementEnforced = 2;

    // VirtualizationBasedSecurityStatus values
    private const int VBSNotConfigured = 0;
    private const int VBSNotRunning = 1;
    private const int VBSRunning = 2;

    // WLDP lockdown state constants
    private const uint WLDP_HOST_INFORMATION_REVISION = 1;
    private const uint WLDP_HOST_ID_GLOBAL = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLDP_HOST_INFORMATION
    {
        public uint dwRevision;
        public uint dwHostId;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string szSource;
        public IntPtr hSource;
    }

    [DllImport("wldp.dll", CharSet = CharSet.Unicode)]
    private static extern int WldpGetLockdownPolicy(
        ref WLDP_HOST_INFORMATION hostInformation,
        out uint lockdownState,
        uint lockdownFlags);

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

    public static object[] Query()
    {
        EnsureElevated();

        bool ciEnabled = false;
        bool umciEnabled = false;
        bool hvciRunning = false;
        bool secureBootEnabled = false;
        string enforcementMode = "Off";
        uint policyOptions = 0;
        string vbsStatus = "NotConfigured";

        using (var searcher = new ManagementObjectSearcher(
            "root\\Microsoft\\Windows\\DeviceGuard",
            "SELECT * FROM Win32_DeviceGuard"))
        {
            foreach (ManagementObject obj in searcher.Get())
            {
                // CodeIntegrityPolicyEnforcementStatus
                var ciStatus = obj["CodeIntegrityPolicyEnforcementStatus"];
                if (ciStatus != null)
                {
                    int status = Convert.ToInt32(ciStatus);
                    ciEnabled = status != EnforcementOff;
                    switch (status)
                    {
                        case EnforcementEnforced: enforcementMode = "Enforced"; break;
                        case EnforcementAudit:    enforcementMode = "Audit";    break;
                        default:                  enforcementMode = "Off";      break;
                    }
                }

                // UsermodeCodeIntegrityPolicyEnforcementStatus
                var umciStatus = obj["UsermodeCodeIntegrityPolicyEnforcementStatus"];
                if (umciStatus != null)
                    umciEnabled = Convert.ToInt32(umciStatus) != EnforcementOff;

                // SecurityServicesRunning — check if HVCI is in the array
                var services = obj["SecurityServicesRunning"] as int[];
                if (services != null)
                {
                    foreach (int svc in services)
                    {
                        if (svc == HypervisorEnforcedCI)
                        {
                            hvciRunning = true;
                            break;
                        }
                    }
                }

                // RequiredSecurityProperties — check for Secure Boot
                var reqProps = obj["RequiredSecurityProperties"] as int[];
                if (reqProps != null)
                {
                    foreach (int prop in reqProps)
                    {
                        if (prop == 2) // SecureBoot
                        {
                            secureBootEnabled = true;
                            break;
                        }
                    }
                }

                // AvailableSecurityProperties for secure boot confirmation
                var availProps = obj["AvailableSecurityProperties"] as int[];
                if (availProps != null && !secureBootEnabled)
                {
                    foreach (int prop in availProps)
                    {
                        if (prop == 2) // SecureBoot capable
                        {
                            secureBootEnabled = true;
                            break;
                        }
                    }
                }

                // VirtualizationBasedSecurityStatus
                var vbs = obj["VirtualizationBasedSecurityStatus"];
                if (vbs != null)
                {
                    switch (Convert.ToInt32(vbs))
                    {
                        case VBSRunning:       vbsStatus = "Running";       break;
                        case VBSNotRunning:    vbsStatus = "NotRunning";    break;
                        default:               vbsStatus = "NotConfigured"; break;
                    }
                }

                break; // Only one instance expected
            }
        }

        // Query WLDP for runtime lockdown bitmask
        try
        {
            var hostInfo = new WLDP_HOST_INFORMATION
            {
                dwRevision = WLDP_HOST_INFORMATION_REVISION,
                dwHostId = WLDP_HOST_ID_GLOBAL,
                szSource = null,
                hSource = IntPtr.Zero
            };

            uint lockdownState;
            int hr = WldpGetLockdownPolicy(ref hostInfo, out lockdownState, 0);
            if (hr == 0)
                policyOptions = lockdownState;
        }
        catch { /* WLDP unavailable — policyOptions remains 0 */ }

        // Return as object array: [ci, umci, hvci, secureboot, enforcement, options, vbs]
        return new object[] {
            ciEnabled, umciEnabled, hvciRunning, secureBootEnabled,
            enforcementMode, policyOptions, vbsStatus
        };
    }
}
'@ -ReferencedAssemblies $CIRefWmi
    }

    Write-Verbose 'Querying CI policy enforcement status...'

    $result = [WDACPolicyStatusReader]::Query()

    [PSCustomObject]@{
        CodeIntegrityEnabled        = [bool]$result[0]
        UMCIEnabled                 = [bool]$result[1]
        HVCIRunning                 = [bool]$result[2]
        SecureBootEnabled           = [bool]$result[3]
        EnforcementMode             = [string]$result[4]
        PolicyOptions               = [uint32]$result[5]
        VirtualizationBasedSecurity = [string]$result[6]
    }
}
