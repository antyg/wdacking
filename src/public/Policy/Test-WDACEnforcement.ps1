function Test-WDACEnforcement {
    <#
    .SYNOPSIS
        Tests whether Code Integrity policy is actively enforced (not just audit mode).

    .DESCRIPTION
        Performs a quick boolean check of the current CI enforcement state by reading
        the Code Integrity configuration from the Windows kernel via registry and the
        DeviceGuard WMI namespace. Returns a structured result with enforcement details.

        This is designed as a lightweight guard-clause function — use it in scripts that
        should only run when CI is (or is not) enforcing.

    .PARAMETER IncludeUMCI
        Also check User Mode Code Integrity (UMCI) enforcement status.

    .OUTPUTS
        PSCustomObject with properties:
            - IsEnforced         [bool]   True if kernel-mode CI is in enforcement mode
            - UMCIEnforced       [bool]   True if user-mode CI is in enforcement mode (only with -IncludeUMCI)
            - EnforcementMode    [string] 'Enforced', 'Audit', or 'Off'
            - CheckedAt          [datetime] Timestamp of the check

    .EXAMPLE
        if ((Test-WDACEnforcement).IsEnforced) { Write-Host 'CI is enforcing!' }
        Quick guard clause to check enforcement state.

    .EXAMPLE
        Test-WDACEnforcement -IncludeUMCI -Verbose
        Checks both kernel and user mode CI enforcement.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows only
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeUMCI
    )

    if (-not ([System.Management.Automation.PSTypeName]'WDACEnforcementTester').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Management;
using System.Security.Principal;

public static class WDACEnforcementTester
{
    // CodeIntegrityPolicyEnforcementStatus values
    private const int EnforcementOff = 0;
    private const int EnforcementAudit = 1;
    private const int EnforcementEnforced = 2;

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
    /// Returns [isEnforced, umciEnforced, enforcementModeString].
    /// </summary>
    public static object[] Test(bool checkUmci)
    {
        EnsureElevated();

        bool isEnforced = false;
        bool umciEnforced = false;
        string enforcementMode = "Off";

        using (var searcher = new ManagementObjectSearcher(
            "root\\Microsoft\\Windows\\DeviceGuard",
            "SELECT CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard"))
        {
            foreach (ManagementObject obj in searcher.Get())
            {
                // Kernel-mode CI status
                var ciStatus = obj["CodeIntegrityPolicyEnforcementStatus"];
                if (ciStatus != null)
                {
                    int status = Convert.ToInt32(ciStatus);
                    isEnforced = (status == EnforcementEnforced);
                    switch (status)
                    {
                        case EnforcementEnforced: enforcementMode = "Enforced"; break;
                        case EnforcementAudit:    enforcementMode = "Audit";    break;
                        default:                  enforcementMode = "Off";      break;
                    }
                }

                // User-mode CI status
                if (checkUmci)
                {
                    var umciStatus = obj["UsermodeCodeIntegrityPolicyEnforcementStatus"];
                    if (umciStatus != null)
                        umciEnforced = (Convert.ToInt32(umciStatus) == EnforcementEnforced);
                }

                break; // Only one instance expected
            }
        }

        return new object[] { isEnforced, umciEnforced, enforcementMode };
    }
}
'@ -ReferencedAssemblies $CIRefWmi
    }

    Write-Verbose 'Testing CI policy enforcement state...'

    $result = [WDACEnforcementTester]::Test($IncludeUMCI.IsPresent)

    $output = [PSCustomObject]@{
        IsEnforced      = [bool]$result[0]
        EnforcementMode = [string]$result[2]
        CheckedAt       = [datetime]::Now
    }

    if ($IncludeUMCI) {
        $output | Add-Member -NotePropertyName 'UMCIEnforced' -NotePropertyValue ([bool]$result[1])
    }

    $output

    Write-Verbose "CI enforcement mode: $($result[2])"
}
