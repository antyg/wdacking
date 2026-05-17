function Invoke-WDACPolicyRefresh {
    <#
    .SYNOPSIS
        Refreshes the Windows Code Integrity (CI) policy without requiring a reboot.

    .DESCRIPTION
        Calls NtSetSystemInformation with SystemCodeIntegrityPolicyInformation (info class 0xA4)
        to trigger a live refresh of WDAC/Code Integrity policy. Requires elevation (Run as Administrator).

        The C# interop code pins a 32-byte buffer containing the refresh flag (0x00000001) and passes
        it to the NT kernel via P/Invoke. Memory is safely released in a finally block.

    .OUTPUTS
        None. Writes success or failure to the verbose/warning streams.

    .EXAMPLE
        Invoke-WDACPolicyRefresh -Verbose
        Refreshes the active CI policy and shows verbose status output.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows only (ntdll.dll)
    #>
    [CmdletBinding()]
    param()

    # Define the C# interop type if not already loaded
    if (-not ([System.Management.Automation.PSTypeName]'RefreshWDACPolicy').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class RefreshWDACPolicy
{
    // NtSetSystemInformation info class for Code Integrity policy operations
    private const uint SystemCodeIntegrityPolicyInformation = 0xA4;

    // Buffer size required by the CI policy information structure
    private const uint PolicyBufferSize = 0x20;

    // Flag to trigger a policy refresh
    private const int RefreshFlag = 0x00000001;

    // NTSTATUS success code
    private const uint STATUS_SUCCESS = 0x00000000;

    [DllImport("ntdll.dll")]
    private static extern uint NtSetSystemInformation(uint InfoClass, IntPtr Info, uint Length);

    /// <summary>
    /// Triggers a refresh of the active Code Integrity policy.
    /// Returns 0 (STATUS_SUCCESS) on success, or an NTSTATUS error code on failure.
    /// </summary>
    public static uint Refresh()
    {
        byte[] buffer = new byte[PolicyBufferSize];
        BitConverter.GetBytes(RefreshFlag).CopyTo(buffer, 0);

        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            IntPtr pointer = handle.AddrOfPinnedObject();
            return NtSetSystemInformation(SystemCodeIntegrityPolicyInformation, pointer, PolicyBufferSize);
        }
        finally
        {
            handle.Free();
        }
    }
}
'@
    }

    Write-Verbose 'Invoking CI policy refresh via NtSetSystemInformation...'

    $ntStatus = [RefreshWDACPolicy]::Refresh()

    if ($ntStatus -eq 0) {
        Write-Verbose 'CI policy refreshed successfully (STATUS_SUCCESS).'
    }
    else {
        $hexStatus = '0x{0:X8}' -f $ntStatus
        Write-Warning "CI policy refresh failed with NTSTATUS $hexStatus."
    }
}
