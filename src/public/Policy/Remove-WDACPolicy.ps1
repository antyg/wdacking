function Remove-WDACPolicy {
    <#
    .SYNOPSIS
        Removes a deployed Code Integrity policy from the system.

    .DESCRIPTION
        Removes a CI policy file from the multi-policy active directory by Policy GUID,
        or removes the legacy SIPolicy.p7b. Uses C# interop for filesystem operations
        with elevation checks and file verification.

        The policy is identified by its GUID (from the .cip filename). A policy refresh
        is recommended after removal to apply the change without reboot.

    .PARAMETER PolicyId
        The GUID of the policy to remove (e.g., 'A1B2C3D4-E5F6-7890-ABCD-EF1234567890').
        Matches against .cip filenames in the active policies directory.

    .PARAMETER Name
        Remove a policy by its FriendlyName. Supports wildcards (e.g., 'AllowMicrosoft*').
        Resolves the name to a PolicyId via Get-WDACPolicy binary header parsing.
        If multiple policies match, all are presented for confirmation.

    .PARAMETER Legacy
        Remove the legacy single-policy SIPolicy.p7b instead of a multi-policy file.

    .OUTPUTS
        PSCustomObject with properties:
            - PolicyId     [string]   GUID of the removed policy (or 'Legacy')
            - FilePath     [string]   Path of the file that was removed
            - SizeBytes    [long]     Size of the removed file
            - RemovedAt    [datetime] Timestamp of removal
            - Success      [bool]     Whether the removal succeeded

    .EXAMPLE
        Remove-WDACPolicy -PolicyId 'A1B2C3D4-E5F6-7890-ABCD-EF1234567890' -Verbose
        Removes the specified multi-policy CI policy file.

    .EXAMPLE
        Remove-WDACPolicy -Name 'AllowMicrosoft*' -Verbose
        Removes policies matching the friendly name pattern.

    .EXAMPLE
        Remove-WDACPolicy -Legacy -Verbose
        Removes the legacy SIPolicy.p7b file.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows only
        A policy refresh (Invoke-WDACPolicyRefresh) is recommended after removal.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByGuid')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$PolicyId,

        [Parameter(Mandatory, ParameterSetName = 'ByName')]
        [SupportsWildcards()]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Legacy')]
        [switch]$Legacy
    )

    if (-not ([System.Management.Automation.PSTypeName]'WDACPolicyRemover').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Security.Principal;

public static class WDACPolicyRemover
{
    private const string MultiPolicyRelative = @"System32\CodeIntegrity\CiPolicies\Active";
    private const string LegacyPolicyRelative = @"System32\CodeIntegrity\SIPolicy.p7b";

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
    /// Locates the policy file. Returns [filePath, fileSize] or throws if not found.
    /// </summary>
    public static object[] Locate(string policyId, bool legacy)
    {
        EnsureElevated();

        string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string filePath;

        if (legacy)
        {
            filePath = Path.Combine(sysRoot, LegacyPolicyRelative);
        }
        else
        {
            string dir = Path.Combine(sysRoot, MultiPolicyRelative);

            // Try common filename patterns: {GUID}.cip and GUID.cip
            string bracedPath = Path.Combine(dir, "{" + policyId + "}.cip");
            string plainPath  = Path.Combine(dir, policyId + ".cip");

            if (File.Exists(bracedPath))
                filePath = bracedPath;
            else if (File.Exists(plainPath))
                filePath = plainPath;
            else
                throw new FileNotFoundException(
                    string.Format("No policy file found for GUID '{0}' in '{1}'.", policyId, dir));
        }

        if (!File.Exists(filePath))
            throw new FileNotFoundException("Policy file not found at expected path.", filePath);

        var info = new FileInfo(filePath);
        return new object[] { info.FullName, info.Length };
    }

    /// <summary>
    /// Deletes the policy file. Returns true if the file no longer exists after deletion.
    /// </summary>
    public static bool Remove(string filePath)
    {
        File.Delete(filePath);
        return !File.Exists(filePath);
    }
}
'@ -ReferencedAssemblies $CIRefBase
    }

    # Resolve -Name to -PolicyId via Get-WDACPolicy
    if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Write-Verbose "Resolving FriendlyName '$Name' via Get-WDACPolicy..."
        $resolved = @(Get-WDACPolicy -Name $Name)

        if ($resolved.Count -eq 0) {
            Write-Warning "No policies found matching name '$Name'."
            return
        }

        # Process each matching policy
        foreach ($policy in $resolved) {
            Write-Verbose "Matched: '$($policy.FriendlyName)' (PolicyId: $($policy.PolicyId))"
            Remove-WDACPolicy -PolicyId $policy.PolicyId
        }
        return
    }

    $targetLabel = if ($Legacy) { 'Legacy (SIPolicy.p7b)' } else { $PolicyId }
    Write-Verbose "Locating CI policy: $targetLabel"

    $located = [WDACPolicyRemover]::Locate(
        $(if ($Legacy) { '' } else { $PolicyId }),
        $Legacy.IsPresent
    )
    $filePath = [string]$located[0]
    $fileSize = [long]$located[1]

    if ($PSCmdlet.ShouldProcess($filePath, "Remove CI policy '$targetLabel'")) {
        Write-Verbose "Removing policy file: $filePath"

        $success = [WDACPolicyRemover]::Remove($filePath)

        [PSCustomObject]@{
            PolicyId  = if ($Legacy) { 'Legacy' } else { $PolicyId }
            FilePath  = $filePath
            SizeBytes = $fileSize
            RemovedAt = [datetime]::Now
            Success   = $success
        }

        if ($success) {
            Write-Verbose "Policy '$targetLabel' removed successfully. Run Invoke-WDACPolicyRefresh to apply."
        }
        else {
            Write-Warning "Policy file may still exist at '$filePath' after removal attempt."
        }
    }
}
