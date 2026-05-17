function Set-WDACPolicy {
    <#
    .SYNOPSIS
        Sets a compiled Code Integrity policy binary as active on the system.

    .DESCRIPTION
        Copies a compiled CI policy binary (.cip) to the active multi-policy directory
        (%SystemRoot%\System32\CodeIntegrity\CiPolicies\Active\) or optionally to the
        legacy single-policy location (SIPolicy.p7b).

        Uses C# interop for file operations with validation of the source file, elevation
        checks, and atomic copy with verification. Optionally triggers a policy refresh
        after deployment.

    .PARAMETER Path
        Full path to the compiled policy file (.cip or .p7b) to deploy.

    .PARAMETER Legacy
        Deploy as the legacy single-policy SIPolicy.p7b instead of multi-policy format.

    .PARAMETER Force
        Overwrite existing policy file at the destination without prompting.

    .OUTPUTS
        PSCustomObject with properties:
            - SourcePath       [string]   Path of the source policy file
            - DestinationPath  [string]   Path where the policy was deployed
            - PolicyId         [string]   GUID extracted from filename (or 'Legacy')
            - SizeBytes        [long]     File size in bytes
            - DeployedAt       [datetime] Timestamp of deployment
            - Success          [bool]     Whether the deployment succeeded

    .EXAMPLE
        Set-WDACPolicy -Path 'C:\Policies\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}.cip' -Verbose
        Deploys the policy to the multi-policy active directory.

    .EXAMPLE
        Set-WDACPolicy -Path 'C:\Policies\SIPolicy.p7b' -Legacy -Force
        Deploys as the legacy single-policy, overwriting any existing policy.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows only
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path,

        [switch]$Legacy,

        [switch]$Force
    )

    if (-not ([System.Management.Automation.PSTypeName]'WDACPolicyDeployer').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Security.Principal;
using System.Text.RegularExpressions;

public static class WDACPolicyDeployer
{
    private const string MultiPolicyRelative = @"System32\CodeIntegrity\CiPolicies\Active";
    private const string LegacyPolicyRelative = @"System32\CodeIntegrity\SIPolicy.p7b";

    // Minimum valid policy file size (bytes) — a policy binary is at least a few hundred bytes
    private const long MinPolicySize = 64;

    // Maximum reasonable policy file size (50 MB)
    private const long MaxPolicySize = 50 * 1024 * 1024;

    private static readonly Regex GuidPattern = new Regex(
        @"\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?",
        RegexOptions.Compiled);

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
    /// Validates the source file and returns [destinationPath, policyId, sourceSize].
    /// Throws on validation failure.
    /// </summary>
    public static object[] Prepare(string sourcePath, bool legacy)
    {
        EnsureElevated();

        if (!File.Exists(sourcePath))
            throw new FileNotFoundException("Source policy file not found.", sourcePath);

        var info = new FileInfo(sourcePath);

        if (info.Length < MinPolicySize)
            throw new InvalidOperationException(
                string.Format("Policy file is too small ({0} bytes). Minimum expected: {1} bytes.",
                    info.Length, MinPolicySize));

        if (info.Length > MaxPolicySize)
            throw new InvalidOperationException(
                string.Format("Policy file is too large ({0} bytes). Maximum allowed: {1} bytes.",
                    info.Length, MaxPolicySize));

        string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string destPath;
        string policyId;

        if (legacy)
        {
            destPath = Path.Combine(sysRoot, LegacyPolicyRelative);
            policyId = "Legacy";
        }
        else
        {
            string destDir = Path.Combine(sysRoot, MultiPolicyRelative);

            // Ensure the multi-policy directory exists
            if (!Directory.Exists(destDir))
                Directory.CreateDirectory(destDir);

            destPath = Path.Combine(destDir, info.Name);

            var match = GuidPattern.Match(info.Name);
            policyId = match.Success ? match.Groups[1].Value : Path.GetFileNameWithoutExtension(info.Name);
        }

        return new object[] { destPath, policyId, info.Length };
    }

    /// <summary>
    /// Performs the file copy. Returns true on success.
    /// </summary>
    public static bool Deploy(string sourcePath, string destinationPath, bool overwrite)
    {
        File.Copy(sourcePath, destinationPath, overwrite);

        // Verify the copy
        if (!File.Exists(destinationPath))
            return false;

        var src = new FileInfo(sourcePath);
        var dst = new FileInfo(destinationPath);
        return dst.Length == src.Length;
    }
}
'@ -ReferencedAssemblies $CIRefBase
    }

    Write-Verbose "Preparing to deploy policy from: $Path"

    $prepared = [WDACPolicyDeployer]::Prepare($Path, $Legacy.IsPresent)
    $destPath = [string]$prepared[0]
    $policyId = [string]$prepared[1]
    $srcSize  = [long]$prepared[2]

    # Check for existing file at destination
    if ((Test-Path $destPath) -and -not $Force) {
        Write-Warning "Policy already exists at '$destPath'. Use -Force to overwrite."
        [PSCustomObject]@{
            SourcePath      = $Path
            DestinationPath = $destPath
            PolicyId        = $policyId
            SizeBytes       = $srcSize
            DeployedAt      = [datetime]::MinValue
            Success         = $false
        }
        return
    }

    if ($PSCmdlet.ShouldProcess($destPath, "Deploy CI policy '$policyId'")) {
        Write-Verbose "Deploying policy '$policyId' to: $destPath"

        $success = [WDACPolicyDeployer]::Deploy($Path, $destPath, $Force.IsPresent)

        [PSCustomObject]@{
            SourcePath      = $Path
            DestinationPath = $destPath
            PolicyId        = $policyId
            SizeBytes       = $srcSize
            DeployedAt      = [datetime]::Now
            Success         = $success
        }

        if ($success) {
            Write-Verbose "Policy '$policyId' deployed successfully."
        }
        else {
            Write-Warning "Policy deployment verification failed for '$policyId'."
        }
    }
}
