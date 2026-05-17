function Get-WDACPolicyFile {
    <#
    .SYNOPSIS
        Lists all deployed Code Integrity policy files on the system.

    .DESCRIPTION
        Scans the standard CI policy deployment locations for active policy files:
        - Multi-policy directory: %SystemRoot%\System32\CodeIntegrity\CiPolicies\Active\*.cip
        - Legacy single-policy: %SystemRoot%\System32\CodeIntegrity\SIPolicy.p7b
        - EFI system partition: EFI\Microsoft\Boot\CiPolicies\Active\*.cip (if accessible)

        Uses C# interop for filesystem enumeration with structured output including file metadata
        and policy GUID extraction from filenames.

    .OUTPUTS
        PSCustomObject[] with properties:
            - PolicyId       [string]   GUID extracted from filename (or 'Legacy' for SIPolicy.p7b)
            - FileName       [string]   File name
            - FullPath       [string]   Full file path
            - SizeBytes      [long]     File size in bytes
            - LastModified   [datetime] Last write time
            - Location       [string]   'MultiPolicy', 'Legacy', or 'EFI'

    .PARAMETER Name
        Filter policies by FriendlyName. Supports wildcards (e.g., 'AllowMicrosoft*').
        Requires Get-WDACPolicy for binary header resolution.

    .EXAMPLE
        Get-WDACPolicyFile
        Lists all deployed CI policy files.

    .EXAMPLE
        Get-WDACPolicyFile -Name 'AllowMicrosoft*'
        Lists policy files matching the friendly name pattern.

    .EXAMPLE
        Get-WDACPolicyFile | Where-Object Location -eq 'MultiPolicy'
        Lists only multi-policy format deployments.

    .NOTES
        Requires: Administrator elevation (for EFI partition access)
        Platform: Windows only
    #>
    [CmdletBinding()]
    param(
        [SupportsWildcards()]
        [string]$Name
    )

    if (-not ([System.Management.Automation.PSTypeName]'WDACPolicyFileEnumerator').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.Text.RegularExpressions;

public static class WDACPolicyFileEnumerator
{
    // Standard CI policy paths relative to SystemRoot
    private const string MultiPolicyRelative = @"System32\CodeIntegrity\CiPolicies\Active";
    private const string LegacyPolicyRelative = @"System32\CodeIntegrity\SIPolicy.p7b";
    private const string EfiRelative = @"EFI\Microsoft\Boot\CiPolicies\Active";

    // Pattern to extract GUID from .cip filenames like {GUID}.cip
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
    /// Returns array of object[] rows: [PolicyId, FileName, FullPath, SizeBytes, LastModified, Location]
    /// </summary>
    public static List<object[]> Enumerate()
    {
        EnsureElevated();

        var results = new List<object[]>();
        string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        // Multi-policy directory (Windows 10 1903+)
        string multiDir = Path.Combine(sysRoot, MultiPolicyRelative);
        if (Directory.Exists(multiDir))
        {
            foreach (string file in Directory.GetFiles(multiDir, "*.cip"))
            {
                var info = new FileInfo(file);
                string policyId = ExtractGuid(info.Name);
                results.Add(new object[] {
                    policyId, info.Name, info.FullName,
                    info.Length, info.LastWriteTime, "MultiPolicy"
                });
            }
        }

        // Legacy single-policy
        string legacyPath = Path.Combine(sysRoot, LegacyPolicyRelative);
        if (File.Exists(legacyPath))
        {
            var info = new FileInfo(legacyPath);
            results.Add(new object[] {
                "Legacy", info.Name, info.FullName,
                info.Length, info.LastWriteTime, "Legacy"
            });
        }

        // EFI partition — attempt common mount points
        string[] efiRoots = { @"S:\", @"T:\", @"X:\" };
        foreach (string efiRoot in efiRoots)
        {
            string efiDir = Path.Combine(efiRoot, EfiRelative);
            if (Directory.Exists(efiDir))
            {
                try
                {
                    foreach (string file in Directory.GetFiles(efiDir, "*.cip"))
                    {
                        var info = new FileInfo(file);
                        string policyId = ExtractGuid(info.Name);
                        results.Add(new object[] {
                            policyId, info.Name, info.FullName,
                            info.Length, info.LastWriteTime, "EFI"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { /* EFI partition may be locked */ }
            }
        }

        return results;
    }

    private static string ExtractGuid(string fileName)
    {
        var match = GuidPattern.Match(fileName);
        return match.Success ? match.Groups[1].Value : Path.GetFileNameWithoutExtension(fileName);
    }
}
'@ -ReferencedAssemblies $CIRefBase
    }

    Write-Verbose 'Enumerating deployed CI policy files...'

    $files = [WDACPolicyFileEnumerator]::Enumerate()

    $output = foreach ($row in $files) {
        [PSCustomObject]@{
            PolicyId     = [string]$row[0]
            FileName     = [string]$row[1]
            FullPath     = [string]$row[2]
            SizeBytes    = [long]$row[3]
            LastModified = [datetime]$row[4]
            Location     = [string]$row[5]
        }
    }

    # Apply -Name filter via Get-WDACPolicy binary resolution
    if ($PSBoundParameters.ContainsKey('Name')) {
        Write-Verbose "Resolving FriendlyName filter '$Name' via Get-WDACPolicy..."
        $resolved = Get-WDACPolicy -Name $Name
        $matchIds = @($resolved | ForEach-Object { $_.PolicyId })

        $output = $output | Where-Object { $_.PolicyId -in $matchIds }
    }

    $output

    if ($files.Count -eq 0) {
        Write-Verbose 'No deployed CI policy files found.'
    }
    else {
        Write-Verbose "Found $($files.Count) deployed CI policy file(s)."
    }
}
