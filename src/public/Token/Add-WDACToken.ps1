function Add-WDACToken {
    <#
    .SYNOPSIS
        Adds a Code Integrity trust token for a file, granting it dynamic code trust.

    .DESCRIPTION
        Creates a CI trust token for the specified file by computing its SHA256 hash and
        writing a trust entry via NtSetSystemInformation. This grants the file permission
        to execute under CI policy even if it isn't explicitly whitelisted in a policy rule.

        The trust token is stored in the CI token cache and persists until explicitly removed,
        the policy is refreshed with different settings, or the system is rebooted (depending
        on token type and persistence settings).

        Uses direct NT API P/Invoke for token creation with SHA256 hash computation via
        .NET System.Security.Cryptography.

    .PARAMETER Path
        Full path to the file to trust. The file must exist and be readable.

    .PARAMETER Type
        The type of trust token to create:
        - DynamicCodeTrust: General dynamic code trust (default)
        - ManagedInstaller: Mark as deployed by a managed installer

    .PARAMETER Persistent
        If specified, the token persists across reboots by writing to the token cache on disk.
        Without this switch, the token is session-only (memory-resident).

    .OUTPUTS
        PSCustomObject with properties:
            - FilePath     [string]   Path of the trusted file
            - FileHash     [string]   SHA256 hash of the file
            - TokenType    [string]   Type of token created
            - Persistent   [bool]     Whether the token persists across reboots
            - NtStatus     [string]   NTSTATUS result code (hex)
            - Success      [bool]     Whether the token was created successfully
            - CreatedAt    [datetime] Timestamp of creation

    .EXAMPLE
        Add-WDACToken -Path 'C:\Tools\MyApp.exe' -Verbose
        Grants dynamic code trust to MyApp.exe.

    .EXAMPLE
        Add-WDACToken -Path 'C:\Deploy\Package.msi' -Type ManagedInstaller -Persistent
        Grants persistent managed installer trust to a deployment package.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows 10 1903+ / Windows 11
        Warning: Granting trust tokens bypasses CI policy rules for the specified file.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path,

        [ValidateSet('DynamicCodeTrust', 'ManagedInstaller')]
        [string]$Type = 'DynamicCodeTrust',

        [switch]$Persistent
    )

    if (-not ([System.Management.Automation.PSTypeName]'WDACTokenWriter').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

public static class WDACTokenWriter
{
    // NtSetSystemInformation info class for CI token operations
    private const uint SystemCodeIntegrityVerificationInformation = 0xBB;  // 187

    // Token type constants
    private const uint TokenTypeManagedInstaller = 1;
    private const uint TokenTypeDynamicCodeTrust = 3;

    // Token flags
    private const uint TokenFlagPersistent = 0x00000001;
    private const uint TokenFlagSessionOnly = 0x00000000;

    // Token cache paths for persistent storage
    private const string DynamicCodeTrustCacheRelative =
        @"System32\CodeIntegrity\CiCacheTokens\DynamicCodeTrust";
    private const string ManagedInstallerCacheRelative =
        @"System32\CodeIntegrity\CiCacheTokens\ManagedInstaller";

    private const uint STATUS_SUCCESS = 0x00000000;

    [DllImport("ntdll.dll")]
    private static extern uint NtSetSystemInformation(
        uint SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength);

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
    /// Computes the SHA256 hash of a file and returns it as a hex string.
    /// </summary>
    public static string ComputeFileHash(string filePath)
    {
        using (var sha256 = SHA256.Create())
        using (var stream = File.OpenRead(filePath))
        {
            byte[] hash = sha256.ComputeHash(stream);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash)
                sb.Append(b.ToString("X2"));
            return sb.ToString();
        }
    }

    /// <summary>
    /// Creates a CI trust token for the specified file.
    /// Returns object[]: [fileHash, ntStatusHex, success]
    /// </summary>
    public static object[] CreateToken(string filePath, string tokenType, bool persistent)
    {
        EnsureElevated();

        // Compute file hash
        byte[] fileHashBytes;
        string fileHashHex;
        using (var sha256 = SHA256.Create())
        using (var stream = File.OpenRead(filePath))
        {
            fileHashBytes = sha256.ComputeHash(stream);
            var sb = new StringBuilder(fileHashBytes.Length * 2);
            foreach (byte b in fileHashBytes)
                sb.Append(b.ToString("X2"));
            fileHashHex = sb.ToString();
        }

        uint typeId = tokenType == "ManagedInstaller"
            ? TokenTypeManagedInstaller
            : TokenTypeDynamicCodeTrust;

        uint flags = persistent ? TokenFlagPersistent : TokenFlagSessionOnly;

        // Encode the file path as UTF-16
        byte[] pathBytes = Encoding.Unicode.GetBytes(filePath);

        // Build the token structure:
        //   uint32 StructureSize
        //   uint32 TokenType
        //   uint32 Flags
        //   uint32 HashAlgorithm (SHA256 = 0x800C)
        //   uint32 HashLength
        //   byte[] Hash
        //   uint32 PathLength (in bytes)
        //   byte[] Path (UTF-16)
        int structSize = 20 + fileHashBytes.Length + 4 + pathBytes.Length;
        byte[] buffer = new byte[structSize];
        int offset = 0;

        BitConverter.GetBytes((uint)structSize).CopyTo(buffer, offset); offset += 4;
        BitConverter.GetBytes(typeId).CopyTo(buffer, offset); offset += 4;
        BitConverter.GetBytes(flags).CopyTo(buffer, offset); offset += 4;
        BitConverter.GetBytes((uint)0x800C).CopyTo(buffer, offset); offset += 4; // SHA256
        BitConverter.GetBytes((uint)fileHashBytes.Length).CopyTo(buffer, offset); offset += 4;
        Array.Copy(fileHashBytes, 0, buffer, offset, fileHashBytes.Length); offset += fileHashBytes.Length;
        BitConverter.GetBytes((uint)pathBytes.Length).CopyTo(buffer, offset); offset += 4;
        Array.Copy(pathBytes, 0, buffer, offset, pathBytes.Length);

        // Call NtSetSystemInformation
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        uint ntStatus;
        try
        {
            IntPtr ptr = handle.AddrOfPinnedObject();
            ntStatus = NtSetSystemInformation(
                SystemCodeIntegrityVerificationInformation,
                ptr, (uint)structSize);
        }
        finally
        {
            handle.Free();
        }

        bool success = ntStatus == STATUS_SUCCESS;

        // If persistent and API succeeded, also write to cache directory
        if (persistent && success)
        {
            try
            {
                WriteToCacheDirectory(filePath, fileHashBytes, tokenType);
            }
            catch { /* Cache write is best-effort */ }
        }

        string ntStatusHex = string.Format("0x{0:X8}", ntStatus);
        return new object[] { fileHashHex, ntStatusHex, success };
    }

    private static void WriteToCacheDirectory(string filePath, byte[] hashBytes, string tokenType)
    {
        string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string cacheDir = tokenType == "ManagedInstaller"
            ? Path.Combine(sysRoot, ManagedInstallerCacheRelative)
            : Path.Combine(sysRoot, DynamicCodeTrustCacheRelative);

        if (!Directory.Exists(cacheDir))
            Directory.CreateDirectory(cacheDir);

        // Write token file named by hash
        var sb = new StringBuilder(hashBytes.Length * 2);
        foreach (byte b in hashBytes)
            sb.Append(b.ToString("X2"));
        string tokenFile = Path.Combine(cacheDir, sb.ToString() + ".token");

        // Token file contains: hash bytes + UTF-16 path
        using (var fs = new FileStream(tokenFile, FileMode.Create, FileAccess.Write))
        {
            fs.Write(hashBytes, 0, hashBytes.Length);
            byte[] pathBytes = Encoding.Unicode.GetBytes(filePath);
            fs.Write(pathBytes, 0, pathBytes.Length);
        }
    }
}
'@ -ReferencedAssemblies $CIRefBase
    }

    $resolvedPath = (Resolve-Path $Path).Path
    Write-Verbose "Computing SHA256 hash for: $resolvedPath"

    if ($PSCmdlet.ShouldProcess($resolvedPath, "Add CI trust token ($Type)")) {
        $result = [WDACTokenWriter]::CreateToken($resolvedPath, $Type, $Persistent.IsPresent)

        [PSCustomObject]@{
            FilePath   = $resolvedPath
            FileHash   = [string]$result[0]
            TokenType  = $Type
            Persistent = $Persistent.IsPresent
            NtStatus   = [string]$result[1]
            Success    = [bool]$result[2]
            CreatedAt  = [datetime]::Now
        }

        if ([bool]$result[2]) {
            Write-Verbose "Trust token created successfully for '$resolvedPath'."
        }
        else {
            Write-Warning "Failed to create trust token. NTSTATUS: $($result[1])"
        }
    }
}
