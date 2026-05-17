function Remove-WDACToken {
    <#
    .SYNOPSIS
        Removes a Code Integrity trust token, revoking dynamic trust for a file.

    .DESCRIPTION
        Revokes a CI trust token by its token identifier or by the file path it was granted to.
        Uses NtSetSystemInformation to invalidate the in-memory token and removes the corresponding
        cache file on disk if it exists (for persistent tokens).

        After removal, the file will be subject to normal CI policy evaluation on next execution.

    .PARAMETER TokenId
        The token identifier to remove (as returned by Get-WDACToken).

    .PARAMETER Path
        Remove the trust token associated with the specified file path. Computes the file's SHA256
        hash and looks up the corresponding token.

    .OUTPUTS
        PSCustomObject with properties:
            - TokenId      [string]   Token identifier that was removed
            - FilePath     [string]   File path associated with the token
            - FileHash     [string]   SHA256 hash of the file
            - NtStatus     [string]   NTSTATUS result code (hex)
            - CacheRemoved [bool]     Whether the persistent cache file was also removed
            - Success      [bool]     Whether the token was revoked successfully
            - RemovedAt    [datetime] Timestamp of removal

    .EXAMPLE
        Remove-WDACToken -TokenId 'DYN-A1B2C3D4' -Verbose
        Removes the specified trust token by ID.

    .EXAMPLE
        Remove-WDACToken -Path 'C:\Tools\MyApp.exe' -Verbose
        Revokes trust for the specified file.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows 10 1903+ / Windows 11
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [string]$TokenId,

        [Parameter(Mandatory, ParameterSetName = 'ByPath')]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    if (-not ([System.Management.Automation.PSTypeName]'WDACTokenRemover').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

public static class WDACTokenRemover
{
    // NtSetSystemInformation info class
    private const uint SystemCodeIntegrityVerificationInformation = 0xBB;  // 187

    // Revocation flag
    private const uint TokenActionRevoke = 0x00000002;

    // Hash algorithm ID for SHA256
    private const uint HashAlgorithmSHA256 = 0x800C;

    // Token cache directories
    private const string TokenCacheRelative = @"System32\CodeIntegrity\CiCacheTokens";

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
    /// Computes SHA256 hash of a file and returns the bytes.
    /// </summary>
    public static byte[] ComputeHash(string filePath)
    {
        using (var sha256 = SHA256.Create())
        using (var stream = File.OpenRead(filePath))
        {
            return sha256.ComputeHash(stream);
        }
    }

    /// <summary>
    /// Converts hash bytes to hex string.
    /// </summary>
    public static string HashToHex(byte[] hash)
    {
        var sb = new StringBuilder(hash.Length * 2);
        foreach (byte b in hash)
            sb.Append(b.ToString("X2"));
        return sb.ToString();
    }

    /// <summary>
    /// Revokes a CI token by file hash.
    /// Returns object[]: [hashHex, ntStatusHex, cacheRemoved, success]
    /// </summary>
    public static object[] RevokeByHash(byte[] hashBytes)
    {
        EnsureElevated();

        // Build revocation structure:
        //   uint32 StructureSize
        //   uint32 Action (Revoke = 2)
        //   uint32 HashAlgorithm (SHA256 = 0x800C)
        //   uint32 HashLength
        //   byte[] Hash
        int structSize = 16 + hashBytes.Length;
        byte[] buffer = new byte[structSize];
        int offset = 0;

        BitConverter.GetBytes((uint)structSize).CopyTo(buffer, offset); offset += 4;
        BitConverter.GetBytes(TokenActionRevoke).CopyTo(buffer, offset); offset += 4;
        BitConverter.GetBytes(HashAlgorithmSHA256).CopyTo(buffer, offset); offset += 4;
        BitConverter.GetBytes((uint)hashBytes.Length).CopyTo(buffer, offset); offset += 4;
        Array.Copy(hashBytes, 0, buffer, offset, hashBytes.Length);

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
        string ntStatusHex = string.Format("0x{0:X8}", ntStatus);

        // Attempt to remove cache files
        bool cacheRemoved = TryRemoveCacheFile(hashBytes);

        return new object[] { HashToHex(hashBytes), ntStatusHex, cacheRemoved, success };
    }

    /// <summary>
    /// Searches for and removes the cache file matching the given hash.
    /// </summary>
    private static bool TryRemoveCacheFile(byte[] hashBytes)
    {
        string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string cacheRoot = Path.Combine(sysRoot, TokenCacheRelative);

        if (!Directory.Exists(cacheRoot))
            return false;

        string hashHex = HashToHex(hashBytes);
        string tokenFileName = hashHex + ".token";
        bool removed = false;

        try
        {
            // Search recursively for matching token file
            foreach (string file in Directory.GetFiles(cacheRoot, tokenFileName, SearchOption.AllDirectories))
            {
                File.Delete(file);
                if (!File.Exists(file))
                    removed = true;
            }

            // Also try hash-named files without extension
            foreach (string file in Directory.GetFiles(cacheRoot, hashHex, SearchOption.AllDirectories))
            {
                File.Delete(file);
                if (!File.Exists(file))
                    removed = true;
            }
        }
        catch (UnauthorizedAccessException) { }

        return removed;
    }
}
'@ -ReferencedAssemblies $CIRefBase
    }

    # Resolve file hash and identity
    $fileHash = ''
    $resolvedPath = ''
    $tokenIdLabel = ''

    if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
        $resolvedPath = (Resolve-Path $Path).Path
        Write-Verbose "Computing SHA256 hash for: $resolvedPath"
        $hashBytes = [WDACTokenRemover]::ComputeHash($resolvedPath)
        $fileHash = [WDACTokenRemover]::HashToHex($hashBytes)
        $tokenIdLabel = $fileHash.Substring(0, 8)
    }
    else {
        # Resolve TokenId to hash via Get-WDACToken
        Write-Verbose "Looking up token '$TokenId' via Get-WDACToken..."
        $token = Get-WDACToken | Where-Object { $_.TokenId -eq $TokenId } | Select-Object -First 1

        if (-not $token) {
            Write-Warning "Token '$TokenId' not found in the token cache."
            return
        }

        $resolvedPath = $token.FilePath
        $fileHash = $token.FileHash
        $tokenIdLabel = $TokenId

        # Convert hex hash back to bytes
        $hashBytes = [byte[]]::new($fileHash.Length / 2)
        for ($i = 0; $i -lt $fileHash.Length; $i += 2) {
            $hashBytes[$i / 2] = [Convert]::ToByte($fileHash.Substring($i, 2), 16)
        }
    }

    if ($PSCmdlet.ShouldProcess("Token '$tokenIdLabel' (File: $resolvedPath)", 'Revoke CI trust token')) {
        Write-Verbose "Revoking trust token for hash: $fileHash"

        $result = [WDACTokenRemover]::RevokeByHash($hashBytes)

        [PSCustomObject]@{
            TokenId      = $tokenIdLabel
            FilePath     = $resolvedPath
            FileHash     = [string]$result[0]
            NtStatus     = [string]$result[1]
            CacheRemoved = [bool]$result[2]
            Success      = [bool]$result[3]
            RemovedAt    = [datetime]::Now
        }

        if ([bool]$result[3]) {
            Write-Verbose "Trust token revoked successfully."
        }
        else {
            Write-Warning "Failed to revoke trust token. NTSTATUS: $($result[1])"
        }
    }
}
