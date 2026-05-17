function Get-WDACToken {
    <#
    .SYNOPSIS
        Enumerates Code Integrity trust tokens on the system.

    .DESCRIPTION
        Queries the CI trust token cache using NT API calls to retrieve all active trust tokens.
        Trust tokens represent dynamic trust decisions made at runtime for files not explicitly
        covered by a CI policy, including:
        - Managed Installer tokens (SCCM/Intune deployed apps)
        - Intelligent Security Graph (ISG) tokens (cloud reputation)
        - Dynamic Code Trust tokens (runtime-approved scripts and binaries)

        Uses NtQuerySystemInformation with SystemCodeIntegrityVerificationInformation and
        related info classes to enumerate the token store. Falls back to parsing the CI
        token cache files on disk if the API query is unavailable.

    .PARAMETER TokenId
        Filter to a specific token by its identifier.

    .PARAMETER Type
        Filter tokens by type: 'ManagedInstaller', 'ISG', 'DynamicCodeTrust', or 'All'.
        Defaults to 'All'.

    .PARAMETER IncludeExpired
        Include tokens that have expired but are still in the cache.

    .OUTPUTS
        PSCustomObject[] with properties:
            - TokenId          [string]   Unique token identifier
            - Type             [string]   Token type (ManagedInstaller, ISG, DynamicCodeTrust)
            - FilePath         [string]   File path associated with the token (if available)
            - FileHash         [string]   SHA256 hash of the trusted file
            - TrustLevel       [string]   Trust level (Trusted, Revoked, Expired)
            - CreatedAt        [datetime] When the token was created
            - ExpiresAt        [datetime] When the token expires (DateTime.MaxValue if permanent)
            - TokenSize        [uint32]   Size of the token data in bytes
            - Source           [string]   Source of token data ('NtApi' or 'CacheFile')

    .EXAMPLE
        Get-WDACToken
        Lists all active CI trust tokens.

    .EXAMPLE
        Get-WDACToken -Type ManagedInstaller
        Lists only Managed Installer trust tokens.

    .EXAMPLE
        Get-WDACToken -IncludeExpired | Where-Object TrustLevel -eq 'Expired'
        Shows expired tokens still in the cache.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows 10 1903+ / Windows 11
    #>
    [CmdletBinding()]
    param(
        [string]$TokenId,

        [ValidateSet('All', 'ManagedInstaller', 'ISG', 'DynamicCodeTrust')]
        [string]$Type = 'All',

        [switch]$IncludeExpired
    )

    if (-not ([System.Management.Automation.PSTypeName]'WDACTokenReader').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public static class WDACTokenReader
{
    // NtQuerySystemInformation info classes for CI tokens
    private const uint SystemCodeIntegrityVerificationInformation = 0xBB;  // 187
    private const uint SystemCodeIntegrityAllPoliciesInformation  = 0xC7;  // 199

    // CI token cache directory
    private const string TokenCacheRelative = @"System32\CodeIntegrity\CiCacheTokens";
    private const string ManagedInstallerCacheRelative = @"System32\CodeIntegrity\CiCacheTokens\ManagedInstaller";
    private const string ISGCacheRelative = @"System32\CodeIntegrity\CiCacheTokens\ISG";
    private const string DynamicCodeTrustRelative = @"System32\CodeIntegrity\CiCacheTokens\DynamicCodeTrust";

    // Token type identifiers in the binary structure
    private const uint TokenTypeManagedInstaller = 1;
    private const uint TokenTypeISG = 2;
    private const uint TokenTypeDynamicCodeTrust = 3;

    // Trust level values
    private const uint TrustLevelTrusted = 1;
    private const uint TrustLevelRevoked = 2;

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(
        uint SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        out uint ReturnLength);

    // NTSTATUS codes
    private const uint STATUS_SUCCESS = 0x00000000;
    private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
    private const uint STATUS_BUFFER_TOO_SMALL = 0xC0000023;
    private const uint STATUS_NOT_IMPLEMENTED = 0xC0000002;

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

    private static string ClassifyTokenType(uint typeId)
    {
        switch (typeId)
        {
            case TokenTypeManagedInstaller: return "ManagedInstaller";
            case TokenTypeISG: return "ISG";
            case TokenTypeDynamicCodeTrust: return "DynamicCodeTrust";
            default: return "Unknown(" + typeId + ")";
        }
    }

    private static string ClassifyTrustLevel(uint level, DateTime expiresAt)
    {
        if (expiresAt < DateTime.Now && expiresAt != DateTime.MaxValue)
            return "Expired";
        if (level == TrustLevelRevoked)
            return "Revoked";
        if (level == TrustLevelTrusted)
            return "Trusted";
        return "Unknown";
    }

    /// <summary>
    /// Attempts to query CI token info via NtQuerySystemInformation.
    /// Returns list of object[]: [TokenId, Type, FilePath, FileHash, TrustLevel,
    ///   CreatedAt, ExpiresAt, TokenSize, Source]
    /// Falls back to cache file enumeration if the API is unavailable.
    /// </summary>
    public static List<object[]> QueryTokens(bool includeExpired)
    {
        EnsureElevated();

        var results = new List<object[]>();

        // Attempt NT API query first
        bool apiSuccess = TryQueryViaApi(results, includeExpired);

        // Fall back to cache file enumeration
        if (!apiSuccess)
            EnumerateCacheFiles(results, includeExpired);

        return results;
    }

    private static bool TryQueryViaApi(List<object[]> results, bool includeExpired)
    {
        uint returnLength;

        // Initial probe to get required buffer size
        uint status = NtQuerySystemInformation(
            SystemCodeIntegrityVerificationInformation,
            IntPtr.Zero, 0, out returnLength);

        // If not implemented or not supported, fall back
        if (status == STATUS_NOT_IMPLEMENTED || returnLength == 0)
            return false;

        if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
            return false;

        // Allocate buffer and query
        IntPtr buffer = Marshal.AllocHGlobal((int)returnLength);
        try
        {
            status = NtQuerySystemInformation(
                SystemCodeIntegrityVerificationInformation,
                buffer, returnLength, out returnLength);

            if (status != STATUS_SUCCESS)
                return false;

            // Parse the returned buffer
            ParseTokenBuffer(buffer, (int)returnLength, results, includeExpired);
            return true; // API call succeeded — no fallback needed regardless of token count
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void ParseTokenBuffer(IntPtr buffer, int length, List<object[]> results, bool includeExpired)
    {
        if (length < 8)
            return;

        int offset = 0;

        // Header: uint32 token count
        uint tokenCount = (uint)Marshal.ReadInt32(buffer, offset);
        offset += 4;

        // Sanity check
        if (tokenCount > 100000 || tokenCount == 0)
            return;

        for (uint i = 0; i < tokenCount && offset < length - 16; i++)
        {
            // Each token entry structure (variable length):
            //   uint32 EntrySize
            //   uint32 TokenType
            //   uint32 TrustLevel
            //   uint32 HashLength
            //   int64  CreatedTimestamp (FILETIME)
            //   int64  ExpiresTimestamp (FILETIME)
            //   byte[] Hash (HashLength bytes)
            //   uint16 PathLength (in chars)
            //   char[] Path (UTF-16)

            if (offset + 32 > length)
                break;

            uint entrySize = (uint)Marshal.ReadInt32(buffer, offset);
            if (entrySize < 32 || offset + (int)entrySize > length)
                break;

            uint tokenType = (uint)Marshal.ReadInt32(buffer, offset + 4);
            uint trustLevel = (uint)Marshal.ReadInt32(buffer, offset + 8);
            uint hashLength = (uint)Marshal.ReadInt32(buffer, offset + 12);

            DateTime createdAt;
            DateTime expiresAt;

            try
            {
                long createdFt = Marshal.ReadInt64(buffer, offset + 16);
                createdAt = createdFt > 0 ? DateTime.FromFileTime(createdFt) : DateTime.MinValue;
            }
            catch { createdAt = DateTime.MinValue; }

            try
            {
                long expiresFt = Marshal.ReadInt64(buffer, offset + 24);
                expiresAt = expiresFt > 0 && expiresFt < long.MaxValue
                    ? DateTime.FromFileTime(expiresFt)
                    : DateTime.MaxValue;
            }
            catch { expiresAt = DateTime.MaxValue; }

            // Skip expired unless requested
            string trustLevelStr = ClassifyTrustLevel(trustLevel, expiresAt);
            if (!includeExpired && trustLevelStr == "Expired")
            {
                offset += (int)entrySize;
                continue;
            }

            // Read hash
            string fileHash = "";
            int hashOffset = offset + 32;
            if (hashLength > 0 && hashLength <= 64 && hashOffset + (int)hashLength <= length)
            {
                byte[] hash = new byte[hashLength];
                Marshal.Copy(IntPtr.Add(buffer, hashOffset), hash, 0, (int)hashLength);
                var sb = new StringBuilder((int)hashLength * 2);
                foreach (byte b in hash)
                    sb.Append(b.ToString("X2"));
                fileHash = sb.ToString();
            }

            // Read path
            string filePath = "";
            int pathLenOffset = hashOffset + (int)hashLength;
            if (pathLenOffset + 2 <= offset + (int)entrySize)
            {
                ushort pathLength = (ushort)Marshal.ReadInt16(buffer, pathLenOffset);
                int pathDataOffset = pathLenOffset + 2;
                if (pathLength > 0 && pathLength <= 2048 &&
                    pathDataOffset + pathLength * 2 <= offset + (int)entrySize)
                {
                    char[] pathChars = new char[pathLength];
                    for (int c = 0; c < pathLength; c++)
                        pathChars[c] = (char)Marshal.ReadInt16(buffer, pathDataOffset + c * 2);
                    filePath = new string(pathChars).TrimEnd('\0');
                }
            }

            // Generate token ID from hash + type
            string tokenId = string.Format("{0}-{1:X8}",
                ClassifyTokenType(tokenType).Substring(0, Math.Min(3, ClassifyTokenType(tokenType).Length)).ToUpper(),
                (fileHash.Length >= 8 ? fileHash.Substring(0, 8) : i.ToString("X8")));

            results.Add(new object[] {
                tokenId,
                ClassifyTokenType(tokenType),
                filePath,
                fileHash,
                trustLevelStr,
                createdAt,
                expiresAt,
                entrySize,
                "NtApi"
            });

            offset += (int)entrySize;
        }
    }

    /// <summary>
    /// Fallback: enumerate CI token cache files on disk.
    /// </summary>
    private static void EnumerateCacheFiles(List<object[]> results, bool includeExpired)
    {
        string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var cacheDirs = new Dictionary<string, string>
        {
            { "ManagedInstaller", Path.Combine(sysRoot, ManagedInstallerCacheRelative) },
            { "ISG", Path.Combine(sysRoot, ISGCacheRelative) },
            { "DynamicCodeTrust", Path.Combine(sysRoot, DynamicCodeTrustRelative) }
        };

        // Also check the root token cache
        string rootCache = Path.Combine(sysRoot, TokenCacheRelative);
        if (Directory.Exists(rootCache))
        {
            try
            {
                foreach (string file in Directory.GetFiles(rootCache, "*", SearchOption.TopDirectoryOnly))
                    AddCacheFileToken(results, file, "Unknown", includeExpired);
            }
            catch (UnauthorizedAccessException) { }
        }

        foreach (var kvp in cacheDirs)
        {
            if (!Directory.Exists(kvp.Value))
                continue;

            try
            {
                foreach (string file in Directory.GetFiles(kvp.Value, "*", SearchOption.AllDirectories))
                    AddCacheFileToken(results, file, kvp.Key, includeExpired);
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void AddCacheFileToken(List<object[]> results, string filePath, string tokenType, bool includeExpired)
    {
        try
        {
            var info = new FileInfo(filePath);

            // Skip very large files (not token files)
            if (info.Length > 1024 * 1024)
                return;

            // Compute a simple hash-based ID from the filename
            string tokenId = string.Format("{0}-{1}",
                tokenType.Substring(0, Math.Min(3, tokenType.Length)).ToUpper(),
                Path.GetFileNameWithoutExtension(info.Name));

            // Read first bytes to check for hash data
            string fileHash = "";
            byte[] data = File.ReadAllBytes(filePath);
            if (data.Length >= 32)
            {
                // First 32 bytes may be a SHA256 hash
                var sb = new StringBuilder(64);
                for (int i = 0; i < 32; i++)
                    sb.Append(data[i].ToString("X2"));
                fileHash = sb.ToString();
            }

            results.Add(new object[] {
                tokenId,
                tokenType,
                filePath,
                fileHash,
                "Trusted",  // Cache files are assumed trusted (expired are cleaned by OS)
                info.CreationTime,
                DateTime.MaxValue,
                (uint)info.Length,
                "CacheFile"
            });
        }
        catch { /* Skip unreadable files */ }
    }
}
'@ -ReferencedAssemblies $CIRefBase
    }

    Write-Verbose 'Querying CI trust tokens...'

    $tokens = [WDACTokenReader]::QueryTokens($IncludeExpired.IsPresent)

    $output = foreach ($row in $tokens) {
        [PSCustomObject]@{
            TokenId    = [string]$row[0]
            Type       = [string]$row[1]
            FilePath   = [string]$row[2]
            FileHash   = [string]$row[3]
            TrustLevel = [string]$row[4]
            CreatedAt  = [datetime]$row[5]
            ExpiresAt  = [datetime]$row[6]
            TokenSize  = [uint32]$row[7]
            Source     = [string]$row[8]
        }
    }

    # Apply filters
    if ($PSBoundParameters.ContainsKey('TokenId')) {
        $output = $output | Where-Object { $_.TokenId -eq $TokenId }
    }

    if ($Type -ne 'All') {
        $output = $output | Where-Object { $_.Type -eq $Type }
    }

    $output

    if ($tokens.Count -eq 0) {
        Write-Verbose 'No CI trust tokens found.'
    }
    else {
        Write-Verbose "Found $($tokens.Count) CI trust token(s)."
    }
}
