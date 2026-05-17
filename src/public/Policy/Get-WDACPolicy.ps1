function Get-WDACPolicy {
    <#
    .SYNOPSIS
        Enumerates deployed Code Integrity policies with full metadata.

    .DESCRIPTION
        Scans all deployed CI policy files (.cip and .p7b), parses their binary content
        using ConvertFrom-WDACBinary to produce SiPolicy XML, then transforms the XML
        into a standardised output contract via ConvertTo-WDACPolicyObject.

        For each policy, extracts:
        - PolicyId and BasePolicyId from V6+ versioned blocks or legacy PolicyTypeID
        - FriendlyName from Settings (when present in binary)
        - PolicyVersion from the binary header
        - EnforcementMode from Rule Options
        - PolicyType classification from GUID or XML attribute
        - Full Rule Options array with name-to-ID reverse mapping

        PKCS#7 signed policies (.p7b and signed .cip files) are automatically unwrapped
        before parsing. This includes the 11 system-deployed policies that the previous
        C# parser could not handle.

        Scans three deployment locations:
        - MultiPolicy: %SystemRoot%\System32\CodeIntegrity\CiPolicies\Active\*.cip
        - Legacy: %SystemRoot%\System32\CodeIntegrity\SIPolicy.p7b
        - EFI: S:\, T:\, X:\ EFI\Microsoft\Boot\CiPolicies\Active\*.cip

    .PARAMETER Name
        Filter policies by FriendlyName. Supports wildcards (e.g., 'AllowMicrosoft*').

    .PARAMETER PolicyId
        Filter to a specific policy by its GUID.

    .OUTPUTS
        PSCustomObject[] with properties:
            - PolicyId           [string]   Policy GUID
            - BasePolicyId       [string]   Base policy GUID
            - FriendlyName       [string]   Policy name from Settings (if available)
            - Version            [string]   Policy version (Major.Minor.Build.Revision)
            - IsSupplemental     [bool]     True if this is a supplemental policy
            - EnforcementMode    [string]   'Enforced' or 'Audit'
            - FormatVersion      [uint32]   Binary format version (1-9)
            - PolicyType         [string]   'Enterprise', 'Base Policy', etc.
            - RuleOptions        [PSCustomObject[]] Array of { Id [uint32]; Name [string] }
            - FilePath           [string]   Full path to the deployed .cip/.p7b file
            - Location           [string]   'MultiPolicy', 'Legacy', or 'EFI'
            - FileSize           [long]     File size in bytes
            - LastModified       [datetime] File last write time
            - IsDuplicate        [bool]     True if another policy shares this PolicyId

    .EXAMPLE
        Get-WDACPolicy
        Lists all deployed CI policies with full metadata.

    .EXAMPLE
        Get-WDACPolicy | Where-Object { $_.EnforcementMode -eq 'Audit' }
        Lists only policies running in audit mode.

    .EXAMPLE
        Get-WDACPolicy -PolicyId 'A1B2C3D4-E5F6-7890-ABCD-EF1234567890'
        Retrieves a specific policy by its GUID.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows only
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param(
        [Parameter(ParameterSetName = 'ByName')]
        [SupportsWildcards()]
        [string]$Name,

        [Parameter(ParameterSetName = 'ById')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$PolicyId
    )

    # -----------------------------------------------------------------------
    # Elevation check
    # -----------------------------------------------------------------------
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw [System.UnauthorizedAccessException]::new(
            'This operation requires Administrator elevation. Run PowerShell as Administrator.'
        )
    }

    # -----------------------------------------------------------------------
    # Deployment location paths
    # -----------------------------------------------------------------------
    $sysRoot = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows)

    $multiPolicyDir = [System.IO.Path]::Combine($sysRoot, 'System32\CodeIntegrity\CiPolicies\Active')
    $legacyPath     = [System.IO.Path]::Combine($sysRoot, 'System32\CodeIntegrity\SIPolicy.p7b')
    $efiRelative    = 'EFI\Microsoft\Boot\CiPolicies\Active'
    $efiRoots       = @('S:\', 'T:\', 'X:\')

    # -----------------------------------------------------------------------
    # Collect policy file entries: @{ Path; Location }
    # -----------------------------------------------------------------------
    $fileEntries = [System.Collections.Generic.List[hashtable]]::new()

    # MultiPolicy: *.cip files
    if ([System.IO.Directory]::Exists($multiPolicyDir)) {
        foreach ($file in [System.IO.Directory]::GetFiles($multiPolicyDir, '*.cip')) {
            $fileEntries.Add(@{ Path = $file; Location = 'MultiPolicy' })
        }
    }

    # Legacy: single SIPolicy.p7b
    if ([System.IO.File]::Exists($legacyPath)) {
        $fileEntries.Add(@{ Path = $legacyPath; Location = 'Legacy' })
    }

    # EFI partition: scan known drive letters
    foreach ($efiRoot in $efiRoots) {
        $efiDir = [System.IO.Path]::Combine($efiRoot, $efiRelative)
        if ([System.IO.Directory]::Exists($efiDir)) {
            try {
                foreach ($file in [System.IO.Directory]::GetFiles($efiDir, '*.cip')) {
                    $fileEntries.Add(@{ Path = $file; Location = 'EFI' })
                }
            }
            catch [System.UnauthorizedAccessException] {
                Write-Verbose "EFI partition at $efiRoot is not accessible."
            }
        }
    }

    Write-Verbose "Enumerating and parsing deployed CI policies... ($($fileEntries.Count) file(s) found)"

    # -----------------------------------------------------------------------
    # Parse each file
    # -----------------------------------------------------------------------
    $output = foreach ($entry in $fileEntries) {
        $filePath = $entry.Path
        $location = $entry.Location

        try {
            # Read raw bytes and unwrap PKCS#7 if present
            $rawBytes = [System.IO.File]::ReadAllBytes($filePath)
            $unwrapped = Unprotect-Pkcs7Policy -Data $rawBytes

            # Extract FormatVersion from first 4 bytes of unwrapped binary
            $formatVersion = [System.BitConverter]::ToUInt32($unwrapped, 0)

            # Parse binary → XmlDocument
            $xml = ConvertFrom-WDACBinary -Data $unwrapped

            # Transform XML → output contract PSCustomObject
            ConvertTo-WDACPolicyObject -Xml $xml -FormatVersion $formatVersion -FilePath $filePath -Location $location
        }
        catch {
            Write-Warning "Failed to parse '$filePath': $($_.Exception.Message)"

            # Fallback stub: minimal metadata for unparseable files
            $fileInfo = [System.IO.FileInfo]::new($filePath)
            $fileName = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
            $parseResult = [guid]::Empty
            $fallbackId = if ([guid]::TryParse($fileName.Trim('{', '}'), [ref]$parseResult)) {
                $parseResult.ToString()
            }
            else {
                $fileName
            }

            [PSCustomObject]@{
                PolicyId        = [string]$fallbackId
                BasePolicyId    = [string]''
                FriendlyName    = [string]''
                Version         = [string]'Unknown'
                IsSupplemental  = [bool]$false
                EnforcementMode = [string]'Unknown'
                FormatVersion   = [uint32]0
                PolicyType      = [string]'Unknown'
                RuleOptions     = @()
                FilePath        = [string]$fileInfo.FullName
                Location        = [string]$location
                FileSize        = [long]$fileInfo.Length
                LastModified    = [datetime]$fileInfo.LastWriteTime
            }
        }
    }

    # -----------------------------------------------------------------------
    # Annotate duplicates — flag policies that share a PolicyId
    # -----------------------------------------------------------------------
    $outputArray = @($output)
    $duplicateIds = @($outputArray | Group-Object -Property PolicyId |
        Where-Object { $_.Count -gt 1 } |
        ForEach-Object { $_.Name })
    foreach ($item in $outputArray) {
        $isDup = $duplicateIds -contains $item.PolicyId
        $item | Add-Member -NotePropertyName 'IsDuplicate' -NotePropertyValue ([bool]$isDup)
    }
    $output = $outputArray

    # -----------------------------------------------------------------------
    # Apply filters
    # -----------------------------------------------------------------------
    if ($PSBoundParameters.ContainsKey('Name')) {
        $output = @($output) | Where-Object { $_.FriendlyName -like $Name }
    }
    elseif ($PSBoundParameters.ContainsKey('PolicyId')) {
        $output = @($output) | Where-Object { $_.PolicyId -eq $PolicyId }
    }

    $output

    if ($fileEntries.Count -eq 0) {
        Write-Verbose 'No deployed CI policy files found.'
    }
    else {
        Write-Verbose "Parsed $($fileEntries.Count) deployed CI policy file(s)."
    }
}
